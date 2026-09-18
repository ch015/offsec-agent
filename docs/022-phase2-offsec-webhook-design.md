# Phase 2: OffSec Webhook 연동 설계

> **이전 기록 — 2026-09-18 현행화 메모.** 통합 플랫폼 시점의 설계·운영 기록이다. 현재 OffSec는 모듈/CLI, Feedback와 SOC는 각각 분리된 gateway를 사용한다. 당시 라우트·배포 수량·비용 예상은 현재 운영 보장이 아니다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md) · [현재 서비스 API](../../docs/service-api.ko.md)

Status: 설계 (2026-08-12)
Parent: `docs/021-service-platform-architecture.md`

## 1. 목적

Git push/PR/티켓 생성 등 외부 webhook 이벤트를 수신해 OffSec 취약점 진단(`assess`)을
자동으로 실행하고, 결과를 요청 소스(PR comment, 티켓, 보고서 저장소)에 라우팅한다.

## 2. 트리거 소스

| 소스 | 이벤트 | 동작 |
|---|---|---|
| GitHub | `push`, `pull_request.opened/synchronize` | 대상 repo를 clone해 진단 실행 |
| GitLab | `push`, `merge_request` | 동일 |
| 분석 티켓 (Jira/Linear) | ticket created with label | 티켓 본문에서 repo URL + scope 추출 |
| 수동 API 호출 | `POST /api/v1/jobs` (domain=offsec) | CLI/대시보드에서 직접 요청 |

Phase 2 초기 구현: **GitHub webhook**. 나머지는 WebhookAdapter 추가로 확장.

## 3. 아키텍처

```
GitHub/GitLab/Jira
        │ webhook POST
        ▼
┌───────────────────────────────────┐
│  Webhook Receiver                  │
│  POST /api/v1/hooks/offsec/:source │
│                                    │
│  • 서명 검증 (HMAC-SHA256)        │
│  • payload → CanonicalRequest     │
│  • 중복 방지 (delivery ID)        │
│  • 필터링 (branch/path/label)     │
└──────────────────┬────────────────┘
                   │
                   ▼
┌───────────────────────────────────┐
│  Gateway API                       │
│  • tenant 확인                    │
│  • concurrent job cap 체크        │
│  • Job 생성 → offsec queue        │
└──────────────────┬────────────────┘
                   │
                   ▼
┌───────────────────────────────────┐
│  BullMQ: offsec queue              │
│  • concurrency: 2~4 (계약 제한)   │
│  • timeout: 60min                  │
│  • retry: 1 (preflight 실패만)    │
└──────────────────┬────────────────┘
                   │
                   ▼
┌───────────────────────────────────┐
│  OffSec Worker                     │
│                                    │
│  1. Source 준비                    │
│     • git clone (shallow, depth=1)│
│     • checkout target ref         │
│  2. assess() 실행                 │
│     • engagement-dir = ephemeral  │
│     • work-units = auto           │
│     • semgrep = best-effort       │
│  3. 결과 수집                      │
│     • 보고서 → S3 artifact store  │
│     • 요약 추출                    │
│  4. Progress 이벤트 발행           │
│  5. Cleanup (ephemeral dir 삭제)  │
└──────────────────┬────────────────┘
                   │
                   ▼
┌───────────────────────────────────┐
│  Result Router                     │
│                                    │
│  callback.type에 따라:            │
│  • github_pr → PR comment         │
│  • gitlab_mr → MR note            │
│  • ticket → Jira/Linear comment   │
│  • webhook → POST callback URL    │
│  • none → poll/SSE only           │
└───────────────────────────────────┘
```

## 4. Webhook Adapter 인터페이스

```typescript
interface WebhookSource {
  id: string;                    // 'github' | 'gitlab' | 'jira' | ...
  verifySignature(req: IncomingRequest): boolean;
  parsePayload(body: unknown): OffsecWebhookEvent | null;  // null = 무시
}

interface OffsecWebhookEvent {
  source: string;                // 'github'
  deliveryId: string;            // 중복 방지 키
  repoUrl: string;               // clone URL
  ref: string;                   // branch or commit SHA
  defaultBranch?: string;
  prNumber?: number;
  prTitle?: string;
  changedFiles?: string[];       // scope 힌트
  sender: string;
  tenantId: string;              // webhook secret → tenant 매핑
  callback: ResultCallback;      // 결과 전달 대상
}

interface ResultCallback {
  type: 'github_pr' | 'gitlab_mr' | 'ticket' | 'webhook' | 'none';
  owner?: string;                // repo owner
  repo?: string;                 // repo name
  prNumber?: number;
  ticketId?: string;
  url?: string;                  // callback URL
}
```

새로운 webhook 소스 추가 = `WebhookSource` 구현체 1개.

## 5. GitHub Webhook 상세

### 5.1 등록

```
Repository Settings → Webhooks → Add webhook
  URL:    https://gateway.example.com/api/v1/hooks/offsec/github
  Secret: (tenant별 HMAC secret, Vault에서 관리)
  Events: push, pull_request
```

### 5.2 필터링 정책

모든 webhook이 진단을 트리거하면 과부하. 다음 중 하나 이상 만족해야 실행:

| 필터 | 조건 | 설정 위치 |
|---|---|---|
| Branch | default branch (main/master) 또는 PR target이 default | 기본 활성 |
| Path | 변경 파일 중 소스 코드가 1개 이상 | 기본 활성 |
| Label (PR) | 특정 label 부착 시만 (e.g., `security-review`) | tenant 설정 |
| Manual only | webhook 수신하되 label 없으면 무시 | tenant 설정 |

### 5.3 결과 PR Comment 포맷

```markdown
## 🔒 Security Assessment

**Status:** 완료 | 취약점 3건 발견

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 1 |
| Medium   | 2 |

**요약:** 인증 우회 가능성과 SQL injection 후보 발견.

[📄 전체 보고서 보기](https://artifacts.example.com/tenant/job-id/07_security_report.md)

<details>
<summary>상세 (클릭하여 펼치기)</summary>

1. **[HIGH] CWE-287: 인증 우회** — `src/auth/session.ts:42`
2. **[MEDIUM] CWE-89: SQL Injection 후보** — `src/db/queries.ts:118`
3. **[MEDIUM] CWE-532: 민감정보 로그 기록** — `src/utils/logger.ts:27`

</details>

---
*secops-nunchi-agent v0.x · engagement: `abc123` · cost: $2.34*
```

## 6. 소스 준비

### 6.1 Git Clone 전략

```typescript
interface SourcePreparer {
  prepare(event: OffsecWebhookEvent): Promise<PreparedSource>;
  cleanup(source: PreparedSource): Promise<void>;
}

interface PreparedSource {
  localPath: string;       // ephemeral 절대경로
  commitSha: string;       // 실제 checkout한 커밋
  scope?: string;          // 변경 파일 기반 자동 scope
}
```

- **Shallow clone:** `git clone --depth=1 --branch=<ref>` (대부분 수십 초)
- **인증:** Deploy key (Vault → VSO → env) 또는 GitHub App installation token
- **Ephemeral:** 워커 컨테이너의 tmpfs 또는 `/tmp/nunchi-offsec-<job-id>/`
- **Cleanup:** Job 완료 후 즉시 삭제. 실패 시에도 삭제 (진단 결과는 artifact store에 보존)
- **크기 제한:** Clone 대상 repo 크기 1GB 초과 시 rejected

### 6.2 자동 Scope 추론

PR webhook인 경우 `changedFiles`로 자동 scope를 생성:

```typescript
function inferScope(event: OffsecWebhookEvent): string | undefined {
  if (!event.changedFiles?.length) return undefined;
  // 변경 파일의 공통 디렉토리 상위 경로
  const dirs = [...new Set(event.changedFiles.map(f => dirname(f)))];
  if (dirs.length <= 5) {
    return `변경된 모듈 집중 진단: ${dirs.join(', ')}`;
  }
  return undefined; // 너무 넓으면 전체 진단
}
```

## 7. 동시성 및 자원 관리

| 항목 | 값 | 근거 |
|---|---|---|
| Queue concurrency | 2~4 | 계약 `maximumConcurrency: 4` |
| Job timeout | 60min | 대형 repo 기준 |
| Clone timeout | 5min | 1GB 초과 repo 차단 |
| 워커 메모리 | 4~8 GB | assess + Semgrep + graph 생성 |
| Per-tenant concurrent cap | 2 | 한 tenant가 큐 독점 방지 |
| 일일 진단 cap (tenant) | 20 | Phase 2 내부 팀 기준, 설정 가능 |

## 8. Progress 이벤트

assess는 내부적으로 여러 phase를 거치므로 Progress를 세분화:

| Phase | Progress 메시지 | 예상 소요 |
|---|---|---|
| `clone` | "소스 코드 준비 중" | 10~60초 |
| `manifest` | "소스 분석 중 (N개 파일)" | 5~30초 |
| `graph` | "의존성 그래프 생성" | 10~60초 |
| `va` | "취약점 분석 중 (unit M/N)" | 수분~수십분 |
| `verify` | "검증 진행 중" | 수분 |
| `converge` | "결과 수렴 중" | 1~3분 |
| `report` | "보고서 생성 중" | 1분 |
| `publish` | "결과 발행" | 수초 |

SSE와 callback 모두에 동일한 progress 이벤트를 발행한다.
PR의 경우 comment를 최초 1번 생성 후 edit으로 갱신하여 스팸 방지.

## 9. 실패 처리

| 실패 유형 | 동작 |
|---|---|
| Clone 실패 (권한/네트워크) | rejected + callback에 에러 전달 |
| Semgrep unavailable | `semgrep=best-effort`이므로 계속 진행 |
| assess timeout | failed + 부분 결과가 있으면 artifact 보존 |
| 모델 API 에러 | 1회 자동 재시도 (30초 후). 재실패 시 failed |
| Worker OOM | failed + 자동 재시작 (큐 재소비). job은 실패 처리 |
| 중복 webhook (같은 commit) | deliveryId 기반 중복 제거. 동일 SHA 진행 중이면 무시 |

## 10. 보안 고려

| 위협 | 대응 |
|---|---|
| Webhook 위조 | HMAC-SHA256 서명 검증 (per-tenant secret) |
| 악성 repo 코드 실행 | assess는 Read-only 분석. Bash 도구 비활성. 컨테이너 격리 |
| Deploy key 유출 | Vault + VSO. 키는 워커 env에만 주입, 로그에 마스킹 |
| PR에 민감정보 노출 | comment에 파일 내용 미포함. 요약만. 전문은 인증된 링크 |
| Rate bomb (대량 push) | Per-tenant concurrent/daily cap + 큐 backpressure |

## 11. Tenant 설정 스키마

```typescript
interface OffsecTenantConfig {
  // 소스 접근
  git: {
    authMethod: 'deploy-key' | 'github-app' | 'token';
    credentialRef: string;        // Vault path
  };
  
  // 필터 정책
  filter: {
    branches?: string[];          // 허용 branch 패턴 (default: default branch only)
    pathPatterns?: string[];      // 관심 경로 (default: 소스 코드 전체)
    requireLabel?: string;        // PR에 이 label이 있어야 실행
    autoTrigger: boolean;         // false면 label 필수
  };
  
  // 실행 정책
  execution: {
    maxConcurrent: number;        // default: 2
    dailyCap: number;             // default: 20
    effort: 'low' | 'medium' | 'high' | 'max';
    maxBudgetUsd?: number;        // per-job
    verificationMode: 'VA_ONLY' | 'VA_PENTEST';
  };
  
  // 결과 라우팅
  result: {
    prComment: boolean;           // PR에 코멘트 작성
    reportStore: boolean;         // S3에 전문 저장
    ticketUpdate?: { provider: string; projectKey: string };
    webhookCallback?: string;     // 추가 callback URL
  };
}
```

## 12. API 엔드포인트 (Phase 2 추가분)

```yaml
# Webhook 수신 (외부 Git 플랫폼이 호출)
POST /api/v1/hooks/offsec/github     # GitHub webhook
POST /api/v1/hooks/offsec/gitlab     # GitLab webhook (확장)
POST /api/v1/hooks/offsec/jira       # Jira webhook (확장)

# Tenant offsec 설정
GET  /api/v1/tenants/:id/offsec-config
PUT  /api/v1/tenants/:id/offsec-config

# Job은 Phase 1 API 그대로 사용
POST /api/v1/jobs                    # 수동 offsec 요청도 가능
GET  /api/v1/jobs/:id
GET  /api/v1/jobs/:id/stream         # SSE
```

## 13. Phase 1과의 공유/재사용

| 구성요소 | Phase 1에서 이미 구현 | Phase 2에서 추가 |
|---|---|---|
| Gateway API 서버 | ✓ | webhook 라우트 추가 |
| Job lifecycle | ✓ | 그대로 사용 |
| BullMQ 큐 | ✓ (feedback queue) | offsec queue 추가 (별도 concurrency) |
| PostgreSQL jobs table | ✓ | 그대로 사용 |
| Result Router | ✓ (Slack reply) | GitHub/GitLab adapter 추가 |
| SSE progress | ✓ | 그대로 사용 |
| Tenant 인증 | ✓ | webhook secret → tenant 매핑 추가 |
| S3 artifact | ✓ | 그대로 사용 |
| Docker Compose | ✓ | offsec-worker 서비스 추가 |

## 14. 최소 Docker Compose 추가분

```yaml
# Phase 2 추가 서비스
services:
  offsec-worker:
    build: .
    command: ["node", "--import", "tsx", "src/gateway/workers/offsec-worker.ts"]
    environment:
      - REDIS_URL=${REDIS_URL}
      - DATABASE_URL=${DATABASE_URL}
      - ARTIFACT_BUCKET=${ARTIFACT_BUCKET}
      # Vault VSO가 주입하는 credential
      - GIT_DEPLOY_KEY_PATH=/secrets/deploy-key
      - ANTHROPIC_API_KEY  # from Vault
    volumes:
      - /secrets:/secrets:ro   # VSO mount
      - /tmp/nunchi-offsec:/tmp/nunchi-offsec
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 8G
```

## 15. 구현 순서

```
2-1. WebhookAdapter 인터페이스 + GitHub 구현체
2-2. Webhook receiver 라우트 (서명 검증 + 중복 제거 + 필터링)
2-3. SourcePreparer (git clone + ephemeral + cleanup)
2-4. OffSec worker (BullMQ consumer → assess() 래핑 → progress 발행)
2-5. Result Router: GitHub PR comment adapter
2-6. Tenant offsec config 스키마 + API
2-7. Progress event 세분화 (assess 내부 phase hook)
2-8. 통합 테스트 (mock GitHub webhook → clone → 분석 → PR comment)
2-9. Docker Compose에 offsec-worker 추가
```

## 16. 제외 (Phase 2 범위 밖)

| 항목 | 도입 시점 |
|---|---|
| GitLab/Jira webhook adapter | 필요 시 추가 (WebhookSource 1개) |
| VA_PENTEST (live test) | 별도 승인 프로세스 필요. 별도 phase |
| PR 차단 (required check) | GitHub Check Runs API 연동. Phase 2+ |
| 자동 수정 PR 생성 | 보안 진단은 리포트만. 자동 fix는 별도 도메인 |
| Monorepo 하위 프로젝트별 분리 진단 | 현재 assess가 target 1개 = engagement 1개 |
