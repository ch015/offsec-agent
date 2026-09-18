# secops-nunchi-agent 리팩토링 설계서 v3

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)

> v2 GPT-5.6-sol 검토 반영 + 컨텍스트 오염 ROI 기반 재정렬 + 전 도메인 통합 + offsec 병렬화 + 큐 고도화

## 1. 목적

현재 시스템의 핵심 문제:

1. **fail-closed 중단** — 검증 실패 시 재시도/보정 없이 미션 종료
2. **컨텍스트 오염** — 불필요한 정보가 모델 context에 누적되어 출력 품질 저하
3. **offsec 처리량 부족** — 단일 순차 실행으로 다수 요청 처리 불가

해결 방향:
- fail-closed → **fail-forward** (기록+보정+계속 진행, 최종 단계에서 종합 판단)
- 컨텍스트 오염 → **선별적 주입 + 새니타이징 + 격리**
- 처리량 → **병렬 워커 풀 + 큐 고도화**

## 2. 현황 (변경하지 않는 것)

| 유지 항목 | 이유 |
|---|---|
| Claude Agent SDK | 핵심 런타임 |
| engine.ts WorkflowHost | 이미 phase 루프 + 상태 영속 + attempt 관리 수행 |
| DomainAdapter 패턴 | outputFormat, validateResult, buildPrompt 이미 작동 |
| Hono + BullMQ + Redis + PostgreSQL | 게이트웨이 잘 동작 중 |
| 도메인 3분할 (offsec/soc/feedback) | 유효 |
| state-store.ts 상태 관리 | 유지 + 확장 |
| hooks.json → SDK 실행 | SDK hook 메커니즘 유지 (호스트 검증과 구분) |
| 기존 테스트 + eval 체계 | 유지 + 추가 |

## 3. 변경 우선순위 (컨텍스트 오염 ROI 순)

### 3.1 C3: 도구 출력 새니타이징 ⭐⭐⭐

**문제**: 타겟 코드/파일에서 모델 context로 들어오는 내용에 injection 패턴이 포함될 수 있음.

**구현**: `src/runtime/sanitize.ts`

```typescript
export function sanitizeToolOutput(raw: string, opts?: { maxChars?: number }): string {
  const maxChars = opts?.maxChars ?? 8000;
  let output = raw.slice(0, maxChars);
  output = output.replace(
    /\[SYSTEM\]|<\|system\|>|<\/?instructions?>|<\|im_start\|>|<\|im_end\|>/gi,
    '[FILTERED]'
  );
  return output;
}
```

**적용 지점**: SDK의 tool result가 모델에 반환되기 전. DomainAdapter에 `sanitizeToolResult()` 메서드 추가.

**전 도메인 적용**: offsec/soc/feedback 모두 동일하게 DomainAdapter에서 처리.

---

### 3.2 C8: Knowledge-Base 선별 로드 ⭐⭐⭐

**문제**: 모델이 Read 도구로 knowledge-base를 탐색할 때 현재 phase에 무관한 문서까지 읽을 수 있음.

**구현**: KB 파일에 YAML frontmatter 추가 + `allowedReadFiles`에 phase별 필터링

```yaml
# domains/offsec/knowledge-base/tier1-dimensions/a1-auth.md
---
phases: [va, verify]
keywords: [authentication, session, credential]
---
```

```typescript
// src/runtime/knowledge/loader.ts
export function resolveKnowledgeFiles(domain: string, phase: string): string[] {
  const entries = scanKnowledgeBase(domain);
  return entries
    .filter(e => e.phases.includes(phase))
    .map(e => e.absolutePath);
}
```

**engine.ts 연동**: `allowedReadFiles`에 해당 phase의 KB 파일만 포함. 다른 KB는 Read 시도 시 SDK hook(PreToolUse)에서 거부.

**전 도메인 적용**: offsec KB (47K+줄), soc/feedback는 소규모이므로 우선 offsec에 적용.

---

### 3.3 C1: 에이전트 Phase 입력 선별 ⭐⭐

**문제**: agents/*.md 전체(188~295줄)가 매 phase에 통째 주입. 해당 phase에 불필요한 지시도 포함됨.

**변경**: 기존 .md를 유지하되, `DomainAdapter.buildPrompt()`에서 phase별 필요 섹션만 추출하여 주입.

```typescript
// src/runtime/agents/prompt-builder.ts
export interface PhasePromptConfig {
  domain: string;
  agent: string;
  phase: string;
  /** .md에서 추출할 섹션 헤딩 목록 */
  sections: string[];
  /** 추가 phase-specific 지시 */
  phaseDirective?: string;
}

export function buildPhasePrompt(config: PhasePromptConfig): string {
  const fullMd = loadAgentMd(config.domain, config.agent);
  const filtered = extractSections(fullMd, config.sections);
  return [filtered, config.phaseDirective].filter(Boolean).join('\n\n');
}
```

**전 도메인 통합 형식**:

```typescript
// src/runtime/agents/registry.ts
export interface AgentPhaseConfig {
  domain: 'offsec' | 'soc' | 'feedback';
  agent: string;
  phases: Record<string, PhasePromptConfig>;
}

// 모든 도메인이 동일 형식으로 등록
export const agentRegistry: AgentPhaseConfig[] = [
  // offsec
  { domain: 'offsec', agent: 'pentester', phases: { ... } },
  { domain: 'offsec', agent: 'va-auditor', phases: { ... } },
  { domain: 'offsec', agent: 'verifier', phases: { ... } },
  { domain: 'offsec', agent: 'offsec-lead', phases: { ... } },
  // soc
  { domain: 'soc', agent: 'soc-reporter', phases: { ... } },
  { domain: 'soc', agent: 'soc-investigator', phases: { ... } },
  { domain: 'soc', agent: 'soc-report-evidence-reviewer', phases: { ... } },
  // feedback
  { domain: 'feedback', agent: 'feedback-analyst', phases: { ... } },
  { domain: 'feedback', agent: 'feedback-reviewer', phases: { ... } },
  { domain: 'feedback', agent: 'feedback-normalizer', phases: { ... } },
];
```

---

### 3.4 C6: engine.ts 확장 (fail-forward + context 격리) ⭐⭐

**문제 1**: `validateResult()` throw → phase 종료. 재시도/보정 없음.
**문제 2**: 이전 phase 잔여물이 다음 phase context에 누적.

**변경**: engine.ts `executePhase()`에 재시도 루프 + context 정리 삽입.

```typescript
// engine.ts executePhase 확장 (개념)
async executePhase(options) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const outcome = await this.runSession(options);
    
    try {
      const result = this.input.adapter.validateResult({ value: outcome.structuredOutput, ... });
      this.input.adapter.validateAcceptedResult?.({ result, ... });
      return result; // 성공
    } catch (validationError) {
      if (isSafetyViolation(validationError)) throw validationError; // 안전 위반은 즉시 중단
      
      if (attempt < maxAttempts) {
        // 재시도: 에러 피드백을 다음 시도 context에 포함
        options.retryContext = {
          previousError: validationError.message,
          attempt,
        };
        continue;
      }
      
      // 최종 시도도 실패: record+continue
      this.qualityCollector.record({
        type: 'validation-failure',
        phase: options.id,
        severity: 'error',
        detail: validationError.message,
      });
      return buildPartialResult(outcome, validationError);
    }
  }
}
```

**context 격리**: 각 phase 시작 시 이전 phase의 raw 출력을 정리. `buildPrompt()`가 이전 phase의 **artifact 경로**만 전달하고, 실제 내용은 모델이 Read로 필요 시 접근.

**전 도메인 적용**: engine.ts는 모든 도메인이 공유하므로 한 번 구현으로 전 도메인 적용.

---

### 3.5 C7: 비용 제어 + 관찰가능성 ⭐⭐

**비용 제어**:
```typescript
// src/runtime/workflow/cost-guard.ts
export interface CostGuardPolicy {
  maxAttemptsPerPhase: number;      // 기본 3 (본실행 1 + retry 2)
  maxTotalCostUsd: number;          // 미션 전체 상한
  maxTokensPerSession: number;      // 세션당 토큰 상한 (context 폭발 방지)
}
```

**관찰가능성**: 기존 `TelemetrySink` 확장
```typescript
export interface PhaseMetrics {
  runId: string;
  phase: string;
  domain: string;
  inputTokens: number;
  outputTokens: number;
  contextWindowUsage: number;       // % — 오염 모니터링 핵심 지표
  attempts: number;
  validationPassed: boolean;
  qualityIssues: QualityIssue[];
  duration: number;
}
```

---

### 3.6 C2: 출력 검증 강화 (기존 확장) ⭐

**현재**: `DomainAdapter.validateResult()`가 Zod/계약 검증 수행. 실패 시 throw.

**변경**: 기존 `validateResult()`에 retry 의도를 표현하는 결과 타입 추가.

```typescript
// DomainAdapter 확장
export interface ValidationOutcome {
  status: 'pass' | 'retry' | 'record-continue' | 'safety-fail';
  data?: PhaseResult;
  error?: string;
  corrections?: Record<string, unknown>;  // 자동 보정된 필드
}
```

- `pass`: 정상 통과
- `retry`: 재시도 가치 있음 (형식 오류, 파싱 실패 등)
- `record-continue`: 기록하고 계속 (논리 불일치, evidence 부족 등)
- `safety-fail`: 즉시 중단 (compliance claim, 민감정보 유출 등)

**전 도메인 적용**: 모든 DomainAdapter가 `ValidationOutcome`을 반환하도록 통일.

---

### 3.7 C5: 방법론 → Phase 전이 코드화 ⭐

**현재**: methods/*.md를 모델이 Read로 참조. 계약 JSON이 phase 순서를 선언하지만, 전이 **조건**은 없음.

**변경**: Phase 전이 조건을 코드로 표현. 모델에게 방법론을 주입하되, 전이 결정은 호스트가 함.

```typescript
// src/runtime/workflow/transitions.ts
export interface TransitionPolicy {
  from: string;
  to: string;
  condition(state: PhaseState): { allowed: boolean; reason?: string };
}
```

**전 도메인 적용**: offsec/soc/feedback 각각의 transition 규칙을 동일 형식으로 정의.

---

## 4. OffSec 병렬화 + 큐 고도화

### 4.1 현재 상태

```
Gateway → BullMQ (nunchi-offsec) → Worker × 1 (concurrency:3) → assess() 순차 실행
                                      ↓
                            계약 maximumConcurrency: 4
                            계약 maximumWorkUnits: 128
```

### 4.2 목표

```
Gateway → BullMQ (nunchi-offsec)
              │
              ├── 우선순위 큐 (priority 1-5)
              ├── rate limiter (per-tenant, 선택적)
              ├── 중복 제거 (commit SHA)
              └── 재시도 정책 (exponential backoff)
              │
              ▼
    ┌─────────────────────────────────────┐
    │        OffSec Worker Pool            │
    │                                      │
    │  Worker-1 ──→ assess() ──→ result   │
    │  Worker-2 ──→ assess() ──→ result   │
    │  Worker-3 ──→ assess() ──→ result   │
    │  Worker-4 ──→ assess() ──→ result   │
    │                                      │
    │  각 Worker 내부:                     │
    │  work-unit도 최대 4 병렬 (계약)      │
    │                                      │
    │  Work-Unit 부분 실패:                │
    │  → 개별 work-unit retry (최대 2회)   │
    │  → 전부 실패 시 부분 결과로 converge │
    └─────────────────────────────────────┘
```

### 4.3 큐 고도화 설계

```typescript
// src/gateway/job/queue-config.ts
export interface DomainQueueConfig {
  domain: string;
  concurrency: number;
  priority: boolean;
  rateLimiter?: {                  // 선택적 — 미설정 시 무제한
    max: number;
    duration: number;
    groupKey?: string;
  };
  retry: {
    attempts: number;
    backoff: { type: 'exponential' | 'fixed'; delay: number };
  };
  timeout: number;
  deduplication?: {
    key: (job: Job) => string;
    window: number;
  };
}

export const QUEUE_CONFIGS: Record<string, DomainQueueConfig> = {
  offsec: {
    domain: 'offsec',
    concurrency: 4,
    priority: true,
    // rateLimiter: 미설정 → 무제한. 필요 시 config에서 활성화
    retry: { attempts: 2, backoff: { type: 'exponential', delay: 30_000 } },
    timeout: 3_600_000,
    deduplication: {
      key: (job) => `${job.tenantId}:${job.input.options?.ref ?? ''}`,
      window: 300_000,
    },
  },
  feedback: {
    domain: 'feedback',
    concurrency: 8,
    priority: false,
    retry: { attempts: 3, backoff: { type: 'exponential', delay: 5_000 } },
    timeout: 900_000,
  },
  soc: {
    domain: 'soc',
    concurrency: 6,
    priority: true,
    retry: { attempts: 2, backoff: { type: 'exponential', delay: 10_000 } },
    timeout: 600_000,
    deduplication: {
      key: (job) => (job.input.metadata as Record<string,string>)?.signalId ?? job.id,
      window: 300_000,
    },
  },
};
```

### 4.4 API Rate Limit (선택적 Config)

```typescript
// src/runtime/config/rate-limit.ts
export interface ApiRateLimitConfig {
  enabled: boolean;                // false → 무제한
  maxRequestsPerMinute?: number;   // 클러스터 전체 합산
  maxTokensPerMinute?: number;     // 입력+출력 합산
  implementation: 'redis-token-bucket' | 'none';
}

// 환경변수로 제어:
// API_RATE_LIMIT_ENABLED=false (기본: 무제한)
// API_RATE_LIMIT_RPM=600
// API_RATE_LIMIT_TPM=2000000
```

미설정/빈칸 시 **무제한** 사용. 필요 시 config만 변경해 활성화.

### 4.5 Work-Unit 부분 실패 처리

```typescript
// assess.ts executeBoundedWork 확장
async function executeWithRetry(unit: WorkUnit, maxRetries: number): Promise<UnitResult> {
  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await executeUnit(unit);
    } catch (error) {
      if (attempt > maxRetries) {
        // 최종 실패: 부분 결과 생성
        return { unitKey: unit.unitKey, status: 'partial-failure', error: error.message };
      }
      // retry: 에러 기록 후 재시도
      qualityCollector.record({
        type: 'work-unit-retry',
        phase: `va:${unit.unitKey}`,
        severity: 'warn',
        detail: `attempt ${attempt} failed: ${error.message}`,
      });
    }
  }
}

// converge phase는 부분 결과를 수신:
// - 성공 unit: 정상 findings 포함
// - partial-failure unit: "이 unit은 분석 완료되지 않았음" 표기
// - 최종 보고서에 coverage gap으로 명시
```

### 4.6 OffSec Worker Pool 배포

```yaml
services:
  offsec-worker:
    deploy:
      replicas: 4
      resources:
        limits: { memory: 8G }
    environment:
      WORKER_CONCURRENCY: "1"    # 프로세스당 1 job (assess 내부 4 work-unit 병렬)
      API_RATE_LIMIT_ENABLED: "false"  # 기본 무제한
```

### 4.7 큐 모니터링

```typescript
export interface QueueHealth {
  domain: string;
  waiting: number;
  active: number;
  delayed: number;
  failed: number;
  completed24h: number;
  avgDurationMs: number;
  oldestWaitingAge: number;
}
// GET /api/v1/admin/queues
```

---

## 5. 전 도메인 통합 형식

모든 도메인이 동일한 구조를 따르도록 **기존 DomainAdapter에 optional 메서드 추가** (별도 인터페이스 생성 안 함):

### 5.1 DomainAdapter 확장 (기존 generic 타입 안전성 보존)

```typescript
// 기존 DomainAdapter<TContract, TPhase, TResult>에 추가되는 optional 메서드
export interface DomainAdapterExtensions {
  sanitizeToolResult?(toolName: string, output: string): string;
  resolveKnowledgeFiles?(phase: string): string[];
  canTransition?(from: string, to: string, state: PhaseState): { allowed: boolean; reason?: string };
  validateResultV2?(value: unknown, phase: unknown, ctx: unknown): ValidationOutcome;
}
```

기존 `validateResult()`는 그대로 유지. 새 `validateResultV2()`는 engine.ts 재시도 루프에서만 호출.
미구현 시 engine.ts가 기존 `validateResult()`를 try/catch로 래핑해 동일 동작.

### 5.2 도메인별 적용

| 메서드 | offsec | soc | feedback |
|---|---|---|---|
| `sanitizeToolResult` | ✅ (타겟 코드) | ✅ (로그) | ✅ (문서) |
| `resolveKnowledgeFiles` | ✅ (47K줄 선별) | 선택 | 선택 |
| `canTransition` | ✅ | ✅ | ✅ |
| `validateResultV2` | M10 구현 | M10 구현 | 이미 record+continue |

### 5.3 Quality Gate Reform 전 도메인 확장

`QualityIssueCollector`를 `src/runtime/quality-issues.ts`로 범용화:

**offsec 적용**: finding evidence 실패→record, work-unit 불일치→record+retry
**soc 적용**: advisory action 형식→record+auto-correct, evidence locator→record

---

## 6. CH015 포팅 연계 (docs/026 품질 향상 통합)

### 6.1 시너지

| 포팅 항목 | 리팩토링 연계 | 효과 |
|---|---|---|
| **Selective Read Protocol** | C8 (KB 선별) + C3 (새니타이징) | 500줄+ 파일 부분 읽기 → context 포화 방지 |
| **Attack Surface Priority (P0-P3)** | C1 (phase 프롬프트 선별) | VA phase에 우선순위 지시만 주입 |
| **도메인별 P0 정의** | C8 (KB overlay 선별) | AI/Native 프로젝트 시 해당 overlay만 로드 |

### 6.2 Selective Read → engine.ts 연동

```typescript
interface EngineReadPolicy {
  maxFullReadLines: number;        // 기본 500 (selective-read 규칙)
  enforcePartialRead: boolean;
}
```

### 6.3 Attack Surface → buildPrompt() 연동

VA phase 프롬프트에 recon Phase 0-7 결과를 `[CH015 Attack Surface Context]`로 주입.

### 6.4 포팅 + 리팩토링 통합 순서

| 단계 | 작업 | 선행 |
|------|------|------|
| P0-port | selective-read + recon P0-7 + context-loading 포팅 | 없음 (즉시) |
| M7 | KB frontmatter + resolveKnowledgeFiles | P0-port |
| P1-port | ai-agent + native-client overlay 포팅 | M7 |
| M8 | phase-prompt 선별 (Attack Surface 주입 포함) | P0-port + M7 |

---

## 7. 마이그레이션 순서 (최종)

| 단계 | 작업 | 규모 | 위험 | 독립 |
|------|------|------|------|------|
| **M1** | 관찰가능성 (PhaseMetrics + contextWindowUsage) | S | 낮음 | ✅ |
| **M2** | sanitize.ts + DomainAdapter.sanitizeToolResult | S | 낮음 | ✅ |
| **M3** | QualityIssueCollector 범용화 + offsec/soc 적용 | M | 중간 | ✅ |
| **M4** | 큐 고도화 (priority, dedup, optional rate limiter) | M | 낮음 | ✅ |
| **M5** | offsec Worker Pool 4 replicas + work-unit retry | S | 낮음 | M4 |
| **M6a** | engine.ts 재시도 루프 (기존 throw 기반, try/catch 래핑) | M | 중간 | M3 |
| **M7** | KB frontmatter + 선별 로드 + CH015 포팅 연동 | M | 낮음 | P0-port |
| **M8** | Agent phase-prompt 선별 조립 + Attack Surface 주입 | M | 중간 | M1, M7 |
| **M9** | DomainAdapterExtensions optional 메서드 추가 | S | 낮음 | M2, M3 |
| **M10** | ValidationOutcome + validateResultV2 | M | 중간 | M6a |
| **M6b** | engine.ts retry를 ValidationOutcome 기반으로 전환 | M | 중간 | M10 |
| **M11** | 비용 제어 (CostGuard) | S | 낮음 | M1 |
| **M12** | Phase 전이 조건 코드화 (canTransition) | S | 낮음 | ✅ |
| **P0** | CH015 Selective Read + recon P0-7 포팅 | S | 낮음 | ✅ |
| **P1** | CH015 ai-agent + native-client overlay 포팅 | S | 낮음 | M7 |

**총 예상**: 10-12주
**체크포인트**: M3→eval, M6a→Linkerd 재실행, M8→eval

---

## 8. Gateway 호환성 계약

| 보장 항목 | 이유 |
|---|---|
| `DomainHandler.process(job)` 시그니처 불변 | gateway worker 진입점 |
| Job lifecycle 상태 불변 | 큐/모니터링 의존 |
| `assess()`, `feedback()`, `socReport()` public API 불변 | gateway handler 호출 |
| BullMQ 큐 이름 (`nunchi-{domain}`) 불변 | worker discovery |
| SSE event 형식 (새 type은 additive) | 클라이언트 호환 |
| PostgreSQL: additive migration만 | 기존 데이터 보존 |

### DB Migration

```sql
-- src/gateway/migrations/003-fail-forward.sql
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS quality_issues JSONB DEFAULT '[]';
ALTER TABLE job_events ADD COLUMN IF NOT EXISTS attempt INT DEFAULT 1;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS partial_results JSONB;
```

### Result Router 확장

부분 완료(quality issues 포함) 시 result router가 정상 처리:
- PR comment: "분석 완료 (일부 검증 미통과 항목 N건 포함)"
- Slack reply: 요약 + quality issues 요약 포함
- SSE: `event: completed` + `data.qualityIssues: [...]`

---

## 9. 테스팅 전략

| 레벨 | 범위 | 기준 |
|---|---|---|
| **Unit** | sanitize, quality-issues, prompt-builder, cost-guard, transitions, rate-limit | 80%+ branch |
| **Integration** | engine.ts retry, work-unit retry+partial, DomainAdapter V2 | 실패→retry→성공 |
| **Resilience** | Redis 단절, worker crash, lease 경합(4 replicas) | 재연결/복구 |
| **E2E** | gateway → 4 offsec workers → 동시 완주 | 4 webhook 동시 |
| **Regression** | eval:offsec, eval:soc, eval:feedback | ±5% |
| **Red-team** | sanitize.ts 우회 (Claude-specific injection) | 성공률 < 5% |
| **Cost** | retry 비용 폭발 방지 | phase당 ≤3 attempts |

**각 M-step**: `pnpm test:all` 필수. 실패 시 롤백.

---

## 10. 의도적으로 하지 않는 것

| 항목 | 이유 |
|---|---|
| agents/*.md → .ts 파일 이동 | .md 유지 + buildPrompt()에서 섹션 추출이면 충분 |
| 별도 Orchestrator 클래스 | engine.ts가 이미 역할 수행 |
| Hook JS → TS 전면 재작성 | ROI 낮음. SDK CJS 필수. 기존 테스트 통과 중 |
| UnifiedDomainAdapter 별도 인터페이스 | 기존 generic DomainAdapter에 optional 추가가 적절 |
| systemPrompt 토큰 상한 | eval 기반 결정. 인위적 제한 없음 |
| KB RAG/임베딩 | 현재 규모에서 과잉. frontmatter로 충분 |
| API rate limit 하드코딩 | config 분리, 빈칸 시 무제한 |

---

## 11. 위험 관리

| 위험 | 완화 |
|---|---|
| engine.ts retry가 기존 동작 깨짐 | extensions optional; feature flag per-run |
| SDK 버전 업데이트로 hook 변경 | SDK 고정 + probe-*.ts 검증 |
| offsec 4병렬 리소스 경합 | 워커당 1 job, 내부 work-unit만 병렬, 8G 제한 |
| 새니타이징이 정상 출력 훼손 | 최소 패턴만. red-team eval 측정 |
| 큐 고도화 중 job 유실 | Redis AOF, maintenance window |
| quality gate가 잘못된 결과 통과 | verify phase 종합 판단. safety만 즉시 중단 |
| prompt 선별이 필수 지시 누락 | eval 비교. 점수 저하 시 롤백 |
| 병렬 워커 상태 충돌 | 독립 engagement. 공유 없음 |
| work-unit 부분 실패 | 개별 retry → 최종 실패 시 partial result로 converge |
| M6/M10 의존성 | M6a(throw 기반)→M10(ValidationOutcome)→M6b(전환)으로 분리 |

---

## 12. 검증 기준

| 기준 | 목표 | 측정 |
|---|---|---|
| eval 점수 | ±5% | eval:offsec, eval:soc, eval:feedback |
| fail-forward 완주율 | 90%+ 최종 phase 도달 | 10회 중 9회+ |
| 컨텍스트 사용률 | phase 평균 < 60% | PhaseMetrics.contextWindowUsage |
| offsec 동시 처리 | 4 동시 assess 완주 | 4 webhook 동시 |
| 큐 SLA | 대기 < 5분 | QueueHealth.oldestWaitingAge |
| 비용 제어 | phase당 ≤3 attempts | PhaseMetrics.attempts |
| injection 방어 | red-team < 5% | sanitize eval |
| work-unit retry | 부분 실패 → 재시도 후 정상화 | retry 로그 확인 |
