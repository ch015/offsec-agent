# secops-offsec-agent

문서 기준: 2026-09-18. [현재 개발 현황](../docs/development-status.ko.md) · [문서 목록](docs/README.md)

기존 앱에서 직접 호출하는 공개 API: [`createOffsecAgent`](src/index.ts). `pnpm build:library` 후 모듈 import로 사용할 수 있습니다. [코드 연동 가이드](docs/embedding.md) · [앱 예제](../examples/embedded-app/agents.mjs)

취약점 진단(OffSec) 전용 로컬 에이전트. **Claude Agent SDK 호스트**가
`domains/offsec` 로컬 플러그인을 로드하고, 역할별 SDK 세션과 병렬 작업 단위를 조율한다.

이 리포는 `secops-nunchi-agent` 멀티 도메인 플랫폼에서 OffSec 그룹만 분리한
독립 모듈·로컬 CLI 버전이다. SOC·Feedback 도메인, HTTP 게이트웨이, 워커 큐,
MCP 배포 표면은 포함하지 않는다.

## 구조

```
domains/offsec/      취약점 진단 그룹 = 로컬 플러그인 1개 (확장 표면)
  .claude-plugin/    플러그인 매니페스트
  contracts/         호스트가 강제하는 버전 계약, JSON Schema, 표준 registry
  methods/           phase별 짧은 실행 방법 카드
  agents/*.md        계약 agentFile이 가리키는 system prompt 정본·직접 플러그인 호환
  skills/            방법론 문서
  hooks/hooks.json   도메인 게이트·불변식 (SDK가 실행한다)
  lib/               이식·보완한 게이트 구현 (CommonJS)
  package.json       {"type":"commonjs"} — 리포는 ESM이므로 모듈 타입을 국소화한다

src/index.ts         앱용 공개 API (createOffsecAgent + native 미션/recovery exports)
src/api/             인증·이벤트·취소·engagement lock을 연결하는 factory
src/runtime/
  offsec-contract.ts  계약 로드·참조·phase 결과 검증
  finding-contract.ts 증거 재대조와 submit_finding 원장
  objection-contract.ts verifier objection 집계·검증
  session.ts          Options 조립 — 격리·명시적 role·훅·원장
  session-types.ts    도메인·세션 스펙 타입 (이 리포는 offsec 단일 도메인)
  domains/            도메인 어댑터 + 레지스트리 (offsec만 등록)
  workflow/           host 상태 기계·work-plan·의존성 그래프·scope assurance·상태 저장소
  live-*.ts           라이브 DAST 브로커·세션·증거 계약 (PENTEST 경로)
  missions/assess.ts        취약점 진단 진입점 (v1 — pentest/redteam/feedback loop)
  missions/assess-v2.ts     취약점 진단 진입점 (v2 — 선형 6-phase 파이프라인)
  missions/assess-resume.ts PostgreSQL 백엔드 run 재개 진입점 (v1)
  providers/          Anthropic Agent SDK provider 런타임

scripts/             SDK 계약 프로브·offsec 평가·admin 유틸리티
evals/offsec/        고정 산출물 evaluator·벤치마크 러너·스코어링
docs/                OffSec 관련 결정과 관측 기록
```

## 출처

방법론과 저수준 검증기는 `ch015-pentester`에서 이식한 뒤 호스트 실행에 맞춰 보완했다.
실행 계약은 `domains/offsec/contracts/offsec-contract.v1.json`과 `offsec-contract.v2.json`이며
미션에 맞는 버전을 시작 시 검증한다.
자세한 내용은 `domains/offsec/README.md` 참조.

## 실행

### 전제 조건

- Node.js ≥ 22.18.0, pnpm (최근 검증 환경: Node 22.18.0 / pnpm 9.15.0)
- `pnpm install` 완료
- Claude Agent SDK 인증·설정 사용 가능 (`ANTHROPIC_API_KEY` 또는 OAuth profile)

> **참고**: tree-sitter 네이티브 바인딩은 `lib/ch015/ast/`의 AST 분석에 필요하다.
> 설치 도구의 build-script 정책으로 네이티브 빌드가 생략됐다면 tree-sitter 빌드를 허용하고
> 다시 설치해야 한다. `pnpm approve-builds`는 해당 명령을 제공하는 pnpm 버전에서만 사용한다.
> (typecheck·대부분의 테스트는 네이티브 빌드 없이 통과한다.)

모든 플래그는 `--key=value` 형식만 지원한다 (`--key value` 불가).

### 취약점 진단 (assess — v1)

> **v1**은 pentest/redteam/feedback loop·verifier·objection 시스템을 포함한 진단 경로다.
> 선형 파이프라인 v2는 아래 [취약점 진단 (assess — v2)](#취약점-진단-assess--v2) 참조.

```bash
# 기본 실행 — model=opus, review-model=sonnet, max-turns=120, verification=VA_ONLY
pnpm assess /absolute/path/to/target

# 범위 지시문 추가
pnpm assess /absolute/path/to/target "인증 모듈과 API 라우터만 진단"

# 읽기 전용 대상이면 쓰기 가능한 engagement 디렉토리 지정 (새 디렉토리 또는 빈 디렉토리)
pnpm assess /absolute/path/to/target --engagement-dir=/tmp/eng-001

# 모델을 명시적으로 변경 (model ≠ review-model 필수)
pnpm assess /absolute/path/to/target --model=sonnet --review-model=haiku
```

기본 출력은 `<target>/.nunchi/reports/<engagementId>/`에 기록된다.
비어 있지 않은 기존 engagement 디렉토리는 retry/resume 경로를 제외하고 거부된다.

#### assess 옵션

| 플래그 | 값 / 설명 |
|---|---|
| `--model=<id>` | 주 모델 (기본 `opus`) |
| `--review-model=<id>` | 리뷰 모델 (기본 `sonnet`); model과 달라야 함 |
| `--effort=<low\|medium\|high\|max>` | 진단 깊이 |
| `--max-turns=<n>` | 최대 턴 (기본 120) |
| `--max-usd=<n>` | 비용 상한 |
| `--verification-mode=<mode>` | `VA_ONLY` (기본) · `VA_PENTEST` · `VA_PENTEST_REDTEAM` |
| `--semgrep=<mode>` | `required` (기본) · `best-effort` · `off` |
| `--work-units=<mode>` | `auto` (기본) · `force` · `off` |
| `--max-concurrency=<n>` | 병렬 work-unit 수 |
| `--engagement-dir=<path>` | 결과 출력 절대 경로 (새/빈 디렉토리 권장) |
| `--test-url=<url>` | PENTEST 모드 필수; `http(s)://…` — credentials/fragment 불가 |
| `--live-test-profile=<path>` | 승인된 live-test profile JSON 경로 |
| `--auth-interaction=<mode>` | `remote-handoff` · `local-headed-browser` · `none` |

#### OffSec 동작

- **근거 무결성 유지** — source manifest·checkpoint·작업 계획·산출물 receipt의 해시를 검증
- **발행 게이트 강제** — 초안 작성과 최종 발행은 별도이며, 호스트 검증 실패 시 발행 차단
- **Objection 미해결 시 진행** — feedback 상한 도달 후에도 converge → report 진행
- **제한된 재시도** — 재시도 가능한 실패 unit은 1회 재시도; timeout 단위는 즉시 재시도하지 않음. 같은 run 안의 검증된 cross-attempt artifact 참조 허용
- **Host 자동 보정** — finding/objection count를 host가 추적하고 자동 보정
- **병렬 실행** — `maxConcurrency`와 계약 상한 안에서 작업 단위 실행

#### Work-Unit 자동 분할

`work-units=auto`는 소스 파일 ≥ 50개이고 분할 결과가 2개 이상일 때 활성화된다.
활성화된 run은 다음 산출물을 생성한다:

- `00_dependency_graph.json`, `00_work_plan.json` (V2), `00_work_unit_results.json`, `00_scope_assurance.json`
- 최종 보고서: `07_security_report.md`

#### PENTEST 모드 (live 테스트)

명시적으로 승인된 비운영 대상·profile에 한해서만 사용한다.

```bash
pnpm assess /absolute/path/to/target --verification-mode=VA_PENTEST \
  --test-url=https://staging.example.com \
  --live-test-profile=/path/to/approved-profile.json \
  --auth-interaction=remote-handoff
```

#### 로컬 headed-browser 재개

PostgreSQL backend로 시작한 run에 대해:

```bash
pnpm assess:resume -- --engagement-dir=<path> --request-id=<id> \
  --request-sha256=<sha256> --expected-version=<n>
```

### 취약점 진단 (assess — v2)

v2는 v1의 pentest/redteam/feedback loop·verifier·objection 시스템을 제거한 **선형
6-phase 파이프라인**이다. 계약 정본은 `domains/offsec/contracts/offsec-contract.v2.json`
(`version: 2.0.0`, `leadRole: reporter`)이다.

#### v2 워크플로

```
recon → plan → analyze → review → evaluate → report
```

| phase | 실행 주체 | 산출물 (요약) |
|---|---|---|
| `recon` | host | `00_recon.json`, `00_dependency_graph.json` (+ `00_ast_context.yaml`, semgrep preanalysis) |
| `plan` | host | `01_analysis_plan.json` (+ `00_work_plan.json`) |
| `analyze` | analyzer | `02_analysis_result.md`, `02_findings_index.yaml` (work-unit별 병렬 실행) |
| `review` | reviewer | `03_review_result.json` (모든 finding을 실제 코드와 재대조) |
| `evaluate` | evaluator | `04_evaluation.json`, `04_evaluation_classification.yaml` |
| `report` | reporter | `07_security_report.draft.md` → 발행 시 `07_security_report.md` |

`recon`·`plan`은 host가 결정론적으로 실행하고, `analyze`는 work-unit 단위로 병렬 실행되며,
`review`·`evaluate`·`report`는 root host가 계약 검증 아래 순차 실행한다. v1과 달리
verifier objection·feedback iteration이 없다. v2는 항상 작업 단위를 사용하며 `--work-units=off`는 거부한다. 병렬 분석은 전체 예산을 나눠 예약하고, 일부 단위 실패는 미검토 파일 공개 및 종료 코드 2로 표시한다.

#### v2 역할 (roles)

| 역할 | 담당 | 도구 |
|---|---|---|
| `analyzer` | 8차원 보안 아키텍처 진단·증거 기반 취약점 후보 생성 | Read, Grep, Glob, Bash, Write, submit_finding |
| `reviewer` | 분석 산출물의 모든 finding을 실제 코드와 대조·보정 | Read, Grep, Glob, Write, submit_finding |
| `evaluator` | 커버리지·심각도·전체 보안 수준 객관 평가 | Read, Grep, Glob, Write |
| `reporter` | 평가 결과 기반 최종 보고서 초안 작성 (lead role) | Read, Grep, Glob, Write |

#### v2 실행

```bash
# 기본 실행 — model=opus, review-model=sonnet, semgrep=required, work-units=auto
pnpm assess:v2 /absolute/path/to/target

# 범위 지시문 추가
pnpm assess:v2 /absolute/path/to/target "인증 모듈과 API 라우터만 진단"

# 쓰기 가능한 engagement 디렉토리 명시 (새/빈 디렉토리)
pnpm assess:v2 /absolute/path/to/target --engagement-dir=/tmp/eng-v2-001

# 모델 변경 (model ≠ review-model 필수)
pnpm assess:v2 /absolute/path/to/target --model=sonnet --review-model=haiku
```

v2 assess 플래그는 v1과 동일하되 pentest 전용 플래그(`--verification-mode`,
`--test-url`, `--live-test-profile`, `--auth-interaction`)는 지원하지 않는다:
`--model`, `--review-model`, `--effort`, `--max-turns`, `--max-usd`, `--semgrep`,
`--work-units`, `--max-concurrency`, `--engagement-dir`.

#### v2 출력 구조

v2는 대상 리포 하위의 `.nunchi` 디렉토리에 engagement를 기록한다 (자동으로 `.gitignore` 생성):

```
<target>/.nunchi/
  .gitignore                         # 산출물 전체 미추적 (취약점 상세 포함)
  reports/<engagementId>/            # engagement 루트
    00_recon.json
    00_dependency_graph.json
    00_ast_context.yaml
    01_analysis_plan.json
    00_work_plan.json
    work-units/<unitKey>/attempt-N/  # analyze phase per-unit 산출물
    00_work_unit_results.json        # host가 집계한 unit 결과
    00_scope_assurance.json
    standard-findings/               # 승격된 finding 원장
    02_analysis_result.md
    03_review_result.json
    04_evaluation.json
    07_security_report.md            # 최종 발행 보고서 (draft → rename)
    host-ledger.jsonl                # host 실행 원장
```

`--engagement-dir`로 절대경로를 지정하면 `.nunchi/reports/<id>` 대신 해당 경로에 기록한다.
비어 있지 않은 기존 engagement 디렉토리는 거부된다.

### 평가 (고정 산출물 evaluator — agent 실행·live 품질이 아님)

```bash
pnpm eval:offsec                # OffSec 고정 후보 산출물 evaluator
pnpm eval:offsec:run            # OffSec 벤치마크 러너
pnpm eval:offsec:adjudicate     # 벤치마크 판정
pnpm eval:offsec:prepare-pilot  # 파일럿 준비
```

> **v1/v2 어댑터**: 벤치마크 정규화 어댑터는 계약 버전별로 분리돼 있다. v1 산출물은
> `evals/offsec/adapters/current.ts`, v2 산출물은 `evals/offsec/adapters/current-v2.ts`가
> 각 계약의 phase 순위로 finding lineage를 정규화한다. `policy.json`의 `declaredClaims`는
> v2가 생성하지 않는 `pentest`·`redteam-iac`를 제외하고 `semgrep`·`large-repository`만
> 선언한다. 벤치마크 러너·판정 스크립트(`run-offsec-benchmark`, `adjudicate-offsec-benchmark`)와
> A/B 비교(`scripts/ab-compare.ts`)는 아직 v1 phase 마커·objection YAML을 전제로 하므로
> v2 산출물에는 직접 적용할 수 없다(v2 지원은 후속 작업).

### 로컬 PostgreSQL & 공유 상태 실행 (선택)

기본은 로컬 파일 상태 저장소다. resume/lease를 위한 공유 PostgreSQL 백엔드를 쓰려면:

```bash
pnpm db:local:start && pnpm db:local:migrate

NUNCHI_STATE_BACKEND=postgres NUNCHI_DATABASE_URL=<url> \
  NUNCHI_ARTIFACT_ROOT=<shared artifact path> \
  NUNCHI_SHARED_ENGAGEMENT_ROOT=<shared run path> \
  pnpm assess /absolute/path/to/target
```

### 운영 (admin)

```bash
pnpm run:admin -- inspect --engagement=<path> --run-id=<id>
pnpm run:admin -- recover-publication --engagement=<path> --run-id=<id>
```

### 프로브 & 테스트

```bash
pnpm probe:offsec <대상>    # 플러그인 로드·훅 발화·도구 제한 확증
pnpm probe:plugin           # SDK 플러그인 계약 재확인 (docs/002 재현)
pnpm probe:entry-agent      # entry agent 계약 프로브
pnpm typecheck              # tsc --noEmit
pnpm test                   # vitest (host 계약 테스트)
pnpm test:vendor            # OffSec 벤더 테스트 + self-test
pnpm test:all               # 계약 리소스 + typecheck + host tests + vendor tests
```

## 환경변수

`.env.example` 참조. 주요 항목:

| 변수 | 용도 |
|------|------|
| `ANTHROPIC_API_KEY` | Anthropic API 인증 |
| `AUTH_MODE` | `api_key` (기본) · `oauth` |
| `ASSESS_PRIMARY_MODEL` | 주 모델 기본값 |
| `ASSESS_REVIEW_MODEL` | 리뷰 모델 기본값 |
| `ALLOW_SAME_MODEL` | 개발 중 primary/review 동일 모델 허용 |
| `NUNCHI_STATE_BACKEND` | `postgres`이면 공유 상태 백엔드 사용 |
| `NUNCHI_DATABASE_URL` | PostgreSQL 연결 문자열 |
| `NUNCHI_ARTIFACT_ROOT` | 공유 artifact 루트 |
| `NUNCHI_SHARED_ENGAGEMENT_ROOT` | 공유 run 루트 |

## 설계 근거

실행 정본은 `domains/offsec/contracts/`의 버전 계약이다. 역할, phase, 도구,
preload skill, 격리, JSON Schema를 계약에서 읽고 호스트가 검증한다. v1은
`offsec-contract.v1.json`, v2는 `offsec-contract.v2.json`이 정본이며, 런타임이 시작 시
계약 버전을 확인한다 (`assess-v2`는 `2.x` 계약만 허용).

### v1 (assess)

Verifier objection이 feedback 상한 후에도 남아 있으면 converge에서 DISPUTED/PENDING으로
분류해 보고서 초안으로 전달할 수 있다. 이 흐름이 최종 발행 승인을 뜻하지는 않는다.
호스트가 source·범위·증거·보고서 게이트를 검증하며 실패하면 최종 발행을 차단한다.
Cross-attempt artifact는 같은 run의 검증된 경로만 허용한다. 재시도 가능한 단위 실패는
1회 재시도하며 timeout된 단위는 중첩 실행을 막기 위해 즉시 재시도하지 않는다.

### v2 (assess:v2)

v2는 v1의 pentest/redteam/feedback loop·verifier·objection 시스템을 완전히 제거하고
`recon → plan → analyze → review → evaluate → report` 선형 파이프라인으로 단순화했다.
검증은 별도 verifier phase 대신 `review` phase가 모든 finding을 실제 코드와 재대조하는
방식으로 수행하고, `evaluate` phase가 커버리지·심각도를 객관 평가한 뒤 `reporter`(lead
role)가 초안을 작성하고 호스트 게이트가 최종 발행한다. `analyze`는 work-unit 단위 병렬 실행이며, 완료 unit이
하나라도 있으면 진행한다(부분 완료는 `quarantinedUnits`/`uncoveredFiles`로 기록). 출력은
대상 리포 하위 `.nunchi/reports/<id>`에 격리되고 `.gitignore`로 자동 미추적 처리된다.

평가 어댑터(`evals/offsec/adapters/`)와 정책(`evals/offsec/policy.json`)은 계약 버전에
맞춰 분리한다. v1 산출물은 `current.ts`(v1 phase 순위: va/verify/pentest/redteam …), v2
산출물은 `current-v2.ts`(v2 phase 순위: recon/plan/analyze/review/evaluate/report)로
정규화한다. `policy.json`의 `declaredClaims`는 v2가 생성하지 않는 `pentest`·`redteam-iac`
주장을 제거하고 v2에서도 유효한 `semgrep`·`large-repository`만 남긴다.

## 확장

OffSec 호스트 역할·phase를 추가할 때는 계약과 해당 role/method card를 함께 갱신해야 한다.
런타임은 계약에 없는 역할, 위임, raw Bash를 실패-폐쇄 방식으로 거부한다.

게이트를 붙일 때는 `domains/offsec/hooks/hooks.json`에 한 항목을 추가한다.
커맨드 경로에는 반드시 `${CLAUDE_PLUGIN_ROOT}`를 쓴다 — 훅의 `cwd`는 플러그인
디렉토리가 아니라 진단 대상이다.

행동 자율성, 종료 조건 및 운영 변경은 [에이전트 행동 지침](docs/agent-autonomy.md)을 참조한다.
