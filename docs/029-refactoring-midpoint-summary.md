# 리팩토링 완료 정리 (2026-08-14 18:08)

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

## 완료 현황

### M-Steps 진행 (12/12 완료)

| 단계 | 내용 | 상태 | 신규 테스트 | 핵심 파일 |
|------|------|------|-------------|-----------|
| M1 | 관찰가능성 (PhaseMetrics) | ✅ | +5 | `src/runtime/workflow/phase-metrics.ts` |
| M2 | 도구 출력 새니타이징 | ✅ | +11 (vendor) | `domains/offsec/hooks/sanitize-tool-output.js` |
| M3 | QualityIssueCollector 범용화 | ✅ | +8 | `src/runtime/quality-issues.ts` |
| M4 | 큐 고도화 (priority/dedup/retry) | ✅ | +13 | `src/gateway/job/queue-config.ts`, `deduplication.ts` |
| M5 | offsec 4 replicas | ✅ | docker | `docker-compose.yml` (replicas:4, concurrency:1) |
| M6a | engine.ts 검증 재시도 | ✅ | +6 | `src/runtime/workflow/engine.ts` |
| M7 | KB 선별 로드 | ✅ | +9 | `src/runtime/knowledge/loader.ts` + 20 frontmatter |
| M8 | phase-prompt 선별 조립 | ✅ | +15 | `src/runtime/agents/phase-prompt-filter.ts` |
| M9 | DomainAdapterExtensions (canTransition) | ✅ | +19 | `src/runtime/domains/domain-adapter.ts` + 3 adapters |
| M10 | ValidationOutcome + validateResultV2 | ✅ | +8 | `src/runtime/domains/domain-adapter.ts`, `engine.ts` |
| M11 | CostGuard (phase당 비용 상한) | ✅ | +18 | `src/runtime/workflow/cost-guard.ts` |
| M12 | Phase 전이 조건 코드화 | ✅ | +16 | `src/runtime/workflow/transitions.ts` |

### 검증 결과

| 항목 | 값 |
|------|-----|
| pnpm typecheck | ✅ pass |
| host tests (vitest) | 658 passed, 6 skipped |
| vendor tests | 607+ passed, 0 fail |
| gateway tests | 179 passed |
| contract resources | in sync |
| git diff --check | clean |
| GPT-5.6-sol 독립 검수 | APPROVED (10건 피드백 전부 반영 후) |
| Linkerd feedback 체크포인트 | ✅ exit 0, awaiting-input (3 phase 완료) |
| Docker services | 6 healthy (gateway, feedback×2, postgres, redis, minio) |

### 신규/수정 파일 목록

**신규 생성 (리팩토링):**
- `src/runtime/workflow/phase-metrics.ts` — M1
- `src/runtime/__tests__/phase-metrics.test.ts` — M1
- `src/runtime/quality-issues.ts` — M3
- `src/runtime/__tests__/quality-issues.test.ts` — M3
- `src/gateway/job/queue-config.ts` — M4
- `src/gateway/job/deduplication.ts` — M4
- `src/gateway/__tests__/queue-config.test.ts` — M4
- `src/runtime/__tests__/engine-retry.test.ts` — M6a
- `src/runtime/knowledge/loader.ts` — M7
- `src/runtime/__tests__/knowledge-loader.test.ts` — M7
- `src/runtime/agents/phase-prompt-filter.ts` — M8
- `src/runtime/__tests__/phase-prompt-filter.test.ts` — M8
- `domains/offsec/hooks/sanitize-tool-output.js` — M2
- `domains/offsec/hooks/test/sanitize-tool-output.test.js` — M2
- `src/runtime/workflow/cost-guard.ts` — M11
- `src/runtime/__tests__/cost-guard.test.ts` — M11
- `src/runtime/workflow/transitions.ts` — M12
- `src/runtime/__tests__/transitions.test.ts` — M12
- `src/runtime/__tests__/can-transition.test.ts` — M9
- `src/runtime/__tests__/validation-outcome.test.ts` — M10

**수정 (리팩토링):**
- `src/runtime/workflow/engine.ts` — M1 metrics + M6a retry + M10 validateResultV2 + M11 CostGuard 연동
- `src/runtime/session.ts` — M7 KB files + M8 filtered prompt
- `src/runtime/domains/offsec.ts` — M7 resolveKnowledgeFiles + M9 canTransition
- `src/runtime/domains/feedback.ts` — M9 canTransition
- `src/runtime/domains/soc.ts` — M9 canTransition
- `src/runtime/domains/domain-adapter.ts` — M7 optional method + M9 PhaseTransitionState/TransitionDecision/canTransition + M10 ValidationOutcome/validateResultV2
- `src/runtime/offsec-contract.ts` — M3 quality collector
- `src/runtime/soc-artifacts.ts` — M3 quality collector
- `src/runtime/feedback-quality-issues.ts` — M3 re-export shim
- `src/runtime/feedback-validation.ts` — quality gate reform (이전 세션)
- `src/runtime/feedback-analysis.ts` — quality gate reform
- `src/runtime/feedback-analysis-review.ts` — quality gate reform
- `src/runtime/feedback-contract.ts` — quality gate reform
- `src/runtime/feedback-standards.ts` — quality gate reform
- `src/runtime/feedback-payload.ts` — SDK $schema/oneOf fix
- `src/runtime/soc-contract.ts` — SDK $schema/oneOf fix
- `src/gateway/job/queue.ts` — M4 config 적용
- `src/gateway/workers/runner.ts` — M4 concurrency
- `src/gateway/workers/offsec-entry.ts` — M4+M5 config + env override
- `src/gateway/workers/feedback-entry.ts` — M4 config
- `src/gateway/workers/soc-entry.ts` — M4 config
- `src/gateway/router.ts` — M4 dedup
- `domains/offsec/hooks/hooks.json` — M2 PostToolUse 등록
- `domains/offsec/knowledge-base/**/*.md` (20개) — M7 frontmatter
- `docker-compose.yml` — M5 replicas

### 핵심 성과

1. **fail-closed → fail-forward**: feedback 파이프라인이 6번 연속 중단에서 1번에 완주로 개선
2. **검증 재시도**: engine.ts에 validation retry (최대 3회, feature flag) + ValidationOutcome V2로 구조화
3. **새니타이징**: SDK PostToolUse hook으로 injection 패턴 차단 (Read/Grep/Bash)
4. **컨텍스트 최적화**: KB 선별(phase별) + prompt 선별(feedback phase에서 ~40-50% 감소)
5. **병렬화**: offsec 4 replicas × 1 concurrent, 큐 priority/dedup/retry
6. **전 도메인 quality gate**: offsec 6건 + soc 3건 + feedback 44건 = 53건 hard-fail → record+continue
7. **비용 안전망**: CostGuard — phase당/run 전체/session 토큰 상한, engine.ts retry 루프에 연동
8. **전이 코드화**: canTransition (3 도메인) + TransitionPolicy pre-flight API
9. **구조화 검증**: ValidationOutcome (pass/retry/record-continue/safety-fail) + engine.ts 자동 디스패치

### M9–M12 세부 설계

#### M9: canTransition (DomainAdapterExtensions)

`DomainAdapter` 인터페이스에 `canTransition?(from, to, state): TransitionDecision` optional 메서드 추가.

**전 도메인 구현:**
- **offsec**: 예산 소진 가드 + feedback phase 반복 상한 (`maxFeedbackIterations`) + converge 전제조건
- **feedback**: 예산 가드 + draft→verify 순서 가드
- **soc**: 예산 가드 + judge/analyze→verify 순서 가드

**타입 정의 (`domain-adapter.ts`):**
- `PhaseTransitionState` — completedPhases, runStatus, totalCostUsd, maxBudgetUsd, completedAttemptsByPhase
- `TransitionDecision` — { allowed, reason? }

#### M10: ValidationOutcome + validateResultV2

기존 throw 기반 `validateResult`를 보완하는 구조화 인터페이스:

```typescript
interface ValidationOutcome<TResult> {
  status: 'pass' | 'retry' | 'record-continue' | 'safety-fail';
  data?: TResult;
  error?: string;
  corrections?: Record<string, unknown>;
}
```

**engine.ts 통합:**
- `validatePhaseResult()` private 메서드가 V2 존재 시 우선 디스패치
- `ValidationRetryError` — 항상 retry 대상
- `ValidationSafetyError` — 즉시 중단, retry 불가
- `record-continue` — 부분 결과 반환 + quality event 발행
- V2 미구현 시 기존 `validateResult` + `validateAcceptedResult` fallback

#### M11: CostGuard

```typescript
interface CostGuardPolicy {
  maxAttemptsPerPhase: number;      // 기본 3
  maxTotalCostUsd?: number;         // run 전체 상한
  maxCostPerPhaseUsd?: number;      // phase 단위 상한
  maxTokensPerSession?: number;     // session 토큰 상한
}
```

**engine.ts 연동:**
- `WorkflowHost` 생성자에 `costGuardPolicy?: CostGuardPolicy` optional 입력
- retry 루프 진입 전 `checkCostGuard()` — 초과 시 throw
- `attempt.received` 후 `recordPhaseAttempt()` — 누적 기록
- env 변수 기반 파싱: `NUNCHI_MAX_COST_USD`, `NUNCHI_MAX_PHASE_COST_USD`, `NUNCHI_MAX_SESSION_TOKENS`, `NUNCHI_MAX_PHASE_ATTEMPTS`
- NaN env 값은 안전하게 undefined 처리

**검사 우선순위:** attempts > total-cost > phase-cost > session-tokens

#### M12: Phase 전이 코드화

**역할:** 미션 오케스트레이터(assess.ts, feedback.ts 등)를 위한 **pre-flight query API**.

`engine.ts`의 runtime enforcement(`assertWorkflowPrerequisites`)와 별도로, 전이 허용 여부를 사전에 질의.

```typescript
// Pre-flight query (does NOT throw)
evaluateTransition(contract, adapter, from, to, state): TransitionDecision

// Run state → PhaseTransitionState 변환
buildPhaseTransitionState(snapshot): PhaseTransitionState

// 모든 가능 전이 스캔
availableTransitions(contract, adapter, currentPhase, state): Array<{phase, decision}>
```

`TransitionPolicy` 인터페이스는 `@planned` future extension으로 유지.

### 설계서 현황

| 문서 | 내용 | 상태 |
|------|------|------|
| docs/021 | 서비스 플랫폼 아키텍처 | 확정 |
| docs/022 | Phase 2 offsec webhook | 구현 완료 |
| docs/023 | Phase 3 SOC event ingress | 구현 완료 |
| docs/024 | Phase 1 gateway + feedback | 구현 완료 |
| docs/025 | Gateway API Reference | 작성 완료 |
| docs/026 | CH015 포팅 계획 | 검토 완료, P0 대기 |
| docs/027 | 리팩토링 설계서 v3 | GPT APPROVED, **M1~M12 구현 완료** |
| docs/028 | 리팩토링 실행 계획 (checkpoint) | 완료 |
| docs/029 | 리팩토링 완료 정리 (본 문서) | **최종** |

### 기술 스택 현황

| 계층 | 기술 | 상태 |
|------|------|------|
| Runtime | Claude Agent SDK 0.3.229 + Node 22 | 가동 중 |
| Gateway | Hono + BullMQ + PostgreSQL + Redis | 가동 중 (Docker) |
| 큐 | BullMQ (priority, dedup, exponential retry) | M4 적용 완료 |
| DB | PostgreSQL 16 + migrations (001, 002) | 가동 중 |
| 도구 보안 | PostToolUse sanitize hook | M2 적용 완료 |
| 관찰가능성 | PhaseMetrics (stderr JSON) | M1 적용 완료 |
| 품질 관리 | QualityIssueCollector (전 도메인) | M3 적용 완료 |
| 비용 제어 | CostGuard (env-driven, engine 연동) | M11 적용 완료 |
| 전이 가드 | canTransition (3 도메인) + TransitionPolicy API | M9+M12 적용 완료 |
| 검증 V2 | ValidationOutcome + engine.ts 디스패치 | M10 적용 완료 |

### GPT-5.6-sol 검수 이력

**초기 검수 (M9–M12):** NEEDS_CHANGES — 3 major, 4 minor, 3 nit

**수정 후 재검증:**
- Major 1: TransitionPolicy `@planned` 문서화 + evaluateTransition 역할 명시 → 해결
- Major 2: CostGuard engine.ts 연동 (checkCostGuard + recordPhaseAttempt) → 해결
- Major 3: (Major 1과 통합) evaluateTransition/assertWorkflowPrerequisites 관계 문서화 → 해결
- Minor: NaN 검증, 반복 코드 리팩터, 누락 테스트, boundary 테스트 추가 → 전부 해결
- Nit: 테스트 이름 수정, record-continue quality event 발행 → 해결

**최종 상태:** 모든 검수 항목 반영 완료
