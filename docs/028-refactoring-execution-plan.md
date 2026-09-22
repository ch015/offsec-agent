# 027 리팩토링 실행 계획 (Context Checkpoint)

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

**작성일**: 2026-08-14
**상태**: GO (조건부 승인)
**설계서**: docs/027-refactoring-design.md v3

## 실행 조건 (GPT-5.6-sol 최종 검토 결과)

| # | 조건 | 해결 방법 | 시점 |
|---|---|---|---|
| 1 | C3 새니타이징 SDK 훅 포인트 확인 | M2 시작 전 0.5일 spike | M2 착수 시 |
| 2 | M6a engine 재시도 규모 → L로 상향 | M6a-1(파싱 에러만 단순 retry) → M6a-2(전체) 분할 | M6a 착수 시 |
| 3 | inter-phase context 오염 가정 → 실제는 intra-phase | C3/C6 설계를 tool output 내 오염에 집중 | 즉시 인지 |

## 실행 순서 (첫 3단계)

### M1: 관찰가능성 (S, 2-3일)

**목표**: PhaseMetrics + contextWindowUsage 수집. 기존 TelemetrySink 확장.

**구현 범위**:
- `src/runtime/workflow/phase-metrics.ts` 생성
- engine.ts `executePhase()` 전후에 메트릭 수집 삽입
- 메트릭: inputTokens, outputTokens, contextWindowUsage(%), attempts, duration, domain, phase
- state-store에 기록 (기존 run-events.jsonl 활용)
- 단위 테스트

**검증**:
- pnpm test:all 통과
- 로컬 feedback 실행 시 메트릭 출력 확인 (console.log 또는 event)
- 5회 이상 실행으로 baseline 데이터 확보

**dead code**: 없음 (additive only)
**rollback**: 메트릭 수집 코드 제거하면 원복

---

### M2: sanitize.ts (S, 2-3일 + spike 0.5일)

**spike**: SDK `query()` 내부에서 tool result를 가로채는 방법 확인
- PostToolUse hook에서 `tool_response`를 수정 가능한지
- 불가 시: tool wrapper approach (tool 정의를 래핑하는 방식)

**구현 범위**:
- `src/runtime/sanitize.ts` 생성
- 패턴: `[SYSTEM]`, `<instructions>`, `<|im_start|>`, XML delimiter injection
- 길이 제한: maxChars (기본 8000)
- DomainAdapter에 `sanitizeToolResult?()` optional 메서드 추가
- 20개 injection 테스트 케이스 corpus
- 단위 테스트

**검증**:
- pnpm test:all 통과
- injection corpus 20/20 차단 확인
- 정상 도구 출력 5개 통과 확인 (훼손 없음)

**dead code**: 없음 (신규 모듈)
**rollback**: sanitize.ts 제거 + adapter 메서드 삭제

---

### M3: QualityIssueCollector 범용화 (M, 1주)

**구현 범위**:
- `src/runtime/feedback-quality-issues.ts` → `src/runtime/quality-issues.ts` 이동/범용화
- domain 필드 추가
- offsec 적용: `src/runtime/offsec-contract.ts` 검증 실패 지점에 record+continue
- soc 적용: `src/runtime/soc-contract.ts` + `src/runtime/soc-artifacts.ts`
- 기존 feedback 경로 유지 (import path 변경만)
- 단위 테스트 + offsec/soc 검증 실패 시나리오 테스트

**검증**:
- pnpm test:all 통과
- eval:offsec, eval:soc, eval:feedback 기존 ±5%
- offsec finding evidence 실패 시 record 확인 (throw 안 함)

**dead code**: `feedback-quality-issues.ts` → `quality-issues.ts`로 이동 후 원본 삭제. import path 변경.
**rollback**: git revert (원본 파일 복원)

---

## 각 단계별 GPT-5.6-sol 피드백 루프

```
구현 → typecheck → test → GPT review → 수정 → 최종 확인
```

매 M-step 완료 시:
1. `pnpm typecheck` 통과
2. `pnpm test:all` 통과
3. dead code 검증 (`grep -r` 미사용 export 확인)
4. GPT-5.6-sol 독립 검토 (설계 대비 정확성, 오버스펙, 미사용 코드)
5. 수정 필요 시 Opus 4.6 correction → GPT 재검토
6. APPROVED 후 다음 단계 진행

## 현재 codebase 상태 기록

| 항목 | 값 |
|---|---|
| branch | main |
| 최근 typecheck | pass |
| 최근 test | 541 passed, 6 skipped |
| gateway tests | 166 passed |
| Docker 서비스 | gateway + feedback-worker×2 + postgres + redis + minio (healthy) |
| SDK 버전 | @anthropic-ai/claude-agent-sdk@0.3.229 |
| Claude CLI | 2.1.229 |
| 주요 수정 파일 (이번 세션) | feedback-validation.ts, feedback-analysis.ts, feedback-analysis-review.ts, feedback-contract.ts, feedback-standards.ts, feedback-payload.ts, soc-contract.ts, missions/feedback.ts |
| 신규 파일 (이번 세션) | src/runtime/feedback-quality-issues.ts, src/gateway/** (전체), docs/021~027 |
