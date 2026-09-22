# Compaction-safe immutable work-unit identity hardening

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)
> Canonical implementation plan. This document has no ASX runtime dependency.

## Goal

Opus Juice Shop run `run_1525b1d07f21`에서 확인된 다음 직접 인과를 폐쇄한다.

- `unit-300db21a3fd0a921` attempt 1과 `unit-7f4234520faaefdf` attempt 2에서 auto compaction이 발생했다.
- compact summary가 `workPlanSha256`와 `assignedSourceSha256`를 누락했다.
- 모델이 host request와 다른 identity를 StructuredOutput에 반환했고 `WorkflowHost`의 exact 비교에서 phase가 실패했다.
- `unit-7f4234520faaefdf` 실패는 `run-events.jsonl` seq 92와 terminal `run.blocked` seq 105에 직접 포함됐다.
- 반면 identity를 summary에 보존한 compacted session 4개는 모두 완료됐다. Haiku는 compaction 0개인데도 다른 계약 결함으로 blocked였다.

따라서 목표는 compaction을 금지하거나 모든 blocked를 설명하는 것이 아니라, **immutable work-unit identity가 모델 기억·요약·복사 정확도에 의존하지 않게 만들고 compaction을 engagement 원장에 관측 가능하게 하는 것**이다.

## Constraints and non-goals

- 기존 `nunchi.offsec.assessment@1.10.0`의 stored phase result와 work-plan identity 의미를 유지한다.
- identity 외의 모델 산출물, artifact, finding/objection ledger 및 usage 검증은 완화하지 않는다.
- malformed identity 때문에 모델 retry를 소비하거나 work-unit barrier를 실패시키지 않는다.
- compact summary 본문은 민감하거나 비결정적인 모델 문맥이므로 engagement 원장에 저장하지 않는다.
- SDK 내부 transcript 파일을 runtime 정본으로 의존하지 않는다.
- compaction이 아닌 artifact/count/objection/scope/provider 실패를 이번 변경으로 자동 복구하지 않는다.
- contract version bump, 데이터 backfill, 새 외부 서비스 또는 새 dependency를 도입하지 않는다.

## Current behavior

1. `src/runtime/session.ts::bindWorkUnitOutputFormat`은 provider JSON schema의 `workUnit`을 required로 만들고 세 identity 필드에 `const`를 건다.
2. `src/runtime/offsec-contract.ts::buildPhasePrompt`는 모델에 `host_work_unit_output_binding`을 마지막 JSON에 그대로 복사하라고 지시한다.
3. `src/runtime/workflow/engine.ts::executePhase`는 validated result의 `workUnit`을 `options.resultIdentity`와 exact 비교하고 다르면 실패시킨다.
4. `runSession`은 SDK stream의 `system/compact_boundary`를 소비하지만 기록하지 않는다. `host-ledger.jsonl`과 `run-events.jsonl`에는 compact metadata가 없다.
5. SDK 0.3.220은 `PostCompact` hook, `SDKCompactBoundaryMessage.compact_metadata` 및 `PreToolUseHookSpecificOutput.additionalContext`를 제공한다.

실제 run은 schema `const`와 복사 지시만으로는 충분하지 않음을 입증했다. 더 강한 retry 또는 prompt 반복만 추가하는 접근은 같은 권위 오류를 유지하므로 채택하지 않는다.

## Rejected Alternatives

### A. PostCompact prompt reinjection only

장점은 변경이 작고 모델의 후속 행동을 돕는다는 것이다. 그러나 SDK `PostCompact`에는 전용 `additionalContext` output이 없고, compaction 직후 모델이 도구 호출 없이 final output을 만들 수 있다. 모델 복사에 계속 의존하므로 단독 해법으로 부적합하다.

### B. Host authoritative output binding only

모델이 identity를 누락·변조해도 canonical result를 만들 수 있어 직접 원인을 제거한다. 다만 compaction 후 verifier manifest 등 모델 작업에 identity가 필요한 경우의 복구 UX와 사후 관측성이 부족하다.

## Chosen approach

### C. Layered host authority + one-shot reminder + durable telemetry — chosen

- provider-facing output schema에서 `workUnit`을 required identity field가 아닌 optional·permissive·host-ignored placeholder로 바꾼다. 모델에는 생성을 요구하지 않지만 관성적으로 wrong/malformed 값을 출력해도 SDK retry를 유발하지 않는다.
- provider 결과를 domain validation하기 직전에 host가 `resultIdentity`를 복제 결속한다.
- `PostCompact` 이후 최초 `PreToolUse` 응답에 immutable identity를 한 번만 `additionalContext`로 전달한다. 도구 호출이 없더라도 host binding이 최종 correctness를 보장한다.
- SDK compact boundary metadata를 provider event, `host-ledger.jsonl`, `run-events.jsonl`에 보존한다.
- 모델이 identity를 공급했는지와 host가 override했는지를 별도 run event로 남겨 결함을 숨기지 않는다.

이 접근이 correctness 권위를 host에 두면서도 token overhead를 bounded하게 유지하는 최소 변경이다.

## Ownership boundaries and files

### Runtime implementation

- `src/runtime/session-types.ts`
  - compact metadata를 실을 typed ledger field를 추가한다.
  - summary 본문을 타입에 포함하지 않는다.
- `src/runtime/session.ts`
  - `bindWorkUnitOutputFormat`을 host-owned identity placeholder 변환으로 교체한다.
  - work-unit provider schema의 `required`에서 `workUnit`을 제거하고 `properties.workUnit`은 identity를 검증하지 않는 permissive placeholder로 바꾼다. schema 전체의 `additionalProperties` 정책과 다른 필드 검증은 그대로 둔다.
  - `PostCompact` hook은 closure flag만 설정한다. compact summary는 기록하거나 재사용하지 않는다.
  - 다음 `PreToolUse` 한 번에만 canonical identity envelope를 `additionalContext`로 넣고 flag를 소진한다.
  - `runSession`이 `SDKCompactBoundaryMessage`를 만나면 trigger, pre/post token 수, duration, SDK boundary UUID만 typed ledger row로 emit한다.
- `src/runtime/providers/provider-runtime.ts`
  - `ProviderRuntimeEvent`에 typed compaction metadata를 추가한다.
  - `ProviderRuntimeFailure`가 이미 관측된 provider events를 보존할 수 있게 확장한다.
- `src/runtime/providers/anthropic-agent-sdk.ts`
  - session ledger compact row를 provider event로 normalize한다.
  - success뿐 아니라 subtype/structured-output/model-receipt failure에도 수집된 events를 `ProviderRuntimeFailure`에 첨부한다.
- `src/runtime/workflow/engine.ts`
  - raw provider result가 plain object일 때만 canonical `resultIdentity`를 clone-inject한 뒤 adapter validation을 수행한다. non-object/malformed payload는 기존처럼 실패한다.
  - raw `workUnit` 상태를 `absent | matched | overridden`으로 분류하되 canonical 값 이외에는 신뢰하지 않는다.
  - 기존 identity mismatch throw를 제거한다. identity 외 validation은 순서와 fail-closed 동작을 유지한다.
  - provider success와 `ProviderRuntimeFailure` 양쪽에서 compaction events를 attempt에 결속해 append한다.
  - work-unit result binding disposition을 run event로 기록한다.
- `src/runtime/workflow/state-store.ts`
  - additive event `phase.context-compacted`를 정의한다: attempt identity, provider, trigger, preTokens, optional postTokens/durationMs/boundaryId.
  - additive event `phase.result-identity-bound`를 정의한다: attempt identity, source=`host`, providerIdentity=`absent|matched|overridden`.
  - 두 event는 run/attempt status, usage, artifact state를 변경하지 않는 audit event다.
  - compaction event는 started/received attempt에만, identity binding은 receipt가 있는 attempt에만 허용한다.

### Prompt/contract behavior

- `src/runtime/offsec-contract.ts`
  - `host_work_unit_output_binding`을 모델이 복사해야 하는 output binding이 아니라 host-owned immutable scope context로 표현한다.
  - “마지막 JSON에 workUnit 복사” 지시를 제거하고 “final JSON에 host-owned workUnit을 생성·복구하지 말라”고 명시한다.
  - verifier autonomous manifest에 필요한 identity 사용은 유지한다. host seal 검증은 완화하지 않는다.
- `domains/offsec/contracts/offsec-contract.v1.json`
  - stored result schema가 이미 optional `workUnit`을 허용하고 host가 canonical result를 저장하므로 원칙적으로 변경하지 않는다.
  - 구현 중 실제 schema가 provider/stored schema 분리를 막는다고 확인될 때만 최소 수정하고, 그 경우 resource manifest를 재생성한다.

### Tests and final audit

- `src/runtime/__tests__/session.test.ts`
- `src/runtime/__tests__/workflow-engine.test.ts`
- `src/runtime/__tests__/state-store.test.ts`
- 필요 시 `src/runtime/__tests__/provider-domain.test.ts` 또는 작은 전용 provider test
- 필요 시 `src/runtime/__tests__/assess.test.ts`
- `docs/015-compaction-identity-hardening-audit.md`

## Steps

1. **Define canonical identity helper and audit classification**
   - engine에 field-wise exact matcher와 plain-object clone binding helper를 만든다.
   - missing/wrong/extra provider identity는 canonical host identity로 교체한다.
   - identity 이외의 payload를 변경하지 않는다.
2. **Remove model output authority**
   - work-unit session에 전달되는 SDK output schema에서 `workUnit` required를 제거하고 그 property만 permissive host-ignored placeholder로 바꾼다. 이는 모델이 필드를 생략하도록 유도하면서도 잘못 출력했을 때 identity-only SDK retry를 막는다.
   - prompt에서 final identity echo 의무를 제거한다.
   - stored domain result는 host injection 후 기존 schema로 validate한다.
3. **Add bounded post-compaction reminder**
   - `PostCompact`에서 work-unit session에만 pending reminder를 세운다.
   - 다음 `PreToolUse` 한 번에 canonical JSON envelope를 `additionalContext`로 전달하고 즉시 clear한다.
   - no-tool final response는 host binding으로 처리한다.
4. **Capture compact boundary without summary content**
   - `runSession` stream에서 `system/compact_boundary`를 명시적으로 처리한다.
   - snake_case SDK metadata를 typed internal metadata로 변환한다.
   - `compact_summary`, assistant/user text, target contents는 이벤트에 넣지 않는다.
5. **Persist lifecycle evidence**
   - Anthropic runtime success/failure가 compact events를 보존하도록 한다.
   - engine이 deterministic event ID로 `phase.context-compacted`를 receipt/failure 앞에 append한다.
   - host binding 직후 `phase.result-identity-bound`를 append한다.
   - file/PostgreSQL state backend 모두 기존 append path를 사용하고 별도 side channel을 만들지 않는다.
6. **Regression tests**
   - 아래 acceptance cases를 먼저 실패시키고 구현 후 통과시킨다.
7. **Documentation and verification**
   - direct evidence, 변경 범위, event example, 검증 결과, 남은 한계를 `docs/012-...md`에 기록한다.
   - live model rerun을 하지 않았다면 그렇게 명시하며 결함 폐쇄를 모델 품질 개선으로 과장하지 않는다.

## Acceptance criteria

### Host authority

1. work-unit provider output schema에서 `workUnit`은 required가 아니며 identity `const`/regex 검증을 하지 않는 optional host-ignored placeholder다. 다른 필드와 schema의 `additionalProperties` 정책은 유지된다.
2. provider result에 `workUnit`이 없어도 host-stored `domainResult.workUnit`은 `resultIdentity`와 정확히 같다.
3. provider result의 identity가 틀리거나 malformed여도 **그 이유만으로** phase가 실패하지 않고 canonical host identity로 교체된다.
4. provider result가 non-object이거나 identity 외 필수 field/artifact/count/ledger가 잘못되면 기존처럼 실패한다.
5. root/non-work-unit phase에는 `workUnit`을 주입하지 않는다.
6. completed event/envelope에 저장되는 canonical result와 downstream phase가 읽는 result는 동일한 host identity를 가진다.

### Compaction resilience and observability

7. `PostCompact` 이후 첫 `PreToolUse`에만 exact canonical identity reminder가 포함되고 두 번째 호출에는 반복되지 않는다.
8. compact 이후 도구 호출 없이 final output이 와도 acceptance 2–3이 성립한다.
9. compact boundary 하나당 `host-ledger.jsonl`과 `run-events.jsonl`에 trigger/preTokens/postTokens(optional)/duration(optional)/boundary ID가 남는다.
10. provider가 compact 후 실패해도 가능한 범위의 compact event가 phase failure보다 먼저 run-events에 남는다.
11. compact summary 본문과 source/user prompt 내용은 host ledger/run events에 저장되지 않는다.
12. identity binding event가 `absent|matched|overridden`을 기록해 host overwrite가 silent하지 않다.

### Compatibility and safety

13. old run-events는 migration 없이 replay된다. 새 audit events는 snapshot status/cost/completedPhases를 변경하지 않는다.
14. file backend와 PostgreSQL backend가 공통 state schema/append 경로를 유지한다.
15. usage receipt ordering, lease fencing, artifact hash, method-read, finding/objection validation 및 work-plan all-required barrier는 완화되지 않는다.
16. 새 dependency, secret logging, transcript filesystem dependency가 없다.

## Required tests

- Session schema test: work-unit provider schema makes `workUnit` optional and permissive without weakening other fields; root schema behavior unchanged.
- Hook test: `PostCompact -> PreToolUse -> PreToolUse`에서 reminder가 정확히 한 번이며 summary가 유출되지 않는다.
- Stream test: mocked SDK query가 compact boundary를 emit하면 typed ledger metadata가 수집된다.
- Provider test: compact event survives successful outcome and each `ProviderRuntimeFailure` path.
- Engine table test:
  - provider identity absent -> canonical complete + `absent` event
  - exact -> canonical complete + `matched` event
  - wrong/malformed -> canonical complete + `overridden` event
  - malformed non-identity field -> failed
  - no `resultIdentity` -> no injection/event
- State replay test: compact/binding audit events are idempotent, correctly ordered, and snapshot-neutral.
- Failure ordering test: compact event -> optional usage receipt -> phase.failed.
- Existing OffSec work-unit/assess tests to ensure downstream verifier and barrier semantics remain unchanged.

## Verification commands

Run from repository root:

```bash
pnpm vitest run \
  src/runtime/__tests__/session.test.ts \
  src/runtime/__tests__/workflow-engine.test.ts \
  src/runtime/__tests__/state-store.test.ts \
  src/runtime/__tests__/provider-domain.test.ts \
  src/runtime/__tests__/assess.test.ts
pnpm typecheck
node --import tsx scripts/generate-contract-resources.ts --check
pnpm test:all
git diff --check
```

If a listed optional test file is not modified, it still runs as regression coverage. If full `pnpm test:all` is blocked by an external service, record the exact failing command/output and run all deterministic local subsets; do not report full success.

## Risks

- **Risk: host overwrite hides model drift.** Mitigation: required `phase.result-identity-bound` disposition event; do not store untrusted malformed values.
- **Risk: generic WorkflowHost becomes OffSec-specific.** Existing `resultIdentity` is already explicit and optional; keep binding behind this option and do not affect other domains.
- **Risk: additional context increases tokens.** Reminder is one-shot per compact, work-unit only, and not sent without compaction.
- **Risk: duplicate compact events.** Use SDK boundary UUID in deterministic event ID and existing idempotency semantics.
- **Risk: failed provider loses events.** Carry collected events in `ProviderRuntimeFailure` and persist before phase.failed. A process crash before host append remains an acknowledged durability limit.
- **Risk: permissive placeholder weakens identity field validation.** Mitigation: permissiveness is limited to the one discarded provider field; schema-level `additionalProperties` and every non-identity field remain strict, and the stored result is validated only after host canonical replacement.
- **Risk: contract drift.** Stored result remains contract-conformant after host binding. Run resource-manifest check and change contract resources only if implementation proves necessary.

## Migration, rollout, and rollback

- Change is additive for run event parsing; no historical event rewrite or database migration is required.
- Roll out behind the existing presence of `executePhase.resultIdentity`; root and non-work-unit calls are unchanged.
- Before declaring production closure, run a bounded live-provider work-unit smoke that forces or naturally reaches compaction and verify canonical completion plus both audit events. This is a follow-up operational validation, not a unit-test gate if deterministic compaction forcing is unavailable.
- Rollback is code-only: restore provider identity schema/compare behavior while retaining additive event readers. Existing new events remain replayable and snapshot-neutral.

## Remaining decisions

No blocking product decision remains. Implementation must not broaden into unrelated Haiku contract/artifact/ledger failures. A live compaction smoke is desirable after deterministic regressions but is explicitly separated from this code change’s acceptance gate.
