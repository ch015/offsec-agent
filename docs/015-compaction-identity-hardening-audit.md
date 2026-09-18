# Compaction identity hardening audit

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)

## Evidence boundary

This audit covers the current worktree implementation of the approved scope in
`docs/012-compaction-identity-hardening-spec.md` and
`docs/013-compaction-identity-hardening-plan.md`. It does not claim a live
provider/model engagement or a production compaction smoke; all correctness
claims below are based on deterministic unit/integration tests and static
verification in this worktree.

## Design implemented

- Provider-facing work-unit output now has an optional `{}` placeholder. The
  placeholder is the only permissive field; root `additionalProperties: false`
  and every other result constraint remain unchanged.
- `WorkflowHost` clones the requested `resultIdentity` into a plain provider
  object before adapter validation. Raw identity is classified as
  `absent`, `matched`, or `overridden`, and the host binding is recorded as an
  additive run event. Non-object output still fails closed.
- OffSec prompt context is explicitly host-owned scope context; the final JSON
  identity echo instruction is removed. Verifier autonomous manifest sealing
  remains host-enforced.
- A work-unit `PostCompact` hook arms a one-shot reminder. The next
  `PreToolUse` returns the exact canonical identity in `additionalContext` and
  clears the pending reminder. Compact summary text is neither read nor stored.
- SDK `compact_boundary` messages are reduced to typed trigger, token,
  duration, and boundary UUID metadata in session/provider events. Provider
  failures retain already-collected events.
- Existing file/PostgreSQL state append and fencing paths accept the additive
  `phase.context-compacted` and `phase.result-identity-bound` events. Compaction
  events precede receipt/failure; audit events do not alter status, cost, or
  completed phases and are append-idempotent.

## Files changed for this task

- `src/runtime/session-types.ts`
- `src/runtime/session.ts`
- `src/runtime/offsec-contract.ts`
- `src/runtime/providers/provider-runtime.ts`
- `src/runtime/providers/anthropic-agent-sdk.ts`
- `src/runtime/workflow/engine.ts`
- `src/runtime/workflow/state-store.ts`
- `src/runtime/__tests__/session.test.ts`
- `src/runtime/__tests__/session-stream.test.ts`
- `src/runtime/__tests__/workflow-engine.test.ts`
- `src/runtime/__tests__/state-store.test.ts`
- `src/runtime/__tests__/provider-domain.test.ts`
- `src/runtime/__tests__/offsec-contract.test.ts`
- `docs/015-compaction-identity-hardening-audit.md`

No dependency, contract version, generated resource, transcript filesystem, or
database migration was added.

## Acceptance trace

| Criterion | Evidence |
|---|---|
| Optional/permissive provider identity with strict surrounding schema | `session.test.ts` schema controls missing, wrong, malformed, invalid non-identity, and unknown-root fields. |
| Absent/exact/wrong/malformed identity | `workflow-engine.test.ts` table; all cases complete with canonical stored identity and disposition event. |
| Non-object and non-identity fail closed | `workflow-engine.test.ts` rejects array output; fixture validation rejects malformed artifacts/status. Existing OffSec adapter and assess regressions remain covered. |
| Root/non-work-unit behavior | `session.test.ts` confirms root required fields and identity schema remain unchanged; engine tests exercise no-identity paths. |
| Canonical result/downstream identity | Workflow result table asserts returned result identity equals host request after binding. |
| One-shot PostCompact reminder | `session.test.ts` runs `PostCompact -> PreToolUse -> PreToolUse` and asserts exactly one reminder. |
| No summary/source leakage | `session.test.ts` reminder assertion and `session-stream.test.ts` compact stream assertion reject summary/source text. |
| Compact metadata capture | `session-stream.test.ts` verifies typed SDK boundary normalization; `provider-domain.test.ts` verifies provider normalization. |
| Success and failure event transport | `provider-domain.test.ts` checks success and `ProviderRuntimeFailure.events`; engine failure test persists the event before receipt/failure. |
| Durable event ordering | `workflow-engine.test.ts` asserts `phase.context-compacted`, `attempt.received`, `phase.failed`, and `run.blocked` order. |
| Identity audit disposition | Workflow table asserts `absent`, `matched`, and `overridden`. |
| Idempotent, replay-neutral, snapshot-neutral events | `state-store.test.ts` appends compact event twice, reopens/replays, and checks unchanged status/cost/completed phases/attempt lifecycle. |
| File/PostgreSQL append compatibility | Events are defined in shared `RunEventSchema` and use the existing `RunStateBackend` append path; PostgreSQL parser consumes the shared union without migration. |
| Safety barriers retained | Targeted assess/work-unit tests and full deterministic suites cover artifacts, method reads, finding/objection ledgers, usage, model receipt, leases, and work-plan barriers. |

## Validation evidence

The coordinator independently reran the targeted command after worker completion:

```text
pnpm vitest run src/runtime/__tests__/session.test.ts src/runtime/__tests__/session-stream.test.ts src/runtime/__tests__/workflow-engine.test.ts src/runtime/__tests__/state-store.test.ts src/runtime/__tests__/provider-domain.test.ts src/runtime/__tests__/assess.test.ts
Test Files  6 passed (6)
Tests  72 passed (72)
```

Typecheck and resource-manifest check:

```text
pnpm typecheck
`tsc --noEmit`: passed

node --import tsx scripts/generate-contract-resources.ts --check
contract resource manifests: in sync
```

The coordinator also independently reran the required full command:

```text
pnpm test:all
exit status: 0
Host Vitest: 48 files passed, 1 skipped (49 total)
Host tests: 302 passed, 6 skipped (308 total)
live-dast.integration.test.ts: 2 tests passed
Vendor tests: 554 passed, 0 failed, 0 skipped
```

The worker's earlier sandbox run had reported one `live-dast.integration.test.ts`
failure caused by `listen EPERM: operation not permitted 127.0.0.1`, followed by
`Server is not running`. That environment-specific failure was not reproduced
by the coordinator: the same full command and the live DAST suite passed in the
final current-worktree validation.

The independent standalone vendor run also passed:

```text
pnpm test:vendor
1..452
# tests 554
# pass 554
# fail 0
# skipped 0
```

`git diff --check` was rerun after the implementation and passed with no output.

## Remaining limits

No live model compaction smoke was run, so this change does not claim a
model-quality improvement or production closure. A bounded live provider smoke
remains operational follow-up evidence. PostgreSQL compatibility is established
through the shared schema/append implementation and deterministic tests; no live
PostgreSQL integration was run because those environment-gated tests remained
skipped.

## Live-compaction-smoke status

**Not run.** Deterministic compact-boundary and host-binding regressions and the
full current-worktree host/vendor suite pass; the runtime was not connected to a
live provider/model engagement in this task.

## Claude Sonnet 5 independent follow-up

The completed implementation was independently reviewed against acceptance
criteria 1–16 by Claude Sonnet 5 through a new Orca Run/Task/Dispatch. No
reproducible defect was found and no production or test code was changed. Model
provenance, startup recovery, lifecycle settlement, informational observations,
and worker/coordinator validation evidence are recorded in
`docs/016-compaction-identity-sonnet-review.md`.
