# Compaction identity hardening — Claude Sonnet 5 independent review

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

## Scope and outcome

This document records the independent Claude Sonnet 5 review of the completed
current-worktree implementation described by:

- `docs/012-compaction-identity-hardening-spec.md`
- `docs/013-compaction-identity-hardening-plan.md`
- `docs/014-compaction-identity-hardening-execution.md`
- `docs/015-compaction-identity-hardening-audit.md`

The worker reviewed acceptance criteria 1–16 and attempted to falsify the
correctness, security, replay/idempotency, and event-ordering claims. It found
no reproducible defect and therefore made no production-code or test-code
change. This was intentionally a review-only result rather than a duplicate
implementation.

The evidence interpretation remains bounded: compaction-time identity omission
is a confirmed contributing cause in the observed failures, not a universal or
exclusive cause.

## Model and Orca provenance

- Orca runtime: `2d7d6d10-1ded-4dfa-99df-6cbb01d3d656`
- Run: `run_faa37d1680e4`
- Task: `task_af12e342c2d6`
- Requested Claude model ID: `claude-sonnet-5`
- Completed Dispatch: `ctx_1a9ac0f59483`
- Completed worker terminal: `term_564ec189-7928-4baa-a193-d44de668cfc1`
- Claude session: `954aabb6-7f7b-4957-aa9f-b497976db62c`
- Worker completion message: `msg_b927a2a55009`
- Delivery: `delivery_dbb8d5fc9597`, acknowledged

The normal `worker-start --agent claude --model claude-sonnet-5` receipt for the
first attempt, Dispatch `ctx_1f4f5afe756e`, reported both
`launch.requested.model` and `launch.effective.model` as exactly
`claude-sonnet-5`. Its task injection nevertheless reached a bare `zsh` prompt
instead of a Claude TUI and failed there with a shell parse error. The worker did
not begin the review. The coordinator treated this as a startup anomaly, not as
a worker result, and used `worker-stop`; Orca closed exact terminal
`term_beaee72f-0221-410e-8ebd-218ae858e0f5`.

The replacement used the same current worktree and an explicitly created
terminal command:

```text
claude --model claude-sonnet-5
```

The coordinator waited for `tui-idle` before binding the replacement through
`worker-start --retry-of ctx_1f4f5afe756e --terminal ...`. Orca then returned a
Claude transcript source and the injected lifecycle preamble was present in the
actual provider transcript. The resulting local Claude session metadata records
`"model":"claude-sonnet-5"`, independently confirming the effective model for
the completed review.

The Task and replacement Dispatch settled `completed`; the Dispatch failure
count is `0`. `worker-release` correctly retained the replacement because it
was a coordinator-created external terminal, after which the coordinator closed
that exact terminal. No unrelated terminal or worktree was changed.

## Independent acceptance review

### Host authority, criteria 1–6

Passed. The provider-facing work-unit identity is optional and permissive while
the surrounding schema remains strict. `WorkflowHost` requires a plain object,
clone-binds the canonical host identity before adapter validation, classifies
the raw provider identity as `absent`, `matched`, or `overridden`, preserves
non-identity validation, leaves root phases unchanged, and returns/persists the
bound result.

### Compaction resilience and observability, criteria 7–12

Passed. A work-unit `PostCompact` arms one pending reminder, and the next
`PreToolUse` consumes it once. Host-side result binding does not depend on the
reminder or on a later tool call. Typed compact-boundary metadata survives
provider success and `ProviderRuntimeFailure`, is appended before receipt or
failure lifecycle events, and excludes compact summary/source/user-prompt
content. The result-binding audit event carries the required disposition.

### Compatibility and safety, criteria 13–16

Passed. The two event types are additive, replay-idempotent, and
snapshot-neutral. File and PostgreSQL stores consume the shared event schema
and replay path, with a text event type and no migration requirement. Existing
usage, lease, artifact, method-read, ledger, verifier-sealing, and work-plan
barriers remain unchanged and pass regression. No dependency, secret logging,
contract bump, transcript-filesystem dependency, or migration was added.

## Findings and observations

No confirmed defect was found. Two informational observations remain:

1. If the first `PreToolUse` after compaction is denied, the host still consumes
   the one-shot reminder on that call. Whether the SDK exposes
   `additionalContext` from a deny decision to the model is a live SDK/provider
   behavior not established here. Host-owned result binding remains independent
   of that behavior, so this does not violate the acceptance criteria.
2. The PostgreSQL integration suite has no test dedicated specifically to the
   two new audit event types. Static parity is established by the shared schema,
   replay implementation, and non-enum text column, but no live PostgreSQL
   integration was run in this review.

Neither observation justified implementation churn under the approved scope.

## Worker validation

The Sonnet worker independently reported:

```text
Targeted Vitest: 6 files passed, 76 tests passed
pnpm typecheck: passed
contract resource check: in sync
pnpm test:all: exit 0
  host: 48 files passed, 1 skipped; 302 passed, 6 skipped
  live-dast.integration.test.ts: 2 passed
  vendor: 554 passed, 0 failed, 0 skipped
pnpm vitest run src/runtime/__tests__/assess.test.ts: 15 passed
git diff --check: passed
```

## Coordinator independent verification

After the accepted `worker_done`, the coordinator independently reran the
required checks in the same current worktree:

```text
Targeted Vitest: 6 files passed, 76 tests passed
pnpm typecheck: passed
node --import tsx scripts/generate-contract-resources.ts --check:
  contract resource manifests: in sync
pnpm test:all: exit 0
  host: 48 files passed, 1 skipped (49 total)
  host tests: 302 passed, 6 skipped (308 total)
  live-dast.integration.test.ts: 2 passed
  vendor: 554 passed, 0 failed, 0 skipped
git diff --check: passed
```

The scoped status inspection found no additional tracked diff attributable to
the Sonnet review. The pre-existing broad uncommitted/untracked current-worktree
state was preserved.

## Remaining limits

- No live provider/model compaction smoke was run. This review does not claim a
  model-quality improvement or production closure.
- The six environment-gated PostgreSQL integration tests remained skipped
  because `NUNCHI_DATABASE_URL` and a live PostgreSQL service were not supplied.
- The deny-path reminder observation requires a bounded live SDK/provider probe
  if operational evidence is later required; it is not a host-binding blocker.

## Canonicalization steering provenance

[STEERING steer-040c4f454224424ebf8a865260fc6774: spec·plan 정본을 루트 docs로 이관하고 최종 audit 번호를 조정했다.]

[STEERING steer-dbefc10f56e2434a83d0f80317823ec6: ASX에서 필요한 spec·plan·workflow/self-review 상태를 docs/012~014에 보존하고, 재생성 가능한 cache/skills와 빈 goals/artifacts는 이관 불필요로 분류해 이후 작업의 ASX 의존을 제거했다.]
