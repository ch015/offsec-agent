# Three-domain production readiness baseline

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)

- Baseline captured: 2026-08-05T00:50:26Z
- Repository: `secops-nunchi-agent`
- Runtime: Node `v22.18.0`, pnpm `10.14.0`, Vitest `3.2.7`
- Worktree: pre-existing changes were present before this baseline; they are not attributed to Wave 0.
- Scope: deterministic local tests and static labelled-fixture aggregation only. No live provider or live source call was made. Current post-baseline changes are recorded in `008-readiness-gap-closure-audit.md`.

## Reproducible baseline commands

| Command | Result | Observed evidence |
|---|---|---|
| `pnpm test:all` | PASS, exit 0 | TypeScript check passed; Vitest passed 24 files and 151 tests; OffSec vendor Node tests and self-tests passed. |
| `pnpm exec vitest run src/runtime/__tests__/domain-references.test.ts src/runtime/__tests__/workflow-contract.test.ts src/runtime/__tests__/offsec-contract.test.ts src/runtime/__tests__/feedback-contract.test.ts src/runtime/__tests__/soc-contract.test.ts` | PASS, exit 0 | Vitest resolved 12 files and 44 tests; all passed. |
| `pnpm eval:feedback` | PASS, exit 0 outside sandbox | Five static, human-labelled cases were aggregated. This is not an execution-based agent-quality result. |

The first sandboxed `pnpm eval:feedback` attempt failed before the evaluator ran because `tsx` could not create its Unix IPC pipe (`listen EPERM`). The same command was then run successfully with the required external execution approval. This is an environment limitation, not a passing product test result.

## Readiness matrix

| Area | Current evidence | Readiness state | Next planned boundary |
|---|---|---|---|
| Contract resources | OffSec, Feedback, and both SOC contracts independently pin exact role, skill, method, and schema resources with SHA-256; generator parity and cache revalidation pass. | Contract boundary verified; deployment drift still gated | Deployment must preserve the separately managed contract/resource artifacts. |
| Durable run state | `FileRunStateStore` remains a fixture backend; local PostgreSQL couples run events, fencing, immutable receipts, and outbox rows transactionally. | Local PostgreSQL verified; deployment inputs remain open | Platform-owned migration, shared artifact, outbox consumer, and test database. |
| Recovery and idempotency | Typed inspect/reconcile/resume uses expected version, lineage, and fencing; incomplete provider attempts are not silently rerun. | File and local PostgreSQL transitions verified | Provider crash recovery and multi-worker deployment rehearsal remain open. |
| SOC source boundary | Sealed snapshot, typed redaction receipt, and offline prepared-snapshot CLI are tested. No approved live connector exists. | Offline snapshot verified; live source blocked | Wave 4: CLI first; live adapter remains blocked until external inputs arrive. |
| Model quality | Feedback has a five-case provenance-labelled deterministic runner; SOC has a six-case adversarial deterministic runner. No live provider, repeated model trial, cross-provider comparison, or calibration evidence exists. | Deterministic fixture regression only | Owner-approved live/repeated evaluation remains separate. |
| Standards and unported assets | Feedback has pinned curated ASVS indexes with source metadata and safe locator checks. OffSec unported paths are classified per asset in the decision registry. | Bounded mapping; semantic applicability remains human-gated | No normative-text or compliance claim is inferred. |
| Operational actions/publication | Case mutation, notification, containment, WAF changes, and external publication connectors are outside the current contracts. | Explicit non-goal/deferred | Separate approved command contracts only. |

## Baseline interpretation

The passing commands prove deterministic host and fixture behavior at this revision. The local PostgreSQL integration proves the repository transaction boundary, not a deployed database or shared artifact topology. The commands do not prove production readiness, semantic entailment, live provider quality, source truthfulness, multi-worker crash recovery, or regulatory compliance. Those claims remain gated by the external decisions in the plan.

The machine-readable decisions and unresolved external inputs are recorded in [`three-domain-decision-registry.json`](../../secops-agent-feedback/docs/three-domain-decision-registry.json).

## Wave 1 progress

Wave 1 now has a shared `ContractResourceSchema` and validation helper for normalized safe paths, duplicate rejection, exact resource-set matching, file existence, and SHA-256 verification. OffSec, Feedback, and both SOC contracts independently declare their role, skill, method, and schema resources. OffSec schema definitions are also materialized as separately pinned JSON resources, while the loader checks that they still equal the contract schema fields.

All three loaders hash the contract source before returning a cached contract and re-run the resource/reference validation on every cache hit. Contract resource generation is explicit and has a check mode:

```text
pnpm generate:contract-resources -- --check
contract resource manifests: in sync
```

The Wave 1 focused suite passed 17 files and 53 tests, including path traversal, duplicate/orphan, missing-file, and post-pin mutation cases. Wave 1 itself did not claim PostgreSQL state coupling, live source integration, or live model evaluation; later sections record the local PostgreSQL boundary and remaining external inputs.

## Wave 2 progress and deployment configuration

`RunStateStore` now has a synchronous file backend for fixtures and an asynchronous PostgreSQL backend for durable execution. PostgreSQL uses `pg@8.22.0`, locks the run row, checks the active fencing token, enforces the expected sequence, and commits event state plus immutable artifact receipts and outbox rows on one connection and transaction. `nunchi_run_events` protects both `(run_id, seq)` and event IDs with unique constraints.

Local development is reproducible with `pnpm db:local:start` and `pnpm db:local:migrate`. It uses PostgreSQL `14.20` at `127.0.0.1:55432/nunchi_local` and a dedicated data directory under `/private/tmp/secops-nunchi-postgres`; the stop script does not remove that directory. Runtime and deployment configuration use `NUNCHI_DATABASE_URL` (with `DATABASE_URL` as a compatibility fallback), so deployment does not inherit local host, database, or credentials.

The real PostgreSQL integration test passed with `NUNCHI_DATABASE_URL=postgresql://philip@127.0.0.1:55432/nunchi_local pnpm exec vitest run src/runtime/__tests__/postgres-run-state.integration.test.ts`: one file and two tests passed. It exercised concurrent append serialization, same-event idempotency, payload collision rejection, rollback after an immutable artifact collision, state/artifact/outbox coupling, stale fencing rejection after lease ownership changed, and PostgreSQL outbox retry/dead-letter behavior.

The remaining Wave 2 evidence is intentionally not implied: provider-response crash recovery, a production shared object-store implementation, and a live outbox consumer/delivery retry test remain Wave 3 or deployment-specific work. The deployment registry still owns supported PostgreSQL version, migration ownership, artifact backend, and shared test database decisions.

## Wave 3 progress

The common reconciliation boundary now provides typed `inspectRun`, explicit incomplete-attempt reconciliation, and lineage/version-checked resume. Reconciliation marks an incomplete attempt failed with a bounded reason code; it never silently reruns a provider call. Resume requires the expected state version, the next input revision, and both parent hashes from the awaiting-input state. The same service supports the file backend and PostgreSQL fencing-token append path.

Typed telemetry events contain run/contract identity, status, sequence, cost, counts, input revision/context hash, latency, and bounded reason codes. They exclude provider payloads, raw source text, secrets, and arbitrary error messages. File and PostgreSQL transition tests cover OffSec incomplete-attempt reconciliation, Feedback awaiting-input resume, and SOC blocked inspection. The focused Wave 3 suite passed two files and five tests.

This does not claim a deployed telemetry exporter, automatic provider crash retry, or live source integration. Those remain explicit operational/deployment work.

## Wave 4 progress

SOC prepared snapshots now require a typed redaction receipt (`policyId`, redactor version, source payload hash, removed-field list, and explicit approval). The offline `soc:snapshot` CLI validates mission, tenant, actor, required read scope, sealed hash, schema version, UTC half-open window, compact safety checks, row limit, page/page-size, and configured rate-limit bound before returning only compact paginated records plus provenance metadata. It never opens a network connection or infers a live source contract.

The focused SOC suite passed four files and 26 tests, including tenant mismatch, missing receipt, pagination, row-limit, instruction-like, secret-like, query receipt, and snapshot integrity failures. Live source authentication, source-side tenant isolation, and source truthfulness remain blocked by the external inputs in the decision registry.

## Wave 5 progress

Feedback evaluation cases preserve expected status, supported locators, forbidden claims, required questions, risk slice, reviewer rationale, and human adjudication. SOC adds unsupported entailment, alternative-hypothesis, counterevidence, partial-coverage, advisory proportionality, and injection-shaped evidence slices. The current runners compute corpus and contract-resource hashes, report point estimates and Wilson 95% upper bounds, and explicitly emit `static-labeled-fixture-aggregation`, `agentQualityMeasured: false`, and live provider/source execution set to false.

`pnpm eval:feedback` aggregates five cases and `pnpm eval:soc` aggregates six. Their `observed` values remain human-authored, so they are neither executable product regression evidence nor release thresholds. Zero-denominator, per-risk slice eligibility, human disagreement consistency, and Wilson upper-bound gates fail closed, but live model/provider quality, repeated-run variance, cross-provider comparison, and calibration remain unmeasured.

## Wave 6 progress

The decision registry now contains an `unportedAssets` list with one record per intentionally absent OffSec path. Each record has a classification, owner, decision ID, rationale, and evidence reference. `domain-references.test.ts` consumes this registry instead of a test-local exception list; it fails on new orphan references and on paths that were already ported.

Feedback standards remain limited to two pinned, official-source ASVS curated clause indexes. The loader verifies registry-to-snapshot identity, SHA-256, source metadata, safe source locators, and clause fragments. The snapshots deliberately set `normativeTextIncluded: false`: exact quote checks apply to user-source evidence, while clause semantic applicability remains a reviewer/human decision and is not an automated compliance claim.

README and the three domain review records now use the same boundary terms: local PostgreSQL is an exercised development backend, deployment database/artifact/migration inputs remain separately owned, SOC live source remains blocked by missing external contracts, and deferred publication/actions are not implemented.

Wave 6 verification passed with the following evidence: the decision registry parsed with nine classified assets; the focused standards/reference/Feedback suite passed 3 files and 20 tests; `pnpm typecheck` passed; `pnpm test:all` passed 30 files and 164 tests with 3 PostgreSQL tests skipped in the environment, and the vendor suite passed 430 tests; the externally executed PostgreSQL/reconciliation suite passed 2 files and 5 tests; `pnpm generate:contract-resources -- --check` reported `contract resource manifests: in sync`; both deterministic evaluation runners passed (Feedback 5 cases, SOC 6 cases); `asx review` passed for the four changed runtime/test files; and `git diff --check` passed. Sandboxed PostgreSQL/tsx attempts returned environment `EPERM` errors and were not counted as product failures; the required commands were rerun successfully with external execution approval.
