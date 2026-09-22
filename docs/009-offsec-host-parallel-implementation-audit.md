# OffSec host-parallel implementation audit

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

Date: 2026-08-05

## Bounded conclusion

The host-parallel OffSec path is implemented and deterministic regression tests pass, but capability
superiority over CH015 is not established. The comparison result remains `not_run` because no frozen
three-arm observation corpus, CH015 headless adapter, authorized live target, or live-provider run was
available. Feature presence and passing unit tests are not treated as comparative performance evidence.

## Implemented and verified

- The normalized workflow contract declares the `assess` entrypoint, sealed VA/Verify work set,
  concurrency and unit bounds, all-required barrier, and direct-phase prohibition.
- Source manifests exclude prior report and agent-tool state, split oversized monoliths deterministically,
  assign every selected source file exactly once, and bind per-file bytes and hashes. Root and worker
  sessions receive exact sealed read lists instead of the target root. Runtime source freshness rescans
  are intentionally disabled; deployment must provide an immutable or read-only checkout.
- Local pinned Semgrep sorts inputs and findings before truncation, validates result paths, records rule,
  executable and per-source byte hashes, and receives the complete source-manifest list plus applicable
  IaC files. Findings remain candidates, not trusted conclusions.
- Unit VA/Verify runs use isolated source sets. Verifier objections enter a bounded unit feedback loop.
  Unit typed Finding records are hash-checked, promoted by the host into the root ledger, and must be
  represented in the final report.
- Pentest uses a sealed source-first plan and a bounded host HTTP broker. A live-confirmed Finding must
  bind source evidence, scenario, immutable receipt, observed impact, and inferred impact. The plan and
  receipts are revalidated before publication, and the report must cite the receipt.
- Red Team uses a dedicated source-readable, network-denied role and a sealed IaC applicability manifest
  with per-file hashes and explicit `not_applicable` coverage.
- Evaluation rejects case target/corpus drift and paired evaluator-version drift. Holdout opening state is
  fixed outside result paths, bound to corpus and policy hashes, atomically claimed, and append-audited.
  Library evaluation output is explicitly diagnostic-only.

## Verification record

- `pnpm test:all`: passed. Vitest reported 222 passed and 6 skipped; the OffSec vendor suite and self-tests
  also exited successfully.
- `node --import tsx scripts/generate-contract-resources.ts --check`: contract resources in sync.
- `git diff --check`: passed.
- Static checks passed for the changed runtime, contract, evaluation, manifest, Semgrep, and broker files.
  `assess.ts` passed with an explicit 1,200-line ceiling and currently has 1,041 lines.
- `pnpm eval:offsec -- --mode=deterministic`: recorded `not_run`; no superiority claim was emitted.

## Remaining limits

- The HTTP broker is deliberately read-only: GET/HEAD and optional Accept only. It does not yet cover
  authenticated headers, request bodies, POST/PUT/PATCH, browser flows, or state-changing API checks.
- The evaluator scores supplied observations but does not yet launch the CH015, current-sequential, and
  current-parallel arms. The CH015 adapter command, frozen corpus/labels, credentials, and authorized live
  target remain external inputs.
- A failed work-unit wave blocks safely. There is no transient-error classifier, automatic retry, or
  automatic concurrency-to-one replay; operators can explicitly choose the sequential path.
- Runtime source mutation detection is intentionally disabled. The deployment is responsible for making
  the checkout immutable or read-only; the host continues to validate plans, output artifacts, and receipts.
- Dependency context resolves common JavaScript/TypeScript and Python relative imports. Other language,
  build-system, and alias edges are recorded unresolved rather than silently claimed as covered.
- PostgreSQL-backed execution currently clamps work-unit concurrency to one. Real shared-backend parallel
  scheduling and crash-resume evidence remain outside this local verification.
- Real Semgrep execution and live model/provider behavior were not re-run in this verification; Semgrep
  process behavior was tested with deterministic fixtures.

## Bias and confidence check

The implementation was challenged by a separate read-only reviewer. Reproducible findings were converted
to tests or retained above as limits. No conclusion is based on prompt length, agent count, feature count,
or the earlier CH015 comparison narrative. The only comparative status supported by current evidence is
`not_run`/`inconclusive`.
