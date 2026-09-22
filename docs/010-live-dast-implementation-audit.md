# LLM-led Live DAST implementation audit

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

- Scope: OffSec authenticated and stateful Live DAST contracts, host lifecycle, adaptive broker, independent verification, local integration fixture, and evaluation claim controls.
- Contract: `nunchi.offsec.assessment@1.9.0`; contract resources are hash-pinned.
- Authority: the host owns interaction-mode sealing, phase order, scenario validation, network execution, global operational limits, cleanup, receipt persistence, resume state, and publication gates.

## Implemented controls

The initial request seals `remote-handoff`, `local-headed-browser`, or `none` before an authentication session is created. Owner-assisted OAuth/OIDC, device, passkey, and wallet captures are stored as opaque actor-bound sessions; provider, redirect, target-origin, scope, material-kind, and chain mismatches fail closed. Runtime-first discovery is a separate `pentest-discovery` phase whose inputs intentionally exclude VA and verifier findings.

Adaptive scenarios are strict, append-only, profile-bound records. The broker enforces target prefix, method/header/body policy, run-wide request and state-change limits, timeout, redirect scope, 429 and consecutive-5xx breakers, bounded redacted output, and cleanup execution. Reversible state changes reserve both primary and cleanup request capacity. A failed cleanup remains explicit in the immutable receipt and blocks live-confirmed Finding submission and final evidence validation.

The local integration fixture executes the same role-differential, input-validation, controlled-error, safe-endpoint, session, state-change, and cleanup behavior through both remote handoff and local headed-browser contracts. It uses a loopback HTTP server and does not call an external network or a live model provider.

## Evaluation boundary

The comparative schema names three arms: legacy read-only, adaptive without independent verification, and adaptive with verification. It records applicable coverage, confirmed recall and precision, unsafe-request rejection, receipt completeness, reproducibility, and inconclusive rate. No verified observation corpus exists, so the checked-in result is `not_run` and the only permitted aggregate claim is `inconclusive`; no superiority claim is made.

## Residual limitations

The remote provider adapters are integration interfaces, not bundled OAuth/WalletConnect services. Browser availability, provider callbacks, wallet events, and production deployment isolation still require environment-specific acceptance tests. Response redaction is defense in depth rather than a proof that arbitrary secrets cannot appear. The local integration test verifies the host/broker boundary with fake auth adapters; it does not measure live model quality. `src/runtime/missions/assess.ts` remains a 1,331-line orchestration module and exceeds the static-review size limit; decomposing its work-unit and phase-runner closures is separate structural debt and was not used to claim this implementation fully audited.

## Verification record

The final `pnpm test:all` run passed TypeScript checking, 246 host tests across 42 files, and all 543 OffSec vendor tests. Six PostgreSQL integration tests were skipped because no database test environment was supplied; they are not represented as passes. The loopback Live DAST fixture passed for both interaction modes. Contract resource generation reported `in sync`, `git diff --check` passed, and the deterministic OffSec evaluator reproduced `not_run` with an `inconclusive` claim because no verified comparative observation file exists. Static review passed for the decomposed Live DAST, auth, broker, Finding, session, evaluation, and resume modules; only the oversized `assess.ts` and its legacy combined test file exceeded the review tool's 500-line input limit.
