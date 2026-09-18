# Readiness gap closure audit

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)

- Reviewed: 2026-08-05
- Scope: OffSec, Feedback, and SOC host runtime, contracts, recovery, trust boundaries, and evaluation claims.
- Method: repository inspection, focused and full tests, real local PostgreSQL integration, contract digest checks, and a separate read-only reliability review session.

## Implemented boundaries

The three mission entry points now select file or PostgreSQL state through `MissionRuntime`. PostgreSQL execution requires a fenced lease, immutable artifact store, and an explicitly configured shared engagement root. Phase completion commits state, artifact receipts, and outbox intent in one database transaction. Feedback resume uses the same runtime and preserves the PostgreSQL fencing token through `WorkflowHost`.

Outbox claims now contain the payload and a visibility lease. Expired claims are recovered, stale acknowledgements are rejected, repeated crashes reach dead-letter, acknowledgement-uncertain delivery is surfaced without an invalid failure rewrite, and JSON payload hashes use canonical key ordering before JSONB storage.

`pnpm run:admin` exposes inspect, explicit incomplete-attempt reconciliation, and lineage-checked resume for file and PostgreSQL backends. Operator telemetry can be persisted as validated JSONL without raw provider or source payloads.

SOC redaction receipts are Ed25519-signed and bind issuer, key ID, source hash, exact model-visible projection hash, and issue time. Mission ingestion and the snapshot CLI require an external trust store. Recomputed snapshot hashes do not make a forged redaction signature valid.

OffSec, Feedback, and SOC select distinct primary and reviewer model requests by default. The Anthropic adapter validates exact, dated-alias, and bounded family forms, records a canonical actual model key from `modelUsage`, and rejects lookalikes or request/receipt mismatches. A host outcome policy compares provider-verified actual identities before phase completion, so different aliases cannot silently resolve to the same primary and reviewer model.

The previously oversized `workflow/engine.ts` and `feedback-contract.ts` files were decomposed below the repository's 500-line static-review limit.

## Evaluation and claim boundary

Evaluation policy now fails closed for zero eligible denominators, insufficient required slice metrics, inconsistent human disagreement labels, and Wilson 95% upper bounds above policy. Corpus hashes and contract-resource bundle hashes are computed from actual bytes; SOC preserves report versus investigation contract provenance.

Feedback and SOC case files now contain structured candidate artifacts rather than human-authored `observed` booleans. Repository evaluators derive observations from candidate status, decisions, evidence locators, questions, coverage, and review signals before policy calculation. The runners identify themselves as `deterministic-candidate-artifact-evaluation`, set `repositoryEvaluatorExecuted` to true, and keep `agentQualityMeasured`, `hostControlExecuted`, `liveProviderExecuted`, and `liveSourceExecuted` false. They prove evaluator regression behavior only; they do not prove agent quality, calibration, absence of bias, semantic robustness, or live-source correctness. Execution-based provider corpora remain incomplete.

## Context-contamination and self-calibration review

The runtime isolation baseline remains `settingSources: []`, strict MCP configuration, disabled automatic memory, bounded subagent depth, exact allowed-read files, and SHA-256-pinned host resources. Feedback source text and SOC compact evidence remain untrusted data rather than instructions. No new host skill, plugin, memory, or ambient settings source is injected into tenant sessions.

The independent session found and disproved several initial completion assumptions: payload-less outbox delivery, stale claim acknowledgement, self-asserted SOC receipts, request-only model identity, PostgreSQL resume without fencing, JSONB key-order hashing, shared-root symbolic-link escape, model-ID lookalikes, alias correlation, and quality claims based on static labels. It also generated adversarial evaluator counterexamples for missing anchors, locator substitution, and aggregate masking. Those findings were corrected or, for live evaluation, explicitly retained as an unmeasured limitation. No production-readiness, legal compliance, or bias-absence claim is made from local tests.

## Deployment conditions and remaining limits

- PostgreSQL deployments must configure `NUNCHI_DATABASE_URL`, `NUNCHI_ARTIFACT_ROOT`, and `NUNCHI_SHARED_ENGAGEMENT_ROOT`. The host resolves real paths and rejects symbolic-link escape, but cannot prove that an operator's mount is actually shared or durable.
- Existing outbox rows created with the former non-canonical payload hash require an operator migration or drain before upgrading; new rows use canonical JSON hashing.
- The standard registries remain curated clause indexes without normative text, legal interpretation, or automatic semantic applicability decisions.
- String safety filters are defense-in-depth. Multilingual or semantic instruction attacks still require live adversarial evaluation and human gates.
- Live provider repetition, order-swap/blind comparison, cross-model error correlation, selective-risk by slice, and source truthfulness are not measured in this repository run.

## Verification record

The final verification commands and exact counts are recorded in the active ASX goal evidence and the completion response. PostgreSQL integration is counted only when `NUNCHI_DATABASE_URL` is set; skipped database tests are not represented as passes.
