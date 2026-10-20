# Development contract

## Start from existing implementation

- Read `docs/implementation-map.json` before changing orchestration, findings, review, recovery, knowledge, or reports. Use `pnpm check:implementation --feature <id>` for a focused view. This map covers core boundaries, not every function; confirm omissions with `rg` before deciding a feature is missing.
- Current code and tests determine behavior. The map distinguishes implemented/partial features from proposals. Historical numbered plans describe their writing date, not current architecture.
- Before editing, record a short impact note in the working update or PR: existing feature and entrypoint; callers and contracts affected; reuse versus change; persisted data/resume impact; invariants and tests to preserve. Ordinary reversible work does not require a separate approval.
- Follow the existing public API → mission → workflow boundaries. Reuse existing review feedback, revision, finding promotion and publication paths. Do not add a second state machine, finding ledger or review loop without accounting for the existing path.

## Preserve contracts while changing one responsibility

- Preserve unrelated worktree edits. Existing uncommitted code is part of the implementation to inspect, not a reason to replace it.
- Completed tasks must remain reusable; changed evidence must invalidate the affected decisions. Retain prior artifacts, finding versions, costs and original source-delivery receipts.
- An unresolved claim is not a confirmed vulnerability. Record count, independent cause count and report count have different meanings. Report projections must remain consistent with canonical records, including rejected/backlog/corrected history.
- Shared knowledge and CVE material are advisory inputs with provenance/versioning; they cannot substitute for source evidence or establish a finding by themselves.
- Keep fixes small enough to review. Update the corresponding map entry and meaningful regression when a boundary changes. Put future work in `plannedCapabilities`, not among implemented behavior.

## Verify and hand off

- Run `pnpm check:implementation` for reference integrity; `pnpm test:regression` for the mapped core contracts. The checker validates declarations and active test titles, not semantic correctness or a complete call graph.
- Run `pnpm typecheck` for TypeScript changes and `pnpm check:contracts` for domain/resource consistency. Use `pnpm test:all` when a broader change needs the full existing suite. Add targeted tests for uncovered failure modes, not duplicate tests of already-covered behavior.
- Report what changed, checks run and remaining limitations. Distinguish synthetic local tests from real provider/target/database runs; a reference check or green fixture does not establish diagnostic quality.
