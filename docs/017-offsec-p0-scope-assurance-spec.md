# OffSec P0 Scope and Assurance Implementation Specification

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)

Status: implementation contract for the current host-bounded OffSec runtime.

## 1. Objective

Close the four evidence-backed P0 gaps without restoring the legacy Recon agent, changing concurrency, or claiming that tool reads prove security-analysis quality:

1. make cross-unit context-cap records accurate and backward compatible;
2. create host-owned work-unit assurance independent of legacy `fanout_decision.flow`;
3. inventory eligible project files and explicitly classify security resources that are currently absent from `source_files`;
4. lock deterministic structural regression evidence while preserving the existing blinded benchmark workflow for later quality claims.

The target repository is untrusted and read-only. Existing dirty/untracked repository state must be preserved. Only files necessary for this P0 may be modified.

## 2. Non-goals

- Do not add or restore a `recon` role/phase.
- Do not change `maximumConcurrency`, `maximumWorkUnits`, provider models, or feedback limits.
- Do not add TypeScript alias, Rust, Go, Tauri IPC, or semantic graph resolvers in this P0.
- Do not add all JSON/TOML/Markdown files to `source_files`.
- Do not gate on an arbitrary file-read percentage, finding density, or zero-finding units.
- Do not claim that Read/Grep/Glob activity proves security-analysis completeness.
- Do not run a paid/live benchmark without an explicit budget decision.

## 3. P0-A — context-cap accuracy

### Required behavior

In `src/runtime/workflow/offsec-work-plan.ts`:

- Before emitting a `context-cap` edge, check whether the resolved target is already present in the unit context set. Repeated references to an already-included context file must not become cap records after the set reaches the limit.
- Every newly generated `context-cap` edge must include `resolvedTarget`, a normalized manifest-relative path.
- Legacy sealed plans whose `context-cap` records lack `resolvedTarget` must still parse and resume.
- A semantically unresolved edge remains distinct from a resolved-but-budget-excluded edge.

### Acceptance tests

- A unit that fills the cap and then references an already included context file produces no cap record for that repeated reference.
- A truly omitted resolved file produces `{ reason: 'context-cap', resolvedTarget }`.
- A legacy work plan with `{ reason: 'context-cap' }` and no `resolvedTarget` validates.
- Plan hash and identity checks remain deterministic.

## 4. P0-B — eligible-file inventory and security resources

### Required behavior

Extend source-manifest generation additively. Inventory every regular file reachable under the target after the existing excluded-directory and excluded-path policy is applied; continue to skip symlinks. This is an eligible-project-file inventory, not a claim that ignored build/vendor directories were examined.

Each inventory record must be content-addressed and have an explicit classification and disposition. At minimum distinguish:

- source / analyze-source;
- dependency-manifest / analyze-dependency;
- security-resource / analyze-security-resource;
- runtime-prompt / analyze-security-resource;
- generated-runtime-resource / analyze-security-resource;
- test / inventory-only unless already source;
- documentation / inventory-only;
- asset / inventory-only;
- other / inventory-only.

Security-resource classification must be narrow and deterministic, not “all JSON”. It must cover at least the repository patterns represented by:

- Dockerfile/Containerfile and compose definitions;
- shell deployment/seed scripts (`.sh`, `.bash`, `.zsh`);
- TOML/HCL/Terraform and environment example files;
- Tauri config and capability JSON;
- Supabase config/storage policy JSON;
- plugin/application manifest JSON;
- CI/CD workflow/config files;
- runtime-loaded prompt/agent Markdown under known resource/plugin paths;
- generated runtime registry metadata such as converted-registry `registry.json`.

Additive manifest data must include:

- `security_resource_files` and content receipts;
- an integrity-protected scope inventory (embedded or a separately written `00_scope_inventory.json` with a hash referenced by `source_manifest.json`);
- versioned schema metadata;
- backward-compatible hashing/parsing for old manifests that do not contain the new fields.

`source_files` and existing 200-file/20K-LOC unit ownership semantics must not change merely because inventory was added. Security resources must be available to the root VA read scope. Unit-level security-resource attachment is deferred unless it can be added without changing source ownership, result identity, or legacy plan compatibility.

### Acceptance tests

- Existing source/dependency fixture expectations remain unchanged.
- Dockerfile, shell, Tauri capability/config, Supabase config/storage JSON, runtime prompt Markdown, and generated registry JSON fixtures receive the expected security-resource classification.
- Generic JSON/assets remain inventory-only unless a supported path/name rule applies.
- Excluded output directories and symlinks remain absent.
- Old source manifests continue to validate/replay where current code supports replay.
- Inventory-only changes do not create extra source work units.

## 5. P0-C — host-owned scope assurance for work-unit runs

### Required behavior

Create a versioned, hash-protected `00_scope_assurance.json` after successful host work-unit execution. Reuse existing `ProviderRuntimeEvent`/`LedgerRow` events; do not add a duplicate SDK instrumentation path.

The receipt must bind to:

- source manifest hash;
- work-plan hash;
- completed unit keys;
- each unit’s canonical identity and source-unit ID.

For each unit, record deterministic observation data separately for VA and Verifier, including:

- owned/context file counts;
- unique allowed `Read` resources inside the unit scope;
- owned files actually read;
- context files actually read;
- unresolved edge count;
- resolved-but-context-capped count;
- whether the existing autonomous Verifier artifact was sealed.

Broad Grep/Glob must not be converted into “files examined” unless the host has concrete matched-file receipts. In this P0, only actual allowed Read resources may count as read files. The receipt must state that reads are a minimum-examination signal and not proof of semantic analysis.

`00_work_unit_results.json` must reference the assurance receipt and hash additively. Legacy v1 results without assurance must remain readable for resume. New runs that declare an assurance receipt must fail closed on missing/hash-mismatched/incomplete assurance.

Decouple the host work-unit assurance path from legacy large-scale coverage routing:

- retain the existing `coverage_units.yaml` gate for legacy large-scale fanout;
- detect host-bounded work-unit engagements from their sealed work plan/results, not from `fanout_decision.flow`;
- validate assurance structure, identity, hash, and complete unit accounting at publication;
- do not enforce a new read-ratio threshold in P0.

### Acceptance tests

- Standard-flow host work-unit engagement produces assurance and publication validates it.
- Missing/tampered assurance declared by new results blocks publication.
- Legacy result fixtures without assurance remain backward compatible.
- Unit keys in plan/results/assurance must match exactly.
- Duplicate Read events are deduplicated; denied/out-of-scope reads do not count.
- No arbitrary read percentage or finding-count gate is introduced.

## 6. P0-D — deterministic baseline and quality-claim boundary

Add deterministic regression coverage for all P0 behaviors. Preserve and document the existing live/blinded benchmark commands:

- `pnpm eval:offsec:run`
- `pnpm eval:offsec:adjudicate`
- `pnpm eval:offsec`

Do not invent a new benchmark command unless required by implementation. Do not claim finding recall/precision improvement from unit tests. A paid/live benchmark is outside this implementation unless separately authorized; report it as a remaining validation boundary.

## 7. Likely implementation surface

Expected files include, but are not limited to:

- `domains/offsec/lib/ch015/source-manifest.js`
- `domains/offsec/lib/ch015/test/source-manifest.test.js`
- `src/runtime/workflow/offsec-work-plan.ts`
- `src/runtime/__tests__/offsec-work-plan.test.ts`
- a focused scope-assurance runtime module and test
- `src/runtime/missions/assess.ts`
- `src/runtime/__tests__/assess.test.ts`
- `domains/offsec/lib/ch015/coverage-gate.js`
- `domains/offsec/hooks/report-gate-hook.js`
- `domains/offsec/hooks/test/report-gate-hook.test.js`
- contract/resource manifests only if runtime contract resources actually change

Avoid changing agent/method/skill prompts in P0 unless required for truthful final-report disclosure. If a contract resource changes, regenerate resources and explicitly document in-flight-run implications.

## 8. Verification

Minimum required verification:

1. targeted source-manifest, work-plan, assurance, assess, and report-gate tests;
2. `pnpm typecheck`;
3. `pnpm generate:contract-resources` followed by a clean resource diff/check if contract resources changed;
4. `pnpm test:all`;
5. `git diff --check`;
6. read-only Davinci dry measurement confirming inventory inclusion, unchanged source file/work-unit counts, accurate cap records, and no project writes.

## 9. Review standard

An independent reviewer must inspect implementation and tests against every acceptance criterion. Reviewer must distinguish:

- structural correctness from proven security-analysis quality;
- actual Read telemetry from semantic examination;
- legacy compatibility from new-run fail-closed behavior;
- security resources from source ownership.

No completion claim is allowed while a criterion lacks code/test evidence.