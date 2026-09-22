# OffSec P1/P2 Typed Dependency Graph and Budgeted Work-Plan Specification

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

Status: canonical implementation contract following `docs/017-offsec-p0-scope-assurance-spec.md`.

## 1. Objective

Improve host-owned OffSec work planning without restoring Recon, changing provider/concurrency policy, or claiming semantic security-analysis completeness:

1. P1: replace the planner's conflated regex-only dependency view with a versioned, hash-bound typed file-dependency graph;
2. P2: select cross-unit context deterministically using graph evidence plus both file-count and approximate-token budgets;
3. preserve P0 source ownership, scope assurance, legacy resume, and publication behavior;
4. establish deterministic Davinci regression measurements while keeping security-quality claims behind the existing blinded benchmark process.

The target repository is untrusted and read-only. Existing dirty/untracked repository state must be preserved.

## 2. Non-goals and claim boundary

- Do not restore a semantic `recon` role or phase.
- Do not change `maximumConcurrency`, `maximumWorkUnits`, provider models, feedback limits, source-manifest 200-file/20K-LOC ownership, or existing phase order.
- Do not implement Tauri IPC/call-graph/data-flow semantics in P1/P2.
- Do not treat syntactic graph resolution as proof that a dependency graph is semantically complete.
- Do not treat estimated tokens as provider-billed or provider-tokenizer-exact counts.
- Do not gate on read percentage, finding density, zero-finding units, or graph-edge count.
- Do not add all security resources to every unit. P0 root-level security-resource access remains valid; unit attachment requires an independently bounded relevance policy and is deferred from this implementation.
- Do not run a paid/live benchmark without a separate budget decision.

## 3. Baseline to preserve and improve

Read-only Davinci baseline before P1/P2:

- 3,953 source files;
- 67 manifest units / 66 non-empty work units;
- 2,794 conflated `unresolved` records;
- 211 accurate context-cap records / 132 unique omitted targets;
- context bytes: P90 425,527, P95 619,419, max 945,319;
- 9 units above 256 KiB of context;
- TS local alias imports and Rust `crate::`/`super::` imports are not resolved by the v1 planner;
- `src-tauri` units receive no Rust-derived context in the v1 planner.

P1/P2 must not change source-file membership or unit ownership merely to improve graph/context planning.

## 4. P1 — typed dependency graph

### 4.1 Focused module and graph identity

Create a focused runtime module, recommended:

- `src/runtime/workflow/offsec-dependency-graph.ts`
- `src/runtime/__tests__/offsec-dependency-graph.test.ts`

The graph must be versioned, strictly parsed, deterministic, and self-hashed using the repository's sorted-key stable JSON + SHA-256 convention.

Minimum graph shape:

- one unique node per sealed source file;
- node path, owner source-unit ID, language, byte count, deterministic estimated-token count;
- typed edges with `from`, original `specifier`, language, classification, resolution kind, and zero or more resolved target paths;
- graph generation metadata that discloses supported parsers/resolvers and unsupported file counts;
- `dependencyGraphSha256` binding all graph content except timestamp/self-hash.

Allowed edge classifications must distinguish at least:

- `local-resolved` — one or more sealed source targets were deterministically resolved;
- `local-unresolved` — syntax indicates a local/project edge but no sealed target was resolved;
- `external` — package/crate/module import not owned by the sealed source manifest.

External package imports must not be reported as semantically unresolved local edges.

### 4.2 Required resolver coverage

Implement deterministic, repository-local resolution for:

1. JavaScript/TypeScript relative imports, exports, `require`, and literal dynamic imports;
2. TypeScript `compilerOptions.baseUrl` / `paths`, including applicable referenced configs such as root `tsconfig.json` -> `tsconfig.app.json`;
3. workspace package names/subpaths using local `package.json` names and source-oriented `exports`, `types`, `module`, or `main` entries;
4. Python relative imports and unambiguous project-local absolute module/package imports;
5. Rust `crate::`, `self::`, `super::`, and file-backed `mod name;` edges within the nearest Cargo crate source root;
6. Go imports beginning with the nearest `go.mod` module path, resolving deterministically to sealed `.go` files in the imported package directory.

Bare JS packages, external Python modules, external Rust crates, and Go imports outside the local module prefix must be classified `external`.

Resolution must never escape the target, follow unsealed paths, or synthesize nonexistent targets. Ambiguous package-directory resolution may produce multiple sorted `resolvedTargets`; all must be sealed graph nodes.

### 4.3 Determinism and no-silent-drop

- Nodes and edges must have deterministic sort and deduplication rules.
- Every syntactically extracted import/use/mod statement in a supported parser must produce a typed edge.
- Unsupported source languages/files must be counted and disclosed, not silently described as parsed.
- Every `local-resolved` target must exist in the node set.
- `local-unresolved` and `external` edges must have no resolved targets.
- Graph self-hash verification must fail closed on node, edge, metadata, or resolution tampering.
- Graph artifacts must state that the graph is a syntactic planning aid, not semantic or security-analysis completeness evidence.

### 4.4 P1 acceptance tests

At minimum add fixtures proving:

- JS/TS relative import remains resolved;
- root referenced tsconfig alias such as `@/lib/auth` resolves locally;
- local workspace package root and exported subpath resolve to source files;
- unknown bare package remains `external`, not `local-unresolved`;
- Python relative and local absolute imports resolve; external Python import remains external;
- Rust `crate::`, `super::`, and `mod name;` resolve across files; external crate remains external;
- Go local module import resolves to sorted package files; external module remains external;
- target traversal/unsealed targets are rejected;
- deterministic re-generation yields identical graph hash;
- tampering causes graph verification failure;
- unsupported-language accounting is explicit.

## 5. P2 — graph- and token-budgeted work planning

### 5.1 Work-plan v2 and legacy compatibility

Fresh plans must use a new work-plan schema version (recommended `2.0.0`) that embeds or hash-binds the typed dependency graph and planning policy. Existing sealed v1 (`1.0.0`) plans must continue to parse, verify, resume, and publish without graph fields.

Do not mutate/re-hash a stored v1 plan into v2 during resume. New-run v2 and legacy v1 behavior must be distinguished by schema version, not by deleting optional fields.

`assertOffsecWorkPlanIntact`, `assertOffsecWorkUnitIntact`, scope assurance, results resume, and the plain-JS publication gate must remain valid for both versions. New v2 plans must fail closed when graph/policy/selection receipts are missing or tampered.

### 5.2 Deterministic approximate-token policy

Use a deterministic estimator suitable for planning, with its algorithm and limits sealed in the plan. Required defaults:

- `estimatedCharsPerToken: 4`;
- `maxContextEstimatedTokensPerUnit: 65_536`;
- preserve `maxContextFilesPerUnit: 50` as an independent upper bound.

The estimate must be derived from sealed file content and be labeled approximate. It must not be described as Anthropic/OpenAI tokenizer output or billing usage.

Owned source files remain owned even when their estimated size exceeds a context budget. The token budget applies to additional cross-unit context only; ownership semantics must not change.

### 5.3 Context candidate selection

Build context candidates exclusively from cross-unit `local-resolved` graph targets. Same-unit targets and external edges require no context attachment. Local-unresolved edges remain explicit unresolved records.

Required deterministic ranking:

1. descending number of distinct direct references from the unit's owned files;
2. ascending estimated tokens (prefer the smaller candidate when reference counts tie);
3. ascending normalized target path.

Walk the ranked list once. Include a candidate only when both remaining file-count and estimated-token budgets allow it. Continue considering later candidates if one candidate does not fit.

Every unique candidate must receive exactly one disposition:

- selected as `contextFiles`; or
- omitted with `file-cap` or `token-cap`, target path, estimated tokens, and direct-reference count.

No resolved cross-unit target may disappear without one of those dispositions. Repeated references to one target must not create duplicate context or omission records.

### 5.4 V2 unit planning receipts

Each v2 unit must add a strict context-selection receipt containing at least:

- owned estimated tokens;
- candidate count;
- selected context file count and estimated tokens;
- omitted target records and reasons;
- ranking-policy identifier.

For compatibility with existing model inputs and P0 assurance:

- retain `ownedFiles`, `contextFiles`, `unresolvedEdges`, and `assignedSourceSha256`;
- local-unresolved graph edges remain represented as `reason: 'unresolved'`;
- budget omissions remain represented as `reason: 'context-cap'` with `resolvedTarget`, plus a v2 budget reason where needed;
- external edges must not inflate `unresolvedEdges`;
- pass the unit's typed dependency edges and context-selection receipt to VA inputs;
- do not change work-unit concurrency, phase order, or verifier autonomy.

### 5.5 Integrity validation

V2 plan verification must cross-check, rather than merely schema-parse:

- graph self-hash and plan self-hash;
- exact node/source ownership correspondence;
- edge endpoints and classifications;
- deterministic candidate ranking and selected/omitted partition;
- file and estimated-token limits;
- context file receipts against graph targets;
- no duplicate candidate, selected target, or omission target;
- exact selected/omitted accounting for every cross-unit local target.

### 5.6 P2 acceptance tests

At minimum add fixtures proving:

- high-reference candidates rank first;
- tie-breaking is deterministic by estimated tokens then path;
- a too-large candidate is omitted but a later fitting candidate is still selected;
- file-cap and token-cap omissions are distinct and explicit;
- repeated edges to one target produce one candidate/disposition;
- external edges do not consume context budget or unresolved counts;
- v2 selection tampering or graph tampering fails closed;
- legacy v1 plan parsing/hash remains unchanged;
- v2 work-unit VA inputs contain typed edges and planning receipt;
- source file count, unit count/ownership, concurrency, and maximum work-unit policy remain unchanged.

## 6. Davinci deterministic regression

Run read-only generation only; do not write into Davinci. Record before/after target git status digest.

Required measurements:

- source-file and non-empty unit counts remain 3,953 / 66;
- graph node and edge counts by classification/resolution kind;
- TS alias/workspace local-resolution counts;
- Rust crate/super/mod local-resolution counts and `src-tauri` units receiving context;
- Go local-module resolution counts;
- local-unresolved versus external counts (do not compare their sum to the conflated v1 unresolved count as if semantically equivalent);
- context bytes and estimated tokens P50/P90/P95/max;
- units exceeding the 65,536 estimated-token context budget must be zero;
- selected and omitted candidate accounting must be exact;
- `.ch015` remains absent and target git status remains unchanged.

A lower unresolved count, higher resolved-edge count, or smaller context is structural planner evidence only. It is not finding recall/precision evidence.

## 7. Expected implementation surface

Likely files:

- new `src/runtime/workflow/offsec-dependency-graph.ts`;
- new `src/runtime/__tests__/offsec-dependency-graph.test.ts`;
- `src/runtime/workflow/offsec-work-plan.ts`;
- `src/runtime/__tests__/offsec-work-plan.test.ts`;
- `src/runtime/missions/assess.ts`;
- `src/runtime/__tests__/assess.test.ts`;
- scope-assurance/publication tests only if v2 compatibility requires changes;
- a new implementation report under `docs/`.

Avoid contract/resource changes unless implementation proves they are necessary. The P2 defaults may be sealed in work-plan v2 without changing the current OffSec contract version, preventing unrelated in-flight contract migration.

## 8. Verification and review loop

Required before completion:

1. focused graph, work-plan, assurance, assess, and publication tests;
2. `pnpm typecheck`;
3. `pnpm test:all`;
4. contract-resource sync check;
5. `git diff --check`;
6. read-only Davinci measurements from §6;
7. independent GPT-5.6-sol review against every acceptance criterion;
8. Opus 4.6 correction pass for material review findings, followed by repeated validation;
9. final independent re-review if any material code changes were required.

No completion claim may convert structural graph/planner regression evidence into a security-quality claim. Live/blinded benchmark evidence remains separately budgeted.
