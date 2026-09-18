# OffSec P1/P2 Typed Dependency Graph and Budgeted Work-Plan Implementation

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)

Implementation report for `docs/019-offsec-p1-p2-dependency-planning-spec.md`.

## 1. Design summary

### P1 — Typed dependency graph

Created `src/runtime/workflow/offsec-dependency-graph.ts` (806 lines) implementing a versioned, hash-bound file-dependency graph.

**Graph identity.** Schema version `1.0.0`. Each sealed source file becomes a unique `GraphNode` with path, owner unit ID, language, byte count, and deterministic estimated token count (`Math.ceil(byteCount / estimatedCharsPerToken)`). Edges carry `from`, original `specifier`, language, classification (`local-resolved` / `local-unresolved` / `external`), resolution kind, and zero-or-more resolved target paths. Graph metadata discloses supported parsers, unsupported file counts per language, and a fixed disclaimer stating the graph is a syntactic planning aid.

**Resolver coverage:**

| Language | Resolution kinds | Technique |
|---|---|---|
| JavaScript/TypeScript | `relative-import`, `tsconfig-paths`, `workspace-package`, `bare-specifier` | Regex extraction of `import`/`export`/`require`/`import()` specifiers; relative path resolution with extension probing; tsconfig.json `baseUrl`/`paths` with `extends` chain following; workspace `package.json` `exports`/`types`/`module`/`main` with dist→src equivalence |
| Python | `python-relative`, `python-local-absolute`, `external-python-module` | Regex extraction of `from X import`/`import X`; relative dot-prefix resolution; local absolute via `__init__.py` / `.py` probing |
| Rust | `rust-crate-path`, `rust-self-path`, `rust-super-path`, `rust-mod-decl`, `external-crate` | `use crate::`/`self::`/`super::` path resolution within nearest `Cargo.toml` crate root; `mod name;` sibling/subdir probing; non-crate `use` classified external |
| Go | `go-local-module`, `external-go-module` | `go.mod` module path prefix matching; package directory `.go` file collection (excluding `_test.go`) |

**Determinism guarantees.** Nodes ordered by source file sort. Edges deduplicated by `from|specifier` and sorted by `from` → `specifier` → `classification`. Self-hash via sorted-key stable JSON + SHA-256 (same convention as work plan and scope assurance). `assertDependencyGraphIntact` verifies hash plus node-set membership of all edge endpoints.

**No-silent-drop.** Every extracted specifier produces a typed edge. Unsupported languages are counted and disclosed in metadata, never described as parsed. External packages are classified `external`, not `local-unresolved`.

### P2 — Graph- and token-budgeted work planning

Extended `src/runtime/workflow/offsec-work-plan.ts` (576 lines, +263 from P0 baseline) with work-plan schema version `2.0.0`.

**V2 schema additions:**

- `PlanningPolicySchema`: seals `estimatedCharsPerToken` (4), `maxContextEstimatedTokensPerUnit` (65,536), `maxContextFilesPerUnit`
- `WorkUnitV2Schema`: extends V1 with `estimatedTokens` and `contextSelectionReceipt`
- `ContextSelectionReceiptSchema`: owned estimated tokens, candidate count, selected context files/tokens, omitted records with target/reason/tokens/refs, ranking policy identifier
- `ContextOmissionSchema`: per-candidate disposition with `file-cap` or `token-cap` reason
- `OffsecWorkPlanV2Schema`: binds `dependencyGraphSha256`, `planningPolicy`, V2 units

**Context selection algorithm** (`buildUnitV2`):

1. Collect cross-unit `local-resolved` targets from the unit's owned-file edges
2. Aggregate per-target distinct reference counts (deduplicated)
3. Sort by: ref-count desc → estimated tokens asc → path asc (`ref-count-desc/tokens-asc/path-asc`)
4. Walk ranked list once; include candidate only when both remaining file-count and token budgets allow
5. Continue considering later candidates if one doesn't fit
6. Every unique candidate receives exactly one disposition: selected or omitted with reason

**Backward compatibility:**

- V1 (`1.0.0`) plans continue to parse, verify, resume, and publish unchanged
- `assertOffsecWorkPlanIntact` routes by `schemaVersion` to V1 or V2 verification
- `OffsecWorkPlanAny` union type used throughout scope-assurance and assess
- V2 `unresolvedEdges` adds optional `budgetReason` field; V1 plans simply lack it
- No v1-to-v2 mutation during resume

### Integration in assess.ts

- Fresh runs create a dependency graph via `createDependencyGraph()`, write it as `00_dependency_graph.json`, and produce a V2 work plan via `createOffsecWorkPlanV2()`
- Resume of V2 plans reads and verifies the graph from disk via `readDependencyGraph()` + `assertDependencyGraphIntact()`
- Resume of V1 plans proceeds without graph (no graph reading or creation)
- VA inputs for V2 plans include `typedDependencyEdges` (from `getUnitTypedEdges()`) and `contextSelectionReceipt`
- V1 VA inputs remain unchanged
- Work-unit concurrency, phase order, verifier autonomy, and publication gate are unchanged

## 2. Files changed

| File | Change |
|---|---|
| `src/runtime/workflow/offsec-dependency-graph.ts` | **New** — P1 graph module |
| `src/runtime/__tests__/offsec-dependency-graph.test.ts` | **New** — P1 acceptance tests |
| `src/runtime/workflow/offsec-work-plan.ts` | Modified — V2 schemas, `createOffsecWorkPlanV2`, `buildUnitV2`, `assertPlanHashV2`, `getUnitTypedEdges`, union types |
| `src/runtime/__tests__/offsec-work-plan.test.ts` | Modified — P2 acceptance tests added |
| `src/runtime/missions/assess.ts` | Modified — graph creation, V2 plan creation, graph resume, VA input integration |
| `src/runtime/workflow/scope-assurance.ts` | Modified — `OffsecWorkPlanAny` type import |

## 3. Migration

No migration required. Fresh engagement runs produce V2 plans automatically. Existing sealed V1 plans resume without modification. The publication gate (`scope-assurance-gate.js`) and scope assurance module accept both versions via the `OffsecWorkPlanAny` union.

## 4. Test summary

### P1 acceptance tests (offsec-dependency-graph.test.ts — 12 tests)

- JS/TS relative import resolved
- Root tsconfig alias `@/lib/auth` resolved via `tsconfig-paths`
- Local workspace package root and `exports` subpath resolved to source files
- Unknown bare package classified `external`, not `local-unresolved`
- Python relative and local absolute imports resolved; external Python import external
- Rust `crate::`, `super::`, `mod name;` resolved; external crate external
- Go local module import resolved to sorted package files; external module external
- Target traversal rejected
- Deterministic re-generation yields identical graph hash
- Graph tampering causes verification failure
- Unsupported-language accounting explicit
- Write/read round-trip with integrity verification

### P2 acceptance tests (offsec-work-plan.test.ts — 10 new tests)

- High-reference candidates rank first
- Tie-breaking deterministic by estimated tokens then path
- Too-large candidate omitted but later fitting candidate still selected
- File-cap and token-cap omissions distinct and explicit
- Repeated edges deduplicated into one candidate/disposition
- External edges do not consume context budget or inflate unresolved counts
- V2 plan tampering fails closed
- V1 plan parsing/hash unchanged after V2 addition
- V2 VA inputs contain typed edges and planning receipt
- Source file count and unit ownership unchanged between V1 and V2

### Full suite results

- `pnpm typecheck`: pass (0 errors)
- `pnpm test`: Vitest 375 passed, 6 skipped (postgres integration)
- `pnpm test:vendor`: 585/585 pass (hooks 252 + ch015 lib 224 + ch015 ast 109)
- `pnpm test:all`: all pass
- `git diff --check`: clean
- Contract resource sync check: in sync

## 5. Metrics

| Metric | Value |
|---|---|
| Graph version | `1.0.0` |
| Work-plan version | `2.0.0` (V1 `1.0.0` preserved) |
| Estimated chars per token | 4 (deterministic, labeled approximate) |
| Max context estimated tokens per unit | 65,536 |
| Max context files per unit | 50 (preserved from P0) |
| Ranking policy | `ref-count-desc/tokens-asc/path-asc` |
| Supported parsers | JavaScript, TypeScript, Python, Rust, Go |

## 6. Residual limitations

1. **No semantic analysis.** The dependency graph is syntactic — regex-based import extraction. It does not parse ASTs, follow dynamic imports with computed specifiers, or trace data flow. The graph disclaimer states this explicitly.

2. **No security-quality claim.** Higher resolution counts and smaller context are structural planner evidence only. They are not finding recall/precision evidence.

3. **Estimated tokens are approximate.** The `byteCount / 4` estimator is labeled approximate and is not described as Anthropic/OpenAI tokenizer output or billing usage.

4. **Workspace package resolution assumes conventions.** Source equivalence (`dist/` → `src/`, `.js` → `.ts`) covers common monorepo patterns but may miss unusual configurations.

5. **Go resolution is package-directory level.** All `.go` files in the imported package directory are included as resolved targets, which may over-include files in large packages.

6. **Rust resolution is file-backed only.** Inline `mod { ... }` blocks and re-exports are not traced. Only file-backed `mod name;` declarations and `use crate::`/`self::`/`super::` paths are resolved.

7. **Python resolution does not trace `sys.path` modifications.** Only relative imports and imports whose top-level package has an `__init__.py` or `.py` file in the sealed source set are resolved locally.

8. **Security resource attachment deferred.** Per spec §2 non-goals, security resources are not attached to individual units. P0 root-level security-resource access remains valid.

## 7. Opus 4.6 Correction Pass (2026-08-12)

### Findings addressed

| Finding | Fix | Evidence |
|---|---|---|
| F1: readTsConfig follows extends but not root references; JSONC | Rewrote as `readTsConfigWithReferences()` with `stripJsonc()` (no-dep JSONC parser), per-source applicability via `include` patterns, and referenced config resolution | New test: `F1: resolves alias from referenced tsconfig.app.json with JSONC comments` passes |
| F2: Go resolver reads only root go.mod | Replaced root-only `readGoModulePath` with `findNearestGoMod(filePath, target)` per Go source file; resolved paths rooted relative to module directory | New test: `F2: resolves Go imports against nearest parent go.mod per source file` passes |
| F3: assertPlanHashV2 lacks §5.5 structural cross-validation | Added `assertPlanV2InternalIntegrity` (plan-only) and exported `assertPlanGraphIntegrity` (full graph cross-validation); checks candidate count, selected/omitted exact partition, reference counts, tokens, file/token limits, ranking, duplicates | Tests: `assertPlanGraphIntegrity passes`, `F3: rejects plan with tampered context selection`, `F3: plan-only validation rejects internally-invalid V2 receipt without graph` |
| F4: assess resume never compares plan.dependencyGraphSha256 to loaded graph | Added fail-closed check in assess.ts resume block and creation block; `assertPlanGraphIntegrity` called at both sites | Test: `F4: fails closed when plan.dependencyGraphSha256 does not match graph` |
| JSONC: JSON.parse cannot parse Davinci tsconfig.app.json comments | Implemented `stripJsonc()` without external dependencies | Test: `JSONC strip handles trailing commas and block comments` |
| readWorkspacePackages uses require('node:fs') in ESM | Replaced with top-level imported `readdirSync` | Typecheck passes; workspace resolution tests pass |
| Rust resolver: repeated super:: and brace/alias forms | Rewrote `extractRustSpecifiers` to handle `use super::super::`, brace expansion `use super::{a, b}`, and `as alias` stripping | Test: `Rust: handles repeated super::super:: and brace forms` |
| Graph fail-closed on duplicate/non-normalized/missing sources | `createDependencyGraph` now rejects duplicate source paths, missing files, and multiple owners with explicit errors | Tests: `fails closed on duplicate source paths`, `fails closed on missing source file` |
| assertDependencyGraphIntact: ordering, duplicates, token/byte consistency | Added node/edge ordering checks, duplicate detection, and `estimatedTokenCount` derivation verification | Tests: `fails on duplicate nodes`, `fails on out-of-order edges` |
| Graph self-hash: exclude only generatedAt and dependencyGraphSha256 | Confirmed via `const { dependencyGraphSha256: _sealed, generatedAt: _ts, ...core } = graph` — all other content bound | Existing deterministic hash test verifies |
| Remove unused v1 creator import from assess | Removed `createOffsecWorkPlan` import from assess.ts (fresh runs use only v2) | Typecheck clean; no runtime reference |
| Omission provenance | Replaced `input.unit.files[0]!` / target-as-specifier with deterministic first referencing edge (`candidateFirstEdge` map) | Test: `omission records preserve truthful source/specifier provenance` |

### Validation results

- `pnpm typecheck`: pass (0 errors)
- Focused graph tests: 22/22 pass
- Focused work-plan tests: 29/29 pass
- Focused assess tests: 20/20 pass
- Scope-assurance tests: 6/6 pass
- Full suite: 357 passed, 6 skipped (postgres)
- Vendor tests: 32/32 pass
- `git diff --check`: clean

### Davinci deterministic regression (coordinator-verified, read-only)

Executed by coordinator as read-only in-memory measurement against `/Users/philip/workdir/pentest/davinci`. No writes to target confirmed: `git status` SHA256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (0 lines) before and after; `.ch015` empty array before and after.

| Metric | Value |
|---|---|
| Manifest source files | 3953 |
| Manifest units | 67 (non-empty/plan units: 66) |
| Graph nodes | 3953 |
| Owned receipts | 3953 unique, exact ownership |
| Graph SHA-256 | `7774441088ffd2759d3aa70d9d4c3538d060f64892b671bd017e47e65b74179a` |
| Total edges | 5825 |
| — local-resolved | 3161 |
| — local-unresolved | 115 |
| — external | 2549 |
| Unsupported files | 32 (sql: 31, yaml: 1) |

**Local resolved edge kinds:**

| Kind | Count | Notes |
|---|---|---|
| relative | 2739 | |
| tsconfig paths | 86 | |
| workspace package | 0 | Measured zero; fixture tests cover resolution capability — not unsupported behavior |
| Rust crate | 150 | |
| Rust super | 117 | |
| Rust mod | 17 | |
| Rust self | 0 | Measured zero; fixture tests cover resolution capability — not unsupported behavior |
| Go local module | 52 | |

**External edge kinds:** bare JS 2005, external crate 417, external Go 113, external Python 14.

**Local unresolved edge kinds:** relative 63, Rust crate 2, Rust super 50.

**Context selection statistics:**

| Metric | Value |
|---|---|
| Context bytes P50 | 0 |
| Context bytes P90 | 256,794 |
| Context bytes P95 | 261,652 |
| Context bytes max | 262,102 |
| Context estimated tokens P50 | 0 |
| Context estimated tokens P90 | 64,208 |
| Context estimated tokens P95 | 65,417 |
| Context estimated tokens max | 65,530 |
| Units >65,536 tokens | 0 |
| Max selected files per unit | 31 |
| Units >50 files | 0 |

**Candidate accounting:** 600 total = 249 selected + 351 omitted (exact). Unresolved records: 115. Context-cap records: 351.

**Rust-derived context units:** 4, all `src-tauri` (src-tauri#001 / #002 / #003 / #004).

**Claim boundary:** These measurements are structural planner evidence only. They demonstrate graph resolution coverage, deterministic context budgeting, and fail-closed integrity verification. They are not evidence of semantic completeness, finding recall/precision, or security quality.

## 8. §5.5 Final Hardening Pass (2026-08-12 post-review)

Addresses coordinator-identified exact §5.5 gaps after the GPT-5.6-sol second review.

### Production changes

| Item | Change |
|---|---|
| `assertPlanGraphIntegrity` | Calls full `assertDependencyGraphIntact` (not merely hash recompute). Requires `plan.planningPolicy.estimatedCharsPerToken === graph.estimatedCharsPerToken` and `plan.maxContextFilesPerUnit === plan.planningPolicy.maxContextFilesPerUnit`. Re-derives and verifies each `unit.estimatedTokens = owned + selected context`. |
| Node byteCount / context receipts | Verifies every graph node's `byteCount` equals its canonical owned-file receipt `bytes`. Verifies every context `FileReceipt` exactly equals the canonical owned receipt for that graph target (path, bytes, sha256). |
| Unresolved/omitted reconstruction | Reconstructs exact expected `unresolvedEdges` per unit from graph local-unresolved edges plus deterministic one-per-omitted-candidate context-cap records. Rejects missing, extra, duplicate, or altered entries. Verifies omitted array order against deterministic ranked selection. |
| `assertDependencyGraphIntact` | Enforces one edge per `from+specifier` (same comparator as generation). Requires unique sorted `resolvedTargets`. Verifies edge language consistent with source node language. Verifies exact `metadata.unsupportedFileCount`/`unsupportedLanguageCounts`. Enforces deterministic `supportedParsers` value/order. |
| JS/TS edge language | `extractJsTsSpecifiers` now receives and propagates the actual source node language (`javascript`/`typescript`) rather than hardcoding `'javascript'`. |
| Go resolver prefix | Requires module import prefix to be exactly `modulePath` or `modulePath + '/'`, avoiding false local classification for prefix collisions. Resolves exact module-root import to sorted non-test `.go` files in `modDir`. |
| `createDependencyGraph` | Rejects unit files not in `source_files`. Rejects duplicate unit IDs. |
| `createOffsecWorkPlanV2` | Invokes full `assertPlanGraphIntegrity` before returning. |
| assess publication-time | For V2 with `depGraph`, calls full `assertPlanGraphIntegrity` again before publication. |
| Dead code | Removed unused `selectedTokenSum` computation in `assertPlanV2InternalIntegrity`. |
| Rust brace test | Corrected misleading comment about resolution path; added classification assertions. |

### Tests added

| Test file | Test |
|---|---|
| `offsec-dependency-graph.test.ts` | Go resolver rejects prefix collision |
| | Go resolver resolves exact module-root import |
| | JS/TS edge language equals source node language |
| | assertDependencyGraphIntact rejects tampered edge language |
| | assertDependencyGraphIntact rejects tampered metadata unsupported counts |
| | assertDependencyGraphIntact rejects unsorted resolvedTargets |
| | assertDependencyGraphIntact enforces one edge per from+specifier |
| | assertDependencyGraphIntact enforces deterministic supportedParsers |
| | createDependencyGraph rejects unit files not in source_files |
| | createDependencyGraph rejects duplicate unit IDs |
| `offsec-work-plan.test.ts` | assertPlanGraphIntegrity verifies planningPolicy.estimatedCharsPerToken |
| | assertPlanGraphIntegrity verifies maxContextFilesPerUnit matches planningPolicy |
| | assertPlanGraphIntegrity verifies unit.estimatedTokens = owned + selected |
| | assertPlanGraphIntegrity rejects tampered omission order |
| | assertPlanGraphIntegrity rejects extra unresolvedEdge entries |
| | V2 publication-gate fixture passes assertOffsecWorkPlanIntact |
| | V2 self-hash tamper rejection |
| | V2 plan+graph round-trip passes assertPlanGraphIntegrity |

### Validation results

- `pnpm typecheck`: pass (0 errors)
- Focused graph tests: 32/32 pass
- Focused work-plan tests: 37/37 pass
- Focused assess tests: 20/20 pass
- Scope-assurance tests: 6/6 pass
- Publication gate (report-gate-hook) tests: 55/55 pass
- Full suite (vitest): 375 passed, 6 skipped (postgres)
- Vendor tests (hooks): 252/252 pass
- Vendor tests (ch015 lib): 224/224 pass
- Vendor tests (ch015 ast): 109/109 pass
- `git diff --check`: clean

## 9. Final Coordinator-Verified Regression (2026-08-12)

### Full regression

| Check | Result |
|---|---|
| `pnpm test:all` — Vitest | 375 passed, 6 skipped (postgres) |
| `pnpm test:all` — Vendor Node suite | 585 tests passed + all self-tests |
| `pnpm typecheck` | pass |
| Contract resources | in sync |
| `git diff --check` | clean |

### GPT-5.6-sol review loop

1. Initial review: **NEEDS_CHANGES** — findings F1–F4 (tsconfig references/JSONC, Go nearest go.mod, §5.5 structural cross-validation, assess resume graph SHA mismatch).
2. Opus corrections applied (see §7).
3. Repeated final reviews: **APPROVED**.
4. Cleanup verification: **APPROVED** — no findings.

### Residual limitations (preserved)

These remain accurate and are not addressed by the Davinci measurement:

1. Syntactic/regex-based resolution only — no AST, no dynamic imports, no data flow.
2. Estimated tokens are approximate (`byteCount / 4`), not tokenizer output.
3. Measurements are structural planner evidence only — no benchmark, semantic completeness, or security-quality inference.
