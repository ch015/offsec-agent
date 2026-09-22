# OffSec P0 Scope and Assurance — Implementation Report

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

Implements: `docs/017-offsec-p0-scope-assurance-spec.md`.

## 1. Files touched

All modifications are additive to the existing (pre-existing untracked/dirty) worktree. No file
outside this list was modified, no destructive git operation was run, and no commit was made.

### Modified

| File | P0 | Change |
| --- | --- | --- |
| `src/runtime/workflow/offsec-work-plan.ts` | A | Dedupe fix for repeated context-file references; `resolvedTarget` on `context-cap` edges |
| `src/runtime/__tests__/offsec-work-plan.test.ts` | A | 3 new tests (dedupe, resolvedTarget, legacy-no-resolvedTarget) |
| `domains/offsec/lib/ch015/source-manifest.js` | B | Eligible-file inventory, narrow security-resource classifier, additive manifest fields |
| `domains/offsec/lib/ch015/test/source-manifest.test.js` | B | 4 new tests (classification, generic-inventory-only, exclusion/symlink, legacy hash) |
| `src/runtime/missions/assess.ts` | C | Scope-assurance creation/write on fresh work-unit runs; fail-closed replay validation; security-resource files added to root read scope |
| `src/runtime/__tests__/assess.test.ts` | C | Assurance artifact assertions added to the existing work-unit test; 2 new tests (tamper fail-closed, legacy v1 backward compat) |
| `domains/offsec/hooks/report-gate-hook.js` | C | New publication-routing block, independent of `fanout_decision.flow` |
| `domains/offsec/hooks/test/report-gate-hook.test.js` | C | 7 new tests for the scope-assurance publication gate |

### New

| File | P0 | Purpose |
| --- | --- | --- |
| `src/runtime/workflow/scope-assurance.ts` | C | zod-typed create/write/assert API for `00_scope_assurance.json` |
| `src/runtime/__tests__/scope-assurance.test.ts` | C | 6 dedicated unit tests for the module above |
| `domains/offsec/lib/ch015/scope-assurance-gate.js` | C | Plain-JS structural/hash/identity verifier used by the publication hook (mirrors the TS module's hash scheme; no zod dependency, so it runs in the hook's plain-Node context) |

## 2. P0-A — context-cap accuracy

**Bug:** `buildUnit` in `offsec-work-plan.ts` checked `context.size < maxContextFilesPerUnit` before
adding a resolved cross-unit dependency to the context set, but did **not** first check whether the
resolved target was already present in that set. Once the cap was reached, every *subsequent*
reference to an *already-included* file wrongly emitted a fresh `context-cap` unresolved-edge record.

**Fix:** check `context.has(resolved)` first (no-op if already present, not a cap record), then check
the cap, then push `{ reason: 'context-cap', resolvedTarget: resolved }` only for a genuinely
newly-excluded file. `resolvedTarget` was added to the schema as `.optional()` — verified empirically
(zod 4.4.3) that omitted optional keys are **not** materialized as `undefined` properties on the parsed
object, so legacy sealed plans (created before this field existed) rehash identically under the
unchanged `stableJson`/`digest` functions. A dedicated test reconstructs such a legacy plan (strips
`resolvedTarget`, recomputes `workPlanSha256` with an independent copy of the hashing algorithm) and
confirms it still validates.

## 3. P0-B — eligible-file inventory and security resources

Added, purely additively, to `createSourceManifest`:

- `walkEligibleFiles` — full walk (same exclusion policy/symlink-skip as the existing walkers) over
  every regular file, not limited to configured code extensions.
- `classifyInventoryEntry` — priority order: **dependency-manifest → source → security-resource
  (narrow patterns) → test → documentation → asset → other**. Membership in the existing
  `source_files`/`dependency_files` sets always wins first, so `source_files`, `dependency_files`,
  and unit ownership are provably unchanged (asserted directly in tests).
- `classifySecurityResource` — narrow, deterministic rules for: Dockerfile/Containerfile/compose,
  `.sh`/`.bash`/`.zsh`, `.toml`/`.hcl`/`.tf`/`.tfvars`/`.env.example`, Tauri
  `tauri.conf.json`/`src-tauri/capabilities/*.json`, `supabase/**/*.json`, `plugin.json`/
  `manifest.json`/`.claude-plugin/`, CI workflow files, runtime-loaded prompt Markdown under
  `agents/`/`skills/`/`commands/`/`methods/`, and `registry.json`. Deliberately **not** "all JSON".
- New manifest fields: `security_resource_files`, `security_resource_receipts`, `scope_inventory`
  (embedded, content-addressed), `scope_inventory_sha256`, `scope_inventory_schema_version`.
- `sourceManifestContentProjection` includes the new fields **only when present** on the input object,
  so recomputing the content hash of an old (pre-P0-B) manifest object reproduces its original hash
  bit-for-bit — verified with a test that independently replicates the pre-P0-B projection function.

**Design choice:** the inventory is embedded in `source_manifest.json` rather than split into a
separate `00_scope_inventory.json` (the spec explicitly allows either). This avoids new
read/allow-list plumbing; the tradeoff is a larger `source_manifest.json` on very large target repos.

## 4. P0-C — host-owned scope assurance + publication routing

### Assurance receipt (`src/runtime/workflow/scope-assurance.ts`)

`createScopeAssurance` reuses the **existing** per-phase `ProviderPhaseOutcome.events` (already scoped
correctly to one `executePhase` call, even under concurrent work-unit execution — no shared-ledger
interleaving risk, no new SDK instrumentation). For each completed unit it separately aggregates VA and
Verifier events (including feedback-loop rounds), counts only `tool: 'Read', decision: 'allow'`
resources resolved against the unit's owned/context file sets, and records owned/context file counts
and unresolved/context-capped edge counts straight from the sealed work plan. The receipt is hash-sealed
(`scopeAssuranceSha256`) the same way `offsec-work-plan.ts` seals plans. `assertOffsecWorkPlanComplete`
is reused for barrier/unit-accounting — the assurance module does not invent its own completeness rule.

In `assess.ts`, after a fresh work-unit wave completes, the receipt is written to
`00_scope_assurance.json` and referenced additively from `00_work_unit_results.json` via
`assurancePath`/`assuranceSha256`. On resume/replay, if those two fields are present, the file is
re-hashed and `assertScopeAssuranceComplete` re-validates identity/hash/unit-accounting — any
mismatch throws (fail closed). If both fields are absent (pre-P0-C / legacy results), the check is
skipped entirely.

### Publication routing (`domains/offsec/lib/ch015/scope-assurance-gate.js` + `report-gate-hook.js`)

A **new, independent** block in `report-gate-hook.js`'s `runGate` detects a host-bounded work-unit
engagement purely from `00_work_plan.json` + `00_work_unit_results.json` presence — **not** from
`fanout_decision.flow`. It is wired alongside, not instead of, the existing `coverage_units.yaml`
large-scale gate, which is untouched. The gate validates structure/hash/identity/complete-unit-
accounting only; it introduces no read-ratio or finding-density threshold. Toggle:
`CH015_SCOPE_ASSURANCE_GATE=off`.

The verifier is a **second, independent implementation** in plain CommonJS (no zod) because
`report-gate-hook.js` runs as a plain-Node hook process outside the `tsx`/TypeScript runtime that
`assess.ts` runs in — it cannot `require()` a `.ts` module. It re-implements the same
sorted-key-stable-JSON + sha256 hashing convention already used independently by
`offsec-work-plan.ts`, `source-manifest.js`, and `coverage-gate.js` in this codebase.

## 5. Test summary

- `pnpm typecheck` — clean.
- `pnpm test` (vitest) — 316 passed, 6 skipped (pre-existing Postgres integration tests requiring a
  live DB), 0 failed.
- `pnpm test:vendor` (`node --test` + self-tests) — passed (source-manifest.test.js 17/17,
  report-gate-hook.test.js 48/48), 0 failed, plus all `--self-test` CLIs green.
- `pnpm exec tsx scripts/generate-contract-resources.ts --check` — in sync (no contract/resource
  changes were made, so this is a no-op confirmation).
- `git diff --check` — clean (no whitespace errors).
- Read-only dry measurement (see below) — no project writes.

New/changed test counts: +3 (`offsec-work-plan.test.ts`), +4 (`source-manifest.test.js`), +6
(new `scope-assurance.test.ts`), +3 (`assess.test.ts`: 2 new tests + assertions added to an existing
one), +7 (`report-gate-hook.test.js`).

Post-correction: assess.test.ts legacy-resume fixture updated (§8 §2) — 1 test changed, 0 new.

## 6. Read-only dry measurement

Section 8 item 6 of the spec calls for "a read-only Davinci dry measurement." No such external target
repository is available in this dispatched environment. As a substitute, `createSourceManifest` was
run read-only (no `writeSourceManifest` call) against this repository itself, confirming:

- `git status` was byte-identical before and after the call (no project writes).
- `source_file_count: 272`, `dependency_files: 3` — unchanged code paths, as expected.
- `scope_inventory` produced 464 entries; `security_resource_files` correctly picked up 84 real files
  in this repo (e.g. `domains/*/.claude-plugin/plugin.json`, `domains/*/agents/*.md` as
  `runtime-prompt`, `scripts/postgres/*.sh`).
- `scope_inventory_sha256` is a valid 64-hex-char digest.

**Finding surfaced (pre-existing, not a P0 defect):** `source: 271` + `dependency-manifest: 3` = 274,
one less than `272 + 3 = 275`, because `pnpm-lock.yaml` matches **both** the configured `.yaml` source
extension and the `pnpm-lock.yaml` dependency-manifest marker — a overlap that already existed in the
independent `walkSourceFiles`/`walkDependencyFiles` functions before this P0. The unified inventory
must pick one classification per real file path and picks dependency-manifest; `source_files`,
`dependency_files`, and unit ownership themselves are computed by unchanged code and are unaffected.
Not fixed here per the explicit non-goal against changing that pre-existing behavior.

## 7. Unmet / deferred items (explicit, per spec §9)

1. **Live/paid benchmark** (`pnpm eval:offsec:run` / `:adjudicate` / `:eval:offsec`) was not run — the
   commands are preserved unchanged and documented, but running them requires a separate budget
   decision per the spec. No claim of finding recall/precision improvement is made anywhere in this
   change.
2. **Davinci dry measurement** — no such external target was available; a self-repo substitute was run
   instead (§6). This is disclosed, not silently substituted.
3. **Unit-level security-resource attachment** — deliberately deferred, per spec §4: only root-level VA
   read-scope inclusion was implemented (`sealedSecurityResourceFiles` in `assess.ts`), since
   attaching resources per work unit would touch source-unit ownership / result-identity surfaces the
   spec explicitly protects.
4. CI/CD workflow and TOML/HCL/Terraform/plugin-manifest classification rules are implemented (per
   §4 "Required behavior") but only the acceptance-bullet-required subset (Dockerfile, shell, Tauri,
   Supabase, runtime-prompt Markdown, `registry.json`) has dedicated fixture tests; the remainder is
   exercised only by code inspection, not a fixture test, given the acceptance bullet does not name them.

## 8. P0 correction pass

A post-implementation correction pass addressed six objective gaps. Each gap, its
implementation, and its test evidence:

### §1 — scope_inventory integrity binding

`sourceManifestContentProjection` (source-manifest.js:113-117) recomputes
`scope_inventory_sha256` from the actual embedded `scope_inventory` array, not from the
stored `scope_inventory_sha256` field. This binds the inventory content to the content hash
even if only the array was tampered while the stored hash was left unchanged. Old manifests
(pre-P0-B, no new fields) retain their original hash via conditional-inclusion guards
(lines 108-123).

Test: `scope inventory content mutation changes the new-schema content hash while the legacy
projection is unaffected` (source-manifest.test.js).

### §2 — schema version bump for new work-unit results (downgrade prevention)

New work-unit results are written with `schemaVersion: '1.1.0'`
(`WORK_UNIT_RESULTS_SCHEMA_VERSION` in assess.ts). Legacy 1.0.0 results (pre-P0-C, no
assurance concept) are the only results allowed to omit `assurancePath`/`assuranceSha256`.
If a non-legacy result has both references deleted, both assess.ts (resume path, line 1074)
and scope-assurance-gate.js (publication gate, line 97-106) reject with
`SCOPE_ASSURANCE_REFERENCE_MISSING` — the result cannot be downgraded into legacy by field
deletion alone.

Tests: `scope-assurance-gate: dropping assurance references from a fresh (non-legacy)
schemaVersion result is blocked, not downgraded to legacy` (report-gate-hook.test.js);
`resumes a legacy v1 work-unit result that never declared a scope assurance receipt`
(assess.test.ts — uses true legacy `schemaVersion: '1.0.0'` to confirm backward
compatibility).

### §3 — assurancePath confinement

`assurancePath` must be exactly `'00_scope_assurance.json'` — the comparison is a string
literal match, so any path traversal (`../`), absolute path, or alternative filename is
rejected without resolving against the filesystem. Enforced in both assess.ts (resume,
line 1086-1089) and scope-assurance-gate.js (publication, line 114-124).

Tests: `scope-assurance-gate: assurancePath with an interior traversal segment is rejected`;
`scope-assurance-gate: an absolute assurancePath is rejected` (report-gate-hook.test.js).

### §4 — plain-JS gate parity

scope-assurance-gate.js (CommonJS, no zod dependency) independently verifies:

- `sourceUnitId` against the sealed work plan (line 218-219)
- `sourceManifestSha256` against the sealed work plan (line 178-179)
- unresolved / context-capped edge counts (lines 213-227)
- `autonomousVerifierSealed === true` (line 228-229)
- `schemaVersion` literal `'1.0.0'` (lines 162-166)
- `disclosure` literal (lines 169-170)
- duplicate `completedUnitKeys` in results (lines 125-129)
- duplicate unit records in assurance (lines 195-199)
- structural nonnegative observation fields (lines 233-259)

No read-ratio or finding-density gate was added.

Tests: 14 tests in report-gate-hook.test.js (lines 693-849) exercise each check
independently, including self-consistently-forged documents that pass self-hash but
fail cross-validation.

### §5 — narrow Supabase JSON classification

`classifySupabaseSecurityJson` (source-manifest.js:280-289) recognizes only:
- `supabase/config.json` (project settings)
- `supabase/storage_buckets/**/*.json` (storage/bucket policies)

Other JSON under `supabase/` paths (e.g., `src-tauri/supabase/functions/share-viewer/deno.json`)
falls through to generic `other / inventory-only` unless another explicit rule applies.

Test: `scope inventory narrows Supabase JSON classification to config/storage-policy paths
only` (source-manifest.test.js) — covers `supabase/config.json`,
`supabase/storage_buckets/public-shares.json` (both security-resource), and
`src-tauri/supabase/functions/share-viewer/deno.json` (other / inventory-only).

### §6 — normalized traversal-free POSIX paths

`RelativePathSchema` (offsec-work-plan.ts:12-17) rejects `\0`, backslash, absolute paths,
and any segment that is `''`, `'.'`, or `'..'` (including interior `../`). This applies to
all `path` fields in `FileReceiptSchema` and `unresolvedEdges`. Valid legacy generated paths
(`packages/api/app.ts`) pass unchanged.

Tests: `rejects an interior ../ traversal segment in a parsed source manifest file path`;
`rejects an interior ../ traversal segment in a sealed work plan file field on parse`;
`still accepts normal generated relative paths after the traversal-free tightening`
(offsec-work-plan.test.ts).

### Correction-pass test fix

The legacy-resume test (`resumes a legacy v1 work-unit result that never declared a scope
assurance receipt` in assess.test.ts) was updated to set `schemaVersion: '1.0.0'` on the
fixture result. Previously, the fixture stripped assurance references from a `1.1.0` result,
which the downgrade protection in §2 correctly blocked — the test expectation was stale
relative to the implemented behavior.

## 9. Final hardening pass

A minimal final hardening pass addressed five areas without changing legacy behavior,
read-ratio/finding-density thresholds, or security-quality claims.

### §H1 — schemaVersion allow-list (1.0.0 and 1.1.0 only)

Both `assess.ts` (resume path) and `scope-assurance-gate.js` (publication gate) now
explicitly reject any `00_work_unit_results.json` whose `schemaVersion` is not in the
accepted set `{1.0.0, 1.1.0}`. Missing schemaVersion also fails closed.

- **1.0.0 without assurance**: true legacy — passes (backward compatible).
- **1.0.0 with assurance**: validated — assurance hash/structure checks run normally.
- **1.1.0**: requires exact `assurancePath`/`assuranceSha256` references (existing rule).
- **Any other or missing**: fail closed in both paths.

Tests: `scope-assurance-gate: an unknown results schemaVersion (e.g. 2.0.0) is fail-closed`;
`scope-assurance-gate: a missing results schemaVersion is fail-closed`
(report-gate-hook.test.js); `fails closed on resume when result schemaVersion is not in the
accepted set` (assess.test.ts).

### §H2 — results.units complete accounting

Both paths now validate `results.units` with the same rigor already applied to
`completedUnitKeys` and assurance `units`:

- `results.units` array required, length must match plan unit count.
- Unique `unitKey` per record — a duplicate record substituting for a missing unit is rejected.
- Exact key set — every plan unit must have exactly one result unit, and vice versa.
- `sourceUnitId` parity — when present, must match the sealed work plan.

`assess.ts` resume path enforces all four checks. `scope-assurance-gate.js` publication
gate enforces count, uniqueness, unknown-unit, and sourceUnitId parity.

Tests: `scope-assurance-gate: a duplicate result unit record substituting for a missing unit
fails`; `scope-assurance-gate: a result unit with mismatched sourceUnitId against the plan
is rejected` (report-gate-hook.test.js); `fails closed on resume when a result unit record
is duplicated to substitute for a missing unit` (assess.test.ts).

### §H3 — workPlanSha256 recompute at publication

`scope-assurance-gate.js` now independently recomputes `workPlanSha256` from the plan
content (excluding `workPlanSha256` and `generatedAt`, matching the TS `offsec-work-plan.ts`
convention) and compares against the stored value. A plan whose `maxContextFilesPerUnit` or
`units` were tampered after sealing — even if the rest of the cross-references happen to
align — is now caught at publication time.

Test: `scope-assurance-gate: a tampered workPlanSha256 (content hash recompute mismatch)
blocks publication` (report-gate-hook.test.js).

### §H4 — security_resource_files path validation

`assess.ts` now validates every `security_resource_files` entry before `resolve()`:
rejects absolute paths, null bytes, backslashes, empty segments, `.`, and `..` segments.
This is defense-in-depth for the P0-B-added root allow-list input surface; it does not
change legacy source/dependency file handling.

Test: `rejects a security_resource_files entry with a traversal segment on resume`
(assess.test.ts).

### §H5 — no read-ratio/finding-density thresholds

No read-ratio, finding-density, or security-quality thresholds were introduced in this
pass. All new checks are structural identity/integrity validations only.

### Hardening-pass test summary

New tests: +3 (`assess.test.ts`: duplicate result unit, unknown schemaVersion,
security_resource_files traversal); +5 (`report-gate-hook.test.js`: unknown schemaVersion,
missing schemaVersion, duplicate result unit, sourceUnitId mismatch, plan hash tamper).

## 10. Reviewer checklist cross-reference (spec §9)

- Structural correctness vs. proven security-analysis quality: the assurance receipt's `disclosure`
  field states plainly that Read counts are a minimum-examination signal, not proof of semantic
  analysis; no code path treats a nonzero read count as a quality claim.
- Actual Read telemetry vs. semantic examination: only `tool: 'Read', decision: 'allow'` events count;
  Grep/Glob activity is never promoted to "files examined" anywhere in this change.
- Legacy compatibility vs. new-run fail-closed: legacy paths (no `resolvedTarget`, no
  `security_resource_files`, no `assurancePath`/`assuranceSha256`) are explicitly tested to pass;
  new-run paths with a declared-but-broken assurance receipt are explicitly tested to fail closed, both
  at resume time (`assess.ts`) and at publication time (`report-gate-hook.js`).
- Security resources vs. source ownership: `source_files`, `dependency_files`, and unit `files` arrays
  are asserted unchanged by every new inventory test.
