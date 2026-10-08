# Structure planning

Inspect the host inventory, dependency graph and recon evidence. Read representative entry points and configuration when needed.
Read `inputs.resolvedDependencies` completely: it contains every resolved file dependency in compact form, without repeated parser metadata. After assigning units, account for EVERY directed pair of units connected by these edges, including imports from tests, configuration, boot code, shared helpers and environment files. These syntactic edges are planning obligations, not confirmed runtime reachability.
Group files by execution/trust boundary and functional/data responsibility. File count alone does not define a unit.
Assign EVERY listed source file to exactly one unit; priority surfaces do not narrow the analysis scope.
For each known dependency edge crossing units, assign a directed cross-unit flow and an owner at one endpoint. A single flow can cover multiple edges between the same units.
Write `00_scanner_plan.json` using this exact shape:
```json
{"schemaVersion":"1","units":[{"id":"U-AUTH","responsibility":"Authentication and session authorization","rationale":"Shared identity and credential trust boundary","files":["auth.ts"],"boundaryEvidence":["auth.ts"],"assumptions":[]}],"interfaces":[{"id":"I-AUTH","unitId":"U-AUTH","file":"auth.ts","kind":"HTTP","description":"Receives authentication requests from external clients"}],"prioritySurfaces":[{"unitId":"U-AUTH","files":["auth.ts"],"reason":"External authentication boundary and credential handling"}],"crossUnitFlows":[],"unresolved":[]}
```
Each crossUnitFlows item: `id`, `fromUnit`, `toUnit`, `ownerUnit`, `files` (evidence at both endpoints), `question` (what the Analyzer must trace).
Only inventory-relative exact file paths are accepted. No globs, omitted files, invented paths or duplicate owners.
Every `boundaryEvidence` path must belong to that unit's own `files`. A shared entry point such as `server.ts` belongs to one unit only; record other units' connections to it as crossUnitFlows with evidence from both owners. A flow's `ownerUnit` must be one of its two endpoints, and its `files` must include a file from each endpoint and none from unrelated units.
Write validation may return several defects together. Correct the full list before resubmitting; an invalid Write is not saved as an approved plan.
Use source evidence for every boundary. State uncertainty in assumptions/unresolved.
Do not write analysis findings. Return the normal phase result envelope after writing the plan.
