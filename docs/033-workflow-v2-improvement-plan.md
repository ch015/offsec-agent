# OffSec 워크플로 개선 계획

> **이전 기록 — 2026-09-22 안내 갱신.** v2 전환 계획과 당시 구현 기록이다. 현재 v1/v2가 공존하며 source·범위·발행 검증을 유지한다. 아래 미체크 항목이나 전면 throw 삭제 계획은 현재 승인된 구현 상태를 뜻하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

> 대상: `secops-offsec-agent`
> 목표: 13-phase/5-role → 6-phase/4-role 선형 파이프라인 전환
> 전제: 외부 침입으로 인한 산출물 변조 위협 모델 제거

## 0. 구현 현황 (Implementation Status)

> 갱신: M9. **M1–M8 완료.** v1(assess.ts)은 보존한 채 v2 선형 파이프라인을 병행 추가했다.

### 마일스톤

| 마일스톤 | 상태 | 비고 |
|----------|------|------|
| M1 계약 재정의 | ✅ 완료 | `offsec-contract.v2.json` (version `2.0.0`) 생성 |
| M2 로더 + 어댑터 | ✅ 완료 | `offsec-contract.ts`, `domains/offsec.ts` v2 분기 |
| M3 세션 + finding | ✅ 완료 | reviewer/analyzer role 추가, pentest 분기 guard |
| M4 오케스트레이터 | ✅ 완료 | `missions/assess-v2.ts` 신규 (v1 대체가 아닌 병행) |
| M5 엔진/인프라 정리 | ✅ 완료 | phase-agnostic 인프라 재사용 |
| M6 throw 정리 | ⚠️ **별도 재검토 예정** | 아래 throw 현황 참조 |
| M7 테스트 | ✅ 완료 | v2 계약/오케스트레이션 테스트 |
| M8 평가/스크립트 | ✅ 완료 | `assess:v2` 스크립트 등록, eval adapter 갱신 |

### 계약 검증 (실측)

- **버전**: `offsec-contract.v2.json` → `version: "2.0.0"` ✓
- **역할**: `analyzer` / `reviewer` / `evaluator` / `reporter` (verifier/pentester/redteam 제거) ✓
- **phase**: `recon → plan → analyze → review → evaluate → report` ✓
- **leadRole**: `reporter`, `executionMode`: `host-bounded-workers`
- v1 계약(`offsec-contract.v1.json`)과 v1 진입점(`assess.ts`)은 **그대로 보존** — resume/legacy 경로 유지

### 계획 대비 실제 변경 (편차 기록)

| 항목 | 계획 | 실제 | 편차 |
|------|------|------|------|
| recon/plan 방법 카드 | `methods/recon.md`, `methods/plan.md` 신규 | host phase로 구현, `requiredMethodFiles: []` | 방법 카드 대신 host 결정론 실행. recon.md/plan.md 미생성 |
| report 방법 카드 | `methods/report.md` 유지 | `methods/report.v2.md` 신규 | v1 report.md 보존, v2 전용 카드 분리 |
| analyze 산출물 | `02_units/unit-*/findings.json` + `analysis.md` | `work-units/<unitKey>/` per-unit + `00_work_unit_results.json` 집계 | 경로/집계 방식 구체화 |
| review 산출물 | `03_review.json` | `03_review_result.json` | 파일명 |
| evaluate 산출물 | `04_evaluation.json` | `04_evaluation.json` + `04_evaluation_classification.yaml` | classification yaml 추가 |
| report 산출물 | `security_report.md` | `07_security_report.draft.md` → `07_security_report.md` (publication) | draft/final 2단계 |
| v2 오케스트레이터 | `assess.ts` 재작성 (1970→~800줄) | `assess-v2.ts` **신규**, `assess.ts` 무변경 보존 | v1 대체가 아닌 병행 추가 |

### throw 현황 (실측)

| 경로 | throw 수 | 비고 |
|------|--------:|------|
| **v2 경로** | **78** | 목표 ~76 대비 +2. M6에서 재검토 |
| **v1 경로 (보존)** | **605** | v1 유지 결정에 따라 삭제하지 않고 그대로 보존 |

> M4에서 v1을 삭제·재작성하는 대신 v2를 **병행 추가**하기로 결정하면서, 계획의 "v1 throw 605 → ~76"은
> "v2 경로 신규 78 + v1 605 보존"으로 재해석되었다. 전면 throw 삭감(계획 §1, §6)은
> **M6 throw 정리를 별도 작업으로 재검토**할 때 v1 deprecation 시점과 함께 다룬다.

---

## 1. 현재 → 목표

```
현재 (13 phase, 5 role):
va → verify → (va-feedback ↔ verify-feedback)* → pentest-plan → pentest-discovery
→ pentest → pentest-verify → (pentest-feedback ↔ pentest-verify-feedback)*
→ redteam → converge → report

목표 (6 phase, 4 role):
recon → plan → analyze (병렬) → review → evaluate → report
```

### 산출물 구조

```
<target>/.nunchi/
  engagements/<engagementId>/
    00_recon.json                    ← recon (host deterministic)
    00_dependency_graph.json         ← recon (기존 재사용)
    01_analysis_plan.json            ← plan (work-unit 분할 + 분석 지시)
    02_units/                        ← analyze (에이전트별 병렬)
      unit-<hash>/
        findings.json
        analysis.md
    03_review.json                   ← review (전수 검수 + 코드 대조 보정)
    04_evaluation.json               ← evaluate (커버리지 + 객관적 평가)
  reports/
    security_report.md               ← report (최종 리포트)
```

### 역할 재편

| 현재 | 목표 | 변경 |
|------|------|------|
| va-auditor | **analyzer** | 이름 변경, 분석 역할 동일 |
| verifier | ❌ 삭제 | review 에이전트가 대체 |
| — | **reviewer** (신규) | 산출물 검수·실제 코드 대조·보정 |
| — | **evaluator** (신규) | 전체 객관적 평가 |
| offsec-lead | **reporter** | report 전용 단순화 |
| pentester | 보류 (v2) | PENTEST 별도 모드 분리 |
| redteam-reviewer | 보류 (v2) | REDTEAM 별도 모드 분리 |

### throw 영향

| 범주 | 현재 | 전환 후 | 설명 |
|------|----:|-------:|------|
| 외부 변조 방어 BLOCK | 74 | 0 | 위협 모델 제거 |
| path safety BLOCK | 36 | 36 | 유지 (에이전트 hallucination 방어) |
| WARN (품질 검증) | 485 | ~30 | review 에이전트가 직접 판단, 최소 안전장치만 잔존 |
| AUTOFIX | 2 | 0 | review 에이전트가 수행 |
| 신규 (새 워크플로) | — | ~10 | 새 phase 최소 안전장치 |
| **합계** | **605** | **~76** | **87% 감소** |

---

## 2. 실행 단계

### M0. 준비 — 결정 확정 + 분기

**작업:**
- [ ] PENTEST/REDTEAM 결정: v1에서 제외, v2에서 별도 모드로 분리 (확정)
- [ ] `feature/workflow-v2` 브랜치 생성
- [ ] 기존 코드의 현재 테스트 상태 스냅샷 기록

**산출물:** 브랜치, 결정 기록

---

### M1. 계약 재정의 — `domains/offsec/`

**대상 파일:**
| 파일 | 작업 | 설명 |
|------|------|------|
| `contracts/offsec-contract.v2.json` | 신규 생성 | 6 phase, 4 role, 새 artifact 목록 |
| `contracts/roles/analyzer.md` | 신규 (va-auditor.md 기반) | analyze 역할 system prompt |
| `contracts/roles/reviewer.md` | 신규 | review 역할 system prompt — 코드 대조 지침 |
| `contracts/roles/evaluator.md` | 신규 | evaluate 역할 system prompt |
| `contracts/roles/reporter.md` | 신규 (offsec-lead.md 기반) | report 전용 단순화 |
| `methods/recon.md` | 신규 | recon 방법 카드 |
| `methods/plan.md` | 신규 | plan 방법 카드 |
| `methods/analyze.md` | 신규 (va.md 기반) | analyze 방법 카드 |
| `methods/review.md` | 신규 | review 방법 카드 — evidence 대조 절차 |
| `methods/evaluate.md` | 신규 (converge.md 기반) | evaluate 방법 카드 |
| `methods/report.md` | 기존 유지 | 경미한 수정 |
| `contracts/roles/verifier.md` | 삭제 | reviewer가 대체 |
| `methods/verify.md` | 삭제 | review.md가 대체 |
| `methods/va-feedback.md` 등 | 삭제 | feedback loop 제거 |
| `methods/pentest-*.md` | 삭제 | v2 보류 |
| `methods/redteam.md` | 삭제 | v2 보류 |
| `hooks/verify-invariants.js` (+test) | 삭제 | 외부 변조 모델 제거 |
| `hooks/hooks.json` | 수정 | verify-invariants 연결 제거, 역할명 갱신 |
| `hooks/pre-tool-use.js` | 수정 | 역할/phase 참조 갱신 |
| `hooks/report-gate-hook.js` | 수정 | review 기반 발행 조건 |

**계약 v2 핵심 구조:**
```json
{
  "id": "nunchi.offsec.assessment",
  "version": "2.0.0",
  "phases": [
    { "id": "recon",    "role": "host",      "requires": [] },
    { "id": "plan",     "role": "host",      "requires": ["recon"] },
    { "id": "analyze",  "role": "analyzer",  "requires": ["plan"] },
    { "id": "review",   "role": "reviewer",  "requires": ["analyze"] },
    { "id": "evaluate", "role": "evaluator", "requires": ["review"] },
    { "id": "report",   "role": "reporter",  "requires": ["evaluate"] }
  ],
  "roles": {
    "analyzer":  { "tools": ["Read","Grep","Glob","Bash","Write","submit_finding"] },
    "reviewer":  { "tools": ["Read","Grep","Glob","Write"] },
    "evaluator": { "tools": ["Read","Grep","Glob","Write"] },
    "reporter":  { "tools": ["Read","Grep","Glob","Write"] }
  }
}
```

**검증:** `pnpm generate:contract-resources` → resource manifest 재생성, `pnpm typecheck`

---

### M2. 계약 로더 + 도메인 어댑터 갱신 — `src/runtime/`

**대상 파일:**
| 파일 (LOC) | 작업 | 변경량 |
|------------|------|--------|
| `offsec-contract.ts` (640) | 수정 | ~80줄 — v2 schema 분기, `resolvePhaseMethodologyFiles` 역할 목록 갱신, `liveTestPolicy` 선택적, version regex `^[12]\.\d+\.\d+$` |
| `domains/offsec.ts` (330) | 수정 | ~120줄 — `createOffsecWorkflowContract` v2 분기, `canTransition` 재작성 (analyze→review→evaluate→report), `validateAcceptedResult` 단순화 (verifier/pentest 분기 제거), `assertOffsecConvergenceReady` → `assertReviewComplete` |
| `domains/registry.ts` (66) | 무변경 | — |
| `contracts/workflow-contract.ts` (210) | 무변경 | — (제네릭, phase-agnostic) |
| `contracts/result-contract.ts` (150) | 무변경 | — |
| `session-types.ts` (60) | 무변경 | — |

---

### M3. 세션 + Finding 계약 갱신

**대상 파일:**
| 파일 (LOC) | 작업 | 변경량 |
|------------|------|--------|
| `session.ts` (730) | 수정 | ~60줄 — `sourceReadable` 역할 목록에 `reviewer`, `analyzer` 추가; pentest/live-DAST 분기를 `verificationMode` guard로 감싸 비활성화 |
| `finding-contract.ts` (500) | 수정 | ~40줄 — pentester 분기 비활성화 (`verificationMode` guard); `assertPentestRuntimeEvidenceIntact` 호출 조건화 |
| `objection-contract.ts` (180) | 삭제 | objection 개념 제거 — review 에이전트가 대체 |
| `finding-mcp-server.ts` (100) | 무변경 | — (phase/role 파라미터는 caller가 전달) |

---

### M4. 오케스트레이터 재작성 — `missions/assess.ts`

**가장 큰 변경. 1970줄 → ~800줄 예상.**

**유지 (인프라, ~600줄):**
- CLI 파싱 (`parseArgs`, `main`) — 플래그 정리 (pentest 옵션 비활성화)
- 프리플라이트 (target/model/budget 검증, checkpoint, engagementDir)
- `createMissionRuntime` + 상태/lease/artifact 배관
- `ModelIndependenceGuard`
- AST preanalysis + Semgrep
- `executeBoundedWork` 호출 패턴 (병렬 단위 실행 인프라)
- `publishValidatedReport`, `recordOffsecPublication`

**재작성 (phase 시퀀싱, ~200줄 신규):**
```
assess() 새 흐름:
  1. preflight (기존)
  2. recon: createDependencyGraph + runHostRecon → 00_recon.json
  3. plan: createOffsecWorkPlanV2 → 01_analysis_plan.json
  4. analyze: executeBoundedWork (unit별 analyzer 에이전트)
     - 각 unit → findings.json + analysis.md
     - feedback loop 없음, verify 없음
  5. review: 단일 reviewer 에이전트
     - 모든 unit findings를 받아 실제 코드 대조 + 보정
     - 03_review.json 산출
  6. evaluate: 단일 evaluator 에이전트
     - 커버리지, severity 분포, 전체 보안 수준
     - 04_evaluation.json 산출
  7. report: reporter 에이전트 → security_report.md
  8. publish (기존)
```

**삭제 (~800줄):**
- verify/feedback loop 전체 (~1451–1530)
- PENTEST 블록 전체 (~1560–1710)
- REDTEAM 블록 (~1712–1760)
- `assertOffsecConvergenceReady` 호출 (→ `assertReviewComplete`로 교체)
- live-DAST 준비 (`prepareLiveDast`, `resolveLiveTestTarget` 등)
- IaC manifest 준비
- unit 내부 verify/feedback inner loop

**산출물 경로 변경:**
```typescript
// 현재
const engagementDir = input.engagementDir ?? join(target, '.nunchi', 'reports', engagementId);

// 변경
const engagementDir = input.engagementDir ?? join(target, '.nunchi', 'engagements', engagementId);
const reportDir = join(target, '.nunchi', 'reports');
```

---

### M5. 엔진 + 워크플로 인프라 정리

**대상 파일:**
| 파일 (LOC) | 작업 | 변경량 |
|------------|------|--------|
| `workflow/engine.ts` (888) | 무변경 | — (phase-agnostic 재사용) |
| `workflow/offsec-dependency-graph.ts` (1177) | 무변경 | — (100% 재사용) |
| `workflow/offsec-work-plan.ts` (913) | 무변경 | — (95% 재사용) |
| `workflow/graph-rag.ts` (500) | 무변경 | — |
| `workflow/scope-assurance.ts` (170) | 수정 | ~20줄 — verifier 관측 제거, analyzer만 기록 |
| `workflow/bounded-work-executor.ts` (100) | 무변경 | — |
| `workflow/cost-guard.ts` (150) | 무변경 | — |
| `workflow/state-store.ts` (460) | 수정 | ~10줄 — publication 도메인 guard에서 offsec 조건 완화 |
| `workflow/transitions.ts` (120) | 수정 | ~30줄 — 새 phase DAG에 맞춰 전이 규칙 갱신 |
| `workflow/host-recon.ts` (80) | 무변경 | — |
| `workflow/run-lease.ts` (220) | 무변경 | — |
| `workflow/mission-runtime.ts` (140) | 무변경 | — |
| `workflow/model-independence.ts` (40) | 무변경 | — |
| `workflow/host-integrity.ts` (50) | 수정 | ~20줄 — hash 재검증 경로 간소화 |

---

### M6. throw 정리

**M1–M5가 완료된 후, 잔존 throw를 정리.**

| 대상 | 현재 throw | 정리 후 | 방법 |
|------|----:|-------:|------|
| 외부 변조 방어 (hash/seal/fencing) | 74 | 0 | 삭제 |
| WARN (형식/중복/상태) | 485 | ~30 | 대부분 삭제; 최소 안전장치(path, sandbox)만 유지 |
| pentest/redteam/live-DAST 전용 | ~80 | 0 | 코드 자체 삭제 |
| verify/feedback/objection 전용 | ~50 | 0 | 코드 자체 삭제 |
| 잔존 (path safety + 새 워크플로) | — | ~46 | 유지 + 신규 |

---

### M7. 테스트 갱신

| 분류 | 파일 수 | 테스트 수 | 작업 |
|------|-------:|--------:|------|
| KEEP (제네릭 인프라) | 20 | ~150 | 무변경 |
| REWRITE (phase 결합) | 14 | ~156 | phase 이름/역할/artifact 갱신 |
| DELETE (verify/feedback/seal) | 4 | ~21 | 삭제 |
| CONDITIONAL (live-DAST) | 7 | ~34 | v1에서 비활성화, v2에서 복원 |
| 신규 (review/evaluate) | 3+ | ~30+ | 신규 작성 |

**핵심 신규 테스트:**
- `review-agent.test.ts` — reviewer가 잘못된 evidence를 보정하는지, false positive를 제거하는지
- `evaluate-agent.test.ts` — evaluator가 커버리지 누락을 감지하는지
- `assess-v2.test.ts` — 새 6-phase 오케스트레이션 E2E

---

### M8. 평가 + 스크립트 갱신

| 파일 | 작업 |
|------|------|
| `evals/offsec/adapters/current.ts` | phaseOrder 맵 재작성 (6 phase) |
| `evals/offsec/policy.json` | declaredClaims에서 pentest/redteam 제거, review/evaluate 추가 |
| `scripts/ab-compare.ts` | objection 파싱 제거 |
| `scripts/probe-offsec-load.ts` | v2 계약 참조 |
| `README.md` | 새 워크플로, 역할, 산출물 구조, CLI 옵션 반영 |

---

### M9. 문서 + 최종 검증

- [x] 설계 결정 문서 (본 문서 §0 구현 현황으로 기록)
- [x] v2 계약 검증 (version 2.0.0 / analyzer·reviewer·evaluator·reporter / recon→plan→analyze→review→evaluate→report)
- [x] v1 경로(assess.ts, offsec-contract.v1.json) 보존 확인
- [ ] M6 throw 정리 별도 재검토 (v2 78, v1 605 보존)

---

## 3. 실행 순서 + 의존성

```
M0 ─→ M1 ─→ M2 ─→ M3 ─→ M4 ─→ M5 ─→ M6 ─→ M7 ─→ M8 ─→ M9
 준비   계약   로더   세션   오케    인프라  throw  테스트  eval   검증
             어댑터  finding 스트레   정리   정리   갱신   문서
                          이터
```

**M1–M3은 순차** (계약이 로더/어댑터의 입력).
**M4는 M1–M3 완료 후** (오케스트레이터가 모든 런타임을 조합).
**M5는 M4와 병렬 가능** (인프라는 독립적 정리).
**M6은 M4–M5 완료 후** (throw 정리는 코드 안정 후).
**M7–M9는 M6 완료 후** (테스트·검증은 최종).

---

## 4. 변경량 추정

| 항목 | 줄 수 |
|------|------:|
| 신규 작성 | ~1,200 |
| 수정 | ~400 |
| 삭제 | ~2,500 |
| **순 변경** | **~-900** (코드 감소) |

| 세부 | 신규 | 수정 | 삭제 |
|------|-----:|-----:|-----:|
| 계약 JSON + 역할 .md + 방법 카드 | 500 | — | 300 |
| assess.ts 재작성 | 200 | — | 800 |
| offsec.ts + offsec-contract.ts | — | 200 | 150 |
| session.ts + finding-contract.ts | — | 100 | 50 |
| objection-contract.ts | — | — | 180 |
| verify-invariants.js + tests | — | — | 700 |
| hooks 수정 | — | 50 | — |
| throw 정리 | — | 50 | 300 |
| 테스트 (삭제 + 신규) | 500 | — | 200 |

---

## 5. 위험 + 완화

| 위험 | 영향 | 완화 |
|------|------|------|
| reviewer 에이전트 context window 한계 | finding 수가 많으면 전수 코드 대조 불가 | unit별 review 병렬화 + merge 2단계 |
| reviewer 품질이 verifier보다 낮을 가능성 | false positive 증가 | evaluate 단계에서 교차 검증 + 벤치마크 |
| 기존 벤치마크/eval 호환성 깨짐 | 성능 비교 불가 | M8에서 eval adapter 갱신, v1 baseline 보존 |
| v2 계약과 v1 산출물 비호환 | 기존 engagement resume 불가 | v2는 새 engagement만. v1 resume은 git tag로 보존 |
| PENTEST/REDTEAM 보류로 커버리지 감소 | 동적 검증 없음 | v1 대비 명시적 한계 문서화, v2 로드맵에 포함 |

---

## 6. 성공 기준

1. `pnpm typecheck` 오류 0
2. `pnpm test` 통과 (기존 인프라 테스트 + 신규 v2 테스트)
3. `pnpm test:vendor` 기존 결과 유지 (592 pass)
4. throw 수 605 → 80 이하
5. 실제 타겟 대상 E2E: recon → plan → analyze → review → evaluate → report 완주
6. 산출물이 `<target>/.nunchi/engagements/` + `reports/`에 정상 생성
