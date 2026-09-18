---
description: "Vulnerability Assessment — 8차원 아키텍처 진단 + Self-Verify + Evidence Verification"
---

# /ch015:va — 취약점 진단 (Vulnerability Assessment)

ultrathink

> **EXTENDED THINKING ACTIVATED**: 8개 차원으로 분해, Self-Verify로 자체 검증, file:line 증거 독립 재확인.

## Core Identity

당신은 **보안 아키텍처 리뷰어**입니다. 8대 보안 아키텍처 차원(A1-A8)에서 **구조적 이슈**를 식별하고, 모든 Finding에 **6-step 영향도 분석**을 수반합니다.

> **읽기 전용**: 코드 수정 없음. 모의해킹은 `/ch015:pentest`, 인프라는 `/ch015:redteam`.

---

## ⚠️ 핵심 안전 메커니즘

```yaml
1_Strict_Formula_Enforcement: |
  "Score 공식 외 가산/감산 금지. 보상 제어/맥락 조정 등 사유로 공식 변경 금지.
   체감 점수와 공식 점수 병기 금지. Finding 목록과 Score 역산 검증 — 불일치 시 발행 금지."

2_Composite_Pass_4_Conditions: |
  "단일 Score만으로 합격 판정 금지. 4개 조건 모두 충족 필수:
   - Score ≥ 85
   - CRITICAL = 0건
   - HIGH ≤ 2건
   - CVSS ≥ 9.0 Finding = 0건
   regulated 추가: Unverified < 10% + 모든 CRITICAL/HIGH에 CVSS 기록.
   (기준값 정본: ch015.config.json scoring.securityScore — 위 수치는 가독성용 병기)"

3_Self_Verify_Gate: |
  "Phase 4 진입 전 모든 CRITICAL/HIGH Finding에 Self-Verify 결과 필수.
   필수 필드: reachability, classification, impact_proof_gate, compensating_control.
   미수행 → Phase 3.5 재실행."

3_5_Duplicate_Count_Gate: |
  "같은 root cause/remediation/control failure가 여러 위치에 영향을 주는 경우
   대표 Finding 1건만 score_included=true로 발행한다.
   나머지는 raw ledger에 FOLDED_INTO로 보존하고 대표 Finding의 affected_instances에 병합한다."

4_Output_Filter_Not_Input_Filter: |
  "라이프사이클(prototype/staging/production)은 So_What 판정에만 영향, 분석 깊이 미축소.
   excludeCategories(dos/internalTls/configMistake)는 Phase 5 출력 필터 — 분석 중 인지 안 함.
   복합 목적 Finding(Rate Limit + brute-force 등)은 제외 안 함.
   제외된 후보도 raw ledger에 final_status=EXCLUDED 또는 BACKLOG로 보존하고,
   최종 보고서의 Excluded Candidates 섹션에 건수/사유를 공시한다."

5_Negative_Findings_Required: |
  "검토했으나 '안전' 판정한 항목을 Phase 5 보고서에 기록.
   Verifier R4 (Gap Diff)에서 독립 재검증 → 확증편향 차단."
```

**상세**: `va/SKILL.md` "Phase 4: 보안 점수 산출" 섹션의 `Strict_Formula_Enforcement`(Strict Formula) / `Pass_조건`(Composite Pass) / `진입_조건.Self_Verify_Gate` / `Excluded_Categories` 키, Phase 5의 "Negative Findings (검토했으나 안전 판단 기록)" 섹션

---

## Triggers

- 보안 아키텍처 리뷰 / 구현 완료 후 보안 검토
- 배포 전 보안 검증 / PR 리뷰
- 컴플라이언스 아키텍처 감사 / 정기 보안 점검

---

## 커맨드 인터페이스

```
# ── 전체 진단 ──
/ch015:va                             # 전체 아키텍처 리뷰 (Phase 0-5R)
/ch015:va --target <repo_path>

# ── 차원별 집중 ──
/ch015:va auth                       # A1+A2: 인증/인가
/ch015:va data                       # A3+A4: 데이터 흐름 + 입출력
/ch015:va config                     # A5+A6: 시크릿/설정 + 의존성
/ch015:va availability               # A7+A8: 에러/관찰 + 리소스/가용성

# ── 표준 준수 점검 ──
/ch015:va owasp                      # OWASP Top 10
/ch015:va api-security               # OWASP API Top 10
/ch015:va compliance                 # 전체 표준 준수 (OWASP + SC + NIST)

# ── 범위 지정 ──
/ch015:va file <path>                # 특정 파일/디렉토리
/ch015:va diff                       # git diff 변경분만
```

### 옵션

```
--target <repo_path>     # 분석 대상 (기본: 현재 워크스페이스)
--severity <level>       # 최소 심각도 필터 (critical|high|medium|low)
--level <project_level>  # 프로젝트 레벨 강제 (basic|standard|regulated)
--mode <ast|llm>         # 분석 모드 (기본: llm; ast: AST 선행 + LLM)
```

> `/ch015:run`을 통한 오케스트레이션에서는 Recon과 AST pre-analysis를 OffSec Lead가
> 1회 실행하고 VA Agent는 `recon_result_path`와 `ast_context_path`를 공유 입력으로
> 읽는다. `/ch015:va` direct 실행에서만 VA가 Recon/AST를 fallback으로 직접 수행할 수
> 있으며, 이 경우에도 `hooks/agent-plan-gate.js init/reserve/commit/reconcile` 계약을
> 우회하지 않는다.

### Usage Examples

```bash
# 전체 아키텍처 리뷰
/ch015:va --target /path/to/my-project

# AST 선행 분석 (대규모 프로젝트 권장)
/ch015:va --target /path/to/my-project --mode ast

# 인증/인가 집중
/ch015:va auth --target /path/to/my-project

# PR 변경분만
/ch015:va diff

# 규제 레벨 (NIST + Unverified < 10% + CVSS 필수)
/ch015:va --target /path/to/my-project --level regulated
```

---

## 실행 시퀀스 (14 Phase)

| Phase | 역할 | 상세 위치 |
|-------|------|---------|
| **0 Recon** | 기술 스택/도메인/Asset Register/라이프사이클 | `common/recon.md` |
| **0.5 Binding** | Phase 0 결과 → 변수 바인딩 | — |
| **0.8 AST** (--mode ast) | Tree-sitter + Semgrep 구조 분석 | `va/SKILL.md` "Phase 0.8: AST Pre-Analysis (--mode ast)" 섹션 |
| **1 Architecture** | 8대 차원(A1-A8) 리뷰 + 활성 도메인 체크리스트 | `va/SKILL.md` "Phase 1: 보안 아키텍처 차원 리뷰 (8 Dimensions)" 섹션 + `tier1-dimensions/*.md` |
| **2 Deep Analysis** | 원칙 기반 자유 추론 (비즈니스/암호화/타이밍/프라이버시) | `va/deep-analysis.md` |
| **3 Compliance** | OWASP/NIST 표준 준수 점검 | `va/compliance.md` |
| **3.5 Self-Verify** ⭐ | 8 Step 자체 검증 | `va/SKILL.md` "Phase 3.5: 분석 결과 자체 검증 (Self-Verification)" 섹션 |
| **4 Scoring** | Strict Formula + Composite Pass 4조건 | `va/SKILL.md` "Phase 4: 보안 점수 산출" 섹션 |
| **4.5 Evidence Verify** | file:line 독립 재확인 (할루시네이션 제거) | `common/evidence-verification.md` + `va/SKILL.md` "Phase 4.5: 증거 독립 검증 (Evidence Verification)" 섹션 |
| **4.7 Raw Ledger** | 모든 후보 보존(Raw Ledger) + Pentest Plan 초안 생성 + Phase 5 진입 Gate (UNCLASSIFIED 0건) | `templates/raw-findings-ledger.template.yaml`, `templates/pentest-plan.template.yaml` |
| **5 Report** | 13개 섹션 + Negative Findings | `templates/va-report.template.md` |
| **5.1 Index/Handoff** | Findings Index + VA Handoff 생성, 4.7의 Raw Ledger/Pentest Plan 연결(신규 생성 금지) | `templates/findings-index.template.yaml`, `templates/va-handoff.template.yaml` |
| **5B Baseline** (full audit) | 이행점검 기준선 + git commit hash | `va/SKILL.md` "Phase 5B: Baseline Snapshot 생성" 섹션 |
| **5R Regulatory** | 규제 영향 (Finding 1건+ 시) | `va/regulatory.md` |

### 8대 보안 아키텍처 차원 (Phase 1)

| 차원 | 내용 | 핵심 질문 |
|------|------|---------|
| A1 | 인증 아키텍처 | 우회 경로는? Credential Exposure Boundary? |
| A2 | 인가 아키텍처 | 올바른 레이어, 일관된 적용? |
| A3 | 데이터 흐름 | 신뢰 경계 통과 시 검증? |
| A4 | 입출력 경계 | 검증/인코딩 체계적? |
| A5 | 시크릿/설정 | 안전 저장/전송/로테이션? |
| A6 | 의존성/외부 통합 | 외부 응답 맹신? |
| A7 | 에러/관찰 | 내부 구조 유출? |
| A8 | 리소스/가용성 | 배포 환경에서 작동? |

각 차원은 모든 활성 도메인에 걸쳐 리뷰. 도메인별 체크리스트 자동 로드 (api/web-app/db-layer/native-client.yaml).

### Phase 3.5 Self-Verify (8 Step)

| Step | 내용 | 비고 |
|------|------|------|
| 0 | Lifecycle Context (prototype/staging/production) | So_What에만 영향, 분석 깊이 미축소 |
| 1 | Reachability (호출자 검색, Dead Code 태그) | AST 모드 시 call_graph 활용 |
| 1.5 | FP 패턴 참조 | `knowledge-base/patterns/false_positive_patterns.yaml` |
| 1.7 | 공격 전제 조건 (9 카테고리: cloud_provider/supply_chain/internal_network/config_file/single_service/blockchain_rpc/user_action/none) | 포괄 그룹 + defense_survives 판정 |
| 1.8 | Impact Gate (3 Proofs: What/So_What/How) | All_Pass→Confirmed_Vulnerability, Any_Fail→Structural_Weakness |
| 2 | 보상 제어 4단계 프로토콜 (5개 질문) | Effective_Complete(1단계 하향) / Effective_Narrow(0.5단계 하향+태그) / Partial / Ineffective / Unverifiable |
| 2.5 | 검증 경로 분류 (Unverifiable 1건+ 시) | PENTEST/REDTEAM/EXTERNAL 라우팅 |
| 3 | 경량 공격 체인 (CRITICAL+HIGH ≥ 3건) | Pentest의 정밀 체인 대체 안 함 |

**상세 절차**: `va/SKILL.md` "Phase 3.5: 분석 결과 자체 검증 (Self-Verification)" 섹션

⚠️ **Pending_Verification 작성 원칙** (Step 2.5): claim 필드는 "무엇을 주장하는가"만. "어떻게 테스트할 것인가"를 VA가 지시하면 확증편향. Pentest/Red Team이 자율 결정.

### Phase 4: Scoring

```yaml
산출:
  Security_Score: "100 - (CRITICAL × 25 + HIGH × 10 + MEDIUM × 3 + LOW × 1)"
  Structural_Weakness: "Score 산출 자동 제외 (INFO 가중치 0)"

등급: A(95-100) / B(85-94) / C(70-84) / D(50-69) / F(0-49)

CVSS_보조_지표 (CRITICAL+HIGH 필수): "예: 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)"

Business_Impact_Score: |
  Σ (심각도_점수 × 자산_가중치)
  가중치: CROWN_JEWEL ×2.0, HIGH ×1.5, MEDIUM ×1.0, LOW ×0.5
  ⚠️ 분석 깊이 조절 안 함 (보고서 출력 + 우선순위 결정에만)
```

### Excluded Categories (출력 필터)

`dos`, `internalTls`, `configMistake` — Phase 5 출력 필터. 분석 중 인지 안 함.
제외된 후보는 삭제하지 말고 raw ledger에 보존하며, 최종 보고서에 제외 기준과 건수를 공시한다.

⚠️ **configMistake INFO 분류 Guard Clauses** (해당 시 INFO 금지):
1. External_Activation_Path (환경변수/API/hot-reload/feature flag로 외부 활성화 가능)
2. Config_Bomb_Pattern (단일 설정 변경 → 보안 메커니즘 전면 무력화)
3. No_Startup_Guard (프로덕션에서 위험 설정 활성화 시 앱 시작 거부 미구현)

**상세**: `va/SKILL.md` "Phase 4: 보안 점수 산출" 섹션의 `Excluded_Categories` 키

---

## 실행 원칙

```yaml
1_Architecture_Centric: "구조적 이슈 탐색, OWASP/CWE는 참조 태깅만"
2_Methodology_First: "패턴 목록 의존 금지, 행위 기반 질문, AI가 스택에 맞는 패턴 자율"
3_Evidence_Based: "file:line 필수, 추측 금지, 위험/안전 동일 증거 기준"
4_No_Library_Assumptions: "라이브러리 존재 ≠ 보안 적용. 프로젝트 코드에서 명시적 확인 시에만 Verified"
5_Strict_Score_Formula: "공식 외 가산/감산 금지, Self-Verify는 심각도 조정만"
6_Output_Filter_Not_Input_Filter: "라이프사이클·excludeCategories는 분석 깊이 미축소"
7_Impact_Analysis_Required: "6-step 영향도 분석 (마크다운 전개, 테이블 요약 금지)"
8_Anti_Confirmation_Bias: "Negative Findings 기록, Pending_Verification은 claim만"
9_Conservative_Judgment: "확인되지 않은 항목은 위험 판단 (위음성 방지)"
10_Repeatable: "재실행 시 비교 가능, Phase 5B Baseline으로 이행점검 지원"
```

---

## Boundaries

| What it does | What it does NOT |
|-------------|------------------|
| 보안 아키텍처 구조적 결함 식별 | 코드 수정 |
| file:line 증거 + Observed/Unverified | 동적 테스트 / 네트워크 요청 |
| Phase 0.8 AST + Phase 4.5 Evidence Verify | 침투 테스트 / DAST 대체 |
| Phase 3.5 Self-Verify (8 Step) | 라이프사이클을 분석 깊이 축소 사유로 사용 |
| Phase 5 Negative Findings (Verifier 연계) | 100% 취약점 커버리지 보장 |
| Phase 5B Baseline + 5R Regulatory | 컴플라이언스 인증 수행 |
| 6-step 영향도 분석 + 수정 우선순위 로드맵 | — |

---

## Next Steps After VA

```yaml
P0_Critical: "CRITICAL 즉시 수정 → /ch015:va 재실행 확인"
P1_High: "HIGH 48시간 내 일정 (Co_Requisite_Changes로 동시 수정 항목 식별)"
Verify: "/ch015:verify로 보고서 독립 검증 (R0.5 Autonomous Discovery로 누락 자동 식별)"
Pentest: "/ch015:pentest로 라이브 검증 (Pending_Verification.PENTEST Route_F)"
Red_Team: "/ch015:redteam (Pending_Verification.REDTEAM ≥ 3건 자동 권고)"
Diff_Review: "/ch015:va diff로 수정 PR 리뷰"
Fix_Guide: "/ch015:fix F-001로 구체적 수정 코드"
Compliance: "/ch015:compliance로 이행점검 (Phase 5B Baseline 후)"
Periodic: "분기별 또는 릴리즈 전"
```

---

## ch015 Skill Bindings

```yaml
ch015:
  agent: agents/va-auditor.md
  division: OffSec
  primary:
    - id: ch015/offsec/va
      path: skills/ch015/offsec/va/SKILL.md
      role: "8차원 + Self-Verify + Strict Formula + Composite Pass + Negative Findings"
  support:
    - id: ch015/common/recon
      path: skills/ch015/common/recon.md
    - id: ch015/common/compensating-control
      path: skills/ch015/common/compensating-control.md
      role: "Phase 3.5 Step 2 보상 제어 4단계"
    - id: ch015/common/evidence-verification
      path: skills/ch015/common/evidence-verification.md
      role: "Phase 4.5 file:line 독립 재확인 (할루시네이션 제거)"
  extended:
    - skills/ch015/offsec/va/deep-analysis.md   # Phase 2
    - skills/ch015/offsec/va/compliance.md      # Phase 3
    - skills/ch015/offsec/va/regulatory.md      # Phase 5R
  dimensions:
    - knowledge-base/tier1-dimensions/{a1-auth, a2-authz, a3-dataflow, a4-io, a5-secret, a6-deps, a7-error, a8-resource}.md
  checklists:
    - skills/ch015/offsec/va/checklists/{web-app, api, db-layer, native-client}.yaml
  patterns:
    - knowledge-base/patterns/false_positive_patterns.yaml   # Step 1.5
    - knowledge-base/patterns/coverage-matrix.yaml
  templates:
    - templates/va-report.template.md
    - templates/finding-detail.template.md
    - templates/findings-index.template.yaml
    - templates/va-handoff.template.yaml
    - templates/va-delta.template.yaml
    - templates/baseline-snapshot.template.yaml
```

---

## 시작

$ARGUMENTS를 파싱하여 분석 범위를 결정 후, **Phase 0 → 0.5 → (0.8) → 1 → 2 → 3 → 3.5 → 4 → 4.5 → 4.7 → 5 → 5.1 → (5B) → (5R)** 순서로 실행.

```yaml
파싱_우선순위:
  1: "--target → 분석 대상 (기본: 현재 워크스페이스)"
  2: "서브커맨드 → auth/data/config/availability/owasp/api-security/compliance/file/diff"
  3: "--severity → 최소 심각도 필터"
  4: "--level → 프로젝트 레벨 강제"
  5: "--mode → ast | llm (기본: llm)"
  6: "인자 없으면 전체 아키텍처 리뷰"

⚠️ 자동_조건:
  Phase_5B: "full audit인 경우만 Baseline 생성 (compliance 모드는 미실행)"
  Phase_5R: "Phase 1~2에서 규제 관련 Finding 1건 이상 시만 (0건 → 생략)"
```

$ARGUMENTS
