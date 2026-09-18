# Adversarial Verification Report — {{project_name}}

> **사용 시점**: Verifier 실행 (`/ch015:verify`) 시 — VA/Pentest/RedTeam 보고서 독립 검증 결과
> **대상 독자**: VA/Pentest 작성자 + OffSec Lead + CISO (이의 목록 + 의존성 + 누락 식별)
> **연관 산출물**: `02a_verify_autonomous-<round>.md` (R0.5), `02b_verify_gap-<round>.md` (R4)

**원본 보고서**: `{{original_report_path}}` (생성일: {{original_report_date}})
**검증 수행일**: {{verification_date}}
**대상 소스**: `{{source_path}}`
**Round**: {{verify_round}}   <!-- 1st | 2nd -->

---

## 0. Autonomous Discovery Summary (R0.5)

> VA 보고서를 열람하기 전에 Verifier가 **독립적으로** 수행한 탐색 결과입니다.
> 파일: `{{autonomous_file}}` (02a_verify_autonomous-{{round}}.md)

| 지표 | 값 |
|---|---|
| Autonomous Finding 후보 수 | {{autonomous_finding_count}} |
| Lite/Full 모드 | {{autonomous_mode}} |
| 커버된 차원 | {{autonomous_dimensions_covered}} |
| 탐색 못 한 영역 | {{autonomous_uncovered}} |

{{#autonomous_findings}}
- **{{id}}** ({{dimension}}, {{severity_estimate}}) — `{{location}}`: {{one_line_reason}}
{{/autonomous_findings}}

{{#has_ast_stats}}
### 0-2. AST 구조 분석 통계

> ast-grep + semgrep으로 수집한 정량적 코드 구조 데이터입니다.

| 항목 | 탐지 수 | 주요 위치 |
|------|---------|-----------|
{{#ast_pattern_rows}}
| {{pattern}} | {{count}} | {{locations}} |
{{/ast_pattern_rows}}

| semgrep Rule | 탐지 수 | 비고 |
|-------------|---------|------|
{{#semgrep_rows}}
| {{rule}} | {{count}} | {{note}} |
{{/semgrep_rows}}
{{/has_ast_stats}}

---

## 1. Evidence Audit (R1-Unified)

### 1-1. Observed / Unverified / Invalidated 재분류

| Finding | 원본 분류 | 재분류 | 사유 |
|---------|----------|-------|------|
{{#evidence_rows}}
| {{finding_id}} | {{original}} | {{revised}} | {{reason}} |
{{/evidence_rows}}

### 1-2. Semantic Taint Re-trace (CRITICAL/HIGH 필수)

| Finding | Source | Sink | Hops | Sanitizer | 분류 |
|---------|--------|------|------|-----------|------|
{{#taint_rows}}
| {{finding_id}} | `{{source}}` | `{{sink}}` | {{hops}} | {{sanitizer}} | {{classification}} |
{{/taint_rows}}

### 1-3. Compensating Control Re-verification

| Finding | 보상제어 | VA 판정 | Verifier 판정 | 근거 |
|---------|---------|--------|-------------|------|
{{#compensating_rows}}
| {{finding_id}} | {{control}} | {{va_verdict}} | {{verifier_verdict}} | {{evidence_items}} |
{{/compensating_rows}}

---

## 2. Dependency + Sensitivity (R2-Analysis)

### 2-1. Finding 의존성 그래프

```
{{dependency_graph_ascii}}
```

### 2-2. What-If 심각도 민감도

{{#sensitivity_rows}}
- **{{finding_id}}** 가 해소되면 → `{{affected}}` 이 {{impact}}
{{/sensitivity_rows}}

### 2-3. Quantitative Corrections (AST 정량 보정)

{{#has_quantitative_corrections}}
| Finding | VA/PT 주장 | AST 정확 카운트 | 보정 |
|---------|-----------|----------------|------|
{{#quantitative_rows}}
| {{finding_id}} | {{claim}} | {{ast_count}} | {{correction}} |
{{/quantitative_rows}}
{{/has_quantitative_corrections}}

### 2-4. Score Recalculation (심각도 조정 시에만)

{{#score_diff_present}}
| 항목 | 원본 | 재계산 |
|---|---|---|
| CRITICAL | {{orig_crit}} | {{new_crit}} |
| HIGH | {{orig_high}} | {{new_high}} |
| MEDIUM | {{orig_med}} | {{new_med}} |
| LOW | {{orig_low}} | {{new_low}} |
| Security Score | {{orig_score}} | {{new_score}} |
{{/score_diff_present}}

---

## 3. Gap Diff — Autonomous × VA (R4-GapDiff)

> Verifier의 R0.5 독립 탐색과 VA 보고서를 교차 분석한 결과입니다.
> 파일: `{{gap_file}}` (02b_verify_gap-{{round}}.md)

### 3-1. 분류 카운트

| 분류 | 개수 | 의미 |
|---|---|---|
| Matched | {{matched_count}} | 양쪽 다 발견 |
| VA_Only | {{va_only_count}} | Verifier가 놓침 (학습 데이터) |
| **Autonomous_Only** | **{{auto_only_count}}** | **VA가 놓침 (누락 후보)** |

### 3-2. Autonomous_Only — 누락 Finding 상세

{{#autonomous_only_findings}}
#### {{v_id}} → {{promoted_finding_id}}

- 위치: `{{location}}`
- 심각도 (Verifier 독립 추정): {{severity}}
- Taint 재추적 결과: {{taint_classification}}
- 근거: {{rationale}}
{{/autonomous_only_findings}}

### 3-3. Raw Candidate Omission Audit

> Raw ledger에는 있었지만 final report에 없거나 다른 항목으로 접힌 후보입니다.
> 삭제가 아니라 상태 분류가 되었는지 검증합니다.

| Candidate | Title | Initial Severity | Final Status | Verifier Opinion | Required Next Step |
|---|---|---:|---|---|---|
{{#omission_audit_rows}}
| {{candidate_id}} | {{title}} | {{severity_initial}} | {{final_status}} | {{verifier_opinion}} | {{required_next_step}} |
{{/omission_audit_rows}}

### 3-4. Classification Completeness Gate

| 항목 | 값 |
|---|---:|
| Raw candidates | {{raw_candidate_count}} |
| Classified | {{classified_candidate_count}} |
| Unclassified | {{unclassified_candidate_count}} |
| Publish allowed | {{publish_allowed}} |

{{#unclassified_candidates}}
- **{{candidate_id}}** — {{title}}: {{reason}}
{{/unclassified_candidates}}

### 3-5. Over-Confidence Gate

| 지표 | 값 |
|---|---|
| VA Negative Findings 수 | {{negative_count}} |
| VA Finding 수 | {{finding_count}} |
| Negative/Finding 비율 | {{ratio}} |
| 게이트 발동 (≥1.5배) | {{over_confidence_triggered}} |
| 뒤집힌 Negative 비율 | {{reversed_negative_pct}} |
| VA 재실행 권고 | {{va_rerun_recommended}} |

---

## 4. Dispute Resolution (CISO Escalation 시)

{{#has_disputes}}
{{#dispute_items}}
### {{finding_id}} — Disputed

| 항목 | VA 주장 | Verifier 주장 |
|---|---|---|
| Severity | {{va_severity}} | {{verifier_severity}} |
| 근거 | {{va_evidence}} | {{verifier_evidence}} |

**CISO Decision**:
- Method: {{dispute_method}} <!-- pentest_route_f | reanalysis | conservative_default | time_bounded_accept (agents/ciso.md decision_schema 정본) -->
- Final Severity: {{dispute_final_severity}}
- Evidence Artifact: `{{dispute_evidence_path}}`
- Rationale: {{dispute_rationale}}

{{/dispute_items}}
{{/has_disputes}}

---

## 5. Detection Signals (RedTeam 보고서 병합 시에만)

> Red Team 결과가 포함된 통합 진단의 경우, 공격 체인별 SOC Detection 힌트를
> 요약한다. 상세는 `06b_redteam_result.md` 의 Phase 6 Detection Engineering 섹션.

{{#detection_signals}}
### {{chain_id}}: {{chain_title}}

- 주요 아티팩트: {{artifacts_summary}}
- 예상 로그 소스: {{log_sources}}
- 현재 EDR/SIEM 커버리지: {{edr_coverage}}
- 탐지 갭: {{detection_gap}}
- 추천 탐지 룰 (SIEM/EDR): {{recommended_rules}}
{{/detection_signals}}

---

## 6. 최종 권고

- Convergence Ready: {{convergence_ready}}
- Adjusted Security Score: {{adjusted_score}} / 등급 {{adjusted_grade}}
- 재실행 필요 여부: {{rerun_required}}
- CISO 전달 사항:
  {{#ciso_hints}}- {{.}}
  {{/ciso_hints}}

---

**Verifier**: {{verifier_agent_version}}
**Engagement**: `{{engagement_id}}`
**Audit Log**: `{{engagement_dir}}/audit.log`
