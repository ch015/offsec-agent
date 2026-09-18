# Finding Detail: {{finding_id}}

> **사용 시점**: 개별 Finding 인용/공유 시 (Jira 티켓 description, Slack 알림, 외부 reviewer 송부 등)
> **대상 독자**: 해당 Finding의 수정 담당자 (개발자 또는 보안 엔지니어)
> **연관 보고서**: 전체 보고서 `va-report.template.md` 또는 `pentest-report.template.md` Section 5/6에서 인라인 참조 가능

---

## 개요

| 항목 | 내용 |
|------|------|
| ID | {{finding_id}} |
| 제목 | {{title}} |
| 심각도 | {{severity_icon}} {{severity}} |
| 발견 서비스 | {{service}} |
| Architecture Dimension | {{dimension}} |
| Root Cause | {{root_cause}} |
| 발견 일시 | {{timestamp}} |

---

## 표준 매핑

| 표준 | 항목 | 필수 |
|------|------|------|
| CWE | {{cwe}} | **필수** — CWE-NNN 형식. 복수 해당 시 쉼표 구분 |
| OWASP Top 10 | {{owasp}} | **필수** — A01~A10 또는 N/A |
| OWASP API Top 10 | {{owasp_api}} | API 도메인 활성 시 필수 |
| Secure Coding | {{secure_coding}} | 선택 |
| NIST 800-53 | {{nist}} | 선택 |

---

## 코드 위치

**파일**: `{{file_path}}`
**라인**: {{line_number}}

```{{language}}
{{vulnerable_code}}
```

---

## Taint Path Re-trace (Verifier Phase R1.2 / P1-2 신규)

| 항목 | 내용 |
|------|------|
| Classification | {{taint_classification}} <!-- Verified_Taint_Path \| Mitigated_Path \| Unreachable_Path \| Incomplete_Trace -->|
| Source | `{{taint_source_file}}:{{taint_source_line}}` |
| Sink | `{{taint_sink_file}}:{{taint_sink_line}}` |
| Hops | {{taint_hop_count}} |
| Sanitizers Found | {{taint_sanitizers_found}} |
| Notes | {{taint_notes}} |

> CRITICAL/HIGH Finding은 필수. 분류별 조치:
> - Verified_Taint_Path → Finding 유지
> - Mitigated_Path → 심각도 1단계 하향 + objection 발행
> - Unreachable_Path → LOW + Reachability 태그
> - Incomplete_Trace → manual_review_required

---

## 구조적 이슈

{{structural_description}}

> 이 이슈가 왜 구조적인지, 어떤 아키텍처 결정이 이를 만들었는지 설명합니다.

---

## 공격 시나리오

{{attack_scenario}}

---

## 공격 전제 조건 (Prerequisites)

| 항목 | 내용 |
|------|------|
| 직접 전제 | {{prerequisites_direct}} |
| 카테고리 | {{prerequisites_category}} |
| 침해 시 범위 | {{prerequisites_scope_if_compromised}} |
| 이 방어선 독립 유효성 | {{prerequisites_defense_survives}} |
| 실전 Feasibility | {{prerequisites_adjusted_feasibility}} |
| 판정 근거 | {{prerequisites_rationale}} |

> 전제조건이 "none"이면 외부 인터넷만으로 즉시 실행 가능한 공격입니다. 즉시 패치 필수.
> 전제조건이 "cloud_provider"이고 defense_survives=false이면 프로바이더 침해 시 이 방어선도 무력화됩니다.

---

## POC

### 전제 조건
{{poc_prerequisites}}

### 실행 코드
```{{poc_language}}
{{poc_code}}
```

### 성공 판정 기준
{{poc_criteria}}

---

## 라이브 검증 결과

| 항목 | 내용 |
|------|------|
| 상태 | {{live_status}} |
| 검증 방법 | {{live_method}} |
| 증거 | {{live_evidence}} |

---

## 수정 권고 + 6-step 영향도 분석

### 1. Change Target (수정 대상)
{{change_target}}

### 2. Reference Tracing (참조 추적)
{{reference_tracing}}

**추적 대상:**
- callers: 이 함수를 호출하는 모든 함수/컴포넌트
- importers: 이 모듈을 import하는 모든 파일
- API clients: 이 엔드포인트를 호출하는 프론트엔드 코드
- DB dependencies: 이 테이블/함수에 의존하는 트리거, 뷰, 정책

### 3. Impact Scope (영향 범위)

| 구분 | 영향 |
|------|------|
| Direct Impact | {{direct_impact}} |
| Indirect Impact | {{indirect_impact}} |

### 4. Side Effect Risks (부작용 위험)
{{side_effect_risks}}

### 5. Co-Requisite Changes (동시 수정 항목)
{{co_requisite_changes}}

### 6. Post-Fix Verification (수정 후 검증)
{{post_fix_verification}}

---

## 수정 예시 코드

```{{language}}
{{remediation_code}}
```

---

## 관련 Finding

{{#related_findings}}
- **{{id}}**: {{title}} ({{severity}}) — {{dimension}}
{{/related_findings}}

---

*CH015 AI Security Firm — {{timestamp}}*
