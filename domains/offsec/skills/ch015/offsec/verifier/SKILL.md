---
name: ch015-verifier
description: "Run CH015 adversarial verification workflows to independently validate security reports, recheck file-line evidence, find false positives, severity errors, missed findings, and dependencies."
---

# 독립 검증 (Adversarial Verification) Skill

> 보안 진단 보고서를 독립적으로 검증하여 오탐, 심각도 오류,
> 누락된 Finding, Finding 간 의존성을 식별합니다.

---

## 서비스 개요

| 항목 | 내용 |
|------|------|
| 서비스명 | 독립 검증 (Adversarial Verification) |
| 방법론 | 증거 재검증 + 교차 의존성 분석 + 심각도 민감도 분석 |
| 출력물 | 검증 보고서 (증거 감사 + 의존성 그래프 + 심각도 재평가 + 누락 탐색) |
| 코드 수정 | ❌ 없음 (읽기 전용) |
| 입력 | VA/Pentest/Red Team 보고서 + 대상 소스코드 |

---

## 설계 원칙

### 독립성 원칙

```yaml
Principles:
  Independent_Context: |
    "원본 보고서를 생성한 분석과 별도 세션에서 실행한다.
     이전 분석의 가정에 오염되지 않은 상태에서 증거를 재검증한다."

  Challenger_Stance: |
    "모든 판단(위험 판단과 안전 판단 모두)을 의심한다.
     보고서의 결론을 수용하지 않고, 증거로부터 독립적으로 결론을 도출한다.
     원본 보고서와 동일한 결론에 도달하더라도 그 과정이 증거 기반이어야 한다."

  No_Library_Assumptions: |
    "라이브러리의 존재, 이름, 일반적 평판으로 보안 속성을 추론하지 않는다.
     보안 속성은 프로젝트 코드에서 명시적으로 확인 가능할 때만
     '적용됨(Verified)'으로 판단한다."

  Severity_Is_Contextual: |
    "심각도는 고정값이 아니라 다른 Finding과의 관계에 의해 변동한다.
     Finding A의 해소가 Finding B의 심각도에 영향을 줄 수 있다.
     이 의존성을 명시적으로 식별하고 기록한다."
```

---

## Phase 구조 (v2 — 4-Phase 통합, P1-3)

```
Phase R0-sealed : Context Binding (봉인)     → target/engagement 경로만 수령, VA 보고서 경로는 봉인
Phase R0.5      : Autonomous Discovery       → ★ VA 보고서 미열람 상태의 독립 VA 패스 (A1-A8)
                                               Large Scale(서브프로젝트≥5 또는 ≥100K LOC)만 풀패스.
                                               일반 엔게이지먼트는 "R0.5-Lite"(차원별 canonical 질문만)
                                               산출물: 02a_verify_autonomous-<round>.md
                                               존재 전까지 R1 금지 (Invariant I1)

Phase R1-Unified: Evidence & Context Audit   ← 기존 R0 + R1 + R1.2 + R1.5 + R1.7 통합
                  · R0 서브단계: VA 보고서 파싱
                  · R1 서브단계: Observed/Unverified/Invalidated 재분류
                  · R1.2 서브단계 (CRITICAL/HIGH 필수, 나머지 20% 샘플): Semantic Taint Re-trace
                  · R1.5 서브단계: Attack Prerequisites 독립 재평가
                  · R1.7 서브단계: Asset Value 태그 대조
                  · R1.8 서브단계: Impact Gate(3 Proofs) 분류 독립 재검증
                  · 보상 제어 재검증 (compensating-control.md 참조)

Phase R2-Analysis : Dependency + Sensitivity ← 기존 R2 + R3 + R3.5 통합
                    · R2 서브단계: Finding 간 교차 의존성 그래프
                    · R3 서브단계: 심각도 민감도 (What-If)
                    · R3.5 서브단계: Score Recalculation 항상 수행
                      trigger: "R1-Unified 완료 후 항상 실행"

Phase R4-GapDiff : Autonomous × VA × Raw Ledger 교차 분석
                                               · Matched / VA_Only / Autonomous_Only / Ledger_Only 분류
                                               · Final report omission audit
                                               · Over_Confidence_Gate 판정
                                               산출물: 02b_verify_gap-<round>.md

Phase R5        : Verification Report        → 통합 보고서 생성 (규제 영향 참조 포함, 해당 시)
```

### 변경 이유 (P1-3 Consolidation)

기존 11개 Phase는 개념적으로 잘 분리되어 있었으나 **모두 순차 실행을 강제**하여
소규모 엔게이지먼트에서도 20시간+ 소요 가능성. 본 통합은:
- 논리적 의존성을 유지하면서 메시지 왕복 수 감소
- R3.5는 경량 독립 재계산으로 유지 → 점수/Composite Pass 오류 차단
- R0.5-Lite 옵션으로 non-large-scale에서 R0.5 비용 절반으로 축소
- 각 서브단계는 여전히 별도 섹션/출력 필드로 유지되어 추적성은 보존

### 핵심 불변식 (Phase 순서 불변)

```yaml
Invariants:
  I1_R0_5_Required_Before_R1: |
    "02a_verify_autonomous-<round>.md 파일이 engagement 디렉토리에 존재하지 않으면
     R0 · R1 · 이후 모든 Phase를 실행해서는 안 된다.
     Lead는 해당 파일 존재 여부를 확인한 뒤에만 후속 Phase를 지시한다."

  I2_VA_Report_Sealed_Until_R0_5: |
    "Phase R0.5 완료 이전에는 VA/Pentest/Red Team 보고서 경로를
     Read 도구로 열지 않는다. 열면 즉시 세션을 중단하고
     'ANCHORING_VIOLATION'을 engagement 로그에 기록한다."

  I3_Autonomous_Output_Immutability: |
    "02a_verify_autonomous-<round>.md는 R0.5 종료 시점에 파일시스템에 기록되며,
     R4 단계에서 VA 보고서와 diff할 때까지 수정하지 않는다.
     R4가 새 Finding을 도출했다면 별도 파일(02b_verify_gap-<round>.md)에 기록한다.
     ⚠️ 자동 강제: hooks/verify-invariants.js (I3_PROTECTED_TOOLS) — Edit/Write/NotebookEdit/MultiEdit + 02a 경로 → exit 2 + I3_VIOLATION 기록."
```


---

## Phase R0-sealed: Context Binding (봉인 컨텍스트 수령)

Verifier는 Lead로부터 다음 세 가지 경로만 수령한다. **VA 보고서 경로는
봉인 상태**(sealed)로 전달되며, Phase R0.5 완료 전까지 Read 금지.

```yaml
Input:
  target_source_path:      "대상 프로젝트 소스코드 경로 (읽기 허용)"
  engagement_dir:          "engagement 작업 디렉토리 (쓰기 허용)"
  va_report_path_SEALED:   "★ R0.5 종료 전까지 Read 금지 — 문자열만 전달"

Seal_Enforcement:
  - "Lead는 봉인 경로를 `va_report_path_SEALED` 라벨로만 전달한다."
  - "Verifier는 Phase R0.5 보고서를 파일로 저장하기 전까지
     어떤 이유로도 이 경로를 Read 도구에 넘기지 않는다."
  - "엔지니어링 감사 로그(hook)가 이 경로에 대한 Read를 탐지하면
     세션을 중단시켜야 한다 (Invariant I2)."
```

---

## Phase R0.5: Autonomous Discovery (VA 독립 탐색)

VA 보고서를 보지 않은 상태에서 **Verifier가 자체적으로 8차원 축약 VA를
수행**한다. 이 단계의 목적은 Verifier가 자신의 독립적인 취약점 목록을
먼저 만들고, 이후 VA 보고서와 diff하여 누락을 구조적으로 감지하는 것이다.

```yaml
R0_5_Methodology:

  1_Recon:
    action: |
      skills/ch015/common/recon.md의 Recon 절차를 요약 수행.
      프로젝트 레벨, 활성 도메인, 엔트리 포인트, 의존성만 식별.
      VA가 작성한 00_recon.md가 있어도 직접 Read 하지 않고 자체 재실행.

  2_Dimension_Pass_A1_A8:
    # P1-3: Lite 모드 도입
    mode_selection:
      full: |
        적용 조건: Large Scale Flow (서브프로젝트 ≥5 또는 LOC ≥100K) 또는
          offsec-lead가 --verify-full 플래그 전달
        깊이: 각 차원 1~2시간, VA에 준하는 수준
      lite:
        적용 조건: "그 외 기본 엔게이지먼트 (소~중규모 단일 프로젝트)"
        깊이: |
          각 차원의 Core_Architecture_Questions 전체 답변 (현재 기준 차원당 3개).
          dimension 파일(knowledge-base/tier1-dimensions/a1~a8.md)의
          Core_Architecture_Questions 섹션 참조.
          full의 30~40% 비용으로 전체 커버리지 유지 + 앵커링 방지 목적 달성.
    action: |
      8대 차원(A1-A8) 각각에 대해 선택된 모드로 "Review Perspective" 질문을 수행한다.
      VA/Pentest 팀이 사용한 것과 동일한 knowledge-base/tier1-dimensions/* 스킬은 로드 가능
      (프레임은 공유, 결과는 독립).

    # AST-Enhanced Discovery (R0.5에서 구조적 코드 분석 병행)
    ast_structural_scan:
      trigger: "ast-grep 또는 semgrep가 시스템에 설치되어 있을 때 자동 활성화"
      fallback: "미설치 시 기존 LLM-only 탐색으로 폴백 (기능 저하 없음)"
      procedure:
        1_Build_AST_Context:
          action: |
            lib/ch015/ast/context-builder.js를 Bash로 실행하여 ast-context.yaml 생성:
            ```
            node {ch015_root}/lib/ch015/ast/context-builder.js {target_source_path}
            ```
            출력: {target_source_path}/.ch015/ast-context.yaml
          output: "entry_points, call_graph, data_flows, taint_paths, semgrep_findings"
        2_Pattern_Scan:
          action: |
            ast-grep으로 보안 관련 구조 패턴을 정량 스캔한다.
            LLM의 "다수" "대부분" 같은 추정 대신 정확한 카운트를 확보:
            - innerHTML/outerHTML assignments (XSS sink)
            - eval/Function/setTimeout(string) (code injection sink)
            - .from() / .query() (DB 접근 패턴)
            - href/src 동적 할당 (URL injection)
            - exec/spawn/system (command injection sink)
            - dangerouslySetInnerHTML (React XSS)
            AST 결과는 구조적 사실이다. 보안 판단(위험 여부)은 LLM이 수행한다.
          output: "패턴별 {count, locations[file:line]} → Autonomous Finding 후보에 반영"
        3_Semgrep_Auto_Scan:
          action: |
            semgrep가 설치되어 있으면 p/default + p/secrets 룰셋으로 자동 스캔:
            ```
            semgrep scan --config p/default --config p/secrets --json {target_source_path}
            ```
            semgrep 결과는 R0.5 Autonomous Finding 후보에 추가한다.
            semgrep이 없으면 이 단계를 건너뛴다.
          output: "semgrep findings → V-xxx 후보에 병합"
      principle: |
        AST는 '구조적 사실'만 추출한다 (몇 개, 어디에, 어떤 흐름으로).
        그 사실이 취약점인지, 심각도가 어떤지는 LLM Verifier가 판단한다.
        이것은 ch015의 "AST: Structure Only, Judgment by LLM" 원칙을 따른다.
    output_format: |
      Finding_Candidate:
        id: "V-{NNN}" (Verifier 고유 접두사 — knowledge-base/conventions/finding-id-naming.md 참조)
        dimension: A1 | A2 | ... | A8 | BIZ | CONC | OTHER
        title: "..."
        location: "file:line"
        severity_estimate: CRITICAL/HIGH/MEDIUM/LOW
        evidence: Observed/Unverified
        one_line_reason: "..."

  3_Free_Exploration:
    action: |
      8차원 프레임 밖 카테고리에 대해서도 탐색한다.
      - 비즈니스 로직 상태 전이
      - 동시성/레이스
      - 암묵적 신뢰 경계 (공유 DB/큐/gRPC)
      - 수치 정밀도/오버플로우
      - 캐시/큐 순서 조작
      - SSRF/XXE/Deserialization/Smuggling 등 P2-1 커버리지
    rationale: "VA 프레임 앵커링을 구조적으로 차단"

    ast_free_scan:
      trigger: "ast-context.yaml이 2_Dimension_Pass에서 생성되었을 때"
      action: |
        ast-context.yaml의 call_graph와 data_flows를 활용하여
        8차원 프레임에서 벗어난 패턴을 자동 탐색한다:
        - call_graph에서 dead code (caller 0건인 exported 함수) 식별
        - taint_paths에서 sanitizer 없이 sink에 도달하는 경로 후보 식별
        - semgrep findings 중 8차원 매핑이 없는 항목을 Free_Exploration 후보로 분류
        - postMessage wildcard, missing SRI, hardcoded credentials 등
          LLM grep으로 놓치기 쉬운 패턴을 AST/semgrep 결과에서 보충
      output: "추가 V-xxx 후보 → 4_Persist_Output에 병합"

  4_Persist_Output:
    action: |
      engagement_dir/02a_verify_autonomous-<round>[-<group>].md 로 원자적으로 저장한다.
      (1차: 02a_verify_autonomous-1st.md / feedback 라운드: 02a_verify_autonomous-<ordinal>.md — 2nd, 3rd …,
       <ordinal>은 Lead가 프롬프트로 전달한 라운드 접미사를 그대로 사용)
      ⚠️ 그룹/배치 병렬 검증(grouped/full/large-scale)에서는 프롬프트로 group_id(예: auth, a1) 또는
      unit_id가 주어진다. 이 경우 반드시 -<group> 접미를 붙인다(예: 02a_verify_autonomous-1st-auth.md).
      접미를 누락하면 병렬 Verifier가 같은 파일을 덮어쓰고, 능동 게이트(-<group> 확인)와 불일치한다.
      tmp 파일에 쓰고 rename (동시 Reader TOCTOU 방지).
      저장 성공 → Lead에게 요약 반환 + R0 진입 가능 상태 선언.
    must_include:
      - Autonomous Finding 목록 (V-001~)
      - 각 차원별 커버리지 선언 (탐색함/넘어감)
      - 탐색하지 못한 영역 (시간/컨텍스트 제약)

Exit_Criteria:
  - "02a_verify_autonomous-<round>.md가 engagement_dir에 생성되었다."
  - "파일에 최소 1건의 Autonomous Finding Candidate 또는
     'None Identified with rationale' 명시가 포함되어 있다."
```

---

## Phase R0: Report Ingestion (보고서 수집 — R0.5 완료 후에만 실행)

**선행 조건**: `02a_verify_autonomous-<round>.md` 존재 필수 (Invariant I1).

```yaml
Pre_Check:
  - "engagement_dir/02a_verify_autonomous-<round>.md 존재 여부를 Glob/ls로 확인"
  - "존재하지 않으면 즉시 에러 반환 — R0.5를 먼저 실행하라"

Input:
  report_path: "VA/Pentest/Red Team 보고서 파일 경로 (이제 Read 허용)"
  source_path: "대상 프로젝트 소스코드 경로"

Actions:
  1_Parse_Report:
    - 보고서에서 모든 Finding 추출 (F-XXX)
    - 각 Finding의 메타데이터 파싱:
        finding_id, title, severity, dimension,
        root_cause, location, evidence, attack_chain

  2_Parse_Healthy_Patterns:
    - "건전한 패턴" 섹션에서 모든 ✅ 판정 추출
    - 각 판정의 증거와 근거 파싱

  3_Parse_Score:
    - Security Score, 등급, Finding 분포 추출

  4_Build_Index:
    - Finding ID → 메타데이터 맵 생성
    - Location → Finding ID 역인덱스 생성
    - 공격 체인의 전제 조건 목록 추출
```

---

## Phase R1: Evidence Audit (증거 감사)

모든 Finding과 Healthy 판정의 증거를 **소스코드에서 독립적으로 재검증**합니다.

```yaml
R1_Methodology:

  For_Each_Finding:
    1_Verify_Observed_Evidence:
      action: |
        Finding의 Evidence 섹션에서 "Observed" (file:line) 증거를 추출하고,
        해당 파일의 해당 라인을 실제로 열어 확인한다.
      check:
        - "해당 코드가 실제로 존재하는가?"
        - "코드의 의미가 보고서의 해석과 일치하는가?"
        - "코드가 변경되었는가? (보고서 작성 이후)"

    2_Identify_Implicit_Assumptions:
      action: |
        Finding의 구조적 이슈 설명과 공격 체인에서
        명시적 증거 없이 사용된 가정을 식별한다.
      patterns:
        - "~일 것이다" / "~하므로" 형태의 추론
        - 라이브러리/프레임워크 동작에 대한 암묵적 신뢰
        - 다른 보안 메커니즘의 존재/부재에 대한 가정

    3_Reclassify_Evidence:
      action: |
        모든 증거를 재분류한다:
        - Observed: 프로젝트 코드에서 직접 확인 (file:line)
        - Unverified: 라이브러리/프레임워크 기본값에 의존, 코드에서 확인 불가
        - Invalidated: 보고서의 증거가 실제 코드와 불일치
      output: "Finding별 증거 감사 결과"

    # -----------------------------------------------------------------
    # Phase R1.2: Semantic Taint Re-trace (의미론적 taint 재추적)
    # -----------------------------------------------------------------
    # Finding이 "user input → unsafe sink" 형태의 주장을 포함할 때,
    # 파일:라인 존재만 확인하는 것이 아니라 source→sink 경로의 모든 홉에서
    # sanitizer/validator/parameterization이 있는지 독립 재추적한다.
    # CRITICAL/HIGH는 필수, MEDIUM/LOW는 샘플링 (최소 20%).
    # -----------------------------------------------------------------
    3_5_Taint_Path_Retrace:
      trigger: "severity in [CRITICAL, HIGH] OR 샘플링 대상 MEDIUM/LOW"
      procedure:
        1_Read_Source_Context:
          action: "Finding의 source 지점 파일:라인 ±20줄을 Read"
          check: "해당 라인에서 실제로 사용자 입력/외부 데이터가 유입되는가?"
        2_Read_Sink_Context:
          action: "Finding의 sink 지점 파일:라인 ±20줄을 Read"
          check: "해당 라인이 정말로 위험한 sink인가? (exec/query/eval/write/render)"
        3_Hop_Trace:
          action: |
            source에서 sink까지의 호출 경로를 Grep으로 역추적한다.
            중간 함수 호출 각각(홉)에서 다음을 독립 확인:
            - parameterization (prepared statement, $1 placeholder)
            - sanitization (escape, encode, validate, strip)
            - type coercion (parseInt, zod.parse)
            - access control (if role !== 'admin' return)
          ast_augmented_trace: |
            ast-context.yaml이 존재하면 call_graph/data_flows/taint_paths를 활용하여
            Grep 기반 역추적을 보강한다:
            - call_graph에서 caller→callee 체인을 구조적으로 확인
            - data_flows에서 파라미터 전달 경로를 대조
            - taint_paths에서 source/sink 후보와 sanitizer 힌트를 대조
            - Grep이 놓친 간접 호출(콜백, 이벤트 핸들러)을 call_graph에서 보충
            AST 경로와 Grep 경로가 불일치하면 양쪽 모두 기록하고 수동 확인 권고.
        4_Classify:
          Verified_Taint_Path:
            조건: "모든 홉에서 sanitizer 부재 확인, sink 도달 가능"
            액션: "Finding 심각도 유지, 증거 태그 = Observed_Taint_Verified"
          Mitigated_Path:
            조건: "최소 1홉에서 적절한 sanitizer 발견"
            액션: "Finding 심각도 1단계 하향 + objection type=severity_dispute 발행"
          Unreachable_Path:
            조건: "caller 0건 또는 조건부 dead code (DEV_MODE 등)"
            액션: "심각도 LOW로 하향 + Reachability 태그"
          Incomplete_Trace:
            조건: "홉 수 > 5, 동적 디스패치, 리플렉션, 런타임 플러그인 로딩"
            액션: "Finding 유지 + 'manual_review_required' 플래그"

      output_field: "Finding.evidence.taint_trace = { classification, hops[], sanitizers_found[] }"

    # -----------------------------------------------------------------
    # Phase R1.3: Response Reflection Re-trace (응답 반영 역추적)
    # -----------------------------------------------------------------
    # Finding이 프록시/게이트웨이 응답 반영 취약점을 주장할 때,
    # 업스트림 응답 → 클라이언트 전달 경로의 필터링 여부를 독립 재추적한다.
    # R1.2가 "사용자 입력 → 싱크" 방향이라면,
    # R1.3은 "업스트림 응답 → 클라이언트 싱크" 역방향을 검증한다.
    # -----------------------------------------------------------------
    3_7_Response_Reflection_Retrace:
      trigger: "Finding이 응답 헤더/바디 반영, 프록시 패스스루, 게이트웨이 응답 관련인 경우"
      procedure:
        1_Identify_Proxy_Code:
          action: "업스트림 fetch/request → 응답 → 클라이언트 전달 코드를 Read"
          check: "해당 코드가 실제로 프록시/중계 역할을 수행하는가?"
        2_Header_Passthrough_Check:
          action: "응답 헤더 전달 방식을 확인"
          check: |
            - allowlist 기반인가? (안전)
            - denylist 기반인가? (위험 — 누락 헤더 존재 가능)
            - 전체 패스스루인가? (위험)
            - Set-Cookie, Location, Access-Control-*, Content-Type이 통과하는가?
        3_Body_Passthrough_Check:
          action: "응답 바디 전달 방식을 확인"
          check: |
            - Content-Type이 강제되는가? (예: application/json 고정)
            - 업스트림이 text/html을 반환하면 클라이언트에서 렌더링 가능한가?
            - 에러 응답에 내부 URL/호스트명/스택 트레이스가 포함되는가?
        4_Classify:
          Verified_Reflection:
            조건: "위험 헤더가 allowlist 없이 통과, 또는 Content-Type 미강제"
            액션: "Finding 심각도 유지, 증거 태그 = Observed_Response_Reflection"
          Mitigated_Reflection:
            조건: "allowlist 기반 헤더 필터링 + Content-Type 강제"
            액션: "Finding 심각도 1단계 하향 + objection type=response_mitigated"
          Not_Applicable:
            조건: "해당 코드가 프록시/중계가 아님, 또는 응답이 클라이언트에 미전달"
            액션: "Finding 기각 + objection type=not_proxy_pattern"
      output_field: "Finding.evidence.response_trace = { classification, header_filter, body_filter, dangerous_headers[] }"

    4_Verify_Reference_Fields:
      action: |
        각 Finding에 CWE + OWASP_Top10 필수 참조가 존재하는지 확인한다.
        누락 시 objection type: "reference_missing"으로 이의 제기.
      check:
        - "CWE 필드가 존재하고 'CWE-' 접두사 + 숫자 형식인가?"
        - "OWASP_Top10 필드가 존재하고 A01~A10 또는 'N/A'인가?"
        - "API 도메인 활성 프로젝트에서 OWASP_API_Top10이 존재하는가?"

  For_Each_Healthy_Pattern:
    1_Verify_Healthy_Claim:
      action: |
        "✅ Healthy" 판정의 근거를 코드에서 재확인한다.
      check:
        - "Healthy 판정의 근거가 Observed인가 Unverified인가?"
        - "Healthy 판정이 특정 라이브러리 동작에 의존하는가?"
        - "Healthy 판정이 다른 Finding과 모순되는가?"

    2_Probe_Healthy_Gaps:
      action: |
        Healthy 판정 영역에서 보고되지 않은 위험이 있는지 탐색한다.
        특히 Credential_Exposure_Boundary 관점에서
        자격 증명의 접근 경계를 재확인한다.

  For_Each_Live_Verification:
    설명: |
      Pentest 보고서에 라이브 검증(Phase 6) 결과가 포함된 경우,
      해당 결과의 인과관계를 독립적으로 감사한다.
      API 응답만으로 취약점을 판정한 경우 오탐 가능성이 높다.

    1_Response_vs_State_Consistency:
      action: |
        라이브 검증에서 "CONFIRMED"로 판정된 Finding에 대해:
        - API 응답(HTTP status, body)만 근거인가, 상태 변경(State Delta)이 입증되었는가?
        - 상태 변경이 입증되지 않은 "CONFIRMED"는 과대 판정(Overstatement) 의심
      check:
        - "CONFIRMED 판정에 State Delta 증거(전후 스냅샷)가 포함되어 있는가?"
        - "202 Accepted 응답을 근거로 CONFIRMED 판정하지 않았는가?"
        - "fire-and-forget 아키텍처 분석이 선행되었는가?"

    2_Causality_Attribution:
      action: |
        라이브 검증에서 관찰된 상태 변화가 POC에 의한 것인지,
        시스템의 자연적 행동에 의한 것인지 인과관계를 검증한다.
      check:
        - "대조군(Control Group)이 설정되었는가?"
        - "대조군 없이 관찰된 변화를 POC에 귀인하지 않았는가?"
        - "게임/실시간 시스템의 AI 행동, 틱 처리 등 자연적 변화를 배제하였는가?"
        - "변화의 시점이 POC 전송 시점과 인과적으로 일치하는가?"

    3_Verification_Method_Completeness:
      action: |
        라이브 검증에 사용된 기법의 완전성을 평가한다.
      check:
        - "Response Semantics Analysis가 수행되었는가?"
        - "Failure Injection으로 fire-and-forget 여부를 확인하였는가?"
        - "Differential Testing 또는 Control Group이 적용되었는가?"
        - "통합 프로토콜(Integrated Verification Protocol)을 따랐는가?"
      reclassify:
        전체_프로토콜_준수: "Verified — 라이브 검증 결과 신뢰 가능"
        부분_프로토콜: "Partially Verified — 미수행 기법 명시 + 판정 불확실성 기록"
        응답_코드만_근거: "Unverified — 라이브 검증 결과 신뢰 불가, 재검증 필요"

    4_Blind_Accept_Detection:
      action: |
        다음 패턴이 보고서에서 감지되면 즉시 경고 플래그를 설정한다:
      patterns:
        - "응답 202 Accepted + {success: true, accepted: true} → CONFIRMED 판정"
        - "fire-and-forget 프록시 분석 없이 API 응답으로 판정"
        - "상태 조회 없이 액션 전송 결과만으로 판정"
        - "대상 에이전트/리소스의 전후 상태 비교 없음"
      경고_시_조치: |
        - CONFIRMED → BLIND_ACCEPT 재분류 권고
        - 심각도 CRITICAL/HIGH → LOW/Informational 하향 권고
        - 코드 분석으로 최종 처리 계층(Module)의 인증 로직 확인 필요
```

---

## Phase R1.5: Prerequisites Audit (전제조건 검증)

VA가 각 Finding에 부여한 **공격 전제 조건 분석 (Step 1.7)** 결과를 독립적으로 재평가합니다.

```yaml
R1_5_Methodology:

  목적: |
    VA의 전제조건 분석이 정확한지 검증한다:
    - category 분류가 적절한가?
    - defense_survives 판정이 올바른가?
    - adjusted_feasibility가 합리적인가?
    - 포괄 그룹 묶음이 논리적인가?

  검증_항목:

    1_카테고리_재확인: |
      각 Finding의 prerequisites.category가 실제 배포 환경에 부합하는지 확인:
      - "cloud_provider"로 분류된 Finding: 실제로 프로바이더 관리형 인프라가 전제인가?
        (예: 자체 호스팅 DNS를 AWS Route53으로 잘못 분류하지 않았나?)
      - "internal_network"로 분류된 Finding: 실제로 VPC 내부만 경유하는가?
        (예: 외부 도메인 경유를 간과하지 않았나?)
      - "supply_chain"으로 분류된 Finding: T(이론적)로 과소평가하지 않았나?
        (실제 공급망 공격 사례 참고: SolarWinds, event-stream, ua-parser-js)

    2_defense_survives_재검증: |
      "defense_survives: false" 판정의 논리적 타당성:
      - 전제 침해 시 해당 방어선이 의존하는 자원(키, 인프라)도 같이 침해되는가?
        (예: JWKS가 같은 AWS에 있으면 → AWS 침해 시 JWKS도 조작 → 로컬 검증 무력화 → false 타당)
      - 방어선이 전제와 독립적인 자원을 사용하는가?
        (예: AMQP HMAC key가 Vault에 있고, 침해 전제가 config_file이면
         Vault ≠ config_file → defense_survives: true가 맞음)

    3_포괄_그룹_논리성: |
      - 같은 그룹에 묶인 Finding들이 실제로 같은 전제를 공유하는가?
      - 다른 그룹에 있지만 실제로 같은 전제인 Finding이 있는가?
      - compound 전제 (2개 이상 카테고리 조합)의 AND/OR 논리가 맞는가?

    4_과대_평가_탐지: |
      cloud_provider defense_survives=false인데 실전 Feasibility를 HIGH 이상으로
      유지한 경우 → 과대 평가 이의 제기 (T로 조정 권고)

    5_과소_평가_탐지: |
      supply_chain 카테고리를 T로 판정한 경우
      → 실제 사례 존재 여부 + 해당 패키지의 공격 이력 확인
      → 과소 평가 시 L-M으로 상향 이의 제기

  출력: |
    Prerequisites Audit 결과를 이의 목록에 포함:
    [{finding_id, type: "prerequisites_dispute", reason, instruction}]
```

---

## Phase R1.7: Asset Value Audit (자산 가치 검증)

VA가 Finding에 부여한 `Asset_Value` 태그가 Recon Asset Register와 일치하는지 독립 검증합니다.

```yaml
R1_7_Checklist:
  1_태그_일치성: "각 Finding의 Asset_Value가 Asset Register의 해당 엔티티 가치 등급과 일치하는가? 불일치 시 objection: asset_value_mismatch"
  2_CROWN_JEWEL_커버리지: "Asset Register의 CROWN_JEWEL 엔티티 각각에 관련 Finding이 최소 1건 존재하는가? 없으면 crown_jewel_uncovered 경고"
  3_과대_태깅: "Asset Register에 없는 엔티티를 CROWN_JEWEL/HIGH로 태그한 Finding이 있는가? 과대 시 objection: asset_inflation"
  4_BIS_대조: "검증된 Asset_Value로 Business Impact Score를 재계산하여 VA 보고서와 5% 이내인가? 차이 시 원인 Finding 식별 + 이의 제기"
  가중치: "CROWN_JEWEL ×2.0, HIGH ×1.5, MEDIUM ×1.0, LOW ×0.5"
```

---

## Phase R1.8: Impact Gate Audit (비즈니스 영향 게이트 검증)

VA의 Step 1.8(비즈니스_영향_증명_게이트)에서 수행한 3 Proofs 판정을 독립 재검증합니다.

```yaml
R1_8_Checklist:

  대상: "모든 Finding (Confirmed_Vulnerability + Structural_Weakness 모두)"

  1_Confirmed_재검증:
    대상: "Classification = Confirmed_Vulnerability인 Finding"
    action: |
      3 Proofs(What/So_What/How) 각각을 독립적으로 재평가한다.
      - What: 명시된 자산/데이터가 실제로 영향받는가? Asset Register와 대조.
      - So_What: 공격 결과가 구체적이고 현실적인가? 추상적 위험("보안 위반")은 불충분.
      - How: Step 1(도달 가능성)에서 확인한 경로가 실제 존재하는가?
    판정:
      3_Proofs_유효: "Confirmed 유지"
      임의_Proof_불충분: |
        objection: impact_gate_overclassified
        권고: "Structural_Weakness로 재분류 검토"

  2_Structural_Weakness_재검증:
    대상: "Classification = Structural_Weakness인 Finding"
    action: |
      VA가 FAIL 판정한 Proof를 재평가한다.
      - 실제로 비즈니스 영향이 있는데 VA가 과소 판정한 것은 아닌가?
      - 서비스 컨텍스트를 재검토하여 Confirmed로 승격해야 할 Finding이 있는가?
    판정:
      FAIL_유효: "Structural_Weakness 유지"
      FAIL_부당: |
        objection: impact_gate_underclassified
        권고: "Confirmed_Vulnerability로 승격 검토 + 원래 심각도 복원"

  3_Anti_Pattern_탐지:
    checks:
      - "전체 Finding 중 Structural_Weakness 비율이 60% 초과 → objection: excessive_structural_weakness (점수 인위 상승 의심)"
      - "CRITICAL/HIGH Finding이 Structural_Weakness로 다운그레이드된 경우 각각 근거 강도 재확인"
      - "So_What에서 이론적 위험만으로 Confirmed 통과한 항목이 있는가?"

  4_Score_영향_검증:
    action: |
      Impact Gate 재분류 결과를 반영하여 Security Score를 재계산한다.
      VA 보고서 Score와 차이가 5점 초과 시 원인 Finding 명시.
```

---

## Phase R2: Cross-Finding Dependency (교차 의존성 분석)

Finding 간 심각도 연쇄를 식별합니다.

```yaml
R2_Methodology:

  1_Extract_Prerequisites:
    action: |
      각 Finding의 공격 체인에서 전제 조건을 추출한다.
    example:
      F-003:
        attack_chain:
          - "Step 1: 피해자 세션 획득 ← 전제 조건"
          - "Step 2: /api/wallet/register 호출"
          - "Step 3: /api/vault/withdraw-request 호출"
        prerequisites:
          - "세션 탈취 가능 (→ F-012, F-010과 연관)"

  2_Build_Dependency_Graph:
    action: |
      전제 조건과 다른 Finding을 매칭하여 의존성 그래프를 생성한다.
    structure:
      nodes: "각 Finding"
      edges: "Finding A의 해소 → Finding B의 심각도 변동"
      direction: "영향 방향"
    example: |
      F-012 (세션 토큰 보호) ──해소 시──→ F-003 심각도 ↓ (HIGH → MEDIUM)
      F-012 (세션 토큰 보호) ──해소 시──→ F-010 심각도 ↓ (HIGH → MEDIUM)
      F-010 (CSP 미설정)     ──해소 시──→ F-012 영향도 ↓ (XSS 난이도 상승)

  2_5_Quantitative_Correction:
    trigger: "ast-context.yaml이 존재하고 VA/Pentest 보고서에 정량 주장이 포함된 경우"
    action: |
      VA/Pentest 보고서의 정량 추정치를 AST 정확 카운트로 교차 검증한다.
      보고서가 "175개 주입 포인트", "다수의 API 호출" 등 추정을 사용한 경우,
      ast-grep 정확 카운트(예: "31개 innerHTML assignments")로 보정한다.
    procedure:
      - VA/PT 보고서에서 수량 표현 추출 ("~N개", "다수", "대부분", "N개 이상")
      - ast-context.yaml 또는 ast-grep 재실행으로 정확 카운트 확보
      - 불일치 시 Objection(type: quantitative_correction) 발행
      - 정확 카운트를 검증 보고서에 기록하여 공격 표면의 실제 크기를 명시
    output: |
      quantitative_corrections: [{finding_id, claim, ast_count, correction}]
    principle: |
      LLM은 코드를 "읽고 이해"하여 추정한다. AST는 구조적으로 카운트한다.
      양쪽이 다를 때 AST 카운트가 정량적 사실이다.
      단, AST가 커버하지 못하는 동적 패턴(runtime eval, reflection)은
      LLM 추정이 유효할 수 있으므로 맹목적 교체는 금지.

  3_Identify_Keystone_Findings:
    action: |
      의존성 그래프에서 "핵심 노드"를 식별한다.
      핵심 노드: 해소 시 다른 Finding의 심각도에 가장 큰 영향을 미치는 Finding.
    output: |
      핵심 노드 목록 + 각 노드 해소 시 영향받는 Finding 수와 심각도 변동 폭

  4_Detect_Circular_Dependencies:
    action: |
      순환 의존성을 탐지한다.
    example: |
      "F-010 해소 → F-012 영향도 감소" 와
      "F-012 해소 → F-010 심각도 감소" 가 동시에 존재하면
      → 두 Finding을 함께 해소해야 최대 효과. 수정 로드맵에 반영.
```

---

## Phase R3: Severity Sensitivity (심각도 민감도 분석)

각 Finding의 심각도가 다른 조건에 얼마나 민감한지 분석합니다.

```yaml
R3_Methodology:

  1_Per_Finding_Sensitivity:
    action: |
      각 Finding에 대해 아래 질문을 적용한다:
    questions:
      - "이 Finding의 전제 조건 중 하나가 '해소됨'이면 심각도가 어떻게 변하는가?"
      - "이 Finding의 전제 조건 중 하나가 '보고서보다 심각'하면 심각도가 어떻게 변하는가?"
      - "이 Finding이 해소되면 다른 Finding의 심각도에 어떤 영향을 주는가?"

  2_What_If_Scenarios:
    action: |
      --assume 인자가 제공된 경우, 해당 조건을 적용하여
      전체 Finding 목록의 심각도를 재계산한다.
    example:
      assume: "F-012 mitigated (HttpOnly 적용)"
      result:
        F-003: "HIGH → MEDIUM (세션 탈취 난이도 상승, but 아키텍처 결함 잔존)"
        F-010: "HIGH → MEDIUM (CSP가 유일한 방어선이 아니게 됨)"
        Score: "52 → 62 (D등급 유지, but CRITICAL 3건 → 3건 변동 없음)"

  3_Severity_Stability_Rating:
    action: |
      각 Finding의 심각도가 얼마나 안정적인지 평가한다:
    ratings:
      Stable: "다른 Finding의 해소와 무관하게 심각도 유지 (예: F-001 Rate Limiting)"
      Sensitive: "특정 Finding의 해소 시 심각도 변동 (예: F-003)"
      Dependent: "다른 Finding에 완전히 의존 (예: 세션 보호 없이만 존재하는 공격 체인)"
    output: "Finding별 안정성 등급 + 변동 시나리오"
```

---

## Phase R3.5: Score Independent Recalculation (점수 독립 재계산)

```yaml
R3_5_Methodology:
  trigger: "R1-Unified 완료 후 항상 실행 (심각도 변경 여부와 무관)"
  절차:
    1_Primary_Score: "검증 완료된 Finding 목록으로 ch015.config.json.scoring.securityScore 공식에 따라 Score 재계산. excludeCategories 필터 올바른지 확인."
    2_Composite_Pass: "4개 조건 독립 판정 (Score≥85, CRITICAL=0, HIGH≤2, CVSS≥9.0=0건 — 기준값 정본: ch015.config.json scoring.securityScore). VA 판정과 불일치 시 이의."
    3_BIS_재계산: "R1.7에서 검증된 Asset_Value 기반으로 Business Impact Score 재계산. VA 보고서와 대조."
  regulated_추가: "Unverified 증거 비율 < 10% + 모든 CRITICAL/HIGH에 CVSS 기록 확인"
```

---

## Phase R4: Gap Diff — Autonomous × VA × Raw Ledger 교차 분석

이 단계의 목적은 Phase R0.5에서 Verifier가 **독립적으로 발견한 Finding 목록
(02a_verify_autonomous-<round>.md)**, VA 최종 보고서, Raw Candidate Ledger를
구조적으로 비교하여 어느 후보가 확인/보류/누락/삭제되었는지 대칭 기록하는 것이다.

### 설계 변경 이력 (2026-04-17)

기존 "Anti-Anchoring Protocol"은 Verifier가 VA 보고서를 먼저 읽은 후
"VA 프레임 밖"을 의식적으로 탐색하라고 요청했으나, 인지적으로 이는 여전히
VA 프레임에 앵커링된 상태였다. 이를 **Phase 순서 강제**로 대체:
Verifier는 R0.5에서 먼저 자율 탐색을 완료한 뒤에만 VA 보고서를 열람한다
(Invariant I2). R4는 이제 순수한 diff/reconcile 단계다.

```yaml
R4_Methodology:

  0_Load_Inputs:
    autonomous_set: "engagement_dir/02a_verify_autonomous-<round>.md (V-xxx)"
    va_set:         "VA 보고서의 Finding 목록 (F-xxx)"
    raw_ledger:     "engagement_dir/0N_va_raw_findings_ledger-<round>.yaml (CAND-xxx)"
    findings_index: "engagement_dir/0N_va_findings_index-<round>.yaml"
    # 라운드별 접두 규칙(va-auditor.md storage 기준): 1차=01_..-1st, feedback 라운드=03_..-<ordinal>(2nd, 3rd …)
    #   접두(01/03)는 고정, 접미 ordinal만 라운드별로 증가 — "-2nd" 하드코딩 시 2회차가 1회차를 덮어쓴다(F2).
    va_negative:    "VA 보고서의 Negative Findings 섹션"

  1_Match_By_Location:
    action: |
      (파일경로, 라인 범위 ±30, dimension) 튜플로 클러스터링하여
      Autonomous Finding과 VA Finding의 매칭 후보를 생성한다.
    output:
      - Matched: "V-xxx ↔ F-xxx (동일 대상)"
      - VA_Only: "Autonomous에서 미발견된 VA Finding"
      - Autonomous_Only: "VA에서 미발견된 Verifier Finding (← 누락 후보)"
      - Ledger_Only: "Raw ledger에는 있으나 VA 최종 보고서에 없는 후보"

  1_5_Duplicate_Overcount_Audit:
    action: |
      VA report, findings_index, raw_ledger를 맥락 기준으로 비교한다.
      문자열 key에 의존하지 않고 같은 취약점이 여러 CONFIRMED/DOWNGRADED Finding으로
      점수에 중복 반영되었는지 감사한다.
    checks:
      - "같은 보안 통제 실패인가"
      - "같은 remediation 단위 또는 같은 root cause인데 별도 Finding으로 발행되었는가"
      - "같은 exploit precondition, trust boundary, affected asset을 공유하는가"
      - "Pentest/Verifier가 새로 확인한 route/function/file이 새 Finding이 아니라 affected_instances로 들어가야 하는지"
    output:
      duplicate_groups:
        - group_id: "DG-001"
          decision_recommendation: "MERGE | SPLIT | KEEP"
          primary_candidate: "대표 후보 제안"
          fold_candidates: ["F-xxx 또는 CAND-xxx"]
          affected_instances: ["route/function/file/asset/flow 목록"]
          recommendation: "대표 1건 유지, 나머지는 FOLDED_INTO로 convergence 반영"

  2_Reconcile:
    VA_Only:
      action: "Verifier가 왜 놓쳤는지 회고 — 다음 라운드 개선 데이터"
      label: "verifier_gap"
    Autonomous_Only:
      action: |
        Verifier가 독립 발견했으나 VA가 놓친 항목.
        → Phase R1.2 taint re-trace 대상으로 승격.
        → taint_trace 결과가 Verified/Mitigated/Unreachable 중 어느 것인지에 따라
           최종 Finding (02b_verify_gap-<round>.md 에 기록) 또는 FP 라벨.
      label: "va_missing"
    Ledger_Only:
      action: |
        VA가 raw 후보로 식별했으나 final report에서 제외한 항목.
        삭제가 아니라 상태 분류가 있어야 한다.
        final_status가 BACKLOG/PENDING/FOLDED/EXCLUDED/FALSE_POSITIVE/OUT_OF_SCOPE 중 하나인지 확인하고,
        MEDIUM 이상 또는 인증/인가/결제/배포/시크릿 관련 후보면 omission audit에 기록한다.
      label: "final_omission_candidate"
    Matched:
      action: "증거·심각도·taint_trace 3요소 크로스체크"
      label: "both"

  2_5_Verify_Queue_From_Ledger:
    action: |
      Raw ledger에서 아래 조건에 해당하는 후보를 검증 큐에 강제 포함한다.
      이 큐는 CRITICAL/HIGH만 검증하는 기존 편향을 보완한다.
    must_include:
      - "모든 CRITICAL/HIGH 후보"
      - "final report에서 빠지는 모든 MEDIUM 후보"
      - "인증/인가/결제/배포/시크릿/감사로그/웹훅/외부연동 관련 후보"
      - "PENDING_PENTEST 또는 PENDING_EXTERNAL 후보"
      - "FOLDED_INTO 후보"
      - "severity가 2단계 이상 변한 후보"
      - "business_relevance=high 후보"
    output: "verify_queue 섹션과 omission_audit 섹션에 기록"

  3_VA_Negative_Reversal:
    action: |
      VA의 Negative_Findings에 명시된 '안전' 판단 각각에 대해,
      Autonomous 세트와 대조하여 Autonomous가 동일 영역에서 위험을 찾았다면
      VA Negative를 '오판' 후보로 표시.
    output: "Negative Findings 중 뒤집힌 개수 / 전체 개수"

  4_Coverage_Gap_Detection:
    action: |
      소스코드 주요 디렉토리/패키지를 Glob으로 나열하고,
      Autonomous와 VA 어느 쪽에도 Finding 또는 Negative로 언급되지 않은
      디렉토리를 '완전 커버리지 갭'으로 표시.
    output: "미커버 디렉토리 목록 → Deep Audit 후보"

  4_5_Classification_Completeness_Gate:
    action: |
      Raw ledger의 모든 candidate가 최종 상태를 갖는지 검증한다.
      UNCLASSIFIED가 1건이라도 있으면 convergence_ready=false로 반환한다.
    checks:
      - "FOLDED_INTO → folded_into target 존재"
      - "PENDING_EXTERNAL → required_access/external_system 존재"
      - "PENDING_PENTEST → pentest route 존재"
      - "FALSE_POSITIVE → counter-evidence 존재"
      - "OUT_OF_SCOPE → scope reason 존재"
    output: "classification_completeness = {total, classified, unclassified, publish_allowed}"

  5_Free_Exploration_Check:
    action: |
      R0.5의 `3_Free_Exploration` 결과(비즈니스 로직, 동시성, 암묵적 신뢰 등)를
      다시 꺼내 VA 보고서와 대조. VA가 다루지 않은 카테고리는 모두
      Autonomous_Only로 분류된다.

  6_AST_Pattern_Gap:
    trigger: "ast-context.yaml이 존재할 때"
    action: |
      R0.5에서 AST/semgrep이 탐지했으나 VA 보고서에 대응 Finding이 없는
      패턴을 Autonomous_Only 후보로 추가 분류한다.
      특히 LLM이 놓치기 쉬운 패턴에 집중:
      - semgrep findings 중 VA/Pentest가 커버하지 않은 항목
      - ast-grep 패턴 중 VA가 언급하지 않은 sink/source 위치
      - call_graph의 dead code 중 보안 관련 함수
    output: "추가 Autonomous_Only 후보 → 02b_verify_gap에 AST 출처 명시"
```

### 과신(Over-confidence) 샘플링 게이트

```yaml
Over_Confidence_Gate:
  trigger:
    expression: "len(va_negative_findings) > len(va_findings) * 1.5"
    의미: "VA가 너무 많은 영역을 '안전'으로 분류 — 과신 신호"
  action:
    - "VA Negative 전량을 R4 Step 3에 투입 (샘플링 아닌 전량 검증)"
    - "뒤집힌 Negative 비율이 5% 이상이면 Lead에게 VA 재실행 권고"
    - "감사 로그(engagement_dir/audit.log)에 게이트 발동 기록"
```

```yaml
# R4 후반부 — Negative/커버리지 검사 (위 R4_Methodology의 Step 6에서 이어짐)
R4_Negative_And_Coverage_Checks:

  7_Healthy_Pattern_Reversal:
    action: |
      보고서의 "건전한 패턴 ✅" 목록 각각에 대해 반박을 시도한다.
    questions:
      - "이 Healthy 판정의 증거가 Observed인가?"
      - "이 Healthy 판정이 라이브러리 기본값에 의존하는가?"
      - "이 Healthy 판정이 부분적으로만 적용되어 있는가?"
        (예: 일부 헤더만 설정, 일부 API만 인증)

  8_Credential_Exposure_Recheck:
    action: |
      A1 Credential_Exposure_Boundary 질문을 독립적으로 재수행한다.
    methodology: |
      1. 인증 자격 증명의 저장/전달 위치를 코드에서 재식별
      2. 각 위치의 접근 주체 열거
      3. 공격 벡터의 도달 범위 열거
      4. 접근 주체 ∩ 공격 도달 범위 평가
      5. 보고서의 판단과 비교 → 불일치 시 신규 Finding 후보

  9_Attack_Chain_Completeness:
    action: |
      각 Finding의 공격 체인에서 누락된 전제 조건이나
      보고되지 않은 중간 단계가 있는지 확인한다.
    example: |
      F-003 공격 체인: "세션 탈취 → 지갑 등록 → 출금"
      질문: "세션 탈취"의 구체적 벡터가 보고서에 분석되었는가?
      → F-012가 누락되었다면 여기서 발견

  10_Dimension_Coverage_Check:
    action: |
      8개 아키텍처 차원(A1-A8) 각각에 대해
      보고서에 최소 하나의 Finding 또는 명시적 "Healthy" 판정이 있는지 확인한다.
    check: |
      - 특정 차원에 Finding도 Healthy 판정도 없으면 → "분석 누락 가능" 경고
      - 활성 도메인(Backend, Frontend, Web3 등)별로 차원 커버리지 확인

  11_CWE_OWASP_Coverage_Check:
    action: |
      knowledge-base/patterns/coverage-matrix.yaml을 Read로 로드하고,
      프로젝트의 활성 도메인/언어에 해당하는 CWE Top 25 항목을 필터링한다.
      
      각 해당 CWE에 대해:
      1. 보고서의 Finding 중 해당 CWE가 Reference에 존재하는가?
      2. 보고서의 Negative Findings에서 해당 CWE 영역이 "안전" 판정되었는가?
      3. 위 둘 다 없으면 → 해당 CWE의 매핑 차원(dimensions)을 확인하고
         해당 차원 분석에서 관련 이슈가 커버되었는지 재확인
      4. 커버 확인 불가 → "CWE Coverage Gap" 경고 + 신규 Finding 후보로 등록
    
    owasp_check: |
      OWASP Top 10 각 항목에 대해서도 동일 프로세스 수행.
      활성 API 도메인이면 OWASP API Top 10도 포함.
    
    output: |
      Section 4 (Missing Findings)에 커버리지 매트릭스 추가:
      
      ### CWE/OWASP 커버리지
      | Standard | ID | 이름 | 해당 여부 | 커버 상태 | 관련 Finding |
      |----------|----|------|---------|---------|------------|
      
      커버 상태:
      - ✅ Covered: Finding 또는 Negative Finding에서 확인됨
      - ⚠️ Implicit: 해당 차원에서 간접 커버 (명시적 CWE 매핑 없음)
      - ❌ Gap: 커버리지 확인 불가 — 신규 탐색 필요
```

---

## Phase R5: Verification Report (검증 보고서)

```yaml
R5_Methodology:
  template: "templates/verify-report.template.md"
  필수_섹션:
    - "Section 1: Autonomous Discovery Summary (R0.5) — V-xxx 목록 + 차원별 커버리지"
    - "Section 2: Evidence Audit — Observed/Unverified/Invalidated 분류표"
    - "Section 3: Severity Adjustments — 조정 사유 + 의존성 영향"
    - "Section 4: Missing Findings — Autonomous_Only + 교차 분석 결과"
    - "Section 5: Revised Assessment — 재계산 Score + Composite Pass"
    - "Section 6: Gap Diff (R4) — Over_Confidence_Gate 결과"
    - "Section 7: Recommendations — 수정 우선순위 + Keystone Finding"
  regulatory: "skills/ch015/offsec/va/regulatory.md 참조 (regulated 레벨 시)"
```

> **Report Gate 주의 (능동 게이트 1차 / 훅 보조)**: 오케스트레이터가 발행 전에
> `node hooks/report-gate.js`를 **능동 호출**해 분류 완결성/equivalence/score를 검증하며
> (설계 A), PreToolUse 훅(hooks/report-gate-hook.js)은 활성화 시 보조 방어선이다 —
> engagement_dir 내부에 파일명에 `report`/`result`/`summary`/`backlog`가 포함된 `.md`를
> Write/Edit하는 순간(예: `02_verify_result-1st.md`) 동일 검증을 재수행한다.
> 차단(exit 2)되면 파일명 변경이나
> Bash 리다이렉트로 우회하지 말 것 — Verifier 산출물 파일명은 SoD 화이트리스트
> (verify-invariants.js VERIFIER_OUTPUT_PATTERNS)와도 배선되어 있어 임의 변경 금지.
> 누락 산출물의 보완 주체는 raw ledger는 VA Phase 4.7, classification은 OffSec Lead
> Convergence이므로, blocker 사유를 반환 메시지로 Lead에 보고하고 보완 후 재시도한다.

---

## 보상 제어 재검증 (Compensating Control Re-Verification)

```yaml
Reference: "common/compensating-control.md"

When_To_Apply: |
  Phase R1 (Evidence Audit) 또는 R4 (Missing Finding Probe)에서
  원본 보고서가 보상 제어를 근거로 심각도를 완화한 경우,
  common/compensating-control.md의 4단계 프로토콜로 재검증한다.

Protocol:
  1_Identify: "보상 제어로 판단된 메커니즘의 존재 확인"
  2_Verify_Config: "설정 파일에서 보상 제어의 구현 확인"
  3_Evaluate_Effectiveness: "보상 제어가 원본 위협을 실제로 차단하는지 평가"
  4_Document: |
    재검증 결과를 Section 1 (Evidence Audit) 또는
    Section 5 (Revised Assessment)에 기록

Key_Principle: |
  보상 제어의 존재(Presence)와 유효성(Effectiveness)은 별개의 판단이다.
  원본 보고서가 존재만으로 완화 판정한 경우 유효성을 코드에서 재확인한다.
```

---

## Anti-Patterns (이 스킬이 하지 않아야 하는 것)

```yaml
Anti_Patterns:
  Rubber_Stamping: |
    "원본 보고서의 결론을 그대로 확인하는 것은 검증이 아니다.
     모든 판단을 증거로부터 독립적으로 재도출해야 한다."

  Scope_Expansion: |
    "검증 과정에서 새로운 전체 VA를 수행하지 않는다.
     Phase R4는 누락 탐색이지 전면 재분석이 아니다.
     신규 Finding 후보가 발견되면 별도 VA 실행을 권고한다."

  Severity_Inflation: |
    "검증자가 보수적이라는 이유로 모든 심각도를 올리지 않는다.
     심각도 변경에는 증거 기반 근거가 필요하다."

  Assumption_Without_Evidence: |
    "검증 과정에서도 No_Library_Assumptions 원칙을 준수한다.
     원본 보고서의 가정을 반박할 때도 증거 기반이어야 한다."
```
