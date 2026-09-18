# Large Scale Flow — 대규모 프로젝트 3-Tier 분석 프로토콜

> 서브프로젝트 5개 이상 / 소스 파일 500개 이상 / 100K줄 이상의 대규모 프로젝트에
> 3-Tier Scanning + 모델 라우팅 + 배치 실행을 적용합니다.
> OffSec Lead가 필요 시 Read로 로드합니다.

---

```yaml
Large_Scale_Flow:
  description: "대규모 프로젝트 — 3-Tier Scanning + 모델 라우팅 + 배치 실행"
  trigger: |
    아래 조건 중 하나 이상 충족 시 자동 활성화:
    - 서브프로젝트(독립 빌드 단위) 5개 이상
    - 소스 파일 500개 이상
    - 소스 코드 100K줄 이상
    CISO가 "--large-scale" 옵션으로 강제 활성화할 수도 있다.

  Continuous_Execution: |
    ⚠️ 모든 Tier(0→1→Cross-Reference→2→Convergence→Report)를
    중단 없이 순차 자동 실행한다.
    Tier 간 사용자 확인을 요청하지 않는다.
    각 Tier 완료 시 진행 상황만 간략히 출력하고 즉시 다음 Tier로 진행한다.
    예외: CISO가 명시적으로 "--step-by-step" 옵션을 지정한 경우에만 단계별 확인.

  Model_Routing: |
    ch015.config.json의 agentModel 설정 참조.
    - agentModel.costOptimized=true  → 아래 각 Tier의 config.agentModel.routing.* 값을 model로 사용한다.
    - agentModel.costOptimized=false → routing 값을 무시하고 모든 Tier를 agentModel.default로 실행한다.
    이 규칙은 이 파일의 모든 config.agentModel.routing.* 참조에 동일 적용된다.

  # ─────────────────────────────────────────────────────────────
  # Tier 0: Project Scanning (Haiku, 병렬)
  # ─────────────────────────────────────────────────────────────
  Tier_0_Scan:
    protocol: skills/ch015/common/project-scanner.md
    execution: |
      Agent({
        subagent_type: "general-purpose",
        model: config.agentModel.routing.tier0_scanner,
        prompt: <<SCANNER_PROMPT>>,
        description: "Tier 0 프로젝트 스캔"
      })
    prompt_구성: |
      먼저 skills/ch015/common/project-scanner.md를 Read하여 프로토콜을 로드한 뒤
      Phase S0~S5를 실행하라.
      대상: {target_path}
      engagement_dir: {engagement_dir}
      결과를 00_scan_manifest.yaml, 00_security_surface_map.yaml,
      00_api_inventory.yaml, 00_scan_plan.yaml로 저장하라.
      ⚠️ general-purpose Agent이므로 스킬 자동 바인딩 없음 — 반드시 Read로 로드.
    출력: |
      - Unit Manifest (서브프로젝트 분해)
      - Security Surface Map (Unit별 보안 파일 목록)
      - API Inventory (전체 엔드포인트)
      - Scan Plan (배치 계획 + 비용 추정)

  # ─────────────────────────────────────────────────────────────
  # Tier 1: Targeted VA (Sonnet, 배치 병렬)
  # ─────────────────────────────────────────────────────────────
  Tier_1_VA:
    execution: |
      Tier 0의 scan_plan.yaml에 따라 배치별로 VA Agent를 병렬 호출한다.
      각 배치는 3-4 Unit을 동시 실행한다.

      배치 실행 예시:
      # Batch 1 (단일 메시지에서 병렬 호출)
      Agent({
        subagent_type: "va-auditor",
        model: config.agentModel.routing.tier1_va,
        prompt: "targeted 모드 — 보안 표면 파일만 분석\n
                 target: {unit_path}\n
                 security_surface: {surface_files_yaml}\n
                 api_inventory: {unit_api_yaml}\n
                 level: {level}\n
                 engagement_dir: {dir}",
        description: "VA {unit_id}"
      })
      # ... 동일 메시지에서 Batch 내 다른 Unit도 동시 호출

    배치_크기: |
      동시 실행 Agent 수: 3-4개 (리소스 제약)
      배치 간 순차 실행 — 이전 배치 완료 후 다음 배치 시작.
      단, 배치 내 Agent들은 병렬 실행.

    targeted_모드: |
      VA Agent는 security_surface_map에 명시된 파일만 정밀 분석한다.
      - entry_points → A1(인증), A2(인가), A4(입출력) 집중
      - auth_files → A1, A2 집중
      - crypto_files → A5 집중
      - data_access → A3(데이터흐름), A4 집중
      - transaction_files → Phase 2 비즈니스 로직 집중
      - config_files → A5, A7, A8 집중
      비보안 파일은 호출 체인 추적 시에만 부분 Read한다.

    gate: "Standard_Flow와 동일 — 8차원 분석 완료 + Unverified < 20%"

  Tier_1_Review:
    배치_크기: "Verifier도 VA와 동일하게 3-4 Unit 이내로 배치 분할한다."
    execution: |
      VA 배치 완료 후, Verifier Agent를 배치별로 호출한다.
      Verify도 config의 모델 설정에 따라 실행한다.

      Agent({
        subagent_type: "verifier",
        model: config.agentModel.routing.tier1_verify,
        prompt: "targeted Verify — VA 결과 검증\n
                 target: {unit_path}\n
                 unit_id: {unit_id}\n
                 va_report_path_SEALED: {va_result_path} (★ R0.5 완료 전 Read 금지)\n
                 security_surface: {surface_files_yaml}\n
                 engagement_dir: {dir}\n
                 지시: Verifier는 R0.5 Autonomous Discovery를 먼저 수행하고\n
                 {engagement_dir}/02a_verify_autonomous-{round}-{unit_id}.md 생성 후에만\n
                 봉인 경로를 Read할 수 있다 (offsec-lead.md Phase_2_Verify와 동일 규칙).\n
                 ⚠️ 배치별 Verifier가 병렬 실행되므로 02a/결과 파일은 반드시 -{unit_id} 접미를\n
                 붙여 충돌을 막는다(접미 없으면 단일 파일을 공유해 덮어쓰기·I3 차단 발생).",
        description: "Verify {unit_id}"
      })
      # 게이트 호출 시에도 그룹 인자로 unit_id를 전달:
      #   AGENT_VERIFY_GROUP={unit_id} node hooks/verify-invariants.js check {dir} {round} {unit_id}

    피드백_루프: |
      이의 발생 시 Standard_Flow와 동일하게 피드백 루프 실행.
      VA feedback Agent도 Sonnet으로 실행.

  Tier_1_Cross_Reference:
    실행_주체: "OffSec Lead가 직접 수행"
    action: |
      Parallel_Flow의 Cross_Reference와 동일.
      모든 Unit의 결과 파일을 Read하여 교차 검증.
      Systemic Issue(SYS-XXX), Cross-Boundary Finding(CB-XXX) 식별.

  # ─────────────────────────────────────────────────────────────
  # Tier 2: Deep Audit (Opus, CRITICAL/HIGH만)
  # ─────────────────────────────────────────────────────────────
  Tier_2_Deep:
    condition: "Tier 1에서 CRITICAL 또는 HIGH Finding이 1건 이상"
    execution: |
      CRITICAL/HIGH Finding만 추출하여 Opus Agent로 심층 검증한다.
      전체 보고서가 아닌 해당 Finding의 코드 체인만 집중 분석한다.

      Agent({
        subagent_type: "va-auditor",
        model: config.agentModel.routing.tier2_deep,
        prompt: "deep-audit 모드 — CRITICAL/HIGH Finding 심층 검증\n
                 target: {target_path}\n
                 findings_to_verify: [{finding_id, location, claim}]\n
                 va_report_path: {path}\n
                 engagement_dir: {dir}",
        description: "Tier 2 Deep Audit"
      })

    scope: |
      - 해당 Finding의 코드 체인 전체 추적 (entry point → 취약 코드 → 영향 범위)
      - 보상 제어 정밀 검증
      - 6-step 영향도 분석 보강
      - 증거 검증 (evidence-verification.md)

    결과_반영: |
      Tier 2 결과를 Tier 1 보고서에 병합하여 최종 보고서 생성.
      Tier 2에서 Invalidated된 Finding은 강등/제거.
      Tier 2에서 확인된 Finding은 검증 상태를 "Opus-verified"로 표기.

  # ─────────────────────────────────────────────────────────────
  # Tier 2: Pentest (조건부, Opus)
  # ─────────────────────────────────────────────────────────────
  Tier_2_Pentest:
    condition: "CISO verification_mode에 Pentest 포함 시"
    execution: |
      Standard_Flow의 Phase_4_Pentest와 동일.
      model: config.agentModel.routing.tier2_pentest
      입력은 Tier 1/2에서 확정된 Finding 요약.

  # ─────────────────────────────────────────────────────────────
  # Final: 통합 보고서
  # ─────────────────────────────────────────────────────────────
  Lead_Session_Continuity:
    설명: |
      Large Scale Flow에서 Lead 세션은 다수 Agent 결과를 누적하여
      컨텍스트 윈도우가 포화될 수 있다. Tier 경계에서 phase_state.json을
      확인하고, 누적 토큰이 warn_threshold(80%)에 도달하면
      현재까지 결과를 engagement_dir에 기록한 후 context를 정리한다.
    체크포인트: |
      - Tier 1 VA 배치 완료 시: phase_state.json의 cumulative_tokens 확인
      - Tier 1 Review 완료 시: Cross-Reference 시작 전 상태 점검
      - Tier 2 완료 시: Final Convergence 시작 전 상태 점검

  Final_Convergence:
    실행_주체: "OffSec Lead가 메인 세션에서 직접 수행 (Agent 위임 아님)"
    action: |
      Large Scale Flow의 분산된 결과를 통합하여 최종 보고서를 생성한다.
      Standard_Flow의 Convergence와 달리, Unit별 분산 파일을 합치는 추가 절차가 필요하다.

    Step_1_Unit별_결과_수집: |
      각 Unit의 VA 결과 파일을 Read하여 Finding 목록을 추출한다:
      - {unit_id}_va_result.md → Finding 섹션
      - {unit_id}_finding_summary.yaml → 요약 데이터
      - Unit별 raw findings ledger (존재 시) → 전체 후보와 상태
      Unit별 Finding에 소속 Unit ID를 태그한다 (F-U1-001, F-U2-001 등).
      Unit별 raw ledger를 candidate_id 충돌 없이 병합하여 consolidated ledger를 생성한다:
      → engagement_dir/09_raw_findings_ledger-consolidated.yaml
        (templates/raw-findings-ledger.template.yaml 스키마.
         파일명은 report-gate-hook.js LEDGER_RE 매칭 필수 — 임의 변경 금지)

    Step_2_Cross_Reference_반영: |
      00_cross_reference_result.md를 Read하여:
      - Systemic Issue (SYS-XXX): Unit 간 공통 패턴 → 통합 Finding으로 생성
      - Cross-Boundary Finding (CB-XXX): Unit 경계 취약점 → 신규 Finding 추가
      - 심각도 재조정: 교차 검증에서 변동된 심각도 반영

    Step_3_Deep_Audit_반영: |
      08_deep_audit_result.md가 존재하면 Read하여:
      - Tier 2에서 Invalidated된 Finding → 강등/제거
      - Tier 2에서 확인된 Finding → "Opus-verified" 태그
      - 보강된 6-step 영향도 분석 → 해당 Finding에 병합

    Step_4_Verify_조정_반영: |
      Unit별 Verify 결과 파일을 Read하여:
      - 심각도 조정 사항 반영
      - 이의 처리 결과 반영 (승인/기각/Disputed)

    Step_5_Pentest_RedTeam_반영: |
      (해당 시) Pentest/RedTeam 결과를 Standard_Flow와 동일하게 반영:
      - Pentest Route_F 검증 → Unverifiable_HTTP 재분류
      - RedTeam Phase 4.6 → Unverifiable_Infra 재분류

    Step_6_통합_Score_산출: |
      모든 조정이 반영된 최종 Finding 목록으로 Score를 산출한다:
      - Primary Score: 100 - (CRITICAL × 25 + HIGH × 10 + MEDIUM × 3 + LOW × 1)
      - Composite Pass: Score ≥ 85 AND CRITICAL=0 AND HIGH≤2 AND (CVSS≥9.0 Finding 건수)=0
      - Business Impact Score: Σ(심각도 × Asset_Value 가중치)
      ⚠️ Unit별 Score의 단순 평균이 아닌, 전체 Finding 통합 후 재산출.
      Asset Register는 Tier 0에서 전체 프로젝트 단위로 1회 생성되므로
      Unit별 Finding의 Asset_Value는 전체 Asset Register를 참조한다.

    Step_6.5_분류_게이트: |
      Standard_Flow의 Convergence(offsec-lead.md Phase_5_Convergence)와 동일한
      게이트를 최종 보고서 생성 "이전"에 적용한다:
      - consolidated ledger의 모든 candidate를 CONFIRMED/DOWNGRADED/FOLDED_INTO/
        BACKLOG/EXCLUDED/PENDING_PENTEST/PENDING_EXTERNAL/FALSE_POSITIVE/
        OUT_OF_SCOPE/DISPUTED 중 하나로 분류 (DOWNGRADED는 downgrade_reason 필수)
      - equivalence_review로 동일 취약점 MERGE/SPLIT/KEEP 판단 완료
        (Unit 경계를 넘는 Systemic Issue/Cross-Boundary 후보 포함)
      - 대표 Finding의 affected_instances에 Unit별 영향 대상 병합
      - UNCLASSIFIED 후보 0건 확인 — 1건 이상이면 최종 보고서 발행 금지
      - PENDING_PENTEST 후보가 pentest plan에 1:1 라우팅되었는지 확인
      분류 산출물: engagement_dir/09_convergence_classification.yaml
      (templates/convergence-classification.template.yaml 스키마.
       파일명은 report-gate-hook.js CLASSIFICATION_RE 매칭 필수 — 임의 변경 금지)

    Step_7_최종_보고서_생성: |
      va-report.template.md를 기반으로 통합 보고서를 생성한다.
      Standard Flow 보고서와 동일 구조에 추가 섹션:
      - Unit별 요약 테이블 (Unit ID, Score, Finding 수, 핵심 이슈)
      - Cross-Boundary Finding 섹션
      - Systemic Issue 섹션
      - Tier별 비용 실적 (scan_plan.yaml 대비 실적)
      - 전체 프로젝트 통합 Attack Surface Map

    Step_6.7_커버리지_매니페스트_방출: |
      ★ 커버리지 게이트(전수 커버리지 강제, R1/R2/R3)용 `coverage_units.yaml`를 **반드시** 방출한다.
      이게 없으면 report-gate가 최종 보고서를 COVERAGE_DATA_MISSING으로 차단한다(large-scale flow 한정).
      스키마:
        excluded_units:                    # deep-분석 제외 — 보안관련 코드가 있으면 justification 필수(R7)
          - { path: <uid/path>, justification: "<제외 근거 — 없으면 코드 제외 차단>" }
          # 순수 asset(코드 없음)만 제외 시엔 문자열 [<path>...]도 허용
        defined_units:  [<uid>...]        # 실행하기로 계획한 audit 유닛(분해 후 granularity)
        audit_units:                       # 실제 실행된 audit 유닛
          - { id, path, files_examined }   # files_examined = va SKILL baseline.scope.files_examined 파일 수
          # ※ files_in_scope는 게이트가 source_manifest에서 실제 계산(자기신고 무시, R3′) — 넣어도 무시됨
        sink_signatures:                   # (선택) 확인된 취약 패턴의 교차파일 반복 강제(R8)
          - { pattern: "<grep -E 정규식>", classified_files: [<분류한 파일...>] }
          # 예: { pattern: "inject_pool_oauth_token|pool_server_url", classified_files: [".../account.rs", ".../billing.rs"] }
      게이트 판정(hooks/report-gate-hook.js → lib/ch015/coverage-gate.js):
        - R1 분해: source_manifest.units의 유닛 LOC > 40K인데 이를 덮는 audit 유닛이 ceil(loc/40K) 미만 →
          COVERAGE_REQUIRE_SPLIT (내부 모듈 경계로 sub-unit 분할 필수). ★ S4는 이제 "권장"이 아니라 이 게이트로 강제됨.
        - R2 완결성: defined_units 중 실행 안 된 게 있으면 COVERAGE_INCOMPLETE_FANOUT.
        - R3 커버리지 비율: files_examined / (manifest 실제 scope) < 0.7 → COVERAGE_UNDER_COVERED.
          ★ scope는 source_manifest.source_files에서 audit unit 경로 기준으로 계산 → 표본만 스코프로 신고해
          비율을 부풀리는 은닉이 불가(R3′).
        - R7 제외 정당화: excluded_units에 보안관련 언어 소스(.rs/.go/.ts/.tsx/.js/.jsx/.py/.sql/… )가 있는데
          justification이 없으면 COVERAGE_EXCLUSION_UNJUSTIFIED. 코드를 "jsx=장식" 식으로 무검증 제외하는 것 차단
          (davinci-design-core HIGH 2 누락 정면 수정). 순수 asset 제외는 justification 없이 허용.
        - R8 교차파일 반복: sink_signatures의 패턴을 target에서 grep해 classified_files에 없는 인스턴스가 있으면
          COVERAGE_SYSTEMIC_RECURRENCE. 한 파일서 확인한 취약 패턴을 다른 파일서 누락하는 것 차단(GD-01:
          inject_pool_oauth_token 유출이 billing.rs·account.rs 두 곳인데 한 곳만 분류한 사례).
      토글: CH015_COVERAGE_GATE=off로 해제(권장하지 않음).

    storage: |
      engagement_dir에 저장:
      - 09_raw_findings_ledger-consolidated.yaml (Unit별 raw ledger 통합본 — report-gate 입력)
      - 09_convergence_classification.yaml (분류 + equivalence review — report-gate 입력)
      - 09_large_scale_convergence.yaml (수렴 기록)
      - coverage_units.yaml (커버리지 게이트 입력 — 전수 커버리지 강제, 위 Step_6.7. 미방출 시 발행 차단)
      - 10_final_security_report.md (통합 최종 보고서 — 파일명이 report-gate-hook.js
        FINAL_REPORT_RE에 매칭되어 분류 산출물 미존재 시 fail-closed 차단됨)
    output: "CISO에 전달 — Executive Summary + 통합 Score + 수정 로드맵"

    CISO_전달_형식: |
      CISO에 전달하는 정보:
      - 전체 프로젝트 Security Score + 등급 + Composite Pass 결과
      - Business Impact Score
      - CRITICAL/HIGH Finding 요약 (Unit 소속 표시)
      - Cross-Boundary / Systemic Issue 요약
      - Unit별 Score 비교 테이블
      - 통합 수정 우선순위 로드맵 (Asset_Value 반영)
      - 상세 보고서 경로: engagement_dir/10_final_security_report.md
```
