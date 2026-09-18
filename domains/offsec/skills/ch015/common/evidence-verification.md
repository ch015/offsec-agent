# 증거 검증 프로토콜 (Evidence Verification Protocol)

> Finding 생성 후, 모든 file:line 증거를 독립적으로 재확인하여
> 할루시네이션(존재하지 않는 코드 참조)을 탐지하고 제거합니다.

---

## 설계 원칙

```yaml
Principles:
  Independent_Verification: |
    증거 검증은 Finding을 생성한 분석과 별도로 수행한다.
    분석 컨텍스트의 "기억"에 의존하지 않고,
    각 증거를 파일 시스템에서 직접 재확인한다.

  File_System_Is_Ground_Truth: |
    코드 증거의 진실 출처(ground truth)는 파일 시스템이다.
    컨텍스트에 남아 있는 코드 조각이 아닌,
    Read/Grep 도구로 실제 파일을 열어 확인한다.

  Fail_Safe: |
    검증 실패한 증거는 즉시 Invalidated로 분류한다.
    해당 Finding의 나머지 증거로 결론을 유지할 수 있는지 재평가하고,
    유지 불가하면 Finding을 Unsubstantiated로 강등한다.
```

---

## 실행 시점

```yaml
Trigger:
  VA_Flow: |
    Phase 4(Scoring) 직후, Phase 5(Report) 직전에 실행한다.
    Phase 4.5: Evidence Verification
    검증 결과에 따라 Finding 목록이 조정된 후 보고서를 생성한다.

  Review_Flow: |
    Verifier의 증거 감사(Phase R1)에서도 동일 프로토콜을 적용한다.

  Pentest_Flow: |
    Pentest Phase 4.5(Self-Verify) 후에 POC 코드의 참조 증거를 검증한다.
```

---

## 검증 절차

```yaml
Verification_Steps:

  Step_1_Evidence_Extraction:
    설명: "Finding 목록에서 모든 file:line 참조를 추출"
    입력: "Finding 목록 (Phase 1~4 결과)"
    출력: |
      Evidence_Manifest:
        - finding_id: "F-001"
          evidences:
            - ref: "src/api/auth.ts:42"
              claim: "JWT 검증 없이 토큰을 신뢰"
              classification: "Observed"
            - ref: "src/middleware/cors.ts:15"
              claim: "CORS 와일드카드 설정"
              classification: "Observed"

  Step_2_File_Existence_Check:
    설명: "참조된 파일이 실제로 존재하는지 확인"
    도구: "Glob 또는 Read"
    절차:
      - "각 ref의 파일 경로가 프로젝트에 존재하는가?"
      - "파일이 존재하지 않으면 → Invalidated: FILE_NOT_FOUND"
    주의: |
      경로 변형을 시도하지 않는다.
      "src/api/auth.ts가 없으니 src/api/auth.js일 것이다"는 허용하지 않음.
      정확히 참조된 경로만 확인한다.

  Step_3_Line_Content_Check:
    설명: "참조된 라인의 실제 내용이 claim과 일치하는지 확인"
    도구: "Read (해당 라인 범위)"
    절차:
      - "ref의 라인 번호에서 ±5줄 범위를 Read"
      - "해당 범위에 claim이 설명하는 코드 패턴이 존재하는가?"
      - "존재하면 → Verified"
      - "해당 라인에 코드가 있으나 claim과 무관하면 → Invalidated: CONTENT_MISMATCH"
      - "라인 번호가 파일 범위를 초과하면 → Invalidated: LINE_OUT_OF_RANGE"
    허용_편차: |
      정확한 라인 번호가 ±10줄 이내로 어긋나더라도,
      해당 범위 내에서 claim에 해당하는 코드를 발견하면
      Verified로 판정하고 정확한 라인 번호로 수정한다.
      이것은 코드 편집에 의한 라인 번호 변동을 허용한다.

  Step_4_Classification_Check:
    설명: "증거 분류(Observed/Unverified)가 올바른지 확인"
    절차:
      - "Observed로 분류된 증거: Step 3에서 코드에서 직접 확인 가능해야 함"
      - "Unverified로 분류된 증거: 프레임워크/라이브러리 기본값에 의존하는 것이 맞는지 확인"
      - "Observed인데 실제로는 라이브러리 기본값에 의존 → Reclassified: Unverified"

  # -----------------------------------------------------------------------
  # Step 5: Semantic Taint Re-trace (의미론적 taint 재추적)
  # 참조: skills/ch015/offsec/verifier/SKILL.md — Phase R1.2
  # 목적: 라인 존재 확인(Step 1~4)을 넘어, 주장(claim)의 논리 자체를 재검증.
  #       "user input → unsafe sink" 형태의 Finding이 taint 경로 중간에서
  #       sanitizer/validator/parameterization에 의해 차단될 수 있으므로,
  #       모든 홉을 독립 재추적하여 진짜로 도달하는지 확인.
  # -----------------------------------------------------------------------
  Step_5_Semantic_Taint_Retrace:
    설명: "source→sink taint 경로의 모든 홉에서 sanitizer 부재 여부 재확인"
    적용_대상:
      - "severity in [CRITICAL, HIGH] — 필수"
      - "severity in [MEDIUM, LOW] — 최소 20% 샘플링"
    절차:
      - "Finding에서 source 지점과 sink 지점을 추출 (없으면 Finding에 보강 요청)"
      - "source 파일:라인 ±20줄 독립 Read — 실제로 untrusted input이 유입되는가?"
      - "sink 파일:라인 ±20줄 독립 Read — 실제로 위험한 sink인가?"
      - "Grep으로 중간 호출 경로(caller chain) 역추적"
      - "각 홉에서 검색: parameterization / sanitize / escape / validate / type-coerce"
    분류:
      Verified_Taint_Path: "모든 홉에서 sanitizer 부재 + sink 도달 가능 → Finding 유지"
      Mitigated_Path: "최소 1홉에서 적절한 sanitizer 발견 → 심각도 1단계 하향"
      Unreachable_Path: "caller 0건 또는 조건부 dead code → 심각도 LOW + Reachability 태그"
      Incomplete_Trace: "홉 수 > 5 / 동적 디스패치 / 리플렉션 → manual_review_required"
    기록_필드: |
      Finding.evidence.taint_trace = {
        classification,
        hops: [{ file, line, call, sanitizer_found? }],
        sanitizers_found: [...],
        notes
      }
```

---

## 검증 결과 처리

```yaml
Result_Actions:

  Verified:
    설명: "파일 존재 + 라인 내용 일치 + 분류 정확"
    조치: "Finding 유지, 라인 번호 보정 (편차 있었을 경우)"

  Invalidated:
    유형:
      FILE_NOT_FOUND: "참조된 파일이 프로젝트에 존재하지 않음"
      CONTENT_MISMATCH: "파일은 존재하나 해당 라인에 claim 코드 없음"
      LINE_OUT_OF_RANGE: "라인 번호가 파일 전체 라인 수를 초과"
    조치: |
      1. 해당 증거를 Finding에서 제거
      2. 남은 증거로 Finding의 결론을 유지할 수 있는지 평가:
         - 유지 가능: Finding 유지, 제거된 증거만 삭제
         - 유지 불가: Finding을 Unsubstantiated로 강등
      3. Unsubstantiated Finding은 보고서에 별도 섹션으로 기록:
         "⚠️ 증거 검증 실패 — 아래 Finding은 증거 부족으로 확인 불가"

  Reclassified:
    설명: "증거 분류가 변경됨 (Observed → Unverified)"
    조치: |
      1. 증거 분류를 수정
      2. Unverified 비율 재계산
      3. 비율이 20%를 초과하면 게이트 위반 — 추가 분석 필요

  검증_요약: |
    검증 완료 후 아래 요약을 생성한다:

    Evidence_Verification_Summary:
      total_evidences: N
      verified: N
      invalidated: N (FILE_NOT_FOUND: N, CONTENT_MISMATCH: N, LINE_OUT_OF_RANGE: N)
      reclassified: N
      findings_affected: N
      findings_unsubstantiated: N
      unverified_ratio_before: "X%"
      unverified_ratio_after: "Y%"
```

---

## 경량 Agent 실행 (선택)

```yaml
Lightweight_Agent:
  설명: |
    증거 검증은 컨텍스트 부담이 적은 작업이므로,
    별도 경량 Agent로 위임하여 메인 분석 컨텍스트를 보존할 수 있다.

  실행_조건: |
    아래 조건 중 하나 이상이면 별도 Agent 실행을 권장:
    - Finding 수가 15건 이상
    - 전체 증거 수가 50건 이상
    - 메인 분석 컨텍스트가 이미 압축 경고를 받은 경우

  Agent_호출: |
    Agent({
      subagent_type: "general-purpose",
      prompt: "아래 Evidence_Manifest의 각 file:line 참조를 검증하라.
               각 참조에 대해:
               1. 파일이 존재하는지 Glob으로 확인
               2. 해당 라인 ±5줄을 Read로 읽어 claim과 대조
               3. 결과를 Verified/Invalidated/Reclassified로 분류
               
               Evidence_Manifest:
               {manifest_yaml}
               
               결과를 Evidence_Verification_Summary 형식으로 반환하라.",
      description: "Evidence verification"
    })

  결과_통합: |
    Agent 반환 결과를 받아 Finding 목록을 조정한 후
    Phase 5(Report)로 진행한다.
```

---

## Anti-Patterns

```yaml
Anti_Patterns:
  Memory_Based_Verification: |
    "아까 그 파일을 읽었을 때 42번 줄에 그 코드가 있었다"는
    컨텍스트 기억에 의존한 검증이다. 이것은 유효하지 않다.
    반드시 Read 도구로 파일을 다시 열어 확인한다.

  Path_Guessing: |
    참조된 파일이 없을 때 유사한 경로를 추측하여 대체하지 않는다.
    FILE_NOT_FOUND는 FILE_NOT_FOUND이다.

  Bulk_Assumption: |
    "이 프레임워크는 일반적으로 이런 구조이므로 파일이 있을 것이다"는
    검증이 아니다. 모든 참조를 개별적으로 확인한다.
```
