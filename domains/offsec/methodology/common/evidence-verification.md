# 증거 검증 프로토콜 (Evidence Verification Protocol)

> review phase에서 analyzer Finding의 증거와 주장을 독립적으로 재확인하는 절차다.
> `methods/review.md` 검수 절차 1~2의 상세이며, 충돌하면 review 카드와 호스트 계약이 우선한다.

---

## 설계 원칙

```yaml
Principles:
  Host_Checks_Quotes_Reviewer_Checks_Claims: |
    호스트는 submit_finding 시점에 evidence quote가 지정 라인 범위와 정확히 일치하는지
    이미 검사했다(허용 편차 없음). 따라서 수락된 Finding의 인용문은 실제 코드다.
    reviewer가 검증할 대상은 "그 코드가 주장(title·impact·severityRationale)을 뒷받침하는가"다.

  Independent_Verification: |
    분석 컨텍스트의 "기억"이나 analyzer 서술에 의존하지 않는다.
    각 증거를 Read/Grep 도구로 파일에서 직접 다시 연다.

  Fail_Safe: |
    증거가 주장을 뒷받침하지 못하면 남은 증거로 결론을 유지할 수 있는지 다시 평가한다.
    "증거를 찾지 못했다"는 rejected 사유가 아니다. rejected에는 구체적 반증이 필요하다.
```

---

## 적용 범위

```yaml
Scope:
  대상: "입력 원장의 모든 Finding (전수 검수, 표본 추출 없음)"
  깊이: "홉 추적 깊이는 CRITICAL/HIGH를 우선한다. MEDIUM 이하도 건너뛰지 않는다."
```

---

## 검증 절차

```yaml
Verification_Steps:

  Step_1_Evidence_Relevance:
    설명: "각 evidence의 path·lineStart·lineEnd를 Read로 열고, 인용 코드가 주장과 관련 있는지 확인"
    절차:
      - "주변 문맥(호출부·조건문·반환 처리)을 함께 읽는다"
      - "인용 코드가 주장과 무관하거나 주장의 일부만 보여 주면 관련 위치를 Grep으로 찾는다"
      - "올바른 위치를 찾으면 정확한 path·라인·quote로 submit_finding을 다시 제출해 corrected로 보정한다(같은 주 근거 문장의 claim이면 revises: <원래 ID>)"
      - "관련 위치를 찾지 못하면 그 사실을 판정 사유에 남기고 Step 5 기준으로 판정한다"
    주의: |
      경로 변형을 추측하지 않는다("auth.ts가 없으니 auth.js일 것이다"는 허용하지 않음).
      라인 번호를 어림잡아 맞추지 않는다. 호스트는 정확히 일치하는 인용만 수락한다.

  Step_2_Evidence_Class_Check:
    설명: "evidenceClass가 실제 근거 유형과 맞는지 확인"
    절차:
      - "data-flow·access-control·configuration·runtime 주장이 실제 코드·설정 인용으로 뒷받침되는가"
      - "프레임워크·라이브러리 기본값을 가정한 주장은 그 가정을 preconditions나 unresolved에 명시했는가"
      - "documentation 근거만으로는 CRITICAL/HIGH가 될 수 없다(호스트 강제)"

  Step_3_Semantic_Taint_Retrace:
    설명: "source→sink 경로의 모든 홉을 독립적으로 다시 추적"
    절차:
      - "Finding에서 source와 sink를 식별한다(없으면 그 부재를 판정 사유에 남긴다)"
      - "source 주변을 Read — 실제로 신뢰할 수 없는 입력이 유입되는가"
      - "sink 주변을 Read — 실제로 위험한 sink인가"
      - "Grep으로 호출 경로(caller chain)를 역추적한다"
      - "각 홉에서 parameterization / sanitize / escape / validate / type-coerce, 인가 검사, 필드 덮어쓰기를 찾는다"
    판정_매핑:
      Verified_Path: "모든 홉에서 차단이 없고 sink에 도달 → retained (reviewedSeverity 명시)"
      Mitigated_Path: "적절한 차단이 최소 1홉에서 확인 → 심각도를 다시 평가해 corrected로 제출, 차단 위치를 사유에 기록"
      Unreachable_Path: "도달 불가의 구체적 반증(호출자 0건 입증, 항상 거짓인 조건 등)이 있으면 rejected. 반증이 없고 추적만 실패했으면 reachability를 낮춰 corrected"
      Incomplete_Trace: "동적 디스패치·리플렉션·외부 설정 등으로 추적을 끝낼 수 없음 → inconclusive, 확인 필요 사항을 사유와 unresolved에 기록"
    기록: "추적한 홉, 발견한 sanitizer·guard의 file:line을 판정 reason에 남긴다. Finding 스키마에 별도 taint 필드는 없다"

  Step_4_Remaining_Evidence:
    설명: "일부 증거가 주장을 뒷받침하지 못할 때"
    절차:
      - "남은 증거만으로 결론을 유지할 수 있으면 해당 증거를 뺀 버전을 submit_finding으로 다시 제출해 corrected"
      - "유지할 수 없고 반증이 있으면 rejected, 반증 없이 근거만 부족하면 inconclusive"

  Step_5_Verdict:
    설명: "review 카드의 네 판정 중 하나로 결론"
    판정:
      retained: "증거 정확, 도달 가능, 보상 제어 없음"
      corrected: "증거·severity·reachability·분류 보정. submit_finding으로 다시 제출하고 correctedFindingId 기록"
      rejected: "구체적 반증 증거로 false positive 확인"
      inconclusive: "도달성 판단 불가, 파일 접근 불가, 동적 실행 필요 — 미해결 위험으로 보존"
```

---

## Anti-Patterns

```yaml
Anti_Patterns:
  Memory_Based_Verification: |
    "아까 읽었을 때 42번 줄에 그 코드가 있었다"는 컨텍스트 기억에 의존한 검증이다.
    반드시 Read 도구로 파일을 다시 열어 확인한다.

  Quote_Match_As_Proof: |
    인용문이 파일과 일치한다는 사실은 호스트가 이미 보장했다.
    그것만으로 retained로 판정하지 않는다. 주장의 의미와 도달성을 검증한다.

  Absence_As_Rejection: |
    경로나 증거를 찾지 못한 것을 반증으로 취급하지 않는다. 반증이 없으면 inconclusive다.

  Path_Guessing: |
    참조된 파일이 없을 때 유사한 경로를 추측하여 대체하지 않는다.

  Bulk_Assumption: |
    "이 프레임워크는 일반적으로 이런 구조다"는 검증이 아니다. 모든 참조를 개별적으로 확인한다.
```
