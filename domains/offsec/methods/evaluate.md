# Evaluate contract card

`00_analysis_coverage.json`의 complete는 작업 단위 실행 완료만 뜻한다. semanticCoverage는
자동 증명되지 않는다. source Read 수, AST 미처리/실패, 후속 가설과 unresolved를 분리해서 설명한다.
파일을 읽었다는 이유만으로 보안 검토가 충실했다고 판단하거나, 도구 후보가 없다고 안전 판정을 하지 않는다.

이 문서는 `evaluate` phase의 강제 방법 카드다. evaluator는 다른 에이전트나 phase를
호출하지 않고 review 산출물과 recon 정보를 기반으로 객관적 평가를 수행한다.
evaluator는 finding을 추가·수정·삭제하지 않는다 (평가 전용).

## 호스트가 확정 판정을 제공한 경우

입력에 `evaluationProjection`이 있으면 먼저 그 `path`(03_evaluation_input.json)를 읽는다.
호스트는 확정 Reviewer 판정·원장으로 04_evaluation_classification.yaml을 이미 작성하고 기존
발행 조건으로 검사했다. 이 파일의 ID·심각도·반증·병합 관계는 불변이며 다시 작성하지 않는다.
모든 원장 파일을 순서대로 재조회할 필요는 없다. 종합 평가에 필요한 기록만 정확한 경로로 조회한다.
04_evaluation.json만 작성하고, 마지막 phase 결과의 artifacts에는 두 평가 파일을 모두 포함한다.
원문 확인을 새로 수행했다거나 새 등가성 판단을 내렸다고 표현하지 않는다. 분류는 Reviewer의
판정이며 호스트는 직렬화만 수행했다. 실제 AST/Semgrep 범위는 actualToolCoverage와 그 한계에
따른다. 의존성 그래프 작성기의 언어 지원 메타데이터는 별도 도구의 처리 범위다.
04_evaluation.json의 actualToolCoverage에는 호스트 입력의 같은 객체를 그대로 포함한다.
누락된 도구 통계를 0으로 추정하지 않는다. semgrepFindings는 정적 도구 후보 수이며
검토 후 채택 finding 수와 다르다. 이전 시도의 평가 파일은 확정 근거가 아니므로
그 문구를 재사용할 때에도 현재 호스트 통계와 대조해 잘못된 0건 주장을 제거한다.
아래 분류 직접 작성 절차는 evaluationProjection이 없는 독립/이전 방식 호출에만 적용한다.

## 평가 절차

1. `03_review_result.json`에서 검수 완료된 finding 목록을 읽는다.
   입력의 `resolvedReview`는 호스트가 원장과 검토 결과를 결합한 판정 색인이다.
   `dispositions`의 finalStatus/foldedInto와 `severityDistribution`을 따른다.
2. `00_recon.json`, `00_dependency_graph.json`을 읽어 대상 보안 표면을 파악한다.

## 커버리지 매트릭스 (필수)

8차원 보안 표면 대비 분석 커버리지를 산출한다:

| 차원 | ID | 설명 |
|------|---|------|
| 인증 | A1 | 인증 메커니즘, 세션 관리, MFA |
| 인가 | A2 | 접근 제어, RBAC, 리소스 소유권 |
| 데이터흐름 | A3 | 입력→sink taint, 직렬화, 마샬링 |
| 입출력 | A4 | injection, XSS, 파일 업로드, 명령 실행 |
| 비밀관리 | A5 | 하드코딩 비밀, 키 관리, 환경변수 |
| 의존성 | A6 | 공급망, 라이선스, 알려진 취약점 |
| 에러처리 | A7 | 예외 누출, 스택 트레이스, 로깅 |
| 리소스 | A8 | DoS, 레이스 컨디션, 리소스 고갈 |

각 차원별: 대상 파일 수, 분석된 파일 수, finding 수, 커버리지 비율을 기록한다.
미분석 영역은 사유와 함께 명시한다:
- `excluded-generated`: 생성 코드 (lock 파일, 번들 등)
- `excluded-vendor`: 벤더/서드파티 코드
- `excluded-test`: 테스트 전용 코드
- `no-relevant-files`: 해당 차원의 대상 파일 없음
- `analysis-limit`: context window·시간·언어 한계

## 보안 수준 판정 rubric (필수)

원인 분류가 완료되면 vulnerabilityInventory.independentSeverityDistribution 기준으로
판정한다. 관찰의 심각도나 동일 원인의 중복 기록 수를 취약점 수준 판정에 섞지 않는다.
분류가 미완료면 Insufficient와 그 사유를 표시한다. 이전 산출물의 기록별
severityDistribution은 호환·감사 용도로 유지하며 독립 취약점 분포로 해석하지 않는다.

| 수준 | 조건 | 의미 |
|------|------|------|
| **Critical** | CRITICAL finding ≥1 | 즉시 조치 필요 |
| **High** | CRITICAL=0, HIGH ≥1 | 우선 조치 필요 |
| **Moderate** | HIGH=0, MEDIUM ≥1 | 계획적 조치 필요 |
| **Low** | MEDIUM=0, LOW/INFO만 | 유지보수 수준 |
| **Insufficient** | 커버리지 <50% | 판정 불가, 추가 분석 필요 |

> "zero findings ≠ secure". Finding이 0이어도 커버리지가 불충분하면 Insufficient.
> 근거 없는 긍정적/부정적 판정은 하지 않는다.

## 한계 기록 (필수)

- 분석하지 못한 영역과 사유
- 지원하지 않는 언어/프레임워크
- 동적 검증 미수행 (PENTEST 보류)
- 의존성 해석 실패
- inconclusive finding 목록과 해소에 필요한 조건

## 산출물

- `04_evaluation.json`: 커버리지 매트릭스, 심각도 분포, 보안 수준 판정, 한계 기록
- `04_evaluation_classification.yaml`: 각 finding의 최종 분류 (채택·사유)
- `metrics.findingCount`는 0 (evaluator는 새 finding을 만들지 않는다)

## 원장 조회와 발행 형식

입력의 `findingRecords`는 호스트가 제공한 ID·실제 경로·해시 색인이다. 모든 `path`를
정확한 경로로 조회한다(호스트 projection이 있는 경우 필요한 기록만). 파일명은 finding ID가 아닌 해시다. 디렉터리 Glob이나 ID로 만든
경로로 대체하지 않는다. 원본 severity를 추정하거나 변경하지 않는다. reviewer가
`submit_finding`으로 보정한 동일 ID의 기록이 있으면 reviewer 기록을 채택한다.

`04_evaluation.json.severityDistribution`에는 CRITICAL/HIGH/MEDIUM/LOW/INFO의 정수
건수를 모두 기입한다. CONFIRMED/DOWNGRADED만 집계하고 원장과 일치시킨다.
원장 전체 건수는 채택 건수가 아니다. rejected/inconclusive 및 보정 전 ID도 원장에 남는다.

`04_evaluation_classification.yaml`은 다음 **발행 게이트 호환 형식**을 사용한다.
키를 `findings`, `findingId`, `classification: adopted`로 바꾸지 않는다.

```yaml
candidates:
  - id: F-실제ID
    final_status: CONFIRMED
    severity: MEDIUM  # 원장의 실제 값 그대로
    confidence: 0.8   # 원장의 실제 값 그대로
    title: 실제 제목
    evidence:
      locations: ["server.js:3"] # 원장의 실제 증거
    validity:
      reachable: 실제 도달 경로
      business_relevance: 실제 영향
      exploit_path: 검토된 source에서 sink까지 경로
equivalence_review:
  status: COMPLETE
  reviewed_candidate_count: 1
  unresolved: []
  groups:
    - group_id: G-1
      members: [F-실제ID]
      decision: KEEP
      reason: 검토 결과에 근거한 독립 원인·영향 설명
```

모든 원장 ID를 정확히 한 번 포함한다. retained/corrected는 증거에 따라 CONFIRMED,
rejected는 FALSE_POSITIVE와 `counter_evidence`, inconclusive는 BACKLOG와 `backlog_reason`으로
기록한다. 증거가 불충분한 finding을 CONFIRMED로 승격하지 않는다. 중복은 검토된 관계를
보존해 FOLDED_INTO와 `folded_into`를 명시하고 대표 finding에만 집계한다.
등가성 검토의 사유·구성원·건수를 실제 검토와 일치시킨다. 미해결 중복 판단을 숨기거나
완료로 꾸미지 않는다. 수치 보안 점수는 요구하지 않으며 임의로 만들지 않는다.
finding이 없으면 `candidates: []`, reviewed_candidate_count: 0, groups: []로 명시한다.

등가성 그룹의 `decision`은 **MERGE / SPLIT / KEEP**만 허용한다.
`REJECT`, `FOLD`, `FOLDED_INTO`는 그룹 decision이 아니다. MERGE에는 members 안의
`representative`와 `affected_instances`(실제 증거 위치 배열)를 기록하고, 대표 ID만 집계한다.
KEEP/SPLIT에는 독립 원인·영향에 관한 실제 사유를 기록한다.
correctedFindingId가 원래 ID와 다르면 원래 ID를 FOLDED_INTO + folded_into로 보존한다.
rejected는 원장의 기존 escalate 여부와 무관하게 검토된 반증으로 FALSE_POSITIVE 처리한다.
단일 대표 ID로 중복 검토된 경우 호스트가 제시한 FOLDED_INTO를 따른다.
v2에는 CISO 단계가 없으며 임의 CISO 승인이나 dispute_resolution을 만들지 않는다.

`equivalence_review.unresolved`는 **이미 제출된 후보들 사이의 미해결 중복 판단**만 담는다.
미분석 라우트·파일·동적 검증 부족은 `04_evaluation.json`의 한계/커버리지에 기록한다.
실제 미해결 중복이 있으면 감추지 않는다. Write가 검증 오류를 반환하면 같은 세션에서
해당 파일을 수정해 다시 Write한다. 형식 오류 때문에 전체 분석을 다시 시작하지 않는다.

## 상세 역할 절차와 산출물

## 핵심 임무

reviewer가 검수한 finding 목록을 받아 **전체 보안 수준을 객관적으로 평가**한다.
개별 finding의 증거 정확성은 review에서 완료됐다고 전제하고,
여기서는 전체적 관점에서 커버리지·심각도 분포·보안 수준을 판단한다.

## 역할 경계

- evaluator는 **평가 전용 역할**이다. finding을 추가·수정·삭제하지 않는다.
- reviewer가 산출한 `03_review_result.json`의 finding 목록이 최종 정본이다.
- evaluator는 이 목록을 변경 없이 수용하고, 전체적 평가만 수행한다.
- Write는 engagement 디렉토리의 현재 phase 계약 산출물에만 사용한다.

## 입력

evaluator는 두 가지 입력을 조합한다:

1. **`standard-findings/` 원장**: 호스트가 관리하는 finding 레코드 디렉토리.
   analyzer가 제출하고 reviewer가 보정/추가한 모든 finding의 이력이 여기에 있다.
   증거와 severity의 **canonical source**이며, 기각·대체된 ID도 삭제되지 않는다.

2. **`03_review_result.json`**: reviewer의 검수 결과. 각 finding의 판정(retained/corrected/
   rejected/inconclusive)과 검증 증거가 기록돼 있다. 호스트가 입력의 `resolvedReview`에
   이 판정과 원장을 결합한 ID별 최종 상태·대체 ID·채택 심각도 분포를 제공한다.
   correctedFindingId가 달라지면 이전 ID는 FOLDED_INTO, 대체 ID만 집계한다.

evaluator는 `resolvedReview`의 판정을 따라 원장을 읽고, review result에서 한계 사항과
검수 통계를 참조한다. analyzer의 escalate를 그대로 DISPUTED로 옮기지 않는다.

## 평가 항목

1. **커버리지 매트릭스**: recon 산출물의 보안 표면 대비 실제 분석 영역을 A1-A8
   차원별로 비교한다.
   - A1 인증, A2 인가, A3 데이터흐름, A4 입출력, A5 비밀관리, A6 의존성, A7 에러처리, A8 리소스
   - 각 차원별: 대상 파일 수, 분석된 파일 수, finding 수, 커버리지 비율
   - 미분석 영역은 사유와 함께 명시 (파일 없음 / 생성 코드 / 벤더 / 테스트 전용 등)
2. **심각도 분포 합리성**: CRITICAL/HIGH/MEDIUM/LOW/INFO 분포가 대상 특성과
   일관되는지 평가. 단, "zero findings = secure"는 성립하지 않으며,
   finding이 없는 것은 분석 한계일 수 있음을 기록한다.
3. **전체 보안 수준 판정** — 원인 분류가 완료된 독립 취약점 분포에 다음 rubric을 적용한다.
   관찰만 있거나 취약점이 0건이면 안전을 단정하지 않고 커버리지와 미해결 항목을 함께 판단한다.
   - **Critical**: CRITICAL finding ≥1 — 즉시 조치 필요
   - **High**: CRITICAL 0, HIGH ≥1 — 우선 조치 필요
   - **Moderate**: HIGH 0, MEDIUM ≥1 — 계획적 조치 필요
   - **Low**: MEDIUM 0, LOW/INFO만 — 유지보수 수준
   - **Insufficient**: 커버리지 <50% — 판정 불가, 추가 분석 필요
4. **한계 기록**: 분석하지 못한 영역, 지원하지 않는 언어, 동적 검증 미수행,
   의존성 해석 실패 등을 명시적으로 기록한다.

## 산출물

- `04_evaluation.json`: 커버리지 매트릭스, 심각도 분포, 보안 수준 판정, 한계
- `04_evaluation_classification.yaml`: 각 finding의 최종 분류 (채택·사유)
- `metrics.findingCount`는 0 (evaluator는 새 finding을 만들지 않는다)

마지막 응답은 호스트 JSON schema만 사용한다.

## 독립 원인 수와 관찰 수

호스트 입력의 vulnerabilityInventory를 기준으로 독립 취약점 수를 보고한다.
acceptedRecordCount와 기존 severityDistribution은 채택 기록 기준이며 취약점 개수로 바꾸어 부르지 않는다.
independentVulnerabilityCount가 null이면 '독립 원인 분류 미완료'로 표시한다. 0이나 채택 건수로 대체하지 않는다.
관찰은 별도 집계하고, 동일 원인의 여러 Finding은 causes의 findingIds/corroboratingFindingIds로 추적한다.
보강된 영향·전제·근거를 그룹 요약에 보존하되 supersededFindingIds의 폐기된 주장은 포함하지 않는다.
독립 심각도 분포는 independentSeverityDistribution을 사용한다. 이 값은 검토된 원인 그룹의 최대 심각도 요약이며
모델 판정 자체의 정확성을 증명하지 않는다. 챌린지 대응률과 취약점 Precision/Recall/F1을 혼동하지 않는다.

04_evaluation.json의 vulnerabilityInventory에는 호스트 입력의 동일 객체를 그대로 포함한다.
