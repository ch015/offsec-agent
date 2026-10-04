# Evaluate contract card

`00_analysis_coverage.json`의 complete는 작업 단위 실행 완료만 뜻한다. semanticCoverage는
자동 증명되지 않는다. source Read 수, AST 미처리/실패, 후속 가설과 unresolved를 분리해서 설명한다.
파일을 읽었다는 이유만으로 보안 검토가 충실했다고 판단하거나, 도구 후보가 없다고 안전 판정을 하지 않는다.

이 문서는 `evaluate` phase의 강제 방법 카드다. evaluator는 다른 에이전트나 phase를
호출하지 않고 review 산출물과 recon 정보를 기반으로 객관적 평가를 수행한다.
evaluator는 finding을 추가·수정·삭제하지 않는다 (평가 전용).

## 평가 절차

1. `03_review_result.json`에서 검수 완료된 finding 목록을 읽는다.
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

review에서 retained + corrected된 finding의 최고 severity 기준:

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
정확히 Read한다. 파일명은 finding ID가 아닌 해시다. 디렉터리 Glob이나 ID로 만든
경로로 대체하지 않는다. 원본 severity를 추정하거나 변경하지 않는다. reviewer가
`submit_finding`으로 보정한 동일 ID의 기록이 있으면 reviewer 기록을 채택한다.

`04_evaluation.json.severityDistribution`에는 CRITICAL/HIGH/MEDIUM/LOW/INFO의 정수
건수를 모두 기입한다. CONFIRMED/DOWNGRADED만 집계하고 원장과 일치시킨다.

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
