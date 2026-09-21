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
