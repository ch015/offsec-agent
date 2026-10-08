# Report contract card

`00_analysis_coverage.json`을 확인하고 작업 실행 완료와 의미적 보안 검토를 구분한다.
사전 분석의 누락·실패와 남은 가설을 한계에 명시한다. complete=true만으로 전수 보안 검증을 주장하지 않는다.
evaluationProjection이 제공되면 그 입력의 actualToolCoverage를 실제 AST/Semgrep 처리 통계의
기준으로 사용한다. 의존성 그래프 작성기의 지원 언어 목록과 실제 AST 처리 범위를 혼동하지
않는다. 분류 파일은 확정 Reviewer 판정을 호스트가 내보낸 자료이며 새 모델 판정이 아니다.

입력에 canonicalAppendix가 있으면 호스트가 최종 보고서에 모든 ID·최종 판정·심각도·confidence·
인용·전제·미해결·보완책·표준 매핑의 전체 목록을 자동 첨부한다. reporter는 위험 요약,
대표 근거, 조치 우선순위와 한계를 작성한다. 전체 원장/분류표를 다시 읽거나 수백 개 ID를
수동으로 재작성할 필요가 없다. 본문에 인용한 항목의 전제와 불확실성은 보존한다.
evaluationProjection.classificationSha256과 inputSha256은 각각 분류 파일과 요약 입력 파일의
해시다. 서로 다른 파일의 해시가 다르다는 이유로 출처 충돌을 주장하지 않는다.

이 문서는 `report` phase의 강제 방법 카드다. reporter는 최종 파일이 아니라
`07_security_report.draft.md`만 작성하며 발행 여부는 호스트 report gate가 결정한다.

## Gate 관계 (절대 규칙)

report phase의 임무는 **`07_security_report.draft.md` 1개만 작성**하는 것이다.
정확히 이 초안은 발행물이 아니며, 호스트가 검증된 review/evaluate와 대조해 최종 발행 게이트를 실행한다.
Finding이 0건이면 검토 범위와 한계를 적은 0건 보고서를 작성한다. 없는 원장·점수·Git 커밋을 만들어내지 않는다.
Git 정보가 없는 대상은 source snapshot 식별자와 파일 인벤토리로 출처를 명시한다.

작성 가능한 근거가 있으면 먼저 초안을 작성하고 실제 발행 판정은 호스트에 맡긴다.
게이트 실패를 예상했다는 이유만으로 작업을 멈추거나, 게이트를 우회하기 위해 증거를 꾸미지 마라.
호스트는 증거·출처·검토 기록을 확인하고 실패 시 최종 발행을 거부한다.

보고서 안의 오류는 허용된 draft에서 수정한다. 상위 산출물이나 필수 근거가 실제로 없어
정당한 보고서를 만들 수 없으면 이유와 미해결 사항을 남기고 blocked를 반환한다.
상위 산출물을 임의로 수정하거나 발행 조건을 낮추지 마라. evaluate 산출물이 뒷받침하는
부분 결과는 "Unresolved Items"에 불확실성을 기록한다.
미완료 작업이 있으면 호스트가 제공한 `publicationNotice`와 `uncoveredFiles`를 그대로
보고서에 포함하라. 부분 분석 결과를 전체 분석 완료로 표현하지 마라.

## 규칙

1. evaluate 산출물과 표준 Finding 원장에 존재하는 내용만 보고한다.
2. 각 Finding의 표준 Finding ID literal, 파일·줄 인용, 판정, 심각도, confidence, 영향,
   보완책, 표준 매핑을 보존한다.
3. `abstain`/`escalate`와 미해결 전제는 숨기거나 확정 사실로 바꾸지 않는다.
4. 중복 Finding은 근본 원인 기준으로 합치되 증거 위치를 잃지 않는다.
5. 새 Finding을 만들지 않는다. 따라서 `metrics.findingCount`는 0이어야 한다.
6. 계약에 명시된 draft만 쓰고 마지막 응답은 phase JSON schema를 따른다.

요약의 확신 수준은 본문의 증거 수준을 넘을 수 없다. 독자가 검증 가능한 사실과 권고,
미해결 위험을 명확히 구분할 수 있어야 한다.
소스에 있는 테스트의 기대값을 실제로 통과한 테스트나 관측한 HTTP 응답으로 표현하지 않는다.
실행 영수증이 없는 경우 정적 검토라고 명시하고, 조회·JOIN의 실제 반환 대상과 배포 전제를
보존한다. 개별 finding의 과장된 범위를 포괄적인 한계 문장 하나로 상쇄하지 않는다.

## 독립 원인 수와 관찰 수

호스트 입력의 vulnerabilityInventory를 기준으로 독립 취약점 수를 보고한다.
acceptedRecordCount와 기존 severityDistribution은 채택 기록 기준이며 취약점 개수로 바꾸어 부르지 않는다.
independentVulnerabilityCount가 null이면 '독립 원인 분류 미완료'로 표시한다. 0이나 채택 건수로 대체하지 않는다.
관찰은 별도 집계하고, 동일 원인의 여러 Finding은 causes의 findingIds/corroboratingFindingIds로 추적한다.
보강된 영향·전제·근거를 그룹 요약에 보존하되 supersededFindingIds의 폐기된 주장은 포함하지 않는다.
독립 심각도 분포는 independentSeverityDistribution을 사용한다. 이 값은 검토된 원인 그룹의 최대 심각도 요약이며
모델 판정 자체의 정확성을 증명하지 않는다. 챌린지 대응률과 취약점 Precision/Recall/F1을 혼동하지 않는다.
