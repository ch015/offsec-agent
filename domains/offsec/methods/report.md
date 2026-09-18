# Report contract card

이 문서는 `report` phase의 강제 방법 카드다. 리드는 최종 파일이 아니라
`07_security_report.draft.md`만 작성하며 발행 여부는 호스트 report gate가 결정한다.

## Gate 관계 (절대 규칙)

report gate(CH015)가 검증하는 산출물(classification, equivalence review, provenance 등)은
**converge phase가 이미 engagement 디렉터리에 생성**해둔 것이다. report phase에서 새로
YAML이나 보조 파일을 만들 필요가 전혀 없다. gate hook은 Write 시점에 engagement 디렉터리를
스캔해 기존 산출물을 자동 참조한다.

따라서 report phase의 임무는 **`07_security_report.draft.md` 1개만 작성**하는 것이다.

작성 가능한 근거가 있으면 먼저 초안을 작성하고 실제 발행 판정은 호스트에 맡긴다.
게이트 실패를 예상했다는 이유만으로 작업을 멈추거나, 게이트를 우회하기 위해 증거를 꾸미지 마라.
호스트는 증거·출처·검토 기록을 확인하고 실패 시 최종 발행을 거부한다.

보고서 안의 오류는 허용된 draft에서 수정한다. 상위 산출물이나 필수 근거가 실제로 없어
정당한 보고서를 만들 수 없으면 이유와 미해결 사항을 남기고 blocked를 반환한다.
상위 산출물을 임의로 수정하거나 발행 조건을 낮추지 마라. 근거가 허용하는 부분 결과는
불확실성을 "Unresolved Items"에 명시하고 검토하지 않은 범위를 완료로 표시하지 마라.

## 규칙

1. 수렴 산출물과 표준 Finding 원장에 존재하는 내용만 보고한다.
2. 각 Finding의 표준 Finding ID literal, 파일·줄 인용, 판정, 심각도, confidence, 영향,
   보완책, 표준 매핑을 보존한다. runtime evidence가 있으면 host HTTP receipt ID literal도 인용한다.
3. `abstain`/`escalate`와 미해결 전제는 숨기거나 확정 사실로 바꾸지 않는다.
4. 라이브로 검증하지 않은 POC나 공격 결과는 관측 성공으로 표현하지 않는다.
5. 중복 Finding은 근본 원인 기준으로 합치되 증거 위치를 잃지 않는다.
6. 새 Finding을 만들지 않는다. 따라서 `metrics.findingCount`는 0이어야 한다.
7. 계약에 명시된 draft만 쓰고 마지막 응답은 phase JSON schema를 따른다.

요약의 확신 수준은 본문의 증거 수준을 넘을 수 없다. 독자가 검증 가능한 사실과 권고,
미해결 위험을 명확히 구분할 수 있어야 한다.
