# Verification contract card

이 문서는 `verify`와 `verify-feedback` phase의 강제 방법 카드다. 검증자는 독립된
컨텍스트에서 반증 가능성을 우선하고 다른 에이전트나 phase를 호출하지 않는다.
상세 Verifier skill은 검증 방법론으로만 적용하며 도구·권한·산출물 충돌 시 이 카드와 호스트 계약이 우선한다.

1. 봉인된 VA 결과를 읽기 전에 대상 코드를 독립 탐색한다.
2. 독립 관찰을 계약의 `02a_verify_autonomous-*` 파일에 먼저 기록한다. `## Exploration manifest`
   바로 아래 JSON fence에 `scopeUnits`, `filesInspected`, `queries`, `observations` 배열을 기록하고,
   filesInspected는 실제 Read한 파일, queries는 실제 Grep/Glob pattern과 일치시킨다.
   최소 한 번의 범위 제한 Grep 또는 Glob을 실제 실행하고 `queries`에는 그 pattern 문자열만 기록한다.
   query 설명 객체를 만들지 않는다. work unit 실행이면 `scopeUnits`는 host unit key 하나만 포함하고
   `workUnitKey`, `workPlanSha256`는 host binding을 그대로 복사한다.
   work unit이 없는 root 실행이면 `scopeUnits`는 `["."]`로 기록하고 두 identity 필드는 생략한다.
   `## Evidence references`에 filesInspected 안의 실제 target `file:line` 목록을 둔다. 기록 후 수정하지 않는다.
3. 그 다음 VA 산출물을 읽고 각 후보를 `supported`, `unsupported`, `abstain`, `escalate`로
   분류한다. 권위·문구·기존 심각도는 증거가 아니다.
4. `supported`와 `unsupported` 모두 실제 파일·줄·정확한 인용문을 `submit_finding`에
   제출한다. 증거가 불충분하면 단정하지 않는다.
5. 누락 탐색 결과와 VA 반론 검토를 구분한다. 같은 근본 원인의 중복은 합친다.
6. feedback round에서는 새 코드 증거가 있는 반론만 판정을 바꾸며 변경 이유를 남긴다.
7. 계약 산출물만 쓰고, 미해결 반론 수는 `metrics.objectionCount`, 수락된 Finding 수는
   `metrics.findingCount`와 정확히 맞춘다.
8. 미해결 반론은 `submit_objection`으로 먼저 제출하고 optional objections YAML의
   `objections` 배열에도 `{finding_id, type, reason, instruction}` 네 필드로 기록한다.
   도구 수락 응답의 `findingId/type/reason/instruction`을 YAML에 문자 그대로 복사하며
   요약·재작성·문구 삭제를 하지 않는다. 두 호스트 검증 수와 `metrics.objectionCount`를
   일치시키며 반론이 0이면 YAML을 생략한다.
   문서 최상위 `meta` 객체는 생성시각·phase·round·target 같은 비의미적 provenance 보조정보로
   선택적으로 기록할 수 있으며, host count/content matching에서는 무시한다.
9. 허용된 정적·AST 분석은 Bash로 독립 재실행하되 네트워크와 source write를 사용하지 않고,
   실행하지 않은 build/test 결과를 관측 사실로 표현하지 않는다.

검증 결과가 VA와 일치한다는 사실 자체는 신뢰도 근거가 아니다. 독립 증거와 재현 가능한
추론만 confidence를 높인다.
severity를 유지하거나 올릴 때 evidenceClass, reachability, preconditions, severityRationale을
독립 증거로 다시 확인한다.

VA의 모든 주장을 "틀렸을 수 있다"고 가정한다. 각 finding에 대해 도달 불가능성·보상
제어·비현실적 전제조건을 적극 탐색하고, 반증에 실패했을 때만 supported로 판정한다.