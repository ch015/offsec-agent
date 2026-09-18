# Review contract card

이 문서는 `review` phase의 강제 방법 카드다. reviewer는 다른 에이전트나 phase를
호출하지 않고 analyzer 산출물만 검수한다.

## 검수 원칙

- 단순 인용문 일치가 아닌, 취약점의 **의미론적 유효성**을 검증한다.
- 각 finding에 대해: 증거 무결성 → 도달성/제어 흐름 → 전제조건 → 판정 순으로 진행한다.
- analyzer의 판단을 권위로 수용하지 않는다. 모든 주장을 "틀렸을 수 있다"고 가정한다.

## 검수 절차

1. `evidence[].path`를 `Read`로 열어 인용문 일치를 확인한다.
   불일치 시 `Grep`으로 올바른 위치를 탐색하여 보정한다.

2. 취약 지점(sink)에 도달하는 entry point/source를 식별하고, source→sink 간
   호출 경로·데이터 흐름·제어 흐름을 실제 코드에서 추적한다.
   경로상 sanitizer, guard, 인가 검사, 입력 검증, 보상 제어를 확인한다.

3. finding의 `preconditions`가 현실적인지 평가한다.

4. 판정을 부여한다:
   - **retained**: 증거 정확, 도달 가능, 보상 제어 없음
   - **corrected**: 증거/severity/분류를 보정 — `submit_finding`으로 재제출
   - **rejected**: 구체적 반증 증거로 false positive 확인. 단순 "증거 미발견"은 rejected가 아님
   - **inconclusive**: 도달성 판단 불가, 파일 접근 불가, 동적 실행 필요 — 미해결 위험으로 보존

5. 동일 근본 원인의 중복 finding을 통합하고 모든 증거 위치를 보존한다.

6. 코드 탐색 중 analyzer가 놓친 취약점을 발견하면 `submit_finding`으로 제출한다.

7. severity를 독립적으로 재평가한다:
   - CRITICAL/HIGH에는 비문서 evidenceClass + confirmed/plausible reachability + 전제조건 필요
   - 근거 부족 시 다운그레이드. 과소 평가 시 업그레이드 고려.

8. 계약 산출물만 쓰고 입력 finding 수 = retained + corrected + rejected + inconclusive
   (전수 검수 완전성)를 보장한다.

산출물에는 각 finding별 검수 결과, 검증 증거(코드 위치), 판정 사유를 남긴다.
