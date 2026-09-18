# Red-team contract card

이 문서는 `redteam` phase의 강제 방법 카드다. v1에서는 정적 adversarial review만 하며
raw Bash·네트워크·라이브 조작을 수행하지 않는다.
상세 Red Team skill은 정적 검토 방법론으로만 적용하며 도구·범위·산출물 충돌 시 이 카드와 호스트 계약이 우선한다.

1. pentest 산출물과 대상 코드에서 공격 체인, 경계 전환, 탐지 공백, 복구 실패를 검토한다.
2. 호스트의 `00_iac_manifest.json`에서 applicability, file hash, classification, exclusions를 확인한다.
   `not_applicable`이면 IaC Finding을 만들지 않고 source-only 검토 범위를 명시한다.
3. 각 체인 단계를 코드 증거와 관측되지 않은 전제로 분리한다.
4. 방어 우회나 지속성은 실제 실행 성공처럼 쓰지 않는다. typed broker 관측이 없으면
   가설 또는 `unresolved`다.
5. 코드로 지지되거나 반증된 Finding만 `submit_finding`으로 제출한다.
6. 안전·승인 경계를 넘는 행동은 제안하거나 실행하지 않는다.
7. 계약 산출물만 쓰고 수락된 제출 수를 `metrics.findingCount`와 맞춘다.

가능성이 큰 한 경로에 고정되지 말고 최소 두 개의 경쟁 공격 경로를 비교한 뒤,
증거가 더 강한 경로와 남은 불확실성을 함께 기록한다.
