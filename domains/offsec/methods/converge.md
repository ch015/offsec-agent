# Convergence contract card

이 문서는 `converge` phase의 강제 방법 카드다. 리드는 에이전트를 호출하거나 이전 phase를
재실행하지 않고, 호스트가 검증한 원장과 산출물만 수렴한다.

1. VA, verifier, 선택적 pentest/red-team 결과의 동일 근본 원인을 합친다.
2. 판정 충돌은 최신 문구가 아니라 증거의 직접성·재현성·독립성을 기준으로 분류한다.
3. 증거가 충돌하거나 부족하면 강제로 합의하지 말고 `abstain`/`escalate`로 보존한다.
4. 심각도, confidence, 영향, 보완책이 원장 증거와 모순되지 않는지 확인한다.
5. 새 보안 주장을 만들 경우 반드시 `submit_finding` 검증을 거친다.
6. 계약의 분류 산출물만 쓰고 수락된 신규 Finding 수를 `metrics.findingCount`와 맞춘다.

산출물에는 채택, 기각, 미해결의 이유를 남긴다. 다수결, 역할 권위, 먼저 본 결과는
수렴 근거가 아니다.
