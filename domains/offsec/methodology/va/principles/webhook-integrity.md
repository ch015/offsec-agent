# Webhook 무결성 원칙 (Principles Module)

> 인바운드 Webhook을 수신하는 모든 시스템에 적용되는 보편 원칙.
> 적용 대상: Stripe, GitHub, Slack, Twilio, SendGrid, 커스텀 webhook 등.

---

## 적용 조건

```yaml
Trigger: "Phase 0에서 webhook endpoint 또는 서명 검증 패턴이 감지된 경우"
```

## 핵심 원칙

```yaml
Principles:
  Signature_Verification: |
    "인바운드 webhook은 반드시 서명(HMAC/RSA/Ed25519)으로 검증해야 한다.
     서명 없이 수신하면 위조된 요청으로 상태를 변경할 수 있다."

  Raw_Body_Integrity: |
    "서명 검증은 원본(raw) 요청 바디에 대해 수행해야 한다.
     JSON.parse 후 재직렬화하면 바이트 순서/공백이 변경되어 서명이 무효화된다."

  Timing_Safe_Comparison: |
    "서명 비교는 timing-safe(constant-time) 함수를 사용해야 한다.
     일반 문자열 비교는 타이밍 사이드 채널로 서명을 한 바이트씩 추측 가능하다."

  Replay_Prevention: |
    "타임스탬프 검증(≤5분)과 이벤트 ID 중복 검사로 재전송 공격을 방지해야 한다."

  Idempotency: |
    "webhook 처리는 멱등(idempotent)해야 한다.
     동일 이벤트를 재수신해도 부작용(이중 결제, 중복 생성)이 없어야 한다."
```

## 심층 질문

```yaml
심층_질문:
  - "webhook이 서명/HMAC/OAuth token 중 하나로 검증되는가?"
  - "서명 검증이 raw body에 대해 수행되는가? (JSON parse → re-stringify 하지 않는가?)"
  - "서명 비교가 timing-safe 함수를 사용하는가?"
  - "타임스탬프 허용 범위가 합리적인가? (≤5분)"
  - "이벤트 ID를 저장하여 재전송을 무시하는가? (idempotency key)"
  - "webhook secret 로테이션 기간에 신구 secret을 동시 수용하는가?"
  - "webhook 처리가 비동기로 200 즉시 반환 후 백그라운드 처리하는가?"

놓치기_쉬운:
  공유_시크릿: |
    여러 webhook endpoint가 동일 secret을 공유하면 한 곳 유출로 전체 노출.
  비멱등_처리: |
    재전송 시 결제 이중 처리, 알림 중복 발송, 상태 이중 변경.
```
