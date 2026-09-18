---
phases: [va, pentest, verify]
keywords: [e-commerce, payment, cart, order]
---
# Tier 2 Overlay: 커머스 (Commerce / E-Commerce)

> 상품/카탈로그, 장바구니, 주문, 할인/쿠폰 등 커머스 기능이 감지된 프로젝트에 적용.
> 결제 처리는 payment.md에서 커버 — 이 파일은 주문/상품 관리에 집중.

---

## A1 인증 (Authentication)

```yaml
Guest_vs_Auth_Boundary:
  question: "비회원(게스트) 주문과 회원 주문의 인증 경계가 명확한가?"
  trace: |
    1. 게스트 주문 시 세션 토큰이 발급되고 유효기간이 제한되는가?
    2. 게스트 세션에서 회원 전용 기능(저장 카드, 포인트 등)에 접근이 차단되는가?
    3. 게스트 주문 완료 후 주문 조회 시 인증 방식(이메일+주문번호 등)이 안전한가?
```

## A2 인가 (Authorization)

```yaml
Seller_Buyer_Isolation:
  question: "판매자/구매자 권한이 분리되는가?"
  trace: |
    1. 판매자가 다른 판매자의 상품/주문 데이터에 접근 불가능한가?
    2. 구매자가 판매자 전용 API(재고 수정, 가격 변경 등)를 호출할 수 없는가?
    3. 멀티 벤더 마켓플레이스에서 vendor_id 기반 격리가 강제되는가?
```

## A3 데이터흐름 (Data Flow)

```yaml
Order_State_Machine:
  question: "주문 상태 머신의 전이가 원자적이고 비정상 전이가 차단되는가?"
  trace: |
    1. 허용된 전이만 가능한가? (pending→paid→shipped→delivered→completed)
    2. 비정상 전이(cancelled→shipped)가 서버에서 거부되는가?
    3. 결제 완료↔주문 생성 간 트랜잭션 일관성이 보장되는가?
    4. 부분 배송/부분 환불 시 상태가 정확하게 추적되는가?

Price_Integrity:
  question: "주문 시점의 가격이 변조 불가능한가?"
  trace: |
    1. 클라이언트가 전송한 금액이 아닌 서버 DB의 최신 가격으로 계산되는가?
    2. 카트 담기 → 결제 사이에 가격이 변경된 경우 사용자에게 알림이 있는가?
    3. 할인 적용 후 최종 금액이 서버에서 재계산되는가?
```

## A4 IO (Input/Output Validation)

```yaml
Cart_Manipulation:
  question: "장바구니 데이터 변조가 방지되는가?"
  trace: |
    1. 수량에 음수/0/비정상 값 입력 시 서버에서 거부되는가?
    2. 최대 수량 제한이 있어 재고 초과 주문이 방지되는가?
    3. 상품 ID 변조로 다른 상품의 가격으로 결제가 가능한가?
    4. 쿠폰 코드 대입 공격(brute force)에 Rate Limit이 있는가?

Inventory_Race_Condition:
  question: "동시 주문 시 재고 초과 판매가 방지되는가?"
  trace: |
    1. 재고 차감이 원자적(DB 레벨 락 또는 CAS)으로 수행되는가?
    2. 결제 실패/취소 시 재고가 즉시 복구되는가?
    3. 타임아웃된 카트가 재고를 점유하지 않는가?
```

## A5 시크릿 (Secret Management)

```yaml
Order_Data_Protection:
  question: "주문/배송 데이터에 포함된 PII가 안전하게 관리되는가?"
  trace: |
    1. 배송 주소/전화번호가 암호화 저장되는가?
    2. 주문 내역 조회 API에서 다른 사용자의 PII가 노출되지 않는가?
    3. CS 담당자의 고객 PII 접근이 로깅/감사되는가?
```

## A6 의존성 (Dependencies)

```yaml
Discount_Coupon_Abuse:
  question: "할인/쿠폰 남용이 방지되는가?"
  trace: |
    1. 동일 쿠폰의 다중 사용이 서버에서 방지되는가?
    2. 쿠폰 코드가 예측 가능한 패턴(순번, 짧은 코드)이 아닌가?
    3. 할인 중첩(쿠폰+프로모션+포인트)의 최대 할인율 제한이 있는가?
    4. 환불 후 쿠폰이 재사용 가능한 상태로 복구되는가?
```

## A7 에러 (Error Handling)

```yaml
Partial_Order_Failure:
  question: "부분 주문 실패 시 일관성이 유지되는가?"
  trace: |
    1. 멀티 아이템 주문에서 일부 재고 부족 시 전체 롤백인가, 부분 처리인가?
    2. 결제 성공 후 주문 생성 실패 시 자동 환불이 트리거되는가?
    3. 외부 배송 API 장애 시 주문 상태가 적절히 관리되는가?
```

## A8 리소스 (Resource Consumption)

```yaml
Flash_Sale_Protection:
  question: "플래시 세일/한정판 판매 시 시스템이 보호되는가?"
  trace: |
    1. 급격한 트래픽 증가에 대한 Rate Limit이 있는가?
    2. 봇에 의한 자동 구매가 방지되는가? (CAPTCHA, device fingerprint)
    3. 동일 상품에 대한 동시 주문이 재고 이내로 제한되는가?
```
