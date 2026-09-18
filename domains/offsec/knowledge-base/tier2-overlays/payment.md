---
phases: [va, pentest, verify]
keywords: [payment, pci, stripe, card]
---
# Tier 2 Overlay: 결제 플랫폼 (Payment Platform)

> 결제 처리 플랫폼이 감지된 프로젝트에 적용.
> PG 연동, 결제 상태 머신, FDS, 정산, Webhook, 멀티테넌트 결제 등.
> CROSS PAY Renewal 기획서(v3.4) 기반 실증 설계.

---

## A1 인증 (Authentication)

```yaml
Payment_API_Signature:
  question: "API key + HMAC-SHA256 서명 검증이 모든 결제 엔드포인트에 일관 적용되는가?"
  trace: |
    1. Secret Key 없이 API 호출이 가능한 엔드포인트가 있는가?
    2. 요청 서명 불일치 시 403이 반환되고 상세 원인이 노출되지 않는가?
    3. 서명 생성 시 타임스탬프가 포함되어 replay attack이 방지되는가?
    4. customer_id를 직접 검증하지 않는 설계에서, 서명 우회 시 타인 결제수단 접근이 가능한가?

Environment_Key_Isolation:
  question: "Sandbox/Live API 키가 환경 간 교차 사용 불가능한가?"
  trace: |
    1. test_ 프리픽스 키로 Live 게이트웨이 호출이 차단되는가?
    2. pk_live_ 키로 Sandbox 환경 접근이 차단되는가?
    3. 키 발급 시 환경(env) 필드가 DB에 명시적으로 기록되는가?
    4. Console에서 Live/Sandbox 전환 시 키가 혼용되지 않는가?

Wallet_Signature_Auth:
  question: "SIWE/TronLink 서명 검증이 replay attack에 안전한가?"
  trace: |
    1. 서버 생성 nonce가 1회성이고, 사용 후 즉시 무효화되는가?
    2. 서명 메시지에 만료 시간(expiration)이 포함되는가?
    3. chain-id가 검증되어 cross-chain replay가 불가능한가?
    4. TRON TronLink 서명 검증 라이브러리가 서버 사이드에서 실행되는가?

Business_Registration_Auth:
  question: "Console 온보딩의 사업자번호 인증에 우회 경로가 있는가?"
  trace: |
    1. 국세청 API 실시간 인증이 서버 사이드에서 수행되는가?
    2. 인증 성공 없이 Sandbox API 키 발급이 가능한 경로가 있는가?
    3. Biz Admin 반자동화 승인 프로세스에서 인증 결과가 변조 가능한가?
```

## A2 인가 (Authorization)

```yaml
Multi_Tenant_Isolation:
  question: "project_id 기반 namespace 격리가 모든 쿼리에서 강제되는가?"
  trace: |
    1. 모든 데이터 접근 쿼리에 project_id 필터가 일관적으로 적용되는가?
    2. customer_id가 project_id 없이 단독으로 사용되어 cross-tenant 접근이 가능한가?
       → 게임A의 user_123 ≠ 게임B의 user_123
    3. 저장 카드(토큰화)가 payer_uid + 고객사 + PG/merchant 계정별로 namespace 분리되는가?
    4. quotes 응답의 saved_tokens가 인증 주체와 payer_uid/project 바인딩을 서버에서 검증한 뒤 반환되는가?
    5. 블랙리스트 등록 주소의 결제+조회 차단이 global 범위에서 일관적인가?

Console_RBAC:
  question: "Console RBAC 3종(Owner/Admin/Viewer)이 API 레벨에서도 강제되는가?"
  trace: |
    1. Viewer 역할이 설정 변경 API를 호출할 수 없는가? (UI 숨기기만이 아닌 서버 검증)
    2. Admin 역할이 멤버 관리/정산 계좌 변경이 불가능한가? (Owner 전용)
    3. 마지막 Owner 삭제가 서버에서 방지되는가?
    4. 역할 변경/멤버 초대 시 이메일 알림이 발송되는가?

Admin_RBAC:
  question: "Admin RBAC 6종의 금액별 권한 분리가 서버에서 검증되는가?"
  trace: |
    1. CS Admin의 $50 이하 환불 처리와 Finance Admin의 $50 초과 환불 승인 경계가 서버에서 강제되는가?
    2. Risk Admin의 거래 보류/차단 권한이 다른 Admin 역할에 의해 우회 가능한가?
    3. Super Admin의 Admin 계정 생성/비활성화가 다른 역할에서 불가능한가?
    4. SSO + 2FA + IP 제한(사내망/VPN)이 모든 Admin 접근에 강제되는가?
```

## A3 데이터흐름 (Data Flow)

```yaml
Payment_State_Machine:
  question: "결제 상태 전이가 원자적이고 비정상 전이가 차단되는가?"
  trace: |
    1. 허용된 전이만 가능한가? (created→processing→succeeded→refund_requested→refunded)
    2. 비정상 전이(예: failed→succeeded, refunded→processing)가 서버에서 거부되는가?
    3. 동시 상태 전이 요청 시 race condition이 방지되는가? (DB 레벨 원자성)
    4. 모든 상태 전이에 타임스탬프와 사유가 기록되는가?
    5. 각 전이 시 Webhook이 발송되는가?

Grant_Award_Callback:
  question: "양방향 Callback에서 아이템 지급 완결성이 보장되는가?"
  trace: |
    1. payment.succeeded 시 고객사에 결제 상세(금액, 세금, 수수료, 상품)가 전달되는가?
    2. 고객사가 publisher_purchase_id를 미반환하면 지급 실패로 처리되는가?
    3. Callback 타임아웃/실패 시 결제 상태와 아이템 지급 상태 간 불일치가 발생할 수 있는가?
    4. 5회 재시도 모두 실패 시 Admin 알림 + Console 수동 재전송이 가능한가?

Exchange_Rate_Integrity:
  question: "환율 세션 lock이 전 구간에서 일관적인가?"
  trace: |
    1. 결제 세션 생성 시점 환율이 고정되어 세션 내 변동이 없는가?
    2. 환율 소스(Twelve Data API) 장애 시 마지막 유효 환율 사용 — stale 임계값이 있는가?
    3. 결제 표시 환율과 정산 환율(하나은행 월평균 기준매매율)이 명확히 구분되는가?
    4. 암호화폐(USDT) 5분 단위 갱신 중 세션 환율과 실제 환율 괴리가 허용 범위 내인가?

Data_Protection:
  question: "결제 데이터 보호가 규정에 부합하는가?"
  trace: |
    1. 전송: TLS 1.2+ 강제, 저장: AES-256 암호화가 일관 적용되는가?
    2. GDPR 열람 요청(10영업일) 경로에서 customer_id 외 PII 노출이 없는가?
    3. 법정 보관 기간(5년, 전자금융거래법/세법) 내 삭제 요청 거부 로직이 구현되는가?
    4. 결제 데이터 5년, 로그 1년 보관 기준이 시스템에서 강제되는가?

Quote_Payment_Method_Ordering:
  question: "quotes 응답의 결제수단 정렬/저장 토큰 매핑이 권한과 가용성 필터 이후에 수행되는가?"
  trace: |
    1. payer_uid + country + currency에 매핑된 마지막 결제수단을 우선 배치하기 전에, 해당 결제수단이 현재 quote에서 허용된 PG/국가/통화인지 검증되는가?
    2. fallback 결제수단 선택 시 마지막 결제수단 또는 저장 토큰이 필터를 우회해 삽입되지 않는가?
    3. payer_uid를 임의로 바꿔 타인의 마지막 결제수단 또는 saved_tokens metadata를 열람할 수 없는가?
    4. Worldpay saved_tokens는 ACTIVE 상태 등 결제 가능 상태만 응답되고, 다른 PG 응답에는 혼입되지 않는가?
    5. 정렬 로직은 UX 우선순위만 바꾸며 금액, 환율, 세금, gateway routing 결정에는 영향을 주지 않는가?
```

## A4 IO (Input/Output Validation)

```yaml
Idempotency_Control:
  question: "Idempotency Key 기반 중복 결제 방지가 올바른가?"
  trace: |
    1. 동일 merchant_order_id로 중복 요청 시 기존 세션이 반환되는가? (신규 생성 아닌지)
    2. Idempotency Key의 유효기간과 저장 방식이 race condition에 안전한가?
    3. 동시 요청(EC-F01-03)에서 정확히 하나의 세션만 생성되는가?

Amount_Validation:
  question: "결제 금액 입력이 안전하게 검증되는가?"
  trace: |
    1. amount에 음수/0/소수점 초과 정밀도 입력 시 명확한 에러가 반환되는가?
    2. 금액이 Decimal/정수로 처리되는가? (부동소수점 사용 시 정밀도 손실)
    3. currency에 지원하지 않는 통화 코드 입력 시 에러가 반환되는가?
    4. gateway_currency_mismatch: 요청 통화와 게이트웨이 지정 통화 불일치가 감지되는가?

Checkout_SDK_Security:
  question: "Checkout JS SDK의 iframe 보안이 충분한가?"
  trace: |
    1. iframe postMessage origin 검증: pay.crosspay.ai 외 origin이 무시되는가?
    2. 부모 페이지가 iframe 내 결제 데이터에 접근 불가능한가?
    3. SDK 스크립트 로딩이 50KB(gzipped) 이내이고 Subresource Integrity가 적용되는가?
    4. crossPay.open() 호출 시 sessionId 외 민감 파라미터가 노출되지 않는가?

Quote_Response_Schema_Validation:
  question: "quotes 응답에 추가된 saved_tokens 필드가 최소 노출 원칙으로 검증되는가?"
  trace: |
    1. saved_tokens에는 token 원문, cryptogram, CVV, 전체 PAN이 포함되지 않고 id/brand/masked_pan/expiry/status 등 허용 metadata만 포함되는가?
    2. masked_pan은 BIN + last4 범위를 초과해 노출하지 않는가?
    3. id가 전역 증가값이면 다른 API에서 저장 카드 열거/참조에 악용될 수 없는가?
    4. Worldpay 미지원 국가/통화/merchant 계정에서는 saved_tokens 필드가 비어 있거나 제거되는가?
    5. OpenAPI 스키마와 서버 응답이 일치하며, 클라이언트가 알 수 없는 saved_tokens 값을 결제 요청 파라미터로 재전송하지 않는가?

Wallet_Address_Validation:
  question: "지갑 주소 형식 검증이 올바른가?"
  trace: |
    1. ETH: 0x 프리픽스 + 40자 hex + 체크섬(EIP-55) 검증
    2. TRON: T 프리픽스 + Base58Check 검증
    3. 대소문자 혼용 주소가 소문자 정규화 후 저장/비교되는가?
    4. zero address 입력이 거부되는가?

Tax_Integration:
  question: "Avalara 세금 계산 연동의 입출력이 안전한가?"
  trace: |
    1. SalesOrder → SalesInvoice 2단계 흐름에서 중간 실패 시 세금 불일치가 발생하는가?
    2. billing_address의 국가 코드(ISO 3166-1 alpha-2)가 서버에서 검증되는가?
    3. 환불 시 ReturnInvoice가 호출되어 세금이 차감 반영되는가?
    4. Payletter/CROSS 계열 결제 시 Avalara 미호출이 올바르게 분기되는가?
```

## A5 시크릿 (Secret Management)

```yaml
API_Key_Security:
  question: "API 키 관리가 안전한가?"
  trace: |
    1. APIKey 엔티티의 secret_hash: 원문 미보관, 해시만 저장 확인
    2. API 키 즉시 폐기 시 진행 중 결제 세션에 영향이 없는가?
    3. 폐기된 키로의 호출이 즉시 401을 반환하는가? (캐시 지연 없이)
    4. 프로젝트별 독립 API 키 관리가 강제되는가?

PCI_DSS_Compliance:
  question: "카드 정보가 PCI DSS 기준에 부합하게 처리되는가?"
  trace: |
    1. 카드 원본 번호가 어디에도 평문 저장/로깅되지 않는가?
    2. 토큰화가 PG별 대체키(토큰)로 위임되는가? (CROSS PAY 직접 저장 불가)
    3. 저장 카드 삭제 요청 시 PG 측 토큰도 함께 무효화되는가?
    4. 12개월 미사용 저장 카드 자동 만료가 구현되는가?
    5. Worldpay token 원문이 API 응답, 프론트엔드 상태, 로그/분석 이벤트에 노출되지 않는가?
    6. saved_tokens metadata도 카드 데이터로 취급하여 접근 로그와 마스킹 정책이 적용되는가?

Worldpay_Saved_Token_Security:
  question: "Worldpay 저장 카드 토큰 기능을 자체 페이지에서 지원하기 전 보안성 검토가 완료되었는가?"
  trace: |
    1. 카드 저장/선택 UI는 보안 검토 전 CROSS PAY 페이지/SDK에 노출되지 않고 Worldpay hosted/service page 경계 안에 유지되는가?
    2. 서버가 보관하는 Worldpay token/reference는 암호화 저장되고, 로그/에러/트레이싱/analytics에서 마스킹되는가?
    3. token/reference가 payer_uid + project/customer + gateway/merchant 계정 + country/currency 범위에 바인딩되는가?
    4. 저장 카드 동의(consent), 삭제, 만료, status 동기화가 Worldpay와 서버 양쪽에서 일관되게 처리되는가?
    5. Card-on-file 사용 시 CIT/MIT 구분, SCA/3DS, recurring consent 요구사항이 계약/구현 레벨에서 확인되는가?
    6. 보안 검토가 완료되기 전에는 saved_tokens metadata를 결제 실행 파라미터로 받는 API가 활성화되지 않는가?

Webhook_Secret:
  question: "Webhook HMAC-SHA256 서명 키가 안전하게 관리되는가?"
  trace: |
    1. 서명 키 로테이션 메커니즘이 있는가?
    2. 고객사가 서명을 검증하지 않으면 경고가 표시되는가?
    3. PG별 게이트웨이 설정(API 키, 엔드포인트, 수수료율)이 암호화 저장되는가?
```

## A6 의존성 (Dependencies)

```yaml
Gateway_Resilience:
  question: "멀티 PG 게이트웨이 장애 대응이 충분한가?"
  trace: |
    1. 게이트웨이 헬스체크 주기적 실행 + 장애 시 자동 비활성화가 구현되는가?
    2. 특정 게이트웨이 장애 시 대체 수단 안내가 사용자에게 전달되는가?
    3. 모든 게이트웨이가 동일 어댑터 인터페이스를 구현하여 교체 가능한가?
    4. 신규 게이트웨이 추가 시 어댑터 구현만으로 무중단 통합이 가능한가?

External_API_Fallback:
  question: "외부 API 장애 시 fallback이 안전한가?"
  trace: |
    1. Twelve Data API(환율) 장애: 마지막 유효 환율 사용 — stale 임계값이 있는가?
    2. Avalara Tax API 장애: 세금 미적용 진행 + Admin 알림이 비즈니스적으로 수용 가능한가?
    3. 국세청 API 장애: Console 온보딩이 차단되는가, 우회되는가?
    4. 온체인 결제: RPC 노드 단일점 의존성이 있는가?
```

## A7 에러 (Error Handling)

```yaml
Webhook_Retry:
  question: "Webhook 전송 실패 시 재시도와 에스컬레이션이 구현되는가?"
  trace: |
    1. 지수 백오프(1→5→30→120→720분, 최대 5회)가 구현되는가?
    2. 5회 실패 시 Admin 알림 + Console 수동 재전송이 가능한가?
    3. Webhook 전송 이력(URL, status_code, attempts)이 기록되고 Console에서 조회 가능한가?
    4. 결제 상태 변경 후 5초 이내 Webhook 발송이 보장되는가?

Onchain_Confirmation_Race:
  question: "온체인 트랜잭션 지연/도착 시 이중 처리가 방지되는가?"
  trace: |
    1. 60분 미확인 시 결제 실패 처리 후, 뒤늦은 온체인 confirm 도착 시 어떻게 처리되는가?
    2. 실패 처리된 세션에 대해 이미 온체인 전송된 자금의 환불 경로가 있는가?
    3. 세션 만료(created 1시간, processing 10~60분) 직전 결제 완료 도착 시 race condition 처리

Blacklist_Fail_Open:
  question: "블랙리스트 조회 장애 시 Fail-open 정책의 보상 통제가 충분한가?"
  trace: |
    1. Fail-open(차단 미적용) 시 Admin 알림이 즉시 발송되는가?
    2. Fail-open 기간 동안 처리된 결제가 사후 검증 대상에 포함되는가?
    3. 블랙리스트 서비스 복구 후 Fail-open 기간 거래 일괄 검증이 가능한가?

Refund_Failure:
  question: "환불 실패(refund_failed) 시 에스컬레이션 경로가 있는가?"
  trace: |
    1. 환불 실패 재시도 메커니즘과 최대 재시도 횟수가 정의되는가?
    2. 이미 정산된 건의 환불은 익월 정산에서 차감되는가?
    3. USDT 환불 시 결제 시점 USDT 금액 기준 반환이 올바르게 구현되는가?
```

## A8 리소스 (Resource Consumption)

```yaml
FDS_Rules:
  question: "FDS 규칙 R-01~R-08이 서버 사이드에서 일관 강제되는가?"
  trace: |
    1. R-01(동일 IP 10건/분): 분산 IP 사용 시 탐지 가능한 보조 시그널이 있는가?
    2. R-02(일 결제 한도): 한도 기준이 customer_id + project_id 조합인가?
    3. R-03(비정상 금액 10배): '평균' 기준 기간과 계산 방식이 조작 불가능한가?
    4. R-04(동일 카드 다수 고객사 3개/일): cross-project 집계가 올바르게 구현되는가?
    5. R-05(연속 실패 후 재시도 5회/10분): 카운터 리셋 조건은 무엇인가?
    6. R-07(고액 결제 후 24시간 내 환불): 금액 기준이 통화별로 적절한가?
    7. R-08(환불 비율 ≥30%/30일): 집계 윈도우가 rolling인가 calendar인가?
    8. FDS 탐지 시 '2FA 추가인증' 정책에서 2FA 우회 시 fallback이 있는가?

Session_Timeout:
  question: "세션 타임아웃이 서버에서 강제되는가?"
  trace: |
    1. created 상태 1시간, processing 상태 게이트웨이별 타임아웃이 서버에서 강제되는가?
    2. 클라이언트 타이머에만 의존하지 않는가?
    3. System Background 만료 처리 + Webhook(payment.expired) 발송이 확실한가?
    4. 만료 직전 결제 완료 도착 시 race condition 처리가 되는가?

Blacklist_Cache_Latency:
  question: "블랙리스트 캐시의 등록↔반영 지연이 허용 범위 내인가?"
  trace: |
    1. 캐시 TTL이 적절한가? (너무 길면 등록 후에도 결제 통과)
    2. 등록 즉시 캐시 무효화(cache invalidation)가 수행되는가?
    3. 캐시 미스 시 DB 조회 latency가 결제 세션 생성 SLA(P95 < 500ms)에 영향을 주는가?
```
