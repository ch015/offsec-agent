---
phases: [va, verify, pentest, converge, report]
---
# A1: 인증 아키텍처 (Authentication Architecture)

```yaml
Core_Architecture_Questions:
  - "인증은 어떻게 설계되어 있는가?"
  - "단일 시행 지점인가, 분산되어 있는가?"
  - "우회 가능한 경로가 존재하는가?"

Review_Perspectives:

  Cross_Cutting:
    Credential_Exposure_Boundary:
      question: |
        "자격 증명의 접근 경계(Access Boundary)와
         공격자의 도달 경계(Reach Boundary)가
         겹치는 영역이 존재하는가?"
      methodology: |
        1. 자격 증명이 저장/전달되는 모든 위치를 코드에서 식별한다.
           (쿠키, 메모리, 워커, 로컬 스토리지, 키체인 등 — 추측 금지)
        2. 각 위치의 접근 가능 주체를 열거한다.
           (메인 스레드 JS, 서비스 워커, 서버, 네이티브 앱, 제3자 스크립트 등)
        3. 해당 환경에서 현실적 공격 벡터의 도달 범위를 열거한다.
           (XSS, 네트워크 스니핑, 악성 확장, 물리적 접근 등)
        4. 접근 주체 ∩ 공격 도달 범위를 평가한다.
           - 교집합 ≠ ∅ → Finding 후보
           - 교집합 = ∅ → Verified Safe (증거 기록)
           - 저장 위치 식별 불가 → Unverified (미적용 시 영향 기술)

  Backend:
    Auth_Enforcement_Point:
      question: "인증은 어디서 수행되는가?"
      review: |
        - 미들웨어에서 중앙 수행인가, 라우트 핸들러에 분산되어 있는가?
        - 모든 상태 변경 경로(POST/PUT/PATCH/DELETE)가 이 시행 지점을 통과하는가?
        - 미들웨어가 특정 경로를 면제하는 로직이 있는가? (opt-out 방식인가?)

    E2E_Request_Flow_Tracing:
      question: "요청이 최종 실행 지점까지 도달할 때, 각 홉에서 어떤 인증이 수행되는가?"
      methodology: |
        멀티-홉 아키텍처(Gateway→Proxy→Module, API Gateway→Lambda 등)에서
        인증이 어느 홉에서 실제로 시행되는지 끝까지 추적한다:
        1. 요청 엔트리포인트에서 최종 비즈니스 로직 실행까지
           모든 프록시/게이트웨이/미들웨어 홉을 식별한다.
        2. 각 홉에서 확인:
           a. 인증/인가 미들웨어 유무와 종류
              (필수 인증 vs optional 인증 vs 인증 없음)
           b. 요청 포워딩 방식:
              - 동기 프록시: 업스트림 응답을 그대로 반환
              - fire-and-forget: 즉시 2xx 반환, 업스트림 비동기 처리
              - 큐/이벤트 기반: 메시지 발행 후 ACK 반환
           c. 인증 컨텍스트 전파 방식:
              - req.account, x-account-id 헤더 등이 다음 홉으로 전달되는가?
              - 전달되지 않으면 다음 홉에서 인증 판단이 불가능
        3. 특히 다음 패턴에서 인증 착시(Auth Illusion)를 식별:
           - Gateway에 optional 인증 + fire-and-forget → 클라이언트에 202 반환
             → Module에서 실제 인증 검증 → 401 반환하나 클라이언트는 모름
           - 이 경우 "비인증 접근 가능"은 오탐이며
             실제 위험은 "Blind Accept 패턴"(정보성)이다.
        4. 최종 판정:
           - 모든 홉에 인증 없음 → 진짜 비인증 취약점
           - Gateway에 없으나 Module에 있음 → Blind Accept (정보성)
           - Gateway에 optional, Module에 필수 → 정상 (인증 컨텍스트 전파 확인)

    Service_Client_Usage:
      question: "특권 클라이언트가 호출자 인증 없이 사용되는가?"
      review: |
        - Admin SDK, service_role 등 특권 클라이언트가 호출자 인증 없는 API에서 사용되는가?
        - 이것은 실제 보안 감사에서 발견되는 #1 공격 벡터

    Credential_Lifecycle:
      question: "자격 증명의 전체 생명주기가 안전한가?"
      methodology: |
        인증에 사용되는 모든 자격 증명(세션 토큰, JWT, API 키, 리프레시 토큰 등)에 대해
        아래 각 생명주기 단계를 추적하고 각 단계의 보호 수준을 평가:
        1. 생성(Generation): 토큰/세션 생성 위치와 방법
        2. 저장(Storage): 클라이언트/서버에서 토큰이 저장되는 매체와 보안 속성
        3. 전송(Transmission): 네트워크를 통한 토큰 전송 방법
        4. 갱신(Renewal): 토큰 리프레시/갱신 메커니즘
        5. 폐기(Disposal): 로그아웃/만료 시 토큰 제거

  Frontend:
    Route_Protection:
      question: "라우트 보호는 어디서 수행되는가?"
      review: |
        - 서버 미들웨어에서 수행되는가?
        - 클라이언트 측 리다이렉트로만 보호되는가?

  BaaS_DB:
    Role_Separation:
      question: "인증/비인증 역할이 구분되는가?"
      review: |
        - authenticated와 anon 역할의 권한이 적절히 분리되어 있는가?
        - anon 역할에 불필요한 읽기/쓰기 권한이 있는가?

  Web3:
    Signature_Verification:
      question: "지갑 서명 검증이 일관되게 수행되는가?"
      review: |
        - 모든 지갑 관련 작업에 서명 검증이 있는가?

  Mobile:
    Credential_Storage:
      question: "인증 자격 증명이 플랫폼 보안 저장소에 저장되는가?"
      methodology: |
        토큰/시크릿 저장 코드를 추적하여 저장 매체를 분석:
        1. 안전한 저장소 사용 여부:
           - iOS: Keychain Services 사용하는가?
           - Android: EncryptedSharedPreferences 또는 Android Keystore 사용하는가?
        2. 안전하지 않은 저장소에 자격 증명이 저장되는가?
           - AsyncStorage, SharedPreferences(비암호화), UserDefaults, 로컬 파일
        3. 자격 증명 저장 시 접근 제어 속성이 설정되는가?
           - iOS: kSecAttrAccessible 설정 (잠금 해제 시에만 접근 등)
           - Android: setUserAuthenticationRequired 설정

    Biometric_Authentication:
      question: "생체 인증이 안전하게 구현되는가?"
      review: |
        - 생체 인증이 서버 인증을 대체하는가, 보조하는가?
        - 생체 인증 결과가 로컬 boolean 체크만인가,
          암호화 키 해제(Keychain/Keystore 바인딩)와 연결되는가?
        - 생체 인증 실패 시 폴백이 PIN/패스워드인가, 무제한 재시도가 가능한가?

  SDK:
    Credential_Handling:
      question: "SDK가 개발자로부터 받은 자격 증명을 안전하게 관리하는가?"
      methodology: |
        SDK 초기화 및 인증 흐름을 추적:
        1. 자격 증명 수신: SDK.init(apiKey, secret) 등 초기화 시
           자격 증명을 어떤 형태로 받는가? (문자열, 설정 객체, 파일 경로)
        2. 메모리 내 보관: 수신된 자격 증명이 메모리에서
           어떻게 보관되는가? (전역 변수, 싱글톤 프로퍼티, 클로저)
           - 불변(immutable) 참조인가, 외부에서 읽기/수정 가능한가?
        3. 전송 시 보호: 백엔드 요청에 자격 증명을 포함할 때
           HTTPS를 강제하는가? 헤더/쿼리스트링 중 어디에 포함하는가?
        4. 로그/에러 노출: 자격 증명이 로그, 에러 메시지,
           스택 트레이스, toString() 출력에 포함되는 경로가 있는가?
        5. 해제 시 정리: SDK 해제(destroy/dispose) 시
           자격 증명이 메모리에서 제거되는가?

    Auth_Flow_Delegation:
      question: "SDK가 인증 흐름을 안전하게 위임하는가?"
      methodology: |
        SDK가 OAuth, SIWE 등 인증 프로토콜을 구현하는 경우:
        1. state/nonce 파라미터를 생성하고 검증하는가?
        2. redirect URI 검증이 있는가?
        3. 토큰 갱신(refresh) 로직이 레이스 컨디션에 안전한가?
        4. 토큰 저장 시 플랫폼 보안 저장소를 사용하는가?

  Batch_Worker:
    Job_Authentication:
      question: "배치/워커 작업의 인증이 적절한가?"
      methodology: |
        배치/워커 서비스의 인증 경로를 추적:
        1. 작업 큐(SQS, RabbitMQ, Redis, Kafka 등)에서 메시지를 소비할 때
           메시지 발신자 인증이 수행되는가?
        2. 워커가 내부 API를 호출할 때 사용하는 자격 증명의 범위가 최소인가?
        3. 크론/스케줄러가 직접 호출하는 엔드포인트에 인증이 있는가?
           (내부 네트워크라도 인증 필요)
        4. 워커 간 통신 시 mTLS/서비스 메시 인증이 적용되는가?

    Job_Credential_Isolation:
      question: "배치 작업별 자격 증명이 격리되는가?"
      review: |
        - 모든 배치 작업이 동일한 서비스 계정/API 키를 공유하는가?
        - 작업 유형별(결제 처리, 데이터 동기화, 알림 발송 등) 권한이 분리되는가?
        - 장기 실행 자격 증명(static API key)이 단기 토큰으로 교체 가능한가?

  LLM_AI:
    LLM_API_Key_Boundary:
      question: "LLM API 키가 적절한 경계에서 관리되는가?"
      methodology: |
        LLM 통합의 인증 경로를 추적:
        1. LLM API 호출이 서버 사이드에서만 수행되는가?
        2. 프론트엔드/클라이언트에 LLM API 키가 노출되는 경로가 있는가?
        3. 프록시 서버를 통한 LLM 호출 시 사용자 인증이 수행되는가?
        4. 멀티 테넌트 환경에서 테넌트별 LLM API 키가 격리되는가?

  # ─────────────────────────────────────────────────────────────
  # OAuth / OIDC Flow Integrity — 고급 공격 방어 (P2-2)
  # ─────────────────────────────────────────────────────────────
  OAuth_OIDC_Flow:
    Authorization_Code_Flow_Hardening:
      question: "Authorization Code Flow의 각 보호 메커니즘이 모두 시행되는가?"
      methodology: |
        Authorization Code Grant / OIDC Authentication Request를 사용하는
        경로에서 다음을 모두 확인한다:

        1. state 파라미터:
           - 난수로 생성되는가? (Math.random() 금지, crypto.randomBytes/getRandomValues)
           - 최소 128bit 엔트로피?
           - 세션/쿠키에 바인딩되어 callback에서 정확히 재대조되는가?
           - 타이밍-세이프 비교인가?

        2. nonce 파라미터 (OIDC):
           - ID token의 nonce claim과 요청 시 nonce가 일치하는가?
           - 재사용이 차단되는가? (replay defense)

        3. PKCE (RFC 7636):
           - code_verifier는 43~128자 랜덤인가?
           - code_challenge_method = S256 (plain 금지)?
           - 모바일/SPA뿐 아니라 confidential client도 적용되는가?

        4. redirect_uri 엄격 매칭:
           - 사전 등록된 URI와 정확 매칭(prefix/wildcard 금지)?
           - http:// localhost 예외가 프로덕션에서 비활성화되는가?
           - fragment/query parameter를 포함한 매칭 규칙이 명확한가?

        5. issuer/audience 검증:
           - ID token의 iss가 IdP discovery의 issuer와 일치하는가?
           - aud가 자신의 client_id와 일치하는가?
           - 다중 IdP 지원 시 iss별 키 세트가 분리되는가?
      anti_patterns:
        - "state를 서버 세션과 무관한 localStorage/sessionStorage에 저장"
        - "state를 timestamp로 생성 (충분한 엔트로피 아님)"
        - "redirect_uri 매칭을 startsWith로 구현 (evil.com/?r=https://app.com 우회)"
        - "issuer 검증 누락 → IdP confusion 공격"
      references: [CWE-352, CWE-1275, OWASP-A07]

    JWT_Verification_Depth:
      question: "JWT/JWS 검증이 헤더 조작·키 오기·타이밍 취약점을 모두 방어하는가?"
      methodology: |
        토큰 검증 함수에서 다음을 모두 확인한다:

        1. 알고리즘 고정:
           - 검증 시 허용 알고리즘이 **정적 allowlist**로 하드코딩되어 있는가?
           - 토큰의 `alg` 헤더를 그대로 사용하지 않는가?
           - alg: "none" 수용 경로가 0인가? (특히 일부 라이브러리의 `decode()`
             vs `verify()` 혼동)

        2. HS/RS 혼동 차단:
           - RS256으로 발급된 토큰을 HS256으로 검증 시 공개키가 HMAC 키로
             해석되어 서명 위조 가능 — 알고리즘별 키 타입 강제.

        3. kid 헤더 주입:
           - `kid`를 파일 경로/SQL/RCE에 사용하지 않는가?
           - 미리 등록된 key id의 allowlist에서만 조회하는가?

        4. jku (JWK Set URL) 조작:
           - `jku` 헤더로 외부 URL을 허용하지 않거나, 미리 등록된 jwks_uri
             allowlist만 fetch하는가?
           - fetch된 JWKS가 SSRF/redirect로 내부로 우회하지 않는가?

        5. 클레임 검증:
           - exp/nbf/iat를 모두 검증하고 시계 편차(leeway)가 합리적인가?
           - sub/iss/aud/azp를 모두 검증하는가?

        6. 타이밍-세이프 비교:
           - 서명 비교가 `crypto.timingSafeEqual`/`hmac.compare_digest`인가?

        7. 키 로테이션:
           - 여러 키를 동시 수용하는 기간이 있는가?
           - 폐기된 키를 명시적으로 제거하는 프로세스가 있는가?
      anti_patterns:
        - "jwt.decode(token) 를 검증 대신 사용 (서명 체크 안 함)"
        - "토큰 헤더의 alg를 그대로 verify 옵션에 전달"
        - "HS 키가 대칭키 하드코딩으로 소스코드에 존재"
        - "jwks_uri를 환경변수로 받되 검증 없이 fetch"
      references: [CWE-347, CWE-290, CWE-327]

    Session_Fixation_And_Logout:
      question: "로그인 전후 세션 식별자 교체 / 로그아웃 서버측 무효화가 수행되는가?"
      methodology: |
        1. 로그인 성공 직후 기존 세션 ID를 버리고 새 ID를 발급하는가?
           (Session Fixation 방어, CWE-384)
        2. 로그아웃 시 서버측 세션 저장소에서 즉시 파기되는가?
           (localStorage만 지우는 경우 취약)
        3. refresh token rotation 시 이전 토큰을 블랙리스트 또는 one-time-use로
           관리하는가? 재사용 감지 시 전체 세션 체인을 무효화하는가?
      references: [CWE-384, CWE-613]

Representative_Anti_Patterns:
  - "인증이 라우트 핸들러에 분산 → 새 API 추가 시 누락"
  - "미들웨어가 특정 경로 면제(opt-out) → 새 API가 기본 비인증"
  - "서비스 클라이언트가 호출자 인증 없이 사용 → 비인증 관리자 접근"
  - "인증 토큰 저장 매체에 보안 속성 미설정 → 토큰 탈취 가능"
  - "자격 증명이 AsyncStorage/SharedPreferences 등 비암호화 저장소에 저장"
  - "생체 인증이 로컬 boolean 체크만 → 후킹으로 우회 가능"
  - "Gateway에 optional 인증 + fire-and-forget → 클라이언트에 성공 응답, Module에서 실제 거부 (Blind Accept)"
  - "멀티-홉에서 Gateway만 분석하고 최종 Module의 인증 로직 미확인 → 오탐 발생"

Representative_Healthy_Patterns:
  - "단일 인증 미들웨어가 모든 라우트를 강제 통과"
  - "명시적 allowlist로 예외 지정 (opt-out이 아닌 opt-in)"
  - "호출자 인증이 항상 서비스 클라이언트 사용에 선행"
  - "자격 증명 저장 매체의 보안 속성이 최대 보안으로 명시적 설정"
  - "생체 인증이 Keychain/Keystore 키 해제와 바인딩"
  - "모든 홉에서 인증 컨텍스트가 일관되게 전파되고 최종 핸들러에서 검증"
```
