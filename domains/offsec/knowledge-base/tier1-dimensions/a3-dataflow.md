---
phases: [va, verify, pentest, converge, report]
---
# A3: 데이터 흐름과 신뢰 경계 (Data Flow and Trust Boundary)

```yaml
Core_Architecture_Questions:
  - "데이터가 시스템을 흐르면서 신뢰 경계를 올바르게 통과하는가?"
  - "어떤 데이터가 어떤 레이어에 노출되는가?"
  - "레이어 간 데이터 전달 시 민감 정보가 유출되는가?"

Review_Perspectives:

  Backend:
    Response_Data_Control:
      question: "API 응답에 필요 이상의 데이터가 포함되는가?"
      methodology: |
        각 API 엔드포인트의 DB 쿼리 → 응답 직렬화 경로를 추적:
        1. DB 쿼리가 필요한 컬럼만 선택하는가, 전부 가져오는가?
        2. 응답 변환(DTO/시리얼라이저)이 있는가, 쿼리 결과를 그대로 반환하는가?
        3. 반환 데이터에 포함되는 것:
           - 비밀번호 해시, 내부 메모 등 내부 전용 필드
           - 다른 사용자의 PII
           - 관리자 전용 필드
           - 시크릿, 토큰, API 키

    Request_Data_Binding:
      question: "요청 데이터가 필터링 없이 내부 모델에 바인딩되는가?"
      methodology: |
        각 상태 변경 API의 요청 본문 → DB/모델 레코드 경로를 추적:
        1. 요청 본문이 allowlist/DTO 필터링 없이 직접 저장되는가? (Mass Assignment)
        2. 민감 필드(역할, 잔액, 인증 상태 등)가 클라이언트 입력으로 설정 가능한가?

    State_Transition_Integrity:
      question: "상태 전이가 서버에서 검증되는가?"
      review: |
        - 클라이언트가 상태 필드를 직접 지정할 수 있는가?
        - 금융/재고 컨텍스트에서 TOCTOU(읽기→검증→쓰기 갭) 취약 구조가 있는가?
        - 동시성 제어(DB 트랜잭션, 행 잠금)가 적용되는가?

    Business_Logic_Abuse_Cases:
      question: "정상 기능을 규칙 위반으로 악용하는 경로가 있는가? (설계상 유효한 요청의 오용)"
      review: |
        - 워크플로 스킵: 결제/승인/검증 단계를 건너뛰고 최종 상태(주문완료·권한부여)에 직접 도달 가능한가?
        - 수량/금액 경계: 음수·0·과대 수량, 통화 반올림, 클라이언트 가격 변조가 서버에서 거부되는가?
        - 쿠폰/프로모션 스태킹: 할인·포인트·리퍼럴 중복 적용, 재사용 한도 우회가 가능한가?
        - Idempotency/재생: 동일 요청 재전송(더블 스펜드), 콜백/웹훅 재생에 대한 방어가 있는가?
        - 소유권 경계: 자기 자원만 대상이어야 할 액션에 타인 식별자 주입이 가능한가? (A2 BOLA와 연계)
      note: |
        코드 취약점이 아니라 "유효한 요청의 오용"이므로 taint/AST 자동 분석으로는 잡히지 않는다.
        반드시 상태 전이 흐름 단위로 수기 점검하고, 발견 시 A3(+연계 A2/A8)로 분류한다.

    HTTP_Request_Smuggling_Boundary:
      question: "프론트(WAF/CDN/Reverse Proxy)와 백엔드가 요청 경계를 동일하게
                 해석하는가? (CWE-444)"
      methodology: |
        HTTP/1.1 환경에서 Content-Length와 Transfer-Encoding의 해석이 프론트와
        백엔드에서 달라지면 한 요청이 다음 요청의 일부로 흡수되어 인증·인가·
        캐시 경계를 우회하게 된다. 다음을 확인한다:

        1. 배포 토폴로지 파악:
           - 프론트 프록시(AWS ALB, Cloudflare, Nginx, HAProxy, Envoy)와
             백엔드(Node, Go, Java, Python WSGI/ASGI)의 조합
           - 각 레이어가 HTTP/1.1, HTTP/2, HTTP/3 중 어느 것을 사용하고
             downgrade가 어디서 일어나는가?

        2. 경계 해석 동일성:
           - Content-Length와 Transfer-Encoding이 모두 존재할 때 어느 쪽을
             우선하는지 양쪽이 동일한가?
           - Transfer-Encoding: chunked 외 임의 값(xchunked, chunked\r\nXX)을
             어떻게 처리하는가?
           - 헤더 이름에 공백/탭/유니코드가 섞이면 어떻게 처리되는가?

        3. HTTP/2 → HTTP/1.1 downgrade 취약점:
           - 프론트가 HTTP/2로 받고 백엔드에 HTTP/1.1로 포워딩한다면, 헤더
             주입(CRLF in pseudo-header)으로 smuggled 요청을 끼워 넣을 수 있는가?
           - h2c upgrade 요청이 조작 가능한가?

        4. WebSocket/SSE 관련:
           - Upgrade/Connection 헤더의 재작성 규칙이 정의되어 있는가?

        5. 애플리케이션 레벨 영향:
           - 인증 경로에 smuggled 요청이 들어가면 내부 사용자 토큰을 탈취할
             수 있는가? (cache deception과 결합)
      references: [CWE-444, CWE-113]

    Upstream_Response_Reflection:
      question: "프록시/게이트웨이가 업스트림 응답을 클라이언트에 무검증 반영하는가?"
      methodology: |
        애플리케이션이 다른 서비스(내부 모듈, 외부 API, 마이크로서비스)의
        응답을 중계하는 모든 코드 경로를 추적한다.
        업스트림 응답도 비신뢰 입력으로 취급해야 한다:

        1. 응답 헤더 패스스루:
           - 업스트림 응답 헤더를 전부 클라이언트에 복사하는가? (denylist vs allowlist)
           - 위험 헤더가 필터링 없이 통과하는가?
             Set-Cookie: 게이트웨이 도메인에 세션 고정/쿠키 주입
             Location: 오픈 리다이렉트
             Access-Control-*: CORS 정책 우회
             Content-Type: text/html 반영 시 XSS
             Cache-Control: 민감 응답의 의도치 않은 캐싱
           - 헤더 전달 방식이 denylist(특정 헤더만 제외)인가 allowlist(허용 헤더만 통과)인가?
             → denylist는 신규 위험 헤더를 놓치므로 allowlist가 안전

        2. 응답 바디 반영:
           - 업스트림 응답 바디가 Content-Type 검증 없이 그대로 클라이언트에 전달되는가?
           - 업스트림이 text/html을 반환하면 게이트웨이 도메인에서 XSS가 가능한가?
           - 에러 응답에 내부 URL, 스택 트레이스, 디버그 정보가 포함되는가?

        3. 상태 코드 반영:
           - 업스트림의 3xx 리다이렉트가 그대로 클라이언트에 전달되는가?
           - 업스트림 5xx 에러 바디에 내부 정보가 포함될 때 클라이언트에 노출되는가?

        4. 프록시 아키텍처 특수 패턴:
           - API 게이트웨이, BFF, 리버스 프록시, 사이드카 등
             요청을 중계하는 모든 패턴에 적용
           - fire-and-forget 패턴에서 비동기 응답이 별도 채널로 반영되는 경로
      anti_patterns:
        - "for (const [k,v] of upstream.headers) res.setHeader(k,v) — 전체 헤더 패스스루"
        - "res.send(await upstream.text()) — Content-Type 미강제"
        - "error: `Module ${url} unavailable` — 내부 URL 에러 반영"
      references: [CWE-113, CWE-79, CWE-601, CWE-200]

    Cache_Poisoning_Boundary:
      question: "캐시 키 생성이 신뢰하지 않는 헤더/쿼리를 포함하거나,
                 사용자별 콘텐츠가 공용 캐시에 저장되는가?"
      methodology: |
        HTTP 캐시(CDN, Varnish, Cloudflare) 및 애플리케이션 캐시(Redis,
        Memcached, in-process LRU) 모두를 대상으로:

        1. 캐시 키 구성:
           - 키에 포함되는 필드: method, URL, host, headers?
           - 공격자가 조작 가능한 unkeyed 입력(헤더 X-Forwarded-Host,
             Accept-Language, 커스텀 헤더)이 응답에 반영되면서 키에는 포함되지
             않으면 → 캐시 포이즈닝 경로
        2. 권한 격리:
           - Authorization/Cookie가 있는 요청도 캐시되는가?
             있다면 Vary 헤더가 해당 헤더를 포함하는가?
           - 로그인 사용자 전용 페이지가 캐시되어 비로그인 사용자에게 제공되지
             않는가?
        3. Cache Deception:
           - /account/settings.css 같은 static처럼 보이는 경로가 실제로는
             /account/settings를 반환하는 백엔드와 결합될 때, CDN이 .css로
             믿고 공용 캐시에 저장하지 않는가?
        4. 애플리케이션 캐시:
           - Redis 키가 attacker-controlled 값을 포함하면 키 충돌로 타인의
             데이터를 읽거나 덮어쓸 수 있는가?
      references: [CWE-444, CWE-524, CWE-525]

  Batch_Worker:
    Job_Data_Boundary:
      question: "배치/워커 작업의 데이터 경계가 명확한가?"
      methodology: |
        배치 작업의 데이터 흐름을 추적:
        1. 작업 페이로드에 민감 데이터(PII, 시크릿)가 포함되는가?
        2. 큐 메시지에 포함된 데이터가 암호화되는가?
        3. 실패한 작업이 Dead Letter Queue로 이동할 때 민감 데이터가 잔류하는가?
        4. 작업 로그에 처리 대상 데이터(사용자 정보, 금액 등)가 기록되는가?
        5. 대량 처리 시 메모리에 적재되는 데이터 범위가 제한되는가?

    Job_State_Consistency:
      question: "배치 작업의 상태 일관성이 보장되는가?"
      review: |
        - 작업 중단/실패 시 부분 처리 상태가 정리되는가? (원자성)
        - 동일 작업의 중복 실행이 안전한가? (멱등성)
        - 작업 완료 시점과 결과 반영 시점 사이에 불일치 윈도우가 있는가?

  Frontend:
    Server_Client_Boundary:
      question: "서버→클라이언트 데이터 전달 시 민감 정보가 유출되는가?"
      methodology: |
        서버 측에서 클라이언트 측으로 데이터가 전달되는 모든 경로를 추적

  BaaS_DB:
    Function_Exposure:
      question: "DB 함수가 의도치 않게 클라이언트에 노출되는가?"
      review: |
        - public 스키마 함수가 API로 자동 노출되는가?
        - 특권 함수가 내부 데이터를 반환하는가?

  Mobile:
    Local_Data_Security:
      question: "로컬에 저장되는 민감 데이터가 보호되는가?"
      methodology: |
        로컬 데이터 저장 코드를 추적:
        1. 로컬 DB(SQLite, Realm, Core Data)에 민감 데이터가
           암호화 없이 저장되는가?
        2. 캐시/임시 파일에 민감 데이터가 남는가?
        3. 로그에 민감 정보가 기록되는가? (NSLog, console.log, Log.d 등)
        4. 클립보드에 민감 데이터가 복사 가능한가?
        5. 앱 백그라운드 진입 시 스크린샷에 민감 화면이 캡처되는가?

    IPC_Security:
      question: "앱 간 통신(IPC)이 안전한가?"
      methodology: |
        외부에서 앱으로 진입하는 모든 IPC 경로를 식별:
        1. Deep Link / URL Scheme 핸들러에 입력 검증이 있는가?
        2. Universal Links / App Links 설정이 적절한가?
        3. Intent(Android) 수신 시 발신자 검증이 있는가?
        4. IPC로 전달된 데이터가 검증 없이 내비게이션/기능 실행에 사용되는가?

  AI_ML:
    Sensitive_Data_to_LLM:
      question: "민감 데이터가 LLM API로 전송되는가?"
      methodology: |
        LLM 호출의 입력 데이터를 추적하여 민감 정보 유출 가능성 분석:
        1. 사용자 PII가 프롬프트에 포함되어 외부 LLM API로 전송되는가?
        2. 시스템 시크릿, API 키, 내부 설정이 프롬프트에 포함되는가?
        3. RAG 검색 결과에 다른 사용자/테넌트의 데이터가 포함될 수 있는가?
        4. LLM 호출 로그에 민감 프롬프트/응답이 기록되는가?

    System_Prompt_Exposure:
      question: "시스템 프롬프트가 사용자에게 노출될 수 있는가?"
      review: |
        - 시스템 프롬프트가 API 응답에 포함되는가?
        - 에러 메시지에 프롬프트 내용이 포함되는가?
        - 프롬프트 추출 공격(반복 질문, 역할 전환 요청)에 대한 방어가 있는가?

  SDK:
    SDK_Data_Flow:
      question: "SDK를 통과하는 데이터의 신뢰 경계가 명확한가?"
      methodology: |
        SDK의 데이터 흐름을 3방향으로 추적:
        1. 개발자 → SDK:
           - 개발자가 전달하는 데이터(사용자 정보, 설정)가
             SDK 내부에서 어디까지 전파되는가?
           - 개발자가 의도하지 않은 데이터가 백엔드로 전송되는가?
        2. SDK → 백엔드:
           - SDK가 자동으로 수집하여 전송하는 데이터 목록
             (디바이스 정보, 위치, 사용 통계 등)
           - 전송 데이터에 대한 문서화와 옵트아웃 메커니즘
        3. 백엔드 → SDK → 개발자:
           - 백엔드 응답에서 개발자 콜백/이벤트로 전달되는 데이터에
             다른 사용자의 민감 정보가 포함될 수 있는가?
           - SDK 캐시에 민감 데이터가 잔류하는가?

    SDK_Local_Storage_Security:
      question: "SDK의 로컬 저장이 안전한가?"
      methodology: |
        SDK가 로컬에 저장하는 모든 데이터를 추적:
        1. 저장 항목: 토큰, 캐시, 설정, 로그, 분석 데이터
        2. 저장 매체별 보안 수준:
           - 암호화 저장소 (Keychain, Keystore, EncryptedSharedPreferences)
           - 비암호화 저장소 (파일, localStorage, UserDefaults, SharedPreferences)
        3. 저장 데이터의 생명주기:
           - 만료/삭제 정책이 있는가?
           - SDK 해제 시 로컬 데이터가 정리되는가?
           - 앱 삭제 시에도 잔류하는 데이터가 있는가?

Representative_Anti_Patterns:
  - "서버에서 전체 레코드를 가져온 후 클라이언트에서 필드 필터링"
  - "요청 본문을 필터링 없이 DB에 직접 전달 (Mass Assignment)"
  - "DB에서 모든 컬럼 쿼리, 불필요한 민감 데이터가 응답에 포함"
  - "사용자 PII가 필터링 없이 외부 LLM API 프롬프트에 포함"
  - "민감 데이터가 모바일 로컬 DB에 평문 저장"
  - "프록시가 업스트림 응답 헤더를 denylist 1~2개만 제외하고 전체 패스스루"
  - "업스트림 에러 메시지에 내부 URL을 포함하여 클라이언트에 반환"

Representative_Healthy_Patterns:
  - "쿼리에서 필요한 컬럼만 명시적으로 선택"
  - "응답 DTO/시리얼라이저로 노출 필드 제한"
  - "저장 시 허용된 필드만 명시적으로 선택"
  - "금융 거래에 DB 트랜잭션 + 행 잠금"
  - "LLM 전송 전 PII 마스킹/익명화 적용"
  - "모바일 로컬 DB에 SQLCipher 등 암호화 적용"
  - "프록시 응답 헤더를 allowlist 기반으로 필터링 + Content-Type 강제"
```
