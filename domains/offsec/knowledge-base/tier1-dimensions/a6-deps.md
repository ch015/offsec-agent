---
phases: [va, verify, pentest, converge, report]
---
# A6: 의존성 및 외부 통합 (Dependency and External Integration)

```yaml
Core_Architecture_Questions:
  - "외부 의존성과 서드파티 통합이 안전하게 설계되어 있는가?"
  - "아키텍처가 외부 응답을 맹신하고 있는가?"
  - "외부 통합 지점에서 보안 경계가 유지되는가?"

Review_Perspectives:

  Backend:
    External_API_Trust:
      question: "외부 API 응답을 맹신하는가?"
      review: |
        - 외부 응답이 검증/새니타이징 없이 DB 저장 또는 사용자 전달되는가?
        - 외부 호출에 적절한 타임아웃이 설정되는가?

    Webhook_Verification:
      question: "웹훅 수신 시 발신자 검증이 수행되는가?"
      review: |
        - 서명(HMAC 등) 검증이 있는가?
        - 위조된 웹훅이 시스템 상태를 변경할 수 있는가?

    Proxy_Gateway_Response_Trust:
      question: "프록시/게이트웨이가 업스트림 서비스 응답을 검증 없이 신뢰하는가?"
      methodology: |
        애플리케이션이 리버스 프록시, API 게이트웨이, BFF, 사이드카 역할을
        수행하는 경우, 업스트림 응답의 신뢰 경계를 분석한다:

        1. 응답 헤더 신뢰 범위:
           - 업스트림 응답 헤더를 allowlist 기반으로 필터링하는가?
           - Set-Cookie, Location, Access-Control-*, Content-Type 등
             보안 민감 헤더가 무필터 통과하는가?

        2. 응답 바디 신뢰 범위:
           - 업스트림 응답의 Content-Type을 강제하는가 (예: application/json)?
           - 업스트림 에러 응답에 내부 정보(URL, 스택 트레이스, 호스트명)가
             포함될 때 클라이언트에 그대로 전달하는가?

        3. 업스트림 침해 시나리오:
           - 업스트림 모듈이 침해되었을 때, 게이트웨이를 통해 클라이언트에
             임의 헤더/바디를 주입할 수 있는가?
           - 이 경로로 게이트웨이 도메인의 세션 탈취, XSS, CORS 우회가 가능한가?
      anti_patterns:
        - "업스트림 헤더 전체를 denylist 1~2개만 제외하고 패스스루"
        - "업스트림 에러 메시지를 클라이언트 응답에 그대로 포함"
        - "업스트림 Content-Type을 신뢰하여 text/html을 게이트웨이 도메인에서 렌더링"
      references: [CWE-113, CWE-79, CWE-200]

    SSRF_Structure:
      question: "서버가 사용자 제공 URL로 HTTP 요청을 수행하는가? (CWE-918)"
      methodology: |
        서버 측 HTTP 요청 수행 코드(fetch/axios/requests/http.NewRequest/
        URLConnection 등)를 식별하고, 다음을 모두 검증한다:

        1. URL 출처 추적:
           - 사용자 입력이 요청 URL/host/path/query에 어떻게 포함되는가?
           - 간접 경로 포함 (webhook 등록 URL, image proxy, link preview,
             RSS fetcher, PDF renderer, import-from-URL 기능 등)

        2. 목적지 제한:
           - 도메인 allowlist가 있는가, 아니면 free-form URL인가?
           - DNS resolution 결과가 IP allowlist를 통과하는가?
             (DNS rebinding: 초기 resolve는 공개 IP, 재요청 시 내부 IP)
           - 사설/루프백/링크로컬/특수 용도 IP를 차단하는가?
             (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16,
              0.0.0.0, ::1, fc00::/7, fe80::/10, fd00::/8)
           - metadata 엔드포인트 차단: 169.254.169.254(AWS), fd00:ec2::254,
             metadata.google.internal, 100.100.100.200(Alibaba)

        3. 프로토콜 제한:
           - https만 허용하는가? file://, gopher://, dict://, ftp://,
             ldap:// 등 위험 스킴이 차단되는가?
           - Node.js라면 `http` 모듈 자체 비활성 (fetch 강제)

        4. 리다이렉트 정책:
           - 3xx 응답을 자동 follow 하는가? follow 대상 URL이 재검증되는가?
           - 리다이렉트 체인 각 홉에서 SSRF 체크가 반복되는가?

        5. 응답 크기/타입 제한:
           - 응답 본문이 버퍼링 시 상한이 있는가? (DoS 방지)
           - content-type이 기대와 다르면 거부하는가?

        6. 크레덴셜 릭 방지:
           - 외부 호출에 내부 세션 쿠키/Authorization 헤더가 함께 나가지 않는가?
      anti_patterns:
        - "fetch(userUrl) — 검증 없음"
        - "new URL(userUrl) 만으로 host 검증 (DNS 재확인 미수행)"
        - "SSRF 필터 있으나 302 follow 시 재검증 안 함"
        - "axios({ url, ...defaults }) 에서 defaults에 내부 base_url 합성"
      references: [CWE-918, CWE-601, CWE-20]

  Batch_Worker:
    Worker_Dependency_Trust:
      question: "워커 서비스의 외부 의존성이 안전한가?"
      methodology: |
        배치/워커 서비스의 외부 통합을 분석:
        1. 외부 API 호출에 타임아웃이 설정되는가?
        2. 외부 서비스 장애 시 circuit breaker가 있는가?
        3. 메시지 큐(SQS, RabbitMQ 등) 연결 장애 시 복구 전략이 있는가?
        4. 외부 서비스 응답이 검증 없이 비즈니스 로직에 사용되는가?

  Mobile:
    Mobile_SDK_Dependencies:
      question: "모바일 앱의 서드파티 SDK/라이브러리가 안전한가?"
      review: |
        - 서드파티 SDK가 과도한 시스템 권한을 요구하는가?
        - 서드파티 SDK의 데이터 수집 범위가 문서화/감사되는가?
        - SDK 간 데이터 공유(공유 저장소, 브로드캐스트 등)가 있는가?
        - 서드파티 SDK에 알려진 CVE가 있는가?

  Frontend:
    Client_Communication:
      question: "실시간 통신 채널이 안전하게 설계되어 있는가?"
      methodology: |
        실시간 통신(WebSocket, SSE, Socket.IO 등) 구현을 분석:
        1. 연결 수립 시 인증:
           - 연결 핸드셰이크에 인증이 수행되는가?
           - 연결 중 토큰 만료 시 재인증이 강제되는가?
        2. 메시지 수준 인가:
           - 각 메시지/이벤트에 발신자 권한 검증이 있는가?
           - 연결 수립 시 인증만으로 모든 메시지가 허용되는가?
        3. 브로드캐스트 범위:
           - 채널/룸 구독 시 해당 리소스에 대한 접근 권한 검증이 있는가?
           - 사용자 A의 이벤트가 사용자 B에게 전달될 수 있는가?
        4. 메시지 무결성:
           - 클라이언트가 보내는 메시지에 입력 검증이 있는가?
           - 메시지 크기/빈도 제한이 있는가?
        5. 교차 윈도우 메시징:
           - postMessage에 origin 검증이 있는가?

  BaaS_DB:
    Migration_Safety:
      question: "스키마 마이그레이션이 기존 보안 설정을 무력화하는가?"
      review: |
        - 새 마이그레이션이 기존 보안 정책, 트리거, 권한을 삭제/수정하는가?

  AI_ML:
    LLM_Response_Trust:
      question: "LLM 응답을 맹신하는가?"
      review: |
        - LLM 응답이 검증 없이 비즈니스 로직에 사용되는가?
          (가격 결정, 권한 판단, 콘텐츠 승인 등)
        - LLM이 결정하는 사항에 인간 검토(human-in-the-loop)가 있는가?
        - LLM 환각(hallucination)이 비즈니스 영향을 미칠 수 있는 경로가 있는가?

    AI_Agent_Authority:
      question: "AI 에이전트가 과도한 권한을 보유하는가?"
      methodology: |
        AI 에이전트/함수 호출(tool use) 구현을 분석:
        1. 에이전트가 호출 가능한 도구/함수 목록과 각 함수의 권한 범위
        2. 도구 호출 전 사용자 확인/승인 절차 존재 여부
        3. 도구 호출에 Rate Limit/횟수 제한이 있는가?
        4. 도구의 부작용(데이터 변경, 외부 호출)이 되돌릴 수 있는가?

  SDK:
    SDK_Dependency_Exposure:
      question: "SDK의 의존성이 소비자 앱에 부정적 영향을 미치는가?"
      methodology: |
        SDK가 끌어오는 의존성의 영향을 분석:
        1. 전이 의존성(transitive dependency) 목록과 크기
           - SDK 소비자가 의도치 않게 설치되는 패키지 수
           - 의존성 충돌(version conflict) 가능성
        2. 의존성의 보안 이력:
           - 알려진 CVE가 있는 의존성이 포함되는가?
           - 의존성이 적극적으로 유지보수되는가? (마지막 업데이트 시점)
        3. 의존성 최소화:
           - SDK 기능 대비 불필요한 의존성이 있는가?
           - 선택적 기능의 의존성이 optional/peer로 분리되어 있는가?

    SDK_Backend_Trust:
      question: "SDK가 자체 백엔드 응답을 맹신하는가?"
      review: |
        - SDK가 자사 백엔드 응답을 검증 없이 신뢰하는가?
        - MITM 시나리오에서 변조된 응답으로 SDK 동작을 조작할 수 있는가?
        - 서버 점검/장애 시 SDK의 폴백 동작이 보안을 약화시키는가?

Representative_Anti_Patterns:
  - "외부 API 응답이 검증 없이 DB 저장 → 인젝션 가능"
  - "웹훅 서명 미검증 → 위조된 이벤트가 상태 변경 가능"
  - "사용자 입력 URL로 서버 HTTP 요청 → SSRF"
  - "마이그레이션이 보안 정책 삭제 → 보안 설정 무력화"
  - "WebSocket 연결 수립 시에만 인증, 메시지 수준 인가 없음"
  - "LLM 응답이 검증 없이 비즈니스 결정에 사용"
  - "AI 에이전트가 사용자 확인 없이 데이터 변경 도구 호출"

Representative_Healthy_Patterns:
  - "외부 응답에 스키마 검증 + 새니타이징 적용"
  - "웹훅 서명 검증 + 타임스탬프 검증"
  - "URL allowlist + 내부 네트워크 차단"
  - "WebSocket 메시지별 인가 + 채널 구독 권한 검증"
  - "LLM 결정에 human-in-the-loop + 출력 검증"
  - "AI 에이전트 도구에 최소 권한 + 승인 절차"

Supply_Chain_Cross_Reference:
  module: "offsec/va/supply-chain.md"
  note: |
    A6은 "외부 통합 지점의 보안 경계"에 집중한다.
    공급망 전체(의존성 CVE, lock 파일, 빌드 파이프라인)는
    supply-chain.md에서 분석한다.
    A6과 supply-chain.md의 분석 결과는 Phase 1 완료 시 통합한다.
```
