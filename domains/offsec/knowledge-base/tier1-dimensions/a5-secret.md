---
phases: [va, verify, pentest, converge, report]
---
# A5: 시크릿 및 설정 관리 (Secret and Configuration Management)

```yaml
Core_Architecture_Questions:
  - "시크릿이 안전하게 저장, 전송, 사용되는가?"
  - "보안 설정이 환경별로 적절히 분리되는가?"
  - "클라이언트 노출 설정과 서버 전용 설정이 명확히 구분되는가?"

Review_Perspectives:

  All:
    Secret_Storage:
      question: "시크릿이 안전하게 저장되는가?"
      methodology: |
        코드에서 하드코딩된 시크릿을 식별하는 방법:
        1. 식별: 코드에서 다음 특성의 문자열 리터럴 검색:
           - 높은 엔트로피 (랜덤 문자열 패턴)
           - 자격 증명 컨텍스트 (key, secret, token, password 등 변수명)
           - 알려진 시크릿 형식 (Base64 인코딩 JWT, 클라우드 서비스 키 접두사 등)
        2. 검증: .env 파일이 git에 커밋되는가? (.gitignore 확인)
        3. 판정: 소스코드가 아닌 환경 변수/시크릿 매니저에서 주입되는가?

        Note: "특정 접두사(sk-, AKIA 등)만 검색하는 것은 불충분.
               AI가 컨텍스트와 엔트로피로 자율 판단."

  Frontend:
    Client_Exposure:
      question: "클라이언트 환경 변수에 서비스 키가 포함되는가?"
      methodology: |
        1. 프레임워크 클라이언트 노출 접두사 식별
        2. 해당 접두사 변수에 서비스 키(service_role, secret key)가 포함되는가?
        3. 프로덕션에서 Source Map이 비활성화되는가?

  Backend:
    Security_Configuration:
      question: "보안 관련 설정이 적절한가?"
      review: |
        - CORS 설정 (와일드카드, Origin 반영 등 위험 설정)
        - 프로덕션에서 디버그/내부 엔드포인트 비활성화
        - 보안 헤더 (HSTS, CSP, X-Content-Type-Options 등)

    Active_State_Management:
      question: "미사용 엔드포인트나 기능이 여전히 활성화되어 있는가?"
      methodology: |
        Attack Surface Map과 코드를 교차 참조하여 불필요한 노출 식별

  Batch_Worker:
    Job_Secret_Management:
      question: "배치/워커 서비스의 시크릿이 안전하게 관리되는가?"
      review: |
        - 워커가 사용하는 DB 비밀번호/API 키가 환경 변수 또는 시크릿 매니저에서 주입되는가?
        - 작업 페이로드에 시크릿(API 키, 토큰 등)이 포함되어 큐에 저장되는가?
        - 작업 로그에 시크릿이 기록되는가?
        - 크론/스케줄러 설정에 시크릿이 하드코딩되는가?

  LLM_AI:
    LLM_Secret_Boundary:
      question: "LLM 통합에서 시크릿이 프롬프트/로그에 노출되지 않는가?"
      review: |
        - 시스템 프롬프트에 API 키, DB 비밀번호 등 시크릿이 포함되는가?
        - RAG 검색 결과에 시크릿이 포함될 수 있는가?
        - LLM 호출 로그에 API 키/토큰이 기록되는가?
        - 에이전트가 도구 호출 시 사용하는 시크릿이 대화 응답에 노출되는가?

  Infra:
    Container_Configuration:
      question: "컨테이너/CI 보안 설정이 적절한가?"
      review: |
        - 컨테이너가 root 사용자로 실행되는가?
        - 이미지/빌드 컨텍스트에 시크릿이 포함되는가?
        - CI/CD 파이프라인에서 시크릿이 안전하게 주입되는가?

  Mobile:
    Network_Security_Config:
      question: "네트워크 보안 설정이 적절한가?"
      review: |
        - Android: network_security_config.xml에 cleartext 허용이 있는가?
        - iOS: Info.plist의 ATS(App Transport Security) 예외가 있는가?
        - 인증서 피닝이 구현되어 있는가? 어떤 방식인가?
          (공개키 피닝, 인증서 피닝, 서버 신뢰 평가)
        - 피닝 실패 시 폴백 동작이 안전한가?

    Binary_Protection:
      question: "바이너리에 민감 정보가 포함되는가?"
      review: |
        - API 키, 시크릿이 소스코드에 하드코딩되어 있는가?
        - 난독화(ProGuard/R8, Swift 컴파일러 최적화)가 설정되어 있는가?
        - 빌드 설정에서 디버그 모드가 릴리즈에서 비활성화되는가?

  SDK:
    Secure_Defaults:
      question: "SDK의 기본 설정이 안전한가?"
      methodology: |
        SDK 초기화 시 적용되는 기본값을 전수 검사:
        1. 전송 보안 기본값:
           - HTTPS가 기본 강제인가, HTTP 허용인가?
           - 인증서 검증이 기본 활성화인가?
           - Certificate Pinning이 기본 또는 옵션으로 제공되는가?
        2. 로깅 기본값:
           - 디버그 로깅이 기본 비활성화인가?
           - 릴리즈 빌드에서 verbose 로깅이 자동 비활성화되는가?
        3. 캐시/저장 기본값:
           - 민감 데이터 캐시가 기본 비활성화인가?
           - 로컬 저장 시 기본 암호화가 적용되는가?
        4. 위험 옵션 경고:
           - disableSslVerification, debugMode 등 위험 옵션 활성화 시
             콘솔 경고 또는 런타임 경고가 있는가?
           - 프로덕션 환경에서 위험 옵션이 차단되는가?

    SDK_Distribution_Security:
      question: "SDK 빌드/배포 산출물이 안전한가?"
      methodology: |
        SDK 패키징 및 배포 설정을 분석:
        1. 산출물 내용:
           - 소스맵/심볼 파일이 배포 산출물에 포함되는가?
           - 디버그 정보가 릴리즈 빌드에 포함되는가?
           - 내부 테스트 코드/목 데이터가 배포에 포함되는가?
        2. 무결성:
           - 아티팩트 서명이 설정되어 있는가? (코드 서명, GPG, checksum)
           - 레지스트리 배포 시 2FA/MFA가 설정되어 있는가?
        3. 난독화:
           - 모바일 SDK: ProGuard/R8, Swift 최적화가 적용되는가?
           - Web SDK: 소스 코드 난독화/최소화가 적용되는가?

Representative_Anti_Patterns:
  - ".env 파일이 git에 커밋 — 시크릿 노출"
  - "서비스 키가 클라이언트 환경 변수에 노출"
  - "시크릿이 소스코드에 하드코딩 — 레포 접근자 전원에게 노출"
  - "CORS 설정이 모든 도메인 허용"
  - "프로덕션에서 Source Map 활성화 — 소스 코드 구조 노출"
  - "Android cleartext 허용 + 인증서 피닝 미적용"
  - "릴리즈 빌드에 디버그 모드 활성화"
  - "SDK 기본 설정이 HTTP 허용 / 인증서 검증 비활성화 → 소비자 앱 전체에 영향"
  - "SDK 배포 산출물에 소스맵/심볼 파일 포함 → 내부 구조 노출"
  - "SDK 디버그 로깅이 릴리즈에서도 기본 활성화 → 민감 정보 로그 노출"

Representative_Healthy_Patterns:
  - ".env가 .gitignore에 포함, 환경 변수/시크릿 매니저로 주입"
  - "클라이언트 환경 변수에는 공개 가능 값만 (공개 키, 공개 URL)"
  - "CORS가 명시적 도메인 목록만 허용"
  - "보안 헤더 설정 (HSTS, CSP 등)"
  - "ATS 활성화 + 인증서 피닝 적용"
  - "릴리즈 빌드에서 난독화 + 디버그 비활성화"
  - "SDK 기본값이 HTTPS 강제 + 인증서 검증 활성화 + 디버그 로깅 비활성화"
  - "위험 옵션 활성화 시 런타임 경고 출력"
```
