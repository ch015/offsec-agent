---
phases: [va, verify, pentest, converge, report]
---
# A7: 에러 처리 및 관찰 가능성 (Error Handling and Observability)

```yaml
Core_Architecture_Questions:
  - "에러 처리가 내부 구조를 유출하지 않으면서 적절한 정보를 제공하는가?"
  - "에러 처리가 체계적으로 설계되었는가, 즉흥적인가?"
  - "보안 이벤트를 탐지하고 추적하는 아키텍처가 있는가?"

Review_Perspectives:

  Backend:
    Error_Response_Design:
      question: "에러 응답이 내부 구조를 유출하는가?"
      methodology: |
        에러 처리 경로를 추적하여 내부 정보가 클라이언트에 노출되는지 검증:
        1. catch/except/recover 블록에서 에러 객체 처리 방식
        2. 응답에 DB 스키마, 스택 트레이스, 환경 변수 포함 여부
        3. 프로덕션/개발 환경 간 에러 응답 분기 여부

    Security_Event_Logging:
      question: "보안 이벤트가 로깅되는가?"
      methodology: |
        1. 로깅해야 할 보안 이벤트가 실제로 로깅되는가?
        2. 로그에 시크릿/PII가 기록되는가?
        3. 감사 추적 가능 구조인가?

    Forensic_Readiness_And_Audit_Log:
      question: "침해 사고 발생 12개월 후에도 법적 포렌식 재구성이 가능한 감사 로그가 있는가? (P3-3)"
      methodology: |
        다음을 모두 확인한다:

        1. 감사 대상 이벤트 커버리지:
           - 인증: login 성공/실패, MFA 통과/실패, 세션 만료, 비정상 IP
           - 인가: role 변경, privilege 에스컬레이션, permission grant/revoke
           - 데이터 변경: 모든 state-changing API (CUD), 특히 PII/재무
           - 자금 이동: 결제, 환급, 송금, 포인트 전환
           - 계정 생명주기: 생성, 삭제, 이메일 변경, 비밀번호 재설정
           - 관리자 작업: admin console 접근, 사용자 impersonate, 대량 작업

        2. 무결성 (Tamper-Evident):
           - 로그가 append-only 스토리지에 저장되는가? (S3 Object Lock,
             GCS retention, Azure Immutable Blob)
           - 각 로그 엔트리에 서명 또는 체인 해시(Merkle log / Trillian)?
           - 로그 삭제 권한이 운영자에게 있으면 감사 무결성 무너짐 —
             별도 역할/계정으로 분리되어 있는가?

        3. 보존 기간:
           - 규제가 요구하는 기간(SOX 7년, HIPAA 6년, PCI-DSS 1년)을 만족?
           - 자동 파기 정책이 있어 GDPR '잊혀질 권리'와 균형이 맞는가?

        4. PII 마스킹:
           - 로그에 PII가 포함된다면 필드별 마스킹 규칙(이메일 도메인만,
             카드번호 마지막 4자리 등)이 적용되는가?
           - 마스킹 전에 외부 stream(Slack 알림, 이메일)으로 전송되지 않는가?

        5. 타임스탬프 정확성:
           - 모든 소스가 NTP 동기화되는가?
           - 로그 저장 시 UTC + 원본 시간대를 모두 기록하는가?

        6. 상관관계 가능성:
           - request_id / trace_id 가 인증 이벤트부터 DB 변경까지 이어지는가?
           - 여러 마이크로서비스 로그를 하나의 trace로 합쳐볼 수 있는가?

        7. 이상 탐지 파이프라인:
           - SIEM(Splunk/Elastic/Chronicle)으로 실시간 흐르는가?
           - 보안 이벤트에 대한 탐지 룰이 있는가? (TA0006, TA0001 매핑)
      anti_patterns:
        - "audit log를 동일한 애플리케이션 DB에 저장 + 관리자가 delete 가능"
        - "결제/환급 이벤트 로깅 누락"
        - "stdout 로그만 있고 영구 저장소가 별도 없음 (컨테이너 재시작 시 손실)"
        - "로그에 카드번호·SSN·세션 토큰 평문 기록"
      references: [CWE-778, CWE-532, NIST SP 800-53 AU-*, PCI-DSS 10.*]

  Frontend:
    Client_Error_Handling:
      question: "클라이언트 측 에러 처리가 민감 정보를 노출하는가?"
      methodology: |
        프론트엔드 에러 처리 경로를 추적:
        1. 서버 에러 응답이 사용자에게 그대로 표시되는가?
        2. JavaScript 에러(stack trace)가 프로덕션에서 콘솔에 노출되는가?
        3. Source Map이 프로덕션에서 활성화되어 원본 코드가 노출되는가?
        4. 에러 리포팅 서비스(Sentry 등)로 전송되는 데이터에 PII/시크릿이 포함되는가?

    CSP_Security_Headers:
      question: "보안 헤더(CSP 등)가 적절히 설정되는가?"
      review: |
        - CSP에 unsafe-inline이 script-src에 포함되는가?
        - connect-src가 과도하게 허용(https:)되어 있지 않은가?
        - X-Frame-Options, X-Content-Type-Options, HSTS가 설정되는가?

  Batch_Worker:
    Job_Error_Recovery:
      question: "배치/워커 작업의 에러 처리가 안전한가?"
      methodology: |
        배치 작업의 실패 시나리오를 분석:
        1. 작업 실패 시 재시도 전략이 있는가? (exponential backoff, max retries)
        2. 재시도 횟수 초과 시 Dead Letter Queue로 이동하는가?
        3. 부분 실패 시 처리 완료 항목과 미처리 항목이 추적 가능한가?
        4. 에러 로그에 작업 페이로드의 민감 정보가 포함되는가?
        5. 장기 실행 작업의 타임아웃이 설정되는가?
        6. FlushAndWait/일괄 처리 중단 시 중간 상태가 정리되는가?

    Job_Observability:
      question: "배치 작업의 상태가 모니터링/추적 가능한가?"
      review: |
        - 작업 시작/완료/실패 이벤트가 로깅되는가?
        - 비정상 실행 시간, 비정상 실패율에 대한 알림이 있는가?
        - 작업 간 인과 관계(trace_id)가 추적 가능한가?

  LLM_AI:
    LLM_Error_Handling:
      question: "LLM 호출 실패 시 에러 처리가 안전한가?"
      methodology: |
        LLM 통합의 에러 처리 경로를 분석:
        1. LLM API 호출 실패(rate limit, timeout) 시 재시도 전략이 있는가?
        2. 파싱 실패(비정형 응답) 시 fallback이 안전한가?
        3. 에러 메시지에 API 키, 모델명, 시스템 프롬프트가 노출되는가?
        4. 스트리밍 응답 중단 시 불완전한 데이터가 사용자에게 전달되는가?
        5. LLM 서비스 장애 시 전체 서비스의 graceful degradation이 있는가?

  BaaS_DB:
    DB_Error_Propagation:
      question: "DB 에러 메시지가 클라이언트에 전파되는가?"

  SDK:
    SDK_Error_Disclosure:
      question: "SDK 에러가 내부 구현 정보를 노출하는가?"
      methodology: |
        SDK의 에러 처리 경로를 추적:
        1. 에러 메시지 내용:
           - 백엔드 URL, 내부 경로, 내부 에러 코드가 포함되는가?
           - 스택 트레이스가 개발자에게 전파되는가?
           - 인증 토큰/API 키가 에러 메시지에 포함되는가?
        2. Debug/Release 분기:
           - 디버그 모드에서만 상세 에러를 노출하는 분기가 있는가?
           - 릴리즈 모드에서 내부 정보가 마스킹되는가?
        3. 에러 객체 구조:
           - 개발자가 로깅할 때 toString()/JSON.stringify()로
             민감 정보가 자동 포함되는 구조인가?
           - 에러 타입이 체계적으로 분류되어 있는가?
             (NetworkError, AuthError, ValidationError 등)

    SDK_Logging_Security:
      question: "SDK의 로깅이 안전한가?"
      methodology: |
        SDK 내부 로깅 코드를 전수 검사:
        1. 로그 레벨 제어:
           - 개발자가 로그 레벨을 설정할 수 있는가?
           - 기본 로그 레벨이 릴리즈에 적합한가?
        2. 민감 정보 로깅:
           - API 키, 토큰, 사용자 데이터가 로그에 기록되는 경로
           - 요청/응답 본문 로깅 시 민감 필드 마스킹
        3. 로그 출력 대상:
           - 콘솔(NSLog, Log.d, console.log) 출력은
             프로덕션 앱에서 시스템 로그로 남을 수 있음
           - 파일 로깅 시 로그 파일의 접근 제어

Representative_Anti_Patterns:
  - "에러 처리에서 raw 에러 객체를 클라이언트에 전체 반환"
  - "에러 처리가 핸들러마다 분산 → 누락 시 에러 노출"
  - "시크릿/토큰/비밀번호가 로그에 기록"
  - "보안 이벤트 미로깅 → 침해 탐지 불가"

Representative_Healthy_Patterns:
  - "글로벌 에러 핸들러 + 프로덕션에서 일반 메시지만"
  - "에러 유형별 일관된 응답 형식 (에러 코드 + 사용자 메시지)"
  - "로깅 시 민감 값 마스킹"
  - "보안 이벤트 전용 로거/알림 (인증 실패, 권한 위반)"
```
