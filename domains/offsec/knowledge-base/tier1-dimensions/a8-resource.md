---
phases: [va, verify, pentest, converge, report]
---
# A8: 리소스 소비 및 가용성 제어 (Resource Consumption and Availability)

```yaml
Core_Architecture_Questions:
  - "리소스 소비를 제어하는 메커니즘이 존재하는가?"
  - "해당 메커니즘이 배포 환경에서 실제로 작동하는가?"
  - "제어 부재가 시스템 가용성이나 비용에 영향을 미치는가?"

Review_Perspectives:

  Backend:
    Consumption_Control_Mechanisms:
      question: "요청 빈도, 데이터 크기, 연산량을 제어하는 메커니즘이 있는가?"
      methodology: |
        1. Rate Limiting: 요청 빈도 제한 메커니즘 존재?
           - 상태 저장 방식이 배포 환경에 적합한가?
             (※ Phase 0의 DEPLOY 변수와 교차 참조)
           - Serverless에서 인메모리 저장이 인스턴스 비공유로 무력화되는가?
        2. Pagination: 대량 데이터 쿼리에 페이지네이션/리밋 존재?
        3. 파일/페이로드 크기 제한 설정?

    Attack_Surface_Exposure:
      question: "비인증 엔드포인트에 비용 발생 작업이 있는가?"
      review: |
        - Attack Surface Map의 AUTH: no 엔드포인트 중
          DB 쿼리, 외부 API 호출 등 비용 발생 작업이 있는가?

  Frontend:
    Client_Resource_Control:
      question: "클라이언트 측 리소스 소비가 제어되는가?"
      review: |
        - 대량 데이터 렌더링 시 가상화(virtualization)가 적용되는가?
        - 무한 스크롤/페이지네이션에 로딩 제한이 있는가?
        - WebSocket/SSE 연결 수 제한이 있는가?
        - 파일 다운로드 크기 제한이 클라이언트에서 검증되는가?

  Batch_Worker:
    Job_Resource_Control:
      question: "배치/워커 작업의 리소스 소비가 제한되는가?"
      methodology: |
        배치 작업의 리소스 사용 패턴을 분석:
        1. 단일 작업의 최대 실행 시간(timeout)이 설정되는가?
        2. 동시 실행 워커 수의 상한이 있는가?
        3. 대량 처리 시 배치 크기(batch size)가 제한되는가?
        4. 메모리 사용량이 제한되는가? (OOM 시 다른 서비스 영향)
        5. DB 쿼리에 LIMIT/페이지네이션이 적용되는가?
        6. 외부 API 호출에 rate limit을 준수하는 조절이 있는가?

    Job_Queue_Protection:
      question: "작업 큐가 리소스 고갈 공격에 보호되는가?"
      review: |
        - 큐에 메시지를 발행할 수 있는 주체가 인증/제한되는가?
        - 큐 깊이(depth) 제한이 있어 메모리 고갈이 방지되는가?
        - 독성 메시지(항상 실패하는 메시지)가 감지되어 제거되는가?

  LLM_AI:
    LLM_Resource_Control:
      question: "LLM 호출의 리소스 소비가 제한되는가?"
      methodology: |
        LLM 통합의 리소스 사용을 분석:
        1. 단일 요청의 최대 토큰 수(input + output)가 제한되는가?
        2. 사용자별 일/월 토큰 사용량 한도가 있는가?
        3. 토큰 사용량이 모니터링/알림되는가?
        4. 에이전트 자기 참조 루프(무한 대화)가 방지되는가?
        5. 동시 LLM 호출 수가 제한되는가?
        6. 벡터 DB 크기/문서 수 제한이 있는가?

  BaaS_DB:
    Query_Limits:
      question: "DB 수준의 리소스 소비 제한이 있는가?"

  SDK:
    SDK_Resource_Management:
      question: "SDK가 호스트 앱의 리소스를 과도하게 사용하지 않는가?"
      methodology: |
        SDK의 리소스 사용 패턴을 분석:
        1. 네트워크:
           - 재시도(retry) 로직에 지수 백오프(exponential backoff)가 적용되는가?
           - 최대 재시도 횟수 제한이 있는가?
           - 무한 폴링이나 불필요한 주기적 요청이 있는가?
           - 동시 요청 수 제한이 있는가?
        2. 메모리/저장:
           - 캐시 크기 제한이 있는가?
           - 로컬 저장 데이터에 최대 크기/항목 수 제한이 있는가?
           - 메모리 누수 패턴 (해제되지 않는 리스너, 순환 참조)
        3. CPU/배터리:
           - 백그라운드에서 불필요한 작업이 실행되는가?
           - 타이머/인터벌의 최소 간격이 적절한가?
        4. 연결 관리:
           - WebSocket/TCP 연결이 적절히 해제되는가?
           - 연결 유휴 타임아웃이 설정되는가?

    SDK_Retry_Fallback_Security:
      question: "SDK의 재시도/폴백 로직이 보안 수준을 하향시키는가?"
      review: |
        - HTTPS 실패 시 HTTP로 폴백하는 로직이 있는가?
        - 인증 실패 시 비인증으로 폴백하는 로직이 있는가?
        - 프라이머리 서버 실패 시 폴백 서버의 인증서 검증 수준이 동일한가?
        - 재시도 시 새 토큰을 발급받는가, 만료된 토큰을 재사용하는가?

Representative_Anti_Patterns:
  - "인메모리 Rate Limit + Serverless 배포 → 인스턴스별 독립 카운터, 무력화"
  - "비인증 엔드포인트에 비용 발생 작업 + Rate Limit 없음 → 무제한 호출"
  - "페이지네이션 없는 전체 쿼리 → 대량 데이터 응답으로 성능/비용 영향"

Representative_Healthy_Patterns:
  - "외부 공유 스토리지(Redis, DB 등) 기반 Rate Limiting"
  - "비인증 엔드포인트에 엄격한 Rate Limiting"
  - "모든 목록 쿼리에 페이지네이션 + 최대 크기 제한"

Concurrency_Cross_Reference:
  note: |
    동시성 관련 리소스 이슈(Race condition에 의한 리소스 고갈,
    분산 잠금 실패에 의한 무한 재시도)는 concurrency.md에서 분석한다.
    A8은 리소스 소비 "제어 메커니즘" 유무에 집중한다.
```
