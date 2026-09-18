---
phases: [va, verify, pentest, converge, report]
---
# A2: 인가 아키텍처 (Authorization Architecture)

```yaml
Core_Architecture_Questions:
  - "접근 제어가 올바른 레이어에서, 올바른 세분성으로, 일관되게 수행되는가?"
  - "방어가 단일 지점인가 다층 구조인가?"
  - "모든 리소스 접근 경로에 소유권/역할 검증이 있는가?"

Review_Perspectives:

  Backend:
    Ownership_Verification:
      question: "리소스 접근 시 소유자/권한자 검증은 어디서 수행되는가?"
      review: |
        - 경로 파라미터를 통한 리소스 접근 시 소유권 필터가 있는가?
        - 읽기/수정/삭제 전체에 일관된 소유권 검증이 적용되는가?
        - 일부 HTTP 메서드에만 검증이 있고 다른 메서드에는 누락된 패턴이 있는가?

    Exported_Dangerous_Function_Scan:
      question: "위험한 행동을 수행하는 exported 함수가 현재 미사용이더라도 접근 가능한 상태로 존재하는가?"
      methodology: |
        라우터에 등록된 경로만 분석하는 것은 현재 노출만 확인한다.
        역방향 스캔으로 잠재적 노출을 선제 식별한다:
        1. 암호화 서명, 키 파생, 권한 변경, 데이터 삭제 등
           보안 민감 행동을 수행하는 함수를 코드에서 식별한다.
        2. 해당 함수의 접근 제어 수준을 확인한다:
           - 언어별 가시성: exported/public/package-level
           - 현재 호출자(caller) 수를 검색한다.
        3. 호출자가 0건이면서 exported 상태인 함수를 "Dormant Risk"로 분류한다.
           현재 위험은 없으나, 향후 개발에서 실수로 노출될 수 있다.
        4. 특히 다음 패턴에 주의한다:
           - 도메인 분리/프리픽스 없이 raw 데이터에 직접 작용하는 함수
           - 안전한 래퍼 함수(SignMessage)와 병존하는 위험한 원시 함수(SignHash)
           - 테스트/디버그 용도로 만들어졌으나 제거되지 않은 함수

    State_Change_Authorization:
      question: "상태 전이가 서버에서 검증되는가?"
      review: |
        - 상태(status) 변경이 클라이언트 제공 값을 직접 사용하는가?
        - 서버가 현재 상태를 확인하고 유효한 다음 상태로만 전이를 허용하는가?

  Frontend:
    Client_Access_Control:
      question: "클라이언트 측 역할 검사가 유일한 보호인가?"
      review: |
        - 서버 측 인가 로직이 항상 대응하여 존재하는가?

  BaaS_DB:
    Row_Level_Access_Control:
      question: "행 수준 보안 규칙이 모든 민감 테이블에 적용되는가?"
      review: |
        - 보안 규칙이 활성화되었으나 정책이 정의되지 않은 테이블이 있는가?
        - 컬럼 수준 접근 제어가 적용되는가? (역할, 잔액 등 민감 컬럼)

  Web3:
    Access_Control:
      question: "특권 함수에 접근 제어가 있는가?"
      review: |
        - 자금 인출, 토큰 발행, 일시정지, 업그레이드 등 특권 함수에 접근 제한이 있는가?

  SDK:
    Public_vs_Internal_API:
      question: "SDK의 공개 API와 내부 API가 명확히 분리되는가?"
      methodology: |
        1. export/public으로 노출된 API 목록과 내부 전용 API 목록을 식별
        2. 내부 전용으로 의도된 클래스/함수가 접근 가능한 경로가 있는가?
           - 언어별 접근 제어: internal/private/package-private/@internal
           - 빌드 시 내부 API가 번들에 포함되어 런타임 접근 가능한가?
        3. 공개 API를 통해 내부 상태를 직접 조작할 수 있는가?
           - 설정 객체 참조가 외부에서 변경 가능한가?
           - 내부 이벤트 버스/콜백을 외부에서 트리거 가능한가?

    SDK_Permission_Scope:
      question: "SDK가 요구하는 권한이 최소 권한 원칙을 따르는가?"
      review: |
        - 모바일 SDK: 요구하는 시스템 권한(카메라, 위치, 연락처 등)이
          SDK 기능에 필수적인가, 과도한가?
        - 서버 SDK: 요구하는 IAM/DB 권한이 최소인가?
        - 브라우저 SDK: 요구하는 브라우저 API(localStorage, 쿠키, Geolocation)가
          기능에 필수적인가?

  Batch_Worker:
    Job_Authorization:
      question: "배치/워커 작업의 권한이 최소인가?"
      methodology: |
        배치/워커 서비스의 권한 범위를 분석:
        1. 워커 서비스 계정이 모든 테이블/리소스에 접근 가능한가?
        2. 작업 유형별로 필요한 DB/API 권한만 부여되는가?
        3. 관리자 전용 작업(일괄 삭제, 데이터 마이그레이션)의 실행 권한이 제한되는가?
        4. 작업 큐에 메시지를 발행할 수 있는 주체가 제한되는가?

    Job_Scope_Isolation:
      question: "배치 작업이 의도된 범위를 초과하여 실행되지 않는가?"
      review: |
        - 작업 페이로드에 포함된 대상 범위(tenant_id, user_id 등)가 검증되는가?
        - 작업이 다른 테넌트/사용자의 데이터에 접근 가능한 경로가 있는가?
        - FlushAndWait/일괄 처리 시 처리 범위 제한이 있는가?

  LLM_AI:
    Agent_Tool_Authorization:
      question: "LLM 에이전트의 도구 사용 권한이 사용자 컨텍스트로 제한되는가?"
      methodology: |
        에이전트/함수 호출 구현의 인가 경로를 분석:
        1. 에이전트가 호출하는 도구가 요청한 사용자의 권한으로 실행되는가?
        2. 에이전트가 사용자 A의 요청으로 사용자 B의 데이터에 접근 가능한가?
        3. 에이전트의 자율 액션(human approval 없는)에 권한 상한이 있는가?
        4. 도구 호출 결과가 요청 사용자에게만 반환되는가?

  Mobile:
    Local_Permission_Bypass:
      question: "클라이언트 사이드 권한 검사가 유일한 보호인가?"
      review: |
        - 역할/권한 정보가 로컬에 캐시되어 서버 검증 없이 사용되는가?
        - 앱 내 관리자 기능이 클라이언트 사이드 조건만으로 표시/숨김되는가?
        - 루팅/탈옥 환경에서 로컬 권한 검사가 우회 가능한가?

Representative_Anti_Patterns:
  - "인가가 단일 레이어(코드 OR DB)에서만 수행 → 해당 레이어 우회 시 무방비"
  - "소유권 검증이 특정 HTTP 메서드에만 → 비일관적 적용"
  - "관리자 기능이 클라이언트 측 조건으로만 보호 → 서버에서 미검증"
  - "역할/권한 필드가 클라이언트 제공 값으로 결정 → 권한 상승"

Representative_Healthy_Patterns:
  - "다층 방어: 코드(미들웨어) + DB(보안 규칙) + 컬럼 제한"
  - "모든 HTTP 메서드에 일관된 소유권/역할 검증"
  - "서버가 상태 전이를 검증한 후에만 허용"
```
