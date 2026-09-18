# Phase 3: 보안 표준 준수 점검

### OWASP Top 10 (2021) 매핑

모든 발견 사항을 OWASP Top 10 카테고리에 매핑합니다.

```yaml
OWASP_Top10_2021:
  A01_Broken_Access_Control:
    관련_차원: A1, A2, BaaS_DB
    점검: "인증 우회, 인가 누락, IDOR, 권한 상승, CORS, DB 직접 접근, RLS 미적용"

  A02_Cryptographic_Failures:
    관련_차원: A5
    점검: "민감 데이터 평문 전송/저장, 약한 알고리즘, 하드코딩 키"

  A03_Injection:
    관련_차원: A4
    점검: "SQL Injection, NoSQL Injection, OS Command Injection, XSS"

  A04_Insecure_Design:
    관련_차원: "전체 아키텍처"
    점검: "위협 모델링 부재, 안전하지 않은 기본값, BaaS 직접 접근 설계"

  A05_Security_Misconfiguration:
    관련_차원: A5, A7
    점검: "불필요한 기능 활성화, 기본 계정, 정보 노출, CORS 와일드카드"

  A06_Vulnerable_Components:
    관련_차원: A6
    점검: "알려진 CVE 의존성, 미업데이트 라이브러리"

  A07_Auth_Failures:
    관련_차원: A1
    점검: "약한 비밀번호 정책, 브루트포스 미방어, MFA 부재"

  A08_Data_Integrity_Failures:
    관련_차원: A3, A5
    점검: "CI/CD 무결성, 안전하지 않은 직렬화"

  A09_Logging_Monitoring:
    관련_차원: A7
    점검: "보안 이벤트 로깅 여부, 감사 로그 무결성"

  A10_SSRF:
    관련_차원: A6
    점검: "사용자 입력 URL로 서버 측 HTTP 요청"
```

### OWASP API Security Top 10 (2023) 매핑

API 엔드포인트가 존재하는 경우에만 수행합니다.

```yaml
OWASP_API_Top10_2023:
  API1_BOLA: "ID 기반 리소스 접근 시 소유권/권한 검증"
  API2_Broken_Auth: "인증 플로우 결함"
  API3_BOPLA: "Mass Assignment, 응답 과도한 데이터"
  API4_Resource_Consumption: "Rate limiting, 페이지네이션, 크기 제한"
  API5_Function_Auth: "관리자 전용 기능 역할 체크"
  API6_Business_Flow: "비즈니스 플로우 보호"
  API7_SSRF: "서버 측 요청 위조"
  API8_Misconfiguration: "CORS, 보안 헤더, TLS, 에러"
  API9_Improper_Inventory: "미사용/폐기 API, 버전 관리"
  API10_Unsafe_Consumption: "외부 API 응답 검증"
```

### OWASP Top 10 for LLM Applications (2025) 매핑

AI/ML 도메인이 활성인 경우에만 수행합니다.

```yaml
OWASP_LLM_Top10_2025:
  LLM01_Prompt_Injection: "직접/간접 프롬프트 인젝션"
  LLM02_Sensitive_Information_Disclosure: "민감 데이터 LLM 유출"
  LLM03_Supply_Chain: "모델/플러그인 공급망 보안"
  LLM04_Data_and_Model_Poisoning: "학습/RAG 데이터 오염"
  LLM05_Improper_Output_Handling: "LLM 출력 미검증 사용"
  LLM06_Excessive_Agency: "과도한 에이전트 권한"
  LLM07_System_Prompt_Leakage: "시스템 프롬프트 유출"
  LLM08_Vector_and_Embedding_Weaknesses: "벡터/임베딩 취약점"
  LLM09_Misinformation: "환각 기반 잘못된 정보"
  LLM10_Unbounded_Consumption: "무제한 리소스 소비"
```

### Secure Coding Guide 준수 점검

```yaml
SecureCoding_점검:
  SC-001_입력검증: "모든 외부 입력에 대한 서버 측 검증"
  SC-002_출력인코딩: "출력 컨텍스트에 맞는 인코딩 적용"
  SC-003_에러처리: "에러 처리에서 내부 정보 미노출"
  SC-004_로깅: "로깅 시 민감 정보 마스킹"
  SC-005_난수생성: "보안 목적 난수에 CSPRNG 사용"
  SC-006_타이밍공격방어: "시크릿 비교 시 constant-time"
  SC-007_리소스관리: "파일/DB 핸들 해제, 타임아웃"
  SC-008_시크릿관리: "환경 변수 또는 비밀 관리 서비스"
  SC-009_HTTP보안헤더: "CSP, HSTS, X-Content-Type, SameSite"
  SC-010_의존성관리: "알려진 취약점 의존성"
```

### NIST 보안 프레임워크 참조 (regulated 레벨만)

```yaml
NIST_컨트롤:
  AC_Access_Control: "최소 권한, 역할 분리, 로그인 실패 제한"
  AU_Audit: "감사 이벤트 정의, 레코드 내용, 무결성"
  IA_Identification_Authentication: "사용자 식별, 인증 자격 관리"
  SC_System_Communications: "전송 데이터 보호, 키 관리, 승인 알고리즘"
  SI_System_Information_Integrity: "패치 관리, 입력 검증, 에러 처리"
  CM_Configuration_Management: "기준 구성, 최소 기능 원칙"
```
