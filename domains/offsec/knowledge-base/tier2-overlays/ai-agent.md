---
phases: [va, pentest, verify]
keywords: [llm, prompt-injection, ai, agent, ml]
---
# Tier 2 Overlay: AI/Agent 플랫폼

> AI/ML 또는 LLM 기반 에이전트 플랫폼이 감지된 프로젝트에 적용.
> LLM 통합, 에이전트 오케스트레이션, 벡터 DB, 도구 사용(function calling) 등.

---

## A1 인증 (Authentication)

```yaml
Agent_Auth_Isolation:
  question: "에이전트/사용자 간 인증이 격리되는가?"
  trace: |
    1. 에이전트가 사용하는 API 키와 사용자 인증이 분리되는가?
    2. 에이전트가 사용자 대신 인증할 때 위임 범위(scope)가 제한되는가?
    3. 멀티 에이전트 환경에서 에이전트 간 인증 토큰이 공유되지 않는가?

LLM_API_Key_Exposure:
  question: "LLM API 키가 클라이언트/프론트엔드에 노출되는가?"
  trace: |
    1. LLM API 호출이 서버 사이드에서만 수행되는가?
    2. 프론트엔드 코드에 API 키가 하드코딩되어 있지 않은가?
    3. 프록시 서버를 통한 LLM 호출 시 인증이 적절한가?
```

## A2 인가 (Authorization)

```yaml
Tool_Access_Scope:
  question: "LLM 에이전트의 도구(function calling) 접근 범위가 제한되는가?"
  trace: |
    1. 에이전트가 사용 가능한 도구 목록이 화이트리스트로 관리되는가?
    2. 파일 시스템, DB, 네트워크 접근이 샌드박스로 격리되는가?
    3. 에이전트가 생성한 코드 실행이 격리된 환경(sandbox, container)에서 수행되는가?
    4. 에이전트의 도구 호출에 사용자별 권한 검증이 있는가?

Agent_Action_Audit:
  question: "에이전트가 수행한 액션이 감사 추적 가능한가?"
  trace: |
    1. 에이전트의 모든 도구 호출이 로깅되는가?
    2. 어떤 사용자 요청에 의해 어떤 액션이 수행되었는지 추적 가능한가?
    3. 에이전트의 자율 액션(human approval 없는)에 대한 제한이 있는가?
```

## A3 데이터흐름 (Data Flow)

```yaml
PII_to_LLM:
  question: "민감 데이터(PII)가 LLM API로 전송되는가?"
  trace: |
    1. 사용자 PII(이름, 이메일, 주소 등)가 프롬프트에 포함되어 외부 LLM API로 전송되는가?
    2. PII 마스킹/익명화 처리가 LLM 호출 전에 수행되는가?
    3. LLM 호출 로그에 민감 프롬프트/응답이 기록되는가?
    4. 사용자에게 데이터가 외부 LLM으로 전송된다는 고지가 있는가?

Conversation_Data_Retention:
  question: "대화 데이터의 보관/삭제 정책이 있는가?"
  trace: |
    1. 대화 기록이 무기한 보관되는가?
    2. 사용자 삭제 요청 시 관련 대화/임베딩이 함께 삭제되는가?
    3. 벡터 DB에 저장된 임베딩에서 원문 복원이 가능한가?
```

## A4 IO (Input/Output Validation)

```yaml
Prompt_Injection:
  question: "사용자 입력이 프롬프트 인젝션에 안전한가?"
  trace: |
    1. 사용자 입력이 시스템 프롬프트와 명확히 분리되는가?
    2. 사용자가 시스템 프롬프트를 덮어쓰거나 무시하게 하는 입력이 가능한가?
    3. 입력 길이 제한이 있어 과도한 토큰 소비가 방지되는가?
    4. 간접 인젝션(문서/URL 내 악성 지시)에 대한 방어가 있는가?

LLM_Output_Safety:
  question: "LLM 출력이 안전하게 처리되는가?"
  trace: |
    1. LLM 출력이 코드 실행 컨텍스트(eval, exec, shell)에 전달되는가?
    2. LLM 출력이 DB 쿼리에 직접 포함되는가? (SQL injection via LLM)
    3. LLM 출력이 HTML로 렌더링될 때 XSS 방지가 있는가?
    4. LLM이 생성한 URL이 사용자에게 표시될 때 검증이 있는가?
```

## A5 시크릿 (Secret Management)

```yaml
Agent_Secret_Isolation:
  question: "에이전트 간 시크릿이 격리되는가?"
  trace: |
    1. 멀티 에이전트 환경에서 각 에이전트의 API 키/토큰이 격리되는가?
    2. 에이전트가 접근한 시크릿이 대화 응답에 노출되는가?
    3. 도구 호출 시 전달되는 시크릿이 로그에 기록되지 않는가?
```

## A6 의존성 (Dependencies)

```yaml
LLM_Response_Trust:
  question: "LLM 응답을 맹신하지 않는가?"
  trace: |
    1. LLM 응답이 검증 없이 비즈니스 로직에 사용되는가?
    2. LLM이 결정하는 사항에 human-in-the-loop가 있는가?
    3. LLM 환각(hallucination)이 비즈니스 영향을 미칠 수 있는 경로가 있는가?
    4. LLM 모델 변경/업데이트 시 출력 품질 검증 프로세스가 있는가?

Vector_DB_Integrity:
  question: "벡터 DB 데이터의 무결성이 보장되는가?"
  trace: |
    1. 임베딩 업데이트 시 원자성이 보장되는가?
    2. 벡터 DB 접근 권한이 적절히 제한되는가?
    3. 악의적인 문서 삽입으로 검색 결과가 오염되는가? (data poisoning)
```

## A7 에러 (Error Handling)

```yaml
LLM_Parsing_Failure:
  question: "LLM 응답 파싱 실패 시 fallback이 안전한가?"
  trace: |
    1. JSON/구조화된 응답 파싱 실패 시 재시도 로직이 있는가?
    2. 파싱 실패가 사용자에게 에러 메시지로 적절히 전달되는가?
    3. 파싱 실패한 원본 응답이 사용자에게 그대로 노출되는가?

LLM_Rate_Limit:
  question: "LLM API rate limit/타임아웃 시 사용자 경험이 graceful한가?"
  trace: |
    1. rate limit 도달 시 재시도 전략(exponential backoff)이 있는가?
    2. 타임아웃 시 부분 응답이 안전하게 처리되는가?
    3. 스트리밍 응답 중단 시 불완전한 데이터가 사용자에게 전달되지 않는가?
```

## A8 리소스 (Resource Consumption)

```yaml
Token_Cost_DoS:
  question: "LLM 토큰 사용량에 per-user/per-request 제한이 있는가?"
  trace: |
    1. 단일 요청의 최대 토큰 수가 제한되는가?
    2. 사용자별 일/월 토큰 사용량 한도가 있는가?
    3. 토큰 사용량이 모니터링/알림되는가?
    4. 무한 루프 에이전트(자기 참조 대화)가 방지되는가?

Concurrent_Agent_Limit:
  question: "동시 실행 에이전트 수가 제한되는가?"
  trace: |
    1. per-user 동시 에이전트/대화 수 제한이 있는가?
    2. 에이전트 큐(대기열) 관리가 있는가?
    3. 벡터 DB 크기 제한이 있는가? (무한 문서 삽입 방지)

LLM_Streaming_Buffer:
  question: "LLM 스트리밍 응답의 메모리 버퍼가 제한되는가?"
  trace: |
    1. SSE/WebSocket 스트리밍 버퍼에 크기 제한이 있는가?
    2. 클라이언트 연결 끊김 시 서버 사이드 스트리밍이 즉시 중단되는가?
```
