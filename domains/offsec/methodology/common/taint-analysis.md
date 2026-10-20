# Source-to-Sink Taint Analysis Protocol (오염 추적 분석)

> A3(데이터 흐름), A4(입출력 경계) 분석 시 각 데이터 경로에 대해
> Source → Propagation → Sink → Sanitization 4단계를 구조적으로 추적합니다.

---

## 설계 원칙

```yaml
Principles:
  Methodology_Not_Patterns: |
    "특정 함수명(db.query, exec)이나 프레임워크 API를 열거하지 않는다.
     '외부 입력이 위험한 동작에 도달하는가?'를 질문하고,
     AI가 프로젝트의 기술 스택에 맞는 구체적 경로를 자율 추적한다."
  
  Every_Path_Matters: |
    "메인 경로뿐 아니라 에러 핸들러, 폴백, 캐시 경유,
     비동기 큐 소비자, 배치 작업 등 모든 경로를 추적한다.
     '이 경로는 사용되지 않는다'는 가정을 하지 않는다."
  
  Sanitization_Must_Match_Sink: |
    "검증/이스케이프가 존재하더라도 해당 Sink 유형에 적합한지 확인한다.
     SQL 이스케이프는 XSS를 막지 못하고, HTML 인코딩은 SQL 인젝션을 막지 못한다."
```

---

## 4단계 추적 절차

```yaml
Step_1_Source_Identification:
  질문: "외부 입력이 시스템에 진입하는 모든 지점은 어디인가?"
  탐색_방향:
    직접_입력: |
      HTTP 요청 (body, query, params, headers, cookies),
      WebSocket 메시지, gRPC 요청, GraphQL 변수,
      파일 업로드 내용, CLI 인자
    간접_입력: |
      데이터베이스 읽기 (다른 사용자가 저장한 값 — 2차 인젝션 후보),
      외부 API 응답 (신뢰 불가 — SSRF 체인),
      메시지 큐 소비 (다른 서비스가 생산한 메시지),
      캐시 읽기 (오염된 캐시 값)
    지연_입력: |
      환경변수/설정 파일 (배포 시 주입),
      스케줄러 파라미터, 웹훅 페이로드
  output: "Source 목록 (각각에 신뢰 수준 태그: untrusted / semi-trusted / trusted)"

Step_2_Propagation_Tracing:
  질문: "이 입력이 코드를 거치며 어떤 경로로 전달되는가?"
  추적_방법: |
    Source에서 시작하여 함수 호출 체인을 따라간다:
    - 변수 할당, 함수 인자, 반환값, 콜백 파라미터
    - 문자열 연결/보간/템플릿 리터럴
    - 객체 속성 복사, 스프레드, 디스트럭처링
    - 캐시/세션/글로벌 상태 저장 → 다른 요청에서 재사용
    - 직렬화 → 큐/DB 저장 → 역직렬화 → 다른 서비스에서 사용
  주의: |
    ⚠️ "변환되었으므로 안전하다" 가정 금지.
    변환이 보안 목적인지, 해당 Sink에 적합한 변환인지 Step 4에서 확인한다.
    경로가 여러 파일/서비스를 횡단하면 모든 경유지를 기록한다.

Step_3_Sink_Detection:
  질문: "이 데이터가 최종적으로 위험한 동작에 도달하는가?"
  위험_동작_유형: |
    AI가 프로젝트의 기술 스택에서 아래 유형의 동작을 자율 식별한다:
    - 쿼리 실행 (SQL, NoSQL, GraphQL, ORM raw query)
    - 명령 실행 (OS shell, 프로세스 생성)
    - 파일 시스템 접근 (경로 구성, 파일 읽기/쓰기)
    - HTML/템플릿 렌더링 (브라우저 출력)
    - HTTP/네트워크 요청 구성 (URL, 헤더)
    - 역직렬화 (신뢰 불가 데이터의 객체 복원)
    - 리다이렉트/포워드 (URL 구성)
    - 로그 출력 (로그 인젝션)
    - 이메일/알림 구성 (헤더 인젝션)
  output: "Sink 목록 (각각에 위험 유형 태그)"

Step_4_Sanitization_Verification:
  질문: "Source에서 Sink까지의 경로에 적절한 검증이 있는가?"
  확인_항목:
    존재: "경로상에 검증/이스케이프/인코딩이 존재하는가?"
    위치: "검증이 Source 직후인가, Sink 직전인가, 중간인가?"
    적합성: "검증이 이 특정 Sink 유형에 적합한가? (SQL ≠ XSS ≠ Shell)"
    완전성: "모든 경로에 적용되는가? (정상 경로 + 에러 경로 + 폴백)"
    우회: "검증을 우회할 수 있는 대안 경로가 있는가?"
    프레임워크: "프레임워크 자동 검증에 의존 시 해당 기능이 활성화 + 이 경로에 적용되는가?"
  판정:
    Sanitized: "적합한 검증이 모든 경로에 적용 → 안전"
    Partial: "일부 경로만 검증, 또는 Sink 유형에 부적합한 검증 → Finding"
    None: "검증 없음 → Finding"
    Bypassed: "검증 존재하나 우회 경로 발견 → Finding"
```

---

## 적용 시점

```yaml
Integration:
  Phase_1_A3: "데이터 흐름 분석 시 Trust Boundary 교차 지점에서 이 프로토콜 적용"
  Phase_1_A4: "입출력 경계 분석 시 모든 외부 입력 경로에 이 프로토콜 적용"
  Phase_2_Deep: "Phase 1에서 후보가 발견되면 전체 체인을 이 프로토콜로 정밀 추적"
  Depth_Files: "특정 Sink 유형의 심층 분석 필요 시 depth/ 파일과 결합"
  
  로딩: "Phase 1 진입 시 A3/A4 차원과 함께 로드. Phase 2 완료 후 해제."
  
  note: |
    이 프로토콜은 A3/A4 차원의 Review Perspective를 대체하지 않는다.
    차원이 "무엇을 볼 것인가"를 정의하고,
    이 프로토콜이 "어떻게 추적할 것인가"를 정의한다.
```
