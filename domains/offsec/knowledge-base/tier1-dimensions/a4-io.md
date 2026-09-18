---
phases: [va, verify, pentest, converge, report]
---
# A4: 입출력 경계 (Input/Output Boundary)

```yaml
Core_Architecture_Questions:
  - "입력은 어디서 어떻게 검증되고, 출력은 컨텍스트에 맞게 보호되는가?"
  - "검증/인코딩이 체계적으로 설계되었는가, 즉흥적인가?"
  - "검증 전략이 전체 프로젝트에서 일관적인가?"

Review_Perspectives:

  Backend:
    Input_Validation_Strategy:
      question: "입력 검증이 체계적으로 설계되었는가?"
      review: |
        - 프로젝트 전체에서 일관된 검증 도구/전략이 사용되는가?
        - 검증 누락 엔드포인트가 있는가?

    Cross_Handler_Validation_Consistency:
      question: "동일한 파라미터가 여러 핸들러에서 사용될 때 검증 수준이 동일한가?"
      methodology: |
        동일한 논리적 파라미터가 여러 API 경로를 통해 진입하는 경우
        각 경로의 검증 수준이 일관적인지 교차 대조한다:
        1. 동일 파라미터가 사용되는 모든 핸들러를 식별한다.
           (예: userId, index, chainId 등이 GET query, POST body,
           URL path 등 다른 진입 경로로 수신되는 경우)
        2. 각 핸들러에서 해당 파라미터의 검증 조건을 비교한다:
           - 타입 캐스트 안전성 (int→uint32, string→int 등)
           - 범위 검증 (음수, 오버플로우, 경계값)
           - 형식 검증 (길이, 패턴, 허용 문자)
        3. 한 핸들러에는 검증이 있고 다른 핸들러에는 없는 경우
           누락된 경로가 우회 벡터가 되는지 판단한다.
        4. 검증이 공통 함수/미들웨어에서 수행되는지,
           각 핸들러에서 개별 구현되는지 확인한다.
           개별 구현은 비일관성의 근본 원인이 된다.

    Query_Construction:
      question: "사용자 입력이 DB 쿼리 생성에 안전하지 않게 포함되는가?"
      methodology: |
        인젝션 탐지는 언어별 grep 패턴이 아닌 행위를 추적:
        1. 사용자 입력이 DB 쿼리로 흐르는 모든 경로 식별
        2. 각 경로에서 쿼리 생성 방식 확인:
           - 파라미터화 쿼리/바인딩 사용?
           - 문자열 연결/보간/포맷팅으로 쿼리 생성?
        3. ORM 사용해도 raw query/직접 SQL 실행으로 우회하는 곳?

    File_Upload:
      question: "파일 업로드 처리에 체계적 검증 아키텍처가 있는가?"
      review: |
        - 확장자 화이트리스트, MIME 검증, 크기 제한이 모두 적용되는가?
        - 업로드 파일이 별도 스토리지에 격리되는가?
        - 압축 파일(zip/tar/gzip)의 압축 해제 경로가 Zip Slip(../)으로
          원본 디렉토리를 벗어날 수 없는가?
        - 이미지 파일에 EXIF / polyglot 공격(GIFAR, phar 스트림)이 고려되는가?

    XML_Parsing_Safety:
      question: "XML 파서가 외부 엔티티/DOCTYPE/DTD를 안전하게 처리하는가? (XXE, CWE-611)"
      methodology: |
        XML 입력이 들어오는 모든 경로를 식별한 후, 파서 구성이 다음 모두를
        만족하는지 확인한다:
        1. DOCTYPE 선언이 비활성화되었는가?
           (setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            또는 expatExternalEntityLoader = None 등 언어·라이브러리별 구성)
        2. 외부 엔티티(general/parameter entity) 확장이 차단되었는가?
        3. XInclude 처리가 비활성화되었는가?
        4. Billion Laughs / Quadratic Blowup에 대한 엔티티 확장 한도가 있는가?
        5. SOAP/SAML/XML-RPC 사용 시 서명 검증 전에 파싱이 일어나지 않는가?
      anti_patterns:
        - "Python: xml.etree.ElementTree.parse 기본값 (DTD 로드됨)"
        - "Java: DocumentBuilderFactory에 disallow-doctype-decl 미설정"
        - "Node: libxmljs parseXmlString(xml, { noent: true }) 같이 엔티티 활성화"
        - "SAML IdP metadata를 검증 없이 파싱"
      references: [CWE-611, CWE-776, CWE-827]

    Deserialization_Safety:
      question: "신뢰되지 않는 바이트스트림을 역직렬화할 때 gadget chain 또는
                 타입 혼동이 가능한가? (CWE-502)"
      methodology: |
        다음 패턴이 사용자 입력 경로에 존재하는지 검색:
          - Python: pickle.loads, marshal.loads, yaml.load(Loader 미지정/FullLoader),
                    jsonpickle.decode, dill, shelve
          - Java: ObjectInputStream.readObject, XMLDecoder, XStream 기본 구성,
                  SnakeYAML new Yaml()
          - Node: node-serialize, unserialize-javascript, eval 기반 JSON 파서,
                  prototype pollution 경로 (lodash merge, set, Object.assign)
          - Ruby: Marshal.load, YAML.load (Psych safe_load 아님)
          - .NET: BinaryFormatter, SoapFormatter, DataContractSerializer with
                  KnownTypes 미설정
        각 사용처에서:
          1. 입력 출처가 신뢰되는가? (사용자/외부 / 내부 / 상수)
          2. 안전 변형(safe_load, 명시적 타입 스키마)으로 대체 가능한가?
          3. gadget chain 방지 allowlist가 있는가?
      anti_patterns:
        - "yaml.load(request_body) — FullLoader/SafeLoader 미사용"
        - "Object.assign({}, untrustedBody) — __proto__ 오염"
      references: [CWE-502, CWE-915, CWE-1321]

  Batch_Worker:
    Job_Payload_Validation:
      question: "배치 작업 페이로드가 검증되는가?"
      methodology: |
        큐/이벤트에서 수신하는 작업 페이로드의 검증을 분석:
        1. 페이로드 스키마 검증이 있는가? (필수 필드, 타입, 범위)
        2. 페이로드가 직접 DB 쿼리에 사용될 때 인젝션 방지가 있는가?
        3. 대량 처리 시 개별 항목의 검증 실패가 전체 배치를 중단하는가,
           해당 항목만 건너뛰는가?
        4. 재시도 시 페이로드가 변조될 수 있는 경로가 있는가?

  Frontend:
    Rendering_Security:
      question: "사용자 입력이 안전하게 렌더링되는가?"
      methodology: |
        프레임워크의 "안전하지 않은 HTML 삽입" API를 식별:
        - 각 프레임워크에는 이스케이핑을 우회하는 HTML 삽입 API가 있음
        - 이런 API가 사용되는 곳에 새니타이징이 적용되는가?

    Numeric_Parameter_Safety:
      question: "숫자형 파라미터의 타입 변환이 안전한가?"
      review: |
        - Number(param) 변환 후 NaN 체크가 있는가?
        - parseInt/parseFloat 사용 시 radix 지정이 있는가?
        - NaN이 DB 쿼리에 전달될 때 예기치 않은 결과가 발생하는가?

  BaaS_DB:
    Dynamic_SQL:
      question: "DB 함수 내 동적 SQL에 사용자 입력이 안전하지 않게 포함되는가?"

  AI_ML:
    Prompt_Injection_Boundary:
      question: "사용자 입력이 LLM 프롬프트에 안전하지 않게 삽입되는가?"
      methodology: |
        LLM 호출 경로를 추적하여 프롬프트 구성 방식을 분석:
        1. 사용자 입력이 프롬프트에 포함되는 모든 경로 식별
        2. 시스템 프롬프트와 사용자 입력의 분리 방식:
           - 문자열 연결로 단일 프롬프트에 합성되는가?
           - 역할 분리(system/user/assistant)가 적용되는가?
        3. 간접 프롬프트 인젝션 경로:
           - DB/벡터 스토어에서 검색된 콘텐츠가 프롬프트에 삽입되는가?
           - 해당 콘텐츠는 외부 사용자가 작성 가능한가? (UGC → RAG → 프롬프트)

    LLM_Output_Handling:
      question: "LLM 출력이 안전하게 처리되는가?"
      methodology: |
        LLM 응답이 사용되는 모든 경로를 추적:
        1. LLM 출력이 코드 실행 컨텍스트에 전달되는가? (eval, exec, shell)
        2. LLM 출력이 DB 쿼리에 포함되는가?
        3. LLM 출력이 HTML로 렌더링되는가? (XSS via LLM)
        4. LLM 출력이 파일 시스템 작업에 사용되는가? (경로 조작)
        5. LLM의 구조화된 출력(JSON 등)이 검증 없이 파싱/사용되는가?

  SDK:
    Developer_Input_Validation:
      question: "SDK가 개발자로부터 받는 입력을 검증하는가?"
      methodology: |
        SDK 공개 API의 파라미터 검증을 추적:
        1. 초기화 파라미터: API 키 형식, 필수 설정값,
           URL 형식 등이 검증되는가?
        2. 메서드 파라미터: 각 공개 메서드의 인자에
           타입 검증, 범위 검증, null 검사가 있는가?
        3. 설정 객체: 잘못된 설정 조합
           (예: TLS 비활성화 + 프로덕션 모드)을 감지하고 경고하는가?
        4. 검증 실패 시 에러 메시지가 명확하고
           수정 방향을 안내하는가?

    Backend_Response_Handling:
      question: "SDK가 백엔드 응답을 안전하게 처리하는가?"
      methodology: |
        SDK의 네트워크 응답 처리를 추적:
        1. 응답 스키마 검증: 예상 형식과 다른 응답에 대한 처리
        2. 악의적 응답 방어: MITM 상황에서 변조된 응답이
           SDK 내부 상태를 오염시킬 수 있는가?
        3. 에러 응답 처리: 서버 에러가 개발자에게 적절히
           변환되어 전달되는가, 그대로 전파되는가?

Representative_Anti_Patterns:
  - "일부 API는 스키마 검증, 일부는 수동, 일부는 없음 → 비일관적"
  - "대부분 파라미터화 쿼리이나 일부 문자열 연결 → 혼재"
  - "사용자 입력이 CSP 없이 HTML로 직접 렌더링 → 방어 심층 부재"
  - "사용자 입력이 문자열 연결로 시스템 프롬프트에 합성 → 프롬프트 인젝션"
  - "LLM 출력이 검증 없이 eval/exec에 전달 → 코드 실행"
  - "동일 파라미터가 GET 핸들러에서는 범위 검증, POST 핸들러에서는 미검증 → 우회 경로"

Representative_Healthy_Patterns:
  - "단일 검증 전략이 프로젝트 전체에 일관되게 적용"
  - "모든 DB 쿼리가 파라미터화 방식으로 통일"
  - "CSP 설정 + nonce 기반 스크립트 + 체계적 새니타이즈 라이브러리 적용"
  - "LLM 프롬프트에서 시스템/사용자 역할 명확히 분리"
  - "LLM 출력에 대해 컨텍스트별 검증/새니타이징 적용"
  - "파라미터 검증이 공통 함수/미들웨어에서 수행되어 모든 핸들러에 일관 적용"
```
