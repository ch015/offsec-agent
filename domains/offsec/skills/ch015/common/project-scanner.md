# 대규모 프로젝트 스캐너 (Project Scanner — Tier 0)

> 대규모 프로젝트(다수 서브프로젝트, 소스 파일 500+)를 빠르게 스캔하여
> 보안 표면 맵을 생성합니다. 전체 코드를 읽지 않고
> 구조/설정/라우트 등록/import 패턴만 분석합니다.

---

## 설계 원칙

```yaml
Principles:
  Speed_Over_Depth: |
    Tier 0는 정밀 분석이 아니다. 목적은:
    - 프로젝트를 독립 분석 단위(Unit)로 분해
    - 각 Unit에서 보안 관련 파일만 식별
    - 전체 API 표면과 인증 구조 개요 파악
    전체 코드를 읽지 않는다. 구조와 진입점만 파악한다.

  Grep_Not_Read: |
    파일 내용은 Grep으로 패턴 매칭만 수행한다.
    파일을 처음부터 끝까지 Read하지 않는다.
    예외: 설정 파일(config, env, Dockerfile)은 전체 Read 허용.

  Compact_Output: |
    출력은 구조화된 YAML로 압축한다.
    후속 Tier에서 사용할 메타데이터만 포함한다.
    산문형 분석 보고서를 작성하지 않는다.
```

---

## 실행 모델

```yaml
Model: haiku
이유: |
  Tier 0는 패턴 매칭과 구조 파싱만 수행한다.
  추론 깊이가 필요 없으므로 Haiku로 충분하며
  비용을 98% 절감한다 (Opus $15 → Haiku $0.25 per 1M input).
```

---

## Phase 구조

```
Phase S0: 서브프로젝트 탐지 → Unit Manifest
Phase S1: Unit별 기술 스택 식별
Phase S2: Unit별 보안 표면 파일 식별
Phase S3: 전체 API 인벤토리 + 인증 구조 개요
Phase S4: 대형 Unit 분할 판단
Phase S5: 출력 (security_surface_map.yaml)
```

---

## Phase S0: 서브프로젝트 탐지

```yaml
Phase_S0:
  방법: |
    프로젝트 루트의 디렉토리 구조를 분석하여
    독립 빌드/배포 가능한 서브프로젝트를 식별한다.

  탐지_기준:
    - "자체 의존성 파일 보유 (package.json, go.mod, requirements.txt, Cargo.toml)"
    - "자체 Dockerfile 보유"
    - "자체 main/entry point 보유"
    - "독립 디렉토리에 위치"

  출력:
    unit_manifest:
      - unit_id: "U{N}"
        name: "서브프로젝트명"
        path: "상대 경로"
        type: "backend | frontend | indexer | worker | contract | sdk"
        lang: "Go | TypeScript | Python | Rust | Solidity"
        estimated_lines: "N (Glob으로 파일 수 × 평균 추정)"
```

---

## Phase S1: 기술 스택 식별

```yaml
Phase_S1:
  방법: |
    각 Unit의 의존성 파일과 설정 파일만 Read하여 기술 스택을 식별한다.
    소스코드는 읽지 않는다.

  읽는_파일:
    - "package.json (dependencies 섹션만)"
    - "go.mod (require 블록만)"
    - "Dockerfile"
    - "docker-compose.yml (해당 시)"
    - "*.env.example, *.env.* (변수 이름만 — 값은 무시)"
    - "설정 파일 (config.*, .env.example)"

  추출_정보:
    - framework: "Express, Gin, Next.js, Echo, ..."
    - auth_library: "NextAuth, jwt-go, passport, ..."
    - database: "PostgreSQL, Redis, MongoDB, ..."
    - blockchain: "ethers, web3, go-ethereum, ..."
    - deployment: "Serverless, Container, Traditional"
```

---

## Phase S2: 보안 표면 파일 식별

```yaml
Phase_S2:
  방법: |
    Grep 도구로 보안 관련 패턴을 검색하여
    보안 분석이 필요한 파일만 식별한다.
    파일 내용을 읽지 않고 파일 경로만 수집한다.
    
    # ─── P2-8: AST 기반 탐지로 전환 (단계적) ─────────────────
    # 장기 목표: 정규식에서 tree-sitter 쿼리(언어별 AST)로 이행.
    # 단계:
    #   1) 현재(regex)를 1차 후보 필터로 유지 (빠른 globbing)
    #   2) AST 단계를 추가하여 false positive 축소:
    #      - Go/TS/JS/Python/Java에 대해 tree-sitter parser를 사용해
    #        router 등록, handler 정의, DB access call site를 의미 수준에서 식별
    #      - 커스텀 래퍼 함수(예: app.route2(), db.exec2())도 동명 규칙이 아닌
    #        호출 체인으로 탐지
    #   3) 고위험 유틸 탐지: verifyJWT / decrypt / exec / eval / deserialize /
    #      fetch / query 같은 함수의 호출 밀도가 임계 이상인 파일을 자동 승격
    #   4) 파일명 기반 휴리스틱('utils', 'common')으로 제외 금지 — 고위험 유틸이
    #      이런 경로에 숨는 경우가 많음
    # 구현체 위치: lib/scanner/ast/*.js (tree-sitter-grammars bundle 예정)
    # 현재는 규약(convention)만 문서화 — 하네스 데이터셋(P2-5)에서 recall이
    # 목표치에 도달하지 않을 때 AST 단계를 실제 활성화한다.

  보안_표면_카테고리:

    entry_points:
      설명: "외부 요청을 받는 라우트/핸들러"
      탐색: |
        Grep으로 파일 경로만 수집 (output_mode: files_with_matches):
        - Go: "func.*Handler|router\.(GET|POST|PUT|DELETE|PATCH)|\.HandleFunc"
        - TS/JS: "app\.(get|post|put|delete|patch)|router\.|export.*route|NextResponse"
        - Python: "@app\.(get|post|route)|urlpatterns"

    auth_files:
      설명: "인증/인가 관련 파일"
      탐색: |
        파일명 패턴: "*auth*, *guard*, *middleware*, *session*, *permission*, *role*"
        코드 패턴: "jwt|token|session|cookie|bearer|oauth|2fa|totp"

    crypto_files:
      설명: "암호화/서명/키 관련 파일"
      탐색: |
        코드 패턴: "sign|verify|encrypt|decrypt|hash|hmac|keccak|ecdsa|private.?key|secret.?key"

    data_access:
      설명: "DB/스토리지 접근 파일"
      탐색: |
        코드 패턴: "SELECT|INSERT|UPDATE|DELETE|\.Query|\.Exec|\.Find|prisma\.|supabase\."
        파일명 패턴: "*repository*, *dao*, *model*, *migration*, *schema*"

    transaction_files:
      설명: "자금/거래 관련 파일 (prediction 특화)"
      탐색: |
        코드 패턴: "withdraw|deposit|transfer|settle|balance|order|trade|bid|payout|refund"

    config_files:
      설명: "보안 설정 파일"
      탐색: |
        파일명: "Dockerfile, docker-compose*, .env*, cors*, nginx*, *.config.*"
        코드 패턴: "CORS|helmet|rate.?limit|csrf|csp|origin"

    contract_files:
      설명: "스마트 컨트랙트 (해당 시)"
      탐색: |
        파일 확장자: "*.sol"
        패턴: "contract |function |modifier |require\\(|msg\\.sender"

  출력:
    security_surface:
      - unit_id: "U1"
        categories:
          entry_points: ["path1.go", "path2.go"]
          auth_files: ["path3.go"]
          crypto_files: ["path4.go"]
          data_access: ["path5.go", "path6.go"]
          transaction_files: ["path7.go"]
          config_files: ["Dockerfile", ".env.example"]
        total_security_files: N
        total_security_lines: N (wc -l로 산출)
```

---

## Phase S2.5: 비즈니스 로직 사각지대 탐색 (Anti-Confirmation-Bias Pass)

> Phase S2의 키워드 매칭은 "보안 = 보안 키워드 포함"이라는 확증편향을 내포한다.
> 이 Phase는 키워드에 매칭되지 않는 파일 중 보안 위험이 있는 파일을 식별한다.

```yaml
Phase_S2_5:
  목적: |
    S2에서 보안 표면으로 분류되지 않은 파일 중
    비즈니스 로직 취약점, 동시성 결함, 정밀도 문제 등
    "보안 키워드 없이 위험한" 파일을 식별한다.
    
    확증편향 차단 원칙:
    "키워드에 매칭되지 않음 ≠ 보안과 무관함"

  탐색_카테고리:

    business_logic:
      설명: "비즈니스 규칙 결함 후보 — 가격/수량/상태 조작 가능성"
      탐색: |
        S2에서 미분류된 파일 중 아래 경로 패턴에 위치한 파일:
        - usecase/, domain/, service/, logic/, core/
        이 파일들은 보안 키워드가 없어도 비즈니스 규칙(가격 결정,
        주문 상태 전이, 환급 조건, 수수료 계산)을 구현하므로
        로직 결함이 CRITICAL 취약점이 될 수 있다.
      분류: "business_logic"

    concurrency:
      설명: "동시성/레이스 컨디션 후보"
      탐색: |
        goroutine/channel/async를 사용하지만
        동기화 메커니즘(mutex, lock, atomic, transaction)이 없는 파일:
        - Go: "go func|goroutine|<-chan" 있으나 "sync\\.Mutex|sync\\.Lock" 없는 파일
        - TS/JS: "Promise\\.all|async.*await" 있으나 트랜잭션 처리 없는 파일
      분류: "concurrency"

    numeric_precision:
      설명: "수치 정밀도 결함 후보 — 금융 연산"
      탐색: |
        부동소수점 또는 큰 수 연산을 사용하는 파일:
        - Go: "float64|float32|big\\.Int|big\\.Float|math\\."
        - TS/JS: "Number|parseFloat|toFixed|BigInt"
        금융/거래 프로젝트에서 정밀도 결함은 자금 손실로 직결.
      분류: "numeric_precision"

    external_io:
      설명: "외부 입출력 — SSRF/응답 신뢰/타임아웃 결함 후보"
      탐색: |
        외부 API 호출을 하지만 S2의 보안 키워드에 매칭되지 않는 파일:
        - HTTP 클라이언트 사용 + 보안 키워드 없음
        - 파일/네트워크 I/O + 입력 검증 키워드 없음
      분류: "external_io"

    sql_construction:
      설명: "SQL 직접 조합 — 인젝션 후보"
      탐색: |
        문자열 연결/포맷으로 SQL을 조합하는 파일:
        - "fmt.Sprintf.*SELECT|INSERT|UPDATE|DELETE"
        - 문자열 + 연산자로 쿼리 구성
        S2의 data_access와 중복될 수 있으나,
        S2에서 누락된 파일을 보완한다.
      분류: "sql_construction"

    generated_code:
      설명: "자동 생성 코드 중 보안 설정 포함 파일"
      탐색: |
        gen/, generated/, proto/ 디렉토리의 파일 중
        gRPC 인터셉터, 검증 로직, 직렬화 설정이 포함된 파일만 식별:
        - "Interceptor|Validator|Marshal|Unmarshal|RegisterService"
        전체 gen/ 코드를 분석하지 않고, 보안 설정 파일만 선별.
      분류: "generated_security_config"

  출력: |
    S2 출력에 아래 카테고리를 추가:
    security_surface:
      - unit_id: "U1"
        categories:
          ... (S2 기존 카테고리) ...
          business_logic: ["path1.go", "path2.go"]
          concurrency: ["path3.go"]
          numeric_precision: ["path4.go"]
          external_io: ["path5.go"]
          sql_construction: ["path6.go"]
          generated_security_config: ["gen/platform/v1/interceptor.go"]

  VA_전달_방식: |
    S2.5에서 식별된 파일은 VA Agent에 별도 카테고리로 전달한다.
    VA Agent는 이 파일들을 "보안 키워드 없이 위험한 파일"로 인지하고
    Phase 2(Deep Analysis)에서 비즈니스 로직/동시성/정밀도 관점으로 분석한다.
    S2 파일(정밀 분석)과 S2.5 파일(경량 분석)의 분석 깊이는 다를 수 있다.
```

---

## Phase S3: API 인벤토리 + 인증 구조 개요

```yaml
Phase_S3:
  방법: |
    entry_points 파일에서 Grep으로 라우트 등록 패턴을 추출하여
    전체 API 엔드포인트 인벤토리를 생성한다.
    인증 미들웨어 적용 여부도 함께 파악한다.

  출력:
    api_inventory:
      - unit_id: "U1"
        endpoints:
          - method: "POST"
            path: "/api/v1/orders"
            auth: "middleware detected" | "no auth detected"
            file: "handlers/order.go:45"
        auth_pattern:
          type: "JWT middleware | session | API key | none detected"
          middleware_file: "middleware/auth.go"
          applied_to: "global | per-route | mixed"

    cross_unit_communication:
      - from: "U1"
        to: "U2"
        protocol: "HTTP | gRPC | message queue | shared DB"
        evidence: "파일명:라인 (Grep 결과)"

    shared_data_map:
      설명: |
        동일 데이터 소스(DB 테이블, Redis 키, 메시지 큐 토픽)에
        접근하는 서비스 쌍을 식별한다.
        이것은 Cross_Reference에서 "암묵적 신뢰" 탐색의 핵심 입력이다.
      탐색: |
        1. 각 Unit의 DB 접근 파일에서 테이블명/컬렉션명을 Grep으로 추출
        2. 동일 테이블에 쓰는 Unit과 읽는 Unit을 매핑
        3. gRPC proto 정의에서 서비스 호출 관계를 추출
        4. 메시지 큐 토픽/이벤트 이름에서 발행/구독 관계를 추출
      출력:
        - resource: "orders 테이블"
          writers: ["U1 (platform-service)", "U3 (chain-indexer)"]
          readers: ["U2 (admin-api)", "U4 (service-api)"]
          validation_gap_risk: |
            writer가 외부 데이터를 검증 없이 쓰고
            reader가 DB 데이터를 무조건 신뢰하면
            검증 갭이 발생한다.
```

---

## Phase S4: 대형 Unit 분할 판단

```yaml
Phase_S4:
  방법: |
    총 라인 수가 임계값을 초과하는 Unit을 내부 모듈 경계에서 서브 Unit으로 분할한다.
    ★ 이 분할은 이제 **게이트로 강제**된다(advisory 아님): source_manifest.units의 유닛 LOC > 40K인데
      이를 덮는 audit 유닛이 ceil(loc/40K) 미만이면 report-gate가 COVERAGE_REQUIRE_SPLIT으로 최종
      보고서를 차단한다(lib/ch015/coverage-gate.js, large-scale flow 한정). 따라서 대형 Unit은 반드시
      sub-unit으로 쪼개 audit해야 발행 가능하다. (davinci src-tauri 71K LOC를 1유닛으로 처리해 Critical
      5건을 놓친 사례의 정면 수정.)

  임계값:
    warning: "20K줄 이상 → 분할 권장"
    required: "40K줄 이상 → 분할 필수(게이트 강제 — 미분할 시 발행 차단)"

  분할_기준:
    - "Go: 패키지 경계 (internal/, pkg/, cmd/)"
    - "TS: 디렉토리 경계 (src/modules/, src/features/)"
    - "도메인 경계 (auth, order, settlement, user)"

  출력:
    split_recommendations:
      - unit_id: "U3"
        reason: "보안 파일 45K줄 — 분할 필수"
        suggested_sub_units:
          - sub_id: "U3a"
            name: "platform-service/auth"
            path: "internal/auth/"
            security_lines: 12000
          - sub_id: "U3b"
            name: "platform-service/trading"
            path: "internal/trading/"
            security_lines: 18000
```

---

## Phase S5: 최종 출력

```yaml
Phase_S5:
  engagement_dir에_저장하는_파일:

    00_scan_manifest.yaml: |
      project_name: "{프로젝트명}"
      scan_date: "YYYY-MM-DD"
      total_units: N
      total_source_lines: N
      total_security_lines: N
      security_ratio: "X%"
      estimated_tier1_cost: "$X-Y"
      units: [unit_manifest 전체]

    00_security_surface_map.yaml: |
      모든 Unit의 보안 표면 파일 목록 (Phase S2 출력 통합)

    00_api_inventory.yaml: |
      전체 API 엔드포인트 인벤토리 (Phase S3 출력)

    00_scan_plan.yaml: |
      Tier 1 실행 계획:
      - batch_1: [U1, U2, U3a] (병렬)
      - batch_2: [U3b, U4, U5] (병렬)
      - ...
      model_routing:
        # 해석 규칙: agentModel.costOptimized=true일 때만 routing.* 값 적용 —
        #            costOptimized=false면 routing을 무시하고 모든 tier를 agentModel.default로 실행
        tier0_scanner: "config.agentModel.routing.tier0_scanner"
        tier1_va: "config.agentModel.routing.tier1_va"
        tier1_verify: "config.agentModel.routing.tier1_verify"
        tier2_deep: "config.agentModel.routing.tier2_deep"
        tier2_pentest: "config.agentModel.routing.tier2_pentest"
      estimated_tokens: {input: N, output: N}
      estimated_cost: "$X"

  Agent_반환_요약: |
    OffSec Lead에 반환하는 요약:
    - total_units: N
    - total_security_files: N
    - total_security_lines: N
    - split_required: [Unit IDs]
    - batch_plan: [batch_1, batch_2, ...]
    - storage_paths: [파일 경로 목록]
```

---

## Anti-Patterns

```yaml
Anti_Patterns:
  Full_Code_Read: |
    Tier 0에서 소스 파일을 처음부터 끝까지 Read하지 않는다.
    목적은 '어디를 볼 것인가'를 결정하는 것이지 '분석'이 아니다.

  Premature_Analysis: |
    보안 이슈를 발견하려 하지 않는다.
    Finding 생성은 Tier 1의 역할이다.
    Tier 0는 지도를 그리는 것이다.

  Over_Classification: |
    보안 표면 분류에서 완벽을 추구하지 않는다.
    누락보다 과포함이 낫다 — Tier 1이 불필요한 파일을 스킵하는 것은 싸지만,
    Tier 0이 보안 파일을 누락하면 Tier 1이 해당 취약점을 영원히 놓친다.
```
