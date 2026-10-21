# 취약점 진단 (Vulnerability Assessment) 방법론

> 문서 안의 `methodology/...`, `knowledge-base/...` 경로는 OffSec 도메인 루트(domains/offsec) 기준이다. 실제 Read는 호스트가 전달한 available_methodology_files의 절대경로로 한다.

> 대상 프로젝트의 소스코드를 아키텍처 차원 기반으로 체계적으로 점검하여
> 보안 메커니즘의 구현 현황과 미적용 영역을 식별합니다.

---

## 설계 원칙: 아키텍처 차원 + 방법론 기반 분석

OWASP/CWE는 보고서의 **참조 태깅**으로만 사용합니다.
분석의 조직 원리는 **8대 보안 아키텍처 차원**입니다.

### 분석 원칙: 방법론, 패턴이 아님

```yaml
Principles:
  No_Pattern_Lists: |
    "특정 프레임워크 구문, grep 패턴, 시크릿 접두사 목록에 의존하지 않는다.
     이런 목록은 닫힌 집합이며, 목록에 없는 위험을 구조적으로 놓친다."

  Use_Methodology: |
    "행위(무엇이 일어나는가)를 질문하고, AI가 감지된 기술 스택에 맞는
     구체적 코드 패턴을 자율적으로 판단하여 탐색한다.
     예: '사용자 입력이 문자열 연결로 쿼리에 삽입되는가?'라고 질문하되
     어떤 언어 구문을 찾을지는 AI가 판단."

  Representative_Examples: |
    "안티패턴/올바른 패턴은 '대표적 예시'로만 제시.
     분석은 이 예시에 한정되지 않으며 — 동일한 구조적 이슈를 가진
     모든 변형이 탐지되어야 한다."

  No_Library_Assumptions: |
    "라이브러리의 존재, 이름, 일반적 평판으로 보안 속성을 추론하지 않는다.
     '라이브러리가 X를 할 수 있다' ≠ '이 프로젝트에서 X가 작동하고 있다.'
     보안 속성은 프로젝트 코드에서 명시적으로 확인 가능할 때만
     '적용됨(Verified)'으로 판단한다.
     확인 불가능하면 '미확인(Unverified)'으로 보고하고,
     미적용 시 영향을 함께 기술한다."
```

## 단계와 산출물

단계 순서·산출물은 호스트와 `methods/analyze.md` 카드가 정한다. 이 문서는 분석 판단 기준만 제공한다.

### 호스트 AST·Semgrep 결과 활용

호스트가 AST·Semgrep을 실행하고 `evidenceIndex`/`evidenceDetails`로 전달한다. taint 후보는 신호일 뿐이며
판단 근거는 실제 코드다. 파싱 실패·미지원 파일은 Grep/Read로 보완한다.

```yaml
AST_활용: |
    "호스트가 전달한 evidenceIndex/evidenceDetails를 Read하여 구조적 사실을 확인하세요.
     이 데이터는 구조적 사실과 taint 후보 신호를 포함하며, 최종 보안 판단은 포함하지 않습니다.
     당신이 직접 보안 판단을 수행해야 합니다:

     - data_flows: 엔트리포인트에서 시작하는 함수 간 파라미터 전달 체인.
       어떤 데이터가 어디로 흘러가는지 구조적으로 보여줍니다.
       이 흐름이 보안상 위험한지는 당신이 코드를 읽고 판단하세요.
     - taint_paths: source→sink 후보 경로입니다.
       후보 신호일 뿐이므로 source/sink 의미, sanitizer 효과, 도달 가능성을 반드시 재확인하세요.
     - call_graph: 함수 호출 관계. 인증/인가 미들웨어 존재 여부,
       특정 함수까지의 도달 경로를 파악하는 데 활용하세요.
     - entry_points: HTTP 라우트 핸들러 목록. 공격 표면 매핑에 활용하세요.
     - semgrep_findings: Semgrep 정적 스캔 결과 (있는 경우).

     AST 데이터는 구조적 지도와 후보 신호이며, 보안 판단의 근거는 코드 자체입니다."

  AST_차원별_활용:
    A1_인증: "콜 그래프에서 핸들러 호출 경로에 인증 관련 함수 존재 여부 확인"
    A2_인가: "엔트리포인트별 미들웨어/데코레이터 호출 패턴 분석"
    A3_데이터흐름: "data_flows에서 파라미터 전달 체인을 따라 위험 판단"
    A4_입출력: "data_flows의 terminal 호출과 arguments를 기반으로 데이터 노출 여부 판단"
    A5_비밀관리: "Semgrep 시크릿·설정 관련 룰 결과 참조"
    A6_의존성: "Semgrep findings + entry_points 기반 외부 의존성 분석"
    A7_에러처리: "콜 그래프의 함수 범위에서 try-catch 구조 분석, data_flows에서 로깅 함수로의 데이터 전달 경로 추적"
    A8_리소스: "entry_points·data_flows에서 비신뢰 입력이 반복·할당·외부 호출 규모에 닿는 경로 확인"
```

---

## 보안 아키텍처 차원 리뷰 (A1–A8)

### 도메인별 체크리스트

활성 도메인에 따라 아래 체크리스트를 추가 로드합니다:

```yaml
Checklists:
  Backend_API: "methodology/va/checklists/api.yaml → API 엔드포인트 보안 점검"
  Web_Application: "methodology/va/checklists/web-app.yaml → 웹 앱 클라이언트 보안 점검"
  Database_Layer: "methodology/va/checklists/db-layer.yaml → DB 접근 계층 보안 점검"
  Native_Client: "methodology/va/checklists/native-client.yaml → 네이티브 클라이언트/게임 SDK 보안 점검"
  Loading_Rule: |
    담당 범위에서 확인된 활성 도메인에 해당하는 체크리스트만 로드한다.
    - Backend 도메인 활성 → api.yaml 로드
    - Frontend 도메인 활성 → web-app.yaml 로드
    - BaaS/DB 도메인 활성 → db-layer.yaml 로드
    - NativeClient 도메인 활성 → native-client.yaml 로드
      (Unreal/Unity/C++ SDK, iOS/Android 네이티브 앱)
    체크리스트 항목은 각 차원(A1-A8)의 Review Perspective를 보완한다.
```

**각 차원은 모든 활성 도메인에 걸쳐 리뷰됩니다.**
도메인은 "어디를 볼 것인가" 컨텍스트이며, 조직 원리가 아닙니다.

각 차원의 구조:
- **Core Architecture Questions**: 이 차원의 근본 질문
- **Review Perspectives**: 도메인별 무엇을 어떻게 리뷰할지
- **Representative Anti-Patterns**: 구조적 이슈의 대표 예시 (이에 한정되지 않음)
- **Representative Healthy Patterns**: 건전한 구현의 참조 모델 (이에 한정되지 않음)

### 차원 모듈 (dimensions/)

```yaml
Dimension_Modules:
  # Tier 1 차원 파일 — knowledge-base/tier1-dimensions/ 에 위치
  # 각 차원에 Backend, Frontend, BaaS_DB, Batch_Worker, LLM_AI, SDK, Mobile, Infra 레이어 포함
  A1: knowledge-base/tier1-dimensions/a1-auth.md       # 인증 아키텍처
  A2: knowledge-base/tier1-dimensions/a2-authz.md      # 인가 아키텍처
  A3: knowledge-base/tier1-dimensions/a3-dataflow.md   # 데이터 흐름과 신뢰 경계
  A4: knowledge-base/tier1-dimensions/a4-io.md         # 입출력 경계
  A5: knowledge-base/tier1-dimensions/a5-secret.md     # 시크릿 및 설정 관리
  A6: knowledge-base/tier1-dimensions/a6-deps.md       # 의존성 및 외부 통합
  A7: knowledge-base/tier1-dimensions/a7-error.md      # 에러 처리 및 관찰 가능성
  A8: knowledge-base/tier1-dimensions/a8-resource.md   # 리소스 소비 및 가용성 제어

  # Tier 2 오버레이 — knowledge-base/tier2-overlays/ 에 위치
  # registry.yaml 매칭 시 해당 도메인 오버레이를 추가 로드
  Tier2_Registry: knowledge-base/tier2-overlays/registry.yaml
```

단순 모듈에 모든 문서를 반복해 읽지 않는다(analyze 카드).

---

## 확장 분석 모듈

```yaml
Extended_Modules:
  심층_분석: deep-analysis.md     # 원칙 기반 심층 분석
  표준_매핑: compliance.md        # 보안 표준 준수 점검 (OWASP, NIST)
  규제_참조: regulatory.md        # 규제 영향 참조 (Finding 기반 매핑)

Depth_Trigger_Sweep: |
  ⚠️ A1–A8 기본 점검은 종료 전 각 depth 모듈 트리거에 yes/no/maybe를 명시적으로 답한다.
  대상 트리거: depth/{injection, ssrf, access-control, auth-bypass, crypto-misuse, data-flow, concurrency}.md 의 Trigger.
  - yes 또는 maybe(불확실 포함) → 해당 depth 모듈을 Read하여 정밀 변종을 점검한다:
    DNS-rebinding/302-follow SSRF, alg=none·kid/jku JWT, blind/gadget-chain 역직렬화,
    TOCTOU, 2차(stored) injection 등. "불확실"도 반드시 로드한다.
  - no → 트리거 요소 부재 사유를 1줄 기록. 침묵 스킵 금지.
  근거: depth 모듈이 "후보 감지 시에만" 로드되면 기저 패스가 놓친 클래스는 정밀 방법론이
  아예 가동되지 않아 미세 변종을 통째로 놓친다(recall funnel).
```

---

## 판단 자체 검증 (Self-Verification)

> Finding을 제출하기 전에 아래 항목으로 과대·과소 평가를 점검한다.

```yaml
Self_Verification:
  목적: |
    분석 결과의 오탐(과대 평가)과 과소 평가를 최소화한다.

  Step_0_프로젝트_라이프사이클_컨텍스트:
    설명: |
      프로젝트의 현재 라이프사이클 단계를 담당 범위 코드에서 판별하고,
      이후 영향 판단(Step 1.8)에 구조적 입력으로 제공한다.
      ⚠️ 라이프사이클은 분석 깊이를 줄이지 않는다 — 모든 차원을 동일하게 분석한다.
      라이프사이클은 영향 판단의 So_What에만 영향을 준다.

    판별_기준:
      prototype:
        신호: |
          - mock/hardcoded 데이터가 핵심 비즈니스 로직에 사용
          - 실제 트랜잭션/결제/서명 코드 부재
          - "TODO", "placeholder", "demo" 주석 다수
          - 사용자 인증이 mock이거나 부재
        So_What_지침: |
          "이 취약점이 악용되면 현재 상태에서 실제로 무엇이 발생하는가?"
          mock 데이터만 있으면 "실제 사용자 데이터 유출" 시나리오는 성립하지 않는다.
          단, 구조적 약점의 판단 근거는 severityRationale에 남긴다.

      staging:
        신호: |
          - 실제 API 통합이 있으나 테스트 환경 대상
          - 테스트 데이터와 실제 데이터 혼재
          - 배포 파이프라인이 존재하나 프로덕션과 분리
        So_What_지침: |
          staging 데이터 유출도 영향이 있을 수 있다 (테스트 계정에 실제 이메일 등).
          프로덕션과 동일한 심각도를 적용하되, 영향 범위를 staging으로 한정하여 기술한다.

      production:
        신호: |
          - 실제 사용자 대상 서비스
          - 실제 트랜잭션/결제/개인정보 처리
          - 프로덕션 도메인, 프로덕션 인프라
        So_What_지침: |
          전체 영향도를 적용한다. 추가 조정 없음.

    기록: "라이프사이클 판별 근거는 severityRationale에 쓴다."

    Anti_Patterns:
      - "prototype이므로 전체 심각도를 일괄 하향 — 금지. 개별 영향 판단에서만 조정"
      - "prototype이므로 분석 범위를 축소 — 금지. 라이프사이클은 출력 필터이지 입력 필터가 아님"
      - "production이 아니므로 분석 결과를 간략하게 — 금지. 동일한 깊이로 기록"

  Step_1_도달_가능성_검증:
    설명: "취약 코드가 실제 실행 경로에서 호출되는가?"
    절차:
      - "취약 함수/메서드의 호출자(caller)를 코드 전체에서 검색"
      - "호출자 존재 → 호출 경로(entry point → ... → 취약 함수)를 기록"
      - "조건부 호출 → 조건의 현실적 트리거 가능성 평가"
    ast_보강: |
      호스트가 전달한 evidenceDetails에 흐름 정보가 있으면 이를 참조하여
      엔트리포인트 → Finding 위치까지 경로 존재 여부를 구조적으로 확인한다.
      정적 콜그래프가 경로를 못 짚으면 먼저 코드 리딩으로 경로를 확인한다.
      주의: 동적 호출(eval, reflection, dispatch 테이블)은 콜 그래프에 안 잡히므로 LLM 보완 필수.
    reachability_매핑:
      confirmed: "외부 입력에서 시작하는 호출 경로가 확인됨(콜그래프 또는 코드 리딩으로 확립)"
      plausible: "특정 설정/환경/조건에서만 도달 — 조건을 preconditions에 명시"
      unconfirmed: "콜그래프와 코드 리딩 모두 경로를 확립하지 못함(외부 런타임 설정·플러그인·미지원 언어 등) — 사유를 unresolved에 기록. CRITICAL/HIGH 불가(review 카드)"
      dead_code: "코드 전체 검색에서 호출자 0건이면 최대 LOW로 제출하고 evidence·severityRationale에 'Dead Code — caller 0건'을 명시한다. export된 API·SDK·플러그인 진입점·동적 호출은 호출자 0건이 미사용 입증이 아니므로 dead code로 취급하지 않는다"
    상태_변수_추적: "미검증 입력에서 설정되는 내부 상태 변수를 식별하고, 다운스트림 사용처(UI 표시, 보안 게이트, API 파라미터, 트랜잭션 등)를 추적해 실제 영향 범위를 impact에 기록한다"

  Step_1.5_FP_패턴_참조:
    설명: "knowledge-base/patterns/false_positive_patterns.yaml의 패턴과 매칭하여 과대 평가를 선제 보정한다."
    절차:
      - "현재 Finding의 차원/카테고리/코드 패턴을 false_positive_patterns.yaml의 trigger와 대조"
      - "매칭 시 해당 패턴의 self_verify_action을 실행하여 심각도 재평가"
      - "자동 하향하지 않음 — 코드 증거 기반으로 재평가 후 판단"
    참조_패턴:
      - "FP-001: 설계상 공개 값의 노출 과대 평가 (publishable key 등)"
      - "FP-002: 화이트리스트/내부 상수에 의한 SQL 인젝션 과대 평가"
      - "FP-003: Effective 보상 제어 인정 후 심각도 미하향"
      - "FP-004: 에러 메시지 노출 범위 과대 평가 (마스킹 로직 존재)"
    역참조:
      - "FU-001: 기본값 false (opt-in) 인증의 과소 평가 — CRITICAL 승격 검토"

  Step_1.65_동일_취약점_정규화:
    설명: |
      같은 근본 원인의 반복 위치는 한 Finding으로 묶고 영향 위치를 evidence와 impact에 함께 기록한다(analyze 카드 5).
      다른 원인은 같은 인용을 공유해도 합치지 않는다.
    판단_기준:
      - "같은 보안 통제 누락/오류에서 발생"
      - "같은 코드 수정 또는 설정 변경으로 함께 해결"
      - "여러 route/function/file에서 관찰되지만 root cause와 remediation이 동일"

  Step_1.7_공격_전제_조건_분석:
    설명: |
      각 Finding에 대해 "이 공격이 성립하려면 무엇이 먼저 침해되어야 하는가?"를
      명시적으로 분석하고 태깅한다. 전제조건이 동일한 Finding을 포괄 그룹으로 묶어
      "전제 침해 시 이 방어선이 독립적으로 유효한가?" 판정까지 수행한다.

    절차:
      1_직접_전제_식별: |
        Finding의 공격 경로를 역추적하여 "공격자가 사전에 장악해야 하는 것"을 명시:
        - 네트워크 위치 (내부망, VPC, 특정 pod 접근)
        - 자격증명 (AMQP creds, DB password, signing key)
        - 인프라 (DNS, 인증서, RPC 노드)
        - 사용자 행위 (피싱 클릭, 악성 DApp 연결)
        - 없음 (공개 엔드포인트에서 즉시 실행 가능)

      2_전제_카테고리_분류: |
        직접 전제를 아래 표준 카테고리로 분류:

        cloud_provider:
          정의: "클라우드 프로바이더 관리형 인프라 침해 전제"
          예시: [AWS Route53 DNS, AWS ACM 인증서, AWS VPC, GCP IAM, Azure AD]
          특징: "프로바이더 침해 = 해당 프로바이더 내 전체 서비스 동시 침해"
          판정: "프로바이더 내부의 추가 방어선은 독립 유효성 없음"

        supply_chain:
          정의: "SDK, 패키지, 라이브러리 공급망 침해 전제"
          예시: [npm 패키지 변조, Go 모듈 hijack, PyPI 악성 패키지, GitHub Actions]
          특징: "실제 사례 다수 (SolarWinds, event-stream, ua-parser-js)"
          판정: "이론적 위험으로 치부하지 않는다. 코드 레벨 방어(input validation 등)는 유효할 수 있음"
          ⚠️주의: "supply chain 공격은 이론적이지 않음 — 현실 위협으로 평가해야 한다"

        internal_network:
          정의: "내부망 접근 전제 (VPC, K8s pod-to-pod)"
          예시: [AMQP 접근, gRPC 접근, Redis 직접 접근]
          판정: "메시지 서명, mTLS 등 application-level 방어는 유효"

        config_file:
          정의: "설정 파일/환경변수/CI artifact 접근 전제"
          예시: [config.toml 유출, Docker volume mount 오류, CI/CD artifact leak, git history]
          판정: "Vault 전환 시 config에 secret 없으면 유출 무의미"
          ⚠️주의: "git history에 커밋된 과거 secret은 Vault 전환 후에도 유효할 수 있음"

        single_service:
          정의: "특정 단일 서비스 침해 전제"
          예시: [특정 pod RCE, container escape, dependency exploit]
          판정: "다른 서비스의 방어선은 유효 (lateral movement 방어)"

        blockchain_rpc:
          정의: "블록체인 RPC 엔드포인트 침해 전제"
          예시: [RPC 노드 응답 조작, DNS로 가짜 RPC 유도]
          판정: "다중 RPC 교차 검증은 유효. 단일 RPC면 방어 불가"
          ⚠️주의: "RPC가 cloud_provider 내 관리형이면 cloud_provider 카테고리로 재분류 가능"

        user_action:
          정의: "사용자 행위 전제 (피싱, social engineering)"
          예시: [phishing link 클릭, malicious DApp 연결, 서명 요청 수락]
          판정: "EIP-712 typed data, domain binding, UI 경고 등 유효"

        none:
          정의: "전제조건 없음 — 외부 인터넷만으로 즉시 실행 가능"
          예시: [공개 엔드포인트 취약점, 인증 우회, path traversal]
          판정: "즉시 패치 필수"

      3_포괄_그룹_판정: |
        동일 카테고리의 전제를 가진 Finding들을 포괄 그룹으로 묶고,
        "전제 침해 시 이 방어선이 독립적으로 유효한가?" 를 판정한다:

        판정 기준:
        - defense_survives: true  → 방어선이 전제 침해와 독립적. 원래 심각도 유지.
        - defense_survives: false → 전제 침해 시 이 방어선도 무력화. "전제 침해 = 전체 무력화"를 명시하고, 이 방어선을 심각도 하향 근거로 쓰지 않는다.
        - defense_survives: partial → 부분 유효. 근거를 명시.

        예시:
          JWT 로컬 검증 부재:
            direct: "Route53 DNS 조작 또는 ALB 인증서 위조"
            category: cloud_provider
            scope_if_compromised: "AWS 전체 — Vault, DB, Redis, EKS, JWKS 포함"
            defense_survives: false (JWKS도 같은 AWS에 있으므로)
            rationale: "AWS 침해 = 전체 침해. 로컬 검증 추가해도 JWKS 조작으로 무력화"

          AMQP 무인증:
            direct: "RabbitMQ credentials"
            category: internal_network + config_file (compound)
            scope_if_compromised: "해당 AMQP 큐에 접근 가능한 모든 서비스"
            defense_survives: true (AMQP 메시지 HMAC 서명은 credential과 독립)
            rationale: "AMQP cred 유출 + 네트워크 접근이면 즉시 공격. 메시지 서명은 별도 키로 방어 가능"

    기록: "직접 전제는 preconditions에, 카테고리·defense_survives 판정과 근거는 severityRationale에 기록한다."

    Anti_Patterns:
      - "전제조건을 명시하지 않고 심각도만 부여"
      - "cloud_provider 전제를 식별하고도 HIGH로 유지 (과대 평가)"
      - "supply_chain을 이론적 위험으로 치부 (과소 평가 — 실제 사례 다수)"
      - "단일 Finding만 보고 포괄 그룹 묶지 않음 (비효율 — 같은 전제의 N건을 개별 평가)"

  Step_1.8_비즈니스_영향_증명:
    설명: |
      "이 취약점이 실제 서비스에 어떤 영향을 미치는가?"를
      3개 필수 증명(What/So_What/How)으로 검증하고 impact 필드에 쓴다.
      이 판단은 출력 필터이며 입력 필터가 아니다 — 분석 깊이를 줄이지 않는다.

    3_Proofs:
      What:
        question: "어떤 구체적 자산/데이터/기능이 영향받는가?"
        요구사항: |
          추상적 설명이 아닌 구체적 대상을 명시해야 한다.
          허용: "사용자의 결제 정보(카드 번호, CVV)가 평문으로 노출됨"
          허용: "관리자 API를 통해 전체 사용자 목록에 접근 가능"
          금지: "데이터가 유출될 수 있음" (어떤 데이터?)
          금지: "보안에 영향을 줄 수 있음" (어떤 보안 기능?)
        기록: "영향받는 자산을 impact에 명시"

      So_What:
        question: "악용 시 서비스에 어떤 구체적 결과가 발생하는가?"
        요구사항: |
          이론적 가능성이 아닌 실제 서비스 맥락의 공격 결과를 기술한다.
          허용: "공격자가 타인의 주문을 취소하고 환불을 자기 계좌로 유도"
          허용: "인증 우회로 모든 사용자의 개인정보 열람 가능"
          금지: "보안 위반" (너무 추상적)
          금지: "이론적으로 시스템에 영향" (구체적 시나리오 필요)
        연계: "preconditions의 전제조건 실현 가능성과 함께 판단"

      How:
        question: "외부 입력에서 취약 코드까지 도달 가능한 경로가 존재하는가?"
        요구사항: |
          Step 1(도달 가능성)에서 확인한 호출 경로를 비즈니스 맥락으로 재해석한다.
          entry point → middleware chain → vulnerable function의 구체적 경로를 명시.
          호스트가 전달한 evidenceDetails에 흐름 정보가 있으면 이를 참조해 경로를 확인한다.
        판정: |
          도달성은 Step_1의 reachability_매핑을 따른다.
          ⚠️ "정적 콜그래프가 경로를 못 짚음"은 그 자체로 강등·제외 사유가 아니다 — 반드시 코드 리딩을 먼저 시도한다.
          예: handlers[req.body.action]의 키가 인라인 리터럴→인라인 함수면 읽어서 경로를 확립할 수 있다 → confirmed.
          콜그래프도 코드 리딩도 경로를 확립하지 못한 경우(unconfirmed)를 경로 부재 입증으로 취급하지 않는다.

    판정_규칙: |
      What·So_What·How를 모두 구체적 증거로 입증하면 원래 심각도를 유지한다.
      코드 결함은 확인되지만 현재 서비스 맥락에서 What 또는 So_What(비즈니스 영향)을 입증할 수 없으면
      구조적 약점이다: severity INFO로 제출하고, 입증하지 못한 항목과 원래 판단했을 심각도를
      severityRationale에 남긴다(서비스 맥락이 바뀌면 재평가 대상).
      결함 자체의 증거가 부족하면 supported로 과장하지 않고 abstain/escalate와 구체적 unresolved를 쓴다(analyze 카드 4).

    Anti_Patterns:
      - "3 Proofs를 분석 범위 축소 목적으로 사용 — 이 게이트는 출력 필터이며 입력 필터가 아님"
      - "So_What에서 이론적 위험만으로 통과 — 구체적 서비스 시나리오 필수"
      - "How에서 Step 1 결과를 복사 — 비즈니스 맥락 재해석 필요"
      - "unconfirmed(추적 불가)를 경로 부재 입증으로 취급 — 정적 추적 한계를 안전 근거로 오용 금지"
      - "정적 콜그래프 미추적을 곧바로 강등 — 먼저 코드 리딩 시도 필수. 읽어서 도달 경로가 확립되면(예: 인라인 dispatch 테이블) 원 심각도 유지"

  Step_2_보상_제어_확인:
    설명: "다른 레이어에서 동일 위협을 차단하는 보상 제어가 있는가?"
    프로토콜: "methodology/common/compensating-control.md의 4단계 프로토콜을 실행한다."
    절차:
      - "Step 1: 위협 경로의 모든 레이어를 순회한다"
      - "Step 2: 각 레이어에서 후보 보상 제어를 식별한다"
      - "Step 3: 5개 질문(범위/정밀도/우회가능성/완전성/독립성)으로 유효성을 검증한다"
      - "Step 4: Effective_Complete/Effective_Narrow/Partial/Ineffective/Unverifiable로 판정하고 기록한다 (compensating-control.md Step 4가 정본)"
    원칙:
      - "보상 제어의 존재 ≠ 위협 차단 — 유효성이 코드에서 입증되어야 한다"
      - "판정과 근거를 severityRationale에 기록한다"

  연계_점검:
    설명: "CRITICAL/HIGH 후보가 여러 건이면 동일 데이터 흐름·엔티티·사용자 역할로 묶어 'A가 성공하면 B의 전제조건이 충족되는가?'를 확인한다."
    기록: "연계가 성립하면 각 Finding의 preconditions·impact에 상대 Finding과 연계 영향을 서술한다. 담당 범위를 넘는 연계는 handoff에 남긴다(analyze 카드 Cross-Unit 절)."

  범주_구분_주의:
    - "내부 서비스 간 TLS 미적용과 인증 부재는 별개다. 내부 통신 코드(AMQP, gRPC, Redis 등)에서는 TLS와 무관하게 메시지 서명·토큰 검증·mTLS·API 키, 메시지 무결성(HMAC·스키마 검증), 브로커 ACL·서비스별 credential을 확인한다."
    - "Rate limit 우회나 리소스 고갈이 brute-force·credential stuffing·비즈니스 로직 조작의 전제가 되면 순수 DoS가 아니다. 해당 차원(A1, BL 등)의 Finding으로 다룬다."

  적용_범위: "모든 Finding에 Step 1, 1.5, 1.7, 1.8, 2를 적용한다."
```

---

## 설정 의존 위험 (Configuration Risk)

현재 안전하지만 설정을 바꾸면 취약해지는 항목(dev/mock 플래그, 비활성화 가능한 보안 기능, 디버그 전용 코드 경로,
커밋된 개발용 크레덴셜 등)은 다음 세 가지를 확인한다.

1. 외부 활성화 경로: 환경 변수·API 파라미터/쿼리스트링·hot-reload·feature flag로 값이 바뀔 수 있다 → 원래 심각도 유지
2. 단일 설정이 보안 메커니즘을 전면 해제한다(예: UseMock=true → 전체 인증 우회) → 원래 심각도 유지, startup assertion을 remediation에 포함
3. 프로덕션 시작 가드(환경 검사, build tag 분리)가 없다 → 원래 심각도 유지 또는 최대 한 단계만 낮춘다(INFO 금지)

세 가지 모두 해당하지 않으면 INFO로 제출하고 취약해지는 조건(예: "UseMock=true 설정 시 전체 인증 우회")을
preconditions에, 확인한 가드를 severityRationale에 기록한다. 권고는 startup assertion, 코드 경로 제거, build tag 분리다.
현재 활성 상태인 안전하지 않은 설정과 설정과 무관한 코드 레벨 취약점은 이 절의 대상이 아니다.

---

## 안전 판단 기록 (Negative Findings)

검토했지만 안전하다고 판단한 항목은 `02_file_assessments.json`의 rationale과 evidence에 안전 근거 코드 인용과 함께 남긴다.
안전 판단에도 취약 판단과 같은 증거 기준을 적용한다. 대상: 적절히 구현된 보안 메커니즘, 보상 제어로 충분히 차단된
잠재 위험, 의심스러웠으나 실제로는 안전한 코드 패턴.

---

## 규제 참조

규제 관련 Finding이 있을 때만 `regulatory.md`를 읽는다. 기술적 심각도를 규제 이유로 바꾸지 않는다.

---

### Root Cause Classification (근본 원인 분류)

```yaml
Root_Cause_Types:
  ARCHITECTURE:
    description: "시스템 설계 자체의 문제 — 코드 변경만으로 해결 불가"
    examples: |
      - 인메모리 Rate Limit + Serverless 배포
      - 이중 인증 경로 (미들웨어 + 핸들러 중복, 둘 다 불완전)

  CONFIGURATION:
    description: "기능은 지원되나 설정 누락 — 설정 추가로 해결"
    examples: |
      - CSP 헤더 미설정
      - CORS 와일드카드
      - 보안 규칙 비활성화

  CODE:
    description: "로직 오류 또는 검증 누락 — 코드 수정으로 해결"
    examples: |
      - 인증 호출 누락
      - 에러 메시지 직접 반환
      - 소유권 미검증 쿼리

  PROCESS:
    description: "개발 프로세스/가이드라인 부재로 반복 발생하는 이슈"
    examples: |
      - 새 API 생성 시 인증 체크리스트 없음
      - 코드 리뷰에 보안 항목 없음
      - 마이그레이션 리뷰에 보안 설정 변경 확인 없음
```

### Finding 기록 (mcp__nunchi__submit_finding)

ID는 호스트가 부여한다. 모델이 ID 체계를 만들지 않는다.

- severity: CRITICAL|HIGH|MEDIUM|LOW|INFO. 영향·도달 가능성·권한 경계를 근거로 정한다.
- evidenceClass: data-flow|configuration|access-control|runtime|documentation (documentation만으로 CRITICAL/HIGH 불가)
- reachability: confirmed|plausible|unconfirmed|not-applicable (위 도달 가능성 매핑)
- preconditions: 악용 전제(없으면 빈 배열). severityRationale: 보상 제어 판정·전제 범주·라이프사이클 근거
- evidence: path·lineStart·lineEnd·정확한 quote. 안전 판단에도 같은 증거 기준을 적용하고, 라이브러리 기본값을 가정하지 않는다
- impact: What(영향 자산)·So_What(서비스 결과)·How(진입점→취약 코드 경로)
- remediation: 변경 대상, 호출·참조 지점, 부작용, 동반 변경, 수정 후 확인 항목
- standards: CWE-NNN, OWASP Top 10, API Top 10 식별자. unresolved: 확인하지 못한 조건. confidence: 판정과 분리
