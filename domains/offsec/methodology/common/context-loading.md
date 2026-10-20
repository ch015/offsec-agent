# 컨텍스트 계층적 로딩 프로토콜 (Staged Context Loading Protocol)

> 전체 스킬/차원/체크리스트를 한 번에 로드하지 않고,
> Phase 진행에 따라 필요한 모듈만 선택적으로 로드하여
> 컨텍스트 윈도우를 보안 분석 대상 코드에 집중시킵니다.

---

## 설계 원칙

```yaml
Principles:
  Context_Budget_First: |
    컨텍스트 윈도우는 유한한 자원이다.
    시스템 인스트럭션이 컨텍스트의 대부분을 점유하면
    분석 대상 코드에 할당되는 주의(attention)가 부족해져
    할루시네이션(존재하지 않는 코드 참조, 프로젝트 간 교차 오염)이 발생한다.

  Load_On_Demand: |
    각 Phase에서 필요한 모듈만 그 시점에 로드한다.
    이전 Phase의 모듈은 결과만 유지하고 원문은 해제한다.
    "해제"란 해당 모듈의 상세 지시를 더 이상 참조하지 않고
    Phase 결과(Finding, Score 등)만 보존하는 것을 의미한다.

  Result_Over_Instruction: |
    완료된 Phase의 산출물은 간결한 구조화 데이터로 보존한다.
    "Phase 1에서 A1~A8을 분석한 결과" 전문이 아니라,
    Finding 목록 + 차원별 건강도 요약만 다음 Phase에 전달한다.
```

---

## Phase별 로딩 매니페스트

```yaml
Loading_Manifest:

  Phase_0_Recon:
    load:
      - "methodology/common/recon.md"
    skip: |
      차원 파일(a1~a8), 체크리스트, deep-analysis, compliance,
      compensating-control, regulatory — 모두 불필요
    이유: "정찰은 기술 스택과 공격 표면 식별만 수행"

  Phase_0_5_Binding:
    load: []
    retain_from_Phase_0:
      - "기술 스택 변수 (LANG, FRAMEWORK, AUTH, DB, DEPLOY)"
      - "활성 도메인 목록"
      - "공격 표면 맵"
      - "API 인벤토리"
      - "프로젝트 레벨"
      - "Asset_Register"
    unload:
      - "recon.md 원문 — 결과 변수만 보존"
    이유: "Recon 결과를 바인딩 변수로 압축하여 후속 Phase에 전달"

  Phase_1_Architecture:
    load:
      활성_차원만: |
        Loading_Strategy(methodology/va/index.md 참조)에 따라 선택 로드:
        - full_audit: 8개 차원 전부 (a1~a8)
        - targeted (--focus A1,A2): 지정 차원만
        - daily_diff: 변경 파일이 속한 차원만
      활성_체크리스트만: |
        Phase 0에서 탐지된 활성 도메인에 해당하는 체크리스트만:
        - Backend → api.yaml
        - Frontend → web-app.yaml
        - BaaS/DB → db-layer.yaml
        - NativeClient → native-client.yaml
      taint_analysis: |
        Source-to-Sink 추적 프로토콜:
        - "methodology/common/taint-analysis.md"
        (A3/A4 분석 시 항상 로드 — 추적 절차 제공)
      depth_files: |
        Phase 1에서 취약점 후보가 발견된 경우 해당 depth 파일만 선택 로드:
        - "methodology/va/depth/injection.md" (인젝션 후보 감지 시 — SQL/NoSQL/LDAP/SSTI/GraphQL/Prototype Pollution/Deserialization 통합)
        - "methodology/va/depth/auth-bypass.md" (인증 우회 후보 감지 시)
        - "methodology/va/depth/access-control.md" (접근 제어 이상 감지 시)
        - "methodology/va/depth/ssrf.md" (SSRF 후보 감지 시)
        - "methodology/va/depth/crypto-misuse.md" (암호화 구현 감지 시)
        - "methodology/va/depth/data-flow.md" (데이터 흐름 이상/프록시 패스스루 감지 시)
        - "methodology/va/depth/concurrency.md" (상태 변경 경합/TOCTOU 감지 시)
        no-candidate_sentinel: |
          후보 미감지로 depth 파일을 건너뛰기 전에 아래 sentinel 질문을 1회 수행한다.
          하나라도 YES 또는 UNKNOWN이면 해당 depth 파일을 로드한다:
          - injection: 외부 입력이 query/template/shell/deserialization sink에 닿을 가능성이 있는가?
          - auth-bypass: 인증 미들웨어 없이 도달 가능한 엔드포인트/핸들러가 있는가?
          - access-control: user-controlled id/path/body로 타 리소스를 지정하는 경로가 있는가?
          - ssrf: 외부 입력이 outbound URL/host/path 결정에 영향을 주는가?
          - crypto-misuse: 커스텀 암호화/JWT/서명/키 관리 코드가 있는가?
          - data-flow: 업스트림 응답/사용자 데이터가 클라이언트/로그/redirect로 전달되는가?
          - concurrency: state-changing read-check-write가 transaction/lock/idempotency 없이 수행되는가?
        ⚠️ sentinel이 모두 NO일 때만 로드하지 않는다 (컨텍스트 절약).
        ⚠️ 기술별 세부사항(가젯 체인, 벤더 API, 엔진별 페이로드)은 LLM 내재 지식에 위임한다.
      tier2_overlays: |
        # Tier 2 서비스 도메인 오버레이 로딩
        # knowledge-base/tier2-overlays/registry.yaml의 signal 매칭에 따라 선택 로드.
        #
        # auto 로딩 (도메인 감지 즉시):
        - web3.md                 — Web3 시그널 감지 시 (solidity, ethers, web3, viem 등)
        - payment.md              — 결제 시그널 감지 시 (stripe, PG, checkout 등)
        - sdk.md                  — SDK 프로젝트 감지 시 (library plugin, .podspec 등)
        - ai-agent.md             — AI/Agent 시그널 감지 시 (langchain, openai 등)
        - commerce.md             — 커머스 시그널 감지 시 (cart, order, inventory 등)
        - cloud.md                — 클라우드 시그널 감지 시 (aws_*, terraform 등)
        #
        # conditional 로딩 (세부 시그널 매칭 시):
        - web3-wallet.md          — EVM/Solana 지갑 + KMS/HSM 감지 시
        - cloud-aws.md            — AWS 특화 리소스 감지 시
        - cloud-k8s.md            — Kubernetes 매니페스트 감지 시
        - tee-enclave.md          — TEE/Enclave 감지 시
        #
        ⚠️ registry.yaml의 signal 패턴과 Recon 결과를 교차 매칭.
        ⚠️ 도메인 감지 O + 오버레이 비활성화 시 Domain Gap 경고 발행 (FP-006 방지).

      principles: |
        # 벤더-불문 원칙 모듈 (조건부 로딩)
        Recon 또는 Phase 0.5 Binding에서 해당 패턴이 감지되면 원칙 모듈 로드:
        - RLS/행 수준 접근 제어 감지 (Supabase RLS, Firebase Rules, Hasura, Postgres RLS 등)
          → methodology/va/principles/row-level-security.md
        - OAuth/OIDC 제공자 SDK 감지 (Auth0, Cognito, Clerk, Okta, Supabase Auth, Firebase Auth 등)
          → methodology/va/principles/oauth-provider-misconfig.md
        - Webhook endpoint 또는 서명 검증 패턴 감지
          → methodology/va/principles/webhook-integrity.md
        - BaaS 플랫폼 사용 감지 (Supabase, Firebase, Hasura, Appwrite, Amplify 등)
          → methodology/va/principles/baas-trust-boundary.md
        ⚠️ 해당 패턴 미감지 시 로드하지 않는다 (컨텍스트 절약).
        ⚠️ 벤더별 세부사항(API 이름, SDK 메서드)은 LLM 내재 지식에 위임한다.

      조건부: |
        의존성 관리 파일(package.json, go.mod 등) 존재 시:
        - "methodology/va/supply-chain.md"
        (사실상 대부분의 프로젝트에서 로드됨 — A6 차원 분석 확장)
    skip:
      - "deep-analysis.md — Phase 2에서 로드"
      - "compliance.md — Phase 3에서 로드"
      - "compensating-control.md — Phase 3.5에서 로드"
      - "regulatory.md — Phase 5R에서 로드"
      - "비활성 차원 파일"
      - "비활성 도메인 체크리스트"
    이유: |
      Phase 1에서 8차원 분석에 필요한 차원 정의만 로드.
      심층 분석, 컴플라이언스, 규제 모듈은 아직 불필요하므로
      해당 토큰을 프로젝트 코드 분석에 할당한다.

  Phase_1_완료_시:
    retain:
      - "Finding 목록 (구조화 데이터)"
      - "차원별 건강도 (Healthy/Caution/Critical)"
      - "Unverified 증거 목록"
    unload:
      - "차원 파일(a1~a8) 원문"
      - "체크리스트 원문"
      - "도메인 지식 파일 원문"
    이유: "차원 정의는 분석 완료 후 불필요 — Finding에 결과가 담겨 있음"

  Phase_2_Deep_Analysis:
    load:
      - "methodology/va/deep-analysis.md"
      - 조건부: |
          Phase 0 Recon에서 아래 중 하나 이상 감지 시:
          금융/결제/자산 트랜잭션, 메시지 큐, 분산 서비스,
          동시성 프리미티브, 캐시+DB 이중 기록, Web3 트랜잭션
        load_extra:
          - "methodology/va/concurrency.md"
    retain_from_Phase_1:
      - "Finding 목록"
      - "차원별 건강도"
    이유: "원칙 기반 심층 분석은 Phase 1 결과를 입력으로 사용. 동시성 관련 신호 감지 시 concurrency.md를 추가 로드하여 5개 영역 분석 수행."

  Phase_2_완료_시:
    retain:
      - "Phase 1 Finding + Phase 2 추가 Finding (통합 목록)"
    unload:
      - "deep-analysis.md 원문"

  Phase_3_Compliance:
    load:
      - "methodology/va/compliance.md"
    이유: "보안 표준 준수 점검은 Finding 목록에 대해 수행"

  Phase_3_완료_시:
    retain:
      - "통합 Finding 목록 + 표준 매핑"
    unload:
      - "compliance.md 원문"

  Phase_3_5_Self_Verify:
    load:
      - "methodology/common/compensating-control.md"
    이유: "Self-Verify의 보상 제어 검증에만 필요"

  Phase_3_5_완료_시:
    retain:
      - "Self-Verify 결과가 반영된 최종 Finding 목록"
      - "Pending_Verification 목록"
    unload:
      - "compensating-control.md 원문"

  Phase_4_Scoring:
    load: []
    이유: "점수 산출 로직은 methodology/va/index.md에 이미 포함"

  Phase_5R_Regulatory:
    load:
      조건부: "규제 관련 Finding이 1건 이상인 경우에만"
      - "methodology/va/regulatory.md"
    skip_if: "규제 관련 Finding 0건"

  Phase_4_5_Evidence_Verification:
    load:
      - "methodology/common/evidence-verification.md"
    이유: "Finding의 file:line 증거를 독립 검증 — Scoring 직후, Report 직전에 실행"
```

---

## 로딩 실행 방법

```yaml
Implementation:
  Read_Tool_사용: |
    각 Phase 진입 시 Loading_Manifest에 명시된 파일을 Read 도구로 로드한다.
    "로드"는 해당 파일을 Read하여 현재 Phase의 작업 지시로 사용하는 것이다.

  Unload_의미: |
    "언로드"는 물리적 삭제가 아니다.
    해당 모듈의 상세 인스트럭션을 더 이상 참조하지 않고,
    Phase 결과(구조화 데이터)만 후속 Phase에 전달하는 것을 의미한다.
    자동 컨텍스트 압축이 발생하더라도 결과 데이터는 보존된다.

  Phase_간_브릿지: |
    각 Phase 완료 시 retain에 명시된 데이터를 간결하게 정리하여
    다음 Phase의 입력으로 전달한다.
    전체 보고서가 아닌 구조화된 요약만 전달하여 컨텍스트를 절약한다.

  대용량_프로젝트_조정: |
    프로젝트 코드가 대용량(소스 파일 200개 이상)인 경우:
    1. Phase 1에서 차원을 2~3개씩 묶어 분할 실행
    2. 각 차원 그룹 분석 후 결과만 보존하고 다음 그룹으로 전환
    3. 이를 통해 차원 파일 + 프로젝트 코드가 동시에 점유하는 컨텍스트를 관리

  Batched_Tool_Calls: |
    ⚡ 속도 최적화 — 독립적인 tool call은 단일 메시지에서 병렬 호출한다.

    원칙:
    - 서로 의존성이 없는 Read/Grep/Glob 호출은 반드시 한 메시지에 묶어 발행
    - 직렬 호출은 라운드트립마다 LLM 응답 생성 → 수 초 누적
    - 병렬 호출은 Claude Code 런타임에서 동시 실행 → 라운드트립 1회로 압축

    병렬화_가능_예시:
      Phase_1_차원_분석: |
        한 차원 내에서 여러 파일의 증거를 수집할 때:
        [단일 메시지]
          Grep(pattern="authenticate", type="ts")
          Grep(pattern="requireAuth", type="ts")
          Glob(pattern="**/middleware/*.ts")
          Read(file="src/app.ts")
        → 4개 결과를 한 번에 수신

      Phase_0_Recon: |
        기술 스택 탐지 시:
        [단일 메시지]
          Read("package.json")
          Read("go.mod")
          Read("requirements.txt")
          Read("Dockerfile")
          Glob(".github/workflows/*.yml")

      Phase_4_5_Evidence_Verification: |
        여러 Finding의 증거를 동시 재확인:
        [단일 메시지]
          Read(F-001 증거 파일)
          Read(F-002 증거 파일)
          Read(F-003 증거 파일)

    순차_필수_예시:
      - "이전 결과에 따라 다음 경로가 결정될 때 (Grep 결과 → 특정 파일 Read)"
      - "Phase 간 경계 (이전 Phase 완료 검증 후 다음 진입)"

    금지:
      - "Tool call을 의미 단위로 분해하여 순차 발행 (예: A1 Grep → 응답 → A1 Read → 응답)"
      - "각 차원마다 별도 메시지 발행"
      - "검색 결과를 기다려 다음 검색 생성하는 패턴 (의존성 없을 때)"

    효과:
      - 8차원 분석 라운드트립 수 최대 70% 감소
      - Phase 0 Recon 시간 단축 (10개 파일 → 2초 이내)
      - 증거 검증 일괄 처리
```

---

## Anti-Patterns

```yaml
Anti_Patterns:
  All_At_Once: |
    모든 스킬 파일을 세션 시작 시 한 번에 로드하는 것은 금지한다.
    이것은 150K+ 토큰을 인스트럭션에 소비하여
    프로젝트 코드 분석 품질을 저하시킨다.

  Report_In_Context: |
    완료된 Phase의 전체 보고서를 컨텍스트에 유지하는 것은 금지한다.
    전체 보고서는 파일로 저장하고, 후속 Phase에는 구조화 요약만 전달한다.

  Redundant_Load: |
    동일 모듈을 여러 Phase에서 반복 로드하지 않는다.
    compensating-control.md가 Phase 3.5에서 로드되었으면
    Phase 5에서 다시 로드하지 않는다 — 결과만 참조한다.
```
