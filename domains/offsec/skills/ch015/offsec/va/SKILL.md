---
name: ch015-va
description: "Run CH015 vulnerability assessment workflows for source-code security architecture review, 8-dimension analysis, compliance checks, self-verification, evidence verification, and VA reporting."
---

# 취약점 진단 (Vulnerability Assessment) Skill

> 대상 프로젝트의 소스코드를 아키텍처 차원 기반으로 체계적으로 점검하여
> 보안 메커니즘의 구현 현황과 미적용 영역을 식별합니다.

---

## 서비스 개요

| 항목 | 내용 |
|------|------|
| 서비스명 | 취약점 진단 (VA) |
| 방법론 | 아키텍처 차원 기반 + 방법론 중심 분석 |
| 출력물 | 아키텍처 차원 건강도 + 취약점 목록 + 6-step 영향도 분석 + 표준 준수 현황 |
| 코드 수정 | ❌ 없음 (읽기 전용) |

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

---

## Phase 구조

```
Phase 0: Recon              → 공통 정찰 (common/recon.md 참조)
Phase 0.5: Binding          → 정찰 → 분석 컨텍스트 바인딩
Phase 0.8: AST Pre-Analysis → Tree-sitter + Semgrep 구조 분석 (--mode ast 지정 시)
Phase 1: Architecture       → 8대 보안 아키텍처 차원 리뷰
Phase 2: Deep Analysis      → 원칙 기반 심층 분석
Phase 3: Compliance         → 보안 표준 준수 점검
Phase 3.5: Self-Verify      → 분석 결과 자체 검증 (도달 가능성, 보상 제어, 경량 공격 체인)
Phase 4: Scoring            → 보안 점수 산출 (Self-Verify 결과 반영, Self-Verify Gate 통과 필수)
Phase 4.5: Evidence Verify  → file:line 증거 독립 검증 (common/evidence-verification.md)
Phase 4.7: Raw Ledger       → Raw Findings Ledger + Pentest Plan 초안 생성 (Phase 5 진입 게이트)
Phase 5: Report             → 종합 보고서 + 6-step 영향도 분석
Phase 5.1: Index            → Findings Index YAML 생성 (하류 에이전트 컨텍스트 최적화)
Phase 5B: Baseline          → Baseline Snapshot 생성 (이행점검 기준선, full audit 시에만)
Phase 5R: Regulatory        → 규제 영향 참조 (Finding 기반, 해당 시에만)
```

### Phase 0.8: AST Pre-Analysis (--mode ast)

```yaml
AST_Pre_Analysis:
  trigger: "--mode ast 지정 시 Phase 0.5 Binding 완료 후 실행"
  ownership: |
    /ch015:run 오케스트레이션에서는 OffSec Lead가 Recon 직후, VA fanout 결정 전에
    1회 실행한다. VA Agent별 중복 실행 금지.
    /ch015:va direct 실행에서만 VA가 fallback으로 직접 실행할 수 있다.
  skip_when: "기본 --mode llm 또는 AST 모드 미지정 시 건너뜀"

  execution: |
    Bash로 lib/ch015/ast/context-builder.js를 실행한다:
    node {ch015_root}/lib/ch015/ast/context-builder.js {target_path}

    이 스크립트는:
    1. Tree-sitter로 소스 파일 파싱 (지원 언어 전체)
    2. Semgrep 정적 스캔 (설치된 경우)
    3. 콜 그래프 추출 (함수 정의, 호출 관계, 엔트리포인트)
    4. 구조적 데이터 흐름 추출 (함수 간 파라미터 전달 체인)
    5. source→sink taint 후보 경로 추출 (검증 전 후보)
    6. 결과를 {target}/.ch015/ast-context.yaml에 저장

    ⚠️ 중요: AST 출력의 taint_paths는 후보 신호다.
    최종 보안 판단(취약점 확정, 심각도, 영향도, 악용 가능성)은
    AST 계층이 아닌 LLM/Verifier가 코드 근거로 재검증하여 수행한다.

  output: "{target}/.ch015/ast-context.yaml"
  timeout: "120초"

  fallback: |
    실행 실패 시 (tree-sitter 미설치, 파싱 에러 등):
    경고 메시지 출력 후 LLM-only로 자동 폴백하여 Phase 1 진행.
    "⚠️ AST Pre-Analysis 실패 — LLM-only 모드로 폴백합니다."

    폴백 시 Recon 출력의 ast_fallback_impact 필드에 잃어버린 데이터 유형을 기록:
    - call_graph: "함수 호출 관계 미생성 → A1/A2 미들웨어 도달 경로를 Grep 기반으로 추적해야 함"
    - data_flows: "파라미터 전달 체인 미생성 → A3/A4 taint 추적을 LLM 코드 읽기로 수행해야 함"
    - entry_points: "라우트 핸들러 자동 추출 실패 → Recon V3 Entry Point Completeness로 보완"
    - semgrep_findings: "정적 스캔 결과 없음 → Phase 1-2에서 패턴 매칭을 수동 Grep으로 수행"
    Phase 1 시작 시 이 필드를 참조하여 해당 차원에서 Grep/Read 보완 탐색을 강제한다.

  Phase_1_연계: |
    ast-context.yaml이 존재하면 Phase 1 시작 시 VA 에이전트에게 다음을 지시:
    "AST Pre-Analysis 결과가 .ch015/ast-context.yaml에 있습니다.
     이 파일을 Read하여 구조적 사실을 확인하세요.
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

  Agent_Fanout_불변식:
    - "--mode ast는 Agent 수를 늘리지 않는다."
    - "sequential VA 1개 또는 grouped VA 4개가 동일 ast_context_path를 공유한다."
    - "'AST 기반 8차원 진단'은 AST 컨텍스트를 참고해 A1-A8을 분석한다는 뜻이며 VA 8개 실행이 아니다."

  AST_차원별_활용:
    A1_인증: "콜 그래프에서 핸들러 호출 경로에 인증 관련 함수 존재 여부 확인"
    A2_인가: "엔트리포인트별 미들웨어/데코레이터 호출 패턴 분석"
    A3_데이터흐름: "data_flows에서 파라미터 전달 체인을 따라 위험 판단"
    A4_입출력: "data_flows의 terminal 호출과 arguments를 기반으로 데이터 노출 여부 판단"
    A5_에러처리: "콜 그래프의 함수 범위에서 try-catch 구조 분석"
    A6_의존성: "Semgrep findings + entry_points 기반 외부 의존성 분석"
    A7_로깅: "data_flows에서 로깅 함수로의 데이터 전달 경로 추적"
    A8_설정: "Semgrep 설정 관련 룰 결과 참조"
```

---

## Phase 1: 보안 아키텍처 차원 리뷰 (8 Dimensions)

### 도메인별 체크리스트

활성 도메인에 따라 아래 체크리스트를 추가 로드합니다:

```yaml
Checklists:
  Backend_API: "offsec/va/checklists/api.yaml → API 엔드포인트 보안 점검"
  Web_Application: "offsec/va/checklists/web-app.yaml → 웹 앱 클라이언트 보안 점검"
  Database_Layer: "offsec/va/checklists/db-layer.yaml → DB 접근 계층 보안 점검"
  Native_Client: "offsec/va/checklists/native-client.yaml → 네이티브 클라이언트/게임 SDK 보안 점검"
  Loading_Rule: |
    Phase 0에서 탐지된 활성 도메인에 해당하는 체크리스트만 로드한다.
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

Loading_Strategy:
  full_audit: "전체 차원 로드 (A1~A8)"
  compliance_check: "차원 로드 불필요 — Finding 위치 기반 코드 확인"
  daily_diff: "변경 파일이 속한 차원만 선택 로드"
  targeted: "지정 차원만 로드 (예: --focus A1,A2)"

Staged_Loading: |
  ⚠️ 모든 모듈을 세션 시작 시 한 번에 로드하지 않는다.
  common/context-loading.md의 Loading_Manifest에 따라
  Phase 진입 시점에 해당 Phase의 모듈만 선택적으로 Read한다.
  완료된 Phase의 모듈 원문은 해제하고 결과(Finding)만 보존한다.
  이를 통해 컨텍스트 윈도우를 프로젝트 코드 분석에 집중시킨다.
```

---

## Phase 2~3: 확장 분석 모듈

```yaml
Extended_Modules:
  Phase_2: deep-analysis.md       # 원칙 기반 심층 분석
  Phase_3: compliance.md          # 보안 표준 준수 점검 (OWASP, NIST)
  Phase_5R: regulatory.md         # 규제 영향 참조 (Finding 기반 매핑)

Depth_Trigger_Sweep: |
  ⚠️ 기저 패스(Phase 1)는 종료 전 각 depth 모듈 트리거에 yes/no/maybe를 명시적으로 답한다.
  대상 트리거: depth/{injection, ssrf, access-control, crypto-misuse, data-flow}.md 의 Trigger.
  - yes 또는 maybe(불확실 포함) → 해당 depth 모듈을 Read하여 정밀 변종을 점검한다:
    DNS-rebinding/302-follow SSRF, alg=none·kid/jku JWT, blind/gadget-chain 역직렬화,
    TOCTOU, 2차(stored) injection 등. "불확실"도 반드시 로드한다.
  - no → 트리거 요소 부재 사유를 1줄 기록. 침묵 스킵 금지.
  근거: depth 모듈이 "후보 감지 시에만" 로드되면 기저 패스가 놓친 클래스는 정밀 방법론이
  아예 가동되지 않아 미세 변종을 통째로 놓친다(recall funnel).
```

---

## Phase 3.5: 분석 결과 자체 검증 (Self-Verification)

> Phase 1~3에서 도출된 Finding을 점수 산출(Phase 4)에 반영하기 전에 자체 검증합니다.
> 이 단계의 결과에 따라 심각도가 조정되므로 Scoring 전에 실행해야 합니다.

```yaml
Self_Verification:
  목적: |
    분석 결과의 오탐(과대 평가)을 최소화한다.
    각 Finding에 대해 아래 2단계를 실행한다.

  Step_0_프로젝트_라이프사이클_컨텍스트:
    설명: |
      프로젝트의 현재 라이프사이클 단계를 Phase 0 결과에서 판별하고,
      이후 심각도 평가(Step 1.8 Impact Gate)에 구조적 입력으로 제공한다.
      ⚠️ 라이프사이클은 분석 깊이를 줄이지 않는다 — 모든 차원을 동일하게 분석한다.
      라이프사이클은 Impact Gate의 So_What 판정에만 영향을 준다.

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
          단, 구조적 약점은 Structural_Weakness로 기록하여 프로덕션 전환 시 재평가 대상으로 남긴다.

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

    보고서_표기: |
      Project Summary의 Lifecycle 필드에 판별 결과를 기록한다:
      | Item | Value |
      | Lifecycle | prototype / staging / production |
      | Lifecycle Signals | [판별 근거 1~3줄] |

    Anti_Patterns:
      - "prototype이므로 전체 심각도를 일괄 하향 — 금지. 개별 Impact Gate에서만 조정"
      - "prototype이므로 분석 범위를 축소 — 금지. 라이프사이클은 출력 필터이지 입력 필터가 아님"
      - "production이 아니므로 보고서를 간략하게 — 금지. 동일한 깊이와 형식으로 작성"

  Step_1_도달_가능성_검증:
    설명: "취약 코드가 실제 실행 경로에서 호출되는가?"
    절차:
      - "취약 함수/메서드의 호출자(caller)를 코드 전체에서 검색"
      - "호출자 0건 → Dead Code 태그, 심각도 재평가 (최대 LOW)"
      - "호출자 존재 → 호출 경로(entry point → ... → 취약 함수)를 기록"
      - "조건부 호출 → 조건의 현실적 트리거 가능성 평가"
    ast_보강: |
      .ch015/ast-context.yaml이 존재하면, call_graph와 data_flows를 참조하여
      엔트리포인트 → Finding 위치까지 경로 존재 여부를 구조적으로 확인한다.
      콜 그래프에 경로 없음 + LLM 확인 → severity 1단계 하향 또는 INFO.
      주의: 동적 호출(eval, reflection)은 콜 그래프에 안 잡히므로 LLM 보완 필수.
    판정:
      도달_가능: "호출 경로가 외부 입력에서 시작 → 원래 심각도 유지"
      조건부_도달: "특정 설정/환경에서만 도달 → 조건 명시, 심각도 유지 또는 1단계 하향"
      도달_불가: "Dead Code 또는 호출자 없음 → 심각도 LOW 이하로 재평가"

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
    목표: "1차 VA 심각도 정확도 85% → 90% (Verify 이의 선제 감소)"

  Step_1.65_동일_취약점_정규화:
    설명: |
      VA는 후보 생성 단계에서 "같은 취약점이 여러 위치에 영향을 주는 경우"를
      여러 Finding으로 발행하지 않는다. 단, 문자열 key를 임의 생성하지 않고,
      최종 equivalence_review에서 검증할 수 있도록 근거를 남긴다.
    판단_기준:
      - "같은 보안 통제 누락/오류에서 발생"
      - "같은 코드 수정 또는 설정 변경으로 함께 해결"
      - "여러 route/function/file에서 관찰되지만 root cause와 remediation이 동일"
    출력_규칙:
      - "대표 후보만 CONFIRMED/DOWNGRADED + score_included=true"
      - "나머지 후보는 raw ledger에 보존하되 FOLDED_INTO + folded_into=대표 ID"
      - "대표 후보의 affected_instances[]에 모든 endpoint/function/file/asset/flow를 기록"
      - "MERGE/SPLIT 판단 근거는 Convergence equivalence_review에서 최종 확정"

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
          판정: "T가 아닌 L-M 평가. 코드 레벨 방어(input validation 등)는 유효할 수 있음"
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
          판정: "즉시 패치 필수. Feasibility = HIGH"

      3_포괄_그룹_판정: |
        동일 카테고리의 전제를 가진 Finding들을 포괄 그룹으로 묶고,
        "전제 침해 시 이 방어선이 독립적으로 유효한가?" 를 판정한다:

        판정 기준:
        - defense_survives: true  → 방어선이 전제 침해와 독립적. 원래 심각도 유지.
        - defense_survives: false → 전제 침해 시 이 방어선도 무력화.
          → Feasibility를 T (Theoretical)로 하향. "전제 침해 = 전체 무력화" 명시.
        - defense_survives: partial → 부분 유효. 근거와 함께 Feasibility 조정.

        예시:
          F-API-03 (JWT 로컬 검증 부재):
            direct: "Route53 DNS 조작 또는 ALB 인증서 위조"
            category: cloud_provider
            scope_if_compromised: "AWS 전체 — Vault, DB, Redis, EKS, JWKS 포함"
            defense_survives: false (JWKS도 같은 AWS에 있으므로)
            adjusted_feasibility: T
            rationale: "AWS 침해 = 전체 침해. 로컬 검증 추가해도 JWKS 조작으로 무력화"

          F-01 (AMQP 무인증):
            direct: "RabbitMQ credentials"
            category: internal_network + config_file (compound)
            scope_if_compromised: "해당 AMQP 큐에 접근 가능한 모든 서비스"
            defense_survives: true (AMQP 메시지 HMAC 서명은 credential과 독립)
            adjusted_feasibility: M (config 유출 경로 존재)
            rationale: "AMQP cred 유출 + 네트워크 접근이면 즉시 공격. 메시지 서명은 별도 키로 방어 가능"

      4_보고서_출력: |
        각 Finding에 아래 필드를 추가:

        **공격 전제 조건 (Prerequisites)**:
        - 직접 전제: {direct}
        - 카테고리: {category}
        - 침해 시 범위: {scope_if_compromised}
        - 이 방어선 독립 유효성: {defense_survives} ({rationale})
        - 실전 Feasibility: {adjusted_feasibility}

        보고서 말미에 "포괄 그룹별 Finding 정리" 섹션 추가:
        | 포괄 그룹 | 전제 카테고리 | 해당 Finding | 포괄 판정 |
        |---------|------------|-----------|---------|
        | AWS 관리형 침해 | cloud_provider | F-API-03, ... | 방어 무의미(T) |
        | AMQP credential | internal_network | F-01, F-04, ... | 메시지 서명으로 방어 가능(M) |
        | Config 파일 유출 | config_file | F-10, F-API-02, ... | Vault로 해결(계획) |
        | 전제 없음 | none | F-003 Path Traversal, ... | 즉시 패치(H) |

    Anti_Patterns:
      - "전제조건을 명시하지 않고 일반적 Feasibility만 부여 (이전 방식)"
      - "cloud_provider 전제를 식별하고도 HIGH로 유지 (과대 평가)"
      - "supply_chain을 Theoretical로 치부 (과소 평가 — 실제 사례 다수)"
      - "단일 Finding만 보고 포괄 그룹 묶지 않음 (비효율 — 같은 전제의 N건을 개별 평가)"

  Step_1.8_비즈니스_영향_증명_게이트:
    설명: |
      "이 취약점이 실제 서비스에 어떤 영향을 미치는가?"를
      3개 필수 증명(What/So_What/How)으로 검증한다.
      이 게이트는 출력 필터이며 입력 필터가 아니다 — 분석 깊이를 줄이지 않는다.
    조건: "Step 1~1.7 완료된 모든 Finding"

    3_Proofs:
      What:
        question: "어떤 구체적 자산/데이터/기능이 영향받는가?"
        요구사항: |
          추상적 설명이 아닌 구체적 대상을 명시해야 한다.
          허용: "사용자의 결제 정보(카드 번호, CVV)가 평문으로 노출됨"
          허용: "관리자 API를 통해 전체 사용자 목록에 접근 가능"
          금지: "데이터가 유출될 수 있음" (어떤 데이터?)
          금지: "보안에 영향을 줄 수 있음" (어떤 보안 기능?)
        증거: "Asset_Value 필드와 연계 — Phase 0 Asset Register 기반"

      So_What:
        question: "악용 시 서비스에 어떤 구체적 결과가 발생하는가?"
        요구사항: |
          이론적 가능성이 아닌 실제 서비스 맥락의 공격 결과를 기술한다.
          허용: "공격자가 타인의 주문을 취소하고 환불을 자기 계좌로 유도"
          허용: "인증 우회로 모든 사용자의 개인정보 열람 가능"
          금지: "보안 위반" (너무 추상적)
          금지: "이론적으로 시스템에 영향" (구체적 시나리오 필요)
        연계: "Preconditions 필드의 전제조건 실현 가능성과 함께 판단"

      How:
        question: "외부 입력에서 취약 코드까지 도달 가능한 경로가 존재하는가?"
        요구사항: |
          Step 1(도달 가능성)에서 확인한 호출 경로를 비즈니스 맥락으로 재해석한다.
          entry point → middleware chain → vulnerable function의 구체적 경로를 명시.
          ast-context.yaml이 존재하면 call_graph/data_flows/taint_paths에서 경로를 확인한다.
        판정: |
          도달성은 아래 순서로 판정한다 (혼동 시 진짜 취약점이 점수에서 사라지거나
          과소평가된다). ⚠️ "정적 콜그래프가 경로를 못 짚음"은 그 자체로 감점/제외 사유가
          아니다 — 반드시 ② 코드 리딩을 먼저 시도한다.
          ① DISPROVEN (경로 부재 입증): call_graph/data_flows로 외부 입력 → 취약 코드
             경로가 "존재하지 않음"이 확인됨(dead code / 호출자 없음). → How 실패 →
             Structural_Weakness.
          ② RESOLVED_BY_READING (콜그래프 미추적이나 코드 리딩으로 확립): 동적 디스패치·
             리플렉션·이벤트 핸들러로 콜그래프가 경로를 못 짚어도, ast_보강(LLM 코드 리딩,
             Step 1의 ast_보강 절)으로 실제 도달 경로를 확인할 수 있으면 → How PASS →
             **원 심각도 유지**(강등 없음). 예: handlers[req.body.action]의 키가 인라인
             리터럴→인라인 함수면 읽어서 확립 가능 → 그대로 도달_가능.
          ③ UNTRACED (진짜 미확정): 콜그래프도 코드 리딩도 경로를 확립하지 못함(외부 런타임
             설정·플러그인·미지원 언어 등). "경로 부재 입증"과 다르다. → How_Untraced_Only
             적용(점수 유지·1단계 하향). 절대 DISPROVEN으로 취급하지 않는다.

    판정_규칙:
      All_Pass: |
        What + So_What + How 세 가지 모두 구체적 증거와 함께 입증됨.
        → 원래 심각도 유지. Finding_Classification: "Confirmed_Vulnerability"

      Any_Fail: |
        What 또는 So_What 실패, 또는 How가 DISPROVEN(경로 부재 입증).
        → Original_Severity: 현재 Severity 값 보존
        → Finding_Classification: "Structural_Weakness"
        → Severity: INFO
        → Impact_Proof.Failed_Proofs: 실패한 증명 이름 목록 기록
        → 보고서의 "Structural Weakness" 별도 섹션에 기록
        → Security Score 산출에서 제외

      How_Untraced_Only: |
        What·So_What 통과, How가 ③ UNTRACED(진짜 미확정 — 경로 부재 입증도, ② ast_보강
        코드 리딩 확립도 모두 실패한 경우에만 해당). ② RESOLVED_BY_READING은 여기 아니다
        — 그건 원 심각도로 All_Pass 처리한다(콜그래프 미추적만으로 강등 금지).
        → Finding_Classification: "Confirmed_Vulnerability" 유지
        → Severity: 원래 심각도에서 1단계 하향 (예: HIGH→MEDIUM)
        → Reachability_Note: "static-untraced: <사유>" 기록 (외부 런타임 설정/플러그인 등)
        → Security Score 산출에 포함 (미추적을 반증으로 취급하지 않는다)

    Structural_Weakness_정의: |
      "기술적으로 존재하나 현재 서비스 맥락에서 비즈니스 영향을 입증할 수 없는 구조적 약점."

      특성:
      - Finding으로 기록되나 Security Score에 반영되지 않음
      - 보고서에 별도 섹션으로 표시 (인지 목적)
      - Compliance Check에서 추적 대상에 포함 (코드 변경 시 재평가)
      - 서비스 컨텍스트 변경 시 (새 기능 추가, 자산 가치 변경) Confirmed로 승격 가능

    Anti_Patterns:
      - "3 Proofs를 분석 범위 축소 목적으로 사용 — 이 게이트는 출력 필터이며 입력 필터가 아님"
      - "So_What에서 이론적 위험만으로 통과 — 구체적 서비스 시나리오 필수"
      - "How에서 Step 1 결과를 복사 — 비즈니스 맥락 재해석 필요"
      - "모든 Finding을 Structural_Weakness로 분류하여 점수를 인위적으로 높임"
      - "UNTRACED(추적 불가)를 DISPROVEN(경로 부재 입증)으로 취급해 점수에서 제외 — 정적 추적 한계를 안전 근거로 오용 금지"
      - "정적 콜그래프 미추적을 곧바로 UNTRACED 강등으로 처리 — 먼저 ast_보강(코드 리딩) 시도 필수. 읽어서 도달 경로가 확립되면(예: 인라인 dispatch 테이블) 원 심각도 유지(강등 금지)"

  Step_2_보상_제어_확인:
    설명: "다른 레이어에서 동일 위협을 차단하는 보상 제어가 있는가?"
    프로토콜: "common/compensating-control.md의 4단계 프로토콜을 실행한다."
    절차:
      - "Step 1: 위협 경로의 모든 레이어를 순회한다"
      - "Step 2: 각 레이어에서 후보 보상 제어를 식별한다"
      - "Step 3: 5개 질문(범위/정밀도/우회가능성/완전성/독립성)으로 유효성을 검증한다"
      - "Step 4: Effective_Complete/Effective_Narrow/Partial/Ineffective/Unverifiable로 판정하고 기록한다 (compensating-control.md Step 4가 정본)"
    원칙:
      - "보상 제어의 존재 ≠ 위협 차단 — 유효성이 코드에서 입증되어야 한다"
      - "Effective_Complete 판정 시 심각도 1단계 하향 허용"
      - "Effective_Narrow 판정 시 0.5단계 하향 + narrow/time-limited/config-dependent 태그"
      - "Partial/Ineffective/Unverifiable은 원래 심각도 유지"

  Step_2.5_검증_경로_분류:
    설명: "Unverifiable 보상 제어를 후속 검증 단계로 라우팅하기 위해 분류한다."
    조건: "Step 2에서 Unverifiable로 판정된 보상 제어가 1건 이상"
    프로토콜: "common/compensating-control.md의 Verification_Routing 분류 기준을 적용한다."
    절차:
      - "각 Unverifiable 보상 제어에 대해 Verification_Routing 질문을 실행"
      - "HTTP 요청으로 확인 가능 → Unverifiable_HTTP (verification_target: PENTEST)"
      - "설정 파일/IaC에서 확인 가능 → Unverifiable_Infra (verification_target: REDTEAM)"
      - "모두 불가 → Unverifiable_External (verification_target: EXTERNAL)"
    산출: "Pending_Verification 목록 — offsec-lead를 통해 Pentest/Red Team에 전달"

  Step_3_경량_공격_체인:
    설명: |
      Self-Verify 완료된 CRITICAL/HIGH Finding 간 연결 가능성을 분석하여
      경량 공격 체인을 구성한다. Pentest의 정밀 공격 체인과 달리
      VA 수준에서 "이 Finding들이 조합되면 더 위험한가?"를 판단한다.
    조건: "CRITICAL + HIGH Finding이 합계 3건 이상인 경우 실행"
    절차:
      1_Finding_그룹화: |
        동일 데이터 흐름, 동일 엔티티, 동일 사용자 역할에 관여하는
        Finding들을 그룹화한다.
      2_체인_구성: |
        그룹 내에서 "A가 성공하면 B의 전제조건이 충족되는가?"를
        질문하여 최소 3개 공격 체인을 구성 시도한다.
        체인 구성이 3개 미만이면 가능한 만큼만 기록한다.
      3_체인_영향_평가: |
        개별 Finding 심각도의 합보다 체인의 영향이 큰 경우
        체인 전체를 승격 후보로 태그한다 (최종 결정은 Verify/CISO).
    출력: |
      Attack_Chains:
        - chain_id: "AC-{NNN}"
          steps: ["F-001 (A1 인증 우회)", "F-003 (A2 IDOR)", "F-007 (A3 데이터 유출)"]
          narrative: "인증 우회 → 타인 리소스 접근 → 민감 데이터 탈취"
          combined_impact: "개별 HIGH × 3 → 체인으로 CRITICAL 승격 후보"
    제약:
      - "VA 공격 체인은 코드 분석 기반 — 실현 가능성(Feasibility)은 Pentest에서 판정"
      - "체인 구성 시 새로운 Finding을 만들지 않음 — 기존 Finding 간 관계만 식별"
      - "Pentest Phase 2의 정밀 공격 체인을 대체하지 않음 — 조기 식별이 목적"

  적용_우선순위: "모든 Finding에 Step 1, 1.5, 1.7, 1.8, 2 필수. Unverifiable 존재 시 Step 2.5 필수. CRITICAL+HIGH ≥ 3건 시 Step 3 실행"

  결과_반영:
    Scoring: "Step 1~1.8, 2 결과(Impact Gate 분류 포함)로 조정된 심각도를 Phase 4 점수 산출에 반영"
    Report: "각 Finding의 Self-Verify 결과를 보고서에 기록 (도달 경로, 보상 제어 판정)"
    Verify_참고: "Verify(Phase R1)에서 이 결과를 재검증 대상으로 참조"
    Pending_Verification: |
      Step 2.5에서 분류된 항목을 보고서 '운영 환경 검증 필요 항목' 섹션에 기록하고,
      offsec-lead 핸드오프용 구조화 데이터로 출력한다.

  Pending_Verification_Format: |
    VA 보고서 말미에 아래 구조로 출력:

    Pending_Verification:
      PENTEST:
        - finding_id: "F-XXX"
          control: "[보상 제어 설명]"
          claim: "[이 보상 제어가 주장하는 차단 효과]"
          unverifiable_reason: "[VA에서 확인 불가한 이유]"
      REDTEAM:
        - finding_id: "F-XXX"
          control: "[보상 제어 설명]"
          claim: "[이 보상 제어가 주장하는 차단 효과]"
          unverifiable_reason: "[VA에서 확인 불가한 이유]"
      EXTERNAL:
        - finding_id: "F-XXX"
          control: "[보상 제어 설명]"
          required_access: "[필요한 운영 환경 접근 설명]"

  Pending_Verification_작성_원칙: |
    claim 필드는 "무엇을 주장하는가"만 기술한다.
    "어떻게 테스트할 것인가"를 VA가 지시하면 확증편향이 발생한다.

    금지 (테스트 스크립트):
      - "XSS 페이로드 <script>alert(1)</script>를 전송하여 403 확인"
      - "curl -X POST /api/comments로 WAF 차단 여부 확인"

    허용 (검증 대상 — claim):
      - "WAF가 /api/comments 경로에서 XSS 공격을 차단한다는 주장"
      - "Rate Limiter가 /api/auth/login에서 brute-force를 제한한다는 주장"
      - "API Gateway가 비인증 요청을 거부한다는 주장"

    Pentest/Red Team 에이전트가 Attacker_Mindset으로 자율적으로
    테스트 방법, 페이로드, 우회 기법을 결정한다.
    VA가 공격 방법을 지정하는 것은 Pentest의 독립성을 침해한다.
```

---

## Phase 4: 보안 점수 산출

```yaml
진입_조건:
  Self_Verify_Gate: |
    Phase 4 진입 전 모든 CRITICAL/HIGH Finding에 Self-Verify 결과가 있어야 한다.
    Self-Verify 결과가 없는 CRITICAL/HIGH Finding은 점수에 반영하지 않고
    Phase 3.5를 해당 Finding에 대해 재실행한다.
    MEDIUM/LOW는 Self-Verify 권장이나 필수 아님.
  필수_필드:
    - "reachability: 도달_가능 | 조건부_도달 | 도달_불가"
    - "classification: Confirmed_Vulnerability | Structural_Weakness"
    - "impact_proof_gate: PASS | FAIL"
    - "compensating_control: Effective_Complete | Effective_Narrow | Partial | Ineffective | Unverifiable | N/A"

Excluded_Categories: |
  ch015.config.json의 excludeCategories 설정을 확인한다.
  
  ⚠️ Anti-Confirmation-Bias 원칙:
  제외 카테고리는 "보고서 출력 필터"이지 "분석 범위 축소"가 아니다.
  모든 차원을 동일한 깊이로 분석한 후, 보고서 작성 단계(Phase 5)에서만
  해당 카테고리의 순수 Finding을 별도 섹션으로 분리한다.
  분석 중에는 제외 카테고리를 인지하지 않는다.
  제외된 후보도 삭제하지 않고 Raw Findings Ledger에 final_status=EXCLUDED
  또는 BACKLOG로 보존하며, 최종 보고서의 Excluded Candidates 섹션에
  건수와 제외 사유를 공시한다.

  - dos: true
    적용 시점: Phase 5(보고서 작성) — 분석 중 아님
    동작: A8 차원 분석 결과 중 순수 DoS Finding만 "제외된 항목" 섹션으로 이동.
    ⚠️ 복합 목적 Finding은 제외하지 않음:
      - Rate limiter 우회가 brute-force/credential stuffing의 전제 조건인 경우 → A1로 유지
      - 리소스 고갈이 서비스 장애를 유발하고, 장애 복구 경로에 보안 결함이 있는 경우 → 해당 차원으로 유지
      - 큐/채널 오버플로우가 비즈니스 로직 조작(강제 취소 등)을 가능하게 하는 경우 → BL로 유지
    판단 기준: "이 Finding이 제거되면 다른 공격 체인이 성립 불가능한가?"
      → 예 → 제외하지 않음 (공격 체인 구성 요소)
      → 아니오 → 순수 DoS → 제외 대상

  - internalTls: true
    적용 시점: Phase 5(보고서 작성) — 분석 중 아님
    동작: 내부 서비스 간 TLS 미적용 Finding만 "제외된 항목" 섹션으로 이동.
    ⚠️ 분석 깊이 유지 의무:
      내부 통신 코드(AMQP 연결, gRPC 서버, Redis 클라이언트)를 분석할 때
      TLS 제외 여부와 무관하게 아래를 반드시 확인한다:
      - 인증 메커니즘 (메시지 서명, 토큰 검증, mTLS, API 키)
      - 메시지 무결성 (HMAC, 스키마 검증)
      - 접근 제어 (브로커 ACL, 서비스별 credential)
      이것들은 TLS와 동일 코드 영역에 위치하므로,
      "TLS 제외"를 이유로 해당 코드 영역의 분석을 축소하면 안 된다.
    제외 대상이 아닌 것:
      - 인증 부재 → 암호화와 인증은 별개. 인증 Finding 반드시 유지.
      - 외부 통신 TLS 미적용 (인터넷 경유) → 외부 통신은 TLS 필수.
      - 민감 데이터(개인키, 니모닉) 평문 전송 → CRITICAL이면 제외 대상 아님.

  - configMistake: true
    적용 시점: Phase 5(보고서 작성) — 분석 중 아님
    동작: "설정 실수로 인한 잠재적 취약점"을 INFO로 분류한다.
    
    대상 판별 기준:
    1. 현재 안전한 설정이 적용되어 있으나
    2. 설정을 변경하면 취약해질 수 있는 항목
    
    대표 유형:
      - dev/mock 모드 플래그 (UseMock, DevMode, SKIP_VALIDATION 등)
        → 현재 OFF이면 INFO. 현재 ON이면 원래 심각도 유지.
      - 비활성화 가능한 보안 기능 (reorg detection disable, swagger enable 등)
        → 현재 비활성이면 INFO.
      - 디버그/테스트 전용 코드 경로 (AllowWalletFallback 등)
        → 현재 비활성이면 INFO. 코드 자체 삭제를 권고.
      - 커밋된 개발용 config 파일의 테스트 크레덴셜
        → 프로덕션에서 Vault 등으로 대체 확인 시 INFO.

    INFO 분류 시 보고서 기재:
      - "INFO (Configuration Risk)" 태그
      - 취약해지는 조건 명시: "UseMock=true 설정 시 전체 인증 우회"
      - 권고: startup assertion 추가, 코드 경로 제거, build tag 분리

    ⚠️ INFO 분류 금지 조건 (Guard Clauses):
      configMistake를 INFO로 분류하기 전에 아래를 반드시 확인한다.
      하나라도 해당하면 원래 심각도를 유지한다:
      
      1_External_Activation_Path: |
        설정 값이 외부 입력으로 변경 가능한 경우:
        - 환경 변수로 설정되며 배포 파이프라인 외부에서 주입 가능한 경우
        - API 파라미터/쿼리스트링으로 동적 전환 가능한 경우 (예: ?debug=true)
        - 설정 파일이 runtime에 재로드되는 경우 (hot-reload, config watch)
        - Feature flag 서비스로 원격 토글 가능한 경우
        → 원래 심각도 유지. "외부 활성화 경로 존재" 태그 추가.
      
      2_Config_Bomb_Pattern: |
        단일 설정 변경이 보안 메커니즘을 전면 무력화하는 경우:
        - UseMock=true → 전체 인증 우회
        - SKIP_VALIDATION=true → 전체 입력 검증 우회  
        - DEBUG_MODE=true → 에러 스택트레이스 + 내부 상태 노출
        → 원래 심각도 유지. startup assertion 추가를 CRITICAL 권고.
      
      3_No_Startup_Guard: |
        프로덕션 환경에서 위험 설정이 활성화되었을 때
        앱이 시작을 거부하는 guard가 없는 경우:
        - process.env.NODE_ENV !== 'production' 검사 없이 mock 사용
        - 컴파일 타임 분리(build tag, dead code elimination) 없이 코드 존재
        → 원래 심각도 유지 또는 최대 1단계만 하향 (INFO 금지).
      
      판정_순서:
        1. Guard Clause 3개 확인
        2. 모두 해당 없음 → INFO 분류 허용
        3. 1개 이상 해당 → 원래 심각도 유지, guard clause 위반 사유 기록

    ⚠️ INFO로 분류되지 않는 것:
      - 현재 활성 상태인 안전하지 않은 설정 → 원래 심각도 유지
      - 설정과 무관하게 존재하는 코드 레벨 취약점 → 원래 심각도 유지
      - 설정 변경 없이 악용 가능한 항목 → 원래 심각도 유지

산출_공식:
  Security_Score: "100 - (CRITICAL × 25 + HIGH × 10 + MEDIUM × 3 + LOW × 1)"
  note: "excludeCategories에 해당하는 Finding은 산출에서 제외"

  Strict_Formula_Enforcement: |
    ⚠️ 이 공식은 유일한 점수 산출 방법이다. 아래 행위를 금지한다:

    금지:
      - "보상 제어", "프로토타입 감안", "맥락 조정" 등을 이유로 공식 외 가산/감산 적용
      - Self-Verify 결과를 점수에 직접 반영 (Self-Verify는 심각도를 조정하고, 조정된 심각도가 공식에 들어감)
      - "체감 점수"와 "공식 점수"를 병기하거나 공식 점수를 override

    허용되는 점수 변동 경로:
      1. Self-Verify Step 1~2에서 심각도 변경 (예: HIGH → MEDIUM) → 변경된 심각도로 공식 재산출
      2. Step 1.8 Impact Gate에서 Structural_Weakness 분류 → INFO로 재분류 → 공식에서 자동 제외
      3. Evidence Verification(Phase 4.5)에서 Finding 강등 → 변경된 심각도로 공식 재산출

    검증: |
      보고서의 점수가 Finding 목록과 일치하는지 역산 검증한다.
      CRITICAL 수 × 25 + HIGH 수 × 10 + MEDIUM 수 × 3 + LOW 수 × 1 = 감점 총합
      100 - 감점 총합 = 보고서 Security Score
      불일치 시 보고서 발행 금지.
  Structural_Weakness_제외: |
    Classification = Structural_Weakness인 Finding은 Security Score 산출에서 제외한다.
    INFO로 재분류되므로 가중치 0이 자동 적용된다.
    보고서의 Structural Weakness 섹션에 원래 심각도를 별도 기록한다.
  Pass_조건:
    설명: |
      단일 점수만으로 합격 판정하면 리스크 프로파일 차이를 놓친다.
      아래 복합 조건을 모두 충족해야 PASS:
      (기준값 정본: ch015.config.json scoring.securityScore — 아래 수치는 가독성용 병기)
    기본:
      - "Score ≥ 85"
      - "CRITICAL = 0건"
      - "HIGH ≤ 2건"
      - "CVSS ≥ 9.0 Finding = 0건"
    강화_regulated:
      - "위 기본 조건 전부"
      - "Unverified 증거 비율 < 10% (분모=검증 대상 증거. PENDING_PENTEST/PENDING_EXTERNAL로 라우팅된 정당한 이연 Finding의 증거는 분자·분모 양쪽에서 제외한다 — 정직하게 미검증인 Finding을 후보로 추가·유지해도 게이트가 악화되지 않아야 하며, 이 지표는 '누락 유인'이 아니라 '검증 커버리지'를 측정한다)"
      - "모든 CRITICAL/HIGH에 CVSS 점수 기록"
    
  CVSS_보조_지표:
    설명: |
      Primary Score는 빠른 트렌드 비교용이다.
      CRITICAL/HIGH Finding에 CVSS 3.1 벡터를 보조 기록하여
      리스크 프로파일을 정밀하게 전달한다.
    적용_범위: "CRITICAL + HIGH Finding (필수). MEDIUM/LOW (선택)"
    절차:
      - "Attack Vector, Attack Complexity, Privileges Required, User Interaction 판정"
      - "Confidentiality/Integrity/Availability Impact 판정"
      - "CVSS 점수를 Finding Metadata에 기록"
    보고서_표기: |
      Finding Metadata에 병기:
      CVSS_v3_1: "8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)"
  등급:
    - "A: 95-100 (우수)"
    - "B: 85-94 (양호)"
    - "C: 70-84 (보통)"
    - "D: 50-69 (취약)"
    - "F: 0-49 (위험)"

  Business_Impact_Score:
    설명: |
      Primary Score는 기술적 심각도 기반이다.
      자산 가치를 반영한 비즈니스 영향 보조 지표를 산출하여
      CISO의 비즈니스 리스크 판단에 구조적 입력을 제공한다.
    산출: |
      각 Finding의 심각도 점수에 자산 가치 가중치를 적용:
      가중치: CROWN_JEWEL × 2.0, HIGH × 1.5, MEDIUM × 1.0, LOW × 0.5
      Business_Impact = Σ (심각도_점수 × 자산_가중치)
    용도: |
      - CISO Executive Summary에 Primary Score와 병기
      - 수정 우선순위 로드맵에서 자산 가치 반영
      - 동일 심각도 Finding 간 우선순위 차별화
    주의: |
      ⚠️ Business Impact Score는 분석 깊이를 조절하지 않는다.
      모든 차원은 자산 가치와 무관하게 동일한 깊이로 분석한다.
      이 점수는 오직 보고서 출력과 우선순위 결정에만 사용된다.
```

---

## Phase 4.5: 증거 독립 검증 (Evidence Verification)

> Phase 4(Scoring) 완료 후, 보고서 생성(Phase 5) 전에
> 모든 Finding의 file:line 증거를 파일 시스템에서 독립 재확인합니다.
> 이 단계는 할루시네이션(존재하지 않는 코드 참조)을 탐지하고 제거합니다.

```yaml
Evidence_Verification:
  프로토콜: "common/evidence-verification.md 참조"
  
  실행_절차:
    1_추출: |
      모든 Finding에서 file:line 참조를 Evidence_Manifest로 추출한다.
    2_검증: |
      각 참조를 Read/Glob 도구로 파일 시스템에서 직접 확인한다:
      - 파일 존재 여부
      - 해당 라인의 실제 코드가 claim과 일치하는지
      - 증거 분류(Observed/Unverified)의 정확성
    3_조정: |
      검증 실패한 증거를 Finding에서 제거하고,
      나머지 증거로 결론 유지 가능 여부를 판단한다.
      유지 불가한 Finding은 Unsubstantiated로 강등한다.
    4_재산출: |
      증거 조정으로 Finding이 변경되면 Security Score를 재산출한다.

  별도_Agent_위임: |
    Finding 15건 이상 또는 증거 50건 이상이면
    경량 Agent로 위임하여 메인 컨텍스트를 보존한다.
    common/evidence-verification.md의 Lightweight_Agent 참조.

  Gate: |
    Phase 5 진입 전 Evidence_Verification_Summary가 존재해야 한다.
    Invalidated 증거가 있으면 해당 Finding 조정이 완료되어야 한다.
```

---

## Phase 4.7: Raw Candidate Ledger 생성

> Phase 5 보고서 생성 전에 모든 취약점 후보를 구조화 파일로 보존합니다.
> Final report에 포함하지 않는 후보도 삭제하지 않고 상태 분류로 수렴합니다.

```yaml
Raw_Candidate_Ledger:
  목적: |
    탐지는 recall 우선, 검증은 precision 우선으로 분리한다.
    VA가 발견한 후보가 최종 보고서 작성 과정에서 조용히 사라지는 것을 금지한다.
    최종 보고서/백로그/펜테스트 계획은 모두 이 ledger에서 파생되어야 한다.

  생성_시점: "Phase 4.5 Evidence Verification 완료 직후, Phase 5 Report 진입 전"
  저장_경로: "engagement_dir/01_va_raw_findings_ledger-<round>.yaml"
  스키마: "templates/raw-findings-ledger.template.yaml"

  기록_대상:
    - "최종 Finding으로 승격한 모든 후보"
    - "MEDIUM 이상으로 1회라도 분류된 후보"
    - "인증/인가/결제/배포/시크릿/감사로그/웹훅/외부연동 관련 후보"
    - "외부 시스템 또는 인증 테스트 전제가 있어 확정 불가한 후보"
    - "다른 Finding에 흡수되는 후보"
    - "영향도는 낮지만 코드 결함이 명확한 후보"
    - "Verifier/Pentest가 후속 검증해야 할 Pending 후보"

  금지:
    - "최종 보고서에 넣지 않는다는 이유로 후보 삭제"
    - "Severity가 LOW/MEDIUM이라는 이유만으로 ledger 미기록"
    - "다른 Finding에 접었다고 원본 후보 미기록"
    - "외부 시스템 전제가 필요하다는 이유로 Out of Scope 처리"

  후보_상태:
    CANDIDATE: "검증 전 원시 후보"
    CONFIRMED: "코드/라이브 증거로 유효 취약점 확정"
    DOWNGRADED: "유효하나 심각도 하향 — final_mapping.downgrade_reason 필수 (report-gate 차단 필드)"
    FOLDED_INTO: "상위 Finding에 흡수됨 — folded_into 필수"
    BACKLOG: "유효하나 score-impacting Finding은 아님"
    EXCLUDED: "engagement 출력 필터로 제외 — exclusion_reason 또는 excluded_category 필수"
    PENDING_PENTEST: "라이브/인증/비즈니스 플로우 검증 필요 — routing.pentest_route + routing.pentest_plan_id 필수"
    PENDING_EXTERNAL: "repo 밖 시스템/운영 접근 확인 필요 — routing.required_access 또는 routing.external_system 필수"
    FALSE_POSITIVE: "반증 근거로 기각 — counter-evidence 필수"
    OUT_OF_SCOPE: "명시적 범위 밖 — scope reason 필수"
    DISPUTED: "VA/Verifier/Pentest 합의 실패 — CISO 처리 필요, final_mapping.dispute_reason 필수"
    UNCLASSIFIED: "발행 금지 상태"

  필수_필드:
    - "candidate_id"
    - "title"
    - "source_phase"
    - "severity_initial"
    - "severity_current"
    - "dimension"
    - "affected_instances"     # 이 취약점이 영향을 주는 endpoint/function/file/asset/flow 목록
    - "root_cause_location"    # 근본 원인 코드 위치 (file:line). Convergence에서 동일 위치 후보를 자동 그룹핑하여 FOLDED_INTO 판정에 사용
    - "remediation_key"        # 수정 방법 한 줄 슬러그. 같은 key = 같은 수정 = fold 후보. 예: "add-auth-to-testbed", "mask-webhook-body"
    - "final_status"
    - "evidence.class"
    - "evidence.locations 또는 live_evidence"
    - "validity.reachable"
    - "validity.business_relevance"
    - "validity.exploit_path"
    - "routing.verify_required"
    - "routing.pentest_route"
    - "(PENDING_PENTEST) routing.pentest_plan_id — 아래 Pentest_Plan_초안의 scenario_id 연결"
    - "(PENDING_EXTERNAL) routing.required_access 또는 routing.external_system"
    - "(DOWNGRADED) final_mapping.downgrade_reason"
    - "(DISPUTED) final_mapping.dispute_reason"

  Pentest_Routing_초기값:
    LIVE_UNAUTH: "인증 없이 안전하게 검증 가능"
    LIVE_AUTH_LOW_PRIV: "낮은 권한 세션 필요"
    LIVE_AUTH_ROLE_SPECIFIC: "특정 역할 세션 필요"
    LIVE_BUSINESS_FLOW: "테스트 데이터와 다단계 업무 흐름 필요"
    EXTERNAL_SYSTEM_REQUIRED: "repo 밖 서비스/worker/운영 접근 필요"
    CONFIG_REVIEW_ONLY: "라이브 검증보다 설정/코드 리뷰가 적합"
    NOT_SAFE_WITHOUT_APPROVAL: "명시 승인 전 실행 금지"

  발행_게이트:
    - "UNCLASSIFIED 후보가 1건이라도 있으면 Phase 5 최종 보고서 발행 금지"
    - "PENDING_PENTEST 후보는 pentest-plan.template.yaml에 1:1 라우팅되어야 함 — 후보의 routing.pentest_plan_id에 plan scenario_id 기록"
    - "PENDING_EXTERNAL 후보는 routing.required_access 또는 routing.external_system이 명시되어야 함"
    - "DOWNGRADED 후보는 final_mapping.downgrade_reason이 명시되어야 함"
    - "FOLDED_INTO 후보는 상위 finding_id가 명시되어야 함"
    - "EXCLUDED 후보는 exclusion_reason 또는 excluded_category가 명시되어야 함"
    - "FALSE_POSITIVE 후보는 반증 근거가 명시되어야 함"

# ⚠️ 생성 순서: 오케스트레이터가 발행 전 report-gate.js를 능동 호출(설계 A 1차 방어선,
# PreToolUse 훅은 활성화 시 보조)하며 ledger + pentest plan을 함께 읽으므로,
# pentest plan 초안은 보고서 작성 "이전"에 존재해야 한다.
Pentest_Plan_초안:
  생성_시점: "Phase 4.7 Raw Candidate Ledger 저장 직후, Phase 5 보고서 작성 이전 (필수 순서)"
  저장_경로: "engagement_dir/01_va_pentest_plan-<round>.yaml"
  # 라운드별 접두 규칙(va-auditor.md storage 기준): 1차(initial)=01_..-1st, 2차(feedback)=03_..-2nd
  # 예: 2차 라운드는 01_가 아니라 03_va_pentest_plan-2nd.yaml
  스키마: "templates/pentest-plan.template.yaml"
  절차: |
    ledger의 PENDING_PENTEST 후보를 pentest-plan.template.yaml 스키마로 1:1 라우팅한다.
    각 scenario에 candidate_id를 기록하고, ledger 후보의 routing.pentest_plan_id에
    해당 scenario_id를 역기록한다(양방향 연결).
    Pentest가 실제 테스트 방법을 자율 결정하되,
    VA는 필요한 전제조건과 안전 등급만 기록한다.
  Gate: "PENDING_PENTEST 후보가 1건 이상인데 plan 파일이 없으면 Phase 5 진입 금지"
```

---

## Phase 5: 보고서 + 영향도 분석

{project_root}/templates/va-report.template.md 참조

### Negative Findings (검토했으나 안전 판단 기록)

```yaml
Negative_Findings:
  목적: |
    분석 중 검토했으나 "안전하다"고 판단하여 Finding으로 보고하지 않은 항목을 기록한다.
    이것은 Verifier Agent가 VA의 "안전 판단"을 독립 재검증할 수 있게 하여
    확증편향(안전하다고 믿고 싶은 편향)을 차단한다.

  기록_의무: |
    아래 경우에 Negative Finding을 기록한다:
    1. 보안 메커니즘을 검토했으나 적절히 구현되어 Finding이 아닌 경우
    2. 잠재적 위험을 발견했으나 보상 제어로 충분히 차단된 경우
    3. 코드 패턴이 의심스러웠으나 실제로는 안전한 경우

  기록_형식: |
    보고서의 "건전한 아키텍처 패턴 인식" 섹션에 아래를 포함:
    
    Negative_Findings:
      - area: "검토 영역 (예: A1 인증 — 세션 고정)"
        location: "file:line"
        checked: "무엇을 검토했는가"
        conclusion: "안전하다고 판단한 이유"
        evidence: "안전 판단의 코드 증거 (Observed/Unverified)"
        residual_risk: "잔여 위험 (있다면)"

  Verify_연계: |
    Verifier Agent의 Phase R4(누락 탐색)에서
    Anti-Anchoring Protocol의 2_VA_Negative_대조 단계에서
    이 Negative Findings를 독립 재검증한다.
```

---

## Phase 5.1: Findings Index 생성

> Phase 5 보고서 완료 직후, 하류 에이전트(Verifier, Pentester, OffSec Lead)가
> 전문 보고서를 Read하지 않고도 Finding 목록을 파악할 수 있도록
> 경량 인덱스 파일을 동반 생성합니다.

```yaml
Findings_Index_Generation:
  trigger: "Phase 5 보고서 파일 생성 완료 직후 자동 실행"

  절차:
    1_Finding_추출: |
      Phase 5 보고서에서 각 Finding의 메타데이터만 추출한다:
      id, title, severity, dimension, location, root_cause,
      affected_instance_count (ledger affected_instances 항목 수),
      evidence_class (Observed/Unverified), cwe, cvss,
      classification (Confirmed_Vulnerability/Structural_Weakness),
      prerequisite_category
    2_라인_오프셋_기록: |
      보고서 내 각 Finding 섹션의 시작/끝 라인 번호를 기록한다.
      하류 에이전트가 Read(offset, limit)로 특정 Finding만 선택 열람할 수 있게 한다.
    3_Pending_Verification_추출: |
      Pending_Verification 섹션에서 PENTEST/REDTEAM/EXTERNAL 항목을 추출하고
      각 항목의 보고서 내 라인 오프셋도 함께 기록한다.
    4_Raw_Ledger_연결: |
      Phase 4.7의 raw-findings-ledger 경로를 인덱스와 handoff에 포함한다.
      final report에 없는 후보도 candidate_refs로 남기고 상태를 기록한다.
    5_Pentest_Plan_연결: |
      Phase 4.7에서 생성한 pentest plan 초안(01_va_pentest_plan-<round>.yaml) 경로를
      인덱스와 handoff에 연결한다. (plan 생성은 Phase 4.7에서 이미 완료 —
      이 시점에 신규 생성하지 않는다.) PENDING_PENTEST 후보 ↔ scenario 1:1 라우팅과
      routing.pentest_plan_id 역기록이 유지되는지 확인한다.
    6_저장: |
      engagement_dir에 보고서와 동일한 접두사 + "_index.yaml" 로 저장한다.
      예: 01_va_result-1st.md → 01_va_findings_index-1st.yaml
      grouped 모드: 01_va_result-1st-auth.md → 01_va_findings_index-1st-auth.yaml

  스키마: "templates/findings-index.template.yaml, templates/va-handoff.template.yaml 참조"

  예상_크기: "Finding 20건 기준 ~2-3K 토큰 (전문 50K+ 대비 95% 절감)"

  소비자:
    Verifier: "R1 증거 감사 시 인덱스에서 Finding 목록 파악 → 필요 시 선택 Read"
    Pentester: "pentest_plan과 pending_verification.PENTEST에서 대상 추출 → 전문 Read 불필요"
    OffSec_Lead: "Convergence 시 raw ledger + 인덱스에서 최종 상태 분류"

  agent_return_추가: |
    Agent 반환 메시지의 storage_paths에 인덱스 파일 경로를 추가한다.
    예: storage_paths: [
      01_va_result-1st.md,
      01_va_raw_findings_ledger-1st.yaml,
      01_va_findings_index-1st.yaml,
      01_va_pentest_plan-1st.yaml,
      01_va_handoff-1st.yaml
    ]
```

---

## Phase 5B: Baseline Snapshot 생성

> Full VA 완료 후 자동으로 기준선 스냅샷을 생성합니다.
> Compliance Check(이행점검)에서 이전 진단의 범위와 결과를 참조하는 데 사용됩니다.

```yaml
Baseline_Snapshot_Generation:
  trigger: "Phase 5 보고서 생성 완료 후 자동 실행"
  skip_when: "compliance_check(patch-verify, delta-scan) 모드에서는 생성하지 않음"

  절차:
    1_데이터_수집: |
      Phase 0(Recon) 결과에서:
      - commit_hash: git rev-parse HEAD
      - 분석 대상 파일 목록, 소스 라인 수
      - 활성 도메인, 분석 모드 (llm/ast)
      Phase 1~3 결과에서:
      - 분석된 차원 목록 (A1~A8)
      - 적용된 표준 (OWASP, CWE 버전)
      - 로드된 Tier 2 오버레이
      Phase 4 결과에서:
      - 심각도별 Finding 수 (Structural_Weakness 포함)
      - Security Score, Grade, Pass 여부

    2_파일_리스트_및_해시: |
      분석 대상 소스 파일의 정렬된 상대 경로 목록을:
      (a) 00_baseline_file_list.txt로 저장한다 (개별 파일 소속 확인용).
      (b) SHA-256 해시하여 baseline.scope.files_examined.list_hash에 기록한다 (동일 집합 빠른 검증용).
      Compliance delta-scan의 Previously_Undetected 판정은 (a)의 파일 목록을 사용한다.
      해시만으로는 개별 파일 소속 여부를 판정할 수 없으므로 파일 목록이 필수이다.

    3_저장: |
      engagement 디렉토리에 아래 2개 파일을 저장한다:
      - 00_baseline_snapshot.yaml (templates/baseline-snapshot.template.yaml 스키마)
      - 00_baseline_file_list.txt (분석 대상 파일의 정렬된 상대 경로, 줄당 1개)

  출력:
    - "{engagement_dir}/00_baseline_snapshot.yaml"
    - "{engagement_dir}/00_baseline_file_list.txt"

  용도:
    - "Compliance patch-verify: 이전 Finding 목록 참조"
    - "Compliance delta-scan: commit_hash 기준 git diff + 파일 커버리지 대조"
    - "Compliance full-reaudit: 이전 결과 비교 기준"
```

---

## Phase 5R: 규제 영향 참조 (Regulatory Impact Reference)

```yaml
Module: regulatory.md

Trigger: |
  Phase 1~2에서 발견된 Finding 중 규제 관련성이 있는 것이 1건 이상인 경우에만 실행.
  규제 관련 Finding이 0건이면 생략한다.

Scope: |
  가상자산, 금융, 개인정보 등 규제 민감 도메인에서 발견된 취약점을
  국내외 법률·규제 조항에 매핑하여 참고 정보로 보고서 말미에 첨부한다.
  법률 자문이 아니며, 법무팀 에스컬레이션 근거를 제공한다.

Key_Principles:
  - "법률명 + 조항 번호를 반드시 명시 (모호한 언급 금지)"
  - "적용 관할(🇰🇷/🇪🇺/🇺🇸/🌐)을 명시"
  - "위반 단정 금지 — '저촉 가능성 있으므로 법무 검토 권장'으로 기술"
  - "기술적 심각도를 규제 이유로 변경하지 않음"
```

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

### Finding Structure (모든 발견 사항에 필수)

모든 발견 사항은 아래 구조를 따릅니다. **모든 Finding은 6-step 영향도 분석을 마크다운으로 전개해야 하며, 테이블 형식 요약이나 단일 행 "개선 제안"으로 대체하는 것은 금지됩니다.**

> **ID 명명 규칙**: `knowledge-base/conventions/finding-id-naming.md` 참조 (F-/F-API-/F-S/V-/CAS-/AC-/AS{N}- 통합 규칙)

```yaml
Finding_Structure:
  F-XXX: "[아키텍처 이슈 이름]"

  Metadata:
    Architecture_Dimension: "A1~A8"
    Severity: "CRITICAL / HIGH / MEDIUM / LOW"
    Preconditions: |
      악용에 필요한 전제조건을 열거한다. 없으면 "None".
      예: "MITM 위치 확보", "개발자가 커스텀 로거 주입",
          "사용자가 악성 링크 클릭", "물리적 기기 접근" 등.
      심각도는 전제조건을 포함하여 종합적으로 판단한다.
      (기계적 심각도 조정 금지 — 영향 범위와 전제조건 난이도를 함께 고려)
    Location: "파일, 함수, 설정"
    Root_Cause: "ARCHITECTURE / CONFIGURATION / CODE / PROCESS"
    Asset_Value: "CROWN_JEWEL | HIGH | MEDIUM | LOW (Phase 0 Asset Register 기반, 관련 자산의 가치 등급)"
    Classification: "Confirmed_Vulnerability | Structural_Weakness"
    Original_Severity: "Step 1.8에서 Structural_Weakness로 재분류 시 원래 심각도 보존 (예: HIGH → INFO 시 Original_Severity: HIGH)"
    Affected_Instances:
      - type: "route | function | file | asset | flow | config"
        target: "영향받는 구체적 대상"
        evidence: "file:line 또는 live evidence"
        exploitability: "confirmed | likely | unverified | blocked | not_applicable"
    Impact_Proof:
      What: "영향받는 구체적 자산/데이터/기능"
      So_What: "구체적 공격 결과 시나리오"
      How: "외부 입력 → 취약 코드 도달 경로"
      Gate_Result: "PASS | FAIL (실패 시 어떤 증명이 실패했는지 명시)"
      Failed_Proofs: "실패한 증명 목록 (예: ['So_What', 'How']). PASS 시 빈 배열."
    Reference:
      CWE: "CWE-NNN (필수 — 가장 정확한 CWE ID. 복수 해당 시 쉼표 구분)"
      OWASP_Top10: "A01~A10 (필수 — 해당 없으면 'N/A')"
      OWASP_API_Top10: "API1~API10 (API 도메인 활성 시 필수, 그 외 선택)"
      Note: "CWE/OWASP는 분석의 조직 원리가 아닌 보고서 완전성을 위한 필수 매핑"

  Structural_Issue_Description: |
    이 이슈가 왜 구조적인지, 어떤 아키텍처 결정이 이를 만들었는지 설명.
    단순히 "취약점이 있다"가 아니라 "이런 설계로 인해 이런 문제가 발생"

  Evidence: |
    구체적 코드 참조 (file:line)
    추측 금지 — 코드에서 확인된 것만 보고

    [판단 기준]
    위험 판단과 안전 판단에 동일한 증거 기준을 적용한다.
    - "위험하다"는 결론 → 코드 증거 필수 (기존과 동일)
    - "안전하다"는 결론 → 코드 증거 역시 필수
      프레임워크/라이브러리의 보안 동작을 가정하지 않는다.
      해당 동작이 프로젝트 코드에서 실제로 적용/설정되는지 확인한다.
      확인 불가능한 경우 Unverified로 보고하고
      미적용 시 영향을 함께 기술한다.

    [도달 가능성 (Reachability)]
    취약 코드가 실제 실행 경로에서 도달 가능한지 검증한다.
    - 함수/메서드: 호출자(caller)를 코드 전체에서 검색하고
      호출 경로(call chain)를 기록한다.
      호출자 0건이면 증거에 "Dead Code — caller 0건" 명시.
    - 상태 설정: 미검증 입력에서 설정되는 내부 상태 변수를
      식별하고, 각 변수의 다운스트림 사용처(UI 표시, 보안 게이트,
      API 파라미터, 트랜잭션 등)를 추적하여 실제 영향 범위를 기록한다.
    - 보상 제어: common/compensating-control.md 프로토콜을 실행한다.
      (4단계: 레이어 순회 → 후보 식별 → 유효성 검증 → 기록)

    [증거 분류]
    모든 증거를 아래 중 하나로 명시한다:
    - Observed: 프로젝트 코드에서 직접 확인 (file:line)
    - Unverified: 라이브러리/프레임워크 기본값에 의존,
                  프로젝트 코드에서 확인 불가

  Fix_Recommendation_and_Impact_Analysis:
    1_Change_Target:
      description: "수정할 파일, 함수, 설정과 구체적 방향"

    2_Reference_Tracing:
      description: "변경 대상의 모든 호출/참조 지점 추적"
      trace_targets:
        - "callers: 이 함수를 호출하는 모든 함수/컴포넌트"
        - "importers: 이 모듈을 import하는 모든 파일"
        - "API clients: 이 엔드포인트를 호출하는 프론트엔드 코드"
        - "DB dependencies: 이 테이블/함수에 의존하는 트리거, 뷰, 정책"

    3_Impact_Scope:
      Direct_Impact: "변경 대상이 직접 구현하는 기능"
      Indirect_Impact: "변경 대상을 참조하는 다른 기능"

    4_Side_Effect_Risks:
      description: "변경으로 깨질 수 있는 기능 + 시나리오"

    5_Co_Requisite_Changes:
      description: "동시에 수정해야 하는 항목 + 수정 순서 + 마이그레이션 필요 여부"

    6_Post_Fix_Verification:
      description: "보안 점검 + 회귀 테스트 항목"
```
