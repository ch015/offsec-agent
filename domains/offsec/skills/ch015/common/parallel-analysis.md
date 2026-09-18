# 병렬 독립 분석 프로토콜 (Parallel Independent Analysis)

> 멀티 컴포넌트 프로젝트(프론트/백엔드, 다중 SDK, 마이크로서비스 등)를
> 독립 세션으로 분석한 뒤 교차 검증하여 확증편향을 방지하고
> 컴포넌트 간 신뢰 경계 취약점을 식별합니다.

---

## 설계 원칙

```yaml
Principles:
  Physical_Session_Isolation: |
    각 분석 단위(Unit)는 **물리적으로 격리된 Agent 세션**에서 실행한다.
    프롬프트 수준의 "이전 결과를 무시하라"는 지시가 아니라,
    Claude Code Agent 도구의 isolation: "worktree" 옵션을 사용하여
    각 Unit이 별도 git worktree + 별도 컨텍스트 윈도우에서 실행된다.

    이것은 다음을 보장한다:
    - Unit A의 Finding이 Unit B Agent의 컨텍스트에 물리적으로 존재하지 않음
    - 각 Agent가 자신의 컨텍스트 윈도우 전체를 해당 Unit 분석에 사용
    - 자동 컨텍스트 압축에 의한 교차 오염(cross-contamination) 원천 차단

  Trust_Assumption_Recording: |
    각 독립 세션은 "다른 컴포넌트가 이것을 할 것이다"라는
    신뢰 가정(Trust Assumption)을 명시적으로 기록한다.
    이 가정들이 교차 검증의 핵심 입력이 된다.

  Cross_Reference_Not_Merge: |
    독립 결과를 단순 합치지 않는다.
    교차 검증(Cross-Reference)은 독립 결과 간 모순, 간극, 
    신뢰 위반을 능동적으로 탐색하는 별도 분석 단계다.

  File_Based_Result_Exchange: |
    Agent 간 결과 교환은 반드시 파일 기반으로 수행한다.
    각 Unit Agent는 결과를 engagement 디렉토리에 파일로 저장하고,
    교차 검증 단계에서 OffSec Lead가 해당 파일을 읽어 분석한다.
    컨텍스트 내 보고서 누적을 금지한다.
```

---

## Phase 0: 분석 단위 분해 (Unit Decomposition)

프로젝트 구조를 분석하여 독립 분석 단위로 분해합니다.

```yaml
Unit_Detection:
  자동_분해_기준:
    디렉토리_구조: |
      프로젝트 루트에서 독립 빌드/배포 가능한 디렉토리를 식별한다.
      대표 패턴:
      - monorepo: packages/*, apps/*, services/*
      - 전통적: frontend/, backend/, api/, infra/
      - SDK 다중: sdk-ios/, sdk-android/, sdk-unity/, sdk-unreal/
      - 마이크로서비스: services/auth/, services/payment/, services/notification/

    의존성_그래프: |
      각 디렉토리의 의존성 파일(package.json, go.mod, requirements.txt 등)을
      분석하여 독립 빌드 단위를 확인한다.

    통신_경계: |
      HTTP 클라이언트/서버, gRPC, 메시지 큐, 공유 DB 접근 등
      컴포넌트 간 통신 경계를 식별한다.
      이 경계가 교차 검증의 핵심 대상이 된다.

  Unit_Types:
    frontend: "클라이언트 측 코드 (웹, 모바일, 데스크톱)"
    backend: "서버 측 API/비즈니스 로직"
    api_gateway: "API 게이트웨이/BFF/프록시"
    infra: "IaC, CI/CD, 배포 설정"
    sdk: "외부 배포 SDK/라이브러리 (인스턴스별 분리)"
    shared_lib: "내부 공유 라이브러리"
    worker: "백그라운드 잡/큐 컨슈머"
    database: "DB 스키마/마이그레이션/RLS 정책"

  수동_지정:
    설명: |
      자동 분해가 부정확하거나 사용자가 원하는 분석 단위가 있으면
      --units 옵션으로 명시적으로 지정할 수 있다.
    예시:
      - "--units frontend:src/web,backend:src/api,infra:deploy/"
      - "--units sdk-ios:platforms/ios,sdk-android:platforms/android"

  출력:
    unit_manifest:
      format: |
        ┌─────────────────────────────────────────────────────┐
        │ ANALYSIS UNIT MANIFEST                               │
        ├──────────┬────────────┬──────────────────────────────┤
        │ Unit ID  │ Type       │ Path                         │
        ├──────────┼────────────┼──────────────────────────────┤
        │ U1       │ frontend   │ packages/web/                │
        │ U2       │ backend    │ packages/api/                │
        │ U3       │ infra      │ deploy/                      │
        └──────────┴────────────┴──────────────────────────────┘

        Communication Boundaries:
        │ U1 → U2  │ HTTP REST (fetch → /api/*)               │
        │ U2 → U3  │ Env vars (Vault injection)               │
```

---

## Phase 1: 독립 분석 실행 (Independent Analysis)

각 Unit에 대해 **물리적으로 격리된 Agent 세션**을 실행합니다.

```yaml
Independent_Session:
  격리_구현:
    메커니즘: |
      각 Unit은 Claude Code Agent 도구를 사용하여 독립 세션으로 실행한다.
      반드시 isolation: "worktree" 옵션을 지정하여
      별도 git worktree에서 격리된 컨텍스트로 분석한다.

    Agent_호출_형식: |
      Agent({
        subagent_type: "va-auditor",
        isolation: "worktree",
        prompt: "<Unit 분석 지시 — 아래 공유_허용_정보만 포함>",
        description: "VA Unit {unit_id} 독립 분석"
      })

    병렬_실행: |
      독립적인 Unit Agent들은 단일 메시지에서 동시에 호출하여 병렬 실행한다.
      이것은 실행 순서에 의한 편향을 원천적으로 제거한다.
      Agent 도구는 동일 메시지에서 복수 호출을 허용한다.

    결과_수집: |
      각 Agent는 분석 결과를 engagement 디렉토리에 파일로 저장한다.
      Agent 완료 후 OffSec Lead는 결과 파일을 Read하여 교차 검증에 사용한다.
      Agent의 반환 메시지(컨텍스트 내)는 요약 정보만 포함한다.

  격리_규칙:
    컨텍스트_차단: |
      물리 격리에 의해 자동 보장됨 —
      각 Agent는 자신의 컨텍스트 윈도우만 가지므로
      다른 Unit의 Finding, 보고서, 요약 정보가 존재하지 않는다.
    실행_순서_독립: |
      병렬 Agent 실행으로 보장됨 —
      동일 메시지에서 동시 호출하므로 실행 순서가 결과에 영향 없음.
    공유_허용_정보: |
      각 Agent의 prompt에 동일하게 포함하는 정보:
      - 프로젝트 전체 기술 스택 요약 (언어, 프레임워크)
      - 프로젝트 레벨 (basic/standard/regulated)
      - 공개 API 스펙/인터페이스 정의 (OpenAPI, Proto 등 — 있는 경우)
      주의: API 스펙은 "계약"으로만 제공, 다른 Unit의 구현 상태는 알려주지 않음

  세션별_실행_내용:
    1_Recon: "해당 Unit 범위 내에서 Phase 0 실행 (기술 스택, 도메인, 공격 표면)"
    2_VA: "8차원 아키텍처 분석 — 해당 Unit 코드 범위 한정"
    3_Self_Verify: "Finding별 도달 가능성 + 보상 제어 검증"
    4_Trust_Assumptions: "신뢰 가정 기록 (아래 상세)"
    5_Report: "Unit별 독립 보고서 생성"

  신뢰_가정_기록:
    설명: |
      각 세션은 분석 중 "다른 컴포넌트가 이것을 처리할 것이다"라고
      가정한 모든 항목을 명시적으로 기록한다.
      이 가정들은 Phase 2 교차 검증의 핵심 입력이다.

    Trust_Assumption:
      format:
        id: "TA-{unit_id}-{NNN}"
        direction: "{this_unit} → {target_unit}"
        claim: "가정 내용"
        evidence_basis: "이 가정을 한 근거 (코드 참조)"
        impact_if_false: "가정이 틀렸을 때 영향 (관련 Finding ID)"
        confidence: "HIGH / MEDIUM / LOW"

    대표_가정_유형:
      서버_검증_가정: |
        Frontend: "서버가 입력값을 재검증할 것이다"
        → TA-U1-001: U1→U2, claim: "서버 측 입력 검증 존재",
          impact_if_false: "클라이언트 검증만으로는 F-003 CRITICAL로 승격"

      클라이언트_전송_가정: |
        Backend: "클라이언트가 항상 인증 헤더를 보낼 것이다"
        → TA-U2-001: U2→U1, claim: "클라이언트가 Authorization 헤더 포함",
          impact_if_false: "인증 미들웨어 우회 가능"

      인프라_보호_가정: |
        Backend: "WAF/API Gateway가 악성 요청을 차단할 것이다"
        → TA-U2-002: U2→U3, claim: "WAF 규칙이 SQL Injection 차단",
          impact_if_false: "F-007 보상 제어 Ineffective로 재분류"

      공유_라이브러리_가정: |
        SDK-A: "공유 인증 모듈이 토큰을 안전하게 저장할 것이다"
        → TA-U4-001: U4→shared, claim: "TokenManager가 Keychain 사용",
          impact_if_false: "모든 SDK에서 토큰 유출 위험"

      DB_정책_가정: |
        Backend: "RLS 정책이 테넌트 격리를 보장할 것이다"
        → TA-U2-003: U2→U5, claim: "RLS로 cross-tenant 접근 차단",
          impact_if_false: "F-012 테넌트 격리 우회 가능"

  Unit별_산출물:
    storage_dir: "knowledge-base/engagements/{project}_{YYYYMMDD}/"
    report: "{unit_id}_va_result.md"
    trust_assumptions: "{unit_id}_trust_assumptions.yaml"
    finding_summary: "{unit_id}_finding_summary.yaml"
    evidence_manifest: "{unit_id}_evidence_manifest.yaml"
    저장_의무: |
      각 Unit Agent는 분석 완료 시 반드시 위 파일들을 storage_dir에 저장한다.
      Agent의 반환 메시지에는 아래만 포함한다 (컨텍스트 절약):
      - security_score: 점수
      - finding_count: {CRITICAL: N, HIGH: N, MEDIUM: N, LOW: N}
      - trust_assumption_count: N건
      - storage_paths: [저장된 파일 경로 목록]
      전체 보고서 내용은 반환 메시지에 포함하지 않는다.

    파일_경합_방지: |
      병렬 Agent가 동일 engagement_dir에 동시에 쓸 때의 경합 조건 방지:
      1. 모든 파일명에 {unit_id} 접두사가 포함되어 파일명 충돌 없음
      2. worktree 격리에서도 engagement_dir은 절대 경로로 지정하여
         모든 Agent가 동일 물리 디렉토리에 쓰도록 한다
         (worktree는 git tracked 파일만 분리하므로,
          .gitignore에 포함된 engagement_dir은 worktree 간 공유됨)
      3. OffSec Lead는 모든 Agent 완료 후에만 결과 파일을 Read하므로
         읽기-쓰기 경합은 발생하지 않음
```

---

## Phase 2: 교차 검증 (Cross-Reference Analysis)

모든 독립 세션 완료 후, 결과 **파일**을 읽어 교차 분석합니다.

```yaml
Cross_Reference:
  실행_주체: "OffSec Lead가 직접 수행 (에이전트 위임 아님)"
  입력_방식: |
    OffSec Lead는 각 Unit Agent가 저장한 파일을 Read 도구로 읽는다.
    교차 검증에 필요한 섹션만 선택적으로 읽어 컨텍스트를 절약한다:
    - 신뢰 가정 검증: {unit_id}_trust_assumptions.yaml (전체)
    - Finding 상관: {unit_id}_finding_summary.yaml (전체)
    - 증거 확인 필요 시: {unit_id}_va_result.md (해당 Finding 섹션만)
  입력: "모든 Unit의 보고서 + 신뢰 가정 목록"

  Step_1_Trust_Verification:
    설명: |
      각 Unit의 신뢰 가정(TA)을 대상 Unit의 실제 분석 결과와 대조한다.
      이것이 교차 검증의 핵심이다.

    검증_프로세스:
      각_TA에_대해:
        1_대상_Unit_확인: "TA의 target_unit이 분석되었는가?"
        2_증거_탐색: |
          대상 Unit의 Finding과 Healthy Pattern에서
          TA의 claim을 뒷받침하거나 반박하는 증거를 찾는다.
        3_판정:
          VERIFIED: |
            대상 Unit에서 claim이 코드 증거로 확인됨.
            → 가정에 의존하는 Finding의 심각도 유지 또는 하향 검토
          CONTRADICTED: |
            대상 Unit에서 claim이 거짓으로 확인됨.
            → impact_if_false에 따라 관련 Finding 심각도 조정
            → 신규 Cross-Boundary Finding 생성
          UNVERIFIED: |
            대상 Unit에서 해당 코드가 없거나 확인 불가.
            → 가정을 "미검증 신뢰"로 기록, 보수적 판정 유지
          NOT_ANALYZED: |
            대상 Unit이 분석 범위에 포함되지 않음.
            → 운영 환경 확인 필요로 기록

    출력:
      trust_verification_matrix: |
        ┌────────────┬──────────────┬──────────────┬──────────────┐
        │ TA ID      │ Claim        │ 대상 Unit    │ 판정         │
        ├────────────┼──────────────┼──────────────┼──────────────┤
        │ TA-U1-001  │ 서버 입력검증 │ U2 (backend) │ CONTRADICTED │
        │ TA-U1-002  │ CORS 설정    │ U3 (infra)   │ VERIFIED     │
        │ TA-U2-001  │ 인증 헤더    │ U1 (frontend)│ VERIFIED     │
        │ TA-U2-002  │ WAF 차단     │ U3 (infra)   │ UNVERIFIED   │
        └────────────┴──────────────┴──────────────┴──────────────┘

  Step_1_5_Implicit_Trust_Detection:
    설명: |
      명시적 Trust_Assumption에 기록되지 않은 "암묵적 신뢰"를 탐색한다.
      이것은 확증편향의 핵심 사각지대이다:
      에이전트가 가정을 의식하지 못하면 Trust_Assumption에 기록하지 않고,
      기록되지 않은 가정은 교차 검증에서 빠진다.

    입력: |
      Tier 0의 shared_data_map (00_scan_manifest.yaml 또는 00_api_inventory.yaml)
      각 Unit의 Finding 목록

    탐색_프로세스:
      공유_데이터_검증_갭: |
        shared_data_map의 각 공유 리소스(DB 테이블, 큐 토픽)에 대해:
        1. Writer Unit의 분석 결과에서 "쓰기 전 검증" Finding이 있는지 확인
        2. Reader Unit의 분석 결과에서 "읽기 후 검증" Finding이 있는지 확인
        3. 양쪽 모두 검증 관련 Finding이 없으면
           → "양쪽 모두 안전하다"이거나 "양쪽 모두 놓쳤다"
           → 해당 리소스의 Write/Read 코드를 직접 Read하여 확인
        4. Writer가 외부 데이터를 무검증으로 쓰고 Reader가 DB를 신뢰하면
           → Cross-Boundary Finding (CB-XXX) 생성

      서비스간_인증_전파: |
        gRPC/HTTP 호출 관계에서:
        1. 호출 측이 인증 컨텍스트를 전달하는지 확인
        2. 수신 측이 인증 컨텍스트를 검증하는지 확인
        3. 어느 쪽도 Finding에 이 관계를 언급하지 않으면
           → 인증 전파가 양쪽 모두에게 "당연한 것"으로 간주된 것
           → 실제 코드를 Read하여 인증 전파 여부 확인

      에러_전파_경로: |
        서비스 A의 에러 응답이 서비스 B를 통해 최종 사용자에게 노출되는 경로.
        각 Unit이 독립적으로 "내 에러 처리는 안전하다"고 판단해도
        체인 전체에서는 내부 정보 유출이 가능.

    출력: |
      implicit_trust_findings:
        - id: "IT-{NNN}"
          resource: "공유 리소스/통신 경계"
          units: ["writer_unit", "reader_unit"]
          gap: "검증 갭 설명"
          severity: "추정 심각도"

  Step_2_Finding_Correlation:
    설명: |
      독립 세션에서 같은 근본 원인을 가리키는 Finding을 식별한다.
      동일 이슈가 여러 Unit에서 발견되면 시스템적 문제로 승격한다.

    탐색_항목:
      동일_패턴_반복: |
        Finding의 root_cause, dimension, 코드 패턴이 유사한 것을 그룹화한다.
        3개 이상 Unit에서 동일 패턴 → "Systemic Issue"로 태그.
      공유_라이브러리_전파: |
        shared_lib Unit의 Finding이 이를 사용하는 모든 Unit에 전파되는지 확인.
      일관성_검증: |
        유사 코드에 대해 Unit마다 심각도가 다르면 플래그.
        동일 판단 기준이 적용되었는지 검토.

  Step_3_Gap_Detection:
    설명: |
      어떤 Unit도 개별로는 발견할 수 없는
      컴포넌트 간 취약점을 능동적으로 탐색한다.

    탐색_질문:
      신뢰_경계_무방비: |
        "Unit 간 통신 경계에서 양쪽 모두 검증을 생략하는 곳이 있는가?"
        Frontend가 "서버가 검증"이라 하고 Backend가 "클라이언트가 검증"이라 하면
        실제로 아무도 검증하지 않는 구간이 존재한다.
      인증_전파_단절: |
        "인증 컨텍스트가 컴포넌트 체인을 따라 올바르게 전파되는가?"
        API Gateway → Backend → Worker → DB 체인에서
        인증이 중간에 소실되는 구간을 찾는다.
      데이터_분류_불일치: |
        "같은 데이터를 Unit마다 다른 민감도로 취급하는가?"
        Frontend는 PII를 마스킹하지만 Backend 로그에 평문 기록 등.
      에러_전파_정보_유출: |
        "한 Unit의 상세 에러가 다른 Unit을 통해 사용자에게 노출되는가?"
        Backend 스택 트레이스 → API 응답 → Frontend 에러 화면.

  Step_4_Severity_Reassessment:
    설명: |
      교차 검증 결과를 반영하여 심각도를 재조정한다.

    조정_규칙:
      신뢰_가정_CONTRADICTED: |
        가정이 거짓으로 확인된 경우:
        - impact_if_false에 명시된 대로 관련 Finding 심각도 조정
        - 신규 Cross-Boundary Finding 생성 (CB-XXX 접두사)
      신뢰_가정_VERIFIED: |
        가정이 검증된 경우:
        - 보상 제어로 인정하여 심각도 하향 검토 가능
        - 단, compensating-control.md 4단계 프로토콜 준수
      양쪽_미검증: |
        양쪽 Unit 모두 검증하지 않는 경계 발견 시:
        - 신규 Cross-Boundary Finding 생성
        - 기본 심각도: HIGH (검증 공백)
      패턴_반복_승격: |
        3+ Unit에서 동일 패턴 → Systemic Issue 태그
        - root_cause를 ARCHITECTURE 또는 PROCESS로 분류
        - 개별 수정이 아닌 공통 솔루션 권고
```

---

## Phase 3: 통합 보고서 (Synthesis)

```yaml
Synthesis:
  구성:
    1_Unit_Summary: |
      각 Unit별 독립 분석 결과 요약
      ┌──────────┬────────┬───────┬───────┬───────┬────────┐
      │ Unit     │ Score  │ CRIT  │ HIGH  │ MED   │ LOW    │
      ├──────────┼────────┼───────┼───────┼───────┼────────┤
      │ frontend │ 72/100 │ 1     │ 3     │ 5     │ 2      │
      │ backend  │ 65/100 │ 2     │ 4     │ 3     │ 1      │
      │ infra    │ 88/100 │ 0     │ 1     │ 2     │ 1      │
      └──────────┴────────┴───────┴───────┴───────┴────────┘

    2_Trust_Verification_Result: |
      신뢰 가정 검증 결과 매트릭스
      VERIFIED / CONTRADICTED / UNVERIFIED 분포

    3_Cross_Boundary_Findings: |
      교차 검증에서 발견된 신규 Finding (CB-XXX)
      개별 Unit에서 발견 불가했던 컴포넌트 간 취약점

    4_Systemic_Issues: |
      3+ Unit에서 반복되는 구조적 문제
      공통 근본 원인 + 공통 수정 방안

    5_Integrated_Score: |
      전체 프로젝트 통합 점수
      산출: 모든 Unit의 Finding + Cross-Boundary(CB-XXX) + Systemic(SYS-XXX)
      Finding을 단일 목록으로 통합한 후, 단일 공식으로 재산출한다:
        Score = 100 - (CRITICAL × 25 + HIGH × 10 + MEDIUM × 3 + LOW × 1)
      ⚠️ Unit별 점수의 가중 평균이 아니다 — 전체 Finding 통합 후 재산출
        (large-scale-flow.md Step_6_통합_Score_산출과 동일 원칙).
      ⚠️ Unit 유형별 가중치, Cross-Boundary 별도 감점 등 공식 외 가산/감산을
        금지한다 (va/SKILL.md Strict_Formula_Enforcement).
        CB/SYS Finding도 부여된 심각도로 동일 공식에만 반영한다.

    6_Merged_Roadmap: |
      전체 프로젝트 수정 우선순위
      Cross-Boundary > Systemic > Individual 순서

  Finding_ID_체계:
    Unit별: "F-{unit_id}-{NNN} (예: F-U1-001, F-U2-003)"
    Cross_Boundary: "CB-{NNN} (교차 검증 발견)"
    Systemic: "SYS-{NNN} (3+ Unit 반복 패턴)"

  storage:
    unit_reports: "{unit_id}_va_result.md"
    trust_assumptions: "{unit_id}_trust_assumptions.yaml"
    cross_reference: "00_cross_reference_result.md"
    synthesis: "00_parallel_synthesis.md"
```

---

## 적용 시나리오

```yaml
Scenario_Examples:
  모노레포_풀스택:
    units: ["frontend (React)", "backend (Node)", "infra (Terraform)"]
    핵심_교차점:
      - "Frontend 인증 토큰 처리 ↔ Backend 인증 미들웨어"
      - "Backend 환경 변수 참조 ↔ Infra 시크릿 설정"
      - "Frontend API 호출 ↔ Backend CORS/보안 헤더"

  멀티_SDK:
    units: ["sdk-ios", "sdk-android", "sdk-unity", "sdk-unreal"]
    핵심_교차점:
      - "각 SDK의 토큰 저장 방식 일관성"
      - "공유 백엔드 API 계약 준수 여부"
      - "플랫폼별 보안 API 사용 일관성"
    특수_규칙: |
      멀티 SDK 시나리오에서는 이전 SDK 결과를 절대로 다음 SDK에 전달하지 않는다.
      이것은 SYS-001 크로스 SDK 편향을 방지하기 위한 핵심 격리 규칙이다.

  마이크로서비스:
    units: ["auth-service", "payment-service", "notification-service", "api-gateway"]
    핵심_교차점:
      - "서비스 간 인증 전파 (JWT 포워딩, mTLS)"
      - "이벤트/메시지 무결성 (큐 메시지 검증)"
      - "장애 전파 (서비스 A 장애 → B 보안 약화)"

  프론트_백엔드_분리:
    units: ["web-app", "mobile-app", "api-server"]
    핵심_교차점:
      - "클라이언트 검증 ↔ 서버 검증 (이중 검증 여부)"
      - "API 응답 데이터 ↔ 클라이언트 노출 범위"
      - "인증 흐름 전체 체인 (로그인 → 토큰 발급 → API 사용 → 갱신)"
```

---

## 제약 사항

```yaml
Constraints:
  최소_Unit_수: "2개 이상이어야 병렬 분석의 의미가 있음"
  최대_Unit_수: "권장 5개 이하 — 교차 검증 조합이 기하급수적으로 증가"
  단일_Unit_폴백: |
    분해 결과 Unit이 1개인 경우 Standard_Flow로 폴백한다.
    사용자에게 "단일 컴포넌트 프로젝트로 판단하여 표준 진단을 실행합니다"를 안내.
  shared_lib_처리: |
    공유 라이브러리는 독립 Unit으로 먼저 분석한 후,
    사용하는 Unit의 분석 시에도 해당 코드에 접근 가능하게 한다.
    단, 공유 라이브러리의 Finding은 전달하지 않는다.
```

---

## Phase 4: Verify 연계

Parallel_Flow 완료 후 Standard_Flow의 Verify 단계에 연결하는 절차입니다.

```yaml
Phase_4_Verify_연계:
  설명: |
    Parallel_Flow는 Standard_Flow의 VA 단계를 대체한다.
    교차 검증(Phase_2) + 통합(Phase_3) 완료 후,
    통합 보고서를 기반으로 Verify를 실행한다.
  execution: |
    # model 규칙: agentModel.costOptimized=true일 때만 routing.* 값을 사용한다.
    #            costOptimized=false면 routing을 무시하고 agentModel.default로 실행한다.
    Agent({
      subagent_type: "verifier",
      model: config.agentModel.routing.tier1_verify,
      prompt: "Parallel Analysis 통합 보고서 검증\n
               target: {project_root}\n
               va_report_path_SEALED: 00_parallel_synthesis.md (★ R0.5 완료 전 Read 금지)\n
               unit_reports_SEALED: [{unit_id}_va_result.md 경로 목록 — 동일 봉인 규칙]\n
               cross_reference_SEALED: 00_cross_reference_result.md (동일 봉인 규칙)\n
               engagement_dir: {dir}\n
               지시: Verifier는 R0.5 Autonomous Discovery를 먼저 수행하고\n
               {engagement_dir}/02a_verify_autonomous-{round}.md 생성 후에만\n
               봉인 경로를 Read할 수 있다 (offsec-lead.md Phase_2_Verify와 동일 규칙).",
      description: "Parallel Verify"
    })
  va_report_path: |
    00_parallel_synthesis.md를 주 검증 대상으로 `va_report_path_SEALED` 라벨로 전달한다.
    Verifier는 R0.5(Autonomous Discovery) 완료 + 02a_verify_autonomous-{round}.md
    생성 후에만 봉인 경로를 Read할 수 있다 (Verifier Invariants I1/I2).
    R0.5 완료 후, 필요 시 Unit별 상세 보고서({unit_id}_va_result.md)를
    Read하여 개별 Finding 증거를 검증할 수 있다.
  후속: |
    Verify 완료 후 Pentest/Red Team은 Standard_Flow와 동일하게 연계.
```
