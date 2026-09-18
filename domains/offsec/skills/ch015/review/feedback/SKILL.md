---
name: ch015-feedback
description: "Run CH015 security design review workflows for PRDs and specs to produce security opinions or review findings mapped to standards and regulatory requirements."
---

# Security Design Review — 보안 설계 리뷰 스킬
> PRD/기획서를 분석하여 글로벌 보안 표준·규제에 근거한 **보안 의견서** 또는 **보안 검토 의견서**를 생성한다.

---

## 서비스 개요

| 항목 | 내용 |
|------|------|
| 서비스명 | Security Design Review |
| 방법론 | 문서 정찰 → 위협 표면 매핑 → 표준 바인딩 → 의견/검토 생성 |
| 출력물 | **Opinion**: 섹션별 MUST/SHOULD 의견 + 코드 예시 (OP-{NNN}) |
|        | **Review**: CRITICAL~LOW 검토 Finding + 설계 가이드 (C/H/M/L-{NN}) |
| 코드 수정 | 없음 (명세·의견 생성 전용) |
| 코드 분석 | 없음 (PRD/기획서 텍스트 분석) |
| 토큰 예산 | ~22-35K (Phase별 계층 로딩) |

---

## 출력 모드

```yaml
Mode_Selection:
  opinion:
    trigger: "--mode opinion (기본값)"
    대상: "개발자, AI 코딩 도구"
    관점: "구현 가이드 — '이렇게 만들어라'"
    ID: "OP-{NNN} (001부터 순차)"
    구조: "문서 섹션별 MUST / MUST NOT / SHOULD 의견 + 코드 예시"
    용도: "Cursor, Claude Code 등에 컨텍스트로 주입하여 보안 요건 반영 코딩"

  review:
    trigger: "--mode review"
    대상: "QSA, CISO, 경영진, 개발팀"
    관점: "감사 리포트 — '이 설계의 위험은 이것이다'"
    ID: "C-{NN} / H-{NN} / M-{NN} / L-{NN}"
    구조: "Severity별 Finding + 표준 Gap 분석 + Risk Acceptance Matrix"
    용도: "Go/No-Go 의사결정, 감사 대응, 규제 보고"
```

---

## 설계 원칙

```yaml
No_Pattern_Lists:
  - "CWE/OWASP 카탈로그를 기계적으로 나열하지 않는다"
  - "PRD 컨텍스트에서 실제 관련된 표준만 바인딩"
  - "도메인·관할에 따라 적용 표준이 달라짐을 인지"

Standards_Authority:
  - "권고하는 모든 알고리즘·파라미터에 근거 표준 인용 필수"
  - "표준이 명확하면 그대로 인용 (e.g., NIST SP 800-63B §5.1.1.2)"
  - "표준 간 충돌 시 가장 엄격한 기준 채택"
  - "표준이 업데이트된 경우 최신 버전 적용 (e.g., PCI DSS 4.0.1 future-dated 2025-03-31)"

Implementation_Specificity:
  핵심: "구현자가 바로 코딩할 수 있는 수준"
  bad_examples:
    - "암호화 적용"
    - "강력한 비밀번호 정책"
    - "적절한 접근 제어"
  good_examples:
    - "AES-256-GCM envelope encryption, DEK 로테이션 365일, CMK→DEK 2-tier"
    - "bcrypt cost 12, 최소 12자, zxcvbn score ≥ 3, breached-password 사전 차단"
    - "리소스별 ABAC, policy: {action, resource, condition}, 서버사이드 enforcement"

Conservative_Judgment:
  - "규제 적용 범위 불확실 시 '적용 가능성 있음'으로 포함"
  - "'이 정도면 안전하다'는 표현 금지"
  - "법률 자문이 아닌 기술 보안 관점의 참고 정보"
```

---

## Phase 구조 (Overview)

```
Phase 0: Input Normalization  → 입력 유형 판별 (문서/질문/구현의도) + 도메인·관할·차원 감지
Phase 1: Threat Surface Map   → 문서 섹션별 위협 표면 매핑 (8차원 활용)
Phase 2: Standard Binding     → 위협별 글로벌 표준/규제 바인딩
Phase 3: Opinion/Review/Consultation Gen → 모드별 출력 생성
Phase 4: Code Exemplification → 수정 코드 예시 생성 (의견 모드) 또는 설계 가이드 (검토 모드)
Phase 5: Checklist Assembly   → Phase별 체크리스트 + Risk Acceptance
Phase 6: Output Formatting    → 템플릿 기반 최종 출력
```

### 모드별 Phase 실행 맵

```yaml
Phase_Execution_Map:
  opinion:      [Phase_0, Phase_1, Phase_2, Phase_3, Phase_4, Phase_5, Phase_6]
  review:       [Phase_0, Phase_1, Phase_2, Phase_3, Phase_4, Phase_5, Phase_6]
  consultation: [Phase_0, Phase_2, Phase_3]
  consultation_예외:
    구현_가이드: [Phase_0, Phase_2, Phase_3, Phase_4]
    컴플라이언스_체크: [Phase_0, Phase_1, Phase_2, Phase_3]
```

---

## Phase 0: Input Normalization (입력 정규화)

```yaml
목적: "입력 유형을 판별하고 모드·도메인·관할·차원을 정규화된 context 구조체로 추출한다"

Step_0_0_입력_유형_판별:
  판별_기준:
    document: "파일 경로, Confluence URL, 또는 구조화된 설계 문서 텍스트"
    question: "문서 없이 질문·구현 의도·상황 설명만 입력"
  모드_결정:
    document_입력: "opinion (기본) 또는 review (--mode로 지정)"
    question_입력: "consultation (자동 전환)"
    명시적_override: "--mode consultation으로 강제 가능"
  consultation_패턴_분류:
    구현_가이드:
      시그널: "만들다, 구현, 개발, 추가, 적용"
      예시: "로그인 만들어야 하는데 뭐 조심해야 해?"
      Phase_Map: [Phase_0, Phase_2, Phase_3, Phase_4]
    Finding_트리아지:
      시그널: "지적, 취약점, 감사, 진단 결과, 고쳐야, 수정해야"
      예시: "감사에서 암호화 안 돼 있다고 지적받았는데 큰일이야?"
      Phase_Map: [Phase_0, Phase_2, Phase_3]
    비교_판단:
      시그널: "vs, 비교, 뭐가 나아, 차이, 중에"
      예시: "JWT랑 세션 중에 뭐가 안전해?"
      Phase_Map: [Phase_0, Phase_2, Phase_3]
    컴플라이언스_체크:
      시그널: "출시, 인증, 빠진, 누락, 체크리스트, 준비"
      예시: "다음 주 출시인데 결제 보안 빠진 거 없나?"
      Phase_Map: [Phase_0, Phase_1, Phase_2, Phase_3]
    인시던트_판단:
      시그널: "유출, 사고, 노출, 신고, 해킹"
      예시: "개인정보 유출된 것 같은데 신고해야 해?"
      Phase_Map: [Phase_0, Phase_2, Phase_3]
    보상_제어_정당화:
      시그널: "대체, 대신, 못 하는데, 다른 방법, 보완"
      예시: "WAF 못 다는데 다른 방법으로 대체해도 돼?"
      Phase_Map: [Phase_0, Phase_2, Phase_3]
      추가_로드: "skills/ch015/common/compensating-control.md"
    규정_간_갭:
      시그널: "인증 추가, 갭, 차이점, 전환, 추가로"
      예시: "ISMS 있는데 PCI DSS 추가로 받으려면 뭐가 더 필요해?"
      Phase_Map: [Phase_0, Phase_2, Phase_3]
    default: "시그널 매칭 실패 시 구현_가이드로 분류"

Step_0_1_입력_처리:
  document_모드:
    파일_경로: "Read 도구로 파일 내용 로드 (md, pdf 지원)"
    Confluence_URL: "WebFetch로 페이지 본문 추출"
    인라인_텍스트: "사용자 메시지에서 직접 추출"
    복수_입력: "각 입력을 순차 로드 후 병합. 섹션 경계 보존"
  consultation_모드:
    질문_파싱: "질문 텍스트에서 주제·의도·맥락 키워드 추출"
    컨텍스트_보충:
      원칙: "부족한 정보만 최대 2개 질문으로 보충. 비전문가 언어 사용"
      질문_예시:
        도메인: "결제 관련 서비스예요, 아니면 일반 웹서비스예요?"
        관할: "서비스 대상이 한국이에요, 해외도 포함이에요?"
        스택: "웹서비스예요, 앱이에요?"
        규모: "사용자가 대략 얼마나 되나요?"
      금지: "보안 전문 용어로 질문 (도메인, 관할, 차원 등)"
      판단: "질문에서 추론 가능하면 질문하지 않고 진행. 추론 근거 명시"

Step_0_2_문서_구조_파악:
  적용: "document 모드에서만 실행. consultation 모드에서는 스킵"
  추출_대상:
    - "문서 유형 식별 (PRD, 설계서, API 명세, 아키텍처 문서, 기능 명세)"
    - "섹션 목차 추출 — 의견 생성 시 섹션 단위로 대응"
    - "핵심 기능 목록 (e.g., 결제, 인증, 지갑, 관리자)"
    - "데이터 유형 (PII, 카드 정보, 암호화폐 주소, 세션 등)"
    - "사용자 유형 (일반 사용자, 판매자, 관리자, API 클라이언트)"
    - "외부 연동 (PG, 블록체인 노드, KYC 제공자, 세금 API 등)"
    - "배포 환경 힌트 (클라우드, 리전, 규모)"

Step_0_3_기술_스택_추론:
  방법: "문서 내 기술 언급, 아키텍처 다이어그램, API 명세에서 추론"
  consultation_모드: "질문 텍스트 + 보충 질문 답변에서 추론. 미특정 시 TypeScript/Node.js 가정"
  추론_대상:
    - "언어/프레임워크 (문서에 명시되지 않으면 '미특정'으로 남김)"
    - "인프라 (AWS/GCP/Azure, K8s, 서버리스 등)"
    - "데이터베이스 유형"
    - "인증/인가 아키텍처 (JWT, OAuth, SAML 등)"
  주의: "추론된 스택은 문서 근거와 함께 명시. 근거 없는 추론 금지"

Step_0_4_도메인_감지:
  method: "tier2-overlays/registry.yaml의 시그널 패턴을 문서/질문 텍스트에 자연어 매칭"
  주의: "코드 import가 아닌 PRD/질문 키워드 매칭 — '결제', '지갑', '토큰', 'API 키' 등"
  override: "--domain 옵션이 있으면 자동 감지 대신 강제 적용"
  Loading_Rule: "registry.yaml만 Read. 오버레이 파일은 Phase 1에서 조건부 로드"

Step_0_5_관할_감지:
  signals:
    - "서비스 대상 국가/지역 언급"
    - "법인 소재지"
    - "데이터 저장 위치"
    - "사용자 거주 국가"
  default: "global (다중 관할 가정)"
  override: "--jurisdiction 옵션이 있으면 강제 적용"

Step_0_6_차원_감지:
  적용: "consultation 모드에서 실행. document 모드는 Phase 1에서 전수 분석"
  method: "질문 키워드에서 관련 차원(A1-A8) 추출"
  매핑:
    A1_인증: "로그인, 인증, 비밀번호, MFA, 세션, 토큰"
    A2_인가: "권한, 접근 제어, 역할, 관리자, 승인"
    A3_데이터흐름: "암호화, 전송, 저장, 개인정보, 마스킹"
    A4_입출력경계: "입력, 검증, 업로드, XSS, 인젝션"
    A5_시크릿관리: "API 키, 시크릿, 인증서, 환경변수, 키관리"
    A6_외부통합: "외부 API, SDK, 서드파티, 라이브러리"
    A7_에러관찰: "로그, 에러, 모니터링, 알림"
    A8_리소스가용: "Rate Limit, DDoS, 가용성, 성능"
  default: "매칭 차원 없으면 질문 맥락에서 가장 관련 높은 2-3개 선택"

Output:
  context:
    input_type: "document | question"
    mode: "opinion | review | consultation"
    consultation_pattern: "구현_가이드 | Finding_트리아지 | 비교_판단 | 컴플라이언스_체크 | 인시던트_판단 | 보상_제어_정당화 | 규정_간_갭 (consultation 모드만)"
    phase_map: "[실행할 Phase 목록]"
    document_type: "PRD|설계서|API 명세|... (document 모드만)"
    sections: ["섹션1: 제목", ...]
    project: "프로젝트명"
    description: "1줄 요약"
    features: ["기능1", "기능2", ...]
    data_types: ["PII", "카드 정보", ...]
    user_types: ["일반", "관리자", ...]
    integrations: ["PG", "블록체인", ...]
    inferred_stack:
      languages: ["TypeScript", ...]
      infra: ["AWS", "K8s", ...]
      auth: "JWT + OAuth2"
    domains: ["payment", "web3", ...]
    jurisdiction: "uae|kr|eu|global|..."
    dimensions: ["A1", "A2", ...]
```

---

## Phase 1: Threat Surface Map (위협 표면 매핑)

```yaml
목적: "문서 섹션별로 보안 위협 표면을 식별하고 8대 아키텍처 차원에 매핑한다"

Step_1_1_오버레이_로드:
  절차:
    - "Phase 0에서 감지된 도메인의 tier2-overlay 파일을 Read"
    - "오버레이의 Core Architecture Questions를 위협 식별 시드로 활용"
    - "1-3개 오버레이만 로드 (토큰 예산 제약)"
  Loading_Rule: "감지된 도메인의 오버레이만 Read. 미감지 도메인 파일 로드 금지"
  Unload: "registry.yaml (Phase 0에서 사용 완료)"

Step_1_2_섹션별_위협_매핑:
  방법: |
    문서의 각 섹션(기능)을 8대 아키텍처 차원에 대해 질문한다:
      A1-인증: 이 기능에서 인증 메커니즘이 필요한가? 우회 경로는?
      A2-인가: 리소스 접근 제어가 필요한 지점은?
      A3-데이터흐름: 민감 데이터가 어디서 어디로 이동하는가?
      A4-입출력: 외부 입력 검증이 필요한 지점은?
      A5-시크릿: 키/토큰/자격증명 관리가 필요한 지점은?
      A6-의존성: 외부 서비스/라이브러리 신뢰 경계는?
      A7-에러처리: 민감 정보 노출 가능한 에러 경로는?
      A8-리소스: Rate limiting, DoS 방어가 필요한 지점은?
  참조: "knowledge-base/tier1-dimensions/a1-a8 파일은 Read하지 않는다. 차원명과 질문만 활용"

Step_1_3_위협_표면_레지스트리:
  출력_형식:
    per_section:
      section_ref: "문서 섹션 번호/제목"
      features: ["매핑된 기능"]
      threats:
        - dimension: "A1|A2|...|A8"
          threat: "위협 설명"
          data_at_risk: "위험 데이터"
          attack_scenario: "공격 시나리오 1줄"
    주의: |
      문서에서 언급하지 않는 기능에 대한 위협을 창작하지 않는다.
      위협이 식별되지 않은 차원은 기록하지 않는다 (모든 차원에 대해 위협을 억지로 채우지 않음).
```

---

## Phase 2: Standard Binding (표준·규제 바인딩)

```yaml
목적: "Phase 1에서 식별된 위협별로 적용 가능한 글로벌 표준·규제를 바인딩한다"

Step_2_1_표준_레지스트리_로드:
  action: "knowledge-base/standards/registry.yaml Read"
  내용: "도메인 → 표준 매핑 인덱스"
  Unload: "tier2-overlay 파일 (Phase 1에서 시드 추출 완료)"

Step_2_2_표준_매핑:
  절차:
    - "도메인 × 위협 차원 조합으로 적용 표준 목록 결정"
    - "매칭된 표준 YAML 파일만 조건부 Read (2-4개)"
    - "각 표준의 requirements 중 Phase 1 위협에 해당하는 항목 추출"
  Loading_Rule: "registry.yaml에서 매칭된 표준 파일만 Read. 전체 로드 금지"

Step_2_3_규제_바인딩:
  절차:
    - "관할에 따라 privacy-regulations.yaml 추가 로드"
    - "도메인별 산업 규제 적용 (결제→PCI, 금융→AML/CFT, 의료→HIPAA)"
  예시:
    jurisdiction_uae: "UAE Federal Decree-Law 45/2021 요건 추출"
    jurisdiction_eu: "GDPR 요건 추출"
    jurisdiction_kr: "개인정보보호법, 전자금융거래법 요건 추출"

Step_2_4_위협_표준_바인딩_테이블:
  출력_형식:
    per_threat:
      threat_ref: "Phase 1 위협 ID"
      section_ref: "원본 문서 섹션"
      applicable_standards:
        - standard: "PCI DSS 4.0.1"
          clause: "Req 3.5.1"
          requirement_summary: "저장 PAN 암호화"
        - standard: "NIST SP 800-175B"
          clause: "§4.2"
          requirement_summary: "AES-256 이상 대칭 암호"
      cwe_mapping: ["CWE-311", "CWE-327"]
      owasp_mapping: ["A02:2021"]
  병합_규칙:
    - "동일 위협에 복수 표준 적용 시 가장 엄격한 기준"
    - "표준 간 충돌 시 최신·최엄격 우선"
```

---

## Phase 3: Opinion/Review Generation (의견/검토 생성)

### Mode: Opinion (의견서)

```yaml
목적: "위협별 MUST / MUST NOT / SHOULD 보안 구현 의견을 생성한다"

Constraint_Levels:
  MUST:
    정의: "미준수 시 보안 목표 달성 불가"
    표기: "MUST (RFC 2119)"
    요건: "반드시 CWE/OWASP/NIST 근거 1개 이상"
    예시: "인증 토큰은 MUST 서버사이드에서 검증한다 (CWE-345, OWASP A07:2021)"
  MUST_NOT:
    정의: "실행 시 직접적 취약점 발생"
    표기: "MUST NOT (RFC 2119)"
    요건: "CWE 매핑 필수. 해당 코드 패턴이 왜 위험한지 구체 설명"
    예시: "클라이언트 제출 가격을 MUST NOT 결제 금액으로 사용한다 (CWE-472)"
  SHOULD:
    정의: "방어 심층(defense-in-depth), 베스트 프랙티스. 미준수 시 잔여 위험 증가"
    표기: "SHOULD (RFC 2119)"
    요건: "미준수 시 잔여 위험을 명시"
    예시: "API 응답에 SHOULD rate limit 헤더(X-RateLimit-*)를 포함한다 (미준수 시 클라이언트 자체 조절 불가)"

Quality_Gate:
  - "MUST에는 반드시 CWE/OWASP/NIST 근거 참조"
  - "MUST 비율 ≤ 50% (전체 의견 대비). 초과 시 SHOULD로 재분류 검토 — 과잉 설계 방지"
  - "코드 관련 MUST/MUST NOT에는 Phase 4에서 코드 예시 필수"
  - "문서 섹션 순서를 따른다. 섹션을 건너뛰지 않는다"

ID_Scheme: "OP-{NNN} (001부터 순차. 문서 섹션 순서)"

Output_Format:
  per_opinion:
    id: "OP-001"
    section_ref: "원본 문서 섹션"
    constraint: "MUST | MUST NOT | SHOULD"
    title: "의견 제목 (한글)"
    description: "의견 본문 — 무엇을, 왜, 어떤 수준으로"
    basis: "표준/규제 근거 (복수 가능)"
    cwe: "CWE-NNN (MUST/MUST NOT 필수)"
    risk_if_ignored: "미준수 시 위험 (1-2문장)"
```

### Mode: Review (검토 의견서)

```yaml
목적: "위협별 CRITICAL/HIGH/MEDIUM/LOW 보안 검토 Finding을 생성한다"

Severity_Levels:
  CRITICAL:
    정의: "Go-Live 차단. 법적 제재, 대규모 금전 손실, 인증 실패 초래"
    ID: "C-{NN}"
    시한: "출시 전 필수 해결"
    예시: "PAN 데이터 평문 저장 — PCI DSS 인증 불가"
  HIGH:
    정의: "30일 내 수정 필요. 보안 인시던트 발생 확률 높음"
    ID: "H-{NN}"
    시한: "30일"
    예시: "JWT 서명 검증 누락 — 토큰 위조 가능"
  MEDIUM:
    정의: "90일 내 권고. 보상 제어로 단기 완화 가능"
    ID: "M-{NN}"
    시한: "90일"
    예시: "API rate limiting 미설계 — DDoS 취약"
  LOW:
    정의: "개선 제안. 운영 비효율 또는 감사 지적 위험"
    ID: "L-{NN}"
    시한: "백로그"
    예시: "에러 응답에 내부 스택 트레이스 포함 가능성"

Dual_Perspective:
  QSA_view: "표준 준수 Gap 중심 — 어떤 조항을 충족하지 못하는가"
  CISO_view: "비즈니스 리스크 중심 — 이 Gap이 사업에 미치는 영향은 무엇인가"

Quality_Gate:
  - "CRITICAL은 법적/재무/인증 영향이 명확할 때만 부여"
  - "모든 Finding에 표준 근거 + 비즈니스 영향 + 권고 조치 포함"
  - "표준 준수 Gap Analysis 표 필수 (표준 × 조항 × Finding ID × 준수 상태)"
  - "Risk Acceptance 섹션 필수 (아래 Phase 5 참조)"

Output_Format:
  per_finding:
    id: "C-01 | H-01 | M-01 | L-01"
    severity: "CRITICAL | HIGH | MEDIUM | LOW"
    title: "Finding 제목 (한글)"
    section_ref: "원본 문서 섹션"
    description: "문제 설명 — QSA 관점"
    business_impact: "비즈니스 영향 — CISO 관점"
    basis: "표준/규제 근거"
    recommendation: "권고 조치 (알고리즘·파라미터 수준)"
    timeline: "수정 시한"
```

### Mode: Consultation (보안 상담)

```yaml
목적: "보안 비전문가의 질문에 표준·규제·법적·운영 관점의 근거 기반 답변을 생성한다"

대상_독자: "보안 비전문가 — 기획자, PM, 사업팀, 주니어 개발자"
차별_가치: "일반 AI 대비 knowledge-base(표준 7개 + 오버레이 11개 + 관할 5개) 기반 근거 인용"

톤_원칙:
  - "보안 용어 최소화. 사용 시 괄호로 평문 설명 병기"
  - "'이 정도면 안전하다' 금지 — opinion/review 모드와 동일"
  - "답변은 대화체. 템플릿 렌더링 아닌 자연어 응답"
  - "불확실 시 '확인 필요'로 명시. 추측 금지"
  - "첫 문단 또는 마지막 문단에 '이 답변은 공식 보안 감사가 아니며, 기술 보안 관점의 참고 정보입니다.' 면책 문구 포함"

패턴별_출력_구조:

  구현_가이드:
    구조: |
      📌 [주제] — 이렇게 구현해야 합니다

      [왜 중요한지 비즈니스 영향 1-2문장]

      꼭 해야 하는 것 (MUST):
      1. [평문 설명]
         → 개발팀 전달: "[기술 요약]"
         → 근거: [표준 조항]
         → 안 하면: [리스크]

      하면 좋은 것 (SHOULD):
      1. [평문 설명]
         → 안 하면: [잔여 리스크]

      [구현 가이드 패턴일 때 Phase 4 코드 예시 포함]

  Finding_트리아지:
    구조: |
      📌 [취약점명] — [수정 필수 | 보상 제어로 대체 가능 | 조건부 수용 가능]

      이게 왜 문제인지:
      → [비전문가 이해 가능한 위험 설명]

      판정 근거:
      → [표준 조항] 기준으로 [필수/권장] 사항입니다
      → [관할 규제] 위반 시 [제재 내용]

      [수정 필수인 경우]
      개발팀에 요청: "[구체적 조치]"

      [보상 제어 가능한 경우]
      대안: "[보상 제어 설명]"
      → 유효 조건: [compensating-control.md 기준]

  비교_판단:
    구조: |
      📌 [A] vs [B] — [상황별 권장]

      | 기준 | [A] | [B] |
      |------|-----|-----|
      | 보안 수준 | ... | ... |
      | 표준 권고 | ... | ... |
      | 적합 상황 | ... | ... |

      결론: [상황별 명확한 권장]
      → 근거: [표준 조항]

  컴플라이언스_체크:
    구조: |
      📌 [표준명] 기준 체크리스트

      ✅ 충족 항목: [확인된 것]
      ❌ 미충족/미확인 항목:
      1. [항목] — [표준 조항] — [미충족 시 영향]

      → 출시 가능 여부: [가능/조건부/불가]

  인시던트_판단:
    구조: |
      🚨 [상황] — [신고 필요/불필요/확인 필요]

      지금 해야 할 것:
      1. [즉시 조치]
      2. [24시간 내 조치]

      법적 의무:
      → [관할 규제]: [신고 시한] 이내 [신고 대상 기관]에 신고
      → 미신고 시: [제재 내용]

      ⚠️ 이 답변은 기술 보안 관점 참고 정보입니다. 법무팀 확인을 권장합니다.

  보상_제어_정당화:
    구조: |
      📌 [원래 조치] 대신 [대체 조치] — [유효/부분 유효/부적절]

      판정 근거:
      → [표준]에서 요구하는 보호 수준: [설명]
      → 제안된 대체 수단의 커버리지: [분석]

      [유효한 경우]
      조건: [유효성 유지 조건]
      문서화 필요: [감사 시 제출할 근거]

      [부적절한 경우]
      이유: [미달 사유]
      최소 대안: [실행 가능한 최소 조치]

  규정_간_갭:
    구조: |
      📌 [기존 규정] → [목표 규정] 갭 분석

      이미 충족: [교차 영역 요약]
      추가 필요:
      1. [갭 항목] — [목표 규정 조항] — [이행 난이도]

      예상 이행 기간: [추정]
      핵심 갭: [가장 큰 차이 1-2개 설명]

Quality_Gate:
  - "모든 답변에 최소 1개 표준/규제 근거 인용 필수"
  - "consultation 모드는 공식 보안 감사가 아님을 명시"
  - "법적 판단은 '기술 관점 참고 정보' 면책 문구 병기"
  - "인시던트 패턴은 항상 '법무팀 확인 권장' 부기"
  - "신고 의무·신고 시한·감독기관·과징금/벌칙·법적 제재는 최신 공식 출처 확인 필수"
  - "공식 출처 확인이 불가능하면 단정 금지. '확인 필요'와 기준일(as-of date)을 표시"
  - "확신도가 낮은 답변은 '추가 확인 필요' 명시 — 과신 금지"
```

### Consultation Regulatory Currentness Gate

```yaml
목적: "변동 가능성이 큰 법·규제 답변을 knowledge-base 기억만으로 확정하지 않는다"
적용_대상:
  - "신고 의무, 신고 시한, 감독기관, 과징금/벌칙, 법적 제재"
  - "jurisdiction_specific 규제 판단"
  - "인시던트_판단, 컴플라이언스_체크, 규정_간_갭 패턴"
필수_절차:
  1_기준일_명시:
    - "답변에 '기준일: YYYY-MM-DD'를 포함한다"
  2_공식_출처_확인:
    - "정부/감독기관/표준기관 원문 또는 공식 FAQ를 우선 확인"
    - "내장 knowledge-base는 보조 근거로만 사용"
    - "공식 출처 확인이 가능하면 출처명과 URL/path를 명시"
  3_확인_불가_처리:
    - "네트워크·출처 접근 불가 시 단정 표현 금지"
    - "'확인 필요', '법무팀 확인 권장', '기술 관점 참고 정보'를 명시"
    - "신고 필요/불필요를 확정하지 않고 조건부 판단으로 답변"
  4_출력_필드:
    regulatory_sources:
      - name: "공식 출처명"
        url_or_path: "URL 또는 knowledge-base path"
        checked_at: "YYYY-MM-DD"
        confidence: "official_confirmed | kb_only | unverified"
금지:
  - "오래된 knowledge-base만으로 신고 시한·제재 확정"
  - "출처 확인 없이 '반드시 신고해야 합니다'처럼 단정"
  - "법률 자문처럼 해석"
```

---

## Phase 4: Code Exemplification (코드 예시 / 설계 가이드)

### Mode: Opinion

```yaml
목적: "MUST/MUST NOT 의견에 잘못된 코드(❌)와 올바른 코드(✅)를 대비한다"

적용_대상: "코드 구현이 관련된 모든 MUST, MUST NOT 의견"
코드_스택: "Phase 0에서 추론된 기술 스택 기반. 미특정 시 가장 보편적 스택(TypeScript/Node.js) 사용"

Format:
  per_opinion_with_code:
    opinion_ref: "OP-NNN"
    bad_example:
      label: "❌ 위험한 구현"
      code: |
        // 클라이언트 제출 가격을 그대로 결제에 사용
        const amount = req.body.amount;
        await pg.charge({ amount, orderId });
      explanation: "공격자가 요청 body의 amount를 0으로 조작 가능 (CWE-472)"
    good_example:
      label: "✅ 권장 구현"
      code: |
        // 서버사이드에서 주문 DB 기준 금액 조회
        const order = await Order.findById(req.body.orderId);
        const amount = order.calculatedTotal; // 서버 계산 금액
        await pg.charge({ amount, orderId: order.id });
      explanation: "결제 금액은 서버가 계산한 값만 사용. 클라이언트 입력 불신"

주의:
  - "코드 예시는 핵심 로직만. 보일러플레이트, import, 에러 핸들링은 최소화"
  - "SHOULD 의견은 코드 예시 선택적 (복잡한 구현이 필요한 경우만)"
  - "프레임워크 특화 구문보다 로직 패턴을 보여준다"
```

### Mode: Review

```yaml
목적: "Finding에 대한 설계 수준 권고와 아키텍처 가이드를 제공한다"

적용_대상: "CRITICAL, HIGH Finding (MEDIUM은 선택적)"

Format:
  per_finding_with_guide:
    finding_ref: "C-01"
    design_guidance:
      current_state: "현재 설계에서의 Gap 요약"
      target_state: "달성해야 할 보안 상태"
      approach: |
        1. 토큰화 서비스 도입 (PAN → Token 매핑, 별도 PCI 스코프)
        2. DEK/CMK 2-tier envelope encryption 적용
        3. 키 로테이션 자동화 (CMK 365일, DEK 트랜잭션별)
      reference_architecture: "해당 시 아키텍처 다이어그램 텍스트 설명"
      standards_alignment: "PCI DSS 4.0.1 Req 3.5.1, NIST SP 800-57 Part 1"

주의:
  - "소스코드 수준이 아닌 아키텍처/설계 수준 가이드"
  - "구현 선택지가 여러 개면 장단점과 함께 나열"
  - "LOW Finding에는 설계 가이드 불필요 (recommendation으로 충분)"
```

---

## Phase 5: Checklist Assembly (체크리스트 + Risk Acceptance)

```yaml
목적: "의견/Finding을 실행 가능한 체크리스트로 조립하고 Risk Acceptance를 명시한다"

Step_5_1_체크리스트_생성:
  opinion_mode:
    구조:
      - "[ ] OP-001: [MUST] 인증 토큰 서버사이드 검증"
      - "[ ] OP-002: [MUST NOT] 클라이언트 제출 가격 사용"
      - "[ ] OP-003: [SHOULD] Rate limit 헤더 포함"
    정렬: "MUST → MUST NOT → SHOULD 순서. 각 그룹 내 문서 섹션 순"

  review_mode:
    구조:
      - "[ ] C-01: PAN 토큰화 미설계 — 출시 전 해결"
      - "[ ] H-01: JWT 서명 검증 누락 — 30일"
      - "[ ] M-01: API rate limiting 미설계 — 90일"
      - "[ ] L-01: 에러 응답 정보 노출 — 백로그"
    정렬: "CRITICAL → HIGH → MEDIUM → LOW 순서"

Step_5_2_Risk_Acceptance:
  필수: true
  설명: |
    "제로 리스크는 존재하지 않는다. SHOULD/MEDIUM/LOW 항목 중
     비즈니스 판단으로 수용 가능한 잔여 위험을 명시적으로 기록한다."
  포맷:
    per_accepted_risk:
      id: "OP-NNN 또는 M-NN/L-NN"
      risk_description: "수용하는 위험"
      justification: "수용 근거 (비용 대비 영향, 보상 제어 등)"
      compensating_control: "대체 완화 조치 (있는 경우)"
      review_date: "재검토 일자 (미지정 시 '다음 정기 리뷰')"
  주의:
    - "MUST / MUST NOT / CRITICAL / HIGH는 Risk Acceptance 대상이 아님"
    - "Risk Acceptance는 '빈 섹션'이 되어도 반드시 포함 (해당 없음 시 '해당 없음' 명시)"

Step_5_3_이터레이션_비교:
  trigger: "--previous <path> 옵션 제공 시"
  절차:
    - "이전 리뷰 문서를 Read"
    - "이전 의견/Finding과 현재를 ID/내용 기준 매칭"
    - "신규(NEW), 유지(UNCHANGED), 변경(CHANGED), 해결(RESOLVED) 분류"
    - "Delta Summary 섹션 추가"
  출력:
    delta_summary:
      new: ["OP-015: 신규 OAuth 스코프 관련"]
      resolved: ["OP-003: 이전 리뷰에서 지적된 세션 관련 — 설계 반영 확인"]
      changed: ["OP-007: rate limit 기준값 변경"]
      unchanged_count: 12
```

---

## Phase 6: Output Formatting (최종 출력)

```yaml
목적: "템플릿 기반으로 최종 문서를 조립하여 출력한다"

Step_6_1_템플릿_선택:
  opinion_mode: "templates/feedback-opinion.template.md (Opinion 섹션)"
  review_mode: "templates/feedback-opinion.template.md (Review 섹션, <!-- REVIEW MODE TEMPLATE --> 이후)"
  Unload: "표준 YAML (Phase 2에서 지침 추출 완료)"

Step_6_2_템플릿_렌더링:
  공통_섹션:
    - "프로젝트 메타 (이름, 일자, 버전, 입력 문서)"
    - "적용 표준 목록"
    - "문서 개요 (Phase 0 결과 요약)"
  opinion_mode_섹션:
    - "문서 섹션별 의견 (OP-NNN + 코드 예시 인라인)"
    - "체크리스트 (MUST → MUST NOT → SHOULD)"
    - "Risk Acceptance"
    - "부록: 표준 크로스 레퍼런스 (OP-ID × 표준 × 조항)"
  review_mode_섹션:
    - "Executive Summary (Severity 분포, 핵심 위험 3줄 요약)"
    - "Finding 상세 (Severity별 그룹)"
    - "표준 준수 Gap Analysis 표"
    - "체크리스트 (Severity 순)"
    - "Risk Acceptance Matrix"
    - "부록: 표준 크로스 레퍼런스 (Finding-ID × 표준 × 조항)"

Step_6_3_저장:
  opinion: "{target}/reports/ch015-{project}-{date}-opinion.md"
  review: "{target}/reports/ch015-{project}-{date}-review.md"
  fallback: "저장 경로가 없으면 출력만 수행"

Step_6_4_템플릿_미존재_시:
  절차: |
    템플릿 파일이 없으면 Phase 6에서 직접 마크다운을 조립한다.
    위 섹션 구조를 기반으로 출력. 템플릿은 가이드일 뿐 하드 의존성이 아님.
```

---

## 컨텍스트 로딩 프로토콜

```yaml
Phase_0_로드:
  고정: "이 SKILL.md (이미 로드됨)"
  조건부: "tier2-overlays/registry.yaml (도메인 감지용)"
  토큰: "~2K"

Phase_1_로드:
  조건부: "감지 도메인의 tier2-overlay 1-3개"
  언로드: "registry.yaml (Phase 0에서 사용 완료)"
  토큰: "~3-8K"

Phase_2_로드:
  고정: "standards/registry.yaml"
  조건부: "매칭 표준 YAML 2-4개"
  언로드: "tier2-overlay (Phase 1에서 시드 추출 완료)"
  토큰: "~5-10K"

Phase_3_6_로드:
  고정: "templates/feedback-opinion.template.md 또는 feedback-spec.template.md"
  언로드: "표준 YAML (Phase 2에서 지침 추출 완료)"
  토큰: "~1K"

합계_예상:
  opinion_review: "~22-35K (입력 문서 크기에 따라 변동)"
  consultation: "~8-15K (Phase 1,5,6 스킵 + 차원 한정 표준 로드)"

원칙:
  - "한 시점에 로드된 knowledge-base 파일은 최대 4개"
  - "Phase 완료 시 해당 Phase에서만 필요했던 파일은 결과만 보존하고 원문 해제"
  - "해제란 해당 파일의 상세 지시를 더 이상 참조하지 않고 Phase 결과만 유지하는 것"

Consultation_로딩:
  Phase_0: "registry.yaml만 (~1K). 도메인·차원 감지 후 즉시 해제"
  Phase_2: "감지 차원에 해당하는 표준 YAML만 1-2개 (~3-6K). 전체 로드 금지"
  Phase_3: "템플릿 불필요 — 자연어 응답 직접 생성"
  Phase_4: "구현 가이드 패턴일 때만 코드 예시 생성 (추가 로드 없음)"
  보상_제어: "보상_제어_정당화 패턴 시 compensating-control.md 추가 로드 (~2K)"
```

---

## 옵션 및 파라미터

```yaml
Parameters:
  required:
    input: "분석 대상 문서 또는 질문 (파일 경로, Confluence URL, 인라인 텍스트, 또는 자연어 질문)"

  optional:
    --mode: "opinion (기본) | review | consultation (문서 없으면 자동 전환)"
    --domain: "도메인 강제 지정 (auto-detect 대신)"
    --jurisdiction: "관할 강제 지정 (e.g., kr, eu, uae, global)"
    --level: "essential | standard (기본) | comprehensive"
    --previous: "이전 리뷰 파일 경로 (이터레이션 비교 활성화)"
    --target: "출력 저장 디렉토리"

Usage_Examples:
  기본: "/ch015:feedback docs/prd-payment.md"
  리뷰_모드: "/ch015:feedback docs/prd-payment.md --mode review"
  도메인_강제: "/ch015:feedback docs/prd-wallet.md --domain web3"
  이터레이션: "/ch015:feedback docs/prd-v2.md --previous reports/ch015-myapp-20260401-opinion.md"
  Confluence: "/ch015:feedback https://wiki.example.com/pages/viewpage.action?pageId=12345"
  상담_구현가이드: "/ch015:feedback 인증 구현하고 싶은데 뭐 조심해야 해?"
  상담_트리아지: "/ch015:feedback 취약점 진단에서 XSS 나왔는데 꼭 고쳐야 해?"
  상담_비교: "/ch015:feedback JWT랑 세션 중에 뭐가 더 안전해?"
  상담_컴플라이언스: "/ch015:feedback 다음 주 출시인데 결제 보안 빠진 거 없나? --domain payment"
  상담_인시던트: "/ch015:feedback 개인정보 유출된 것 같은데 신고해야 해? --jurisdiction kr"
  상담_보상제어: "/ch015:feedback WAF 못 다는데 입력값 검증으로 대체해도 돼?"
  상담_갭분석: "/ch015:feedback ISMS 인증 있는데 PCI DSS 추가로 받으려면 뭐가 더 필요해?"
```

---

## Anti-Patterns

```yaml
금지_사항:
  Pattern_Dump:
    설명: "CWE/OWASP 카탈로그를 PRD 컨텍스트 무관하게 전부 나열"
    올바른_접근: "PRD에서 실제 관련된 표준 항목만 바인딩"

  Vague_Recommendations:
    설명: "'암호화 적용', '적절한 인증' 등 구체성 없는 권고"
    올바른_접근: "알고리즘·파라미터·프로토콜 수준 명세"

  Scope_Creep:
    설명: "PRD에 없는 기능에 대한 보안 요구사항 생성"
    올바른_접근: "PRD 범위에 충실. 누락 우려 시 별도 '범위 외 권고' 메모로 분리"

  Legal_Advice:
    설명: "'이 구현으로 GDPR 준수 완료' 등 법적 판단"
    올바른_접근: "'GDPR Art.32 기준 기술적 보호조치 명세' — 법무 검토 필요 부기"

  Over_Loading:
    설명: "모든 표준 YAML을 한 번에 로드하여 토큰 낭비"
    올바른_접근: "도메인·위협에 매칭된 파일만 조건부 Read"

  Code_Analysis:
    설명: "소스코드를 분석하거나 코드 기반 Finding을 생성"
    올바른_접근: "문서 텍스트만 분석. 코드 진단은 /ch015:va로 위임"

  Zero_Risk_Pretense:
    설명: "'이 의견을 모두 반영하면 보안 완료' 등 절대 안전 암시"
    올바른_접근: "Risk Acceptance 섹션으로 잔여 위험 명시. 보안은 지속적 프로세스"

  MUST_Inflation:
    설명: "대부분의 의견을 MUST로 분류하여 과잉 설계 유도"
    올바른_접근: "MUST ≤ 50% 품질 게이트. 방어 심층은 SHOULD로 분류"

  Orphan_Threat:
    설명: "위협을 식별했으나 표준 근거 없이 의견만 생성"
    올바른_접근: "모든 MUST/MUST NOT에 CWE/OWASP/NIST 근거 필수"
```

---

## Root Cause 해당 없음

이 스킬은 기존 코드의 문제를 진단하지 않으므로 Root Cause Classification을 사용하지 않습니다.
출력은 코드 Finding이 아닌 **보안 의견서** 또는 **보안 검토 의견서**입니다.
