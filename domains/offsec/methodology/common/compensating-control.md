# 보상 제어 검증 프로토콜 (Compensating Control Verification Protocol)

> Finding의 심각도를 보상 제어(Compensating Control)로 조정할 때,
> "보상 제어의 존재"가 아닌 "이 특정 위협에 대한 실제 차단 유효성"을 검증합니다.

---

## 설계 원칙

```yaml
Principles:
  Existence_Is_Not_Effectiveness: |
    "보상 제어의 존재"는 심각도 하향의 충분조건이 아니다.
    보상 제어가 "이 특정 위협을 실제로 차단하는가"가 입증되어야 한다.

  Same_Evidence_Standard: |
    동일한 증거 기준을 적용한다:
    - "취약하다"는 결론 → 코드 증거 필수
    - "안전하다"는 결론 → 코드 증거 필수
    - "보상 제어가 있다" → 코드 증거 필수
    - "보상 제어가 이 위협을 차단한다" → 코드 증거 필수

  No_Pattern_Matching: |
    "이런 취약점에는 이런 보상 제어가 있을 수 있다"라는
    패턴 목록에 의존하지 않는다.
    패턴 목록은 닫힌 집합이며:
    - 목록에 있는 보상 제어만 인식하는 편향 유발
    - 매칭만 하고 유효성 미검증 시 False Negative(미탐) 발생
    보상 제어는 AI가 코드를 탐색하여 자율적으로 식별하고,
    아래 프로토콜로 유효성을 검증한다.

  Conservative_Default: |
    검증이 불완전하면 보수적으로 판단한다.
    - 유효성 미확인 → 원래 심각도 유지
    - 부분 유효 → 심각도 조정은 보수적으로 (1단계 이하)
    - 완전 유효 → 심각도 조정 근거로 사용 가능
```

---

## 4단계 검증 프로토콜

### Step 1: 레이어 순회 (Layer Traversal)

```yaml
Step_1:
  목적: "각 Finding에 대해, 위협이 통과하는 모든 레이어를 열거"

  방법론: |
    취약 코드가 위치한 레이어를 기준으로,
    해당 위협이 도달하기까지 거치는 상위/하위 레이어를 식별한다.

    질문: "이 위협이 실제로 악용되려면 어떤 경로를 거쳐야 하는가?"

  탐색_방향:
    상위: "클라이언트 → CDN/WAF → LB → 미들웨어 → 핸들러"
    하위: "핸들러 → 서비스 → ORM/쿼리 → DB → DB정책(RLS등)"
    횡방향: "동일 레이어의 다른 보안 메커니즘"

  산출: |
    이 위협에 대한 레이어 맵
    각 레이어에서 위협과 관련된 처리가 있는지 여부 표시
```

### Step 2: 차단 주장 식별 (Candidate Identification)

```yaml
Step_2:
  목적: "각 레이어에서 이 위협을 차단할 수 있는 메커니즘 식별"

  방법론: |
    AI가 코드를 탐색하여, 각 레이어에서 해당 위협과 관련된
    보안 메커니즘을 자율적으로 식별한다.

  주의: |
    "메커니즘의 존재"만으로 "차단 주장"을 만들지 않는다.
    메커니즘의 설정과 적용 범위를 코드에서 확인해야 한다.

  산출: "후보 보상 제어 목록 (각각에 코드 위치 file:line 포함)"
```

### Step 3: 유효성 검증 (Effectiveness Verification)

```yaml
Step_3:
  목적: "각 후보 보상 제어가 이 특정 위협을 실제로 차단하는지 검증"

  검증_질문:

    범위_Coverage:
      question: "이 보상 제어가 취약한 엔드포인트/경로에 실제로 적용되는가?"
      examples: |
        - WAF가 있지만 해당 경로가 WAF 제외 목록에 있으면 무효
        - Rate Limiter가 있지만 해당 엔드포인트가 제외되어 있으면 무효
        - 미들웨어가 있지만 해당 라우트가 opt-out 목록에 있으면 무효
        - 서버 검증이 있지만 이 특정 파라미터는 검증 대상이 아니면 무효

    정밀도_Precision:
      question: "이 보상 제어가 이 특정 공격 벡터를 차단하는가?"
      examples: |
        - WAF SQL Injection 룰이 있지만 NoSQL Injection은 미커버
        - 입력 검증이 있지만 이 특정 파라미터는 검증하지 않음
        - CORS 제한이 있지만 preflight가 필요 없는 simple request는 통과
        - 인증이 있지만 인가(소유권 확인)는 미적용

    우회가능성_Bypassability:
      question: "이 보상 제어 자체를 우회할 수 있는가?"
      examples: |
        - 클라이언트 측 검증만 존재 (서버에서 미검증)
        - Rate Limiter가 IP 기반이지만 IP 로테이션 가능
        - WAF가 있지만 직접 API 접근 경로(WAF 우회) 존재
        - 헤더 기반 제어지만 헤더 조작 가능

    완전성_Completeness:
      question: "이 보상 제어가 위협의 모든 변형을 차단하는가?"
      examples: |
        - XSS 필터가 있지만 특정 인코딩 우회 가능
        - 입력 길이 제한이 있지만 다중 요청으로 분할 가능
        - 하나의 진입점은 보호되지만 다른 진입점은 미보호

    독립성_Independence:
      question: "이 보상 제어가 원본 취약점과 같은 root cause를 공유하지 않는가?"
      examples: |
        - 동일 개발자/팀이 동일 실수를 반복했을 가능성
        - 동일 설정 누락이 원본과 보상 제어 모두에 영향
        - 동일 라이브러리의 미설정이 양쪽 모두에 해당
```

### Step 4: 기록 및 판정 (Record and Verdict)

```yaml
Step_4:
  판정_기준:

    Effective_Complete:
      조건: |
        5개 질문 모두 통과 + 각 항목당 **Observed 증거 2개 이상 필수**
        (예: 코드 + 설정 파일 / 테스트 케이스 + CI 확인).
        단일 증거만 존재하면 자동으로 Effective_Narrow로 강등.
      영향: "심각도 1단계 하향 가능 (CRITICAL→HIGH, HIGH→MEDIUM)"
      기록: "Finding 증거에 Effective_Complete + 증거 2개 인용"
      예시: "WAF 룰 + 프로덕션 배포 로그 + deploy.sh에 해당 룰 활성화 확인"

    Effective_Narrow:
      조건: |
        5개 질문 통과하나 scope/time/context가 제한적이거나 증거가 1개뿐.
        예: rate limit 10 rpm이 자동화는 막되 저속 수동 시도는 허용.
        예: 프로덕션에만 적용되고 staging/preview는 제외.
        예: config-dependent (env var로 끄면 사라짐).
      영향: "심각도 0.5단계 하향 + 'narrow/time-limited/config-dependent' 태그"
      기록: "Finding 증거에 Effective_Narrow + 제약 조건 명시"
      규칙: |
        - config-dependent인 경우 prod=worst-case 가정
        - 예: WAF가 .env로 비활성화 가능 → 비활성화된 상태 가정하여 원래 심각도 유지
        - CISO에게 'config drift risk' 플래그

    Partial:
      조건: "일부 질문 통과 + 나머지 Unverified 또는 부분 통과"
      영향: "심각도 변동 없음 — Partial은 완전한 차단을 입증하지 못하므로 원래 심각도를 유지한다"
      기록: "Finding 증거에 Partial 보상 제어로 기록 + 미통과 항목 명시"

    Ineffective:
      조건: "하나라도 명확히 실패 (범위 미적용, 우회 가능 등)"
      영향: "보상 제어로 인정하지 않음 — 심각도 변동 없음"
      기록: "Finding 증거에 Ineffective 사유 기록 (분석 투명성)"

    Unverifiable:
      조건: "코드에서 확인 불가 (인프라 레벨, 외부 서비스 등)"
      영향: "심각도 유지 — Unverified 보상 제어로 기록"
      기록: "Finding 증거에 Unverifiable로 기록 + 확인 필요 사항 명시"
      하위_분류:
        Unverifiable_HTTP:
          조건: "HTTP 요청으로 차단 여부를 라이브 검증할 수 있는 보상 제어"
          verification_target: PENTEST
          예시:
            - "WAF/CDN 규칙 — 실제 요청을 보내 차단 응답 확인 가능"
            - "Rate Limiter — 반복 요청으로 429 응답 확인 가능"
            - "API Gateway 인증 — 비인증 요청으로 거부 확인 가능"
            - "BaaS(Supabase/Firebase) 보안 규칙 — API 호출로 확인 가능"
        Unverifiable_Infra:
          조건: "설정 파일/IaC/컨테이너 설정에서 검증할 수 있는 보상 제어"
          verification_target: REDTEAM
          예시:
            - "사설망/VPC 격리 — 네트워크 설정 파일에서 확인"
            - "컨테이너 비root 실행 — Dockerfile/compose에서 확인"
            - "TEE/Enclave 격리 — 인프라 설정에서 확인"
            - "볼륨 마운트 읽기전용 — 컨테이너 설정에서 확인"
            - "CI/CD 시크릿 관리 — 파이프라인 설정에서 확인"
        Unverifiable_External:
          조건: "소스코드/설정/라이브 테스트 모두 검증 불가 — 운영 환경 직접 확인 필요"
          verification_target: EXTERNAL
          예시:
            - "클라우드 콘솔에서만 확인 가능한 IAM 설정"
            - "물리 네트워크 분리"
            - "외부 제3자 서비스의 내부 보안 정책"

  기록_포맷: |
    Finding의 Evidence 섹션에 아래 구조로 기록:

    Compensating_Controls:
      - control: "[보상 제어 이름/설명]"
        location: "file:line (코드 위치) 또는 N/A (코드 외)"
        coverage: "Effective_Complete | Effective_Narrow | Partial | Ineffective | Unverifiable"
        evidence_count: 2    # Effective_Complete는 2 이상 필수 (P2-6)
        evidence_items:
          - { type: "code",   ref: "src/waf.ts:42" }
          - { type: "config", ref: "deploy/waf-rules.yaml:7" }
        verification:
          범위: "PASS | FAIL | UNVERIFIED — [상세]"
          정밀도: "PASS | FAIL | UNVERIFIED — [상세]"
          우회가능성: "PASS | FAIL | UNVERIFIED — [상세]"
          완전성: "PASS | FAIL | UNVERIFIED — [상세]"
          독립성: "PASS | FAIL | UNVERIFIED — [상세]"
        config_dependent: false   # true이면 prod=worst 가정 → 심각도 유지
        severity_impact: "변동 없음 | -1 (CRITICAL→HIGH) | -0.5 (HIGH→HIGH with narrow tag)"
        verification_target: "PENTEST | REDTEAM | EXTERNAL | N/A"
```

### Verifier Re-verification Mandate (P2-6)

```yaml
Verifier_Phase_R1:
  mandate: |
    Verifier Phase R1(Evidence Audit)에서 Finding이 compensating_controls 필드를
    포함한다면, 해당 컨트롤의 증거 재확인이 필수다. VA의 판정을 그대로 수용하지
    않고 Verifier가 직접:
      1. evidence_items의 각 파일:라인을 Read로 재확인
      2. evidence_count가 coverage에 맞는 하한 이상인지 검증
         (Effective_Complete → ≥2, Effective_Narrow → ≥1)
      3. config_dependent=false인데 실제로 env var/설정 플래그에 의존 → 재분류
      4. 재분류 결과가 VA와 다르면 objection type="severity_dispute" 발행
```

---

## Anti-Patterns (이 프로토콜이 하지 않아야 하는 것)

```yaml
Anti_Patterns:
  Pattern_Matching_Shortcut: |
    "이런 취약점에는 이런 보상 제어" 식의 매칭으로 유효성 검증을 생략하지 않는다.
    모든 보상 제어는 위의 4단계를 거쳐야 한다.

  Existence_Equals_Protection: |
    "WAF가 있으므로 XSS는 OK" 식의 존재 기반 판단을 하지 않는다.
    WAF의 룰셋, 적용 범위, 우회 가능성을 코드/설정에서 검증해야 한다.

  Defensive_Stacking: |
    여러 보상 제어를 나열하여 "다층 방어이므로 안전"이라 결론내지 않는다.
    각 보상 제어를 개별적으로 검증하고, 어느 것도 Effective가 아니면
    개수와 무관하게 심각도를 유지한다.

  Infra_Assumption: |
    "프로덕션은 사설망이므로 안전" 등 코드에서 확인 불가한
    인프라 가정으로 심각도를 하향하지 않는다.
    인프라 보상 제어는 Unverifiable 하위 유형으로 분류하고 심각도를 유지한다.
    후속 검증(Pentest/Red Team)에서 확인될 때까지 원래 심각도를 보수적으로 유지한다.
```

---

## 검증 경로 라우팅 (Verification Routing)

> Unverifiable로 판정된 보상 제어를 후속 검증 단계(Pentest / Red Team)에
> 라우팅하기 위한 분류 기준입니다.

```yaml
Verification_Routing:
  목적: |
    VA 단계에서 Unverifiable로 판정된 보상 제어를
    적절한 후속 검증 단계로 자동 라우팅하여,
    최종 보고서의 False Positive를 줄인다.

  분류_기준:
    PENTEST:
      질문: "이 보상 제어의 차단 여부를 HTTP/API 요청으로 확인할 수 있는가?"
      판단:
        - "차단 시 HTTP 응답(403, 429, 401 등)이 달라지는가 → PENTEST"
        - "라이브 환경에서 요청-응답 패턴으로 유효성을 검증할 수 있는가 → PENTEST"
      대표_보상_제어: "WAF, Rate Limiter, API Gateway, BaaS 보안 규칙, CORS 정책"

    REDTEAM:
      질문: "이 보상 제어의 설정/적용을 설정 파일/IaC/컨테이너 설정에서 확인할 수 있는가?"
      판단:
        - "Dockerfile, docker-compose, Kubernetes manifest에서 확인 → REDTEAM"
        - "Terraform, CloudFormation 등 IaC에서 확인 → REDTEAM"
        - "CI/CD 파이프라인 설정에서 확인 → REDTEAM"
        - "네트워크 정책/Security Group 설정에서 확인 → REDTEAM"
      대표_보상_제어: "사설망 격리, 컨테이너 보안, TEE/Enclave, 시크릿 관리, RBAC"

    EXTERNAL:
      질문: "소스코드, 설정 파일, 라이브 테스트 모두로 확인 불가한가?"
      판단:
        - "클라우드 콘솔에서만 확인 가능한 런타임 설정 → EXTERNAL"
        - "제3자 서비스의 내부 보안 정책 → EXTERNAL"
        - "물리 인프라 레벨 격리 → EXTERNAL"
      대표_보상_제어: "클라우드 IAM 런타임 설정, 물리 네트워크 분리, 제3자 SLA"

  라우팅_결과:
    PENTEST: "offsec-lead가 Pentest Phase 6 Route_F로 전달"
    REDTEAM: "offsec-lead가 Red Team Phase 4.6으로 전달 (CISO 승인 시)"
    EXTERNAL: "최종 보고서에 '운영 환경 확인 필요'로 기록, 수동 확인 안내"

  핸드오프_작성_원칙: |
    Pending_Verification 핸드오프 시 claim(검증 대상)만 전달한다.
    테스트 방법, 페이로드, 검증 절차를 VA가 지시하지 않는다.
    Pentest/Red Team 에이전트가 Attacker_Mindset으로 자율적으로
    검증 방법을 결정해야 확증편향 없이 보상 제어의 실제 유효성을 검증할 수 있다.

    핸드오프 필드:
      - finding_id: "대상 Finding ID"
      - control: "보상 제어 설명"
      - claim: "이 제어가 주장하는 차단 효과 (what, not how)"
      - unverifiable_reason: "VA에서 확인 불가한 이유"
```

---

## 적용 컨텍스트

```yaml
Usage:
  VA_Skill:
    위치: "Finding Structure → Evidence → 도달 가능성 → 보상 제어"
    적용: "모든 Finding에 대해 Step 1~4 실행"

  Pentest_Skill:
    위치: "Pentest Phase 4.5 Self-Verify → Step_2_보상_제어_확인"
    적용: "각 공격 시나리오의 보상 제어를 이 프로토콜로 검증"

  Verify_Skill:
    위치: "Phase R1 Evidence Audit"
    적용: "VA/Pentest가 판정한 보상 제어의 유효성을 독립 재검증"
    추가: |
      VA가 Effective로 판정한 보상 제어에 대해서도
      독립적으로 5개 질문을 재실행한다.
      VA와 결론이 다르면 이의(Objection)로 보고한다.

  Prerequisites_연계:
    위치: "VA Step 1.7 → 보상 제어 검증 → Feasibility 조정"
    설명: |
      보상 제어와 전제조건 분석은 상호 보완적이다:

      1. 보상 제어 판정은 "이 취약점을 현재 방어하는 제어가 있는가?" (코드 레벨)
      2. 전제조건 분석은 "이 공격이 성립하려면 무엇이 먼저 필요한가?" (배포/환경 레벨)

      두 결과를 조합하여 최종 실전 Feasibility를 결정:

      [보상 제어 Effective_Complete + 전제 none] → 방어 중이며 즉시 공격 가능 → 보상 효과 반영 (1단계 하향)
      [보상 제어 Effective_Narrow + 전제 none]   → 제한적 방어 중 → 보상 효과 반영 (0.5단계 하향 + narrow 태그)
      [보상 제어 Ineffective + 전제 none]   → 방어 없고 즉시 공격 가능 → 원래 심각도 (가장 위험)
      [보상 제어 Effective + 전제 cloud_provider, defense_survives=false]
        → "보상 제어는 유효하지만 전제 침해 시 무력화" → Feasibility T (이론적)
      [보상 제어 Unverifiable + 전제 internal_network]
        → Pentest/RedTeam에서 검증 필요, 전제 접근권 확보 시 공격 가능 → Feasibility M

    원칙: |
      "보상 제어"와 "전제조건"이 동일 침해 범위에 속하면 독립성이 없다.
      예: 보상 제어가 "AWS VPC network isolation"이고 전제가 "cloud_provider 침해"이면
          보상 제어도 동시에 무력화됨 → defense_survives: false.
      예: 보상 제어가 "HMAC 메시지 서명 (별도 Vault key)"이고 전제가 "config_file 유출"이면
          HMAC key가 Vault에 있으므로 config 유출과 독립 → defense_survives: true.
```
