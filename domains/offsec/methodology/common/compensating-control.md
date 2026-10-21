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
      기록: "severityRationale에 Effective_Complete 판정을 쓰고 독립 근거 2개를 evidence에 인용"
      예시: "WAF 룰 + 프로덕션 배포 로그 + deploy.sh에 해당 룰 활성화 확인"

    Effective_Narrow:
      조건: |
        5개 질문 통과하나 scope/time/context가 제한적이거나 증거가 1개뿐.
        예: rate limit 10 rpm이 자동화는 막되 저속 수동 시도는 허용.
        예: 프로덕션에만 적용되고 staging/preview는 제외.
        예: config-dependent (env var로 끄면 사라짐).
      영향: "심각도 0.5단계 하향 + 'narrow/time-limited/config-dependent' 태그"
      기록: "severityRationale에 Effective_Narrow 판정과 제약 조건을 기록"
      규칙: |
        - config-dependent인 경우 prod=worst-case 가정
        - 예: WAF가 .env로 비활성화 가능 → 비활성화된 상태 가정하여 원래 심각도 유지
        - config 의존이면 preconditions에 명시

    Partial:
      조건: "일부 질문 통과 + 나머지 Unverified 또는 부분 통과"
      영향: "심각도 변동 없음 — Partial은 완전한 차단을 입증하지 못하므로 원래 심각도를 유지한다"
      기록: "severityRationale에 Partial 보상 제어와 미통과 항목을 기록"

    Ineffective:
      조건: "하나라도 명확히 실패 (범위 미적용, 우회 가능 등)"
      영향: "보상 제어로 인정하지 않음 — 심각도 변동 없음"
      기록: "severityRationale에 Ineffective 사유를 기록 (분석 투명성)"

    Unverifiable:
      조건: "코드에서 확인 불가 (인프라 레벨, 외부 서비스 등)"
      영향: "심각도 유지 — Unverified 보상 제어로 기록"
      기록: "severityRationale에 Unverifiable로 기록 + 확인 필요 사항 명시"
      주의: "저장소 안의 IaC·Dockerfile·k8s 매니페스트·배포 설정으로 확인할 수 있는 제어는 Unverifiable로 두지 않고 해당 파일을 읽어 판정한다"
      unresolved: "코드·설정으로 확인할 수 없는 확인 필요 사항을 Finding unresolved에 적는다"

  기록_포맷: |
    Finding의 evidence에는 코드 인용(path·lineStart·lineEnd·quote)만 넣는다. 보상 제어 판정은
    severityRationale에 다음 항목으로 서술하고, 근거가 된 코드·설정 위치는 evidence에 인용으로 추가한다.
    - control: 보상 제어 이름/설명, location: file:line 또는 코드 외(N/A)
    - coverage: Effective_Complete | Effective_Narrow | Partial | Ineffective | Unverifiable
    - 독립 근거 수(Effective_Complete는 2 이상 필수)와 5개 질문(범위·정밀도·우회가능성·완전성·독립성)별 PASS/FAIL/UNVERIFIED
    - config 의존 여부(의존이면 prod=worst 가정, 조건은 preconditions에)
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
    인프라 보상 제어는 Unverifiable로 분류하고 심각도를 유지한다.
    확인될 때까지 원래 심각도를 보수적으로 유지한다.
```

---

## 전제조건 분석과의 관계

```yaml
Prerequisites_연계:
    설명: |
      보상 제어와 전제조건 분석은 상호 보완적이다:

      1. 보상 제어 판정은 "이 취약점을 현재 방어하는 제어가 있는가?" (코드 레벨)
      2. 전제조건 분석은 "이 공격이 성립하려면 무엇이 먼저 필요한가?" (배포/환경 레벨)

    원칙: |
      "보상 제어"와 "전제조건"이 동일 침해 범위에 속하면 독립성이 없다.
      예: 보상 제어가 "AWS VPC network isolation"이고 전제가 "cloud_provider 침해"이면
          보상 제어도 동시에 무력화됨 → defense_survives: false.
      예: 보상 제어가 "HMAC 메시지 서명 (별도 Vault key)"이고 전제가 "config_file 유출"이면
          HMAC key가 Vault에 있으므로 config 유출과 독립 → defense_survives: true.
```
