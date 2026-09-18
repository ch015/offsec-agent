---
name: ch015-redteam
description: "Run CH015 red team infrastructure configuration security review workflows for IaC, CI/CD, containers, Kubernetes, cloud config, MITRE ATT&CK attack paths, and detection engineering."
---

# 인프라 설정 보안 리뷰 (Red Team Operations) Skill

> 인프라/네트워크/배포 레벨의 설정 파일과 IaC를 공격자 관점에서 분석하여
> MITRE ATT&CK 프레임워크에 매핑된 공격 경로를 식별합니다.

---

## 서비스 개요

| 항목 | 내용 |
|------|------|
| 서비스명 | 인프라 설정 보안 리뷰 (Red Team) |
| 방법론 | MITRE ATT&CK 매핑 + Kill Chain 관점 설정 분석 |
| 출력물 | 인프라 공격 표면 맵 + Kill Chain + 6-step 영향도 분석 + 수정 가이드 |
| 코드 수정 | ❌ 없음 (읽기 전용) |
| 외부 스캔 | ❌ 없음 (소스코드/설정 분석 기반) |
| 실제 인프라 접근 | ❌ 없음 (레포 내 파일만 분석) |

---

## 역할 범위와 한계

```yaml
Role_Scope:
  정의: |
    이 스킬은 "인프라 설정 보안 리뷰(Infrastructure Configuration Security Review)"이다.
    실제 인프라에 접근하거나 네트워크 트래픽을 생성하지 않으며,
    레포 내 설정 파일/IaC/CI/CD 파이프라인을 공격자 관점(Kill Chain)으로 분석한다.

  수행_범위:
    - "Dockerfile, docker-compose 등 컨테이너 설정 보안 분석"
    - "GitHub Actions, GitLab CI 등 CI/CD 파이프라인 보안 분석"
    - "Terraform, CloudFormation 등 IaC 보안 분석"
    - "Kubernetes manifest, Helm chart 보안 분석"
    - "시크릿 관리 아키텍처 분석 (Vault, SSM, SA binding 등)"
    - "코드 내 인프라 클라이언트 호출에서 아키텍처 추론"
    - "MITRE ATT&CK Kill Chain 관점 공격 경로 도출"

  수행_불가:
    - "실제 인프라(클라우드, 서버, 네트워크)에 접근 또는 스캔"
    - "실행 중인 서비스에 HTTP 요청 또는 네트워크 패킷 전송"
    - "운영 환경의 실시간 설정 값 확인"
    - "실제 시크릿 유출 테스트 또는 크레덴셜 검증"

  Pentest_차이:
    설명: |
      - Pentest: 실제 HTTP 요청으로 취약점을 라이브 검증 → FP 직접 제거
      - Red Team: 설정 파일을 분석하여 인프라 수준 보상 제어를 확인 → FP 간접 제거
    사용_시점: |
      VA에서 Unverifiable_Infra로 분류된 보상 제어를 설정 파일에서 검증할 때.
      Pentest로 검증할 수 없는 인프라 수준 설정(컨테이너 격리, CI/CD 시크릿 보호 등)이 대상.

  FP_감소_기여:
    직접: "설정에서 확인 가능한 보상 제어 검증 → Effective/Ineffective 판정"
    간접: "Kill Chain 분석으로 복합 공격 경로 식별 → 숨겨진 True Positive 발견"
    한계: "레포에 없는 설정(운영 환경 전용)은 검증 불가 → INCONCLUSIVE"
```

---

## 설계 원칙: 방법론 기반 + 공격 경로 중심

### 분석 원칙: 방법론, 패턴이 아님

```yaml
Principles:
  No_Pattern_Lists: |
    "특정 클라우드 서비스 문법, 설정 키, Dockerfile 명령어 목록에 의존하지 않는다.
     이런 목록은 닫힌 집합이며, 목록에 없는 위험을 구조적으로 놓친다."

  Use_Methodology: |
    "행위(무엇이 일어나는가)를 질문하고, AI가 감지된 인프라 스택에 맞는
     구체적 설정 패턴을 자율적으로 판단하여 탐색한다."

  Kill_Chain_Thinking: |
    "개별 설정 결함이 아닌 공격 경로(Kill Chain) 관점으로 분석.
     '이 설정이 안전한가'가 아니라 '이 설정을 활용해 어디까지 도달할 수 있는가'를 질문."

  Representative_Examples: |
    "안티패턴/올바른 패턴은 '대표적 예시'로만 제시.
     분석은 이 예시에 한정되지 않으며 — 동일한 구조적 이슈를 가진
     모든 변형이 탐지되어야 한다."
```

---

## VA·Pentest·Red Team 비교

| 구분 | VA | Pentest | Red Team |
|------|-----|---------|----------|
| 관점 | 아키텍처 차원 리뷰 | 애플리케이션 공격자 | 인프라/조직 공격자 |
| 대상 | 소스코드 | 소스코드 + API | 설정 파일 + IaC + CI/CD |
| 방법론 | 8대 아키텍처 차원 | 시나리오 기반 공격 | MITRE ATT&CK 매핑 |
| 실행 환경 | 코드 읽기 전용 | 라이브 HTTP 요청 | 코드/설정 읽기 전용 |
| FP 감소 | Self-Verify로 1차 제거 | 라이브 검증으로 직접 제거 (핵심) | 설정 검증으로 간접 제거 |
| 출력 | 차원 건강도 + 6-step 분석 | POC + 라이브 검증 + 6-step | Kill Chain + 6-step 분석 |

---

## Phase 구조

```
Phase 0: Recon          → 공통 정찰 (common/recon.md) + 인프라 정찰
Phase 0.5: Binding      → 정찰 → 분석 컨텍스트 바인딩
Phase 1: Surface        → 인프라/배포 공격 표면 식별
Phase 2: Attack Path    → MITRE ATT&CK 기반 공격 경로 분석
Phase 3: Exploit        → 익스플로잇 가능성 분석 + POC
Phase 4: Deep Analysis  → 원칙 기반 심층 분석
Phase 4.5: Self-Verify  → 분석 결과 자체 검증 (도달 가능성, 보상 제어)
Phase 4.6: VA Escalation → VA Unverifiable_Infra 보상 제어 설정 기반 검증 (해당 시)
Phase 5: Report         → Kill Chain 다이어그램 + 6-step 영향도 분석 보고서
Phase 5R: Regulatory    → 규제 영향 참조 (Finding 기반, 해당 시에만)
Phase 6: Detection      → Detection Engineering Signals (Purple Team 산출물)
```

---

## Phase 0: 인프라 정찰 (Infrastructure Recon)

공통 정찰에 추가로 인프라/배포 관련 정보를 수집합니다.

```yaml
인프라_정찰:
  컨테이너화:
    methodology: |
      컨테이너 설정 파일을 분석하여 보안 관련 설정을 식별:
      - 베이스 이미지, 사용자 설정, 포트 노출, 볼륨 마운트
      - 시크릿 파일 제외 여부 (.dockerignore)

  IaC_설정:
    methodology: |
      인프라 코드를 분석하여 보안 설정을 식별:
      - 클라우드 리소스 설정, 네트워크 정책, IAM 역할
      - 배포 설정 (serverless, PaaS, container orchestration)

  CI_CD:
    methodology: |
      CI/CD 파이프라인 설정을 분석:
      - 시크릿 주입 방식, 환경 분리, 아티팩트 보안
      - 제3자 Action/플러그인 보안

  시크릿_관리:
    methodology: |
      시크릿 관리 아키텍처를 분석:
      - .env 파일 존재 및 git 추적 여부
      - 시크릿 매니저 사용 여부 및 연동 방식
      - 환경별 분리
      - 레포 내 설정 파일(config.toml, .env.example 등)이 샘플인지 실제인지 구분
    시크릿_매니저_통합:
      methodology: |
        시크릿 매니저(Vault, AWS SSM, GCP Secret Manager 등) 연동이 감지되면
        아래 항목을 추가 분석한다:
      분석_항목:
        인증_방식:
          - "K8s Auth: SA 바운딩 → Vault Role 매핑 — SA annotation, Vault K8s auth config"
          - "AppRole: Role ID/Secret ID 주입 경로 — CI/CD 환경변수 또는 파일"
          - "Token: 정적 토큰 사용 여부 — 하드코딩, 환경변수, 파일"
          - "AWS IAM Auth: EC2/ECS/Lambda 역할 기반 인증"
        정책_범위:
          - "Vault 정책 파일이 레포에 있으면 와일드카드(secret/*, kv/*) 사용 여부 확인"
          - "서비스별 최소 권한 분리: 각 서비스가 자신의 시크릿만 접근하는가"
          - "관리자 정책과 서비스 정책의 분리"
        토큰_수명:
          - "TTL/Max TTL 설정 — 코드 또는 설정에서 확인"
          - "토큰 갱신 로직 존재 여부"
          - "장기 유지 토큰(orphan token, periodic token) 사용 여부"
        Vault_Agent_Sidecar:
          - "Agent 설정의 시크릿 렌더링 경로 및 파일 권한"
          - "캐시 활성화 시 캐시 파일 경로 및 보호"
          - "auto-auth 설정의 sink 파일 보호"
      EKS_Vault_패턴:
        설명: "EKS + Vault K8s Auth는 가장 일반적인 패턴"
        공격_경로:
          - "SA 토큰 탈취 → Vault 인증 → 시크릿 접근 (TA0006)"
          - "SA 바운딩 과도 → 다른 서비스의 Vault 시크릿 교차 접근 (TA0008)"
          - "Vault Agent 캐시/렌더링 파일 → 컨테이너 내 평문 시크릿 잔류 (TA0006)"
          - "CI/CD에서 Vault 토큰 로그 노출 → 인프라 전체 접근 (TA0001)"
        레포_단서:
          - "Go/Python/Node 코드에서 vault 클라이언트 초기화 패턴"
          - "Helm chart의 serviceAccount annotation (vault.hashicorp.com/*)"
          - "deployment YAML의 vault agent injector annotation"
          - "CI/CD workflow의 hashicorp/vault-action 또는 vault CLI 호출"

  레포_외부_인프라:
    methodology: |
      설정 파일이 레포에 없더라도, 코드 내 클라이언트 호출에서
      인프라 아키텍처를 추론한다:
      - Vault 클라이언트 초기화 → 시크릿 매니저 사용 확인
      - K8s 클라이언트/SDK 호출 → EKS/GKE/AKS 사용 추론
      - AWS/GCP SDK 호출 → 클라우드 서비스 사용 추론
      - 이 경우 설정 파일 부재 자체를 Finding으로 보지 않으며,
        코드에서 확인 가능한 범위만 분석한다.

  네트워크:
    methodology: |
      네트워크 설정을 분석:
      - 노출 포트, 서비스 간 통신, 외부 접근점
```

---

## Phase 1: 공격 표면 식별 (Attack Surface Mapping)

각 공격 표면 영역은 **방법론 기반**으로 분석됩니다.
아래 점검 항목은 대표 예시이며, AI가 감지된 인프라에 맞게 자율적으로 확장합니다.

### AS1. 컨테이너/런타임 보안

```yaml
Core_Questions:
  - "컨테이너가 최소 권한 원칙을 따르는가?"
  - "컨테이너 레이어에 민감 정보가 포함되는가?"
  - "컨테이너 간 네트워크 격리가 적절한가?"
  - "컨테이너 이스케이프의 전제조건(CAP, 커널 버전, 소켓 마운트)이 갖춰져 있는가?"

Representative_Items:
  AS1-001: "컨테이너에서 root 사용자로 실행"
  AS1-002: "베이스 이미지 버전 고정 미적용"
  AS1-003: "불필요한 패키지/도구 설치"
  AS1-004: "시크릿이 Docker 레이어에 포함"
  AS1-005: "HEALTHCHECK 미설정"
  AS1-006: "네트워크 격리 미설정"
  AS1-007: "privileged 모드 또는 과도한 capabilities"
  AS1-008: "호스트 경로 직접 마운트"
  AS1-009: "docker.sock / containerd.sock / cri.sock 마운트"
  AS1-010: "IMDSv1 허용 또는 hop-limit > 1 (컨테이너에서 IMDS 접근 가능)"
  AS1-011: "automountServiceAccountToken: true + 광범위 RBAC (K8s)"
  AS1-012: "hostPath: / 또는 /etc, /var/lib/kubelet 마운트"
  AS1-013: "seccomp=Unconfined / AppArmor=unconfined"
  AS1-014: "runc/containerd 취약 버전 (CVE-2024-21626, CVE-2019-5736)"
  AS1-015: "커널 취약점 노출 (DirtyPipe 범위: 5.8 ≤ ver < 5.16.11)"

Escape_Precondition_Matrix:
  # 각 이스케이프 프리미티브의 필요조건을 명시 — Finding 작성 시 모두 Observed 필수
  cgroup_v1_release_agent:
    requires: ["CAP_SYS_ADMIN", "cgroup v1 (no unified)", "Linux < 5.8 or fallback"]
  dirtypipe_lpe:
    requires: ["Linux 5.8 ≤ ver < 5.16.11 / 5.15.25 / 5.10.102"]
  runc_leaky_handle:
    requires: ["runc < 1.1.12"]
  hostpath_root:
    requires: ["hostPath: / mount"]
  docker_sock:
    requires: ["/var/run/docker.sock mount"]

Representative_Anti_Patterns:
  - "root 사용자로 실행 → 컨테이너 탈출 시 호스트 접근"
  - "시크릿이 Docker 빌드 레이어에 포함 → 이미지 접근자 전원에게 노출"
  - "IMDSv1 + 애플리케이션 SSRF → IAM Role 탈취 (cloud-aws.md 참조)"
  - "hostPath / 마운트 + 비root 컨테이너 → 여전히 /etc/shadow 읽기 가능"
  - "CAP_SYS_ADMIN 부여된 비root 컨테이너 → cgroup release_agent 이스케이프"

Representative_Healthy_Patterns:
  - "비root 사용자 + 최소 capabilities"
  - "multi-stage 빌드 + 시크릿은 런타임 환경변수로 주입"
  - "IMDSv2 강제 + hop-limit = 1"
  - "automountServiceAccountToken: false"
  - "seccomp RuntimeDefault + read-only rootfs"

Deep_Reference:
  aws: knowledge-base/tier2-overlays/cloud-aws.md
  k8s: knowledge-base/tier2-overlays/cloud-k8s.md
```

### AS2. CI/CD 파이프라인 보안

```yaml
Core_Questions:
  - "CI/CD 파이프라인이 공급망 공격에 취약한가?"
  - "시크릿이 빌드/배포 과정에서 안전하게 관리되는가?"
  - "제3자 코드가 파이프라인에서 실행될 때 권한 범위가 적절한가?"

Representative_Items:
  AS2-001: "CI/CD 시크릿 안전 주입 여부"
  AS2-002: "제3자 Action/플러그인 핀 고정 (SHA 또는 특정 버전)"
  AS2-003: "빌드 아티팩트에 시크릿 포함 여부"
  AS2-004: "PR 기반 CI에서 write 권한 범위"
  AS2-005: "Self-hosted runner 격리 수준"
  AS2-006: "배포 파이프라인 환경 분리"
  AS2-007: "아티팩트 서명/무결성 검증"
  AS2-008: "CI/CD → Vault 연동 시 토큰 노출 여부 (로그, 환경변수 마스킹)"
  AS2-009: "CI/CD → EKS 배포 시 kubeconfig/IAM 인증 방식"

Representative_Anti_Patterns:
  - "제3자 Action이 SHA 고정 없이 최신 버전 사용 → 공급망 공격"
  - "PR CI가 write 권한 → 악의적 PR로 코드 변경"
  - "Vault 토큰이 CI 로그에 마스킹 없이 노출 → 인프라 전체 접근"
  - "kubeconfig가 Actions secret에 평문 저장 → 클러스터 접근"

Representative_Healthy_Patterns:
  - "모든 Action SHA 고정 + 정기 업데이트"
  - "PR CI는 read-only, merge 후에만 배포"
  - "Vault 토큰은 OIDC 또는 GitHub OIDC로 단기 발급"
  - "EKS 배포는 IAM Roles for Service Accounts(IRSA)로 인증"
```

### AS3. 클라우드/IaC 보안

```yaml
Core_Questions:
  - "클라우드 리소스가 최소 권한 원칙을 따르는가?"
  - "데이터가 전송 중/저장 시 암호화되는가?"
  - "외부 접근이 필요한 리소스만 공개되는가?"

Representative_Items:
  AS3-001: "IAM 역할 최소 권한 원칙"
  AS3-002: "Storage 버킷 공개 접근"
  AS3-003: "Security Group/방화벽 규칙 (0.0.0.0/0 인바운드)"
  AS3-004: "데이터베이스 공개 접근"
  AS3-005: "암호화 at-rest / in-transit"
  AS3-006: "로깅/모니터링 활성화"
  AS3-007: "Terraform state 파일 보안"
  AS3-008: "서버리스 함수 실행 시간/메모리 제한"

Representative_Anti_Patterns:
  - "IAM 역할에 * 와일드카드 권한 → 전체 리소스 접근"
  - "데이터베이스 공개 엔드포인트 → 직접 접근 가능"

Representative_Healthy_Patterns:
  - "IAM 역할별 최소 필요 권한만 명시"
  - "데이터베이스는 VPC 내부에서만 접근"
```

### AS4. Kubernetes 보안 (해당 시)

```yaml
Core_Questions:
  - "클러스터 접근 제어가 최소 권한을 따르는가?"
  - "Pod 간 네트워크 격리가 적절한가?"
  - "시크릿이 안전하게 관리되는가?"

Representative_Items:
  AS4-001: "RBAC 최소 권한 (ClusterRole vs Role)"
  AS4-002: "NetworkPolicy 존재 및 격리 수준"
  AS4-003: "PodSecurityPolicy/PodSecurityStandard"
  AS4-004: "시크릿 암호화 (etcd encryption)"
  AS4-005: "서비스 어카운트 토큰 자동 마운트 비활성화"
  AS4-006: "이미지 풀 정책"
  AS4-007: "리소스 Limits/Requests 설정"
```

### AS5. 의존성/공급망 보안

```yaml
Core_Questions:
  - "의존성의 무결성이 보장되는가?"
  - "알려진 취약점이 있는 의존성이 있는가?"
  - "빌드 시 실행되는 스크립트가 안전한가?"

Representative_Items:
  AS5-001: "lock 파일 무결성"
  AS5-002: "알려진 CVE 의존성"
  AS5-003: "의존성 미러/프록시 사용 여부"
  AS5-004: "postinstall/pre-build 스크립트 점검"
  AS5-005: "의존성 자동 업데이트 설정"
```

---

## Phase 2: MITRE ATT&CK 매핑 공격 경로 분석

발견된 공격 표면을 MITRE ATT&CK 전술(Tactic)에 매핑합니다.

```yaml
MITRE_ATT&CK_매핑:
  TA0001_Initial_Access:
    - "공개 API 엔드포인트를 통한 초기 접근"
    - "CI/CD 파이프라인 타협"
    - "공급망 공격 (의존성 변조)"
    - "환경 변수/시크릿 유출"

  TA0003_Persistence:
    - "서비스 어카운트/API 키 장기 유지"
    - "CI/CD 파이프라인에 백도어 주입"
    - "Docker 이미지 변조"

  TA0004_Privilege_Escalation:
    - "IAM 역할 가정 (assume-role)"
    - "Kubernetes RBAC 에스컬레이션"
    - "컨테이너 탈출"
    - "DB 특권 함수 실행"

  TA0005_Defense_Evasion:
    - "로깅 비활성화/우회"
    - "감사 로그 변조"
    - "CloudTrail 로그 S3 버킷 삭제 권한 오남용"
    - "GuardDuty 비활성 region에서 활동 (탐지 사각지대)"
    - "Falco/EDR 룰 예외 처리 악용"
    - "컨테이너 ephemeral FS에 아티팩트 저장 후 재시작으로 삭제"

  TA0006_Credential_Access:
    - "하드코딩 시크릿 추출"
    - "환경 변수에서 API 키 탈취"
    - "Docker/CI 로그에서 시크릿 유출"

  TA0007_Discovery:
    - "내부 서비스 열거"
    - "API 엔드포인트 열거"

  TA0008_Lateral_Movement:
    - "서비스 간 인증 토큰 재사용"
    - "내부 네트워크 피봇"

  TA0009_Collection:
    - "DB 대량 데이터 추출"
    - "Storage/S3 버킷 데이터 접근"

  TA0010_Exfiltration:
    - "외부 API를 통한 데이터 유출"

  TA0040_Impact:
    - "서비스 거부 (리소스 소진)"
    - "데이터 파괴/변조"
```

### 공격 경로 구성

```yaml
공격_경로_분석:
  1_진입점_식별: "MITRE TA0001 후보 중 실현 가능한 진입점"
  2_수평_이동: "진입 후 TA0007/TA0008 기반 이동 경로"
  3_권한_상승: "TA0004 기반 상위 권한 획득 경로"
  4_목표_달성: "TA0009/TA0010/TA0040 기반 최종 영향"
  5_Kill_Chain: "진입 → 이동 → 상승 → 달성 전체 경로 시각화"
```

---

## Phase 3: 익스플로잇 가능성 분석

```yaml
분석_기준:
  실현_가능성:
    HIGH: "공개적으로 접근 가능, 별도 인증 불요"
    MEDIUM: "내부 접근 또는 기본 인증으로 접근 가능"
    LOW: "다단계 공격 체인 필요, 시간/자원 소모"
    THEORETICAL: "이론적으로 가능하나 현실적 장벽 큼"

  영향도:
    CRITICAL: "전체 시스템 타협, 데이터 전량 유출"
    HIGH: "주요 서비스 장애, 대량 데이터 접근"
    MEDIUM: "일부 서비스 영향, 제한적 데이터 접근"
    LOW: "정보 노출, 설정 결함"

  우선순위: "실현_가능성 × 영향도 매트릭스"
```

---

## Phase 4: 원칙 기반 심층 분석

```yaml
Security_Principles:
  Least_Privilege: "모든 서비스/컨테이너/역할에 최소 권한만"
  Defense_in_Depth: "인프라 레벨 다층 방어"
  Zero_Trust: "내부 네트워크도 신뢰하지 않는 아키텍처"

Free_Exploration:
  - "인프라 설정 간 상호작용으로 발생하는 보안 갭"
  - "배포 환경 특성으로 인한 보안 메커니즘 무력화"
  - "멀티 클라우드/하이브리드 환경의 보안 경계 이슈"
```

---

## Root Cause Classification (근본 원인 분류)

```yaml
Root_Cause_Types:
  ARCHITECTURE:
    description: "인프라 아키텍처 설계 자체의 문제"
    examples: "네트워크 격리 설계 미비, Zero Trust 미적용"

  CONFIGURATION:
    description: "설정 누락 또는 과도한 설정"
    examples: "Security Group 과도 허용, RBAC 미설정"

  CODE:
    description: "IaC/CI 코드의 보안 결함"
    examples: "Terraform에 하드코딩 시크릿, Dockerfile root 사용"

  PROCESS:
    description: "인프라 운영 프로세스 부재"
    examples: "시크릿 로테이션 미수행, 설정 변경 리뷰 미실시"
```

## Phase 4.5: 분석 결과 자체 검증 (Self-Verification)

```yaml
Self_Verification:
  목적: |
    인프라 Finding의 오탐(과대 평가)을 최소화한다.
    각 Finding에 대해 아래 2단계를 실행한다.

  Step_1_도달_가능성_검증:
    설명: "취약 설정이 실제 공격 경로에서 도달 가능한가?"
    절차:
      - "해당 설정이 프로덕션에 적용되는지 확인 (환경별 분기)"
      - "해당 리소스가 외부에서 접근 가능한지 네트워크 설정 확인"
      - "도달 불가능하면 Feasibility를 THEORETICAL로 재평가"

  Step_2_보상_제어_확인:
    설명: "다른 레이어에서 동일 위협을 차단하는 보상 제어가 있는가?"
    프로토콜: "common/compensating-control.md의 4단계 프로토콜을 실행한다."
    예시:
      - "Security Group이 과도하지만 VPC 내부에서만 접근 가능"
      - "컨테이너가 root이지만 read-only 파일시스템 + no-new-privileges"
    원칙:
      - "보상 제어의 존재 ≠ 위협 차단 — 유효성이 설정에서 입증되어야 한다"
      - "Effective_Complete(1단계 하향)/Effective_Narrow(0.5단계 하향+태그) 판정 외에는 원래 심각도를 유지한다 (compensating-control.md Step 4가 정본)"

  적용_우선순위: "모든 Finding에 Step 1~2 필수"
```

---

## Phase 4.6: VA 에스컬레이션 인프라 검증 (VA Escalation Infrastructure Verify)

> VA에서 Unverifiable_Infra (verification_target: REDTEAM)로 분류된 보상 제어를
> 설정 파일/IaC/컨테이너 설정에서 검증하여 VA Finding의 심각도를 재조정합니다.

```yaml
VA_Escalation_Verify:
  조건: |
    offsec-lead로부터 Pending_Verification.REDTEAM 목록을 수신한 경우에만 실행.
    CISO 지시에 Red Team이 포함되어 있어야 한다.

  목적: |
    VA 코드 분석에서 "인프라 레벨이라 확인 불가"로 판정된 보상 제어를
    설정 파일/IaC/Dockerfile 등에서 실제 적용 여부를 검증하여 FP를 줄인다.
    Red Team의 인프라 분석 역량(AS1-AS5)을 활용한다.

  입력: |
    Pending_Verification.REDTEAM 목록:
      - finding_id, control, expected_test

  검증_절차:
    Step_1_설정_파일_탐색: |
      VA가 전달한 보상 제어 유형에 따라 관련 설정 파일을 탐색한다:
      - 네트워크 격리 → docker-compose.yml 네트워크 설정, K8s NetworkPolicy, Terraform Security Group
      - 컨테이너 보안 → Dockerfile (USER, capabilities), compose (security_opt, read_only)
      - TEE/Enclave → enclave 설정 파일, VSOCK 설정
      - 시크릿 관리 → CI/CD 설정, .env 추적 여부, 시크릿 매니저 연동
      - 볼륨 접근 제어 → compose volumes (read-only 플래그), K8s PVC 설정
      - Vault 시크릿 주입 → Vault Agent annotation, SA 바운딩, 코드 내 Vault 클라이언트 호출
      주의: 레포 내 config 파일(config.toml, .env.example 등)이 샘플 데이터인 경우,
      실제 시크릿 주입 경로(Vault, SSM 등)를 코드에서 추적하여 판단한다.
      샘플 데이터를 실제 시크릿 노출로 오판하지 않는다.

    Step_2_유효성_검증: |
      compensating-control.md의 5개 질문을 설정 파일 기반으로 실행한다:
      - 범위: 이 보상 제어가 해당 서비스/컨테이너에 실제 적용되는가?
      - 정밀도: 이 설정이 해당 위협 벡터를 차단하는가?
      - 우회가능성: 설정 자체를 우회할 경로가 있는가?
      - 완전성: 모든 관련 서비스/컨테이너에 일관 적용되는가?
      - 독립성: 원본 취약점과 같은 설정 누락을 공유하지 않는가?

    Step_3_Kill_Chain_연계: |
      보상 제어가 유효한 경우, 기존 Red Team Kill Chain에서
      해당 보상 제어가 차단하는 단계를 표시한다.
      Kill Chain이 완성되지 않으면 실현 가능성을 THEORETICAL로 하향.

  판정:
    Effective_Complete:
      조건: "5개 질문 모두 설정에서 확인 + 항목당 Observed 증거 2개 이상 (예: IaC + 배포 설정)"
      영향: "VA Finding 심각도 1단계 하향 근거"
      기록: "보상 제어를 Unverifiable → Effective_Complete로 재분류"

    Effective_Narrow:
      조건: "5개 질문 통과하나 증거가 1개뿐이거나 scope/환경이 제한적 (config-dependent 포함)"
      영향: "심각도 0.5단계 하향 + narrow/config-dependent 태그 (compensating-control.md Step 4)"
      기록: "보상 제어를 Unverifiable → Effective_Narrow로 재분류 + 제약 조건 명시"

    Partial:
      조건: "일부 질문 통과 + 나머지 설정에서 미확인"
      영향: "심각도 유지 (보수적)"
      기록: "보상 제어를 Unverifiable → Partial로 재분류 + 미확인 항목 명시"

    Ineffective:
      조건: "설정에서 보상 제어가 미적용 또는 우회 가능 확인"
      영향: "심각도 유지"
      기록: "보상 제어를 Unverifiable → Ineffective로 재분류"

    Unverifiable_External:
      조건: "설정 파일에서도 확인 불가 — 클라우드 콘솔/물리 환경만 가능"
      영향: "심각도 유지, Unverifiable_External로 재분류"
      기록: "운영 환경 직접 확인 필요로 최종 보고서에 기록"

  결과_기록: |
    VA Finding 원본의 Compensating_Controls 레코드를 업데이트:
    - coverage: Unverifiable → Effective_Complete|Effective_Narrow/Partial/Ineffective/Unverifiable_External
    - verification_target: REDTEAM → REDTEAM_VERIFIED
    - infra_evidence: "[설정 파일 경로:라인 + 설정 내용]"

  결과_출력: |
    검증 결과를 구조화하여 기록:
    ┌────────────────────────────────────────────────────────────┐
    │ INFRA VERIFICATION RESULT                                  │
    ├──────────────┬─────────────────────────────────────────────┤
    │ VA Finding   │ F-XXX                                       │
    │ 보상 제어     │ [보상 제어 설명]                               │
    │ 검증 대상     │ [설정 파일 경로]                               │
    │ 5개 질문 결과 │ 범위/정밀도/우회/완전성/독립성                   │
    │ 최종 판정     │ Effective_Complete / Effective_Narrow /       │
    │              │ Partial / Ineffective / External              │
    │ 심각도 조정   │ 변경 없음 / 변경 사유                           │
    └──────────────┴─────────────────────────────────────────────┘
```

---

## Phase 5R: 규제 영향 참조 (Regulatory Impact Reference)

```yaml
Module: "../va/regulatory.md"

Trigger: |
  Phase 1~5에서 발견된 Finding 중 규제 관련성이 있는 것이 1건 이상인 경우에만 실행.
  규제 관련 Finding이 0건이면 생략한다.

Scope: |
  인프라/배포 레벨 취약점 중 규제 관련성이 있는 것을 국내외 법률·규제 조항에 매핑.
  특히 CI/CD 통제 부재(ISMS-P 2.9.1), 키 관리 구조(가상자산이용자보호법),
  접근 통제(개인정보보호법 제29조) 등이 해당될 수 있다.
  상세 프로토콜, 규제 카탈로그, 출력 형식은 모듈 파일 참조.

Key_Principles:
  - "법률명 + 조항 번호를 반드시 명시 (모호한 언급 금지)"
  - "적용 관할(🇰🇷/🇪🇺/🇺🇸/🌐)을 명시"
  - "위반 단정 금지 — '저촉 가능성 있으므로 법무 검토 권장'으로 기술"
  - "기술적 심각도를 규제 이유로 변경하지 않음"
```

---

## Finding Structure (6-step 영향도 분석)

모든 발견 사항은 6-step 구조를 따릅니다.

> **ID 명명 규칙**: `knowledge-base/conventions/finding-id-naming.md` 참조 (AS{N}-{NNN} Red Team 전용 + 통합 규칙)

```yaml
Finding_Structure:
  F-XXX: "[인프라 이슈 이름]"

  Metadata:
    Attack_Surface: "AS1~AS5"
    MITRE_Tactic: "TA0001~TA0040"
    Severity: "CRITICAL / HIGH / MEDIUM / LOW"
    Feasibility: "HIGH / MEDIUM / LOW / THEORETICAL"
    Location: "파일, 설정"
    Root_Cause: "ARCHITECTURE / CONFIGURATION / CODE / PROCESS"
    Reference:
      CWE: "CWE-NNN (필수 — 가장 정확한 CWE ID. 복수 해당 시 쉼표 구분)"
      MITRE_ATT&CK: "TXXXX (필수 — Tactic + Technique ID)"
      OWASP_Top10: "A01~A10 (해당 시)"
      Note: "CWE/MITRE는 보고서 완전성을 위한 필수 매핑"

  Structural_Issue_Description: "구조적 원인 설명"
  Evidence: "설정 파일 참조"
  Kill_Chain_Impact: "이 발견이 Kill Chain에서 차지하는 위치"

  Fix_Recommendation_and_Impact_Analysis:
    1_Change_Target: "수정 대상 설정과 방향"
    2_Reference_Tracing: "이 설정에 의존하는 모든 서비스/컴포넌트"
    3_Impact_Scope: "직접/간접 영향"
    4_Side_Effect_Risks: "설정 변경으로 서비스 중단 위험"
    5_Co_Requisite_Changes: "동시 변경 항목 (네트워크/IAM/시크릿)"
    6_Post_Fix_Verification: "설정 변경 후 검증 항목"
```

---

## Phase 6: Detection Engineering Signals (P3-2 Purple Team 산출물)

> Red Team 산출물에 **Detection Signals 섹션을 필수 포함**한다.
> 목적: SOC/Detection Engineer가 이 공격이 실행되었을 때 어떤 로그·시그니처가
> 남는지, 현재 SIEM/EDR 룰로 탐지 가능한지, 탐지 갭을 어떻게 메울지 알 수 있도록 한다.

### Detection_Signals_Schema

```yaml
Finding_Detection_Appendix:
  # 각 Kill Chain / Finding 엔트리에 추가로 부가되는 섹션
  attack_artifacts:
    - type: "process_exec | file_write | network_conn | api_call | auth_event"
      detail: "구체적 아티팩트 예시 (예: /usr/bin/runc -v 실행)"
      host_visibility: "kernel | user | none"

  log_sources:
    - "CloudTrail: <eventName>, <resource>"
    - "Kubernetes audit log: <verb>, <resource>, <subject>"
    - "EDR/Falco: <rule_name>"
    - "WAF access log: <pattern>"
    - "application audit: <event>"

  detection_queries:
    splunk: |
      index=cloudtrail eventName=AssumeRole userIdentity.type=AssumedRole ...
    elastic: |
      event.dataset:aws.cloudtrail AND event.action:AssumeRole AND ...
    sigma_rule_id: "proc_creation_lnx_susp_runc_override"

  known_edr_coverage:
    - vendor: "Falco"
      rule: "Mount Launched in Privileged Container"
      coverage: "Effective | Partial | None"
    - vendor: "Datadog Cloud Workload Security"
      coverage: "Partial — hostpath mount detection but not follow-on exploit"

  evasion_considerations:
    # 공격자 관점 — 어떻게 하면 위 탐지를 회피할 수 있는가?
    # 목적은 evasion 가이드가 아니라 SOC가 회피 시도도 탐지할 수 있게 신호 설계.
    - "로그 소스 자체를 비활성화하는 사전 액션 (GuardDuty disable)"
    - "로그 export 후 S3 삭제"
    - "공격을 GuardDuty 비활성 region에서 수행"

  soc_action_recommendations:
    - "AssumeRole 이벤트 중 cross-account + unusual source IP 알람"
    - "GuardDuty 비활성/삭제 이벤트에 즉시 페이지"
    - "runc 실행 자체를 컨테이너 내부에서 차단 (seccomp)"

  detection_gap:
    # 현재 조직이 보유한 검출 스택으로 탐지 불가능한 단계
    - stage: "Initial Access via SSRF"
      gap: "WAF에서 169.254.169.254 블록은 하되 DNS rebinding은 미탐"
      recommendation: "DNS resolve 결과 로깅 + private IP egress 모니터링"
```

### Purple Team 보고서 템플릿 적용 규칙

```yaml
Report_Template_Rule:
  - "06b_redteam_result.md의 각 Kill Chain 항목에 'Detection Signals' 하위섹션 필수"
  - "Finding별 SOC Action Recommendations를 Jira 'detection-eng' 라벨로 티켓 생성 가능한 형태로 명시"
  - "기존 탐지로 커버되지 않는 단계(detection_gap)는 HIGH 우선순위로 별도 목록화"
```

### Evasion Framing Discipline

```yaml
Ethical_Framing:
  rule: |
    evasion_considerations 섹션은 공격 기법 전수 목적이 아니라
    SOC가 '회피 시도까지 탐지'할 수 있도록 하기 위함이다.
    구체적 회피 도구 이름이나 bypass payload는 기재하지 않는다.
    대신 "로그 소스 X의 비활성화" 같은 추상 수준으로 기술한다.
```
