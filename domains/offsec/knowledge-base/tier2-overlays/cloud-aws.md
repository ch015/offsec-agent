---
phases: [va, pentest, verify]
keywords: [aws, s3, lambda, iam, ec2]
---
# AWS Cloud Attack Primitives (P2-3)

> Red Team / Pentest가 AWS 환경을 대상으로 할 때 체크해야 하는
> 고신뢰 공격 프리미티브 목록. MITRE ATT&CK 매핑 포함.
> 참조 시점: redteam/SKILL.md Phase 1 (Infra Recon), pentest/SKILL.md Category 2.

## 1. Metadata / Credential Primitives

### IMDSv1 → Role Takeover (TA0006 Credential Access)

**전제조건**
- EC2 / ECS(EC2 launch type) / 일부 EKS node
- IMDSv1 활성 또는 IMDSv2 hop-limit 미제한
- SSRF 취약점이 애플리케이션에 존재 (see A6 SSRF_Structure)

**공격 체인**
```
SSRF → http://169.254.169.254/latest/meta-data/iam/security-credentials/
     → role name 획득
     → /latest/meta-data/iam/security-credentials/<role>
     → AccessKey/SecretKey/Token JSON 수령
     → aws sts get-caller-identity 검증
     → 과도 권한 IAM에 의한 lateral movement
```

**체크포인트**
- IMDSv2 강제 (`HttpTokens=required`)
- metadata hop-limit = 1 (컨테이너 우회 차단)
- IMDS 네트워크를 컨테이너/lambda에서 차단
- IAM Role에 최소 권한 적용; `*` resource 금지

**탐지 힌트**
- CloudTrail AssumeRole + 비정상 IP
- GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`

---

### ECS Task Role 탈취

- ECS task는 `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` 환경변수로 자격 증명 엔드포인트를 노출.
- 컨테이너 RCE 또는 SSRF가 있으면 task role 탈취 → 태스크 권한으로 AWS API 호출.

---

### Lambda Function URL / Invoke Role

- Public Function URL 설정이 `AuthType=NONE`이면 인증 없이 호출 가능.
- Lambda 내부 SSRF는 `AWS_LAMBDA_*` 환경변수와 `$LAMBDA_TASK_ROOT` 접근을 시도.

---

## 2. IAM Shadow Admin Paths (TA0003 Persistence)

| 권한 조합 | 효과 |
|---|---|
| `iam:CreateUser` + `iam:AttachUserPolicy` | 새 사용자를 admin으로 승격 |
| `iam:UpdateAssumeRolePolicy` | 기존 role 신뢰 정책을 조작하여 외부 계정에 AssumeRole 허용 |
| `iam:PassRole` + `ec2:RunInstances` | 원하는 role을 가진 EC2 인스턴스 실행 |
| `lambda:UpdateFunctionCode` | 기존 관리자 Lambda 코드를 덮어쓰기 → 호출 시 백도어 |
| `cloudformation:SetStackPolicy` + `CreateStackSet` | 다중 계정으로 persistent 백도어 배포 |
| `sts:AssumeRoleWithWebIdentity` | OIDC provider 설정이 허술하면 외부 ID로 AssumeRole |

**체크**
- Access Analyzer external-access findings
- IAM Policy Simulator로 각 주체의 effective permissions 열거
- `AdministratorAccess` 부여된 non-admin 사용자/role 식별

---

## 3. S3 / DNS Takeover

### S3 Bucket Takeover via Dangling DNS
- 이전 S3 버킷 이름이 Route 53의 CNAME/alias로 남아있고 버킷이 삭제되었다면
  공격자가 동일 이름으로 버킷을 선점 → 서브도메인 콘텐츠 장악.
- 체크: Route 53 → 대상 버킷 존재 여부 교차 확인.

### S3 Block Public Access 우회
- 계정 레벨 Block Public Access이 off이면 버킷 정책만으로 public이 될 수 있음.
- ACL 기반 public grant (`AllUsers`, `AuthenticatedUsers`).
- presigned URL이 1년짜리로 발급되면 사실상 public.

---

## 4. KMS / Secrets Manager / SSM

- KMS Key Policy에 `Principal: "*"`가 있으면 동일 region의 모든 주체가 사용 가능.
- SecretsManager에 `GetSecretValue` 권한을 가진 role이 너무 많다면 내부자/피싱으로
  크레덴셜 대량 탈취.
- SSM Parameter Store `SecureString`이 아닌 평문으로 비밀 저장된 경우 GetParameter로 즉시 읽음.
- SSM Session Manager 접근 권한이 Role에 포함된 EC2로 원격 쉘 획득 가능.

---

## 5. VPC / Network Lateral

- Security Group의 `0.0.0.0/0` + 관리 포트(22, 3389, 5432, 6379)
- NACL 누락 또는 반전
- VPC Peering → 다른 VPC의 pod IP로 이동 (east-west 공격)
- Transit Gateway를 통한 계정 간 이동

---

## 6. CloudTrail / GuardDuty / Config 회피

- CloudTrail 로그를 공격자가 삭제 가능한 S3 버킷에 저장하면 증거 인멸 가능.
- GuardDuty 비활성 region에서 활동 (detection 사각지대).
- Config Rule 예외 처리 (aws:ResourceTag/exemption="true") 악용.

---

## 탐지/대응 체크리스트
- [ ] Organization SCP로 민감 API 차단 (iam:CreateUser, kms:ScheduleKeyDeletion 등)
- [ ] CloudTrail → S3(SSE-KMS + Object Lock) + CloudWatch Events 알람
- [ ] GuardDuty All Regions + Findings → Security Hub
- [ ] Access Analyzer External Access
- [ ] Patch Manager + SSM inventory로 drift 감지
- [ ] IMDSv2 강제 (Organization-wide)
