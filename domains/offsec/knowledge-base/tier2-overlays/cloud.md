---
phases: [va, pentest, verify]
keywords: [cloud, infrastructure, iaas]
---
# Tier 2 Overlay: 클라우드 공통 (Cloud Infrastructure)

> 클라우드 인프라(AWS, GCP, Azure 등)가 감지된 프로젝트에 적용.
> 특정 벤더 특화 내용은 cloud-aws.md, cloud-k8s.md에서 커버.
> 이 파일은 벤더 무관 공통 보안 질문.

---

## A1 인증 (Authentication)

```yaml
Service_Account_Auth:
  question: "서비스 계정/IAM 인증이 최소 권한인가?"
  trace: |
    1. 서비스 계정이 개별 서비스마다 분리되는가? (공유 계정 금지)
    2. 장기 자격 증명(Access Key) 대신 임시 자격 증명(STS, Workload Identity)이 사용되는가?
    3. 서비스 계정 키 로테이션 주기가 정의되는가?

Instance_Metadata_Protection:
  question: "인스턴스 메타데이터 서비스가 보호되는가?"
  trace: |
    1. IMDSv2(토큰 기반)가 강제되는가? (IMDSv1 비활성화)
    2. 컨테이너/Lambda에서 메타데이터 접근이 제한되는가?
    3. SSRF 공격으로 메타데이터 서비스에 접근 가능한 경로가 있는가?
```

## A2 인가 (Authorization)

```yaml
IAM_Least_Privilege:
  question: "IAM 정책이 최소 권한 원칙을 따르는가?"
  trace: |
    1. "*" 와일드카드 권한이 사용되는가?
    2. 리소스 범위가 특정 ARN/리소스로 제한되는가?
    3. Condition 절로 접근 조건(IP, MFA, 시간)이 제한되는가?
    4. 사용하지 않는 정책/역할이 정리되는가?

Cross_Account_Access:
  question: "교차 계정 접근이 안전하게 관리되는가?"
  trace: |
    1. AssumeRole 시 외부 ID(ExternalId)가 요구되는가?
    2. 교차 계정 접근의 범위가 최소인가?
    3. 접근 로그가 기록되고 모니터링되는가?
```

## A3 데이터흐름 (Data Flow)

```yaml
Network_Segmentation:
  question: "네트워크 세그멘테이션이 적절한가?"
  trace: |
    1. 퍼블릭/프라이빗 서브넷이 분리되는가?
    2. DB/캐시가 프라이빗 서브넷에 배치되는가?
    3. Security Group/방화벽 규칙이 필요한 포트/IP만 허용하는가?
    4. 서비스 간 통신이 내부 네트워크(VPC peering, Private Link)로 제한되는가?

Data_Encryption_Transit_Rest:
  question: "데이터 전송/저장 시 암호화가 적용되는가?"
  trace: |
    1. 서비스 간 통신이 TLS로 암호화되는가?
    2. DB/스토리지 저장 시 암호화(AES-256, KMS managed key)가 적용되는가?
    3. 암호화 키 관리가 KMS/Vault를 통해 이루어지는가?
```

## A5 시크릿 (Secret Management)

```yaml
Secret_Storage:
  question: "시크릿이 안전하게 저장/관리되는가?"
  trace: |
    1. 시크릿이 코드/설정 파일에 하드코딩되지 않는가?
    2. Secrets Manager/Vault/Parameter Store를 통해 관리되는가?
    3. 시크릿 로테이션이 자동화되는가?
    4. 시크릿 접근 로그가 기록되는가?

IaC_Secret_Exposure:
  question: "IaC(Terraform/CloudFormation)에 시크릿이 노출되는가?"
  trace: |
    1. terraform.tfstate에 평문 시크릿이 포함되는가?
    2. State 파일이 암호화된 원격 백엔드(S3+KMS)에 저장되는가?
    3. IaC 변수에 sensitive 마킹이 적용되는가?
```

## A6 의존성 (Dependencies)

```yaml
Container_Image_Security:
  question: "컨테이너 이미지가 안전한가?"
  trace: |
    1. 베이스 이미지가 공식/검증된 소스인가?
    2. 이미지에 알려진 CVE가 있는가? (Trivy, Snyk 스캔)
    3. 이미지가 서명되는가?
    4. 불필요한 패키지/도구(curl, wget, shell)가 프로덕션 이미지에 포함되는가?

Supply_Chain:
  question: "CI/CD 파이프라인의 공급망이 안전한가?"
  trace: |
    1. GitHub Actions/워크플로우에서 시크릿이 안전하게 관리되는가?
    2. Self-hosted runner 사용 시 환경 격리가 되어 있는가?
    3. 서드파티 액션의 버전이 해시로 고정되는가? (태그 아닌 SHA)
```

## A7 에러 (Error Handling)

```yaml
Cloud_Service_Degradation:
  question: "클라우드 서비스 장애 시 graceful degradation이 구현되는가?"
  trace: |
    1. 의존 서비스(DB, 캐시, 큐) 장애 시 circuit breaker가 있는가?
    2. 가용 영역(AZ) 장애 시 자동 페일오버가 동작하는가?
    3. 장애 시 에러 메시지에 내부 인프라 정보가 노출되지 않는가?
```

## A8 리소스 (Resource Consumption)

```yaml
Logging_Monitoring:
  question: "로깅/모니터링이 충분한가?"
  trace: |
    1. 모든 API 호출, 인증 이벤트, 상태 전이가 로깅되는가?
    2. 로그에 PII/시크릿이 포함되지 않는가?
    3. 로그 보관 기간이 정의되는가?
    4. 이상 탐지 알림이 설정되는가? (비정상 트래픽, 인증 실패 급증)

Cost_Protection:
  question: "클라우드 비용 폭증이 방지되는가?"
  trace: |
    1. 자동 스케일링에 상한이 설정되는가?
    2. 비용 알림(Budget Alert)이 설정되는가?
    3. 사용하지 않는 리소스(EC2, RDS, EIP)가 정리되는가?
```
