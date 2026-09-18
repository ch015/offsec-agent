# Knowledge Base — CH015 조직 기억

현재 호스트가 읽는 보안 차원·도메인 오버레이·표준·판단 보조 패턴입니다. 아래 engagements/CISO 예시는 원본 CH015의 이력 규약이며 현재 호스트의 출력 위치와 구분합니다.

## 지식 리소스와 원본 CH015 이력 규약

```
knowledge-base/
├── tier1-dimensions/                          # Tier 1: 보편적 보안 체크
│   └── a1-auth.md ~ a8-resource.md            #   8차원 × 기술 레이어
│
├── tier2-overlays/                            # Tier 2: 서비스 도메인 오버레이
│   ├── registry.yaml                          #   로딩 조건 (auto/conditional)
│   └── web3.md, payment.md, ...               #   도메인별 8차원 추가 질문
│
├── standards/                                 # 표준/규제 근거
│   ├── registry.yaml                          #   표준 로딩 레지스트리
│   └── owasp-top10.yaml, owasp-asvs-v4.yaml,  #   OWASP/NIST/PCI-DSS/프라이버시 규제
│       nist-sp800-select.yaml, pci-dss-v4.yaml, ...
│
├── conventions/                               # 조직 컨벤션
│   └── finding-id-naming.md                   #   Finding ID 네이밍 규칙
│
├── engagements/                               # 원본 CH015 이력 예시; 현재 host 출력 아님
│   └── {project}_{YYYYMMDD}/                  #   프로젝트명_날짜
│       ├── 00_recon_result.yaml               #     정찰 결과
│       ├── 01_va_result-1st.md                #     VA 1차 보고서
│       ├── 02a_verify_autonomous-1st.md       #     Verifier R0.5 독립 탐색 (VA 미열람 상태 생성)
│       ├── 02_verify_result-1st.md            #     Verify 1차 보고서
│       ├── 02b_verify_gap-1st.md              #     Verifier R4 Gap Diff (VA가 놓친 Autonomous_Only)
│       ├── 02_verify_objections-1st.yaml      #     Verify 1차 이의 목록
│       ├── 03_va_result-2nd.md                #     VA 2차 (피드백 후)
│       ├── 04_verify_result-2nd.md            #     Verify 2차
│       ├── 05_lead_convergence.yaml           #     VA/Verify 수렴 기록
│       ├── 06_pentest_result.md               #     Pentest 보고서
│       ├── 06b_redteam_result.md              #     Red Team 보고서
│       ├── 06c_lead_convergence.yaml          #     최종 수렴 (Pentest/RT 결과 통합)
│       └── 07_ciso_decision.yaml              #     CISO 최종 판단
│
├── patterns/                                  # 판단 보조 패턴
│   ├── false_positive_patterns.yaml           #   오탐/과대평가 패턴
│   ├── known_findings.yaml                    #   반복 발견 패턴
│   ├── domain_issue_map.yaml                  #   도메인별 빈발 이슈
│   └── coverage-matrix.yaml                   #   커버리지 매트릭스
│
└── README.md
```

## Tier 1 — 기술 레이어 (보편적, 모든 프로젝트)

8개 보안 차원 × 기술 레이어 매트릭스.

| 차원 | 파일 | 레이어 |
|------|------|--------|
| A1 인증 | a1-auth.md | Backend, Frontend, BaaS_DB, Web3, Mobile, SDK, Batch_Worker, LLM_AI |
| A2 인가 | a2-authz.md | Backend, Frontend, BaaS_DB, Web3, SDK, Batch_Worker, LLM_AI, Mobile |
| A3 데이터흐름 | a3-dataflow.md | Backend, Frontend, BaaS_DB, Mobile, SDK, AI_ML, Batch_Worker |
| A4 IO | a4-io.md | Backend, Frontend, BaaS_DB, AI_ML, SDK, Batch_Worker |
| A5 시크릿 | a5-secret.md | All, Frontend, Backend, Batch_Worker, LLM_AI, Infra, Mobile, SDK |
| A6 의존성 | a6-deps.md | Backend, Batch_Worker, Mobile, Frontend, BaaS_DB, AI_ML, SDK |
| A7 에러 | a7-error.md | Backend, Frontend, Batch_Worker, LLM_AI, BaaS_DB, SDK |
| A8 리소스 | a8-resource.md | Backend, Frontend, Batch_Worker, LLM_AI, BaaS_DB, SDK |

## Tier 2 — 서비스 도메인 오버레이 (해당 프로젝트만)

registry.yaml의 signal 매칭 시 로드. auto=도메인 감지 즉시, conditional=세부 시그널 매칭 시.

| 파일 | 도메인 | 로딩 |
|------|--------|------|
| web3.md | Web3 공통 | auto |
| web3-wallet.md | 임베디드 월렛 특화 | conditional |
| payment.md | 결제 플랫폼 | auto |
| sdk.md | SDK 전 플랫폼 | auto |
| ai-agent.md | AI/Agent 플랫폼 | auto |
| commerce.md | 커머스 | auto |
| cloud.md | 클라우드 공통 | auto |
| cloud-aws.md | AWS 특화 | conditional |
| cloud-k8s.md | Kubernetes 특화 | conditional |
| tee-enclave.md | TEE/Enclave 특화 | conditional |

## 수정 가이드

- **Tier 1**: 해당 차원 파일의 적절한 레이어 섹션에 추가. 도메인 특화 내용은 Tier 2에.
- **Tier 2 추가**: 2회 이상 engagement에서 gap 발생 시 신규 파일 + registry.yaml 업데이트.
- **패턴 추가**: engagement 검증 후 patterns/ 파일 갱신.

## 파일 네이밍 컨벤션

```
{순번}_{에이전트}_{유형}[-회차].{확장자}
```

| 필드 | 설명 | 예시 |
|------|------|------|
| 순번 | 실행 순서 (00-99) | `00`, `01`, `02` |
| 에이전트 | 작성 주체 | `recon`, `va`, `verify`, `pentest`, `lead`, `ciso` |
| 유형 | 산출물 종류 | `result`, `objections`, `convergence`, `decision` |
| 회차 | 피드백 루프 반복 시만 | `-1st`, `-2nd` (1회성 파일은 생략) |
| 확장자 | 형식 | `.md` (보고서), `.yaml` (구조화 데이터) |

## 저장 위치 분리

- **현재 host v1/v2**: 기본 `{target}/.nunchi/reports/<engagementId>/`에 중간 산출물과 최종 `07_security_report.md`를 함께 둡니다. `engagementDir`를 지정하면 해당 경로를 사용합니다.
- **원본 CH015 직접 실행**: 위 engagements/CISO 파일 규약은 원본 방법론 설명입니다. 현재 factory가 이 디렉터리에 실행 이력을 자동 누적하거나 지식 패턴을 자동 학습·수정하지 않습니다.
- **패턴 갱신**: 검증된 결과를 개발자가 지식 리소스에 반영하는 유지보수 작업입니다.
