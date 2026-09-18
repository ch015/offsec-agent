---
phases: [va, pentest, verify]
keywords: [kubernetes, k8s, container, pod, helm]
---
# Kubernetes Attack Primitives (P2-3)

> K8s / EKS / GKE / AKS 환경에서의 Red Team 공격 프리미티브.
> 참조 시점: redteam/SKILL.md Phase 1 AS1 / AS2.

## 1. Service Account Token 탈취 → RBAC Escalation (TA0006)

**자동 마운트된 토큰**
```
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```
- 컨테이너 RCE 획득 시 즉시 토큰 읽기 가능.
- `automountServiceAccountToken: false`로 비활성 가능 — 디폴트 true는 과도.
- Bound Service Account Token (1.22+): 수명 제한 + audience 바인딩 — 기본 활성화.

**RBAC 이스컬레이션 경로**
| 가진 권한 | 결과 |
|---|---|
| `create pods` | 노드 모든 secret 접근 (pod에 hostPath 마운트) |
| `impersonate users/groups/serviceaccounts` | system:masters 흉내 |
| `escalate verbs on roles` | 자신의 role에 권한 추가 |
| `bind roles` | 아무 role이나 자신에게 매핑 |
| `exec pods` | 다른 pod 내부로 진입 |
| `get secrets` in `kube-system` | controller 토큰 탈취 |

**공격 체인 예시**
```
Container RCE → SA token read → kubectl auth can-i --list
→ 'pods' create 권한 발견
→ 공격자 이미지 + hostPath=/ mount pod 배포
→ host filesystem 장악 → kubelet creds → 클러스터 노드 전체 장악
```

---

## 2. Admission Controller 우회

- ValidatingAdmissionWebhook/MutatingAdmissionWebhook이 timeout 시 `failurePolicy=Ignore`이면
  웹훅을 DoS하여 차단 우회.
- PSP(폐기) / PSA / OPA Gatekeeper / Kyverno 정책이 특정 namespace 예외 처리된 경우 해당 namespace로 우회.
- NetworkPolicy 부재 namespace는 east-west 무제한 이동.

---

## 3. 컨테이너 이스케이프 프리미티브

### CAP_SYS_ADMIN / privileged 컨테이너
- cgroup v1 release_agent 악용 (CVE-2022-0492)
- unshare + mount 조합으로 host 파일시스템 마운트

### Host Path Mount
- `hostPath: /` → container 내부에서 host `/etc/shadow`, kubelet kubeconfig 접근.

### Docker Socket Mount
- `/var/run/docker.sock`이 pod에 마운트되어 있으면 호스트의 모든 컨테이너 제어.

### CRI Socket Mount
- containerd.sock / crio.sock 마운트 시 kubelet을 거치지 않고 직접 컨테이너 제어.

### runC / containerd CVE
- CVE-2024-21626 (runC leaky handle) — workdir를 `/proc/self/fd/7` 같은 경로로 조작하여 호스트 파일시스템 접근.
- CVE-2019-5736 (runC overwrite) — host `/usr/bin/runc`를 덮어쓰기.
- CVE-2022-0811 (CRI-O kernel.core_pattern) — RCE.

### Kernel Exploits
- DirtyPipe (CVE-2022-0847) — 읽기 전용 파일 덮어쓰기 → setuid 바이너리 조작.
- nf_tables (CVE-2023-32233) — LPE → 컨테이너 탈출.

**사전 조건 체크 매트릭스**

| 공격 | 필요 권한 | 필요 커널/버전 | 필요 구성 |
|---|---|---|---|
| cgroup v1 release_agent | CAP_SYS_ADMIN | < 5.8 (cgroup v1) | cgroup unified 아님 |
| DirtyPipe | 없음 (일반 user) | 5.8 ≤ ver < 5.16.11, 5.15.25, 5.10.102 | - |
| runc CVE-2024-21626 | 없음 | - | runc < 1.1.12 |

---

## 4. etcd / Control Plane 접근

- etcd가 노출된 클러스터(잘못된 방화벽)에서 `etcdctl get / --prefix` → 모든 secret/토큰.
- kube-apiserver의 `--anonymous-auth=true` → system:unauthenticated에 과도 권한.
- 인증서 관리 소홀: `client-ca-file`에 공격자 서명 CA 포함 시 임의 클라이언트 인증.

---

## 5. Helm / GitOps 공급망

- Helm repository의 TLS 검증 부재 → MITM으로 차트 교체.
- ArgoCD `automated sync`에 pull request 심사 없음 → attacker가 PR로 악성 manifest merge.
- CI/CD가 service account 토큰을 secret으로 주입한다면 pipeline 로그에 노출 위험.

---

## 6. EKS / GKE / AKS 벤더 특이점

### EKS
- AWS auth ConfigMap 조작으로 IAM principal → RBAC 매핑 주입.
- IRSA (IAM Roles for Service Accounts) → pod가 AWS IAM role 사용 → token audience 검증 누락 시 외부 클러스터에서도 AssumeRole 가능.
- EKS 클러스터 endpoint가 public이면 internet에서 kube-apiserver 직접 호출.

### GKE
- Metadata Concealment v1 비활성 클러스터에서 pod → metadata API → GKE node SA 탈취 → GCP project lateral.
- Workload Identity 미설정 시 node SA(compute.default) 남용.

### AKS
- AAD Pod Identity(deprecated) 사용 중이면 Managed Identity 탈취 경로 노출.
- Azure RBAC와 Kubernetes RBAC 이중 부여 실수.

---

## 7. 네트워크 / Pod 격리 우회

- NetworkPolicy 부재 namespace는 cluster-wide traffic 가능.
- CNI plugin의 IP mapping 조작 (calico/cilium API 접근).
- Service Mesh (istio) sidecar 바이패스: `injection=disabled` 라벨 + direct pod IP 호출.
- Ingress controller 오설정 (wildcard host, path confusion).

---

## 탐지/대응
- [ ] Falco 또는 동급의 런타임 모니터 (process / syscall / file write)
- [ ] automountServiceAccountToken: false (default)
- [ ] admission controller 강제 (Kyverno / Gatekeeper)
- [ ] NetworkPolicy default-deny
- [ ] secret 접근 감사 (audit webhook)
- [ ] kubelet read-only port 비활성
- [ ] Pod Security Admission `restricted`
