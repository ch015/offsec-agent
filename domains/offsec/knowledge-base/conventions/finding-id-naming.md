---
phases: [va, pentest, converge]
---
# Finding ID Naming Convention

> ch015 시스템 내 모든 Finding/Scenario ID 체계의 단일 진실 공급원 (Single Source of Truth).
> 통합 보고서에서 ID 충돌/혼란 방지 + 출처 추적 가능.

---

## ID 체계 카탈로그

| 접두사 | 출처 | 의미 | 예시 |
|--------|------|------|------|
| **F-{NNN}** | VA / Pentest 정규 Finding | 표준 보안 Finding (Phase 1-5에서 발견) | `F-001`, `F-042` |
| **F-API-{NN}** | api.yaml 체크리스트 | API 보안 표준 매핑 Finding | `F-API-03` |
| **F-S{NNN}** | Pentest Phase 6.0 Sweep | 라이브 Sweep에서 발견된 신규 후보 | `F-S001` |
| **V-{NNN}** | Verifier Phase R0.5 | Autonomous Discovery에서 독립 발견한 후보 | `V-001` |
| **CAS-{NNN}** | Pentest Phase 3.5 | Creative Attack Scenario | `CAS-001` |
| **AC-{NNN}** | VA Phase 3.5 Step 3 | 경량 공격 체인 (Attack Chain) | `AC-001` |
| **AS{N}-{NNN}** | Red Team Phase 1 | 공격 표면별 Finding (AS1-AS5) | `AS1-014` |

---

## 단계별 ID 생성 시점

```
Phase 0 Recon         → ID 생성 없음 (자산/엔드포인트만 식별)
Phase 1-3 VA          → F-{NNN} 부여 (체크리스트 매핑 시 F-API-{NN} 추가)
Phase 3.5 VA Step 3   → AC-{NNN} 부여 (공격 체인)
Phase 3.5 Pentest     → CAS-{NNN} 부여 (Creative Attack)
Phase 6.0 Sweep       → F-S{NNN} 부여 (라이브 신규 후보)
Phase R0.5 Verifier   → V-{NNN} 부여 (자율 탐색)
Phase R4 Gap Diff     → V-{NNN} 중 VA로 승격 시 F-{NNN} 재부여
Red Team Phase 1      → AS{N}-{NNN} 부여 (공격 표면별)
```

---

## ID 변환 규칙 (승격/병합)

### Verifier V → 정규 F 승격
- **조건**: Phase R4 Autonomous_Only Finding이 R1.2 taint re-trace 통과 → 신규 정규 Finding 확정
- **변환**: `V-{NNN}` → `F-{NNN+α}` (기존 F 번호 다음으로 부여)
- **추적**: `02b_verify_gap-<round>.md`에 `V-{NNN} → F-{NNN+α}` 매핑 기록

### Sweep F-S → 정규 F 흡수
- **조건**: Phase 6 Route 심층 검증에서 CONFIRMED → 정규 Finding 확정
- **변환**: `F-S{NNN}` → `F-{NNN+α}` 또는 기존 F-{NNN}에 라이브 증거로 병합
- **추적**: Pentest 보고서 Section 5/6에 출처 메타데이터 (`origin: sweep`) 명시

### Creative CAS → 정규 F 승격
- **조건**: Phase 4 POC 생성 + 라이브 검증 CONFIRMED
- **변환**: `CAS-{NNN}` → `F-{NNN+α}` (Creative 분석 영향 메타데이터 보존)

---

## 통합 보고서 표시 규칙

### CISO Convergence (`06c_lead_convergence.yaml`)

```yaml
# 통합 후 ID 체계
final_findings:
  - id: "F-001"
    origin: "va_phase_1"           # va_phase_1 / va_phase_2 / va_phase_3.5 / pentest_phase_6 / verifier_r4 / sweep / creative
    derived_from: null              # 다른 ID에서 변환된 경우 원본 ID
    severity: "HIGH"
    
  - id: "F-042"
    origin: "verifier_r4"
    derived_from: "V-007"           # ★ Verifier에서 승격
    severity: "MEDIUM"
    
  - id: "F-043"
    origin: "pentest_sweep"
    derived_from: "F-S003"          # ★ Sweep에서 흡수 (라이브 검증으로 CONFIRMED)
    severity: "HIGH"
```

### 최종 보고서 본문 표기

```markdown
### F-001: SQL Injection in /api/users
**출처**: VA Phase 1 A4 Input Boundary

### F-042: Cache Key Confusion (V-007 승격)
**출처**: Verifier Phase R4 — Autonomous Discovery에서 발견, taint re-trace 통과 후 정규 Finding 승격
```

---

## 충돌 방지 원칙

### Single Numbering Pool
- **F-{NNN}**의 N은 **CISO Convergence 시점에 통합 풀**에서 재할당
- 각 Phase가 임시로 부여한 F-{NNN}은 Convergence에서 변경 가능 (Phase 보고서에는 원본 + 변환 매핑 기록)

### 접두사 중복 금지
- 신규 Phase/모듈 추가 시 기존 접두사(F/V/CAS/AC/AS)와 충돌 검증 필수
- 신규 접두사는 본 문서에 추가 등록 후 사용

### 외부 시스템 매핑
- **Jira**: 티켓 summary에 `[F-{NNN}]` 접두사 (`commands/report.md` Step 2 Jira 통합)
- **Confluence**: 보고서 헤딩에 ID 명시
- **Slack**: 알림 메시지 첫 줄에 ID

---

## 참조 위치

본 규칙은 다음 위치에서 참조됩니ity:

| 파일 | 참조 컨텍스트 |
|------|--------------|
| `skills/ch015/offsec/va/SKILL.md` | Finding Structure (L947+) |
| `skills/ch015/offsec/pentest/SKILL.md` | Finding Structure + Sweep (L809) + Creative (L539) |
| `skills/ch015/offsec/verifier/SKILL.md` | R0.5 Output (L168) + R4 Reconcile (L686) |
| `skills/ch015/offsec/redteam/SKILL.md` | Finding Structure (L633+) |
| `agents/offsec-lead.md` | Convergence (L519+) |
| `templates/va-report.template.md` | Finding 표시 |
| `commands/report.md` | Jira 통합 |

새 ID 체계 추가 시 본 문서를 먼저 수정한 후 위 파일들에 반영.
