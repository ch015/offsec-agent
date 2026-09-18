# secops-nunchi-agent CH015 포팅 동기화 계획서

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)

**작성일**: 2026-08-13
**작성자**: CH015 개발팀
**검토**: GPT-Sol-5.6 독립 리뷰 완료
**대상**: secops-nunchi-agent `domains/offsec/` (CH015 OffSec 도메인)

---

## 1. 배경

ch015-pentester에 2026-08-13 추가된 3가지 핵심 개선사항이 secops-nunchi-agent에 미반영:

1. **Selective Read Protocol** — 대용량 파일(500줄+) 컨텍스트 포화 방지
2. **Attack Surface Priority (P0-P3)** — 외부 표면 우선 분석 + 미들웨어-first
3. **도메인별 P0 정의** — 비-HTTP 도메인(AI/ML, NativeClient) 공격 표면 식별

이 개선은 Davinci(3,829파일, 252K LOC) 같은 대규모/복합 프로젝트 분석에서
컨텍스트 유실 및 분석 우선순위 부재 문제를 해결한다.

---

## 2. 현재 동기화 상태

### 전체 현황

| 지표 | 값 |
|------|-----|
| 동기화율 | 78.6% |
| 핵심 분석 엔진 동기화 | 100% (VA/Pentest/Verifier/RedTeam SKILL) |
| 누락 집중 영역 | 거버넌스/최적화 계층 |
| 현재 등급 | **B** (양호하나 개선 필요) |

### 완전 동기화된 파일 (변경 불필요)

- `skills/ch015/offsec/va/SKILL.md` (1,352줄) ✅
- `skills/ch015/offsec/pentest/SKILL.md` (1,569줄) ✅
- `skills/ch015/offsec/verifier/SKILL.md` (1,035줄) ✅
- `skills/ch015/offsec/redteam/SKILL.md` (753줄) ✅
- `skills/ch015/common/parallel-analysis.md` (528줄) ✅
- `skills/ch015/common/project-scanner.md` (445줄) ✅
- `skills/ch015/common/compensating-control.md` (363줄) ✅
- `skills/ch015/common/large-scale-flow.md` (309줄) ✅
- `skills/ch015/common/evidence-verification.md` (233줄) ✅
- `skills/ch015/common/taint-analysis.md` (111줄) ✅
- `knowledge-base/tier1-dimensions/` (8파일 전부) ✅
- `knowledge-base/tier2-overlays/` (9파일 — native-client 제외) ✅
- `agents/va-auditor.md`, `pentester.md`, `verifier.md` ✅
- depth 7종 + principles 4종 + checklists 4종 ✅

### Drift/누락 파일

| 파일 | 상태 | Drift |
|------|------|-------|
| `common/recon.md` | 구버전 | -229줄 (Phase 0-7 부재) |
| `common/selective-read.md` | 누락 | -239줄 (전체) |
| `common/context-loading.md` | 구버전 | -5줄 |
| `tier2-overlays/ai-agent.md` | 구버전 | -59줄 (Domain_P0_Definition 부재) |
| `tier2-overlays/native-client.md` | 누락 | -156줄 (전체) |
| `tier2-overlays/registry.yaml` | 구버전 | native-client 항목 부재 |

---

## 3. 포팅 계획

### 3.1. P0 — 즉시 포팅 (원자적)

> **3파일 동시 포팅 필수** — 상호 참조 관계로 인해 부분 포팅 불가

| # | 작업 | 소스 | 대상 | 방법 |
|---|------|------|------|------|
| 1 | selective-read.md 생성 | `ch015-pentester/skills/ch015/common/selective-read.md` | `domains/offsec/skills/ch015/common/selective-read.md` | 전체 복사 |
| 2 | recon.md Phase 0-7 추가 | ch015 recon.md 중 Phase 0-7 섹션 (229줄) | 기존 recon.md의 Phase 0-6 다음에 삽입 | 섹션 추가 |
| 3 | context-loading.md 갱신 | ch015 context-loading.md Phase_0_5_Binding | 기존 `load: []` → selective-read 등재 | 5줄 수정 |

**의존 관계**:
```
selective-read.md ← recon.md Phase 0-7이 참조 (large_files 출력)
                  ← context-loading.md가 로딩 보장
                  ← offsec-lead가 VA prompt에 주입 지시
```

**secops-nunchi-agent 아키텍처 적응 사항**:
- offsec-lead.md가 nunchi에서 별도 설계이므로, Attack_Surface_Priority_Rule은
  `domains/offsec/methods/va.md` 또는 해당 워커 설정에 반영 필요
- 워커 기반 실행에서도 VA 에이전트 프롬프트에 `[CH015 Attack Surface Context]` 블록이
  주입되도록 `offsec-contract.ts` 또는 워크플로우 설정 확인 필요

### 3.2. P1 — 단기 포팅 (1주 이내)

| # | 작업 | 방법 | 비고 |
|---|------|------|------|
| 4 | ai-agent.md Domain_P0_Definition | ch015 ai-agent.md 하단 59줄 append | AI 프로젝트 분석 품질 향상 |
| 5 | native-client.md overlay 생성 | 전체 복사 (156줄) | Tauri/Electron 분석 지원 |
| 6 | registry.yaml native-client 항목 | 12줄 추가 | overlay 자동 로딩 |
| 7 | CH015.md PI-1~PI-5 확인 | nunchi에 동등 방어 규칙 존재 여부 확인 → 없으면 포팅 | 프롬프트 인젝션 방어 |

### 3.3. P2 — 중기 포팅 (스프린트 계획에 포함)

| # | 작업 | 비고 |
|---|------|------|
| 8 | compliance.md 커맨드 | 이행점검 기능 (Remediation Verification) |
| 9 | review-lead + feedback 스킬 | PRD 기반 보안 의견서 생성 |

### 3.4. P3 — 포팅 불필요 (아키텍처 차이)

| 항목 | ch015-pentester | secops-nunchi-agent | 불필요 사유 |
|------|----------------|---------------------|------------|
| offsec-lead.md (1,077줄) | 단일 오케스트레이터 | methods/ 분리 + 워커 모델 | 아키텍처 의도적 차이 |
| ciso.md | CISO 분쟁 해결 | 자체 CISO 오케스트레이션 | 이미 별도 구현 |
| commands/run.md | 슬래시 커맨드 진입점 | 게이트웨이 API 기반 실행 | 실행 모델 차이 |
| agent-plan.js LOC 조건 | JS 런타임 gate | 자체 워크플로우 엔진 | 런타임 아키텍처 차이 |
| hooks/ (pre-tool-use 등) | Claude Code hook | 자체 hook/contract 시스템 | 플랫폼 차이 |

---

## 4. 포팅 절차

### Step 1: P0 원자적 포팅 (소요: 30분)

```bash
# 1. selective-read.md 복사
cp ch015-pentester/skills/ch015/common/selective-read.md \
   nunchi/secops-nunchi-agent/domains/offsec/skills/ch015/common/

# 2. recon.md Phase 0-7 섹션 추가
#    ch015 recon.md에서 "## Phase 0-7" ~ "## Context Binding" 직전까지 추출
#    nunchi recon.md의 Phase 0-6 직후에 삽입

# 3. context-loading.md Phase_0_5_Binding 수정
#    load: [] → load: ["skills/ch015/common/selective-read.md"]
#    persistent_note 추가
```

### Step 2: VA 프롬프트 주입 경로 확인

secops-nunchi-agent는 `offsec-contract.ts`에서 VA 에이전트 프롬프트를 구성한다.
이 파일에서 `[CH015 Attack Surface Context]` 블록이 주입되도록 확인:

```typescript
// 확인 대상: src/runtime/offsec-contract.ts
// VA 프롬프트 구성 시 recon Phase 0-7 결과를 Attack Surface Context로 주입하는 로직 존재 여부
```

없으면 `methods/va.md`에 Attack Surface Priority 지시를 추가.

### Step 3: 검증

- [ ] `selective-read.md` 파일 존재 확인
- [ ] `recon.md`에서 `Phase 0-7` grep 가능
- [ ] `context-loading.md`에서 `selective-read` grep 가능
- [ ] 기존 테스트/하니스 통과 확인 (있을 경우)

---

## 5. 위험 및 주의사항

### 아키텍처 차이로 인한 적응 필요

| ch015 개념 | nunchi 대응 | 적응 방법 |
|-----------|------------|-----------|
| offsec-lead.md 내 Attack_Surface_Priority_Rule | methods/va.md 또는 워커 설정 | 동등 지시를 해당 위치에 추가 |
| VA_Prompt_Injection 블록 | offsec-contract.ts 프롬프트 구성 | TS 코드에서 context 주입 확인 |
| Phase 0-7의 wc -l 실행 | 워커 환경에서 Bash 실행 가능 여부 | 런타임 환경 확인 |
| context-profiler.js phase mapping | nunchi 자체 로딩 메커니즘 | 해당 시 매핑 추가 |

### 포팅 시 수정 금지 항목

- VA/Pentest/Verifier/RedTeam SKILL.md — 이미 100% 동기화. 건드리지 않음
- Tier1 dimensions (a1~a8) — 동기화 완료
- depth/principles/checklists — 동기화 완료

---

## 6. 예상 효과

### P0 포팅 후

| Before | After |
|--------|-------|
| 대형 파일 전체 Read → 컨텍스트 포화 | Grep→부분 Read → 포화 방지 |
| 모든 엔드포인트 균등 분석 | P0(무인증 외부) 먼저 deep |
| 미들웨어 분석 누락 가능 | 미들웨어-first 강제 |

### P1 포팅 후

| Before | After |
|--------|-------|
| AI 프로젝트: HTTP P0만 식별 | 프롬프트 인젝션 경로도 P0 |
| Tauri/Electron: 도메인 질문 없음 | IPC/파일 파서 P0 + 8차원 질문 |

### 등급 변화

```
현재: B (78.6%)
P0 후: A- (88%)
P1 후: A (95%)
```

---

## 7. 승인

- [ ] 개발팀 리드 확인
- [ ] P0 포팅 일정 확정
- [ ] P1 포팅 스프린트 배정
