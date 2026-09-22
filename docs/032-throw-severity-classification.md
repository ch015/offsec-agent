# throw 전수 분류 — severity classification

> **이전 기록 — 2026-09-22 안내 갱신.** 당시 측정·예외 분류 기록이다. 현재 OffSec v1/v2는 증거·범위·보고서 발행 게이트를 강제한다. warning-only/차단 없음 및 과거 throw·비용 수치를 현재 정책·성능으로 사용하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

> 대상: `src/runtime/` 전체 (66개 파일, __tests__ 제외)
> 총 throw: **796건**
> 분류 기준: 차단(BLOCK) / 경고(WARN) / 자동보정(AUTOFIX)

## 분류 요약

| Severity | 건수 | 비율 | 설명 |
|----------|:---:|:---:|------|
| **BLOCK** | ~77 | 9.7% | 보안 무결성 — 반드시 차단해야 함 |
| **WARN** | ~692 | 86.9% | 품질 이슈 — 로그 기록 후 계속 진행 가능 |
| **AUTOFIX** | ~27 | 3.4% | 기계적 보정 가능 — host가 자동 수정 |

> 초기 분류에서 BLOCK을 42건으로 집계했으나, 리뷰(gpt-5.6-sol)에서 ~35건의
> 변조 감지(변경됐다), path/boundary 검증, state machine safety throw가
> 누락된 것으로 확인되어 ~77건으로 상향 조정.

## BLOCK (42건) — 유지해야 하는 throw

hash 무결성, path traversal 방어, fencing token, 봉인 경계 위반.
이것들은 변조 감지·격리 보장이므로 throw가 맞다.

### 패턴별 분류

| 패턴 | 건수 | 예시 |
|------|:---:|------|
| hash 불일치 (SHA-256) | 37 | `artifact hash가 다르다`, `work plan hash가 다르다` |
| path traversal / 봉인 경계 | 22 | `artifact ref가 run의 봉인 디렉터리 밖을 가리킨다`, `traversal 경로`, `engagement 직속` |
| fencing token | 4 | `PostgreSQL append에는 fencingToken이 필요하다` |
| lease 만료 | 3 | `run lease가 만료되었거나 fencing token이 다르다` |
| redaction attestation | 2 | `SOC redaction attestation signature가 유효하지 않다` |
| 변조 감지 (변경됐다) | 5 | `OffSec work unit result artifact가 변경됐다` |
| ValidationSafetyError / entrypoint | 4 | `ValidationSafetyError`, host entrypoint 위반 |

### 파일별 분포

| 파일 | BLOCK 건수 |
|------|:---:|
| missions/assess.ts | 9 |
| workflow/state-store.ts | 3 |
| workflow/postgres-run-state-store.ts | 4 |
| contracts/result-contract.ts | 5 |
| workflow/run-lease.ts | 3 |
| workflow/engine.ts | 4 |
| offsec-contract.ts | 5 |
| soc-redaction.ts | 2 |
| soc-source.ts | 3 |
| live-auth-session.ts | 5 |
| finding-contract.ts | 3 |
| 기타 (20개+ 파일) | ~31 |

> 리뷰 반영: state-store.ts의 state machine 불변식은 WARN으로 재분류.
> assess.ts는 변조 감지(변경됐다) + hash + traversal 5건 추가.
> engine.ts는 ValidationSafetyError + entrypoint 4건 추가.
> finding-contract.ts는 path traversal 2건 + 변조 1건 추가.

## WARN (727건) — throw → 경고 로그로 전환해야 하는 것

LLM 출력 형식 오류, 스키마 필드 누락, 중복 값, 상태 불일치 등.
현재는 전부 throw로 되어있어서 retry cascade를 유발하지만,
실제로는 로그 기록 + best-effort 진행이 적절한 것들.

### 주요 카테고리

| 카테고리 | 건수 | 예시 |
|----------|:---:|------|
| 중복 값 검증 | 89 | `phase id가 중복됐다`, `artifact가 중복됐다` |
| 스키마/형식 불일치 | 112 | `schema와 contract가 다르다`, `format이 잘못됐다` |
| 필수 필드 누락 | 95 | `~가 필요하다`, `~가 없다` |
| 상태 불일치 | 78 | `~가 다르다`, `~와 다르다` (non-hash) |
| blocked status 전파 | 43 | `phase가 blocked 상태다`, `blocked payload가 통과했다` |
| 구조 검증 | 68 | `잘못됐다`, `유효하지 않다` |
| 계약 위반 (soft) | 52 | `계약에 없다`, `계약 밖` |
| provider 능력 부족 | 15 | `provider capability가 부족하다` |
| 도메인 로직 | 175 | 각 도메인별 비즈니스 규칙 검증 |

### 도메인별 분포 (WARN)

| 도메인 | 건수 |
|--------|:---:|
| workflow/ (engine, state, work-plan 등) | 241 |
| offsec 관련 | 178 |
| feedback 관련 | 100 |
| live-test/dast 관련 | 96 |
| soc 관련 | 72 |
| missions/ | 40 |

### 비용 영향이 큰 WARN 항목 (우선 전환 대상)

| 파일 | 건수 | 이유 |
|------|:---:|------|
| **offsec-work-plan.ts** | 57 | work plan 생성 중 형식 오류 → 전체 plan 실패 |
| **assess.ts** | 49 | mission 실행 중 soft 검증 → retry cascade |
| **offsec-contract.ts** | 37 | 계약 로딩 중 soft 불일치 → 실행 자체 불가 |
| **state-store.ts** | 25 | 상태 기록 중 중복/순서 → 불필요 실패 |
| **engine.ts** | 24 | phase 실행 중 soft 검증 → retry |
| **finding-contract.ts** | 23 | finding 제출 중 형식 → 유효 finding 거부 |
| **offsec-dependency-graph.ts** | 29 | 그래프 구성 중 구조 검증 → plan 실패 |

## AUTOFIX (27건) — host가 자동 보정 가능한 것

| 패턴 | 건수 | 보정 방법 |
|------|:---:|----------|
| round/ordinal 누락 | 5 | host가 phase round를 자동 부여 |
| artifact 크기 불일치 | 3 | 재계산 후 보정 |
| artifact 이름 모호 | 4 | 유일한 후보로 자동 해소 |
| schema version 불일치 | 5 | 허용 목록 확장 또는 기본값 적용 |
| count 불일치 | 6 | host ledger에서 실제 count로 보정 (이미 #10에서 일부 구현) |
| encoding/format 정규화 | 4 | 자동 변환 |

## 비교: ch015 원본 vs nunchi 이식

| 지표 | ch015 원본 | nunchi 이식 | 비율 |
|------|:---:|:---:|:---:|
| throw 총 수 | 26 | 796 | **31×** |
| BLOCK 해당 | ~8 | ~77 | 10× |
| WARN 해당 | ~12 | ~692 | **58×** |
| AUTOFIX 해당 | ~6 | ~27 | 5× |
| 검증 밀도 (throw/1000 LOC) | 2.9 | 36.3 | **13×** |

> 리뷰 반영: ch015 원본의 throw 수는 이식본 기준 26건 (초기 13건은 소스만 집계,
> 테스트 제외 전체 기준으로 26건이 정확).

## 결론

796건 중 **진짜 차단이 필요한 건 ~77건 (9.7%)**.
나머지 ~719건 (90.3%)은 경고 또는 자동보정으로 전환 가능.

> 리뷰(gpt-5.6-sol) 검증: 초기 분류에서 BLOCK 42건 → 77건으로 상향.
> 안전하게 WARN 전환 가능한 범위는 ~690–720건 (754건에서 ~35건 차감).
> 변조 감지, path traversal, trust boundary throw는 BLOCK 유지 필수.

현재 이 ~719건이 전부 throw → retry → cascade → blocked → 비용 소진의
원인이 되고 있다. 우선순위:

1. **offsec-work-plan.ts (~52건 WARN)** + **assess.ts (~43건 WARN)** + **engine.ts (~24건 WARN)** = ~119건
   → 이 3개 파일만 warning 전환해도 OffSec run의 주요 실패 경로 차단
2. **offsec-contract.ts (~32건 WARN)** + **finding-contract.ts (~20건 WARN)** = ~52건
   → 계약 로딩 + finding 제출 안정화
3. **state-store.ts (~28건 WARN)** + **offsec-dependency-graph.ts (~29건 WARN)** = ~57건
   → 상태 관리 + 그래프 구성 안정화

총 ~228건 전환으로 전체 실패 표면의 ~29%를 제거할 수 있다.
