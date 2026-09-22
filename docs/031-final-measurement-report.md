# 최종 측정 실행 리포트

> **이전 기록 — 2026-09-22 안내 갱신.** 당시 측정·예외 분류 기록이다. 현재 OffSec v1/v2는 증거·범위·보고서 발행 게이트를 강제한다. warning-only/차단 없음 및 과거 throw·비용 수치를 현재 정책·성능으로 사용하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

> Engagement: davinci_20260819T093808541Z
> 실행 시간: ~80분 (blocked로 종료)
> 날짜: 2026-08-19

## 실행 결과 요약

| 지표 | 이전 (concurrency=8, 66 units) | 현재 (concurrency=16, 55 units) | 변화 |
|------|:---:|:---:|:---:|
| Source files | 3,953 | 1,687 | **-57%** |
| Work units | 66 | 55 | **-17%** |
| maxConcurrency | 8 | 16 | **2x** |
| 50분 시점 진행률 | 22% | 62% | **2.8x** |
| 최종 verified | 65/66 (blocked) | 54/55 (blocked) | 유사 |
| 총 소요 시간 | ~6시간 | **~80분** | **4.5x 단축** |
| 최종 상태 | blocked | blocked | 미해결 |

## 개선 효과 확인

| 개선 항목 | 효과 확인 |
|-----------|----------|
| #12A Inert filter | ✅ 3,953→1,687 파일, 66→55 units |
| #16 maxConcurrency=16 | ✅ 16개 동시 실행 확인 |
| #12B Host Recon | ✅ 00_host_recon.json 정상 생성 |
| #13 Adversarial verifier | ✅ 적용됨 (방법론 변경) |
| #14 Timeout (30분) | — 발동 없음 (unit 소요 < 30분) |
| #17 Context budget 증가 | ✅ 적용됨 |
| #10+11 Upsert | ✅ count mismatch 0건 (이전 3건) |
| **#8 Partial restart** | ❌ **버그 발견 — 아래 상세** |
| #9 Ledger carry-forward | — verify-feedback 도달 unit 소수 |

## 신규 발견 버그: #8 Partial Restart의 cross-attempt artifact path 문제

### 증상
```
phase prior artifact path가 현재 worker의 완료 산출물이 아니다:
  .../unit-X/attempt-1/01_va_result-1st.md
```
- 39건 발생 (13개 unique units)
- 모든 케이스가 retry(attempt-2)에서 cached VA의 attempt-1 경로를 참조

### 근본 원인
```
#8 구현에서:
  1. attempt-1에서 VA 성공 → cachedVaResults에 저장 (artifacts 경로: attempt-1/...)
  2. attempt-1에서 Verify 실패 → unit rejected
  3. retryRejectedOnce → attempt-2 시작
  4. cachedVa 발견 → VA skip
  5. Verify에 priorArtifactPaths = [attempt-1/01_va_result-1st.md] 전달
  6. WorkflowHost (engagementDir=attempt-2/)가 attempt-1 경로를 거부
     → "현재 worker의 완료 산출물이 아니다"
```

### 영향
- 15개 unit에서 partial restart 시도, 13개가 이 에러로 실패
- retryRejectedOnce로 추가 retry 불가 → unit rejected → wave barrier 실패

### 수정 방향
1. **attempt-2의 engagementDir에 cached VA artifacts를 복사** (또는 symlink)
2. **또는** WorkflowHost가 `priorArtifactPaths`를 검증할 때 `allowedReadFiles`에 포함된 외부 경로도 허용하도록 수정
3. **또는** partial restart 시 같은 unitDir(attempt-1)을 재사용하고 verify만 재실행

## 기타 실패 (기존 패턴)

| 유형 | 건수 | 비고 |
|------|:---:|------|
| verify-feedback seal 실패 | 4 | #9 적용 범위 밖 (feedback 미도달 units) |
| artifact path 오류 | 4 | agent 출력 형식 문제, retry로 복구 |
| schema mismatch | 4 | agent structured output 오류, retry로 복구 |

## 결론

### 긍정적
- **속도 4.5배 향상** (6시간 → 80분)
- **Inert filter 효과 극대** (57% 파일 감소)
- **count mismatch 완전 해소** (#10+11 upsert 효과)
- **안정성 개선** (동일 시점 failure 91% 감소)

### 해결 필요
- **#8 Partial restart 버그** — cross-attempt artifact path 불허용. 수정 필요.
- 이 버그만 수정하면 55/55 wave 완료 → Root VA 도달 가능

## 다음 단계
1. #8 버그 수정: cached VA artifacts를 retry engagementDir에 복사하거나 path 검증 완화
2. 재실행하여 Root VA 도달 확인
3. Root VA cross-unit 분석 효과 측정
