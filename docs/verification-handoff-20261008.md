# 내부 진단 품질 검증 인수인계

기준 시각: 2026-10-08 14:45 KST. 사용자가 새 세션에서 검증을 다시 진행하기로 하여 실행을 중지했다. **실제 Precision·Recall·F1은 아직 미측정이며 90%를 달성한 상태가 아니다.** NodeGoat와 DVWA 실행은 체크포인트를 보존했고, 관련 모델 프로세스가 모두 종료됐음을 확인했다.

## 2026-10-08 재시작 기록

15:37 KST에 새 독립 실행 `nodegoat-02`를 시작했다. AST 44파일 파싱·Semgrep 상태 집계를 통과하고 Scanner 호출을 시작했다. `dvwa-02`는 같은 supervisor에서 순서대로 실행하도록 대기한다. 실시간 실행·종료 상태는 `out/implementation-20261008/quality90/restart-02-state.json`, 개별 로그는 `logs/nodegoat-02.log`, `logs/dvwa-02.log`에서 확인한다. 이 절은 재시작 기록이며 분석 완료나 품질 목표 달성 기록이 아니다.

- `01` 실행과 정답의 2,946개 파일 해시, 실행 코드 해시, 작업 트리 diff를 `logs/restart-evidence-20261008T063611Z/`에 보존했다. NodeGoat 111개·DVWA 252개 원본 manifest 항목이 고정 해시와 일치했다.
- 소스 읽기의 과대 `limit` 요청은 24,000바이트 기준으로 제한해 반환하고 `nextOffset`으로 이어 읽는다. UTF-8 문자 경계를 위해 추가 바이트가 포함될 수 있다. 범위 밖 파일·잘못된 정수 요청은 계속 거부한다. 관련 전달·복구 회귀 23개가 통과했다.
- 검증 runner는 재개 전 기존 요약·결과·실패를 `attempt-history/`에 보존하고 실행 중 상태를 기록한다. 취소·예외에도 새 요약을 쓰며, 확정되지 않은 비용은 `null`과 `accountingComplete: false`로 표시한다. 기존 `01` 산출물은 수정하지 않았다.
- Semgrep 1.157.0과 `record-only` 비용 정책을 유지한다. 정답은 모델 입력에 넣지 않았다. AST 흐름 상한과 PHP Semgrep 규칙 커버리지 한계는 아직 남아 있다.
- 이번 변경 전체의 회귀는 임시 PostgreSQL을 포함한 core 682개, 도메인 611개, 자체 점검 103개가 통과했다. TypeScript·계약·패키지·diff 검사도 통과했고 임시 DB 종료를 확인했다. 로그는 `logs/restart-20261008-153531/`에 있다. 검사 뒤 기존 2,946개 파일의 해시가 모두 일치했다. 이 결과는 실제 진단 Precision·Recall 측정과 구분한다.

아래 중지 상태·비용은 재시작 이전 `01` 실행의 역사 기록이다.

## 평가 파일 전달 수정 및 진단 중지

`nodegoat-02`는 17:20 KST에 평가 단계가 blocked를 반환하여 `incomplete / partial`로 종료했다. 확정 비용은 $108.0583183이며 비용 회계는 완료됐다. 입력·분류 파일의 SHA-256 실패는 없었다. 실제 Write 1회는 `vulnerabilityInventory` 객체가 원본과 다르다는 이유로 거절됐고, 이후 모델이 큰 목록을 재작성하기 어렵다고 보고했다. API의 크기 제한 오류는 기록되지 않았다. `dvwa-02`는 이어서 실행됐으며 18:00 KST 사용자 요청으로 중지했다.

사용자가 원본을 그대로 전달하도록 요청하여 다음 수정본을 별도 작업 사본에서 검증했다. DVWA 실행 중에는 도메인 계약·방법 카드의 해시 충돌을 피하기 위해 원래 작업 트리에 적용하지 않았다. 사용자 중지 요청에 따라 실행기와 남은 모델 프로세스 4개의 종료를 확인한 후, 푸시 요청에 맞춰 검증된 수정본을 원래 작업 트리에 적용했다.

DVWA 중지 시 확인 비용은 $64.80041625이며 진행 중이던 4개 호출의 최종 비용이 미확정이다. 두 `02` 실행의 알려진 비용 합계는 $172.85873455이고 최종 총비용은 아니다. 원장·산출물·체크포인트는 보존했으며 진단을 자동 재시작하지 않는다. 중지 확인 근거는 `out/implementation-20261008/quality90/stop-20261008T090053Z.json`이다.

- 작업 사본: `/private/tmp/secops-evaluation-forward-20261008-174731`.
- 패치와 적용 전후 파일 해시: `out/implementation-20261008/evaluation-forward-fix/evaluation-forward.patch`, `patch-manifest.json`.
- 평가 모델은 종합 평가·범위 해석·한계만 쓴다. 호스트가 기존 입력·분류 파일과 Reviewer/원장의 해시를 검증하고 원본 `vulnerabilityInventory`, `severityDistribution`, `actualToolCoverage`를 연결한다. 모델이 명시적으로 다른 값을 제출하거나 최종 파일이 누락·변조되면 기존 검증이 거절한다.
- Evaluate/Report 프롬프트의 전체 `resolvedReview` 중복 전달을 제거하고 파일 경로·해시 참조를 유지했다. 방법 카드와 계약 리소스 해시도 수정 사본에서 갱신했다.
- 실제 NodeGoat의 242,979바이트 목록·69개 원인 기록이 135바이트의 시험용 평가 본문과 함께 손실 없이 연결됨을 오프라인으로 확인했다. 원본 파일은 그대로이며 모델 호출은 0회다. `replay-receipt.json`이 근거다. 이 시험용 산출물은 모델의 새 평가나 최종 보고서가 아니다.
- 수정 사본에서 임시 PostgreSQL을 포함한 core 74개 파일·689개 테스트가 모두 통과했다. 타입·계약·패키지·diff·패치 적용 가능 검사도 통과했고 임시 DB 종료를 확인했다. 검증 근거는 같은 디렉터리의 `validation.json`과 로그에 있다.

이 수정은 재작성 문제를 해결하는 것으로, 보류된 후속 질문 66개나 Precision·Recall 검증까지 완료한 것은 아니다. 적용 전후 파일 해시는 `patch-manifest.json`과 일치함을 확인했다. 향후 사용자가 기존 `02` 실행의 재개를 요청하면 복구 실행으로 기록하며 새 독립 반복이라고 부르지 않는다.

## 새 세션 시작 문구

> `docs/verification-handoff-20261008.md`와 `out/implementation-20261008/quality90/handoff-state.json`을 먼저 읽고 검증을 이어서 진행해줘. 내부 진단용 프로젝트이고 독립 취약점 기준 Precision과 Recall 각각 90% 이상이 목표야. 비용은 제한하지 않고 기록만 해. 기존 산출물과 수정 내용을 보존하고, 현재 코드로 새로운 독립 실행을 진행해. 중단 원인·버그·정상 실행 실패는 바로 알려줘. 구현 테스트와 실제 탐지 성능을 구분하고 모든 예측을 판정해줘.

## 승인된 범위와 작업 원칙

- 대상은 현재 OffSec 에이전트의 구조·진단 품질·완료 및 복구 동작이다. 내부 진단용으로 평가한다.
- 목표는 고정한 독립 원인 정답셋의 **Precision ≥0.90, Recall ≥0.90**이다. F1도 함께 계산한다. 정확도라는 이름으로 챌린지 달성률을 대신 사용하지 않는다.
- 다른 공개 취약 프로젝트와 방어 코드 대조군도 검증한다. 비용 정책은 `record-only`이며 금액 상한을 새로 추가하지 않는다.
- 실제 일반 소스 분석에 정답이나 특정 Finding의 수정 답안을 주입하지 않는다. 새 유효 결함은 별도 `novel-valid`로 판정하며 같은 실행의 Recall 분모를 바꾸지 않는다.
- 작업 트리에 이전부터 많은 변경·삭제·미추적 파일이 있다. 사용자의 변경을 되돌리거나, 이전 결과를 삭제하거나, 임의로 커밋하지 않는다.
- 새 세션이 같은 workspace를 사용해야 로컬 `out/` 산출물이 보인다. 이 디렉터리는 Git 배포 산출물이 아니다.

## 현재 구현

이전 집계 개편의 상세 내용은 [detection-improvements.md](detection-improvements.md)에 있다. 새 실행은 Reviewer가 독립 원인과 관찰을 구분하고 `causeId`, `component`, `rootCause`, `fixBoundary`, 정확한 근거를 제출해야 한다. 동일 인용문을 공유한다는 이유만으로 서로 다른 결함을 합치지 않는다. 평가·보고·벤치마크 어댑터까지 이 집계를 전달한다.

이번 세션에서 추가한 구현은 다음과 같다.

| 위치 | 현재 동작 |
|---|---|
| `src/runtime/planning/security-obligations.ts` | 파일·담당 구간의 입력 검증, 인가, 위험한 출력, 상태·세션, 설정·비밀값에 검토 항목과 사례를 생성한다. 누락·중복 사례, 잘못된 인용, 미등록 Finding 참조를 검사한다. |
| `planning/task-planner.ts`, `planning/analysis-assessments.ts` | 작업 요청과 `02_file_assessments.json`에 검토 항목을 연결한다. 위반은 제출 Finding에 연결하고 미해결 항목은 완료로 처리하지 않는다. 실제 소스 전달 기록도 요구한다. |
| `domains/offsec.ts`, `missions/assess-v2.ts` | 호스트가 검토 범위·참조 가능한 공통 Finding·컨텍스트를 제공하고 결과를 검사한다. `securityControlCoverage`를 집계한다. |
| `planning/source-revision.ts` | 검토 요구사항이나 인용된 가드 소스가 바뀌면 이전 평가 재사용을 제한한다. |
| `domains/offsec/methods/analyze.md` | 상위 미들웨어·ORM·버전·환경 조건을 확인하고 구체적인 판정 근거를 남기도록 지시한다. |
| `src/runtime/diagnostic-quality.ts` | 독립 원인 단위 P/R/F1, 미탐 목록, 새로운 정탐, 중복·미해결·부정확한 조건, 음성 대조군을 집계한다. 숫자가 높아도 미완료·미검증 항목이 있으면 합격시키지 않는다. |
| `domains/offsec/lib/ch015/ast/semgrep.js` | SQL 파일과 `composer.lock`을 파일 유형에 맞게 분류한다. 현재 규칙이 없는 파일을 검사 성공으로 표시하지 않고 `no-applicable-rule`로 기록한다. 알 수 없는 다른 `.lock`은 계속 미확인으로 남긴다. |

검토 항목은 **보수적인 파일·구간별 점검 목록**이다. 모든 API의 의미적 발견이나 모든 실행 경로 검증을 보장하지 않는다. `cross-boundary-flow` 사례 정의는 있으나 해당 검토 항목 생성은 아직 연결하지 않았다. 기존 별도 flow 책임과 근거 검사는 유지된다. 판정 사유의 의미적 진실성은 독립 검토가 필요하다.

기존 `evals/offsec/scoring.ts`와 `BenchmarkCaseSchema`를 새 점수 계산기로 교체한 것은 아니다. 새 `diagnostic-quality.ts`를 실제 독립 판정 결과에 연결하는 작업이 남아 있다. 기존 벤치마크의 양성 라벨 최소 1개 제약, 라벨 수와 원인 수의 구별도 후속 검토 대상이다.

## 구현과 조건 검증 결과

| 검증 | 결과 | 범위 |
|---|---:|---|
| 전체 core Vitest | 659 통과, 8 건너뜀 | 새 검토 항목 구현까지. DB 등 외부 조건이 필요한 테스트 포함 8개 제외. |
| 새 독립 점수 계산 테스트 | 14 통과 | 90% 경계, 미해결 누락 방지, 중복, 잘못된 근거·조건, 순수 음성 사례의 null 지표 등. |
| Semgrep 회귀 테스트 | 10 통과 | SQL·Composer 파일 집계 수정 포함. |
| DVWA 격리 PHP 핸들러 조건 검사 | 21 통과 | 원본 취약/방어 코드, 실제 SQLite, 가로챈 shell·header 호출. |
| TypeScript typecheck | 통과 | 새 점수 계산 모듈 포함. |
| 계약 리소스 생성 및 최종 검사 | 통과 | Semgrep 수정 뒤 리소스 해시 갱신. |
| `git diff --check` | 통과 | 인수인계 문서 작성 전 확인. |

전체 core 테스트는 점수 계산 모듈·마지막 Semgrep 수정 이전 실행이다. 서로 다른 검증 횟수를 합쳐 마지막 전체 테스트 결과인 것처럼 보고하지 않는다. 최종 변경 전체에 대한 core/vendor/package/DB 회귀는 새 세션에서 적절히 완료한다.

DVWA 조건 검사는 실제 HTTP 서비스나 브라우저 공격 결과가 아니다. 네트워크를 끈 PHP 컨테이너에서 핸들러를 실행했으며 shell 명령은 실행하지 않았다. 컨테이너 이미지는 `php@sha256:8dbeb51c352cf1f70d5d50f3642c9fbed311e914475ea2382f5bc1525bef7bb3`이며 PHP 8.3.35다.

## 고정한 평가 자료

기본 디렉터리는 `out/implementation-20261008/quality90/`다.

| 대상 | 고정 커밋 | 알려진 독립 원인 | 음성 검토 |
|---|---|---:|---|
| OWASP NodeGoat | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | 22 | 실제 방어·영향 과장 방지 항목 5개 |
| digininja DVWA | `068d974487a297c155c48722f9fcf7180a83adc4` | 53 | 방어·영향 과장 방지 항목 12개 |

정답은 `truth/nodegoat.json`, `truth/dvwa.json`과 각 `.sha256` 파일에 있다. 모델 예측을 보기 전에 원본 소스의 수정 경계·조건·인용을 고정했다. `freeze-nodegoat.py`, `freeze-dvwa.py`는 기존 정답이 있으면 덮어쓰지 않는다. 분석 에이전트의 target에는 정답 파일을 넣지 않았다.

이 자료는 내부 진단용으로 정리한 **알려진 원인 집합**이다. 공식 전체 취약점 수, 모든 가능한 결함의 완전한 정답, 모델이 처음 접한 holdout이라고 주장하면 안 된다. 교육용 프로젝트 자체에 설명·수정 예시가 포함돼 있다. 정답에 오류가 발견되면 근거와 정정 이력을 남기고 평가 버전을 구분한다. 점수를 올리기 위해 정답을 사후 축소하지 않는다.

DVWA의 서로 독립적으로 수정해야 하는 별도 핸들러는 별도 원인이다. 여러 입력이 사용하는 공유 출력·include 결함은 공유 수정 경계 한 개로 묶었다. `impossible`이라는 이름만으로 파일 전체를 안전하다고 판정하지 않는다. 예를 들어 GCM 변조 방어와 공개 하드코딩 키에 의한 토큰 위조는 별개다.

## 실제 에이전트 실행 중지 상태

최종 상태의 근거는 `handoff-state.json`, 각 실행의 `failure.json`, `engagement/usage-receipts/`다.

| 실행 | 중지 시점 | 완료 정보 | 알려진 비용 |
|---|---|---|---:|
| `runs/nodegoat-01` | 사용자 인수인계 요청으로 분석 중지 | 계획 20유닛·30실행 작업 중 13유닛·16작업 완료 산출물 보존. 최종 uncovered 43파일. 최대 동시 활동 29. | $37.96512175 |
| `runs/dvwa-01` | 도구 복구 후 scanner 단계 중지 | 분석·검토·리포팅 미완료. | 확정된 비용 영수증 $0 |

**비용 회계는 미완료다.** NodeGoat 13호출, DVWA 1호출은 중단 때문에 완전한 usage 영수증을 받지 못했다. DVWA가 무료로 실행됐다는 뜻이 아니며, 두 실행 실제 총비용을 $37.97로 확정할 수 없다. NodeGoat의 quarantined 항목 14개에는 중단 및 미실행 작업이 포함된다.

**`summary.json`과 `result.json`은 첫 사전 도구 실패 당시의 오래된 결과다.** 현재 runner는 재개 도중 취소 예외가 나면 `failure.json`만 쓰고 기존 summary를 갱신하지 않는다. 이 파일의 `$0`, 미시작 표시를 최신 결과로 읽으면 안 된다. 다음 세션에서 runner의 취소 상태 기록도 개선할 필요가 있다. 기존 파일은 감사 이력으로 보존했다.

현재 실제 독립 원인 정탐·오탐·미탐 전체 판정은 하지 않았다. 따라서 P/R/F1도 없다. 중단을 모델 오탐이나 실행 자체의 자연 실패로 집계하지 않는다.

## 이번에 발견한 실행 문제

1. **Semgrep 버전 불일치**: 기본 PATH는 1.163.0, 계약은 1.157.0이다. 첫 NodeGoat 시도는 모델 호출 전 차단됐다. 기존 격리 설치 `/private/tmp/secops-redesign-semgrep-1.157/bin`을 PATH 앞에 두어 복구했다. 전역 설치를 바꾸지 않았다.
2. **파일 읽기 상한 초과 요청**: NodeGoat 분석 중 `package-lock.json`의 `read_source` 요청에서 limit 24,000바이트 상한을 초과해 한 번 거절됐다. 후속 작은 요청의 정상 전달은 확인했다. 전체 파일 읽기 완료는 사용자 중단으로 최종 확정하지 못했다. 상한을 넘는 요청을 명시적으로 나누거나 bounded 응답과 `nextOffset`으로 처리하는 개선은 아직 하지 않았다. 관련 구현은 `source-reader.ts`, `finding-mcp-server.ts`다.
3. **Semgrep 유형 집계 누락**: DVWA의 SQL 파일 5개와 `composer.lock`을 미분류하여 첫 batch에서 중단됐고 이후 batch도 미실행으로 남았다. 파일 유형 분류를 수정하고 10개 회귀 테스트 후 재개했다. 실제 재실행은 198파일 모두 상태가 기록됐다.
4. **AST 흐름 200개 상한**: DVWA에서 `data_flows: true` truncation이 기록됐다. 아직 수정하지 않았다. 직접 소스 분석 범위에는 모든 대상 파일이 남지만 AST 흐름 전체가 제공됐다고 말하면 안 된다.
5. **취소 후 오래된 실행 요약**: 위의 runner summary 갱신 문제. 현재 실제 상태는 handoff 영수증을 사용한다.

복구 후 NodeGoat 사전 분석은 AST 44파일 파싱, Semgrep 요청 78파일 중 검사 48·적용 규칙 없음 30·후보 4였다. DVWA는 AST 179파일 파싱, Semgrep 요청 198파일 중 검사 18·적용 규칙 없음 180·후보 3·미확인 0이다. 현재 Semgrep 규칙의 PHP 커버리지가 부족하다. `complete`는 파일별 처리 상태의 집계 완료이지 전 언어의 취약점 검사 완료가 아니다.

## 재검증 명령

저장소 루트: `/Users/philip/workdir/security-philip/security-project/agent/secops-agent-offsec`.

```sh
export PATH="/private/tmp/secops-redesign-semgrep-1.157/bin:/Users/philip/.nvm/versions/node/v22.18.0/bin:$PATH"
SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 semgrep --version
pnpm check:contracts
pnpm typecheck
```

새 독립 실행은 기존 `01`을 덮어쓰지 않고 `02`를 사용한다. 먼저 저장소 상태와 위에 남은 문제를 확인한다. 내부 provider 설정·API 자격증명은 기존 환경을 사용하고 값을 출력하지 않는다.

```sh
pnpm exec tsx out/implementation-20261008/quality90/run.ts nodegoat 02
pnpm exec tsx out/implementation-20261008/quality90/run.ts dvwa 02
```

위 명령은 순서대로 실행하면 된다. 복구 기능 검증이나 기존 작업을 이어갈 때만 아래 명령을 사용하고, 이를 독립 반복 측정이라고 부르지 않는다.

```sh
pnpm exec tsx out/implementation-20261008/quality90/run.ts nodegoat 01 --resume
pnpm exec tsx out/implementation-20261008/quality90/run.ts dvwa 01 --resume
```

runner 설정은 `--mode ast`에 해당하는 `mode: 'ast'`, `tools: ['semgrep']`, `costPolicy: 'record-only'`, `claude-opus-5` / review `claude-sonnet-5`, effort high, maxTurns 120이다. 원본 파일과 정답의 보존 여부를 먼저 검사하고 정답을 모델 프롬프트에 넣지 않는다. `juice-shop` 및 `fixed-controls` 이름은 runner에 예약돼 있으나 해당 정답 JSON은 아직 준비되지 않았다.

조건 검사는 다음과 같이 재실행할 수 있다.

```sh
python3 out/implementation-20261008/quality90/verify-dvwa.py
pnpm exec vitest run src/runtime/__tests__/security-obligations.test.ts src/runtime/__tests__/diagnostic-quality.test.ts
node --test domains/offsec/lib/ch015/ast/test/semgrep.test.js
```

## 다음 작업 순서

1. 최신 상태·비용 영수증과 dirty tree를 확인하고 보존한다. 취소 summary 문제와 읽기 상한 요청의 복구 동작을 점검한다.
2. 새 일반 실행을 끝까지 수행한다. 모델 입력에 정답이나 특정 결함의 답을 추가하지 않는다. 도구·원장·프로세스 오류는 즉시 알린다.
3. Reviewer의 독립 원인 집계를 검증하고 **모든** 양성 예측에 독립 판정을 부여한다. 관찰로 잘못 분류된 실제 결함도 정답 대비 미탐으로 남겨야 한다. 증거·실제 가드·버전·환경·수정 경계와 전체 주장을 확인한다.
4. 고정한 음성 대조군에 대한 오탐과 새로운 유효 결함을 함께 판정한다. `diagnostic-quality.ts`에 연결해 프로젝트별 TP/FP/FN, P/R/F1, 중복·미해결·완료·비용을 산출한다. 합집합이나 좋은 반복만 골라 단일 실행 성능으로 보고하지 않는다.
5. 목표 미달 원인을 일반화 가능한 코드·지시·도구 개선으로 고치고 동일 정답에 재평가한다. 재평가 이력과 기준 버전을 유지한다.
6. Juice Shop의 독립 원인 정답셋과 새 검증도 완료한다. 기존 111챌린지 비교는 참고 자료이며 독립 원인 정답이 아니다. 전용 수정 대조군 확장, 교차 흐름 검토 항목, AST 상한 후속 처리도 남아 있다.
7. 최종 변경 전체의 적절한 회귀 검수와 실제 측정 근거를 정리한다. 관찰된 목표 달성과 모든 프로젝트에 대한 일반 성능 보장은 구분한다.

## 중요한 산출물

- `out/implementation-20261008/quality90/handoff-state.json`: 사용자 중지 직후 상태·비용·프로세스 종료 확인.
- `out/implementation-20261008/quality90/progress.json`: 목표와 남은 작업.
- `out/implementation-20261008/quality90/truth/`: 고정 정답·조건·소스 manifest.
- `out/implementation-20261008/quality90/runs/`: 실제 실행, 원장, 모델 호출, source snapshot, 체크포인트, 미완료 결과.
- `out/implementation-20261008/quality90/logs/`: 이번 회귀·실행 로그 복사본.
- `out/implementation-20261008/quality90/dvwa-condition-tests.json`: 21개 격리 조건 검사 결과와 이미지·harness 식별 정보.
- `out/implementation-20261008/independent-counting/`: 이전 독립 집계 검수 자료.
- `out/implementation-20261007/challenge-comparison-20261008/`: 기존 Juice Shop 111개 대응 비교.

이전 Juice Shop 결과는 두 실행의 CONFIRMED 기록 234/233개, 챌린지 직접 대응 72/111·76/111이었다. 독립 취약점 수·Precision·Recall이 아니다. 당시 알려진 비용 약 $513.999도 비용 회계 미완료 수치이며, 이번 새 평가의 확인 비용과 혼동하지 않는다. 이전 실행에는 운영자 수정·재개가 있어 깨끗한 독립 반복으로 취급할 수 없다.
