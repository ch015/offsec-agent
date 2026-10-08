# 저장·복구·사용량

기준: 2026-10-08. CLI `assess`, 공개 `createOffsecAgent`, 직접 mission 호출은 같은 실행 경로와 잠금을 사용합니다.

기본 저장 위치는 대상 밖 `~/.ch015/<repo>/<time>_<commit-or-nogit>_<UUID>/engagement/`와 `report/`입니다. `CH015_STATE_HOME` 또는 `stateHome`을 지정할 수 있습니다. 원본 소스, 기존 보고서, 이전 실행을 자동 삭제하지 않습니다.

## 복구 자료

| 자료 | 용도 |
| --- | --- |
| `source-snapshot/`, `00_source_snapshot.json` | 실제 분석한 바이트와 메타데이터 |
| `source_manifest.json`, `00_scanner_plan.json`, `01_execution_tasks.json` | 범위·구조적 소유권·실행 작업 |
| `run-events.jsonl`, `run-state.json` | 파일 backend 원장과 재생 가능한 상태 |
| `.recovery/scheduler.json`, `session-processes/` | 작업 상태, 로컬 SDK 프로세스 생존/종료 |
| `work-units/*/attempt-*` | 재시도별 보존된 산출물 |
| `00_analysis_coverage.json`, `00_completion_coverage.json` | 봉인된 분석 범위와 검토 후 완료 상태 |
| `session-usage/`, `usage-receipts/` | 원래 SDK 사용량과 멱등 정산 영수증 |
| `.recovery/review-coordination.json` | 부족한 근거 질문과 보완 진행 상태 |
| `.recovery/review-progress.json` | 실제 저장 바이트와 대조한 검토 판정 및 독립 원문 전달 증빙 |
| `.recovery/review-reopen.json` | 과거 심각도 판정 보완 시 revision 전후 중단 복구용 원문 증빙·초안 |
| `03_evaluation_input.json`, `04_evaluation_classification.yaml`, `.recovery/evaluation-projection.json` | 확정된 검토의 분류표·실제 도구 범위 요약 및 원장/산출물 무결성 대조 |
| `evaluation-revisions/`, `.recovery/evaluation-reopen.json` | 평가·보고만 보완할 때 이전 산출물과 중단 복구 지시 |
| `07_security_report.draft.md`, `07_security_report.md`, `.recovery/publication-intent.json` | 모델 초안, 전체 판정·출처·범위 부록을 합친 최종 보고서, 발행 준비 영수증 |
| `revisions/` | 보완 전 검토·보고서 보존 |
| `run-archive.json`, `.artifact-store/` | 아카이브와 내용 기반 복구 객체 |

같은 실행을 재개하면 입력과 저장 증거를 검증하고 완료된 Analyzer와 필요한 phase 결과를 재사용합니다. 스냅샷이 다른 새 소스는 `--reuse-from`으로 별도 실행해야 합니다. 소스가 변경됐다는 이유로 과거 보고서를 수정하지 않습니다.

검토자는 `reviewPatch`로 최대 20개 판정씩 저장할 수 있습니다. 호스트는 SDK 쓰기 전 검증한 내용과 실제 파일을 대조하고, 쓰기 완료 콜백 전 중단도 복구합니다. 변경 없는 finding의 기존 판정과 독립 원문 전달만 재사용합니다. 원래 후보에서 판정이 늘어나고 이전 판정이 유지된 경우, `error_max_turns`는 같은 턴 한도를 가진 새 세션으로 이어집니다. 진전이 없으면 미완료로 남깁니다. 검토 초안은 최종 발행 자료가 아니며, 전체 ID·중복·인용 원문의 검사를 통과한 명시적 확정이 필요합니다.

평가 분류표는 확정된 검토와 canonical finding 원장에서 호스트가 생성합니다. 300개 이상의 판정도 모델이 수동으로 재작성하지 않으며, 보정된 ID를 가리키던 중복 관계는 최종 대표 ID까지 따라갑니다. 기존 분류·동일 원인·반증 검사는 생성 시 그대로 적용됩니다. 평가 모델은 종합 평가만 작성하고, 발행 전에 분류표·요약·검토·원장의 무결성을 다시 대조합니다. 이 해시는 실행 증거의 무결성 검사이며 새 소스의 EOL/EOF 변경 재사용 판정과는 별개입니다.

보고서도 같은 확정 원장에서 모든 판정·근거·전제·보완책과 제외된 이력을 부록으로 생성합니다. 모델 초안을 변경하지 않고 Git 출처와 스냅샷 식별자, 전체 부록을 합친 최종 바이트를 검사·발행합니다. 평가 전달 메타데이터의 `classificationSha256`은 분류표, `inputSha256`은 요약 입력을 가리킵니다. 완료 후 재개는 새 호스트 버전으로 부록을 다시 만들지 않고 발행 영수증의 무결성을 확인해 기존 최종 바이트를 복원합니다. 손상된 최종 파일은 정상 발행본으로 취급하지 않습니다.

확정 검토가 유효한 상태에서 평가 통계만 잘못된 경우, 내부 `reopenEvaluation` 복구 경로는 평가·보고 산출물을 보존한 뒤 두 단계만 무효화합니다. 분석 revision·검토 원문 영수증·비용은 유지합니다. 실행 중에는 적용을 거부하며, 원장 이벤트 이후 정리 중 중단되면 재개 시 정리를 마칩니다. 새 평가의 `actualToolCoverage`는 호스트 통계와 일치해야 저장됩니다.

```sh
pnpm assess /absolute/project --engagement-dir=/absolute/run --resume
pnpm run:admin inspect --engagement=/absolute/run --run-id=stored-id
pnpm run:admin resume-assess --engagement=/absolute/run --run-id=stored-id
```

`recover-publication`도 동일 재개 경로를 사용하며 저장된 run ID와 요청 ID가 같아야 합니다. 과거 v1 실행은 새 runtime에서 이어 실행하거나 자동 변환하지 않습니다.

부분 보고서 발행은 `run.incomplete`로 기록합니다. 다음 재개에서 이전 보고서와 검토를 archive한 뒤 실패·누락 작업을 보완합니다. 완료 영수증이 없는 과거 실행을 파일 존재만으로 complete 처리하지 않습니다. 손상된 projection은 검증된 object store 원본으로 복원하고, 원본도 손상되면 incomplete로 보존합니다.

취소 요청 후 worker가 실제 종료할 때까지 슬롯을 반환하지 않습니다. 종료 확인이 불가능하면 admission과 발행을 보류합니다. 재시작은 이전 coordinator와 기록된 SDK 자식의 PID/시작 식별자를 확인해 로컬 종료를 대조합니다. 이 확인은 provider의 원격 종료나 청구 중단 보장이 아닙니다.

## 백엔드와 아카이브

파일 저장소는 write-ahead batch와 fsync를 사용합니다. 마지막 미완성 원장 줄은 원본을 보존하고 복구하며, 중간 원장 손상은 거부합니다. PostgreSQL은 동일 이벤트 계약, lease fencing, outbox를 사용합니다. 공유 engagement 경로와 artifact store가 필요합니다. 실행 도중 file/PostgreSQL backend를 바꾸지 않습니다.

`archiveRun`과 `restoreRunArchive`는 소스 스냅샷·run metadata·보고서·원장을 포함합니다. 절대경로 영수증을 사용하는 현재 계약에서는 복원 시 원래 경로를 유지해야 합니다. 원격 저장 실패는 로컬 큐에 남기고 `ResilientArtifactStore.flush()`로 재전송합니다. 손상된 항목은 격리하며 다른 정상 항목의 전송을 계속합니다.

## 비용

기본 `costPolicy: record-only`는 금액 제한을 작동시키지 않습니다. 제한은 `costPolicy: enforce`와 양수 `maxBudgetUsd`를 함께 지정해야 합니다. CLI는 `--cost-policy=enforce --max-usd=100`입니다. `--no-cost-guard`는 명시한 제한도 해제합니다.

사용량은 결과 채택 전에 영수증으로 보존합니다. 늦은 성공이 작업 판정을 바꾸지 않아도 그 사용량은 정산합니다. 정산 영수증 ID는 중복 반영되지 않습니다. SDK 영수증이 없는 비용은 0으로 확정하지 않고 accountingComplete=false로 남깁니다. 명시적 enforce에서 미정산 예약은 보수적으로 유지합니다. provider 청구에 대한 절대 결제 한도는 보장하지 않습니다.
