# 분석 산출물 보존과 재개

신규 CLI(v1/v2)와 `createOffsecAgent().run()`의 기본 위치는 분석 타겟 밖이다.

```text
~/.ch015/<대상 레포명>/<UTC시간>_<커밋12자리 또는 nogit>_<UUID>/
  run.json
  engagement/
    assess-v2-checkpoint-input.json
    run-events.jsonl
    run-state.json
    run-archive.json
    .artifact-store/             내용과 hash를 확인하는 로컬 불변 객체
    .recovery/                  미반영 상태, 원장 손상본, 전송 대기, 발행 의도
    ...                         manifest, AST, coverage, 단위 결과, draft 등
  report/
    07_security_report.md       검증 후 발행
    analysis.partial.md         복구 가능한 실패가 남은 경우
```

`stateHome` 또는 `CH015_STATE_HOME`으로 루트를 지정할 수 있다. 타겟과 기본 저장 루트의 중첩은
거부한다. 같은 이름의 레포도 실행 UUID로 격리한다. 명시적인 기존 `engagementDir`는 이전 파일
배치를 유지한다. 기본 경로를 사용하는 경우 타겟에 `.nunchi`나 `.gitignore`를 만들지 않는다.

이번 단계는 파일 저장과 재개를 안정화한다. SQLite `state.db` 전환, 취약점 영구 ID/diff 연결,
보관 기간·용량·삭제 정책은 후속 작업이다. 파일 기반 phase 계약 때문에 engagement 안에 final의
검증용 사본과 draft를 유지하고, 사용자가 받는 보고서는 `report/`에 별도로 발행한다.

## 장애가 분석에 미치는 범위

- v2 Semgrep 기본값은 `best-effort`다. 도구 미설치/실패를 분석 공백으로 기록하고 소스 분석을 계속한다.
  호출자가 `required`를 명시해도 독립 분석은 진행하되, 검사 실패는 범위 미완료로 표시하며 SDK는 `incomplete`를 반환한다. v1의 기존 필수 검사 흐름은 유지한다.
- 일부 분석 단위의 실패는 기존처럼 격리한다. root 단계의 provider 오류도 한 번 더 시도한다.
  선택적 cross-unit 후속 분석 실패는 공백으로 남기고 review/evaluate/report를 계속한다.
- 필수 단계가 계속 실패하면 정상 완료를 가장하지 않고 `publicationStatus: 'partial'`과 부분 보고서를
  반환한다. API `status`는 `incomplete`다. 같은 engagement에서 재개할 수 있다.
- 외부 artifact store는 복제 대상이다. 로컬 객체와 전송 의도를 먼저 저장하며 외부 쓰기 실패/3초 초과는
  `storage.pendingReplication`과 `storage.errors`에 나타난다. 동일 실행에서 연속 실패를 반복 호출하지 않는다.
  전송 누락이 분석 세션 실패로 바뀌지 않는다. `ResilientArtifactStore.flush()`가 대기 자료를 재전송한다.
- 상태 이벤트는 fsync한 write-ahead batch를 남긴 후 JSONL에 추가한다. JSONL 쓰기가 실패해도 batch가
  남으면 다음 이벤트를 보존할 수 있다. snapshot은 재생 가능한 투영이므로 쓰기 실패만으로 단계를 실패시키지 않는다.
- JSONL의 잘린 마지막 행은 원본을 `.recovery/`에 보존하고 검증 가능한 앞부분과 pending batch에서 복구한다.
  완성된 중간 행의 손상, 체크섬 충돌, 권한·근거·lease 위반은 정상 데이터로 간주하지 않는다.
- host 로그 쓰기 실패는 별도 복구 로그로 보존하고 상태에 경고한다. 양쪽 모두 실패한 이벤트 수를 노출한다.

모든 로컬 저장 경로가 쓰기 불가능한 상태, 프로세스 강제 종료, 사용자의 취소까지 실행을 계속한다고
보장하지 않는다. 재시도는 유한하며 예산·취소·근거 무결성·공유 DB 소유권 검증은 유지한다.
PostgreSQL 접근 장애는 기존 lease를 우회해 다른 저장소에 성공 상태를 임의 확정하지 않는다.

## SDK에서 재개

```ts
const agent = createOffsecAgent({ apiKey, /* 선택: runtime: { artifactStore } */ });
const result = await agent.run({ target: '/absolute/repository' });
// 상태 저장소/분석 서비스가 회복된 뒤:
const resumed = await agent.resume(result.engagementDir);
```

CLI: `pnpm assess:v2 -- /absolute/repository --engagement-dir=/absolute/run/engagement --resume`.

새 v2 실행은 checkpoint와 준비 산출물의 해시를 검증하고, 완료된 phase outcome을 상태에 보존한다.
재개는 완료 단위를 다시 모델에 요청하지 않는다. 프로세스 종료 시 열린 attempt는 중단으로 기록하고
미완료 작업만 새 attempt에서 실행한다. 검토 단계가 시작된 뒤에는 그 단계가 소비한 분석 범위와
격리 결과를 유지한다. 이미 발행된 부분 보고서의 미검토 파일을 추가 분석하려면 새 실행을 만든다.
변경된 소스·계약·근거는 기존 실행에 몰래 덮어쓰지 않는다. 구형 실행의 완료 outcome이 없으면
자동 재개를 거부하고 기존 증거를 보존한다.

SDK 대화 기록은 `persistSession: false`로 명시했다. 복구는 호스트 checkpoint를 사용한다.
이 설정은 이전에 이미 생성된 SDK 기록을 삭제하지 않는다.

## 보고서 발행과 상태 복구

초안을 final로 이동하지 않고 별도로 복사하므로 완료 이벤트의 draft 참조가 유효하다.
발행 의도를 기록하고, 검증된 파일을 발행한 다음 `publication.completed`, `run.completed`,
관련 outbox를 같은 상태 batch에 기록한다. 파일시스템과 DB가 하나의 트랜잭션인 것은 아니다.
파일 발행 뒤 상태 쓰기가 실패하면 v2 재개가 완료 phase를 재사용해 남은 발행 절차를 수행한다.
기존 final이 draft와 host가 생성한 범위 안내 부록을 합친 예상 내용과 다르면 임의 덮어쓰지
않는다. 파일의 존재만으로 성공을 추정하지 않는다.

## 실행 단위 백업과 복원

v2의 성공/실패 종료 경계에서 phase 선언 목록뿐 아니라 manifest·AST·coverage·checkpoint·finding·
원장·복구 자료 전체를 `run-archive.json`에 등록한다. 외부 배치의 `run.json`과 `report/`도 포함한다.
내부 객체 캐시 자체와 복제 큐는 중복 백업하지 않는다. 실제 자료와 URI·hash·bytes를 등록한다.
각 객체와 manifest는 로컬 불변 저장소에 보관하고 선택적 외부 저장소로 복제한다.
실행 중 강제 종료에는 종료 시점의 묶음 생성이 보장되지 않으므로 로컬 원장/batch에서 먼저 재개한다.

`archiveRun()`은 쓰기가 끝난 경계에서 호출한다. 외부 복제 완료 여부는 별도로 확인한다.
`restoreRunArchive({ uri, store, destination })`는 빈 목적지에 hash 검증 후 복원한다. 기본 배치의
목적지는 `<run-root>/engagement`이며 metadata와 보고서도 함께 복원한다. 다른 위치에도 원본 바이트를
복원할 수 있지만 실행 기록의 절대경로는 변경하지 않는다. 이어 실행할 목적이면 **원래 절대경로**에
복원해야 한다. 타겟 소스와 실행 계약도 해당 시점의 버전이 필요하다. 전체 타겟 소스 복제나 외부
PostgreSQL DB 자체의 백업, 실제 LLM 응답의 재생성까지 이 묶음이 보장하는 것은 아니다.

## 권한과 잠금

관리 디렉터리는 소유권을 확인하고 `0700`, 생성/보관 파일은 `0600`으로 관리한다. 파일 접근은
심볼릭 링크를 거부하며 읽기에는 no-follow를 사용한다. 공유 상위 디렉터리를 임의로 chmod하지 않는다.
실행 lock은 현재 호스트·PID·프로세스 시작 정보와 파일 identity를 확인한다. 죽은 로컬 소유자의 lock만
자동 회수하며, 살아 있는 소유자나 다른 호스트/구형 정보가 불명확한 lock은 임의로 제거하지 않는다.
검사 후 경로를 교체할 수 있는 신뢰하지 않는 프로세스와 같은 UID/쓰기 권한을 공유하는 저장소는 지원하지 않는다.

## 재개 경계 보강 (2026-09)

- 예산을 지정한 v2 실행은 provider 호출 전에 `budget.reserved`, 사용액을 받은 뒤
  `budget.settled`를 같은 run 원장에 남긴다. 재개 시 이미 지출했거나 아직 정산되지 않은
  금액을 동시에 배정하지 않는다. 사용액을 확인할 수 없는 호출은 예약액을 보수적으로 유지한다.
  구형 실행의 배정액도 확인 불가능하면 남은 예산을 재사용하지 않는다. 예산 소진은 신규 모델
  호출을 중단하고 부분 보고서를 반환하며, 원장에 실제 수신 비용과 예약 금액을 구분해 남긴다.
- `analysis.checkpoint`는 기본 unit 결과를 저장한 `units`와 검토 입력을 확정한 `review` 경계를
  구분한다. 후속 분석의 started 기록만으로 coverage가 이미 존재한다고 판단하지 않는다.
  coverage·scope assurance·unit 결과·followup plan은 불변 로컬 객체로 보존한 후 원장에 hash를
  연결한다. 누락되거나 바뀐 projection은 이 원본에서 복구하고 손상본은 `.recovery/`에 남긴다.
  원본까지 손상되면 complete로 승격하지 않고 진단이 포함된 부분 보고서를 반환한다.
- 완료된 구형 실행은 mutable coverage JSON 대신 검증된 원장·준비 입력으로 실행 범위를
  재구성한다. 구형 입력에서 입증할 수 없는 읽기/질문 수는 `unavailableLegacyCounts`로 알린다.
  아직 검토 중인 구형 실행에 봉인된 검토 입력이 없으면 기존 결과를 보존한 partial로 반환한다.
  새 이벤트 형식을 사용한 실행의 재개에는 이 형식을 지원하는 런타임이 필요하다.
- `maximumWorkUnits`는 v2 미션의 한 번에 스케줄링할 작업 창 크기로 사용한다. 전체 inventory는
  자르지 않고 다음 창을 계속 처리한다. concurrency와 사용자가 지정한 예산 제한은 유지한다.
- 읽기 실패 파일/디렉터리는 source manifest의 `source_errors`에 보존한다. 읽을 수 있는 소스만
  unit에 배정하고 미분석 경로는 coverage에 남긴다. 읽기 실패한 입력을 고친 뒤 범위를 확장하려면
  새 실행을 만든다. 기존 봉인 입력에 변경된 소스를 조용히 섞지 않는다.
- 일부 unit이 timeout되어도 독립 unit의 검토·발행을 계속할 수 있도록 열린 attempt를 닫는다.
  늦게 반환된 결과는 종료된 attempt를 완료로 바꾸지 못한다. timeout된 provider의 미정산 예산은
  다시 사용하지 않는다. provider가 취소를 무시하면 그 attempt 디렉터리에 늦은 파일이 생길 수
  있지만 완료 근거로 채택하지 않는다.
- 보고서 모델이 정확한 문구를 누락해도 host가 최종본에 범위 제한과 미검토 경로를 붙인다.
  초안은 수정하지 않으며 최종본의 hash에는 이 부록이 포함된다. phase 출력 검증이 유한한
  재시도 후에도 실패하면 부분 보고서를 보존하고 미완료 단계부터 재개한다. 부분 보고서는
  보존된 finding 관측도 포함하며 새로운 검증 판정으로 취급하지 않는다.
- 복제 큐의 JSON·receipt·본문 누락/hash 손상은 해당 항목을 `.invalid`로 격리하고 나머지를
  전송한다. 원격 서비스 자체가 불가용하면 배치를 중단하고 다음 flush를 기다린다. 격리된
  필수 객체가 있는 archive는 원격에서 완전히 복원할 수 있다고 간주해서는 안 된다.
- 하나의 PostgreSQL mission은 phase·예산·checkpoint 이벤트 writer를 공유해 순서를 정한다.
  버전 확인은 이전 쓰기가 끝난 뒤 수행하며 DB의 fencing/lease 검증을 우회하지 않는다.

회귀 검증은 `analysis-resumption.test.ts`, `budgeted-runtime.test.ts`,
`v2-publication.test.ts`, `postgres-run-state.integration.test.ts`에 있다.
실제 모델/운영 데이터 없이 강제 종료, 병렬 재개, 손상 projection, 129-unit 실행, 읽기 실패,
큐 본문 손상, PostgreSQL 동시 이벤트 저장을 재현한다.

## 예산 제한과 재개 시 증액

기본 v1/v2 계약의 `limits.maxBudgetUsd`는 `null`이므로 금액 상한이 없다. SDK도 예산을
지정하지 않으면 provider에 `maxBudgetUsd`를 전달하지 않는다. `--max-usd` 또는
`maxBudgetUsd`를 지정한 실행에만 유한한 금액 상한을 적용한다.

```sh
# 신규 실행: 기본 금액 상한 없음
pnpm assess:v2 -- /absolute/repository
# 기존 미완료 실행: 금액 상한 해제
pnpm assess:v2 -- /absolute/repository --engagement-dir=/absolute/run/engagement --resume --no-cost-guard
# 기존 미완료 실행: 필요한 경우 특정 금액으로 증액
pnpm assess:v2 -- /absolute/repository --engagement-dir=/absolute/run/engagement --resume --max-usd=1000
```

SDK는 `agent.resume(directory, { noCostGuard: true })` 또는 `{ maxBudgetUsd: 1000 }`을
사용한다. 새 상한은 `run.budget-increased` 이벤트로 남고 이후 재개에도 유지된다.
사용액·미정산 예약액·기존 checkpoint는 지우거나 수정하지 않는다. 이 옵션은 기존 유한
상한의 증액/해제를 위한 것으로 완료된 실행을 다시 분석하지 않는다. 분석 범위가 이미
검토 입력으로 확정된 경우 예산 변경만으로 제외된 단위를 다시 추가하지 않는다.

금액 무제한은 provider 계정의 결제/호출 제한을 변경하지 않는다. 세션 기본 120턴,
후속 분석 최대 32턴, unit 15분 timeout과 유한한 오류 재시도는 별도의 실행 제한이다.
