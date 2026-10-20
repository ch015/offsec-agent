# 결과 기록 감사와 수동 검토

기존 결과의 무결성, 이견 이력, 보완 답변과 범위 판정의 차이를 확인하는 관리 도구입니다. 모델·Scanner·Analyzer·Reviewer를 호출하거나 새 진단을 시작하지 않습니다. 기존 실행 제어는 `run:admin`, 이 문서의 결과 조회와 주석 관리는 `results:admin`이 담당합니다.

## 구현 범위

| 개선 항목 | 현재 상태 | 남은 범위 |
| --- | --- | --- |
| 기존 기능 지도·변경 영향 검토·회귀 검사 | 구현 | 기능 변경마다 지도 갱신 |
| Finding 충돌과 수정 이력, 재개 | 기존 구현 유지·회귀 검증 | 모든 충돌을 새 ID로 숨기거나 자동 병합하지 않음 |
| 수동 이견·해소 기록 | 구현 | 자동 의미 판정이나 검토자 간 자동 중재는 미구현 |
| 수동 이력 PostgreSQL 저장·파일 이력 이전 | 구현 | 원본 산출물은 로컬에 보존하며 파일/DB 이력을 자동 병합하지 않음 |
| 사람의 검토 계약·회신·피드백·통합 현황 | 구현 | 명시한 파일의 묶음 생성과 이력 관리; 에이전트 실행·자동 판정은 미구현 |
| 보완 전후 범위·답변 대조 | 읽기 전용 감사 구현 | 개별 미확인 검사와 보완 근거의 명시적 대응 및 정식 판정 갱신은 미구현 |
| 원장·분류·발행 자료의 일관성 조회 | 구현 | 자연어 서술의 의미적 정확성은 별도 검토 |
| 정답 비교 품질 계산 | 입력 JSON을 받는 오프라인 CLI 구현 | 정답·조건·원문 타당성은 입력 작성자가 검증해야 함 |
| PostgreSQL 설정·공유 지식·CVE 원문/버전·상태 복구 | 기존 구현·통합 테스트 검증 | 자동 CVE 수집, 벡터 검색, 모든 MD 제거는 구현 범위 아님 |
| 독립 검토 병렬화·에이전트 자동 재지시 | 미구현 | 이번 작업에서 제외 |

이 표의 부분 구현을 전체 오케스트레이션 개선 완료로 해석하지 않습니다. 공유 지식과 CVE 정보는 참고 자료이고, 위 명령은 이를 근거로 새로운 취약점 판정을 만들지 않습니다.

## 읽기 전용 감사

```sh
pnpm results:admin inspect --engagement=/absolute/run/engagement
pnpm results:admin inspect --engagement=/absolute/run/engagement --format=markdown --output=/absolute/run/result-audit.md
```

JSON에는 실행 ID, 원본 manifest **파일 바이트 해시**, 분석 revision, 이전/최종 미확인 파일·검사 수, revision별 질문/답변, 판정별 기록 수, 독립 원인 수, 수동 이견과 입력 파일 해시가 포함됩니다. `publicationVerified`는 기존 발행 영수증과 바이트·출처·Finding ID 포함 여부를 대조한 결과이며, 진단 정확도나 전체 범위 완료를 뜻하지 않습니다. JSON manifest의 `hash` 필드와 파일 바이트 해시는 서로 다른 값입니다.

`resolved` 답변은 해당 질문에 답했다는 기록입니다. 다른 미확인 검사를 해결하거나 파일 전체를 검토했다고 추정하지 않습니다. 기존 coverage를 고치지 않으며, 이전/최종 값과 남은 항목을 나란히 보여줍니다. 과거의 새 revision이 없는 질문에 이전 답변을 재사용하지 않습니다. 봉인 영수증이 없거나 원문과 다르면 답변을 `unverified`로 표시합니다.

감사 도중 관측한 로컬 입력이 바뀌면 다시 조회하도록 실패합니다. 손상된 기록을 자동 복구하지 않습니다. 파일 모드는 `run-events.jsonl`, DB 모드는 PostgreSQL 이벤트 원장을 사용하며 두 모드 모두 로컬 산출물이 필요합니다. 원래 절대 경로를 바꾼 백업 복사본의 감사는 지원하지 않습니다.

내보내기는 engagement **밖의 새 파일**만 허용하며 기존 파일을 덮어쓰지 않습니다. 출력 없이 조회하면 원장·보고서·checkpoint를 수정하지 않습니다.

종료 코드는 0=감사 문제 없음 및 기록상 범위 완료, 2=검사 문제 또는 기록상 범위 미완료, 1=입력/형식/동시 변경 오류입니다. 0도 보안상 안전하다는 보증은 아닙니다.

## 수동 이견 기록

먼저 감사 JSON의 `notes.head`와 `references`를 확인합니다. 아래 입력에서 `F-...`와 파일 경로·해시는 실제 감사 값으로 교체합니다. 관련 Finding의 `standard-findings/*.json` 버전을 모두 포함해야 합니다.

```json
{
  "id": "D-001",
  "kind": "dispute",
  "author": "human-reviewer",
  "findingIds": ["F-0123456789ab"],
  "assertions": [
    "첫 번째 해석과 이를 뒷받침하는 조건을 구체적으로 기재합니다.",
    "상충하는 두 번째 해석과 확인되지 않은 조건을 구체적으로 기재합니다."
  ],
  "rationale": "왜 추가적인 사람이 검토해야 하는지와 남은 불확실성을 기재합니다.",
  "references": [
    {"path": "standard-findings/<record-hash>.json", "sha256": "<64자리 실제 파일 해시>"},
    {"path": "03_review_result.json", "sha256": "<64자리 실제 파일 해시>"}
  ]
}
```

```sh
pnpm results:admin note --engagement=/absolute/run/engagement --input=/absolute/dispute.json --expected-head=empty
```

첫 기록 이후 `--expected-head`에는 최신 `notes.head`를 전달합니다. 같은 ID·같은 내용의 재전달은 멱등 처리하고, 같은 ID·다른 내용은 거부합니다. 오래된 head로 새 기록을 덮어쓰지 못합니다. 기존 run 잠금을 재사용합니다. 파일 모드는 `review-notes/history.json`을 원자적으로 저장하고, DB 모드는 트랜잭션과 이력 행 잠금으로 head를 확인한 뒤 새 항목을 추가합니다.

해소 기록은 `kind: "resolution"`, 새로운 `id`, `disputeId`, `author`, `outcome: "resolved" | "unresolved"`, `rationale`, `references`를 사용합니다. 현재 Finding 버전과 현재 근거를 다시 인용해야 합니다. 새 해소 기록이 이전 이견과 해소 이력을 삭제하지 않습니다. 인용 파일이 바뀌면 최신 판정을 `stale`로 표시하며, 사람이 현재 버전에 대해 새 해소 기록을 남길 수 있습니다.

이 기록의 작성자 이름은 입력값이며 인증된 서명이 아닙니다. 해시 연결은 내부 일관성 검사이고 외부에서 신뢰한 head 없이 마지막 항목 삭제까지 증명할 수는 없습니다. DB 관리자에 의한 head와 이력의 동시 변경도 방어하지 않습니다. `resolved`는 사람이 적은 주석 상태일 뿐, canonical Finding·범위·기존 보고서를 고치거나 재발행하지 않습니다. DB 주석은 전용 결과 테이블에 저장하며 모델용 지식 테이블에 자동 노출하지 않습니다.

## PostgreSQL 결과 저장과 기존 이력 이전

기존 `database` 연결 설정을 재사용하며, `results.backend`로 수동 주석의 저장소를 선택합니다. 설정 파일 선택 순서는 `--config=<파일>`, `NUNCHI_CONFIG`, 현재 디렉터리의 `nunchi.config.json`입니다. 기존 설정에 `results`가 없으면 `file`입니다. 비밀번호는 `passwordEnv` 또는 `connectionStringEnv`로 참조하며 설정값을 결과 JSON에 넣지 않습니다.

```json
{
  "version": 1,
  "database": { "connectionStringEnv": "RESULTS_DATABASE_URL" },
  "results": { "backend": "postgres" },
  "runtime": { "backend": "file" }
}
```

`runtime.backend`는 이벤트 원장의 기본 위치입니다. 과거 실행의 위치가 현재 설정과 다르면 `--state-backend=file|postgres`로 명시합니다. DB 이벤트 조회에는 `--run-id`와 `results.backend=postgres`가 필요합니다. 요청한 run의 봉인된 manifest 파일 경로·해시가 현재 engagement와 일치해야 하며, 이벤트는 기존 replay 계약으로 검증합니다. `run-state.json`만 신뢰하거나 로컬 이벤트로 자동 대체하지 않습니다.

```sh
pnpm db:migrate --config ./nunchi.config.json
# 기존 파일 이력이 있으면 먼저 명시적으로 이전합니다. 빈 이력도 등록할 수 있습니다.
pnpm results:admin notes-import --engagement=/absolute/run/engagement --config=./nunchi.config.json --state-backend=file
pnpm results:admin inspect --engagement=/absolute/run/engagement --config=./nunchi.config.json --state-backend=file
pnpm results:admin note --engagement=/absolute/run/engagement --config=./nunchi.config.json --state-backend=file --input=/absolute/dispute.json --expected-head=<latest-head>
# 이벤트까지 PostgreSQL에 있는 실행: 로컬 run-events.jsonl 없이 조회
pnpm results:admin inspect --engagement=/absolute/run/engagement --config=./nunchi.config.json --state-backend=postgres --run-id=<existing-run-id>
```

`notes-import`는 기존 항목의 ID·시간·해시 연결을 그대로 옮기고 원본 파일 바이트를 유지합니다. 반복 이전은 멱등 처리합니다. DB에 더 최신 기록이 있으면 파일 이력이 DB 이력의 정확한 앞부분인지 확인합니다. 갈라진 두 이력은 거부하며 어느 쪽도 덮어쓰지 않습니다. 오래된 근거를 포함한 이력도 보존하고, 감사 시 `stale`로 드러냅니다. `note`/`inspect`가 파일 이력을 자동으로 이전하지는 않습니다.

첫 DB 저장/이전 시 `review-notes/backend.json`에 DB catalog·run·manifest 식별자를 기록합니다. 이후 파일 모드와 다른 catalog의 DB는 거부합니다. 이 파일과 원본 이력은 삭제하지 마세요. DB 연결 실패 시 파일로 대체하지 않습니다. DB를 새로 만들 경우 원본 catalog와 이력도 복원해야 합니다.

로컬 파일과 DB는 하나의 분산 트랜잭션이 아닙니다. 저장소 식별자를 먼저 기록하고 DB를 커밋하므로 중간 장애 시 식별자만 남을 수 있습니다. 이때 원래 `notes-import` 또는 같은 ID·입력·expected-head의 `note`를 재시도합니다. 커밋은 됐지만 응답을 잃은 경우에도 같은 ID·내용의 재시도로 중복 없이 현재 head를 돌려받습니다. 원래 작업 내용을 잃었거나 DB 자체가 유실됐다면 백업에서 복원해야 합니다.

DB 감사는 `REPEATABLE READ READ ONLY` 트랜잭션 시점의 이벤트와 주석을 읽습니다. 조회 중 다른 트랜잭션이 커밋한 기록은 다음 감사에서 보입니다. JSON의 `storage`에는 DB catalog, 주석 head, 이벤트 순번·해시가 포함됩니다. 조회는 잠금 파일·lease·주석·실행 상태를 생성하거나 수정하지 않습니다. DB 모드에서도 보고서, Finding 원본, 근거 파일을 공유 engagement 경로에 보존해야 합니다.

## 사람이 관리하는 검토 계약과 회신

명시한 파일을 개수 기준으로 묶고 담당자를 표기한 계약 초안을 만들 수 있습니다. 이 기능은 원장을 통한 사람의 작업 관리입니다. 파일을 자동 탐색하거나 담당자에게 메시지를 보내거나 에이전트를 실행하지 않습니다. 실제 소스 읽기나 취약점 판정의 근거는 기존 실행 영수증과 별도로 관리합니다.

`review-plan` 입력 예시입니다. 파일 경로는 engagement 기준 상대 경로이며, SHA-256은 감사 JSON의 `references` 등에서 확인한 실제 값으로 바꿉니다. 지시사항은 입력한 문장을 그대로 보존합니다.

```json
{
  "idPrefix": "DOC",
  "author": "coordinator",
  "assignees": ["reader-a", "reader-b"],
  "maxFilesPerAssignment": 10,
  "instructions": "지정된 문서의 서술과 근거가 일치하는지 검토하고 확인하지 못한 항목을 기재합니다.",
  "rationale": "사람이 선택한 문서의 검토 담당과 미응답 항목을 누락 없이 관리합니다.",
  "files": [
    {"path": "review-material/part1.md", "sha256": "<실제 파일 해시>"},
    {"path": "review-material/part2.md", "sha256": "<실제 파일 해시>"}
  ]
}
```

```sh
# 순수 초안 생성: 입력한 파일만 정렬·분할하고 담당자 표기를 순환 배치합니다.
pnpm results:admin review-plan --input=/absolute/plan-input.json --output=/absolute/plan.json
# 검토한 초안을 모든 묶음이 함께 저장되도록 등록합니다.
pnpm results:admin note-batch --engagement=/absolute/run/engagement --config=./nunchi.config.json --input=/absolute/plan.json --expected-head=<latest-head>
pnpm results:admin inspect --engagement=/absolute/run/engagement --config=./nunchi.config.json
```

설정이 파일 모드이면 파일에, `results.backend=postgres`이면 기존 PostgreSQL 주석 원장에 저장합니다. DB 이벤트를 사용하는 실행은 앞 절의 `--state-backend=postgres --run-id=...`도 전달합니다. 새 DB 테이블이나 별도 작업 큐는 추가하지 않습니다.

초안은 `{ "schemaVersion": 1, "assignments": [...] }` 형식이며 각 항목은 `review-assignment` 주석입니다. 파일당 한 번만 배치하고 마지막 남은 묶음도 포함합니다. 한 묶음은 최대 50개 파일, 한 번의 등록은 최대 500개 묶음입니다. 초안 생성은 파일 존재나 해시의 진위를 확인하지 않으며, 등록 시 현재 파일과 대조합니다. 임의로 만든 두 계약의 겹치는 파일은 허용하므로 명시적 중복 검토도 가능합니다. 기본 분할 초안에는 겹침이 없습니다.

`note-batch`는 ID·해시·현재 head를 모두 확인한 뒤 파일을 한 번 저장하거나 DB 트랜잭션을 한 번 커밋합니다. 뒤쪽 항목이 실패해도 앞쪽 항목만 남지 않습니다. 같은 배치 재전달은 이미 저장된 항목을 재사용하며, 일부만 기존 항목인 배치에 새 항목을 추가하려면 최신 head가 필요합니다. 초안만 만들고 등록하지 않은 작업은 현황에 포함되지 않습니다.

등록 이후의 절차는 다음과 같습니다.

1. `inspect`의 `notes.manualReviews.assignments`에서 작업 계약과 `latestRequest`를 확인합니다.
2. 담당자는 `review-response`를 `note` 명령으로 저장합니다. 배정된 파일을 각각 정확히 한 번 열거하고 `completed`, `needs-information`, `not-reviewed` 중 하나와 사유를 기재합니다. 회신의 `assignment`와 `replyTo`는 주석 ID 및 **주석 항목 해시**입니다. 파일 해시나 전체 원장의 head와 혼동하지 않습니다.
3. 요청자는 `review-feedback`에 `accept` 또는 `request-changes`를 명시합니다. `response`에는 가장 최근 회신의 ID·해시를 넣습니다. 수정 요청 이후 새 회신의 `replyTo`는 해당 피드백 항목을 가리켜야 합니다.
4. `accept`는 모든 파일이 `completed`로 회신되고 회신에 인용된 모든 근거 버전이 현재와 일치할 때만 기록할 수 있습니다. `request-changes`는 이미 수락한 회신도 명시적으로 다시 검토 요청할 수 있습니다. 과거 회신·피드백은 삭제하지 않습니다.

회신 예시입니다. `references`에는 계약의 모든 파일 버전을 포함하며 추가 근거도 인용할 수 있습니다.

```json
{
  "id": "REPLY-001", "kind": "review-response", "author": "reader-a",
  "assignment": {"id": "DOC-0001", "sha256": "<계약 항목 해시>"},
  "replyTo": {"id": "DOC-0001", "sha256": "<최초 계약 또는 최신 수정 요청의 항목 해시>"},
  "rationale": "담당자가 확인한 파일과 남은 불확실성을 구분하여 회신합니다.",
  "references": [{"path": "review-material/part1.md", "sha256": "<파일 해시>"}],
  "results": [
    {"path": "review-material/part1.md", "status": "needs-information", "reason": "문서의 서술을 확인할 추가 근거가 필요하여 미확인 상태로 남깁니다."}
  ]
}
```

위 예시는 파일 한 개를 배정한 계약에 대한 회신입니다. 실제 계약의 모든 파일을 열거해야 합니다. 피드백은 공통 `id`, `kind: "review-feedback"`, `author`, `rationale`, `references`에 `assignment`, `response`, `action`을 추가합니다. 회신 작성자 표기는 계약의 `assignee`, 피드백 작성자 표기는 계약의 `author`와 일치해야 합니다. 이 검사는 표기 일치이며 로그인·서명 기반 인증은 아닙니다.

파일 버전이 바뀌면 기존 계약은 `stale`로 표시합니다. 계약 범위를 새 버전으로 덮어쓸 수 없습니다. 요청자는 `action: "cancel"` 피드백으로 이전 계약을 명시적으로 닫고 새 ID의 계약을 등록할 수 있습니다. 취소는 `response`를 생략하며 현재 유효한 근거와 사유를 인용합니다. 취소된 계약의 회신·수락 이력과 변경된 근거 정보도 보존합니다.

통합 JSON과 Markdown에는 `awaiting-response`, `response-received`, `changes-requested`, `accepted`, `cancelled`, `stale` 상태, 담당자, 파일별 회신 상태, 최신 요청/회신, 전체 이력이 포함됩니다. `reportedStatus`는 마지막 회신 내용이므로 수정 요청 중에도 과거 값을 보존합니다. 현재 종결 여부는 작업의 `status`로 확인합니다. 회신이 없으면 파일 상태는 `null`/`미회신`입니다. 미종결 작업은 감사 문제로 표시하고, 취소는 수락으로 세지 않습니다. `allAccepted`는 미등록 시 `null`, 취소가 있으면 `false`입니다.

모든 작업이 수락돼도 기존 진단의 coverage, 미확인 검사, Finding 판정, 독립 원인 수 또는 발행 보고서는 바뀌지 않습니다. 담당자가 실제로 파일을 읽었다는 사실이나 진단 정확도를 이 주석만으로 입증하지 않습니다. 기존 `dispute`/`resolution` 이력의 형식·해시는 그대로 읽으며, 새 주석 종류를 저장한 뒤에는 이 종류를 지원하지 않는 구버전 프로그램으로 원장을 읽을 수 없습니다.

### 담당자·파일별 현황과 회신 양식

전체 결과 감사를 실행하지 않고 등록된 수동 검토 계약을 조회할 수 있습니다. 파일 모드와 PostgreSQL 모드가 같은 투영을 사용하며 기존 `--config`, `--state-backend`, `--run-id` 옵션을 재사용합니다.

```sh
pnpm results:admin review-status --engagement=/absolute/run/engagement --config=./nunchi.config.json
pnpm results:admin review-status --engagement=/absolute/run/engagement --config=./nunchi.config.json --assignee=reader-a --format=markdown --output=/absolute/review-status.md
pnpm results:admin review-response-template --engagement=/absolute/run/engagement --config=./nunchi.config.json --assignment=DOC-0001 --note-id=REPLY-002 --output=/absolute/response-packet.json
```

`review-status` JSON에는 `global`(전체), `selected`(필터 적용), `byAssignee`, `byFile`, `assignments`, 원장 `head`와 run/manifest 식별자가 포함됩니다. 담당자 필터는 정확한 표기 일치로 적용하며 접근 권한 통제가 아닙니다. 필터에 맞는 계약이 없어도 전체 수치를 유지하고 선택 범위의 `allAccepted`를 `null`로 표시합니다. 조회 성공은 미종결 여부와 관계없이 종료 코드 0입니다. 입력·저장소 오류는 1이며, 이 명령은 진단 품질 gate가 아닙니다.

`fileCount`는 서로 다른 경로 수, `fileVersionCount`는 경로·해시 조합 수, `fileObligationCount`는 전체 파일 배정 수입니다. 같은 버전을 두 담당자가 검토해도 두 배정을 보존하고 한 담당자의 수락으로 다른 담당자의 미회신을 지우지 않습니다. 변경 전후 버전도 별도 행으로 표시합니다. 취소는 미종결 수에서 제외하지만 수락으로 세지 않습니다.

`awaitingCurrentResponse`와 해당 집계는 현재 요청이 아직 답변되지 않았음을 나타냅니다. 보완 요청 중에도 `reportedStatus`에는 마지막 회신의 과거 값이 남으며, `completed`였다는 이유로 현재 작업을 수락 상태로 바꾸지 않습니다. 근거가 변경된 미회신 계약은 `stale`과 미회신을 함께 표시하므로 현재 상태도 확인해야 합니다. 계약·현재 요청·최신 회신/피드백의 근거 변경을 표시하며, 현재 요청의 추가 근거는 이후 회신·수락이 생겨도 변경 검사를 유지합니다. 현황은 등록된 계약만 다룹니다. 미등록 파일의 누락이나 실제 진단 범위 완전성은 판단하지 않습니다.

회신 양식은 저장 가능한 주석을 포함한 **편집용 봉투**입니다. `note` 외에 `identity`, `expectedHead`, 원래 지시사항, 최신 `request`, 과거 `previousResponse`를 포함합니다. 출력만으로 ID를 예약하거나 주석을 등록하지 않습니다. 모든 새 파일 결과는 `not-reviewed`로 시작하고, 과거 완료 회신은 참고 맥락으로만 포함합니다. 작성자가 `note.rationale` 및 각 파일의 상태·사유를 직접 편집한 후 다음처럼 제출합니다.

```sh
# response-packet.json의 note를 사람이 편집한 다음 별도 입력 파일로 추출합니다.
jq '.note' /absolute/response-packet.json > /absolute/reply.json
pnpm results:admin note --engagement=/absolute/run/engagement --config=./nunchi.config.json --input=/absolute/reply.json --expected-head="$(jq -r '.expectedHead' /absolute/response-packet.json)"
```

봉투 전체를 `note --input`에 전달하면 거부합니다. 미편집 양식을 명시적으로 제출해도 모든 파일이 미검토로 기록되어 수락할 수 없습니다. 다른 기록이 추가돼 head가 바뀌면 최신 현황을 확인하고 양식을 다시 내보냅니다. head만 바꿔도 이전 요청에 대한 회신은 최신 요청 검사를 통과할 수 없습니다.

미회신 상태의 최신 요청에 대해서만 양식을 만듭니다. 이미 회신·수락·취소된 계약, 사용 중인 주석 ID, 변경된 계약 또는 현재 요청의 근거는 거부합니다. 이전 회신의 추가 근거만 바뀐 경우에는 사람이 새 요청을 기록한 뒤 새 회신을 작성할 수 있으며, 과거 근거를 새 회신에 자동 복사하지 않습니다. 계약 파일 자체가 바뀌면 기존 계약 취소와 새 버전 계약 등록 절차를 사용합니다.

두 명령은 주석·이벤트·Finding·발행 보고서를 수정하지 않습니다. 출력 파일은 engagement 밖의 새 경로만 허용합니다. DB 조회/양식은 동일한 읽기 전용 트랜잭션 스냅샷과 저장소 결합 검사를 사용하고, 커밋된 후속 변경은 다음 조회에서 보입니다. 양식 생성 후의 경쟁 쓰기는 실제 `note` 저장 시 CAS와 최신 요청 검사가 처리합니다. 별도 테이블이나 migration은 필요하지 않습니다.

## 제출 기록 수집과 사람/무인 모드

`review-collect`는 이미 작성된 JSON 기록을 읽어 검사하는 별도 관리 명령입니다. `review-response`와 아래의 `review-opinion`만 받습니다. 모델 호출, 에이전트 생성, 자동 중재·재지시를 실행하지 않습니다. 수집은 읽기 전용이며, 검증된 입력도 주석 원장에 자동 등록하지 않습니다.

```sh
pnpm results:admin review-collect --engagement=/absolute/run/engagement --config=./nunchi.config.json --input=/absolute/submissions/manifest.json --mode=human --concurrency=4 --output=/absolute/collection-human.json
# 사람이 없는 환경에서도 질문이나 입력 대기 없이 결과를 생성합니다.
pnpm results:admin review-collect --engagement=/absolute/run/engagement --config=./nunchi.config.json --input=/absolute/submissions/manifest.json --mode=unattended --concurrency=4 --output=/absolute/collection-unattended.json
pnpm results:admin review-conflicts --engagement=/absolute/run/engagement --config=./nunchi.config.json --mode=unattended --output=/absolute/pending-decisions.json
```

두 모드는 같은 검증·미해결 판정을 사용합니다. `human`은 `decisionRouting: human-review`, `unattended`는 `decisionRouting: deferred`로 후속 판단의 처리를 표시합니다. 무인 모드가 사람의 선택을 대행하거나 기존 이력을 보류 기록으로 덮어쓰지는 않습니다. 기존에 유효하게 기록된 사람의 중재는 계속 표시하고, 새 입력·상충·불확실성은 그대로 남깁니다.

수집 명세 예시입니다. `identity`와 `expectedHead`는 최신 조회 결과에서 가져옵니다. `submissions.path`는 **이 명세 파일의 디렉터리 기준 상대 경로**, `sha256`은 **제출 JSON 파일의 원래 바이트 해시**입니다. 의견이 참조하는 engagement 내부 근거 파일의 해시와 구별합니다.

```json
{
  "schemaVersion": 1,
  "identity": {"runId": "<실제 run ID>", "sourceManifestFileSha256": "<manifest 파일 해시>"},
  "expectedHead": "<최신 주석 head 또는 empty>",
  "submissions": [
    {"path": "reader-a.json", "sha256": "<제출 JSON 바이트 해시>"},
    {"path": "reader-b.json", "sha256": "<제출 JSON 바이트 해시>"}
  ]
}
```

동시성은 기본 4, 최대 16이며 **파일 I/O를 제한된 동시성으로 처리**합니다. JSON 구조 검사와 해시는 같은 프로세스에서 수행하며, CPU 병렬화나 LLM 병렬 검토를 뜻하지 않습니다. 한 명세는 최대 128개 제출 파일, 각 파일과 명세 자체는 최대 1 MiB입니다. 상대 경로 이탈·심볼릭 링크·일반 파일이 아닌 입력은 거부합니다. 큰 묶음은 명세를 명시적으로 나눕니다. 오류가 있어도 다른 제출 파일을 계속 검사하고 원래 입력 순서대로 결과를 냅니다.

출력의 `submissions`에는 각 파일의 요청/관측 해시·크기·상태·오류와 구조 해석에 성공한 기록이 포함됩니다. 상태는 `validated`(현재 원장 기준 등록 검증 통과), `already-recorded`(이미 동일 기록 존재), `duplicate`(입력 내 동일 기록 재전달), `invalid`입니다. 원본 파일은 수정하지 않지만 별도 백업을 생성하지도 않으므로 보관 책임은 제출자에게 있습니다. 잘못된 JSON도 파일 경로와 관측 해시로 추적할 수 있습니다.

같은 ID의 다른 내용은 모든 해당 입력을 충돌로 남기며 새 ID를 임의 발급하지 않습니다. 같은 계약의 같은 요청에 다른 ID의 회신이 동시에 들어오면 모두 `competing-responses`로 표시합니다. 입력 순서나 다수결로 하나를 고르지 않습니다. 각 기록은 같은 원장 스냅샷을 기준으로 검사합니다. 이 명령으로 계약 등록과 그 계약에 대한 회신 등록을 한 번에 처리하지 않습니다.

`storedManualReviews`는 원장에 등록된 계약의 미회신·누락 상태, `storedDisputes`는 기존 이견, `storedMediation`은 저장된 의견/중재를 보여줍니다. `pendingOpinions`는 검증을 통과했으나 아직 저장되지 않은 의견과 같은 주제의 저장된 의견을 함께 보여줍니다. 둘의 `origin`을 구분하고 신규 묶음의 상태는 항상 `unresolved`입니다. 동일 입장의 의견들만 있어도 자동 합의가 아닙니다. 저장하지 않은 회신이 수집 결과에 있다고 해서 저장된 미회신 계약을 완료로 표시하지 않습니다.

`processingComplete: true`는 명세의 입력 처리가 끝났다는 뜻입니다. `persisted: false`이며, `requiresAction`은 오류·미등록 기록·기존 미종결 작업·head 불일치 여부를 나타냅니다. 수집/충돌 조회 종료 코드는 **0=해당 명령 범위의 대기 항목 없음, 2=처리/출력 완료 후 확인 필요 항목 존재, 1=명세·설정·저장소·일관성 또는 출력 오류**입니다. `2`를 진단 실행 실패나 취약점 확인으로 해석하지 않습니다. 출력 경로가 이미 존재하면 덮어쓰지 않습니다.

DB 모드에서도 기존 `--state-backend`/`--run-id`를 사용합니다. 모든 조회는 같은 DB 트랜잭션 스냅샷을 사용하고, 확인한 로컬 파일은 종료 전 변경 여부를 검사합니다. 검증 통과 뒤 원장이 바뀔 수 있으므로 실제 등록은 기존 `note`의 최신 head·계약·ID 검사를 다시 거칩니다.

## 명시적 의견과 중재 이력

`review-opinion`은 기존 근거 문서에 대한 작성자의 표기를 보존하는 주석입니다. `subject.artifact`와 `subject.topic`이 정확히 같은 의견끼리 비교합니다. topic은 앞뒤 공백을 제거한 뒤 대소문자를 구별합니다. 다른 파일 버전이나 다른 topic을 의미적으로 합치지 않습니다. `support`, `oppose`, `uncertain`은 작성자가 입력하는 값이며 프로그램의 취약점 판정이 아닙니다.

```json
{
  "id": "OPINION-A", "kind": "review-opinion", "author": "reader-a",
  "subject": {
    "artifact": {"path": "review-material/part1.md", "sha256": "<현재 근거 해시>"},
    "topic": "이 문서의 설명에 충분한 근거가 있는가"
  },
  "position": "support",
  "rationale": "담당자가 문서와 인용 자료를 대조하여 이 의견의 근거를 기록합니다.",
  "references": [{"path": "review-material/part1.md", "sha256": "<현재 근거 해시>"}]
}
```

사람이 검토한 의견은 기존 `note --input=... --expected-head=...`로 등록합니다. `references`는 정확한 subject 파일 버전을 포함해야 하며 추가 근거를 인용할 수 있습니다. Finding 문서를 대상으로 하더라도 해당 파일에 대한 주석일 뿐 canonical Finding을 갱신하지 않습니다. 기존 자유 서술형 `dispute`/`resolution`은 그대로 유지하며 자동으로 새 의견으로 변환하지 않습니다.

`review-conflicts`의 `groups`는 모든 저장 의견과 중재 이력을 반환합니다. `conflictingPositions`는 서로 다른 명시적 표기가 존재한다는 뜻입니다. 텍스트의 의미를 판단하지 않고, 같은 작성자의 서로 다른 표기도 삭제하지 않습니다. `pending`에는 `awaiting-mediation`, `deferred`, `needs-information`, `stale` 묶음이 포함됩니다. 의견이 한 개뿐이거나 모두 같은 표기여도 사람이 명시적으로 중재하기 전에는 대기입니다.

중재는 `review-mediation` 주석으로 저장합니다. 다음은 두 의견 중 하나를 사람이 선택하는 예시입니다. 모든 현재 의견의 ID와 **주석 항목 해시**를 넣어야 하며, `selectedOpinion`은 그중 하나입니다.

```json
{
  "id": "MEDIATION-001", "kind": "review-mediation", "author": "coordinator",
  "subject": {
    "artifact": {"path": "review-material/part1.md", "sha256": "<현재 근거 해시>"},
    "topic": "이 문서의 설명에 충분한 근거가 있는가"
  },
  "opinions": [
    {"id": "OPINION-A", "sha256": "<A 항목 해시>"},
    {"id": "OPINION-B", "sha256": "<B 항목 해시>"}
  ],
  "outcome": "adopt",
  "selectedOpinion": {"id": "OPINION-A", "sha256": "<A 항목 해시>"},
  "rationale": "중재자가 양쪽 근거를 확인하고 선택한 의견과 남은 제한을 기록합니다.",
  "references": [{"path": "review-material/part1.md", "sha256": "<현재 근거 해시>"}]
}
```

`outcome`은 `adopt`, `defer`, `needs-information`입니다. 보류·추가 확인에는 `selectedOpinion`을 생략합니다. `uncertain` 의견은 채택 완료로 처리할 수 없으며 보류 또는 추가 확인으로 남깁니다. 중재의 근거에는 모든 의견이 인용한 파일 경로의 현재 버전을 넣어야 합니다. 원래 의견의 바이트·과거 근거·모든 중재 이력은 보존합니다. 주석 ID와 작성자 표기는 인증이나 실제 검토를 증명하지 않습니다.

중재 뒤 새 의견이 추가되면 기존 중재의 의견 목록과 달라지므로 다시 대기로 표시합니다. 기존 결정을 자동 확대하지 않습니다. 중재 근거가 바뀌면 `stale`이며, 사람이 새 근거로 다시 중재한 기록을 남길 수 있습니다. subject 파일 자체가 바뀌었으면 새 subject 버전으로 의견을 등록합니다. 최신 의견 전체를 빠뜨린 중재는 최신 head를 사용하더라도 거부합니다. 채택 후에도 상충 표기와 원문 의견을 지우지 않습니다.

이 주석 종류는 기존 파일/PostgreSQL 원장을 재사용하며 별도 테이블이나 migration이 필요하지 않습니다. `inspect`에도 대기 중재를 표시하지만 Finding·실행 coverage·발행 보고서를 변경하지 않습니다. 기존 주석 해시는 유지하며 새 종류를 지원하지 않는 구버전 프로그램과는 호환되지 않습니다.

## 사람이 판정한 자료의 품질 계산

```sh
pnpm results:admin quality --input=/absolute/adjudication.json --output=/absolute/quality-score.json
```

입력 계약은 `src/runtime/diagnostic-quality.ts`의 `DiagnosticQualityInputSchema`입니다. 고정 정답 ID, 전체 예측 ID와 각 예측의 판정, 음성 대조군, 실행/원문 전달/독립 집계/정답 출처 확인 값을 요구합니다. 미해결 예측은 분모에서 숨기지 않습니다. 결과에는 원본 입력 바이트 해시와 지표, gate 실패 사유가 포함됩니다.

출처와 조건 확인 boolean은 작성자의 진술입니다. 이 명령이 원문을 독립적으로 검증했다는 뜻이 아닙니다. 종료 코드는 0=입력에 따른 기준 충족, 2=기준 미달, 1=입력 오류입니다.

## 검증

`pnpm test:regression`에 감사·이견·수동 계약/회신·담당자/파일별 현황·회신 양식·제출 수집·명시적 중재·CLI·연결 오류 회귀가 포함됩니다. 수집 테스트는 동시 읽기 한도, 개별 입력 오류, ID 충돌, 경쟁 회신, 변경된 입력/근거, 무인 미해결 보존을 검사합니다. PostgreSQL 검증은 별도 테스트 DB의 `NUNCHI_DATABASE_URL`로 `postgres-results.integration.test.ts`, `postgres-knowledge.integration.test.ts`, `postgres-run-state.integration.test.ts`를 실행합니다. 결과 관리 통합 테스트는 별도 schema를 생성·삭제하며 동시 쓰기, 명시적 이전, 커밋 응답 유실, 실패 복구, 원자적 배치 등록, DB 전용 이벤트 감사, 파일/DB 현황 일치, 조회 중 경쟁 쓰기와 실제 CLI 연결을 검사합니다. 테스트 DB를 실제 운영 DB와 공유하지 않습니다.
