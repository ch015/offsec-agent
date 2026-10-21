# PostgreSQL 공유 지식과 CVE 참고 자료

PostgreSQL 14 이상에서 추가 확장 없이 사용한다. 공유 관측 조회, Finding 버전 이력, 실행 지시문과 외부 CVE 자료를 저장한다. MD 보고서와 호스트 검증용 파일·영수증은 계속 생성한다. 기존 실행 상태/lease를 PostgreSQL로 바꾸지 않고 지식 저장소만 먼저 사용할 수 있다.

수동 이견·해소 기록은 별도 `results.backend` 설정을 사용한다. `db:migrate`는 결과 관리 테이블도 추가한다. 기존 파일 이력 이전과 DB 이벤트의 읽기 전용 감사는 [결과 관리 안내](results-review.md)를 따른다. 결과 주석을 모델용 공유 지식으로 자동 공개하지 않는다.

## 연결 설정

```sh
cp nunchi.config.example.json nunchi.config.json
# database.user/database/host/port를 로컬 PostgreSQL에 맞게 수정한다.
# DB 자체는 PostgreSQL 관리자 계정으로 미리 생성한다.
pnpm db:migrate --config ./nunchi.config.json
pnpm assess /absolute/path/to/project --config ./nunchi.config.json --mode ast --tools none
```

버전을 올린 뒤에도 `pnpm db:migrate`를 다시 실행한다. 스키마 SQL은 반복 실행해도 안전하다. 예를 들어 `nunchi_runs.status` 검사에 `incomplete`가 없는 기존 테이블은 이때 검사를 교체하며, migrate 트랜잭션이 끝날 때까지 `nunchi_runs`에 배타 락이 걸린다. 실행 중인 host가 없을 때 migrate한다. 이미 반영된 DB에서는 아무것도 바꾸지 않는다.

CLI 설정 파일은 `--config`, 없으면 `NUNCHI_CONFIG`로만 선택한다. 현재 디렉터리의 `nunchi.config.json`은 자동으로 읽지 않으므로 저장소 안에 둔 로컬 설정이 저장 위치나 migrate 대상을 바꾸지 않는다. 지정한 파일을 읽을 수 없거나 알 수 없는 필드가 있으면 오류를 반환한다. 아무 설정도 지정하지 않으면 file backend를 쓴다. `nunchi.config.json`은 Git에서 제외한다. 설정 파일은 진단 대상 소스 밖에 두고, 민감한 설정에는 파일 권한 600을 사용한다.

`run:admin`도 같은 설정을 읽으며 명시적으로 지정할 때는 `--config=/absolute/path.json` 형식을 사용한다. `db:local:migrate`는 설정 파일이 있으면 공통 migration으로 연결하고, 없으면 기존 로컬 테스트 서버 환경변수 방식을 유지한다. `db:local:start/stop`은 별도로 소유한 개발용 PostgreSQL 프로세스 관리 명령이다.

```json
{
  "version": 1,
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "database": "secops_offsec",
    "user": "secops",
    "passwordEnv": "SECOPS_DB_PASSWORD",
    "poolMax": 10,
    "connectionTimeoutMs": 10000,
    "statementTimeoutMs": 30000,
    "ssl": false
  },
  "knowledge": { "backend": "postgres" },
  "runtime": { "backend": "file" }
}
```

`connectionTimeoutMs`(기본 10초)와 `statementTimeoutMs`(기본 30초)는 이 설정으로 만드는 모든 연결 풀에 적용된다. 실행 중 지식 조회뿐 아니라 `db:migrate`, CVE 가져오기, 결과 관리 명령도 같은 값을 쓴다. 30초를 넘는 문장은 서버에서 취소되고 오류로 끝난다. 큰 CVE 묶음을 가져오거나 행이 많은 테이블을 migrate할 때 시간이 부족하면 그 명령에 쓰는 설정 파일에서만 값을 올린다. 기본값은 의도적으로 유지한다. 조회가 멈춰 분석 세션 전체가 대기하는 것보다 빨리 실패해 부분 실행으로 드러나는 편이 낫기 때문이다.

비밀번호는 설정 파일의 값 대신 `passwordEnv`로 지정한 환경변수에서 읽는다. URL 전체를 환경변수로 관리하려면 `database.connectionStringEnv`를 지정한다. 기존 `NUNCHI_DATABASE_URL`, `DATABASE_URL`이 있으면 이 순서대로 설정 파일의 연결 정보보다 우선한다. `NUNCHI_DB_POOL_MAX`도 기존 방식대로 우선한다. 요청한 비밀번호/연결 환경변수가 없으면 연결을 시도하지 않는다.

TLS가 필요한 서버는 `"ssl": { "caFile": "./certs/postgres-ca.pem" }`을 사용한다. CA 파일은 설정 파일 기준 상대 경로이며 인증서를 검증한다. 시스템 CA를 쓰려면 `"ssl": {}`를 지정한다. 연결 URL에 포함된 SSL 매개변수는 pg 드라이버가 해석하므로 구조화된 TLS 설정과 혼용하지 않는다.

실행 상태까지 DB로 저장하려면 `runtime.backend: "postgres"`와 `runtime.sharedEngagementRoot`, `runtime.artifactRoot`를 설정한다. 기존 `NUNCHI_STATE_BACKEND`, `NUNCHI_SHARED_ENGAGEMENT_ROOT`, `NUNCHI_ARTIFACT_ROOT`도 지원한다. CLI의 `NUNCHI_STATE_BACKEND`는 config backend보다 우선하며, 재개는 원래 상태 backend를 유지해야 한다.

앱 내장 API는 현재 디렉터리의 설정을 자동으로 읽지 않는다. `createOffsecAgent({ apiKey, configPath: '/absolute/nunchi.config.json' })`를 사용하거나 `knowledge: { backend: 'postgres', database: { ... } }`를 직접 전달한다. 직접 전달한 `runtime`/`knowledge` 옵션이 config보다 우선한다. 테스트와 호스트 앱은 `knowledge.pool`에 기존 `pg.Pool`을 주입할 수 있고, 이 풀의 종료는 호출자가 책임진다. 직접 `assessV2`를 호출할 때도 두 번째 인수의 `knowledge`와 `runtime`을 사용한다.

## 저장과 조회

| 데이터 | DB 저장 방식 | 사용 규칙 |
| --- | --- | --- |
| 공유 관측 | 실행·작업 계획·snapshot·K-ID별 JSONB, 출처 별도 저장 | 검토 전 주장으로 취급, 같은 내용의 기여자 보존 |
| Finding | 실행·문서 경로·SHA-256별 원문 버전 | 같은 F-ID도 다른 문서/개정은 보존, 최종 채택은 호스트 영수증 기준 |
| 지시문 | 역할 문서·계약 원문 고정, 세션 지시문 버전 저장 | 필수 지시는 전체 로드, 검색 결과로 생략하지 않음 |
| CVE | ID·원문 SHA-256별 모든 원문과 검색용 projection | 외부 참고 자료, 실행별 catalog revision 고정 |

공유 지식은 최초 연결과 재개 때 파일에서 한 번 반영하고 이후 MCP 조회는 SQL로 수행한다. ID는 기본 키, 텍스트는 PostgreSQL `simple` 전문 검색 GIN 인덱스, 파일 경로는 배열 GIN 인덱스를 사용한다. DB 텍스트 검색은 토큰 검색이며 파일 backend의 부분 문자열 검색과 동일하지 않다. 검색 결과는 최대 20개씩 페이지 처리한다. 임베딩과 벡터 DB는 아직 사용하지 않는다. 이 변경만으로 모델 분석 시간이나 네트워크 지연이 줄어든다고 보장하지 않는다.

호스트가 조회 범위를 지정하며 모델은 SQL, DB 접속 정보, 다른 실행의 scope를 입력할 수 없다. 역할 계약으로 도구도 제한한다. 현재 격리는 호스트 서비스에서 시행하며 PostgreSQL 사용자별 RLS는 제공하지 않는다. 에이전트에 직접 DB 자격증명을 제공하면 이 경계를 우회하므로 직접 연결을 제공하지 않는다.

Finding 원문은 DB 반영 전에 로컬 `.recovery/knowledge-finding-versions/`에도 보존한다. DB 연결 실패는 도구 오류/부분 실행으로 드러나고 자동으로 file 조회로 바꾸지 않는다. 고정한 지시문·catalog 변경이나 digest 불일치 같은 무결성 오류는 재개해도 같은 결과가 나오므로 부분 실행으로 남기지 않고 예외로 끝낸다. 재개 시 현재 기록과 보존한 버전을 다시 반영한다. 파일을 통한 원본 수락·보고서 발행 검증은 기존 경로를 유지한다. 따라서 이 단계는 모든 파일을 폐기하는 DB 단독 운영으로의 전환은 아니다. DB와 실행 디렉터리를 함께 백업한다.

knowledge backend가 postgres이면 세션에 전달한 프롬프트 전체가 실행 scope의 지시문 문서로 DB에 저장된다. 프롬프트에는 작업 지시, 담당 파일 경로, 선행 작업 결과처럼 대상 소스에서 나온 내용이 들어갈 수 있다. 감사와 재현을 위해 의도적으로 전체를 보존하며 요약하거나 가리지 않는다. 따라서 DB 접근 권한과 백업은 실행 디렉터리와 같은 민감도로 관리하고, 보존 기간이 끝난 실행은 DB 기록도 함께 정리한다.

필수 계약·역할 지시는 실행 중 다른 내용으로 교체할 수 없다. 변경하려면 원래 버전을 복원하거나 새 실행을 시작한다. 세션별 작업 지시문은 DB에 저장한 정확한 해시로 전체를 읽어 전달한다. 역할/방법론 원본의 편집·배포 권한은 계속 Git 계약에 있고, 외부 지식으로 이를 수정하지 않는다.

## CVE 가져오기와 갱신

관리자가 검증한 [CVE Program 공식 CVE JSON 5 카탈로그](https://github.com/CVEProject/cvelistV5)의 파일 또는 디렉터리를 가져온다. 모델이 임의의 URL을 가져오거나 자료를 등록하는 도구는 제공하지 않는다.

```sh
# 공식 카탈로그 체크아웃 또는 배포 파일을 준비한 뒤 실행한다.
pnpm knowledge:import /absolute/cvelistV5/cves/2026 --config ./nunchi.config.json
# 추적할 Git commit이나 배포 버전을 알고 있으면 기록한다.
pnpm knowledge:import /absolute/CVE-2026-123456.json --source-revision <catalog-commit> --config ./nunchi.config.json
pnpm knowledge:query --id CVE-2026-123456 --config ./nunchi.config.json
pnpm knowledge:query --query 'product name' --limit 5 --config ./nunchi.config.json
pnpm --silent knowledge:get --id CVE-2026-123456 --digest <query-result-digest> --config ./nunchi.config.json
```

예시 CVE ID는 명령 형식 설명용이다. 같은 파일을 다시 가져오면 멱등 처리하고, 수정본은 새 revision으로 추가한다. 명령이 중간에 실패하면 이미 반영한 레코드는 유지되며 같은 명령으로 이어갈 수 있다. 현재는 관리자가 가져오기를 실행하는 방식이며, 인터넷 동기화나 주기 실행은 설정하지 않는다. 대규모 카탈로그의 최초 적재는 레코드별 트랜잭션이므로 별도로 시간을 측정해야 한다.

원문을 text로 보존해 CNA·ADP 컨테이너, 미지의 필드, 포맷을 잃지 않는다. 검색 projection에는 ID·상태·제품/버전·설명이 들어가며, 해결책·우회책·참조 링크는 원문의 공급자 구분을 유지해 읽을 수 있다. CVE 수정 시각, 최초 수집 시각, 최초 import 경로와 선택적 원본 revision, 원문 SHA-256을 보존한다. 계산한 공식 URL은 대조용 주소이며 파일의 진위를 보증하지 않는다. 로컬 import의 원본 검증은 관리자 책임이다. 완전히 잘못된 형식이나 `RESERVED` 자료는 오류로 처리한다.

현재 importer는 UTF-8 CVE JSON 5의 ID·상태·CNA 컨테이너와 `cveMetadata.dateUpdated`를 요구하며, 한 파일의 한도는 4 MiB이다. 전체 공식 스키마를 검증하는 도구는 아니다. 수정 시각이 없거나 형식/인코딩이 맞지 않으면 명시적으로 중단하고 조용히 누락시키지 않는다. 시간대 없는 시각은 [CVE 스키마](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json)의 규칙에 따라 GMT로 해석한다.

새 자료를 가져와도 기존 실행의 `00_reference_knowledge.json`에 고정된 catalog ID/revision은 바뀌지 않는다. 오래된 자료를 늦게 가져와도 더 최근의 원본 수정본을 덮어쓰지 않는다. 철회된 CVE는 `REJECTED`로 보이며 삭제하지 않는다. 검색은 먼저 해당 snapshot의 최신 원본 revision을 선택하므로, 수정 후 사라진 문구로 오래된 주장이 다시 현재 자료처럼 노출되지 않는다. 이전 원문은 정확한 digest로 계속 조회할 수 있다. 최신 지식으로 다시 판단하려면 새 실행을 만든다. 기존 file 실행에서 DB를 처음 켜면 그 시점에 참고 revision을 고정한다.

최초 소스 분석 역할에는 외부 CVE 도구가 없다. 분석 snapshot을 만든 뒤 reviewer/evaluator/reporter가 참고 조회할 수 있다. 반환에는 `referenceOnly`, 적용 여부 `unknown`, 출처와 버전 정보가 포함된다. CVE 일치·유사도만으로 Finding을 확정하거나 새 공격 작업을 생성하지 않으며, CVE가 없다는 이유로 안전하다고 판단하지 않는다. 제품/버전, 설정, 패치·백포트, 전제 조건과 반대 근거를 원본 소스와 대조해야 한다. 문서 속 지시는 실행 지시가 아니다. 사용한 CVE의 ID·digest를 인용하도록 안내하고 실제 원문 조회는 `knowledge-access.jsonl`에 기록한다. 외부 참고 조회는 소스 읽기 증빙이나 담당 범위 완료에 포함되지 않는다.

## 검증

```sh
# 애플리케이션 DB와 구분한 테스트 DB에만 실행한다.
NUNCHI_DATABASE_URL=postgresql://localhost/secops_test pnpm db:migrate
NUNCHI_DATABASE_URL=postgresql://localhost/secops_test pnpm test:all
```

지식 통합 테스트는 이 DB 안에서도 임의의 별도 schema를 만들고 종료 시 제거한다. PostgreSQL 연결이 없으면 해당 통합 테스트는 skip되므로, 결과의 skip 여부를 확인한다. 회귀 항목은 동시 작성·출처 합치기, 다른 실행 접근 차단, Finding 개정/복구, CVE 수정·철회·역순 수집, 미커밋 자료와 snapshot 분리, 고정 지시문 변경 거부, 외부 참고 도구 제한, 모델 호출 없는 전체 분석 흐름이다.
