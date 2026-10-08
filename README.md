# SecOps OffSec Agent

Scanner가 프로젝트 구조와 책임 경계를 판단하고, 호스트가 작업을 나누어 Analyzer를 병렬 실행하는 소스 보안 진단 라이브러리입니다. Reviewer의 독립 검토, Evaluator의 종합 평가, Reporter의 초안 작성 후 호스트가 보고서를 발행합니다.

현재 실행 계약은 `domains/offsec/contracts/offsec-contract.v2.json`의 **2.1.0**입니다. v1 실행·계약·사용자 인증 재개 API는 제거했습니다. `assess:v2`는 단일 `assess` 명령의 호환 별칭입니다. 과거 실행 결과는 보존하며 자동 변환하지 않습니다.

## 설치와 실행

Node.js 22.18 이상과 pnpm이 필요합니다.

```sh
pnpm install --frozen-lockfile
pnpm assess /absolute/project --mode ast
pnpm assess /absolute/project --mode ast --tools semgrep
pnpm assess /absolute/project --mode ast --tools semgrep --semgrep best-effort
pnpm assess /absolute/project --mode ast --tools none
```

CLI 인증은 Claude Agent SDK의 API 키 또는 설정된 로컬 인증을 사용합니다. 앱에 내장할 때는 `apiKey` 또는 `sessionRunner`를 명시합니다. Semgrep은 별도 설치하며 규칙 manifest에 고정한 버전과 규칙 해시를 검증합니다. 명시한 `--tools semgrep`은 기본적으로 필수 도구입니다. 필수 도구 실패 시 모델 호출 전에 중단하고 인벤토리와 사유를 남깁니다. `--mode ast`만 지정하면 Semgrep은 실행하지 않습니다. mode/tools를 모두 생략한 기존 호출은 Semgrep best-effort 동작을 유지합니다.

Solidity 문법은 Tree-sitter 호환성을 검증한 1.2.11로 고정합니다. 현재 Dart/HCL은 AST 미지원으로 명시하고 원본 분석 범위에는 유지합니다. 구문 경고, 파싱 실패, Semgrep 규칙 미적용 파일은 작업별 근거와 보고서에 남깁니다. Semgrep 실행 완료가 모든 파일의 규칙 검사를 뜻하지는 않습니다.

HTML·서버 템플릿·Vue/Svelte와 명시적인 실행/배포 설정도 수집합니다. JSX/TSX는 첫 부분에 실행 키워드가 없다는 이유로 제외하지 않습니다. 일반 문서·바이너리·임의 JSON은 인벤토리에 분류하고 분석 범위와 구분합니다. Semgrep 입력은 최대 128개 파일 또는 24KB 경로 인자 묶음으로 처리하며 묶음별 영수증과 전체 누락 여부를 대조합니다.

## 호출 구조

1. **호스트 준비:** 인벤토리·설정·의존성·보안 리소스를 수집하고 변경 불가능한 소스 스냅샷을 생성합니다. AST와 선택한 도구를 스냅샷에 실행합니다.
2. **Scanner:** 실행·신뢰 경계에 따라 유닛을 정하고 모든 파일의 소유자와 교차 유닛 흐름 담당자를 지정합니다. 우선순위는 범위를 줄이지 않습니다.
3. **호스트 계획·스케줄러:** 유닛을 파일 수·예상 소스 토큰 용량에 맞게 나누어 TaskRequest를 만듭니다. 큰 파일은 정확한 바이트/행 범위로 분할하고, 조각 분석 완료 후 연결 검토 작업을 실행합니다.
4. **Analyzer 병렬 실행:** 담당 범위의 실제 전달 영수증, 파일별 분석 근거, 담당 흐름 판정을 기록합니다. 공통 관측은 같은 실행의 공유 저장소에서 재사용합니다.
5. **Reviewer → 필요한 근거 보완 → 재검토:** 검토자는 실제 소스 근거를 확인합니다. 부족한 질문만 추가 조사하며 반복 요청은 미해결로 남깁니다.
6. **호스트 분류표 → Evaluator → Reporter → 호스트 발행:** 호스트가 확정된 검토 판정을 분류표로 직렬화하고 중복·출처·무결성을 검사합니다. Evaluator는 범위·위험·한계를 종합 평가하고 Reporter가 초안을 작성합니다. 부분 보고서가 발행돼도 실행 상태는 `incomplete`입니다.

호스트는 모델 에이전트나 게이트웨이가 아닌 TypeScript 실행 관리자입니다. 모델 역할은 계약으로 정의되고 호스트가 각 SDK 세션의 역할·정확한 입력·도구·산출물 계약을 전달합니다. 모델이 다른 에이전트를 생성하지 않습니다.

동시성은 1에서 시작해 실제 진행과 자원 여유에 따라 증가합니다. 고정 16개 상한과 128개 페이지 장벽은 없습니다. 같은 호스트 프로세스의 실행은 점유와 provider backoff를 공유합니다. `--max-concurrency=3`처럼 명시한 상한은 유지됩니다. 여러 호스트에 걸친 분산 quota 조정은 제공하지 않습니다.

SDK의 스트림 도착과 도구 실행을 진행 신호로 관측합니다. 기본적으로 15분간 진행 신호가 없으면 작업을 취소하며, 별도로 지정한 전체 실행 시간 상한은 유지합니다. API 재시도·429/503/529 대기 신호는 admission에 전달합니다. 부분 추론 내용이나 미완성 도구 인자는 진행 로그에 저장하지 않습니다.

## 주요 옵션

| 옵션 | 동작 |
| --- | --- |
| `--model`, `--review-model` | 기본 `opus`, `sonnet`; 독립 검토 모델 지정 |
| `--effort`, `--max-turns` | SDK 추론 노력과 세션별 턴 한도 |
| `--max-concurrency=N` | 선택적인 실제 점유 상한 |
| `--max-files-per-agent=N` | 작업당 담당 파일 수, 기본 24 |
| `--max-source-tokens-per-agent=N` | 작업 분할용 예상 소스 토큰, 기본 24000 |
| `--max-followup-hypotheses=N` | 선택적 교차 유닛 후속 질문, 기본 3, 0..8 |
| `--engagement-dir=PATH` | 새/빈 결과 디렉터리 |
| `--resume` | 지정한 기존 실행의 미완료 작업 재개 |
| `--reuse-from=PATH` | 새 실행에서 호환되는 이전 분석만 검증해 재사용 |
| `--cost-policy=record-only` | 기본값. 비용을 기록하고 금액으로 차단하지 않음 |
| `--cost-policy=enforce --max-usd=N` | 명시적인 비용 제한 |
| `--no-cost-guard` | 비용 제한 해제 |

`--max-usd`만 설정해도 기본 record-only 정책은 유지됩니다. 파일 수와 토큰 수는 작업 용량 추정치이며 모델 이해도나 절대 컨텍스트 한도를 뜻하지 않습니다. 재시도는 원인에 따라 최대 3회이며 429/503/과부하와 Retry-After를 반영합니다. 권한 거부를 무한 재시도하지 않습니다.

## 완료와 재개

```sh
pnpm assess /absolute/project --engagement-dir=/absolute/run --resume
pnpm assess /absolute/project --engagement-dir=/absolute/new-run --reuse-from=/absolute/old-run
```

Read 요청, 실제 소스 전달, 파일별 분석, 기존 분석 재사용을 분리합니다. `coverage.complete`는 필수 작업·내용 전달 또는 검증된 재사용·파일/흐름 판정·필수 도구·검토 요청의 완료를 요구합니다. 취약점 부재나 모델의 의미적 이해를 보장하지 않습니다.

Scanner 계획과 Analyzer 파일/흐름 판정은 저장 전 검증합니다. 잘못된 인용·누락된 흐름 양끝·미전달 구간은 같은 세션의 Write에 수정 사유를 반환하고, 세션 종료 때 다시 대조합니다.

Reviewer도 저장 전에 누락된 판정 ID와 읽지 않은 원본 근거 범위를 함께 받습니다. `inconclusive`도 원본 검토를 요구하며, 과거에 이 조건을 충족하지 못한 검토는 재개 시 분석을 보존하고 검토부터 갱신합니다. SDK의 행 단위 읽기와 전용 reader의 바이트 단위 읽기는 원본 위치로 합쳐 집계하며, 한 바이트의 실제 공백도 완료로 처리하지 않습니다. 큰 공통 자료는 검색·페이지 조회 도구로 필요한 관측을 재사용합니다.

대량 검토는 최대 20개 판정씩 원본을 읽고 `reviewPatch`로 저장할 수 있습니다. 호스트가 정확한 ID로 판정을 갱신하고 이전 판정을 보존합니다. 동시 patch 쓰기는 직렬화하며, 초안은 단계 완료나 발행에 사용할 수 없습니다. 마지막 `finalize:true` 요청에서 전체 판정·중복·독립 원문 읽기를 다시 검사합니다. 실패한 검토자가 제출한 보정 기록도 다음 재시도의 정확한 입력·읽기 목록으로 갱신합니다.

채택·보정 판정에는 검토자가 선택한 `reviewedSeverity`를 명시해야 합니다. 설명문에만 등급 변경을 적어 기존 심각도가 발행되는 일을 막도록 원장의 심각도와 대조합니다. 등급을 바꾸려면 보정 finding 제출이 필요합니다. 필드 누락이나 설명문의 명시적인 등급 단정과 원장이 충돌하는 과거 검토는 분석을 보존하고 검토 판정만 다시 확정합니다. 명시적 표현에 대한 일관성 검사이며, 모든 자연어 의미나 심각도의 적절성 자체를 자동 증명하지는 않습니다.

호스트는 수락한 검토 판정과 독립 원문 전달 증빙을 별도 checkpoint에 저장합니다. SDK 쓰기 직후 프로세스가 중단돼도 실제 저장된 바이트가 일치할 때만 복구합니다. 같은 실행·소스 snapshot·검토 모델·분석 revision의 변경 없는 판정만 재사용하며, 변경된 finding은 다시 검토합니다. `maxTurns`는 각 SDK 세션에 적용하고, 턴 한도에 도달한 검토가 원래 할당된 후보의 판정을 실제로 진전시켰다면 새 세션에서 남은 항목을 계속합니다. 진전 없는 반복, 사용자 취소, 명시적 시간·비용 한도는 이 경로로 우회하지 않습니다. SDK의 종료 subtype과 사유도 실패 원장에 남깁니다.

도구 호출 횟수로 컨텍스트 소진을 추정하던 경고와 `NUNCHI_CONTEXT_BUDGET_WARN_TOOLS` 설정은 제거했습니다. 실제 SDK compaction 이후의 작업·발견 기록 복구는 유지합니다.

검토 확정 후 호스트가 `04_evaluation_classification.yaml`과 요약 입력 `03_evaluation_input.json`을 생성합니다. 확정된 판정·심각도·근거·중복 관계를 그대로 옮기며 새로운 보안 판정을 만들지 않습니다. Evaluator는 전체 원장을 다시 열거나 분류표를 재작성할 필요 없이 선택한 근거와 요약으로 `04_evaluation.json`을 작성합니다. 분류표 수정이나 검토 원장 변경은 발행 전에 검출합니다. 실제 AST/Semgrep 처리 범위는 호스트 전처리 영수증을 기준으로 하며 의존 그래프의 파서 메타데이터와 구별합니다.

평가의 `actualToolCoverage`는 호스트의 파일·후보·진단 통계와 저장 전 대조합니다. 빠진 값을 0으로 추정하지 않습니다. 평가·보고만 보완할 때는 별도 `evaluation.reopened` 원장 이벤트로 이전 산출물을 보존하고 독립 검토와 분석 revision, 기존 비용을 유지합니다.

Reporter는 요약·우선순위·대표 근거를 작성하고, 호스트가 확정된 모든 Finding ID·판정·병합 관계·근거·전제·보완책을 최종 보고서 부록에 생성합니다. 기각·보류·보정 전 기록도 포함합니다. 소스 manifest의 Git 출처와 실제 스냅샷 식별자도 함께 발행하며, `classificationSha256`과 `inputSha256`은 각각 다른 평가 파일의 해시입니다. 새 보안 판정을 만들거나 정적 근거를 동적 재현으로 바꾸지 않습니다. 발행 검사와 영수증은 초안과 부록을 합친 최종 바이트를 대상으로 합니다. 완료된 보고서 재개는 발행 영수증을 검증하고 같은 바이트를 반환합니다.

원본 바이트 해시는 스냅샷과 저장 증거 무결성에 사용합니다. 새 실행의 재사용은 변경 분류와 의존 영향 검사를 별도로 거칩니다. 지원되는 JS/TS/JSON의 검증된 CRLF/LF·마지막 개행 차이는 재사용할 수 있으며, 조건·문자열·정책 변경 또는 미지원 형식은 재분석합니다. 과거 읽기는 `ValidatedSourceReuse`로 기록되고 새 읽기로 집계하지 않습니다. 도구 결과는 새 스냅샷에서 다시 생성합니다.

같은 실행의 재개는 기존 스냅샷을 유지하고 성공한 작업을 재호출하지 않습니다. 부분 결과 보완 시 이전 보고서와 검토 결과는 `revisions/`에 보존합니다. 취소 요청 후 실제 로컬 작업 종료 전까지 점유를 유지하며, 종료 확인이 안 되면 새 실행과 발행을 보류합니다. 늦게 도착한 결과와 사용량은 별도로 처리합니다. provider가 전달하지 않은 비용은 unknown으로 남깁니다.

API는 `published | incomplete`, CLI는 완료 0·범위 미완료 2·입력/무결성 오류 1을 반환합니다. 앱은 `onEvent`로 오류·보류·backoff·복구 알림을 받습니다.

## 저장과 배포

기본 결과는 대상 밖 `~/.ch015/<repo>/<time>_<commit-or-nogit>_<UUID>/`의 `engagement/`, `report/`에 저장합니다. `CH015_STATE_HOME`으로 저장 루트를 지정할 수 있습니다. 파일 상태 저장소와 PostgreSQL 상태/lease/outbox, 선택적 artifact store를 지원합니다. 대상 소스는 수정하지 않습니다.

```sh
pnpm build:library
pnpm test:all
# 실제 PostgreSQL 회귀도 실행하려면 독립 테스트 DB의 NUNCHI_DATABASE_URL 지정
```

공개 진입점은 `src/index.ts`, 빌드 결과는 `dist/src/index.js`입니다. 패키지에는 실행 결과·인증 정보·로컬 테스트 자료를 포함하지 않습니다.

- [앱 내장 API](docs/embedding.md)
- [저장·복구·사용량](docs/analysis-storage-recovery.md)
- [분석 범위와 한계](docs/detection-improvements.md)
- [도메인 자산](domains/offsec/README.md)
- [문서 안내와 과거 설계 기록](docs/README.md)
