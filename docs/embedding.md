# OffSec를 애플리케이션 코드에서 사용하기

문서 기준: 2026-09-22. [현재 기능과 한계](README.md) · [저장·복구·재개](analysis-storage-recovery.md)

`src/index.ts`가 공개 진입점입니다. Node.js 22.18 이상 ESM 환경에서 기존 앱의 코드 의존성으로 연결합니다. Kit CLI·통합 tgz·프로젝트 YAML은 필요하지 않습니다.

```sh
pnpm install --frozen-lockfile
pnpm build:library
```

앱의 workspace 또는 pnpm `link:` 의존성으로 이 디렉터리를 연결합니다. 기본 package export는 컴파일한 `dist/src/index.js`와 타입 선언을 사용합니다. TypeScript 실행기를 쓰는 앱은 `secops-offsec-agent/source` export도 사용할 수 있습니다. `dist`의 도메인/템플릿 리소스를 함께 유지하세요.

## 앱 연결 예제

```js
import { createOffsecAgent } from 'secops-offsec-agent';
const controller = new AbortController();
const agent = createOffsecAgent({
  apiKey: process.env.ANTHROPIC_API_KEY,
  defaults: { maxConcurrency: 2, maxFollowupHypotheses: 3 }, // 금액 예산 기본값: 무제한
});
const result = await agent.run({
  target: '/srv/project', scope: '인증 경계 검토',
}, { signal: controller.signal });
// result.status: published | incomplete; result.coverage와 finalReport 확인
```

앱은 실제 대상 절대경로와 인증을 제공하고, 취소 시 `controller.abort()`를 호출합니다.
import는 서버나 worker를 시작하지 않습니다. 모델 키는 인스턴스에 주입하며 process.env나 cwd를 바꾸지 않습니다.
`engagementDir` 생략 시 `~/.ch015/<레포>/<UTC시간>_<커밋 또는 nogit>_<UUID>/` 아래
`engagement/`와 `report/`를 분리합니다. 저장 루트는 `CH015_STATE_HOME`으로 지정합니다.
기존 배치가 필요할 때만 `engagementDir: '/srv/results/job-123'`처럼 새/빈 절대경로를 지정합니다.
재개에는 추측한 최신 폴더가 아닌 결과의 `engagementDir`를 보관해 사용하세요.

`maxConcurrency` 기본값은 2입니다. `maxFollowupHypotheses`는 기본 3, 0..8 범위이며 0은 후속 분석을 끕니다.
유효한 교차 단위 질문이 있을 때만 최대 32턴의 추가 분석 세션 한 라운드를 실행합니다.
`maxBudgetUsd`를 생략하면 기본 금액 상한은 없습니다. `defaults.noCostGuard: true`로 호출자가 전달한 금액 상한도 명시적으로 해제할 수 있습니다.
`maxBudgetUsd`를 설정하면 분석 이후 단계를 위해 30%를 남기고 review 이후 10%, evaluate 이후 5%를 남깁니다.
이 예약은 SDK 사용량 회계 기준이며 절대 결제 한도는 아닙니다.

`coverage.complete`는 배정된 작업의 실행 완료입니다. `ownedFilesRead`는 초기 단위 분석에서 기록된
담당 파일 읽기 수이며 내용 이해를 보증하지 않습니다. `semanticCoverage: 'not-proven'`,
`deferredFollowupQuestions`, 결과 디렉터리의 `00_analysis_coverage.json`도 확인하세요.

소비 앱의 기본 AST parser는 JavaScript/TypeScript입니다. Python 등 다른 언어는 대응하는
선택형 peer를 앱 의존성에 추가합니다. 예: `pnpm add tree-sitter-python@^0.23.6`.
parser 미설치·실패·상한 도달은 증거 공백으로 기록하며 소스 직접 분석을 대체하지 않습니다.
SDK·pg·Playwright는 필요한 실행 경로에서 지연 로딩하지만 필수 설치 의존성으로 유지됩니다.
TypeScript 소비 앱은 일반 Node.js 앱처럼 `@types/node`를 개발 의존성으로 설치합니다.
전체 parser 목록과 검증 범위는 [탐지·경량화 상세](detection-improvements.md)에 있습니다.

`apiKey` 대신 기존 SessionSpec/SessionOutcome을 구현한 `sessionRunner`를 주입할 수 있습니다. `onProgress`, `onLedger`, `onStderr`, `onMetrics`로 앱의 관측 기능을 연결합니다. 출력·파일 입력은 절대경로를 사용합니다. 기본 state는 file이며 `runtime`으로 기존 PostgreSQL pool/artifact 설정을 주입할 수 있습니다. SDK sandbox·파일 시스템·분석 도구 설치 조건은 기존 실행과 같습니다.

같은 결과 디렉터리의 동시 실행은 거부합니다. 취소와 입력·무결성 오류는 예외로 전달됩니다. 복구 가능한 실행 실패는 부분 보고서와 `incomplete`를 반환하며 이미 생성한 증거를 자동 삭제하지 않습니다. 이벤트 callback에서 예외를 던지지 않도록 앱에서 처리하세요.

v2 중단 실행은 `agent.resume(engagementDir)`로 이어갑니다. 저장된 예산이 부족하면
`agent.resume(engagementDir, { maxBudgetUsd: 1000 })`으로 증액하거나
`agent.resume(engagementDir, { noCostGuard: true })`로 금액 상한을 해제합니다.
변경은 원장에 기록되어 이후 옵션 없는 재개에도 유지됩니다. 기존 사용액·미정산 예약액과
봉인된 입력은 보존합니다. 인스턴스 defaults 변경만으로 기존 실행 예산이 바뀌지는 않습니다.
완료된 실행의 분석 범위를 늘리거나 증분 분석하는 기능과는 구분하세요.


## v1 사용자 인증 후 재개

이 고급 API는 v1의 사용자 인증 대기를 이어가는 경로다. v2의 `agent.resume()`과 구분한다.
현재 `assess:resume` CLI는 필수 `--request-sha256`를 인수 파서가 거부하므로 API를 사용한다.

```js
import { resumeAssessOwnerAuth } from 'secops-offsec-agent';

const resumed = await resumeAssessOwnerAuth({
  engagementDir,
  requestId,
  requestSha256,
  expectedVersion,
  adapter,
  waitForOwner,
}, { runtime: { backend: 'postgres' } });
```

위 입력은 앱이 저장된 사용자 인증 요청과 현재 run 상태에서 가져와 전달한다. 해시나 version을
임의로 생성하지 않는다. `adapter`는 앱이 제공하는 `AuthInteractionAdapter`, `waitForOwner`는
사용자가 인증을 완료할 때까지 기다리는 함수다. 구현 계약과 로컬 headed-browser adapter는
[auth-interaction.ts](../src/runtime/auth-interaction.ts)를 참조한다. 원래 실행의 PostgreSQL 설정과
live-test profile·checkpoint가 필요하다. 이미 완료된 phase와 봉인된 입력은 재사용한다.
