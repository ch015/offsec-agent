# OffSec를 애플리케이션 코드에서 사용하기

문서 기준: 2026-09-21. [현재 기능과 한계](../../docs/development-status.ko.md) · [전체 앱 연동 예제](../../docs/embedding-agents.ko.md)

`src/index.ts`가 공개 진입점입니다. Node.js 22.18 이상 ESM 환경에서 기존 앱의 코드 의존성으로 연결합니다. Kit CLI·통합 tgz·프로젝트 YAML은 필요하지 않습니다.

```sh
pnpm install --frozen-lockfile
pnpm build:library
```

앱의 workspace 또는 pnpm `link:` 의존성으로 이 디렉터리를 연결합니다. 기본 package export는 컴파일한 `dist/src/index.js`와 타입 선언을 사용합니다. TypeScript 실행기를 쓰는 앱은 `secops-offsec-agent/source` export도 사용할 수 있습니다. `dist`의 도메인/템플릿 리소스를 함께 유지하세요.

```js
import { createOffsecAgent } from 'secops-offsec-agent';
const agent = createOffsecAgent({
  apiKey: secrets.anthropicKey,
  defaults: { maxBudgetUsd: 10, maxConcurrency: 2, maxFollowupHypotheses: 3 },
});
const result = await agent.run({
  target: '/srv/project', engagementDir: '/srv/results/job-123', scope: '인증 경계 검토',
}, { signal: controller.signal });
// result.status: published | incomplete; result.coverage와 finalReport 확인
```

예제의 secrets/config/controller와 업무 입력은 앱이 제공합니다. import는 서버나 worker를 시작하지 않습니다. 모델 키는 인스턴스에 주입하며 process.env나 cwd를 바꾸지 않습니다.

`maxConcurrency` 기본값은 2입니다. `maxFollowupHypotheses`는 기본 3, 0..8 범위이며 0은 후속 분석을 끕니다.
유효한 교차 단위 질문이 있을 때만 최대 32턴의 추가 분석 세션 한 라운드를 실행합니다.
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

같은 결과 디렉터리의 동시 실행은 거부합니다. 취소/실행 실패는 예외로 전달되며 이미 생성한 증거를 자동 삭제하지 않습니다. 이벤트 callback에서 예외를 던지지 않도록 앱에서 처리하세요.

v2 실행 중단 재개와 증분 분석 캐시는 아직 없습니다. 공개된 v1 recovery API와 구분하세요.
