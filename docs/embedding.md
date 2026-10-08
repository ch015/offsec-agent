# 앱 내장 API

기준: 2026-10-07. Node.js 22.18 이상 ESM 환경에서 `pnpm build:library`로 빌드한 패키지를 연결합니다. import는 서버나 worker를 시작하지 않습니다. `dist`의 도메인/템플릿 리소스를 함께 배포합니다.

```js
import { createOffsecAgent } from 'secops-offsec-agent';

const controller = new AbortController();
const agent = createOffsecAgent({
  apiKey: process.env.ANTHROPIC_API_KEY,
  onEvent: event => console.log(event),
  // maxConcurrency 생략: 진행·자원을 관측해 동적으로 증감
  defaults: { costPolicy: 'record-only' },
});
const result = await agent.run({
  target: '/srv/project', mode: 'ast', tools: ['semgrep'],
}, { signal: controller.signal });
console.log(result.status, result.coverage, result.finalReport);
// 취소: controller.abort()
// 재개: await agent.resume(result.engagementDir)
```

`apiKey` 대신 `sessionRunner(SessionSpec): Promise<SessionOutcome>`를 주입할 수 있습니다. 테스트용 runner도 실제 전달 영수증과 파일별 분석 계약을 충족해야 완료 처리됩니다. 키·cwd·환경을 실행 인스턴스 사이에 공유하거나 변경하지 않습니다. `onProgress`, `onLedger`, `onStderr`, `onMetrics`, `onEvent`를 제공하며 callback 예외가 진단을 중단시키지 않도록 앱에서 처리합니다.

`status`는 필수 범위 완료와 발행을 모두 충족하면 `published`, 나머지는 `incomplete`입니다. `publicationStatus: published`인 부분 보고서도 있을 수 있으므로 반드시 `status`와 `coverage`를 함께 확인합니다. `filesDelivered`는 검증된 도구 반환 내용, `filesValidatedReuse`는 이전 분석을 검증해 재사용한 파일입니다. `semanticCoverage: not-proven`은 모델의 이해도나 취약점 부재를 증명하지 않는다는 의미입니다.

기본 금액 정책은 record-only입니다. 제한은 `costPolicy: 'enforce', maxBudgetUsd: 100`처럼 명시합니다. `maxBudgetUsd` 숫자만으로 제한이 켜지지 않습니다. 재개에도 명시적 enforce가 없으면 기록 전용입니다. 늦게 수신한 비용 영수증은 실패 결과와 분리해 멱등 반영하고, 영수증 없는 지출은 unknown으로 유지합니다.

동시성 기본 상한은 없습니다. `maxConcurrency: 3`은 실제 점유 상한이며 취소 처리 중인 작업도 포함합니다. 작업 용량 기본값은 `maxFilesPerAgent: 24`, `maxSourceTokensPerAgent: 24000`입니다. 호스트가 큰 파일의 범위 작업과 연결 검토를 생성합니다. 프로세스 공유 admission과 provider backoff를 사용하며, 다중 호스트 quota는 별도 조정이 필요합니다.

`mode: 'ast'`, `tools: ['semgrep']`이면 기본 required입니다. `semgrepMode: 'best-effort'`를 명시하면 도구 실패를 제한사항으로 기록합니다. `tools: []`는 Semgrep을 사용하지 않습니다. 필수 도구 실패는 Scanner를 포함한 모델 호출 전에 반환됩니다.

`engagementDir`를 생략하면 대상 밖의 독립 디렉터리를 할당합니다. 명시할 때는 새/빈 절대경로가 필요합니다. 같은 디렉터리의 동시 실행은 CLI/API/직접 mission 호출에서 공통 잠금으로 거부합니다. 취소·입력·무결성 오류는 예외, 복구 가능한 실행 실패는 부분 보고서와 incomplete로 전달됩니다.

`agent.resume(dir)`는 기존 스냅샷으로 미완료 작업만 재개합니다. 원본 작업 트리를 바꿔도 기존 스냅샷은 바뀌지 않습니다. 변경 소스를 분석하려면 새 결과 디렉터리로 `agent.run({ target, reuseFrom: dir })`을 사용합니다. 동일 계약·범위·근거와 변경 영향이 검증된 작업만 재사용하고 검토 단계는 새로 수행합니다. 기존 결과는 덮어쓰지 않습니다.

기본 상태 저장소는 file입니다. `runtime: { backend: 'postgres', pool, artifactStore, sharedEngagementRoot }`로 PostgreSQL을 사용하며 재개 시 원래 backend를 유지합니다. [저장과 복구](analysis-storage-recovery.md)를 참고하세요. v1 실행과 `resumeAssessOwnerAuth`는 제거됐습니다. 과거 자료는 읽기 전용 역사 기록으로 유지합니다.
