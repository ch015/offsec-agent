# domains/offsec — 취약점 진단 리소스

현재 구현 기준: 2026-09-18. [프로젝트 README](../../README.md) · [앱 코드 연동](../../docs/embedding.md).

Claude Agent SDK 로컬 플러그인이다. 호스트는 버전 계약을 읽어 역할별 `Options.agents`, 도구, 방법 카드와 스키마를 구성한다. 방법론/저수준 검증기는 CH015에서 이식한 뒤 현재 실행에 맞춰 보완했다. 원본 저장소를 런타임 의존성으로 사용하지 않는다.

## 실행 경로와 리소스

| 계약 | 미션 | 역할 | 흐름 |
|---|---|---|---|
| `contracts/offsec-contract.v1.json` | `assess` | va-auditor, verifier, pentester, redteam-reviewer, offsec-lead | VA/Verify, 조건부 수정·live Pentest·RedTeam, 수렴·보고 |
| `contracts/offsec-contract.v2.json` | `assessV2`, `createOffsecAgent().run()` | analyzer, reviewer, evaluator, reporter | host recon/plan, 병렬 analyze, review/evaluate/report |

계약의 `contracts/roles/*.md`와 `methods/*.md`가 호스트 세션의 역할·실행 방법 정본이다. 작업 단위 병렬 실행은 호스트가 조율하며 모델 사이의 자유로운 재위임은 허용하지 않는다. 역할 이름이나 메서드 파일 이름을 바꿀 때는 버전별 계약을 함께 확인한다.

`agents/*.md`, `commands/{va,verify,pentest,report,fix,redteam}.md`와 `skills/ch015/`는 직접 플러그인 호출과 이전 CH015 방법론을 위한 호환 자산이다. 모든 문서가 factory 미션에서 실행되는 것은 아니다. 계약 세션에는 `skills/offsec-contract/SKILL.md`와 해당 phase의 방법/지식 리소스를 사용한다. 호환 자산의 CISO·수정·보고 경로 설명을 현재 v2 단계로 해석하지 않는다.

## 도구·증거·발행

도구 목록은 버전 계약의 role 정의와 `src/runtime/session.ts`의 실행별 제한을 따른다. 예를 들어 analyzer/VA/verifier 계약의 Bash는 제한된 명령 정책을 거치며, 작업 단위 실행은 Bash를 제거한다. pentester의 live 요청은 승인된 범위와 host typed broker를 사용한다. 도구 이름 목록만으로 파일·네트워크 실행 권한이 생기지 않는다.

호스트는 허용 파일·산출물 경로, phase 전이, source/checkpoint·artifact hash와 finding의 실제 파일·줄·인용을 확인한다. 동일 finding identity는 근거/심각도 보완 시 upsert할 수 있으므로 finding 파일을 append-only 원장이라고 부르지 않는다. 실행 이벤트와 산출물 이력은 별도로 관리한다.

모델은 `07_security_report.draft.md`를 작성한다. 호스트가 scope·증거·report gate를 통과시킨 뒤 최종 `07_security_report.md`로 발행한다. 부분 분석은 미검토 파일을 공개해야 하며, 검증 실패를 warning만 남기고 최종 발행하지 않는다.

## 훅과 실행 격리

`hooks/hooks.json`은 session 시작, pre-tool 정책·report gate, tool output 정리, stop 훅을 연결한다. `pre-tool-use.js`가 도구 접근 정책을 적용하며 host session의 SDK 훅과 함께 동작한다. `verify-invariants.js`, `on-finding.js`, `post-phase.js`, `budget-tracker.js`, `agent-plan-gate.js` 등 유틸리티는 파일 존재만으로 독립 lifecycle hook에 자동 등록되는 것은 아니다. 실제 연결은 hooks.json과 호출 코드를 확인한다.

호스트 세션은 `dontAsk`, `settingSources: []`, strict MCP, 자동 memory 비활성화, 제한된 환경변수와 sandbox 정책을 사용한다. 직접 plugin probe의 `bypassPermissions` 관측 기록을 현재 호스트 기본값으로 사용하지 않는다. 리포 루트는 ESM이고 이 디렉터리의 package.json은 벤더 코드 실행을 위해 CommonJS를 지정한다.

## 이식·검증 기록

미이식/대체/다른 도메인 소유 자산은 [decision registry](../../../secops-agent-feedback/docs/three-domain-decision-registry.json)의 `unportedAssets`에 기록한다. 이는 이식 당시 결정 기록이며, 현재 제품 기능은 프로젝트 README와 [개발 현황](../../../docs/development-status.ko.md)을 따른다.

리포 루트에서 `pnpm check:contracts`는 역할·방법 카드·스키마 등의 계약 리소스 hash를 확인한다. 계약 리소스를 수정하면 `pnpm generate:contract-resources`로 갱신한다. `pnpm test:all`은 계약·타입·호스트 회귀·벤더 및 self-test를 실행한다. `pnpm probe:offsec <대상 절대경로>`는 실제 SDK 플러그인 로드·도구 제한을 확인하는 별도 프로브다.
