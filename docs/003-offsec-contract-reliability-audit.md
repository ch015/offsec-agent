# OffSec 계약·컨텍스트 신뢰성 감사

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)

- 감사일: 2026-08-03
- 범위: `src/runtime/**`, `domains/offsec/**`, 관련 호스트·벤더 회귀 테스트
- 기준 계약: `domains/offsec/contracts/offsec-contract.v1.json` (`1.0.0`)
- 결론: 확인된 실행 계약 우회와 컨텍스트 오염 경로는 수정했다. 현재 정적·회귀 검증에서
  열린 차단급 Finding은 없지만, 실제 모델 대상 adversarial E2E와 confidence calibration은
  아직 검증되지 않았다.

## 확인 후 수정한 Finding

| 등급 | 확인된 문제 | 근거 | 수정·회귀 증거 |
|---|---|---|---|
| HIGH | 역할 문서가 단계 오케스트레이션까지 맡아 982줄로 팽창했고, 모델이 계약을 재해석할 수 있었다. | 구 `offsec-lead.md` 982줄, 기존 phase 방법론 5,017줄 | 호스트가 순서를 소유하고(`src/runtime/missions/assess.ts:167`), 실행 role card는 18~20줄, method card는 14~18줄로 제한했다. `src/runtime/__tests__/offsec-contract.test.ts:104`에서 크기를 고정한다. |
| HIGH | 계약 없는 OffSec 세션과 `bypassPermissions` 경로가 남아 있었다. | 구 `buildOptions()`는 phase 없이도 OffSec을 조립했다. | phase 없이는 거부하고(`src/runtime/session.ts:230`), 계약 `dontAsk`와 role별 `Options.tools`/`allowedTools`, `Agent`·`Bash` denylist를 적용한다(`src/runtime/session.ts:282-328`). `src/runtime/__tests__/session.test.ts:65-78`. |
| HIGH | 계약 세션의 untrusted scope에 `/ch015:*`가 있으면 레거시 명령 컨텍스트가 주입될 수 있었다. | `UserPromptSubmit`가 전체 prompt 문자열을 command로 재해석했다. | 계약 세션에서는 재해석을 중단한다(`domains/offsec/hooks/user-prompt.js:14-16`). 악성 scope 회귀는 `domains/offsec/hooks/test/contract-adapter.test.js:24`. |
| HIGH | SessionStart가 라이브 POC·폐기 command 메뉴를 계약 세션에도 주입했다. | 레거시 `session-start.js` 공통 context | 계약 ID가 있으면 phase/role과 trust boundary만 주입한다(`domains/offsec/hooks/session-start.js:11-18`). 회귀는 `contract-adapter.test.js:42`. |
| HIGH | 모델이 engagement 내부 임의 파일을 쓰거나 기존 engagement 원장을 덮어쓸 수 있었다. | 구 Write gate는 디렉토리 containment만 검사했고 host ledger는 truncate로 열었다. | 현재 phase의 직속 artifact 이름만 허용한다(`src/runtime/session.ts:423-442`). 기존 engagement는 거부하고 ledger를 exclusive create한다(`src/runtime/missions/assess.ts:146-152`). |
| HIGH | Finding JSON Schema와 런타임 Zod 스키마가 이중 정의되어 드리프트할 수 있었다. | 구 `findingSchema`와 `StandardFindingSchema` 수동 복제 | 계약 JSON Schema에서 런타임 validator와 MCP 입력 필드를 직접 생성한다(`src/runtime/finding-contract.ts:54-75`). file:line quote는 호스트가 재대조한다(`finding-contract.ts:96-114`). |
| MEDIUM | plugin 전체 읽기가 가능해 계약 역할이 5천 줄 레거시 방법론과 상충 지시를 다시 읽을 수 있었다. | 구 Read allowlist에 `pluginPath` 전체 포함 | host 전용 skill만 preload하고, model Read는 현재 method file만 예외 허용한다(`src/runtime/session.ts:241-244, 390-400`). 레거시 skill 거부 회귀는 `offsec-contract.test.ts:271`. |
| MEDIUM | scheduler role, lead role, 최종 report 파일명이 호스트에 별도 하드코딩돼 계약과 어긋날 수 있었다. | 구 `PHASE_RESERVATION`, `entryRole`, report 상수 | `reservationRole`, `leadRole`, `publication`을 계약으로 이동하고 loader가 참조·DAG·artifact 경로를 검증한다(`src/runtime/offsec-contract.ts:88-166`). |
| MEDIUM | 기존 engagement 재실행과 날짜 단위 ID가 충돌해 산출물 유실 또는 혼합 가능성이 있었다. | 일 단위 ID와 `writeFileSync(..., '')` | millisecond ID, 비어 있지 않은 engagement 거부, `wx` ledger를 적용했다(`src/runtime/missions/assess.ts:91-94, 146-152`). |

## 컨텍스트 오염·편향 셀프 검토

### 앵커링과 confirmation bias

- verifier는 별도 top-level 세션이며 VA 내용을 읽기 전에 autonomous artifact를 써야 한다.
  순서는 vendor invariant hook과 phase card가 함께 강제한다.
- VA/Verifier/Pentester 결과는 lead role에서 독립 주장으로 취급한다. 먼저 나온 결론,
  높은 severity, 상세한 문장은 증거로 인정하지 않는다.
- 한계: autonomous artifact의 질과 누락률은 모델 의존적이다. 실제 모델로 순서 교란·VA
  문구 강도 변화 A/B eval을 아직 실행하지 않았다.

### 자기과신과 calibration

- `supported`와 `unsupported`는 실제 파일·줄·정확한 quote 없이는 제출되지 않는다.
  증거가 없을 때 사용할 `abstain`·`escalate`·`unresolved` 상태를 계약에 둔다.
- phase의 `findingCount`는 MCP가 수락한 원장 수와 같아야 다음 단계로 간다.
- 한계: `confidence` 0..1 범위만 기계 검증하며 확률 calibration 자체는 검증하지 않는다.
  severity·impact의 의미 판단도 LLM과 report gate에 남는다. 따라서 현재 confidence를
  경험적 확률이나 SLA로 해석하면 안 된다.

### prompt/context poisoning

- 사용자 scope와 대상 저장소 내용은 data로 표시하고 경로 문자열은 JSON encoding한다.
- project/user settings, 외부 MCP, auto-memory, 임의 부모 환경변수 상속을 차단한다.
- 계약 전용 skill, role card, method card만 실행 경로에 넣고 레거시 slash-command context와
  plugin 문서 Read를 차단한다.
- 한계: 대상 코드와 이전 phase artifact의 자연어가 모델 판단에 미치는 영향 자체를 완전히
  제거할 수는 없다. 호스트의 control flow·capability·evidence gate가 피해 범위를 줄이는
  구조이며, 형식적 non-interference 보장은 아니다.

### 과잉 통제 여부

- raw Bash·네트워크·Agent를 모두 제거한 것은 v1 안전성에는 유리하지만 Semgrep/AST,
  의존성 조회, 실제 POC를 막아 recall과 실행 타당성 검증을 낮춘다. 그래서 현재 pentest와
  red-team 결과는 정적 설계로만 표기한다.
- artifact를 engagement 직속 계약 파일로만 제한해 임시 scratch 파일도 쓸 수 없다. 이는
  재현성과 SoD를 우선한 선택이며, 필요 시 임시 저장을 넓히지 말고 host-owned typed broker와
  별도 scratch 계약을 추가해야 한다.
- 최대 feedback 2회와 전체 예산 상한은 무한 반복을 막지만 어려운 대상에서 조기 종료될 수 있다.
  `blocked`/`unresolved`를 실패 은폐가 아닌 정상 결과로 유지해야 한다.

## 연구·표준 대조

- [Claude Agent SDK permissions](https://code.claude.com/docs/en/agent-sdk/permissions): deny가
  permission mode보다 먼저 적용되고 `dontAsk`는 미승인 도구를 거부한다. 이에 맞춰
  availability allowlist, auto-approval list, denylist, PreToolUse를 분리했다.
- [Claude sandboxing](https://code.claude.com/docs/en/sandboxing): sandbox는 Bash와 자식
  프로세스에 적용되고 permissions와 상호 보완적이다. 모델에 Bash가 없더라도 sandbox를
  fail-closed로 유지하되 Read/Write는 hook으로 별도 검증한다.
- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813): 불신 데이터가
  program flow를 결정하지 못하게 control/data flow와 capability를 분리한다. 본 구현의
  host-owned phase machine과 typed finding tool은 이 방향을 따르지만 형식적 증명 구현은 아니다.
- [Lost in the Middle](https://aclanthology.org/2024.tacl-1.9.pdf): 긴 컨텍스트에서 정보 위치에
  따라 성능이 저하될 수 있다는 실험 결과를 근거로 실행 prompt와 method card를 축소했다.
- [NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence):
  confabulation과 유효성·신뢰성 위험에 대응해 증거 재대조, abstention, 독립 검증, 원장을 둔다.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/download/52117/?tmstv=1765059207):
  goal hijack, tool misuse, 과도 권한, memory/context poisoning을 계약 deny와 context 격리 점검 항목으로 사용했다.

## 검증 기록

- `pnpm typecheck`: 통과.
- `pnpm test`: host test 5개 파일 전체 통과.
- `node --test domains/offsec/hooks/test/contract-adapter.test.js`: contract context 회귀 통과.
- `pnpm test:all`: 최종 변경 후 통과. TypeScript 검사, host 38건, vendor 430건과
  5개 self-test 묶음이 모두 성공했다.
- `asx review <file>`: 핵심 TS/JS/JSON/Markdown 변경 파일 17개 정적 검사 통과.
- 미실행: 실제 유료 모델을 사용한 full assessment와 adversarial A/B eval. 로컬 검증은
  fake session state machine, SDK option 조립, hook subprocess, evidence filesystem gate 수준이다.
