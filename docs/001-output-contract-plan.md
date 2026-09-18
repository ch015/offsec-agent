# 산출물 역산 설계 계획

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)

> 상태: 핵심 계약 구현됨. 계약 정본은
> `domains/offsec/contracts/offsec-contract.v1.json`, typed loader와 phase-result 검증은
> `src/runtime/offsec-contract.ts`다. `src/runtime/finding-contract.ts`가 정본의
> `findingSchema`에서 런타임 검증기와 `submit_finding` 입력 스키마를 직접 만들고,
> Finding별 evidence를 파일시스템과 재대조한다. 아래는 설계 근거로 유지한다.

> 작성: 2026-08-03. `../nahonza-agents` 이식을 접고(`5e0ac7f`) 산출물에서 거꾸로 설계한다.
> 기존 코드는 출발점이 아니다. 참조가 필요하면 그때 grep 한다.

## 0. 이 계획이 지키는 것

이식 시도가 깨진 이유는 하나다. **SDK가 이미 주는 것을 다시 만든 자산을 옮기려 했다.**
그래서 이 계획의 핵심 제약은 역방향이다.

| SDK가 준다 — 만들지 않는다 | 우리가 쓴다 — SDK에 없다 |
|---|---|
| 도구 루프, 턴 관리 | Finding 계약(스키마) |
| `Read` / `Grep` / `Glob` | **증거 대조 게이트** |
| 서브에이전트(`Agent`), 플러그인 `.md` 페르소나 로딩 | `submit_finding` MCP 도구 |
| PreToolUse / PostToolUse 훅, 권한 | 원장(발행·거부·도구 발화) |
| 세션·스트리밍, `modelUsage` 회계 | 미션 진입점, 격리 옵션 조립 |

자체 tool loop, 자체 `file-read`/`grep-search`, 자체 서브에이전트 오케스트레이션,
멀티프로바이더는 **만들지 않는다.**

## 1. 산출물 계약 — Finding

최소 단위는 보고서가 아니라 **Finding**이다. 보고서는 Finding 배열의 렌더링이다.

```ts
Finding {
  id          // sha256(path + lineStart + title) 기반 12자리 숫자 — 재실행에 안정적
  contractVersion
  phase, role, round
  title
  verdict     // 'supported' | 'unsupported' | 'abstain' | 'escalate'
  severity    // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  confidence  // 0..1
  evidence    // Evidence[]
  impact
  remediation
  standards   // ['OWASP-A01', 'CWE-20']
  unresolved  // string[] — abstain 사유
}
Evidence { path, lineStart, lineEnd, quote }
```

불변식 세 개를 스키마와 게이트가 강제한다.

- **I1 증거 부합** — `quote`가 `file`의 `startLine..endLine` 실제 내용과 부합하지
  않으면 그 Finding은 발행되지 않는다. 위반은 원장에 남는다.
- **I2 증거 강제** — `verdict`이 `supported`/`unsupported`면 `evidence.length >= 1`이다.
  증거 없는 단정은 스키마에서 막힌다.
- **I3 모름의 자리** — 증거가 없으면 `abstain`(또는 `escalate`)이 **정답**이다.
  이 경우 `unresolved[]` 사유가 반드시 함께 온다.

I3이 이 설계의 핵심이다. LLM 진단의 제일 큰 실패는 모르는 것을 단정하는 것이고,
어휘에 `abstain`이 없으면 그 실패를 표현할 칸도, 평가할 방법도 없다.

## 2. 필드를 채우는 단서 — 검증자는 파일시스템이다

진단 대상은 로컬 리포지토리 경로다. 에이전트는 SDK 빌트인 `Read`/`Grep`/`Glob`으로
읽고, 인용을 **텍스트로 써서** `submit_finding`에 제출한다. 그 다음이 요점이다.

> 제출된 `quote`를 우리 코드가 `file`에서 같은 줄 범위를 **다시 읽어** 대조한다.

검증 주체가 다른 LLM이 아니라 파일시스템이다. 재검증 에이전트는 나중에 얹을 수 있지만,
지어낸 인용은 그 전에 이미 기계적으로 걸러진다. 이게 있어야 보고서에 신뢰도가 붙고,
eval도 사람 라벨 없이 돌아간다.

## 3. 페르소나와 도구 — 첫 스파이크

`nunchi-offsec:va-auditor` **1개**. 서브에이전트도 게이트도 없다.

프론트매터는 **SDK 규약으로 새로 쓴다.** nahonza 정본을 복사하지 않는다.
`tools:`가 없으면 부모 도구를 전부 물려받기 때문이다(`sdk.d.ts:44`).

```
tools: Read, Grep, Glob, mcp__nunchi__submit_finding
```

구조화 출력은 최종 텍스트를 JSON 파싱하지 않고 **MCP 도구 경계에서** 받는다.
도구 입력 스키마가 곧 Finding 스키마이므로 검증이 한 곳에서 일어나고, 모델이
어긋나면 도구 호출이 실패해 스스로 고친다.

## 4. 단계 — 파일 1개 = exit proof 1개 = 커밋 1개

| # | 파일 | exit proof |
|---|---|---|
| P1 | `src/domain/finding.ts` | zod 스키마. 유효/무효 픽스처 단위테스트, I2·I3 위반이 파싱에서 거부됨 |
| P2 | `src/domain/evidence-gate.ts` | 인용 대조. 일치 / 불일치 / 범위 초과 / 파일 없음 4케이스 테스트 |
| P3 | `src/mcp/nunchi/submit-finding.ts` | `createSdkMcpServer` 도구 1종. 도구 왕복 성공 + 지어낸 인용이 거부됨 |
| P4 | `domains/offsec/agents/va-auditor.md` | `supportedAgents()`에 `nunchi-offsec:va-auditor` 등록 (도구 제한 확증은 P6) |
| P5 | `src/runtime/session.ts` | Options 조립 + `settingSources: []` 고정. 격리 프로브에서 빌트인 5개만 보임 |
| P6 | `src/runtime/ledger.ts` | PreToolUse/PostToolUse 원장. **va-auditor가 Bash를 못 쓰는지 원장으로 확증** |
| P7 | `src/runtime/missions/assess.ts` | 실제 대상 1건 완주 → Finding 배열 + 원장 + `modelUsage` 기록 |
| P8 | 회귀 고정 | 같은 대상 2회 실행에서 게이트 통과율과 원장 형태가 안정 |

세션 묶기: **P1+P2+P3** / **P4+P5** / **P6+P7** / **P8**.
P1~P3은 API 호출 없이 단위테스트로 닫히므로 제일 싸고 제일 확실하다.

## 5. P6이 갚는 빚

이전 세션에서 못 밝힌 질문이 하나 남아 있다. 플러그인 `.md`의 `tools:`가 실제로
서브에이전트 도구를 제한하는지다. `supportedAgents()`가 `name`/`description`만
돌려줘서 그 경로로는 판정되지 않았다. P6의 원장이 이걸 닫는다 — `tools:`에 없는
`Bash`를 유도했을 때 PreToolUse에 발화가 잡히는지 보면 된다.

## 6. 나중

`abstain` 정답률을 재는 eval, 독립 재검증 에이전트, soc/ciso/feedback 도메인,
게이트웨이는 P7이 통과한 뒤에 붙인다. Finding 계약이 서면 전부 그 위에 얹힌다.
