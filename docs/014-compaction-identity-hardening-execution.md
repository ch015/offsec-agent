# Compaction identity hardening execution record

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

## Purpose

이 문서는 ASX package와 `.asx/` runtime state를 삭제해도 compaction-safe work-unit identity 개선 작업을 실행·감사할 수 있도록 계획, 이관, 오케스트레이션, 검증 상태를 보존하는 정본이다.

## Canonical artifacts

- Specification: `docs/012-compaction-identity-hardening-spec.md`
- Approved implementation plan: `docs/013-compaction-identity-hardening-plan.md`
- Execution and ASX disposition: `docs/014-compaction-identity-hardening-execution.md`
- Final implementation audit: `docs/015-compaction-identity-hardening-audit.md`

위 문서가 정본이다. `.asx/specs/compaction-identity-hardening.md`와 `.asx/plans/compaction-identity-hardening.md`는 docs 정본을 가리키는 임시 symlink일 뿐이며 삭제해도 정보가 손실되지 않는다.

## ASX data disposition

| ASX data | 필요 여부 | 이관 결과 |
|---|---:|---|
| compaction identity specification | 필요 | `docs/012-compaction-identity-hardening-spec.md`로 이관 |
| compaction identity implementation plan | 필요 | `docs/013-compaction-identity-hardening-plan.md`로 이관 |
| workflow state (`executing`, previous `approved`) | 필요 | 이 문서에 보존 |
| self-validation result | 필요 | 아래에 보존하고 plan에도 반영 |
| `.asx/goals/`, `.asx/artifacts/` | 불필요 | 사용자 산출물 없음 |
| `.asx/graph.db`, `capabilities.json` | 불필요 | 재생성 가능한 code graph/capability cache |
| `.asx/skills/`, `.managed.json` | 불필요 | package가 제공하는 설치형 workflow/skill 파일이며 프로젝트 산출물이 아님 |

따라서 이 작업은 더 이상 ASX CLI, workflow state, graph DB 또는 skill 파일에 의존하지 않는다.

## Planning and self-validation completed

- 실제 Opus/Haiku engagement 및 60개 SDK transcript에서 확인된 인과 범위에 맞춰 계획을 작성했다.
- Opus compacted session 6개 중 identity를 보존한 4개는 성공했고 누락한 2개는 mismatch로 실패했으며, 그중 `unit-7f423...` 실패가 final `run.blocked` barrier에 직접 포함됐다. 반면 Haiku는 compaction 없이 다른 계약 오류로 blocked였다. 따라서 compaction summary identity omission은 확인된 기여 원인이지만 유일·보편·전체 run의 단독 but-for 원인으로 주장하지 않는다.
- 기존 schema `const`와 prompt echo가 실제 run에서 identity mismatch를 막지 못했음을 전제로 host authority를 선택했다.
- 최초 안의 `workUnit` property 완전 제거는 strict `additionalProperties: false`에서 모델이 관성적으로 해당 필드를 출력할 때 host overwrite 전에 identity-only SDK retry를 재유발할 수 있음을 자체 검증에서 발견했다.
- 최종 계획은 `workUnit`을 optional·permissive·host-ignored placeholder로 제한하고, host가 domain validation 전에 canonical identity를 clone-bind하도록 수정됐다.
- One-shot PostCompact reminder, compact metadata의 provider/host-ledger/run-events 영속화, provider success/failure event transport, binding disposition audit, snapshot-neutral replay와 16개 acceptance criteria가 포함됐다.
- ASX workflow는 삭제 전 `approved`를 거쳐 `executing` 상태였다.

## Worktree constraints observed

- Repository: `/Users/philip/workdir/security-philip/nunchi/secops-nunchi-agent`
- Branch: `main`
- Runtime/source 파일 다수가 기존 uncommitted/untracked 상태였으므로 current worktree에서만 작업했다.
- 기존 unrelated dirty 변경을 보존했다.
- Reset, clean, checkout, revert, broad staging, commit, push를 수행하지 않았다.

## Orca orchestration trace

- Run: `run_a7cb6e2d7def`
- Objective: compaction-safe host-authoritative OffSec work-unit identity binding과 durable compaction telemetry 구현·검증 및 final audit 작성
- Initial task: `task_85da9c89cbec`
  - `.asx` 경로를 포함했으나 dispatch되지 않았다.
  - docs migration 후 superseded `failed`로 명시 종결했다.
- Docs-only replacement task: `task_3bc4510c58e7`
- Dispatch: `ctx_13dc663e4313`
- Worker terminal: `term_f96a1fac-0fd2-4802-815f-c2d74fc842c0`
- Worker command: `codex --model gpt-5.6-luna -c model_reasoning_effort="xhigh"`
- `worker-start --agent luna-xhigh`는 `agent_unconfigured`, `luna-xhigh` shell command는 `command not found`였다. Orca Codex model cache에서 actual model ID `gpt-5.6-luna`와 `xhigh` 지원을 확인했지만 high-level `worker-start` validator가 조합을 거부해 version-matched custom argv 경로를 사용했다.
- TUI ready 후 replacement task를 `dispatch --inject`했고 `task-list`와 `dispatch-show`에서 provenance를 확인했다.
- Worker result: `worker_done outcome=succeeded`
- Task result: `task_3bc4510c58e7` `completed`
- Dispatch result: `ctx_13dc663e4313` `completed`, failure count `0`
- Worker report message: `msg_16224e9703ae`
- Delivery: `delivery_6f130ba76461`, acknowledged successfully (`ok: true`, acknowledged ID 일치, pending message count `0`)
- Low-level custom terminal에는 `worker-start` resource record가 없어 `worker-release`가 `dispatch_not_found`를 반환했다. Task/Dispatch settlement 확인 후 exact terminal handle을 `orca terminal close`로 정상 종료했다.

## Implementation outcome

Luna xhigh worker가 다음 동작을 구현했고 coordinator가 실제 코드와 테스트를 교차 확인했다.

- Provider schema의 `workUnit`을 optional `{}` placeholder로 만들고 surrounding strictness를 유지했다.
- Host가 adapter validation 전에 canonical `resultIdentity`를 clone-bind하며 raw provider identity를 `absent|matched|overridden`으로 audit한다.
- Work-unit `PostCompact` 후 다음 `PreToolUse`에 canonical identity를 one-shot으로 추가한다.
- Compact summary/source text 없이 typed boundary metadata만 session/provider/run events로 전달한다.
- Provider failure에도 이미 수집한 compaction events를 보존한다.
- `phase.context-compacted`와 `phase.result-identity-bound`는 shared schema의 additive, snapshot-neutral audit events다.
- Final audit: `docs/015-compaction-identity-hardening-audit.md`

## Coordinator independent validation

Worker 보고를 그대로 수용하지 않고 current worktree에서 다음을 독립 재실행했다.

```text
Targeted Vitest: 6 files passed, 72 tests passed
pnpm typecheck: passed
contract resource manifests: in sync
pnpm test:vendor: 554 passed, 0 failed, 0 skipped
git diff --check: passed (no output)
```

Full command도 독립 재실행했다.

```text
pnpm test:all: exit 0
Host Vitest: 48 files passed, 1 skipped; 302 tests passed, 6 skipped
Vendor: 554 passed, 0 failed, 0 skipped
live-dast.integration.test.ts: 2 tests passed
```

Worker sandbox에서 최초 `pnpm test:all`은 `live-dast.integration.test.ts`가 `listen EPERM 127.0.0.1`로 실패했지만 coordinator 환경 재실행에서는 해당 suite를 포함해 모두 통과했다. 최초 실패는 당시 실행 환경 관측으로 audit에 보존하되 현재 worktree의 최종 독립 regression 상태는 green이다.

## Evidence boundary and completion status

Deterministic implementation, targeted regression, typecheck, resource check, full host/vendor regression, diff check, Orca settlement, terminal closure, Delivery acknowledgement를 확인했다. Live provider/model compaction smoke는 실행하지 않았으므로 model-quality 개선이나 production closure는 주장하지 않는다. 구현·검증·추적 산출물 완료 조건은 충족했다.
