# Compaction-safe work-unit identity specification

> **이전 기록 — 2026-09-18 현행화 메모.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [개발 현황](../../docs/development-status.ko.md) · [현재 실행 안내](../README.md)
> Canonical specification artifact. This document has no ASX runtime dependency.

## Problem

실제 Orca Juice Shop Opus run에서 auto compaction summary가 immutable work-unit identity를 누락했고, 모델이 다른 SHA를 StructuredOutput에 반환해 host identity validation과 terminal work-plan barrier가 실패했다. Compacted sessions 중 identity가 보존된 4개는 완료되고 누락된 2개는 실패했다. Haiku는 compaction 없이도 blocked였으므로 이 변경은 모든 blocked 원인을 다루지 않는다.

## Goal

Work-unit identity의 정확성을 모델 context, compact summary, 모델 복사 및 structured-output retry에서 분리하고 host가 authoritative하게 결속한다. Compaction 발생 사실과 bounded metadata는 engagement ledger/run events에 남겨야 한다.

## Scope

현재 repository의 OffSec work-unit execution path만 변경한다. Provider-facing output schema, Anthropic SDK session event capture, provider failure event transport, WorkflowHost canonical identity binding, run-state audit event schema와 관련 regression tests/documentation이 범위다. Haiku에서 관측된 artifact/count/objection 계약 실패, 모델 품질 비교, 새 orchestration service는 범위 밖이다.

## Requirements

1. Host request의 `workUnitKey`, `workPlanSha256`, `assignedSourceSha256`가 stored phase result의 유일한 authoritative identity다.
2. 모델이 identity를 생략·오류·malformed로 반환해도 identity만을 이유로 SDK retry 또는 phase failure가 발생하지 않아야 한다.
3. Identity 이외의 schema, artifact, method, finding/objection ledger, usage 및 barrier validation은 기존처럼 fail closed여야 한다.
4. Compaction 이후 모델이 후속 도구 작업에 identity를 필요로 할 때 bounded one-shot reminder를 제공해야 한다.
5. Compact boundary의 trigger와 token/duration/boundary metadata를 host ledger와 run events에 기록해야 한다.
6. Compact summary 본문, source content, user prompt는 새 telemetry에 저장하지 않아야 한다.
7. Provider success와 receipt를 가진 provider failure 모두 가능한 compact events를 보존해야 한다.
8. Host identity binding이 provider identity를 absent/matched/overridden 중 무엇으로 처리했는지 audit event를 남겨야 한다.

## Compatibility requirements

- Root/non-work-unit phase와 다른 domain은 변경하지 않는다.
- 기존 run-events는 migration 없이 replay되어야 한다.
- 새 audit events는 status, cost, completed phase, artifacts를 변경하지 않는다.
- File/PostgreSQL backend의 기존 state append/lease fencing 경계를 유지한다.
- 새 dependency, transcript filesystem dependency, contract version bump를 기본적으로 도입하지 않는다.

## Acceptance Criteria

Deterministic unit/integration regressions으로 missing/exact/wrong/malformed identity, no-tool-after-compaction, provider failure event preservation, snapshot-neutral replay를 검증한다. Typecheck, contract resource check, full `pnpm test:all`, `git diff --check`를 실행하고 결과를 final audit 문서에 기록한다. Live compaction smoke를 실행하지 못하면 그 한계를 명시하고 모델 품질 개선으로 과장하지 않는다.
