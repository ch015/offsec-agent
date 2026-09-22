# OffSec defect closure audit

> **이전 기록 — 2026-09-22 안내 갱신.** 본문의 설계·명령·경로·수치와 완료 표시는 작성 당시 기록이며 현재 지원 범위를 보장하지 않는다.
> 현재 상태: [문서 안내](README.md) · [현재 실행 안내](../README.md)

- Scope: CH015 comparison에서 확인된 source inventory, methodology visibility, Live DAST evidence, IaC applicability, work-unit retry 결함.
- Contract: `nunchi.offsec.assessment@1.10.0`; 계약 리소스는 hash-pinned 상태다.
- Architecture: 기존 단일 host orchestration plane을 유지했으며 별도 agent orchestrator, queue, policy service를 추가하지 않았다.

## Closed defects

Parser가 지원하는 source extension을 manifest 구성과 일치시켰고, exact-read source test가 그 집합을 검증한다. 분석 역할은 공통 및 VA 방법론 리소스를 계약을 통해 전달받으며 Pentest 방법서는 broker가 허용하는 cleanup-bound reversible state change와 일치한다.

Live-confirmed Pentester Finding은 `pentest`와 `pentest-feedback`에서만 제출할 수 있다. 선행 plan/discovery 단계에서 confirmed Finding을 제출하거나 기존 record를 최종 감사까지 우회시키는 경로는 fail closed다. Adaptive receipt는 승인된 profile, plan, scenario, primary receipt 및 child control lineage에 결속된다. Differential oracle는 비교 response field, equal/different 관계, actor/query/body 중 허용된 단일 request delta를 명시해야 한다. Actor-only는 서로 다른 non-null sealed session을, query/body-only는 동일 actor를 요구한다. Empty query, object key order, query-in-path, unrelated receipt 및 동일 HTTP request를 차등 증거로 인정하지 않는다.

IaC manifest는 Terraform HCL/JSON/tfvars JSON, Kubernetes YAML/JSON, CloudFormation YAML/JSON, Bicep, Pulumi, Ansible과 기존 container/CI/deployment 형식을 content-aware하게 분류한다. 실패한 병렬 work unit은 격리된 새 attempt directory에서 한 번만 순차 재시도되고, 재실패 시 기존 fail-closed barrier를 유지한다.

## Independent reliability review

별도 세션은 기존 구현 결론을 전제로 하지 않고 반례를 우선 탐색했다. 이 과정에서 feedback phase 누락, 비-live Pentester phase 우회, 무관한 negative control, 비교 predicate 부재, null-session actor 차등, empty-query 및 query-in-path 동일 요청 우회를 발견했고 모두 회귀 테스트와 함께 수정했다. 최종 재검토는 지정 반례가 폐쇄됐고 정상 상대 경로와 동일 출처 절대 경로가 유지된다고 판정했다.

Provider 종료 훅과 호스트 reservation commit의 순서도 별도 검토했다. 실제 loopback 실행에서 provider 종료 훅이 호스트 commit보다 먼저 실행되어 이미 생성된 VA 산출물을 `AGENT_ARTIFACT_WITHOUT_COMMIT`으로 오탐하는 순서 경쟁을 재현했다. 종료 훅은 이제 기대 산출물과 일치하는 pending reservation을 `PENDING_HOST_COMMIT` 경고로만 기록하고, 호스트가 phase 반환 직후 commit과 무결성 재검사를 수행한다. reservation이 없거나 기대 산출물과 일치하지 않는 산출물은 기존처럼 fail closed다.

Verifier objection 산출물도 실제 YAML과 typed 원장을 대조했다. YAML `>` block scalar가 문장 끝에 추가하는 terminal newline 때문에 의미가 같은 objection이 불일치로 거부되는 직렬화 결함을 재현했다. 비교기는 trailing block-scalar newline만 제거하고 필드·내용·개수는 그대로 일치시킨다. 임의의 내부 내용 변경이나 원장에 없는 objection은 계속 거부한다.

## Claim and context boundaries

이번 결과는 deterministic contract enforcement와 local test coverage의 개선이다. 서로 다른 session ID는 서로 다른 봉인 자격증명 컨텍스트임을 증명하지만, 외부 인증 제공자가 두 토큰을 실제로 서로 다른 사람에게 발급했다는 의미까지 증명하지 않는다. 그 주장은 provider-side subject pseudonym 또는 사용자 확인이 추가로 있어야 한다.

실제 외부 OAuth, wallet provider, 고객 테스트 URL 및 live model 품질은 이번 검증에서 실행하지 않았다. CH015 대비 탐지 recall, precision 또는 설득력의 우세도 labeled corpus 비교가 아직 `not_run`이므로 주장하지 않는다. 방법론 파일의 가시성은 확대했지만 phase별 source/finding input 경계와 독립 worker session은 유지해 이전 Finding이 독립 분석 결론으로 오염되는 경로를 새로 만들지 않았다.

## Verification record

집중 Vitest, TypeScript typecheck, loopback Live DAST 통합 테스트, 전체 host/vendor regression, contract resource manifest check 및 `git diff --check`를 실행했다. 이번 race 수정은 agent-plan/on-stop 회귀 30개, 관련 Vitest 2개 파일, TypeScript typecheck 및 전체 vendor regression을 통과했다. 수정 이전에 시작된 Live DAST 실행은 종료 훅 순서가 고정되지 않았으므로 benchmark 관측에서 제외하고, 수정 후 새 engagement에서 재검증한다. 기존 `src/runtime/missions/assess.ts`와 통합 test 파일은 각각 500줄 정적검사 입력 한도를 초과하는 구조적 부채이며, 이번 결함 수정에서 새 제어면을 추가하지 않기 위해 광범위한 mission 분해는 수행하지 않았다.

## Reproduced contract mismatches

수정 후 #8 loopback 실행에서 `05_pentest_plan.json`이 실제 source-plan 모델 출력(POST/PATCH/PUT, `safety: "safe"`, `sourceEvidence`)과 legacy host schema(GET/HEAD, `ready|not_executable`, strict key set) 사이에서 거부되는 것을 재현했다. plan schema는 canonical HTTP method 집합을 사용하고 `safe`는 입력 전용 `ready` migration alias로만 수용하며, source evidence(`file`+`line|lines`+optional `sink`)를 명시적으로 검증한다. legacy root scenario의 query는 typed request의 query로 분리하고, body/cleanup이 없는 비-읽기 항목은 실행하지 않는 inventory로 보수적으로 유지한다. `offsec-live-test.test.ts`의 회귀 테스트와 contract resource manifest 재생성으로 검증했다.

#9 loopback 실행에서는 위 schema 수정 후 VA·verify·pentest-plan·discovery·pentest가 통과했고, discovery/pentest에서 75개 proposal 중 38개 승인, 37개 실행 receipt, 1개 inconclusive, 상태변경 cleanup 성공을 기록했다. 이후 `pentest-verify`에서 host contract가 요구하는 `06a_pentest_verify_result-1st.md`와 CH015 `verify-invariants` write whitelist가 충돌하는 별도 결함을 재현했다. verifier 결과·objection 산출물 두 패턴을 whitelist에 추가하고 dedicated node test를 통과시켰다. #9의 최종 report는 이 hook 수정 이전 실행이므로 완료/우세 benchmark로 사용하지 않는다.

#10 loopback 실행(`/private/tmp/offsec-live-juice-shop-19.1.1-20260806-10`)에서는 위 whitelist·objection 직렬화·legacy plan migration 수정이 실제 VA/verify 경로에서 통과했다. source manifest는 commit `b76448945fc2b51438874a2cb8938b6c3daf8218`, live profile SHA-256은 `3bfccfd2e83f96eac539533247e5f1ad61c94138f53afaeb8a1be157acfe3d1f`, 컨테이너는 `127.0.0.1:3001`의 Juice Shop `19.1.1`로 확인됐다. VA 1차, verify 1차, feedback/verifier 2·3차까지 모든 필수 산출물이 host seal을 통과했지만, 3차 verifier가 `F-013`의 basket 소유권 누락 범위를 `routes/coupon.ts`와 `routes/order.ts`까지 확장해야 한다는 `scope_incomplete` objection 1건을 남겼다. 계약의 feedback 상한(2회) 뒤 fail-closed로 run을 차단했으며, objection을 임의 병합하거나 pentest를 우회 실행하지 않았다. `live-scenario-journal`·HTTP receipt·pentest 산출물은 생성되지 않았다. 따라서 #10은 계약·회귀 검증에는 유효하지만 live DAST benchmark/report는 `blocked`로 기록하고, 동적 단계의 성공 증거로 사용하지 않는다.

#11 provenance-bound paired smoke(`/private/tmp/offsec-benchmark-smoke-19.2.1-20260807`)는 계획에 고정한 Juice Shop commit `3b178fd07b9f754c9d444d818448cfe58168943f`에서 다시 생성한 461-file source manifest(`8d9f2ceb2d7c247f327cfdfc63dba90af950b868f3269e631f2c3a8f7592a61e`)와 7-label pilot corpus(`7d8efd8fc978c7965d931d202ac403d32dca446d52b66217ae1530e11a83e18a`)를 사용했다. `pnpm eval:offsec:prepare-pilot -- /Users/philip/workdir/benchmarks/juice-shop /private/tmp/offsec-pilot-19.2.1.3Lg2YQ` 결과는 revision·파일 수·manifest/corpus hash가 위 값과 일치했다. seeded dry-run은 `current-sequential` execution order 0, `ch015` order 1을 고정했다. 실제 1회 paired smoke에서 current arm(`run-c535e40b24339ca20b01`)은 VA·verify 및 2·3차 feedback/verifier를 모두 host-seal했지만 3차 verifier가 wallet balance inflation의 `missing_finding` objection 1건을 남겨 feedback 상한에서 exit code 1로 fail-closed 됐다. 따라서 current arm에는 normalized findings를 생성하지 않았다. CH015 arm(`run-050fbb8b58282950616d`)은 exit code 0, 12개 normalized findings와 7-label ground-truth에 대해 adapter source-evidence 검증을 통과했다. 두 arm의 target 461개 파일과 모든 run-record artifact receipt는 해시/바이트 재검사에서 불일치 0건이었다. 이 결과는 실제 paired smoke 및 CH015 source 관측의 증거지만, current normalized observation이 없고 단일 validation case/반복 1회이므로 scoring·superiority claim에는 사용하지 않는다. 본 실행은 Live DAST가 아닌 source-only large-repository pilot이며, 이전 19.1.1 loopback profile과 버전·commit을 혼합하지 않는다.
