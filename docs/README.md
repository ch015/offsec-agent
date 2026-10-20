# OffSec 문서 안내

기준: 2026-10-13. [프로젝트 README](../README.md). 이 문서와 아래 가이드는 이 저장소만 clone한 환경을 기준으로 한다.

## 구현 변경 전 확인

[개발 지침](../AGENTS.md)과 [현재 구현 지도](implementation-map.json)를 먼저 확인합니다. 지도는 핵심 기능별 진입점·연결 지점·계약·대표 테스트·보존할 동작·한계를 연결합니다. 현재 작업 트리를 기준으로 하며, 전체 함수 목록은 아닙니다. `plannedCapabilities`는 아직 구현 완료가 아닌 제안입니다.

```sh
pnpm check:implementation
pnpm check:implementation --feature review-feedback
pnpm test:regression
```

참조 검사는 실제 선언과 활성 테스트 제목이 존재하는지 확인합니다. 동작의 정확성이나 전체 호출 관계를 증명하지는 않습니다. `test:regression`은 지도에 연결된 테스트 파일을 중복 없이 순차 실행하며, 합성 provider와 임시 로컬 자료를 사용합니다. 파일별 병렬 실행에 따른 복구/발행 테스트의 디스크 경합을 줄이고 기존 테스트 시간 제한을 유지합니다. 실제 대상 진단이나 유료 모델 호출을 시작하지 않습니다. PostgreSQL 통합 테스트는 이 묶음과 별도로 실행해야 합니다.

변경 설명에는 기존 구현 위치, 재사용/수정 선택, 호출부·저장 자료·재개에 미치는 영향, 보존할 계약과 검증 결과를 기록합니다. 구현 경계나 테스트 이름을 바꾸면 지도도 같은 변경에서 갱신합니다. `pnpm test:all`에도 참조 검사가 포함됩니다.

## 현재 지원 범위

- Scanner 기반 계획 → 동적 Analyzer → 독립 Review/보완 → Evaluate → Report의 단일 실행 경로입니다. v1 실행은 제거됐습니다.
- CLI/API/재개는 같은 계약과 잠금을 사용합니다. HTTP 게이트웨이는 포함하지 않습니다.
- 기본 비용 정책은 record-only입니다. 명시적 enforce가 있어야 금액 제한을 적용합니다.
- 실제 내용 전달·파일별 분석·검증된 재사용·미완료 상태를 분리합니다. 변경 소스 재사용은 새 실행에서 명시적으로 선택합니다.
- 외부 결과 디렉터리, 파일/PostgreSQL 원장, lease, artifact archive와 부분 결과 재개를 지원합니다.

과거 통합 플랫폼의 상위 `docs/`, 앱 예제와 sibling Feedback decision registry는 이 배포에 포함되지 않는다.
현재 OffSec 사용법은 이 저장소의 문서를 따르고, 아래 역사 기록의 외부 자산명은 출처로만 읽는다.

## 현재 사용 문서

- [results-review.md](results-review.md) — 읽기 전용 결과 감사, 수동 이견/해소 이력, 범위 대조, 오프라인 품질 계산과 구현 범위
- [verification-handoff-20261008.md](verification-handoff-20261008.md) — 내부 진단 90% 목표, NodeGoat·DVWA 중지 상태, 알려진 문제, 새 세션 재검증 절차
- [agent-autonomy.md](agent-autonomy.md)
- [embedding.md](embedding.md)
- [validation-2026-09-23.ko.md](validation-2026-09-23.ko.md) — 독립 lease 스키마 수정·검증 범위
- [validation-2026-09-22.ko.md](validation-2026-09-22.ko.md) — 이전 입력 검증·패키징과 회귀 결과
- [detection-improvements.md](detection-improvements.md) — 독립 취약점 집계 변경, 기존 111개 비교의 한계, Precision/Recall 90%를 위한 상세 변경·검수 계획 (2026-10-08)
- [analysis-storage-recovery.md](analysis-storage-recovery.md) — 외부 저장·백업/복원·재개·예산 증액
- [도메인 계약과 이식 범위](../domains/offsec/README.md)

## 이전 기록

아래 문서의 명령·경로·수치·완료 표시는 작성 당시 기준이다. 이전 통합 플랫폼과 현재 분리 모듈의 지원 범위를 구분한다. 현재 동작은 위 안내와 실제 구현을 따른다.

- [001-output-contract-plan.md](001-output-contract-plan.md)
- [002-plugin-contract-findings.md](002-plugin-contract-findings.md)
- [003-offsec-contract-reliability-audit.md](003-offsec-contract-reliability-audit.md)
- [007-three-domain-readiness-baseline.md](007-three-domain-readiness-baseline.md)
- [008-readiness-gap-closure-audit.md](008-readiness-gap-closure-audit.md)
- [009-offsec-host-parallel-implementation-audit.md](009-offsec-host-parallel-implementation-audit.md)
- [010-live-dast-implementation-audit.md](010-live-dast-implementation-audit.md)
- [011-offsec-defect-closure-audit.md](011-offsec-defect-closure-audit.md)
- [012-compaction-identity-hardening-spec.md](012-compaction-identity-hardening-spec.md)
- [013-compaction-identity-hardening-plan.md](013-compaction-identity-hardening-plan.md)
- [014-compaction-identity-hardening-execution.md](014-compaction-identity-hardening-execution.md)
- [015-compaction-identity-hardening-audit.md](015-compaction-identity-hardening-audit.md)
- [016-compaction-identity-sonnet-review.md](016-compaction-identity-sonnet-review.md)
- [017-offsec-p0-scope-assurance-spec.md](017-offsec-p0-scope-assurance-spec.md)
- [018-offsec-p0-scope-assurance-implementation.md](018-offsec-p0-scope-assurance-implementation.md)
- [019-offsec-p1-p2-dependency-planning-spec.md](019-offsec-p1-p2-dependency-planning-spec.md)
- [020-offsec-p1-p2-implementation.md](020-offsec-p1-p2-implementation.md)
- [022-phase2-offsec-webhook-design.md](022-phase2-offsec-webhook-design.md)
- [026-ch015-porting-sync-plan.md](026-ch015-porting-sync-plan.md)
- [027-refactoring-design.md](027-refactoring-design.md)
- [028-refactoring-execution-plan.md](028-refactoring-execution-plan.md)
- [029-refactoring-midpoint-summary.md](029-refactoring-midpoint-summary.md)
- [031-final-measurement-report.md](031-final-measurement-report.md)
- [032-throw-severity-classification.md](032-throw-severity-classification.md)
- [033-workflow-v2-improvement-plan.md](033-workflow-v2-improvement-plan.md)
