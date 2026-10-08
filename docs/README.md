# OffSec 문서 안내

기준: 2026-10-07. [프로젝트 README](../README.md). 이 문서와 아래 가이드는 이 저장소만 clone한 환경을 기준으로 한다.

## 현재 지원 범위

- Scanner 기반 계획 → 동적 Analyzer → 독립 Review/보완 → Evaluate → Report의 단일 실행 경로입니다. v1 실행은 제거됐습니다.
- CLI/API/재개는 같은 계약과 잠금을 사용합니다. HTTP 게이트웨이는 포함하지 않습니다.
- 기본 비용 정책은 record-only입니다. 명시적 enforce가 있어야 금액 제한을 적용합니다.
- 실제 내용 전달·파일별 분석·검증된 재사용·미완료 상태를 분리합니다. 변경 소스 재사용은 새 실행에서 명시적으로 선택합니다.
- 외부 결과 디렉터리, 파일/PostgreSQL 원장, lease, artifact archive와 부분 결과 재개를 지원합니다.

과거 통합 플랫폼의 상위 `docs/`, 앱 예제와 sibling Feedback decision registry는 이 배포에 포함되지 않는다.
현재 OffSec 사용법은 이 저장소의 문서를 따르고, 아래 역사 기록의 외부 자산명은 출처로만 읽는다.

## 현재 사용 문서

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
