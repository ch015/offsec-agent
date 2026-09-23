# OffSec 문서 안내

기준: 2026-09-23. [프로젝트 README](../README.md). 이 문서와 아래 가이드는 이 저장소만 clone한 환경을 기준으로 한다.

## 현재 지원 범위

- 공개 `createOffsecAgent` API와 로컬 CLI를 제공한다. HTTP 게이트웨이·SOC·Feedback 서비스는 포함하지 않는다.
- v1은 pentest/redteam/검증 흐름, v2는 병렬 단위 분석과 review/evaluate/report 및 조건부 교차 단위 후속 분석을 제공한다.
- v2는 checkpoint에서 재개하고 완료 단위를 재사용한다. 복구 가능한 실패는 근거와 부분 보고서를 보존한다. 증분 분석 캐시는 미제공이다.
- 기본 산출물은 타겟 밖 `~/.ch015/<레포>/<시간>_<커밋>_<UUID>/`에 저장한다. 현재는 파일/선택적 PostgreSQL 상태와 선택적 artifact store를 사용한다.
- SQLite `state.db`, 영구 Finding ID/diff 연계, Nunchi 자동 전송과 보관·삭제 정책은 후속 범위다.
- 기본 금액 상한은 없다. 명시한 금액 상한·턴·단위 timeout·취소·근거 무결성은 각 실행 규칙을 따른다.

과거 통합 플랫폼의 상위 `docs/`, 앱 예제와 sibling Feedback decision registry는 이 배포에 포함되지 않는다.
현재 OffSec 사용법은 이 저장소의 문서를 따르고, 아래 역사 기록의 외부 자산명은 출처로만 읽는다.

## 현재 사용 문서

- [agent-autonomy.md](agent-autonomy.md)
- [embedding.md](embedding.md)
- [validation-2026-09-23.ko.md](validation-2026-09-23.ko.md) — 독립 lease 스키마 수정·검증 범위
- [validation-2026-09-22.ko.md](validation-2026-09-22.ko.md) — 이전 입력 검증·패키징과 회귀 결과
- [detection-improvements.md](detection-improvements.md)
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
