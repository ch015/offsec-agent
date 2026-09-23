# OffSec lease 호환성 검증 — 2026-09-23

[현재 지원 범위](README.md) · [저장·복구·재개](analysis-storage-recovery.md)

독립 `postgres-run-lease.sql`의 테이블에는 `updated_at`이 없다. release에서 이 컬럼을 갱신하면 해제가 실패하고 다음 실행이 기존 lease 만료까지 차단될 수 있었다. 해제 시 `expires_at`만 갱신하도록 수정했다. 행과 fencing token은 유지하며 이전 소유자가 새 소유권을 해제하지 못한다.

Node 22.18.0에서 lease 단위 검사 3개, 실제 임시 PostgreSQL 검사 8개, 타입 검사와 라이브러리 빌드를 통과했다. [새 통합 검사](../src/runtime/__tests__/standalone-lease.integration.test.ts)는 최소 lease 스키마만 적용해 해제·재획득·fencing 증가·오래된 소유자 거부를 확인한다. Kit의 별도 설치본에서도 스크립트 모델로 OffSec 미션 실행을 확인했다.

이번 SQL 한 줄 수정 뒤 전체 OffSec runtime/vendor suite를 다시 실행한 것은 아니다. 이전 날짜의 전체 검사 수를 이번 결과에 합산하지 않는다. 실제 모델·운영 데이터·운영 DB 배포는 사용하지 않았다. 이 수정에는 추가 migration이 필요하지 않다.
