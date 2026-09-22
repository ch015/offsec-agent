# OffSec 입력·패키징 검수 기록

기준: 2026-09-22. [현재 지원 범위](README.md) · [코드 연동](embedding.md)

이번 반영은 이전 전체 검수에서 완료한 입력 검증·패키징 수정과 현재 안내 문서의 동기화다.
`semgrepMode`, `maxTurns`, `effort`를 실행 전에 확인하고 CLI 숫자를 부분 파싱하지 않는다.
설치된 SDK의 `xhigh`를 허용하며 잘못된 옵션이 스캔·모델 실행·출력 생성을 시작하지 않는지 확인했다.
회귀는 [공개 API 테스트](../src/api/__tests__/agent.test.ts)에 있다.

package의 files 포함 목록을 `dist`, `src`, `domains`, `templates`로 제한했다. 별도 tgz 소비 설치에서
native AST·JavaScript 실행·엄격한 TypeScript 소비를 확인했다. SDK·pg·Playwright는 지연 로딩되지만
설치 의존성은 유지된다. Feedback/SOC의 Zod-only 코어 조건을 OffSec에 적용하지 않는다.

2026-09-22 전체 검수의 일반 테스트 477개, 벤더 597개, self-check 103개가 통과했다.
타입·계약·라이브러리 빌드·고정 산출물 평가도 통과했다. 세 에이전트 합산 PostgreSQL 14개를
OffSec 단독 테스트 수로 표기하지 않는다. 실제 모델 호출·운영 배포는 수행하지 않았다.

기존 v2 기본 저장 경로·checkpoint 재개·예산 증액·부분 결과 보존은
[저장·복구](analysis-storage-recovery.md)를 따른다. 정책 문서 RAG는 Feedback의 별도 기능이며
OffSec에 같은 `knowledge` 등록 옵션을 추가한 변경은 아니다.
