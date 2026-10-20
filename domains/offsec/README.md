# OffSec 도메인 자산

현재 실행 계약은 `contracts/offsec-contract.v2.json`의 2.1.0입니다. `assess`와 `assess:v2`는 같은 runtime을 실행합니다. v1 계약·역할·실행 진입점은 제거됐습니다.

역할은 Scanner, Analyzer, Reviewer, Evaluator, Reporter입니다. 역할 지시는 `roles/`, 방법 카드는 `methods/`, 해시로 고정한 분석 방법론은 `methodology/`에 있고 호스트가 계약에 따라 phase마다 명시적으로 로드합니다. `contracts/`에는 계약 JSON과 스키마만, `skills/`에는 SDK 플러그인 스킬 `offsec-contract`만 둡니다. 도구 목록만으로 파일/네트워크 권한이 생기지 않으며 정확한 읽기 허용 목록과 산출물 계약을 함께 적용합니다.

`lib/ch015/`, `methodology/`, `knowledge-base/`는 이식한 분석 방법론과 검증기입니다. 과거 pentest/redteam/verifier 방법론 문서와 대화형 명령·템플릿은 제거됐고 git 이력에서만 복원할 수 있습니다. 소스 진단 모델은 다른 에이전트를 호출하지 않으며 Bash/live 네트워크 실행 권한을 받지 않습니다.

`hooks/report-gate-hook.js`는 명시적으로 선언된 host draft 작성을 발행과 구분합니다. 최종 발행은 호스트의 분류·Finding·범위·무결성 게이트를 통과해야 합니다. 0개 Finding의 보고서도 실제 원장과 평가 결과가 일치해야 발행합니다.

현재 사용법은 [프로젝트 README](../../README.md), 저장·복구는 [안내](../../docs/analysis-storage-recovery.md)를 따릅니다.
