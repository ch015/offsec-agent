# OffSec 탐지와 실행 비용 개선

문서 현행화: 2026-09-23. 아래 크기·시간 측정은 2026-09-21 개선 당시 기록이다. [코드 연동](embedding.md) · [행동 원칙](agent-autonomy.md)

## 탐지에 필요한 근거 전달

AST와 Semgrep의 입력은 봉인된 source manifest다. 별도로 저장소를 재탐색해 제외 파일을
분석하지 않는다. AST가 파일 수 상한에 도달해도 Semgrep은 봉인된 전체 파일 목록을 사용한다.
분석된 파일, 지원하지 않는 파일, parser 실패와 상한으로 생략한 파일을 구분한다.

AST가 만든 source→sink 후보를 Graph RAG에 그대로 전달한다. 인자 흐름·sanitizer·confidence·CWE와
중간 파일을 유지하며 후보를 확정 취약점으로 취급하지 않는다. 이전 형식에만 call-name 휴리스틱을
사용하고, 여러 함수가 같은 이름을 가지면 임의의 함수를 선택하지 않는다.

각 작업 단위는 `00_evidence_index.json`으로 관련 후보와 공백의 수를 확인한다.
상세 후보·진입점·데이터 흐름·Semgrep 결과는 `00_evidence_details.json`에서 필요한 때 조회한다.
색인에 일부 후보만 노출되더라도 상세 파일에는 관련 원본 기록을 유지한다.
모델은 정적 분석에서 후보가 없던 소스도 A1–A8 기본 점검을 수행한다.

## 제한된 자율 후속 분석

단위별 analyzer가 `02_analysis_handoff.yaml`에 미해결 교차 단위 질문을 제출할 수 있다.
호스트는 실제 소스 인용 일치, 서로 다른 작업 단위의 파일, 제출 단위의 소유 파일 포함 여부를
확인한다. 중복을 제거하고 모델이 기재한 영향도 순서로 질문을 선택한다. 의미적 중요도를
호스트가 증명하거나 취약점을 자동 판정하는 기능은 아니다.

| 설정 | 기본 동작 |
|---|---|
| `maxConcurrency` | 2; 계약 상한 16 이내 |
| `maxFollowupHypotheses` | 3; 허용 0..8, 0이면 후속 분석 비활성화 |
| 후속 분석 | review 전 root analyze 한 라운드, 최대 32턴 또는 더 작은 호출자 한도 |
| `maxBudgetUsd` 설정 시 | analyze 이후 30%, review 이후 10%, evaluate 이후 5% 예약 |

후속 질문이 없으면 별도 세션이 생기지 않는다. 기본 흐름은 작업 단위 수 N에 대해 N+3개
논리 세션이며 후속 분석을 선택하면 N+4개다. 출력 검증 재시도는 별도다.
예약 금액은 실제 SDK 사용량 회계에 적용되며 마지막 호출의 초과 청구까지 막는 결제 한도는 아니다.

`00_followup_plan.json`은 선택한 질문과 보류/무효 요청 수를 기록한다. 원래 질문은 해당 단위의
handoff 산출물에 남는다. 모델에는 동일 조사 반복, 전체 저장소 재진단, 재귀 후속 요청을 금지하고
질문의 confirmed/refuted/unresolved와 근거를 남기도록 지시한다.

## 작은 기본 컨텍스트와 선택형 설치

필수 analyze 방법론은 약 150.3 KiB/10개 파일에서 5.4 KiB/1개 카드로 줄였다.
카드에는 A1–A8 기본 점검을 유지하고 상세 방법론은 조사 중 필요할 때 조회한다.
이는 파일 바이트 수 비교이며 실제 토큰·요금 감소율이 아니다.

기본 소비 설치에는 tree-sitter 런타임과 JavaScript/TypeScript grammar가 포함된다.
다른 언어 grammar는 `package.json`의 선택형 peer dependency에서 골라 앱에 설치한다.
예를 들어 Python 대상에는 다음을 추가한다.

```sh
pnpm add tree-sitter-python@^0.23.6
```

선택형 grammar는 C, C++, C#, Dart, Elixir, Go, Java, Kotlin, Objective-C, PHP, Python,
Ruby, Rust, Solidity, Swift다. 언어별 native ABI/build 호환성은 설치 환경에서 확인해야 한다.
미설치 또는 parser 실패 시 공백을 기록하며, 모델의 직접 소스 분석과 Semgrep의 설치 조건은 별개다.
저장소 개발용 설치에는 테스트를 위해 이들 grammar가 계속 포함된다.

SDK·pg·Playwright는 공개 API import 시 로드하지 않고 세션 실행·DB 연결·브라우저 실행에
필요할 때 로드한다. 세 패키지는 필수 설치 의존성으로 유지한다. v1의 live 실행·재개 API도 유지한다.

동일 macOS arm64 / Node 22.18.0 환경의 측정은 다음과 같다.

| 지표 | 변경 전 | 변경 후 |
|---|---:|---:|
| 필수 production 의존성 파일 크기 | 795.0 MiB | 371.5 MiB |
| 공개 API import 중앙값, 새 프로세스 5회 | 약 273 ms | 약 63 ms |
| import 시 RSS 증가 중앙값 | 약 123.4 MiB | 약 33.5 MiB |

의존성 크기는 동일한 그래프 순회 방식의 논리 파일 크기이며 다운로드·압축 크기가 아니다.
import 측정은 warm filesystem에서 수행했고 실제 분석 중 최대 메모리와 다르다.
별도 npm production 소비 설치에서도 JS/TS만 설치되고 native AST 후보 생성과 공개 API 실행이 통과했다.
선택형 15개 grammar 각각을 깨끗한 소비 환경에 설치한 검증은 수행하지 않았다.

## 완료와 품질을 구분하기

`coverage.complete`는 작업 단위 실행의 완료다. `ownedFilesRead`는 초기 단위 분석의 담당 파일
읽기 관측 수이며 이해·반증·취약점 누락 여부를 증명하지 않는다. `semanticCoverage`는
`not-proven`이다. `00_analysis_coverage.json`에는 분석 시점의 미해결 사항과 preanalysis 한계,
후속 질문 보류 수를 기록하며 이후 reviewer 판단은 별도 review 산출물에 남는다.

벤치마크 CLI는 v2 실행·v2 정규화·고정 reviewer 모델 기록을 지원한다. v2에서는 주 모델과 다른
고정 버전의 `--review-model`이 필요하다. `--workflow-version=v1`은 기존 평가 경로다.
`scripts/ab-compare.ts`는 v1/v2 phase를 구분하지만 산출물 개수만으로 탐지율을 판정하지 않는다.

2026-09-21 탐지·경량화 단계의 검증은 런타임 428개, 격리 PostgreSQL 통합 6개, 벤더 597개와 self-check 103개,
타입·계약·빌드·별도 소비 앱 JS/엄격한 TS 사용이다. 모델 응답은 테스트 fixture를 사용했다.
실제 모델의 탐지 정확도·오탐률·비용/시간, 실제 Semgrep 프로세스 실행과 고객 대상 진단은
해당 검증에 포함되지 않았다. 이후 추가된 v2 재개는 `agent.resume(engagementDir)` 또는
`pnpm assess:v2 /absolute/target --engagement-dir=/absolute/run/engagement --resume`으로 사용한다.
완료 단위·checkpoint·예산 원장을 재사용하며 자세한 경계는 [저장·복구 안내](analysis-storage-recovery.md)를 따른다.
증분 분석 캐시는 아직 제공하지 않는다.
