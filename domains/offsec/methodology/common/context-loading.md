# 방법론 파일 선택 기준

> 문서 안의 경로는 OffSec 도메인 루트(domains/offsec) 기준이다. 실제 Read는 호스트가 전달한 available_methodology_files의 절대경로로 한다.

필수는 `methods/analyze.md`다. 아래 파일은 현재 조사 중인 표면·가설에 해당할 때만 Read한다(analyze 카드).
단순 모듈에 모든 문서를 반복해 읽지 않는다.

| 조건(담당 범위에서 확인) | 파일 |
|---|---|
| 외부 입력이 query/template/shell/deserialization sink에 닿을 수 있음 | methodology/va/depth/injection.md |
| 인증 미들웨어 없이 도달 가능한 핸들러 | methodology/va/depth/auth-bypass.md |
| 사용자 제어 id/path/body로 타 리소스 지정 | methodology/va/depth/access-control.md |
| 외부 입력이 outbound URL/host 결정에 영향 | methodology/va/depth/ssrf.md |
| 커스텀 암호화/JWT/서명/키 관리 | methodology/va/depth/crypto-misuse.md |
| 업스트림 응답·사용자 데이터가 클라이언트/로그/redirect로 전달 | methodology/va/depth/data-flow.md |
| read-check-write가 트랜잭션/락/멱등성 없이 수행, 메시지 큐 소비자, 분산 서비스 간 상태 공유, 캐시+DB 이중 쓰기, 블록체인 트랜잭션 | methodology/va/depth/concurrency.md, methodology/va/concurrency.md |
| RLS/행 수준 접근 제어(Supabase RLS, Firebase Rules, Hasura, Postgres RLS 등) | methodology/va/principles/row-level-security.md |
| OAuth/OIDC 제공자 SDK | methodology/va/principles/oauth-provider-misconfig.md |
| Webhook endpoint 또는 서명 검증 | methodology/va/principles/webhook-integrity.md |
| BaaS 플랫폼(Supabase, Firebase, Hasura, Appwrite, Amplify 등) | methodology/va/principles/baas-trust-boundary.md |
| 의존성 manifest·lock 존재 | methodology/va/supply-chain.md (+ knowledge-base/tier1-dimensions/a6-deps.md) |
| A3(데이터 흐름)·A4(입출력 경계) 점검 — 항상 함께 읽는다 | methodology/common/taint-analysis.md |
| 도메인 시그널(web3, 결제, SDK, AI/Agent, 커머스, 클라우드 등) | knowledge-base/tier2-overlays/registry.yaml 매칭 오버레이 |

- depth 파일: 표의 조건을 sentinel 질문으로 답한다. 답이 YES 또는 UNKNOWN이면 읽고, 모두 NO일 때만 건너뛴다. 건너뛴 사유는 결과에 1줄로 남긴다.
- tier2 오버레이: registry.yaml의 signal 패턴과 담당 범위 코드를 교차 매칭한다. 도메인이 감지됐는데 오버레이를 읽지 않으면 그 사유를 남긴다.
- 기술·벤더별 세부사항(가젯 체인, 벤더 API, 엔진별 페이로드)은 모델 내재 지식에 위임한다.
