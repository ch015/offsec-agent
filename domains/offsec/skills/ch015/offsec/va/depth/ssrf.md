# SSRF 심층 분석 (A4+A6 Depth)

> A4/A6에서 서버 측 HTTP 요청 구성에 외부 입력 사용이 감지되었을 때
> 체인 분석과 우회 시나리오로 정밀도를 높입니다.

---

## 적용 조건

```yaml
Trigger: "Phase 1 A4/A6에서 URL 구성, HTTP 클라이언트 호출, 리다이렉트에 사용자 입력이 감지된 경우"
```

## 기본 SSRF

```yaml
심층_질문:
  - "서버가 사용자 입력을 URL로 사용하여 HTTP 요청을 하는가? (웹훅, 이미지 프록시, URL 프리뷰)"
  - "URL 검증이 있는가? scheme(http/https만), 호스트(allowlist), 포트, 경로를 모두 검증하는가?"
  - "DNS rebinding에 취약한가? (검증 시점과 요청 시점의 DNS 결과가 다를 수 있음)"
  - "리다이렉트를 따라가는가? 리다이렉트 대상도 검증하는가?"

놓치기_쉬운:
  내부_서비스_접근: |
    클라우드 메타데이터: http://169.254.169.254/latest/meta-data/
    내부 서비스: http://localhost:8080/admin
    Kubernetes: http://kubernetes.default.svc
  URL_파싱_불일치: |
    검증 라이브러리와 HTTP 클라이언트가 URL을 다르게 파싱.
    예: http://evil.com#@allowed.com → 검증은 allowed.com, 요청은 evil.com
  비HTTP_스킴: |
    file://, gopher://, dict:// 등 비HTTP 스킴으로 로컬 파일 읽기/포트 스캔.
```

## SSRF 체인

```yaml
심층_질문:
  - "SSRF로 도달 가능한 내부 서비스 중 인증 없이 접근 가능한 것이 있는가?"
  - "내부 서비스가 요청 출처(IP)만으로 인증을 판단하는가? (서버 → 내부 서비스는 무조건 신뢰)"
  - "SSRF 응답이 사용자에게 반환되는가? (Full SSRF vs Blind SSRF)"
  - "SSRF + 내부 API 조합으로 데이터 유출, 상태 변경, 권한 상승이 가능한가?"
```

## DNS Rebinding

```yaml
공격_원리: |
  1차 DNS 조회: evil.com → 공인 IP (검증 통과)
  2차 DNS 조회: evil.com → 127.0.0.1 (실제 요청은 내부로)
  TTL=0 설정으로 DNS 캐시 무력화.

심층_질문:
  - "URL 검증과 HTTP 요청 사이에 DNS 재조회가 발생하는가? (TOCTOU)"
  - "검증 후 resolved IP를 고정(pinning)하여 실제 요청에 사용하는가?"
  - "DNS 결과를 자체 캐싱하여 rebinding을 방지하는가?"

탐지_포인트: |
  dns.resolve → validate → http.request 패턴에서
  resolve 결과를 변수에 저장 후 request에 직접 전달하는지 확인.
  URL 객체만 전달하면 HTTP 클라이언트가 다시 resolve → rebinding 가능.
```

## Redirect Chain 우회

```yaml
공격_원리: |
  검증된 외부 URL이 302/307 → 내부 IP로 리다이렉트.
  1단계: https://allowed.com/callback → 검증 통과
  2단계: 302 Location: http://169.254.169.254/latest/meta-data/iam/

심층_질문:
  - "HTTP 클라이언트가 리다이렉트를 자동 follow하는가? (follow_redirects, maxRedirects 설정)"
  - "리다이렉트 대상 URL에도 동일한 검증을 적용하는가? (hop-by-hop 재검증)"
  - "리다이렉트 횟수 제한이 있는가? (무한 리다이렉트 루프 방지)"
  - "scheme 다운그레이드(https → http)를 허용하는가?"

탐지_포인트: |
  axios: maxRedirects (기본 5), beforeRedirect 콜백 존재 여부
  node-fetch: redirect: 'follow'|'manual'|'error' 설정
  Go: http.Client.CheckRedirect 커스텀 함수 존재 여부
```

## Cloud Metadata 엔드포인트

```yaml
대상_엔드포인트:
  AWS_IMDSv1: "http://169.254.169.254/latest/meta-data/ (GET만으로 접근)"
  AWS_IMDSv2: "PUT http://169.254.169.254/latest/api/token (hop limit=1)"
  GCP: "http://metadata.google.internal/computeMetadata/v1/ (Metadata-Flavor: Google 헤더 필요)"
  Azure: "http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Metadata: true 헤더 필요)"

심층_질문:
  - "IMDSv2가 강제되어 있는가? (hop-limit=1이면 컨테이너 내부에서만 접근 가능)"
  - "SSRF로 커스텀 헤더(Metadata-Flavor, Metadata: true)를 설정할 수 있는가?"
  - "메타데이터에서 IAM 자격 증명(access key, secret key, session token) 탈취가 가능한가?"
  - "탈취된 자격 증명의 권한 범위는? (S3 읽기만 vs 전체 관리자)"

IMDSv2_우회: |
  IMDSv2 hop-limit=1은 도커 네트워크 bridge 모드에서 hop 추가로 우회 가능.
  ECS task metadata endpoint(http://169.254.170.2)는 별도 보호 필요.
```

## IPv6 매핑 주소 우회

```yaml
우회_패턴:
  - "::ffff:127.0.0.1 — IPv4-mapped IPv6 주소로 localhost 우회"
  - "::1 — IPv6 루프백"
  - "0:0:0:0:0:ffff:169.254.169.254 — 메타데이터 엔드포인트 IPv6 매핑"
  - "[::]  — IPv6 any address"

심층_질문:
  - "IP 차단 목록이 IPv6 표현도 포함하는가?"
  - "URL 파서가 IPv6 bracket notation([::1])을 올바르게 처리하는가?"
  - "듀얼스택 환경에서 IPv4 차단 시 IPv6 경로가 열려있는가?"
```

## SSRF 응답 방향 분석

```yaml
공격_원리: |
  SSRF 분석은 요청 방향(클라이언트→서버→업스트림)에 집중하기 쉬나,
  프록시/게이트웨이 코드에서는 응답 방향(업스트림→서버→클라이언트)도
  반드시 분석해야 한다. SSRF 자체가 불가능해도, 업스트림 응답의
  무검증 반영은 독립적인 취약점 클래스를 형성한다.

심층_질문:
  - "SSRF 점검 대상 코드가 프록시/게이트웨이 역할을 겸하는가?"
  - "업스트림 응답 헤더가 클라이언트에 allowlist 없이 패스스루되는가?"
  - "업스트림 응답 Content-Type이 강제되는가, 업스트림 값을 그대로 사용하는가?"
  - "업스트림 에러 응답에 내부 URL/호스트명이 포함되어 클라이언트에 노출되는가?"

연계_모듈: |
  프록시 패턴이 감지되면 depth/data-flow.md를 함께 로딩한다.
  SSRF 요청 방향과 응답 반영 방향을 모두 분석해야 완전한 진단이 된다.
```

## URL 파서 차이(Differential Parsing)

```yaml
공격_원리: |
  URL 검증 라이브러리와 HTTP 클라이언트가 동일 URL을 다르게 해석.
  파서마다 authority, fragment, userinfo 처리가 다름.

우회_예시:
  - "http://evil.com\\@allowed.com — backslash를 path로 vs delimiter로 해석"
  - "http://allowed.com@evil.com — userinfo vs host 파싱 차이"
  - "http://0x7f000001 — 16진수 IP 표기 (127.0.0.1)"
  - "http://2130706433 — 10진수 IP 표기"
  - "http://127.0.0.1:80\\@allowed.com:443 — 포트+backslash 조합"
  - "http://allowed.com%00@evil.com — null byte injection"

탐지_포인트: |
  검증과 요청에 동일한 URL 파서를 사용하는지 확인.
  new URL() 결과의 hostname을 직접 비교하고,
  원본 문자열이 아닌 파싱된 hostname을 HTTP 클라이언트에 전달하는지 확인.
```
