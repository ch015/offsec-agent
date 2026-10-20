# 데이터 흐름 심층 분석 (A3+A4+A6 Depth)

> 사용자 제어 데이터가 민감한 출력 채널에 도달하는 경로를
> source-to-sink 추적과 응답 반영 분석으로 정밀 진단합니다.

---

## 적용 조건

```yaml
Trigger: |
  Phase 1 A3/A4에서 데이터 흐름 이상이 감지된 경우, 또는
  프록시/게이트웨이 패턴이 발견된 경우
```

## Source-to-Sink 추적

```yaml
원칙: "사용자 제어 데이터(source)가 보안 민감 지점(sink)에 sanitization 없이 도달하면 취약점이다."

심층_질문:
  - "source(req.body, req.query, req.params, headers, file upload)에서 sink(DB쿼리, 명령, 응답, 파일시스템)까지 데이터가 어떤 경로로 흐르는가?"
  - "중간 변환(함수 호출, 변수 할당, 배열 매핑)을 거쳐도 taint가 유지되는가?"
  - "sanitization 함수가 적용된다면, 해당 sink에 적합한 인코딩인가?"
  - "간접 흐름이 있는가? (source → DB 저장 → 다른 요청에서 읽기 → sink)"

Sink_유형별_확인:
  HTML_출력: "XSS — context-aware 인코딩이 적용되는가? (attribute, script, url context)"
  HTTP_헤더: "header injection — CRLF가 필터링되는가?"
  파일_경로: "path traversal — 정규화(resolve) + jail 제한이 있는가?"
  로그: "log injection — 줄바꿈/제어문자가 필터링되는가?"
  리다이렉트: "open redirect — 목적지 URL이 allowlist 검증되는가?"
```

## 응답 반영 공격 (프록시/게이트웨이)

```yaml
원칙: "업스트림 응답을 클라이언트에 전달할 때, 헤더/바디를 무검증 패스스루하면 업스트림 침해 시 게이트웨이 도메인에서 공격이 실행된다."

심층_질문:
  - "업스트림 응답 헤더가 클라이언트에 전달되는 방식은? (allowlist/denylist/전체)"
  - "업스트림 응답 Content-Type이 프록시에서 강제되는가?"
  - "에러 응답에 내부 정보(URL, 호스트명, 스택 트레이스)가 포함되는가?"

위험_헤더:
  Set-Cookie: "게이트웨이 도메인에 쿠키 주입 → 세션 고정"
  Location: "3xx와 결합 시 오픈 리다이렉트"
  Access-Control-Allow-Origin: "와일드카드 허용 시 CORS 정책 우회"
  Content-Type: "text/html 반환 시 게이트웨이 도메인 XSS"

놓치기_쉬운:
  - "transfer-encoding만 제외하는 denylist — 15+ 위험 헤더가 통과"
  - "hop-by-hop 헤더가 프록시를 통과하면 RFC 위반 + smuggling"
```

## 업스트림 침해 시나리오

```yaml
심층_질문:
  - "업스트림 모듈이 침해되었다고 가정할 때, 프록시를 통해 클라이언트에 가할 수 있는 최대 피해는?"
  - "프록시가 응답 헤더 allowlist, Content-Type 강제, CSP 헤더 추가 등 보상 제어를 하는가?"
  - "업스트림 5xx 에러 바디가 디버그 정보를 포함하여 클라이언트에 노출되는가?"
```
