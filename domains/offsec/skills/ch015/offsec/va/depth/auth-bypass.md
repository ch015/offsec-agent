# Authentication Bypass 심층 분석 (A1 Depth)

> A1 인증 아키텍처에서 인증 우회 후보가 발견되었을 때
> 시나리오별 심층 질문으로 정밀도를 높입니다.

---

## 적용 조건

```yaml
Trigger: "Phase 1 A1에서 인증 미들웨어 미적용, 인증 분기, fallback 경로가 감지된 경우"
```

## JWT / Token 검증

```yaml
심층_질문:
  - "토큰 서명 검증 시 알고리즘을 서버가 고정하는가, 토큰 헤더의 alg을 신뢰하는가? (alg=none 공격)"
  - "RS256 ↔ HS256 혼동: 공개키를 HMAC 시크릿으로 사용할 수 있는가?"
  - "토큰 만료(exp) 검증이 활성화되어 있는가? clock skew 허용 범위는?"
  - "토큰 폐기(revocation) 메커니즘이 있는가? 로그아웃 시 토큰이 즉시 무효화되는가?"
  - "Refresh token rotation이 구현되어 있는가? 재사용 감지가 있는가?"
  - "JWK/JWKS 엔드포인트가 공격자가 제어 가능한 URL에서 로드되는가?"

놓치기_쉬운:
  토큰_혼동: |
    서비스 A가 발행한 토큰을 서비스 B가 수락하는 경우.
    audience(aud) 또는 issuer(iss) 검증이 누락.
  커스텀_헤더: |
    인증 미들웨어가 Authorization 헤더만 확인하지만
    프록시/게이트웨이가 X-User-Id 같은 커스텀 헤더를 추가하고
    백엔드가 이를 무조건 신뢰하는 패턴.
```

## Session Management

```yaml
심층_질문:
  - "세션 ID가 로그인 성공 후 재생성(regenerate)되는가? (세션 고정 공격)"
  - "세션 쿠키에 HttpOnly + Secure + SameSite 속성이 모두 적용되는가?"
  - "세션 저장소(Redis, DB)에 TTL이 설정되어 있는가?"
  - "동시 세션 제한이 있는가? 한 계정에 무제한 세션 생성 가능한가?"

놓치기_쉬운:
  서브도메인_공유: |
    쿠키 domain이 .example.com으로 설정되어
    다른 서브도메인 앱에서 세션 쿠키를 읽을 수 있는 경우.
```

## OAuth / OIDC

```yaml
심층_질문:
  - "state 파라미터가 CSRF 방어로 올바르게 구현되어 있는가? (생성→검증 쌍)"
  - "redirect_uri 검증이 정확한 일치인가, 접두사/패턴 매칭인가?"
  - "Authorization Code를 Access Token으로 교환할 때 PKCE가 적용되는가?"
  - "ID Token의 nonce 검증이 있는가?"
  - "Token 요청 시 client_secret이 안전하게 전달되는가? (프론트엔드 노출 여부)"

놓치기_쉬운:
  오픈_리다이렉트_체인: |
    redirect_uri 검증이 느슨하면 공격자가
    https://app.example.com/callback/../../../attacker.com 같은
    경로로 토큰을 탈취할 수 있음.
```

## Multi-Factor Authentication

```yaml
심층_질문:
  - "MFA 검증을 건너뛸 수 있는 API 경로가 있는가?"
  - "MFA 코드 시도 횟수에 제한이 있는가? (brute-force)"
  - "MFA 등록 전 상태에서 보호된 기능에 접근 가능한가?"
  - "복구 코드의 저장/전달이 안전한가?"
```
