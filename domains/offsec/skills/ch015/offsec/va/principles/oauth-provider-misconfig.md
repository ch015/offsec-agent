# OAuth/OIDC 제공자 보안 원칙 (Principles Module)

> 외부 인증 제공자(Auth0, Cognito, Clerk, Okta, Supabase Auth, Firebase Auth 등)를
> 사용하는 모든 프로젝트에 적용되는 보편 원칙.

---

## 적용 조건

```yaml
Trigger: "Phase 0에서 OAuth/OIDC 제공자 SDK 또는 인증 서비스 사용이 감지된 경우"
```

## 핵심 원칙

```yaml
Principles:
  Server_Side_Verification: |
    "토큰 검증은 반드시 서버에서 수행해야 한다.
     클라이언트에서만 토큰/Claims를 검증하면 변조가 가능하다."

  Redirect_URI_Strictness: |
    "redirect_uri는 정확한 일치(exact match)로 검증해야 한다.
     와일드카드, 접두사 매칭, localhost 허용은 토큰 탈취 경로가 된다."

  Scope_Minimization: |
    "애플리케이션에 부여되는 OAuth scope/permission은 최소 필요만 허용한다.
     특히 M2M(Machine-to-Machine) 앱의 admin:* scope는 위험하다."

  Claims_Trust_Boundary: |
    "사용자가 수정 가능한 metadata/claims(public metadata, custom attributes)를
     권한 판정에 사용하면 권한 상승이 가능하다.
     권한 관련 claims는 서버측에서만 설정/검증 가능한 경로를 사용해야 한다."
```

## 심층 질문

```yaml
심층_질문:
  - "토큰(JWT/ID token) 검증이 서버에서 수행되는가, 클라이언트에서만 수행되는가?"
  - "redirect_uri/콜백 URL이 정확한 일치로 검증되는가? 프로덕션에 localhost가 잔존하지 않는가?"
  - "애플리케이션의 OAuth scope가 최소 필요만 허용하는가?"
  - "사용자 수정 가능한 metadata를 권한 판정에 사용하지 않는가?"
  - "Pre-Signup/Pre-Auth 훅에서 자동 확인(auto-confirm) 로직이 이메일 소유 검증을 우회하지 않는가?"
  - "MFA 강제가 설정되어 있는가? MFA를 건너뛸 수 있는 경로가 없는가?"

놓치기_쉬운:
  Action_Hooks_남용: |
    인증 제공자의 Action/Rule/Lambda Trigger에서 쿼리 파라미터나
    사용자 입력을 그대로 claims에 설정하는 패턴.
  클라이언트_시크릿_노출: |
    SPA/Mobile에서 client_secret을 하드코딩 (PKCE를 사용해야 함).
  다중_제공자_불일치: |
    여러 OAuth 제공자를 사용하면서 서버측 사용자 매핑/권한 통합이 불일치.
```
