# BaaS 신뢰 경계 원칙 (Principles Module)

> Backend-as-a-Service(Supabase, Firebase, Hasura, Appwrite, Amplify 등)를
> 사용하는 프로젝트에 적용되는 보편 원칙.

---

## 적용 조건

```yaml
Trigger: "Phase 0에서 BaaS/서버리스 백엔드 플랫폼 사용이 감지된 경우"
```

## 핵심 원칙

```yaml
Principles:
  Client_Server_Key_Separation: |
    "클라이언트에서 실행되는 코드는 서버 권한 키에 접근할 수 없어야 한다.
     BaaS는 보통 anon/public 키와 service/admin 키를 분리한다.
     서비스 키가 프론트엔드 빌드에 포함되면 RLS/Security Rules가 무력화된다."

  Rules_As_Sole_Authorization: |
    "BaaS Security Rules/RLS가 유일한 인가 레이어인 경우,
     규칙의 완전성이 곧 시스템의 보안 수준이다.
     규칙에 빈틈이 있으면 서버측 방어선이 없어 즉시 데이터 노출."

  Serverless_Function_Auth: |
    "BaaS의 서버리스 함수(Edge Function, Cloud Function, Lambda)가
     서비스 키로 DB에 접근할 때, 함수 자체에서 요청자 인증/인가를 수행해야 한다.
     '서버측이니까 안전하다'는 가정은 잘못이다 — 함수의 HTTP endpoint는 공개될 수 있다."

  Configuration_Drift: |
    "BaaS 설정(Security Rules, Auth 정책, CORS, 리다이렉트 URL)은
     대시보드/콘솔에서 변경되며 코드 리뷰를 거치지 않는다.
     프로덕션 설정이 코드의 가정과 일치하는지 검증해야 한다."
```

## 심층 질문

```yaml
심층_질문:
  - "서비스/관리자 키가 프론트엔드 코드 또는 클라이언트 접근 가능한 환경변수에 노출되지 않는가?"
  - "Security Rules/RLS가 유일한 인가 레이어인가? 규칙의 완전성이 검증되었는가?"
  - "서버리스 함수가 서비스 키를 사용할 때, 함수 자체에서 요청자 인증을 수행하는가?"
  - "프로덕션 BaaS 설정(Auth, CORS, redirect URLs)에 개발용 값이 잔존하지 않는가?"
  - "클라이언트에서 직접 DB 쿼리가 가능한 경우, 쿼리 범위가 규칙으로 제한되는가?"

놓치기_쉬운:
  디버그_로그_잔존: |
    서버리스 함수에 console.log(req.headers.authorization) 같은 디버그 로그가 프로덕션에 잔존.
  이메일_확인_미강제: |
    인증 설정에서 이메일 확인(email confirmation)이 비활성화된 채 프로덕션 운영.
  Storage_공개_버킷: |
    private이어야 할 버킷이 public으로 설정되어 모든 파일에 인증 없이 접근 가능.
```
