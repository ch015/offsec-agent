# Row-Level Security 원칙 (Principles Module)

> RLS/행 수준 접근 제어를 제공하는 모든 시스템에 적용되는 보편 원칙.
> 적용 대상: Supabase, Firebase, Hasura, Postgres RLS, DynamoDB fine-grained access 등.

---

## 적용 조건

```yaml
Trigger: "Phase 0에서 행 수준 접근 제어 메커니즘 사용이 감지된 경우 (DB rules, RLS policies, security rules 등)"
```

## 핵심 원칙

```yaml
Principles:
  Complete_Coverage: |
    "RLS가 활성화된 테이블과 미활성 테이블이 혼재하면,
     미활성 테이블이 우회 경로가 된다.
     모든 사용자 데이터 테이블에 RLS가 적용되어 있는가?"

  Ownership_Verification: |
    "'인증됨(authenticated)'과 '소유자(owner)'는 다르다.
     로그인만으로 모든 행에 접근 가능한 정책은 RLS의 목적을 무효화한다.
     정책이 행의 소유자/권한자를 검증하는가?"

  Operation_Completeness: |
    "SELECT 정책만 있고 UPDATE/DELETE 정책이 없으면 쓰기 경로가 열려 있다.
     모든 CRUD 연산에 대해 정책이 정의되어 있는가?"

  Privileged_Key_Isolation: |
    "관리자/서비스 권한 키(service_role, admin SDK)가 클라이언트에 노출되면
     RLS를 완전히 우회할 수 있다.
     서비스 키가 서버측에서만 사용되는가?"
```

## 심층 질문

```yaml
심층_질문:
  - "모든 사용자 데이터 테이블에 행 수준 접근 제어가 활성화되어 있는가?"
  - "정책이 '인증됨'만 확인하는가, '해당 행의 소유자/권한자'까지 확인하는가?"
  - "SELECT/INSERT/UPDATE/DELETE 모든 연산에 정책이 정의되어 있는가?"
  - "서비스 키/관리자 키가 클라이언트 코드나 환경변수에 노출되지 않는가?"
  - "RLS를 우회하는 서버측 함수(RPC, Edge Function, Cloud Function)가 자체 인가 검증을 수행하는가?"

놓치기_쉬운:
  포괄_허용_정책: |
    "allow all" / "USING (true)" 같은 포괄 정책이 특정 테이블에 잔존.
    마이그레이션 초기에 테스트용으로 넣고 제거하지 않은 패턴.
  관계형_우회: |
    테이블 A에 RLS 적용, 테이블 B에 미적용.
    B에서 A의 데이터를 JOIN으로 접근 가능.
  클라이언트_키_혼동: |
    프론트엔드 .env에 서비스 키를 NEXT_PUBLIC_* 접두어로 노출.
```
