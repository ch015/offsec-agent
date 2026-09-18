# Access Control 심층 분석 (A2 Depth)

> A2 인가 아키텍처에서 접근 제어 이상 후보가 발견되었을 때
> 시나리오별 심층 질문으로 정밀도를 높입니다.

---

## 적용 조건

```yaml
Trigger: "Phase 1 A2에서 소유권 미검증, 역할 미확인, IDOR 후보가 감지된 경우"
```

## IDOR / BOLA (Object Level)

```yaml
심층_질문:
  - "리소스 접근 시 요청자가 해당 리소스의 소유자/권한자인지 서버에서 검증하는가?"
  - "리소스 ID가 순차적(auto-increment)이어서 다른 사용자의 ID를 추측 가능한가?"
  - "목록 API와 상세 API의 접근 제어가 일관적인가? (목록에서 안 보이지만 ID를 알면 접근 가능)"
  - "관련 리소스 접근 시에도 소유권이 검증되는가? (사용자→주문은 검증, 주문→배송은 미검증)"
  - "일괄 작업(bulk) API에서 각 항목의 소유권을 개별 검증하는가?"

놓치기_쉬운:
  간접_참조: |
    직접 리소스가 아닌 관련 리소스를 통한 접근.
    GET /orders/123 은 소유권 검증하지만
    GET /orders/123/invoice 는 invoice 자체의 소유권은 미검증.
  GraphQL_중첩: |
    GraphQL 중첩 쿼리로 인가 검증을 우회.
    query { user(id:1) { orders { ... } } } — user 접근은 검증하지만
    orders의 소유자가 요청자인지는 미검증.
```

## Privilege Escalation (Function Level)

```yaml
심층_질문:
  - "관리자 전용 API에 일반 사용자 토큰으로 접근 가능한가?"
  - "역할 검증이 미들웨어에서 일관되게 적용되는가, 핸들러마다 개별 구현인가?"
  - "역할 변경 API가 자기 자신의 역할을 승격할 수 있는가?"
  - "API 문서/라우트 목록에 노출되지 않은 관리자 엔드포인트가 URL 추측으로 접근 가능한가?"

놓치기_쉬운:
  파라미터_기반_승격: |
    PUT /api/users/me body: { "role": "admin" }
    Mass Assignment로 역할 필드를 직접 변경.
  HTTP_메서드_우회: |
    GET /api/admin/users → 403 (차단)
    하지만 PUT /api/admin/users → 200 (미들웨어가 GET만 차단)
```

## Property Level Authorization (BOPLA)

```yaml
심층_질문:
  - "API 응답에 권한 수준에 맞지 않는 필드가 포함되는가? (다른 사용자의 이메일, 내부 설정)"
  - "API 요청에서 읽기 전용이어야 하는 필드를 수정할 수 있는가? (가격, 상태, 점수)"
  - "DTO/시리얼라이저가 역할별로 다른 필드 셋을 반환하는가?"

놓치기_쉬운:
  확장_파라미터: |
    ?fields=email,phone,ssn 같은 필드 선택 파라미터로
    본래 반환되지 않는 민감 필드를 요청.
  중첩_객체: |
    응답의 중첩 객체(user.organization.billing)에
    상위 레벨에서는 필터링되지만 하위에서는 노출.
```
