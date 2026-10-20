# Phase 2 확장: Concurrency Analysis (동시성 분석)

> 동시 요청, 분산 트랜잭션, 비동기 처리에서 발생하는
> 무결성/일관성 위반을 체계적으로 탐색합니다.

---

## 적용 조건

```yaml
Auto_Load_Trigger:
  설명: |
    Phase 0 Recon에서 아래 중 하나 이상 감지 시 자동 로드:
  조건:
    - "금융/결제/자산 관련 트랜잭션 코드 존재 (payment, wallet, balance, transfer, withdraw)"
    - "메시지 큐 사용 (AMQP, Kafka, SQS, Redis Pub/Sub, NATS)"
    - "분산 서비스 아키텍처 (마이크로서비스, gRPC, 서비스 간 HTTP 호출)"
    - "동시성 프리미티브 사용 (mutex, lock, semaphore, sync.Once, atomic)"
    - "캐시 레이어(Redis, Memcached) + DB 이중 기록 패턴"
    - "Web3 트랜잭션 (nonce 관리, 동시 서명)"
  미감지_시: |
    deep-analysis.md의 Timing_Races 최소 질문만 수행.
    이 모듈은 로드하지 않는다.
```

---

## 분석 원칙

```yaml
Principles:
  Methodology_Not_Patterns: |
    "특정 프레임워크의 트랜잭션 구문(BEGIN/COMMIT)이나
     잠금 API(sync.Mutex)를 패턴 매칭하지 않는다.
     '원자적이어야 하는 작업이 원자적으로 수행되는가?'를 질문하고,
     AI가 감지된 기술 스택에 맞는 구체적 코드를 판단한다."

  State_Centric: |
    "코드 구문이 아닌 상태 변화(State Change)를 추적한다.
     '이 상태 변화가 단독 실행과 동시 실행에서 동일한 결과를 내는가?'
     가 핵심 질문이다."

  Assume_Concurrent: |
    "모든 공개 엔드포인트는 동시에 호출될 수 있다고 가정한다.
     '이 API가 한 번만 호출된다'는 가정은 보안 분석에서 무효하다."
```

---

## 분석 영역

### C1. TOCTOU Race Conditions (확인-사용 경합)

```yaml
TOCTOU:
  methodology: |
    상태 확인(읽기)과 상태 사용(쓰기) 사이에 개입 가능한 경로를 추적한다.
  
  질문:
    - "이 확인-사용 쌍이 단일 DB 트랜잭션 또는 원자적 연산 내에 있는가?"
    - "동시 요청 2개가 확인을 동시 통과하면 어떻게 되는가?"
    - "분산 환경(다중 인스턴스)에서 다른 인스턴스의 동시 확인을 차단하는가?"
    - "SELECT ... FOR UPDATE 또는 동등한 잠금이 적용되는가?"
  
  대표_패턴:
    잔액_이중차감: |
      1. 잔액 확인: balance >= amount? (SELECT)
      2. 잔액 차감: balance -= amount (UPDATE)
      → 1-2 사이에 다른 요청이 같은 잔액으로 확인 통과 가능
    
    재고_초과판매: |
      1. 재고 확인: stock > 0?
      2. 재고 차감: stock -= 1
      → 동시 주문으로 음수 재고 발생 가능
    
    투표_이중집계: |
      1. 투표 여부 확인: has_voted == false?
      2. 투표 기록: has_voted = true, count += 1
      → 동시 요청으로 다중 투표 가능
  
  건전한_패턴:
    - "DB 트랜잭션 + 행 잠금 (SELECT ... FOR UPDATE)"
    - "원자적 UPDATE (UPDATE ... WHERE balance >= amount)"
    - "Redis WATCH + MULTI 또는 Lua script"
    - "분산 잠금 (Redlock, etcd lease)"
```

### C2. Distributed Atomicity (분산 원자성)

```yaml
Distributed_Atomicity:
  methodology: |
    여러 서비스/저장소에 걸친 작업의 원자성을 분석한다.
  
  질문:
    - "여러 서비스/저장소에 걸친 쓰기가 단일 트랜잭션으로 처리되는가?"
    - "서비스 A 성공 + 서비스 B 실패 시 일관성이 유지되는가?"
    - "Saga 패턴/보상 트랜잭션이 구현되어 있는가?"
    - "네트워크 파티션에서 double-spend가 가능한가?"
    - "외부 API 호출 + 로컬 DB 업데이트의 순서가 정의되어 있는가?"
  
  대표_패턴:
    결제_불일치: |
      1. 외부 PG 결제 API 호출 (성공)
      2. 로컬 DB 주문 상태 업데이트 (실패)
      → 결제는 됐으나 주문은 미완료
    
    크로스서비스_데이터_유실: |
      1. 서비스 A에서 포인트 차감 (성공)
      2. 서비스 B에서 상품 지급 (실패)
      → 포인트만 차감되고 상품 미지급
```

### C3. Idempotency (멱등성)

```yaml
Idempotency:
  methodology: |
    동일 요청의 중복 처리를 방지하는 메커니즘을 확인한다.
  
  질문:
    - "부작용이 있는 API(결제, 전송, 투표)에 멱등키가 있는가?"
    - "멱등키 저장/확인이 원자적인가?"
    - "네트워크 재시도 시 중복 처리가 발생하는가?"
    - "멱등키의 TTL/만료 정책이 있는가?"
    - "멱등키 없이 클라이언트 재시도가 가능한가?"
  
  대표_패턴:
    이중_결제: |
      POST /api/pay (네트워크 타임아웃) → 클라이언트 재시도 → 2회 결제
    
    이중_보상: |
      POST /api/reward (500 에러 후 재시도) → 보상 2회 지급
```

### C4. Cache-DB Consistency (캐시-DB 일관성)

```yaml
Cache_DB_Consistency:
  methodology: |
    캐시와 DB 사이의 일관성을 분석한다.
  
  질문:
    - "캐시 무효화 타이밍과 DB 업데이트 순서가 일관적인가?"
    - "캐시 갱신 실패 시 stale 데이터로 보안 결정이 내려지는가?"
    - "동시 업데이트 시 캐시에 오래된 데이터가 남을 수 있는가?"
    - "캐시 기반 인증/인가 결정이 있는가? 캐시 TTL 내 권한 변경이 반영되는가?"
  
  대표_패턴:
    권한_캐시_지연: |
      1. 관리자가 사용자 권한 제거 (DB 업데이트)
      2. 캐시 TTL 5분 → 5분간 이전 권한으로 작업 가능
    
    잔액_캐시_불일치: |
      1. Redis에서 잔액 조회 (캐시)
      2. DB에서 차감 (원본)
      3. 캐시 갱신 전 다른 요청이 캐시 잔액으로 확인 통과
```

### C5. Async Queue Ordering (비동기 큐 순서)

```yaml
Async_Queue_Ordering:
  methodology: |
    메시지 큐/이벤트의 순서 보장과 중복 처리를 분석한다.
  
  질문:
    - "메시지 순서가 비즈니스 무결성에 영향을 미치는가?"
    - "소비자(consumer)가 멱등하게 구현되어 있는가?"
    - "dead letter 큐의 재처리 시 부작용이 있는가?"
    - "메시지 유실 시 상태 불일치가 발생하는가?"
    - "동일 메시지의 중복 배달에 대한 방어가 있는가?"
  
  대표_패턴:
    순서_역전: |
      1. 주문 생성 이벤트 → 결제 서비스
      2. 주문 취소 이벤트 → 결제 서비스
      → 취소가 먼저 처리되면 이후 생성 이벤트로 결제 실행
```

---

## 출력

```yaml
Finding_Tagging:
  dimension: "관련 차원 (A3, A4, A8 등)"
  category: "concurrency-{type}"
  types:
    - "concurrency-toctou"
    - "concurrency-distributed"
    - "concurrency-idempotency"
    - "concurrency-cache"
    - "concurrency-queue"
  
  심각도_가이드:
    금융_자산_영향: "CRITICAL (이중 지불, 잔액 조작)"
    데이터_무결성: "HIGH (상태 불일치, 이중 처리)"
    가용성_영향: "MEDIUM (큐 순서 역전, 캐시 stale)"
    기능_영향: "LOW (UI 불일치, 비핵심 중복)"
```
