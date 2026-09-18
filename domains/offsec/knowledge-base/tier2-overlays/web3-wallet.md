---
phases: [va, pentest, verify]
keywords: [wallet, web3, blockchain, crypto]
---
# Domain Knowledge: Web3 Wallet / Key Management

> Web3 도메인이 활성이고, 지갑 생성/서명/키 관리 기능이 감지된 경우
> Phase 1~2 분석에서 추가로 적용해야 하는 도메인 특화 체크리스트.

---

## 적용 조건

```yaml
Activation:
  domain: Web3
  indicators:
    - "ECDSA / secp256k1 서명 코드 존재"
    - "BIP-32/39/44 키 파생 코드 존재"
    - "EIP-191, EIP-712 등 이더리움 서명 표준 구현"
    - "Shamir Secret Sharing 또는 MPC 구현"
    - "HSM / TEE / Enclave 기반 키 격리"
    - "JSON-RPC 프록시 또는 블록체인 노드 통신"
```

---

## 1. 서명 경로 도메인 바인딩 (Signature Domain Binding)

```yaml
Rationale: |
  이더리움 서명은 목적별로 도메인 분리 표준이 정의되어 있다.
  각 서명 경로가 해당 표준의 보호를 올바르게 적용하는지 확인한다.

Checks:

  EIP_191_Personal_Sign:
    standard: "\\x19Ethereum Signed Message:\\n + len + message"
    check:
      - "프리픽스가 올바르게 적용되는가?"
      - "v 값이 27/28로 조정되는가?"

  EIP_712_TypedData:
    standard: "\\x19\\x01 + domainSeparator + structHash"
    check:
      - "domain.chainId가 서버 측에서 검증되는가?"
      - "chainId 미포함 / 임의 chainId 도메인으로 서명이 생성 가능한가?"
      - "domain.verifyingContract가 검증되는가?"
      - "API 파라미터의 chainId와 typedData 내부 domain.chainId의 교차 검증이 있는가?"

  EIP_155_Transaction:
    standard: "트랜잭션 서명에 chainId 포함"
    check:
      - "chainId == 0 거부가 있는가?"
      - "uint64→int64 캐스트 시 오버플로우가 발생하는가?"
      - "big.NewInt(int64(chainId)) 대신 big.NewInt(0).SetUint64(chainId) 사용하는가?"

  Raw_Hash_Sign:
    check:
      - "도메인 프리픽스 없이 raw hash에 직접 서명하는 함수가 있는가?"
      - "해당 함수가 exported/public 상태인가?"
      - "해당 함수의 현재 호출자(caller)가 있는가?"
      - "도메인 분리된 안전한 래퍼 함수(SignMessage, SignTypedData)와
        병존하는 위험한 원시 함수가 아닌지 확인"

  Cross_Path_Comparison:
    methodology: |
      모든 서명 경로를 나열하고, 각 경로의 보호 속성을 표로 비교한다:
      | 경로 | 프리픽스 | v 조정 | chainId 검증 | 컨텍스트 바인딩 |
      하나의 경로에만 빠져 있는 보호가 있으면 우회 벡터로 판단한다.
```

---

## 2. 키 머터리얼 생명주기 (Key Material Lifecycle)

```yaml
Rationale: |
  Go 등 GC 언어에서 암호화 키/니모닉/엔트로피의 메모리 위생은
  언어 특성상 완벽한 보장이 어렵지만, 합리적 수준의 보호가 필요하다.

Checks:

  Mnemonic_Handling:
    - "니모닉이 string 타입으로 전달/저장되는가?"
    - "Go string은 immutable이므로 제로화 불가 — []byte 기반 작업이 필요"
    - "니모닉 문자열이 함수 반환 후에도 변수에 잔류하는가?"

  Entropy_Zeroing:
    - "엔트로피 바이트가 사용 후 제로화되는가? (defer secureClear)"
    - "제로화 함수가 컴파일러 최적화로 제거되지 않는가?"
    - "runtime.KeepAlive() 또는 동등한 보호가 적용되는가?"

  HD_Key_Derivation:
    - "중간 ExtendedKey에 Zero() 호출이 있는가?"
    - "DeriveAddress가 불필요하게 개인키를 파생하는가?"
    - "index 파라미터의 타입 안전성 (int→uint32 캐스트, 음수, HardenedKeyStart 경계)"

  Cache_Eviction:
    - "캐시(ARC, LRU 등)에서 퇴출 시 secureClear 콜백이 등록되어 있는가?"
    - "명시적 Delete() 시 값이 제로화되는가?"

  TEE_Compensating_Control:
    note: |
      TEE(Nitro Enclave, SGX 등) 내부 메모리 잔류 이슈는
      TEE 격리가 보상 통제로 작용하므로 심각도를 조정한다.
      단, TEE 내부 프로세스 간 격리가 없는 경우
      (동일 Enclave에서 여러 사용자 키를 처리하는 경우) 잔류 위험은 유지.
```

---

## 3. JSON-RPC 프록시 보안 (RPC Proxy Security)

```yaml
Rationale: |
  블록체인 노드의 JSON-RPC를 프록시하는 경우,
  인증된 사용자라도 위험 메서드에 접근하면 안 된다.

Checks:

  Method_Allowlist:
    - "RPC 메서드 화이트리스트가 구현되어 있는가?"
    - "화이트리스트가 주석 처리되거나 비활성화되어 있지 않은가?"
    - "화이트리스트 부재 시 모든 메서드가 노드로 프록시되는가?"

  Dangerous_Methods:
    probing_targets: |
      라이브 검증 시 아래 카테고리의 메서드를 프로빙한다.
      (구체적 메서드명은 노드 종류에 따라 다르므로
       감지된 노드 소프트웨어에 맞는 위험 메서드를 AI가 판단)
    categories:
      - "mempool/txpool 조회 — 펜딩 트랜잭션 정보 노출"
      - "임의 트랜잭션 브로드캐스트 — eth_sendRawTransaction 등"
      - "노드 관리 — admin, debug, miner 계열"
      - "네트워크 토폴로지 — net_peerCount, admin_peers 등"
      - "노드 버전 핑거프린팅 — web3_clientVersion 등"

  Error_Propagation:
    - "노드 에러 응답이 클라이언트에 그대로 전달되는가?"
    - "내부 RPC URL이 에러 메시지에 포함되는가?"
```

---

## 4. 비밀 분할 (Secret Sharing)

```yaml
Rationale: |
  Shamir Secret Sharing, MPC 등 비밀 분할 구현의
  암호학적 정확성과 운영 안전성.

Checks:

  Deterministic_Assignment:
    - "쉐어 할당이 결정적(deterministic)인가?"
    - "Go map 순회 등 비결정적 순서에 의존하는가?"
    note: |
      비결정적 할당은 암호학적 보안에는 영향 없음
      (어떤 2-of-3 조합이든 복원 가능).
      기능적 비결정성(디버깅 어려움)이지 보안 취약점은 아니다.
      FP로 오판하지 않도록 주의.

  Panic_Safety:
    - "GF(256) 연산에서 divide-by-zero panic이 발생 가능한가?"
    - "중복 x-coordinate 입력이 panic을 유발하는가?"
    - "Enclave/서버 handler에 recover() 보호가 있는가?"
    - "panic이 전체 프로세스를 종료시키는가?"

  Share_Storage_Isolation:
    - "ShareA, ShareB, ShareC가 물리적으로 분리된 저장소에 저장되는가?"
    - "하나의 저장소 침해로 threshold 이상의 쉐어를 획득할 수 없는 구조인가?"
```

---

## 5. Prepare→Sign 흐름 (Transaction Authorization Flow)

```yaml
Rationale: |
  트랜잭션 서명 전 prepare 단계를 거치는 아키텍처에서
  재전송 방지와 파라미터 무결성 검증.

Checks:
  - "prepare에서 생성된 UUID가 1회성으로 소비되는가? (GETDEL 등)"
  - "prepare 시점의 파라미터와 sign 시점의 파라미터가 정규화 후 비교되는가?"
  - "prepare 데이터가 사용자(userId)에 바인딩되는가?"
  - "prepare 데이터에 TTL이 설정되어 있는가?"
  - "prepare 없이 직접 sign이 가능한 우회 경로가 있는가?"
```

---

## 6. KDF 파라미터 검증 (Key Derivation Function)

```yaml
Checks:
  - "Scrypt/Argon2/PBKDF2 등 KDF 파라미터가 서버 측에서 범위 검증되는가?"
  - "저장소 데이터 손상 시 약한 KDF 파라미터가 수용되는가?"
  - "최소 안전 기준 (예: Scrypt N ≥ 16384, R ≥ 8)이 적용되는가?"
  note: |
    KDF 파라미터가 서버 측 데이터인 경우 클라이언트 공격 불가.
    저장소 손상/내부자 공격 시나리오에서만 위험.
    심각도 판단 시 이 보상 통제를 고려한다.
```
