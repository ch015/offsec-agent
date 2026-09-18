---
phases: [va, pentest, verify]
keywords: [web3, defi, smart-contract, blockchain]
---
# Tier 2 Overlay: Web3 공통

> Web3 도메인이 감지된 모든 프로젝트에 적용.
> DeFi, Wallet, DEX, DAO, NFT, Bridge, Lending, GameFi 등 서브도메인 무관.
> 8차원에 additive로 주입되는 도메인 특화 질문.

---

## A1 인증 (Authentication)

```yaml
Web3_Auth_Boundary:
  question: "API 인증과 온체인 트랜잭션 서명 권한이 분리되는가?"
  trace: |
    1. 백엔드 API 인증(JWT, API Key)과 블록체인 트랜잭션 서명이 독립적인가?
    2. API 인증 토큰 탈취로 온체인 자산 이동이 불가능한가?
    3. 서버 사이드 서명(hot wallet)이 사용되면 서명 권한이 최소화되는가?

SIWE_Implementation:
  question: "SIWE(Sign-In With Ethereum) 구현이 EIP-4361을 준수하는가?"
  trace: |
    1. 메시지 포맷이 EIP-4361 필수 필드(domain, address, uri, nonce, issued-at)를 포함하는가?
    2. nonce가 서버 생성 1회성이고, 사용 후 즉시 무효화되는가?
    3. 서명 검증이 서버 사이드에서 수행되는가? (클라이언트 검증만으로 충분하지 않음)
    4. expiration-time이 설정되어 replay attack이 방지되는가?
    5. chain-id가 검증되어 cross-chain replay가 불가능한가?
```

## A2 인가 (Authorization)

```yaml
Proxy_Upgrade_Access:
  question: "스마트 컨트랙트 프록시 업그레이드 접근 제어가 안전한가?"
  trace: |
    1. 어떤 프록시 패턴이 사용되는가? (UUPS, Transparent, Beacon, Diamond)
    2. 업그레이드 함수 호출 권한이 다중 서명(multisig) 또는 타임락(timelock)을 요구하는가?
    3. UUPS의 경우 _authorizeUpgrade 함수에 접근 제어가 있는가?
    4. 업그레이드 시 스토리지 레이아웃 호환성이 검증되는가?
    5. 업그레이드 이벤트가 로깅되어 모니터링 가능한가?

Role_Separation:
  question: "온체인 역할(owner, admin, operator)이 최소 권한으로 분리되는가?"
  trace: |
    1. 컨트랙트 owner가 모든 특권 기능에 단독 접근 가능한가? (중앙화 위험)
    2. 역할별 권한이 명확히 구분되는가? (예: pause는 operator, upgrade는 owner)
    3. 역할 변경 시 2단계 프로세스(propose → accept)가 있는가?
```

## A3 데이터흐름 (Data Flow)

```yaml
Onchain_Trust_Boundary:
  question: "온체인 데이터가 신뢰 경계(trust boundary)로 올바르게 분류되는가?"
  trace: |
    1. 온체인 조회 데이터(balanceOf, ownerOf 등)가 "공개 데이터"로 올바르게 분류되는가?
       → 공개 데이터 조회 API에 IDOR를 적용하면 오탐 발생
    2. 오프체인 DB와 온체인 상태 간 동기화 불일치가 감지되는가?
    3. 온체인 이벤트 수집(FilterLogs) 시 체인 재구성(reorg) 처리가 있는가?
    4. 오프체인→온체인 데이터 전달 시 중간 변조 방지가 있는가?

ABI_Encoding_Consistency:
  question: "ABI 인코딩/디코딩이 양 끝에서 일관적인가?"
  trace: |
    1. 프론트엔드(ethers/viem)와 백엔드(go-ethereum)의 ABI 인코딩이 동일한가?
    2. ABI stateMutability(view/pure/nonpayable/payable)와 실제 호출 방식이 일치하는가?
       → view 함수를 트랜잭션으로 호출하거나, nonpayable을 call로 호출하는 불일치
    3. 커스텀 타입(struct, enum)의 인코딩이 양 끝에서 동일한 순서/타입인가?
```

## A4 IO (Input/Output Validation)

```yaml
Integer_Type_Boundary:
  question: "uint256↔Go int↔JS Number 변환 시 오버플로우/정밀도 손실이 있는가?"
  trace: |
    1. uint256 값이 Go int64(최대 ~9.2e18)로 변환될 때 오버플로우 체크가 있는가?
    2. JS Number(최대 2^53-1)로 변환 시 정밀도 손실이 발생하는가?
       → BigInt 또는 문자열 직렬화가 사용되는가?
    3. decimal.Decimal 등 라이브러리 사용 시 signed/unsigned 경계가 검증되는가?
    4. 토큰 decimals(18자리 등)와 표시 금액 간 변환이 정확한가?

Address_Validation:
  question: "블록체인 주소 입력이 올바르게 검증되는가?"
  trace: |
    1. EVM 주소: 0x 프리픽스 + 40자 hex + EIP-55 체크섬 검증
    2. TRON 주소: T 프리픽스 + Base58Check 검증
    3. 대소문자 혼용 주소가 정규화(소문자)되어 저장/비교되는가?
    4. zero address (0x000...0) 입력이 거부되는가?
```

## A5 시크릿 (Secret Management)

```yaml
Private_Key_Isolation:
  question: "개인키/니모닉이 메모리에서 안전하게 격리되는가?"
  trace: |
    1. 개인키가 환경 변수로만 전달되는가? (코드/설정 파일 하드코딩 금지)
    2. HSM/KMS 없이 서명하는 경우, 키가 사용 후 메모리에서 즉시 제거되는가?
    3. 니모닉/시드가 로그, 에러 메시지, 스택 트레이스에 노출되지 않는가?
    4. 키 로테이션 메커니즘이 있는가?

Key_Derivation_Security:
  question: "키 파생(BIP-32/39/44)이 안전하게 구현되는가?"
  trace: |
    1. 엔트로피 소스가 CSPRNG(crypto/rand)인가?
    2. 파생 경로가 표준(m/44'/60'/0'/0/n)을 따르는가?
    3. 하드닝된 경로(')가 적절히 사용되는가?
```

## A6 의존성 (Dependencies)

```yaml
RPC_Node_Redundancy:
  question: "RPC 노드가 단일 점인가? 다중화/교차검증이 있는가?"
  trace: |
    1. 단일 RPC 엔드포인트에 의존하는가? (장애 시 서비스 전체 중단)
    2. 다중 노드 사용 시 응답 교차검증(quorum)이 있는가?
    3. RPC 응답의 블록 번호가 최신인지 확인하는가? (stale node 감지)
    4. 무료 공개 RPC 사용 시 Rate Limit/데이터 신뢰성 위험 인지

Oracle_Integrity:
  question: "Oracle/Price Feed 데이터의 무결성이 검증되는가?"
  trace: |
    1. 가격 데이터가 단일 Oracle에 의존하는가?
    2. 가격 편차 임계값(deviation threshold)이 설정되어 조작 감지가 가능한가?
    3. Oracle 업데이트 지연(stale price) 감지가 있는가?

Contract_Dependency_Pinning:
  question: "컨트랙트 의존성이 버전 고정되는가?"
  trace: |
    1. OpenZeppelin 등 라이브러리 버전이 고정(pinned)되는가?
    2. 외부 컨트랙트 호출 시 주소가 하드코딩인가, 교체 가능한가?
    3. 인터페이스 변경 시 호환성 검증이 있는가?
```

## A7 에러 (Error Handling)

```yaml
Revert_Reason_Safety:
  question: "revert reason이 사용자에게 안전하게 전달되는가?"
  trace: |
    1. 컨트랙트 revert reason이 프론트엔드에 그대로 노출되는가?
       → 내부 로직/상태 정보 유출 가능
    2. 커스텀 에러(custom error)가 사용자 친화적으로 변환되는가?
    3. 예상치 못한 revert(OOG, invalid opcode)의 에러 핸들링이 있는가?

Failed_TX_Retry:
  question: "실패 트랜잭션 재시도 시 nonce/가스 관리가 안전한가?"
  trace: |
    1. nonce가 재사용되어 이전 pending 트랜잭션과 충돌하는가?
    2. 가스 가격 에스컬레이션에 상한이 있는가? (무한 가스비 지출 방지)
    3. 재시도 횟수 제한이 있는가?
    4. 실패 원인 분석 없이 맹목적으로 재시도하는가?
```

## A8 리소스 (Resource Consumption)

```yaml
Reentrancy_Guard:
  question: "리엔트런시 가드가 상태 변경 함수에 적용되는가?"
  trace: |
    1. external call 전에 상태가 업데이트되는가? (checks-effects-interactions 패턴)
    2. ReentrancyGuard(nonReentrant modifier)가 자산 이동 함수에 적용되는가?
    3. cross-function reentrancy가 가능한가? (함수 A에서 함수 B 재진입)

Gas_Protection:
  question: "가스 한도 설정이 적절한가?"
  trace: |
    1. 루프 내 external call이 가스를 고갈시킬 수 있는가?
    2. 사용자가 제어하는 배열 길이로 OOG(Out of Gas)를 유발할 수 있는가?
    3. estimateGas 실패 시 기본값이 과도하지 않은가?

MEV_Exposure:
  question: "MEV/프론트러닝 노출이 있는가?"
  trace: |
    1. 대규모 스왑/거래가 mempool에서 샌드위치 공격에 노출되는가?
    2. slippage tolerance가 설정되어 있는가?
    3. commit-reveal 패턴 또는 Flashbots 등 MEV 보호가 고려되는가?
```
