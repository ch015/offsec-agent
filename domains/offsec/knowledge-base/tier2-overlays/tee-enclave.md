---
phases: [va, pentest, verify]
keywords: [tee, enclave, sgx, trustzone]
---
# 도메인 지식: TEE/Enclave 기반 서비스 (Trusted Execution Environment)

> AWS Nitro Enclave, Intel SGX, ARM TrustZone 등 TEE 기반 보안 서비스에 특화된 체크.

---

## Activation

```yaml
Activation:
  domain: Infra
  indicators:
    - "AWS Nitro Enclave 또는 기타 TEE 사용"
    - "VSOCK 통신 기반 아키텍처"
    - "키 관리/서명 서비스를 격리 환경에서 실행"
    - "Shamir's Secret Sharing, 키 파생(BIP-32/39) 등 암호화 연산"
  detection: |
    다음 중 2개 이상이면 활성:
    - Dockerfile/설정에 enclave, nitro, vsock 키워드
    - VSOCK 통신 코드 (AF_VSOCK, CID, port)
    - NSM/Attestation 관련 코드
    - KMS 연동 + 키 시딩/파생 로직
```

---

## Checks

```yaml
TEE_Specific_Checks:

  VSOCK_Communication_Security:
    dimension: A3
    check: |
      Enclave ↔ Host 간 VSOCK 통신 보안:
      1. VSOCK 통신에 메시지 인증(MAC/서명)이 있는가?
      2. 요청/응답 구조에 replay 방어가 있는가?
      3. Host 측에서 Enclave로 전달하는 데이터에
         입력 검증이 있는가?
      4. Enclave가 반환하는 에러가 내부 구현을
         유출하지 않는가?

  Key_Material_Lifecycle:
    dimension: A5
    check: |
      키 자료의 전체 생명주기:
      1. 키 생성: CSPRNG 사용 여부, 생성 위치 (Enclave 내부?)
      2. 키 저장: 암호화 저장 방식 (KMS 래핑, Shamir 분할)
      3. 키 사용: 서명/복호화 시 키가 메모리에 노출되는 시간
      4. 키 폐기: 사용 후 메모리 제로화 (secureClear 등)
         → 컴파일러 최적화로 제거되지 않는지 확인
      5. 키 로테이션: 주기적 키 교체 메커니즘

  Secret_Sharing_Implementation:
    dimension: A1
    check: |
      Shamir's Secret Sharing 구현 보안:
      1. 쉐어 분할 시 각 쉐어의 저장 위치가 물리적으로 분리되는가?
      2. 복원 임계값(threshold)이 적절한가? (2-of-3 등)
      3. 쉐어 할당 시 Go map 등 비결정적 순회에 의존하지 않는가?
      4. 복원 후 원본 시크릿의 메모리 제로화가 보장되는가?

  Attestation_Verification:
    dimension: A1
    check: |
      NSM/TPM Attestation 검증:
      1. 클라이언트가 Enclave의 attestation document를 검증하는가?
      2. PCR 값 검증이 있는가?
      3. attestation document의 서명 검증이 있는가?
      4. attestation document에 nonce/challenge가 바인딩되는가?

  KMS_Integration:
    dimension: A5
    check: |
      AWS KMS 또는 외부 KMS 연동 보안:
      1. KMS 키 정책이 최소 권한인가?
      2. Enclave만 KMS를 호출할 수 있는 정책 조건이 있는가?
      3. KMS 호출 실패 시 폴백이 보안 수준을 하향시키지 않는가?
      4. KMS 래핑된 키의 캐싱 정책이 적절한가?

  Process_Stability:
    dimension: A8
    check: |
      Enclave 프로세스의 안정성:
      1. panic이 전체 Enclave 프로세스를 종료시키는가?
      2. recover()로 패닉을 적절히 처리하는가?
      3. 패닉 발생 시 키 자료가 메모리에 잔류하지 않는가?
      4. 프로세스 재시작 시 키 복원 절차가 안전한가?

  RPC_Proxy_Security:
    dimension: A6
    check: |
      JSON-RPC 프록시 보안 (블록체인 노드 접근 시):
      1. 허용된 RPC 메서드만 화이트리스트 방식으로 통과하는가?
      2. eth_sendRawTransaction 등 위험한 메서드가 제한되는가?
      3. 프록시가 요청 파라미터를 검증하는가?
      4. 프록시를 통한 SSRF가 가능한가?

  Derivation_Path_Validation:
    dimension: A4
    check: |
      HD 지갑 키 파생 경로 검증 (BIP-32):
      1. 파생 경로의 각 세그먼트에 범위 검증이 있는가?
      2. 정수 오버플로우 (int→uint32 캐스팅) 가능성이 있는가?
      3. 하드닝 플래그(') 처리가 올바른가?
      4. 파생 깊이 제한이 있는가?
```
