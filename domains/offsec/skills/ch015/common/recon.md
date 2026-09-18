# 공통 정찰 절차 (Reconnaissance)

> 모든 서비스(VA, Pentest, RedTeam)의 첫 번째 Phase로 실행됩니다.
> 대상 프로젝트를 처음 보는 것처럼 분석하여 기술 스택과 구조를 자동 식별합니다.

---

## 캐시 프로토콜 (Cache Protocol)

```yaml
Cache_Strategy:
  ⚡ 목적: |
    동일 프로젝트의 반복 진단 시 Phase 0을 재수행하지 않는다.
    기술 스택/도메인/공격 표면은 의존성 파일 변경 없이는 동일하므로
    캐시 재사용으로 수 초~수십 초 단축.

  Cache_Key:
    설명: "의존성/빌드 파일들의 SHA256 해시 조합을 fingerprint로 사용"
    invalidation_files:
      - package.json / package-lock.json
      - go.mod / go.sum
      - requirements.txt / pyproject.toml / Pipfile.lock
      - Cargo.toml / Cargo.lock
      - Dockerfile / docker-compose.yml
    규칙: "위 파일 중 하나라도 해시 변경 시 캐시 무효화"

  실행_순서:
    Step_1_Cache_Check: |
      Phase 0 진입 시 먼저 recon-cache를 확인한다:
      [Bash]
        node {plugin_root}/lib/ch015/recon-cache.js check {target}

      HIT: 캐시된 recon_result.yaml을 Read로 로드하여 Phase 0 스킵
      MISS: 정상 Phase 0 수행

    Step_2_Normal_Recon: |
      Cache MISS 또는 --force-refresh 시 정상 정찰 수행
      (Phase 0-1 기술 스택 탐지부터 Phase 0-6 공격 표면 맵까지)

    Step_3_Cache_Save: |
      Phase 0 완료 후 결과를 캐시에 저장:
      [Bash]
        node -e "
          const c = require('{plugin_root}/lib/ch015/recon-cache');
          c.saveReconCache('{target}', {recon_result_yaml});
        "

  TTL: "기본 7일. ch015.config.json의 ch015.reconCache.ttl_days로 조정"
  cache_dir: "ch015.config.json의 ch015.reconCache.cache_dir (기본 .ch015/cache/recon/)"

  Force_Refresh: |
    다음 경우 캐시를 무시하고 재수행:
    - 사용자가 --force-refresh 플래그 지정
    - git checkout으로 브랜치 변경 감지 (HEAD 해시 diff)
    - engagement 디렉토리에 "recon_invalidated" 마커 파일 존재

  병렬_실행_시: |
    dimension_group 모드(4 병렬 Agent) 사용 시 각 Agent는
    Phase 0을 실행하지 않는다. OffSec Lead가 캐시 또는 1회 실행으로
    00_recon_result.yaml을 생성하고, 각 그룹 Agent에
    recon_result_path로 전달하여 Read 재사용.

  Anti_Patterns:
    - "각 그룹 Agent가 독립적으로 Recon 수행 → 4중 중복"
    - "캐시 무효화 없이 모든 실행에서 스킵 → 의존성 변경 반영 실패"
    - "캐시 파일을 engagement 디렉토리에 저장 → 프로젝트 간 공유 안 됨 (플러그인 레벨 저장 필수)"
```

---

## Extended Thinking Protocol

정찰 단계에서 다음 사고 프로토콜을 따릅니다:

- **Pause**: 프로젝트 구조가 완전히 이해될 때까지 분석 지속
- **Decompose**: 기술 스택 → 도메인 → 공격 표면 순으로 분해
- **Evaluate**: 각 도메인에서 보안 관련 컴포넌트 식별
- **Verify**: 탐지 결과를 실제 코드/설정과 교차 검증

---

## Phase 0-1. 기술 스택 탐지

아래는 **대표적 탐지 대상**이며, 프로젝트에 따라 AI가 자율적으로 추가 탐지를 수행합니다.

```yaml
Detection_Methods:
  language:
    method: "의존성 관리 파일(package.json, go.mod, requirements.txt 등)을 스캔하여 주 언어 판별"
    note: "위는 대표 파일이며 Makefile, CMakeLists.txt, mix.exs, build.sbt 등 다른 빌드 시스템도 존재"

  framework:
    method: "설정 파일, import 패턴, 디렉토리 구조로 프레임워크 판별"
    note: "잘 알려진 프레임워크뿐 아니라 커스텀 프레임워크도 인식. 설정 파일 없어도 import 패턴으로 추론"

  auth_provider:
    method: "인증 라이브러리 import, 설정 파일, 환경 변수로 인증 제공자 식별"
    note: "커스텀 인증 구현(자체 JWT, 세션 관리 등)도 식별"

  database:
    method: "ORM/클라이언트 라이브러리 import, 연결 설정, 마이그레이션 파일로 DB 식별"

  deployment:
    method: "배포 설정, Dockerfile, CI/CD 설정으로 배포 환경 판별"
    classification:
      Serverless: "함수 단위 실행, 인스턴스 간 메모리 비공유 → Rate Limit/캐시 아키텍처에 영향"
      Container: "프로세스 단위 실행, 인스턴스 내 메모리 공유 가능"
      Traditional: "단일 서버, 영속적 메모리/파일시스템"

  sca_readiness:
    method: "Lock 파일 존재 여부와 audit 도구 설치 상태를 확인"
    탐지:
      - "Lock 파일: package-lock.json, yarn.lock, go.sum, Cargo.lock 존재 여부"
      - "Audit 도구: npm audit, govulncheck, pip-audit, cargo audit 설치 여부"
      - "Postinstall: package.json scripts 섹션에 preinstall/postinstall 존재 여부"
    output:
      lock_file_present: "true/false"
      audit_tool_available: "도구명 또는 none"
      postinstall_detected: "true/false"

  cloud_platform:
    # P1-2: 클라우드 공격 프리미티브 모듈 로딩 트리거
    method: "IaC/배포 설정/SDK import로 클라우드 플랫폼 식별"
    탐지:
      aws:
        - "terraform 리소스명 `aws_*`, AWS CloudFormation YAML"
        - ".aws/, aws-cli 설정 존재"
        - "`@aws-sdk/*`, boto3, aws-sdk import"
        - "eksctl, aws-load-balancer-controller 설정"
      gcp:
        - "gcloud, `@google-cloud/*`, google-cloud-python import"
        - "terraform `google_*` 리소스"
      azure:
        - "`@azure/*`, azure-identity, azure-storage import"
        - "terraform `azurerm_*` 리소스"
      kubernetes:
        - "helm chart 디렉토리 (Chart.yaml)"
        - "k8s/ 또는 kustomize/ 디렉토리"
        - "Dockerfile + service account 마운트 패턴"
        - "`@kubernetes/client-node`, kubernetes Python client import"
    output:
      cloud_aws_detected: "true/false"
      cloud_gcp_detected: "true/false"
      cloud_azure_detected: "true/false"
      cloud_k8s_detected: "true/false"
    로딩_트리거:
      - "cloud_aws_detected=true → context-loading.md Phase_1 tier2_overlays에서 cloud-aws.md 로드"
      - "cloud_k8s_detected=true → cloud-k8s.md 로드"

  vendor_flags:
    # 벤더/패턴 감지 → 원칙 모듈 로딩 트리거
    method: "SDK import, 환경변수 prefix, config 파일로 벤더/패턴 식별"
    탐지:
      rls_pattern:
        - "Supabase RLS (ALTER TABLE ENABLE ROW LEVEL SECURITY)"
        - "Firebase Rules (firestore.rules, database.rules.json)"
        - "Hasura permissions, Postgres RLS policies"
      oauth_provider:
        - "`@auth0/*`, `@clerk/*`, `aws-sdk/client-cognito-identity-provider` import"
        - "`okta`, `@okta/okta-sdk-nodejs`, Supabase Auth, Firebase Auth import"
      webhook_pattern:
        - "`stripe` webhooks.constructEvent"
        - "인바운드 webhook endpoint (POST 핸들러 + X-*-Signature 헤더 검증 패턴)"
      baas_platform:
        - "`@supabase/supabase-js`, `firebase`, `firebase-admin`, `@aws-amplify/*`"
        - "supabase/ 디렉토리, firebase.json, amplify/ 디렉토리"
    output:
      has_rls: "true/false"
      has_oauth_provider: "true/false"
      has_webhook: "true/false"
      has_baas: "true/false"
    로딩_트리거:
      - "has_rls=true → principles/row-level-security.md 로드"
      - "has_oauth_provider=true → principles/oauth-provider-misconfig.md 로드"
      - "has_webhook=true → principles/webhook-integrity.md 로드"
      - "has_baas=true → principles/baas-trust-boundary.md 로드"

Result_Variables:
  LANG, FRAMEWORK, AUTH, DB, DEPLOY, API_DIR, MIDDLEWARE_FILE, CONFIG_FILE,
  CLOUD_FLAGS (aws/gcp/azure/k8s), VENDOR_FLAGS (supabase/firebase/auth_provider/stripe/generic_webhook)
```

---

## Phase 0-2. 활성 도메인 판별 (Active Domain Determination)

프로젝트 구조와 설정 파일을 분석하여 아래 도메인 중 활성 상태를 결정합니다.

### Tier 1 기술 레이어 (보편적 — 모든 프로젝트에서 해당 레이어 활성 여부 판별)

각 레이어는 Phase 1 이후 차원별 리뷰의 **"어디를 볼 것인가"** 컨텍스트로 사용됩니다.

```yaml
Layer_Detection:
  Backend:
    detection: "서버 측 API 핸들러, 라우터, 미들웨어가 존재하는가?"
    example_indicators: "API 라우트 디렉토리, 서버 프레임워크 설정, 서버 진입점"

  Frontend:
    detection: "클라이언트 측 렌더링, 컴포넌트, 라우팅이 존재하는가?"
    example_indicators: "프론트엔드 프레임워크 설정, 컴포넌트 디렉토리, 빌드 설정"

  BaaS_DB:
    detection: "BaaS 서비스 또는 직접 DB 접근 구조가 존재하는가?"
    example_indicators: "BaaS 설정 디렉토리, ORM 스키마, 마이그레이션 파일"

  Batch_Worker:
    detection: "배치 처리, 작업 큐, 크론 잡, 백그라운드 워커가 존재하는가?"
    example_indicators: |
      큐 소비자: Bull/BullMQ, Celery, Sidekiq, SQS consumer, RabbitMQ consumer
      크론/스케줄러: cron 설정, node-cron, @Scheduled, APScheduler
      배치 처리: batch/, workers/, jobs/ 디렉토리, Worker 클래스 패턴
      이벤트 처리: Kafka consumer, EventBridge handler, Pub/Sub subscriber

  Web3:
    detection: "블록체인/스마트 컨트랙트 관련 코드가 존재하는가?"
    example_indicators: "스마트 컨트랙트 파일, 블록체인 개발 프레임워크 설정"

  Infra:
    detection: "인프라/배포/CI-CD 설정이 존재하는가?"
    example_indicators: "컨테이너 설정, CI/CD 워크플로우, IaC 파일, 환경 변수 파일"

  Mobile:
    detection: "모바일 앱 프로젝트 구조가 존재하는가?"
    example_indicators: |
      React Native: react-native import, metro.config.js, ios/, android/ 디렉토리
      Flutter: pubspec.yaml (flutter SDK), lib/ 디렉토리, dart 파일
      Expo: app.json/app.config.js (expo 설정), expo-router
      Swift/iOS: .xcodeproj, .xcworkspace, Info.plist, AppDelegate
      Kotlin/Android: build.gradle (android plugin), AndroidManifest.xml
      Capacitor/Ionic: capacitor.config.ts, ionic.config.json
    sub_classification:
      Cross_Platform: "React Native, Flutter, Expo, Capacitor — 공유 코드 + 네이티브 브릿지"
      Native_iOS: "Swift/ObjC — 플랫폼 전용 코드"
      Native_Android: "Kotlin/Java — 플랫폼 전용 코드"

  AI_ML:
    detection: "LLM API 호출, 벡터 DB, 임베딩/추론 파이프라인이 존재하는가?"
    example_indicators: |
      LLM 클라이언트 라이브러리 import (openai, anthropic, langchain, llama-index 등)
      벡터 DB 클라이언트 (pinecone, chromadb, weaviate, pgvector 등)
      프롬프트 템플릿 파일, 시스템 프롬프트 정의
      AI 에이전트 프레임워크 (crewai, autogen, semantic-kernel 등)
      모델 서빙 설정 (vllm, ollama, triton 등)

  NativeClient:
    detection: "네이티브 게임 엔진/C++ 기반 클라이언트 SDK 또는 앱인가?"
    example_indicators: |
      Unreal Engine: .uproject 파일, Build.cs 모듈 정의, UCLASS/UPROPERTY 매크로
      Unity: .csproj + Assembly-CSharp, Assets/ 디렉토리, MonoBehaviour 상속
      C++ 클라이언트: CMakeLists.txt + 네이티브 브릿지(JNI, ObjC++) 코드
      네이티브 브릿지: .mm (ObjC++), JNI_OnLoad, UPL XML 파일
      크로스 컴파일: 단일 코드베이스에서 iOS/Android/Desktop 빌드 설정
    sub_classification:
      Engine:
        Unreal: "Unreal Engine — C++ + Blueprint, UPL 네이티브 브릿지"
        Unity: "Unity — C# + 네이티브 플러그인"
        Custom: "커스텀 C++ 엔진 — 직접 빌드 시스템"
      Platform_Bridge:
        Android_JNI: "JNI 기반 Android 네이티브 브릿지"
        iOS_ObjCpp: "ObjC++ 기반 iOS 네이티브 브릿지"
        Desktop: "데스크톱 전용 (브릿지 불필요)"
    note: |
      Mobile 도메인의 Native_iOS/Native_Android와 구분:
      - Mobile: 순수 모바일 앱 (Swift/Kotlin 주 언어)
      - NativeClient: 게임 엔진/C++ 기반 크로스 플랫폼 클라이언트
      SDK 도메인과 겹칠 수 있으나, NativeClient는 메모리 안전성,
      플랫폼 브릿지, 빌드 설정 등 네이티브 고유 보안 관점을 추가한다.

  SDK:
    detection: "이 프로젝트가 외부 개발자에게 배포되는 라이브러리/SDK인가?"
    example_indicators: |
      Node/TS: package.json에 main, module, types, exports 필드 (라이브러리 배포 구조)
      Java/Kotlin: build.gradle에 maven-publish 또는 library 플러그인
      iOS: .podspec 파일, Package.swift (SPM), .xcframework 빌드 설정
      Android: build.gradle에 com.android.library 플러그인, .aar 출력
      Python: setup.py, pyproject.toml에 [project] 또는 setuptools 설정
      Go: 독립 실행 main 패키지 없이 패키지만 제공
      공통: standalone 서버/앱 진입점 없음, example/ 또는 sample/ 디렉토리,
            README에 Installation / Getting Started / Usage 섹션,
            API reference 문서 생성 설정 (typedoc, javadoc, dokka, swiftdoc 등)
    sub_classification:
      Platform:
        Client_Web: "브라우저 환경 SDK (npm, CDN)"
        Client_iOS: "iOS 네이티브 SDK (CocoaPods, SPM, Carthage)"
        Client_Android: "Android 네이티브 SDK (Maven, Gradle)"
        Client_Cross: "크로스 플랫폼 SDK (React Native, Flutter 플러그인)"
        Server_Side: "서버 환경 SDK (npm, pip, Maven)"
        Embedded: "임베디드/IoT SDK"
      Distribution:
        Package_Registry: "npm, Maven Central, CocoaPods, PyPI, pub.dev, crates.io"
        Direct: "GitHub Release, 직접 배포 (.framework, .aar, .whl)"
        CDN: "CDN 스크립트 태그 (<script src>)"
      Type:
        Client_SDK: "클라이언트 앱에서 백엔드와 통신하는 SDK"
        Server_SDK: "서버에서 외부 서비스와 통신하는 SDK"
        Utility_SDK: "통신 없이 로컬 기능 제공하는 유틸리티 라이브러리"
```

### Tier 2 서비스 도메인 시그널 (오버레이 — 해당 프로젝트에만)

Tier 1 레이어 감지 후, 서비스 도메인 시그널을 추가 감지하여 Tier 2 오버레이 로딩 여부를 결정합니다.
`knowledge-base/tier2-overlays/registry.yaml`의 signal 패턴과 매칭합니다.

```yaml
Tier2_Signal_Detection:
  Web3:
    signals: [solidity, ethers.js, web3.js, viem, hardhat, foundry, truffle, smart contract]
    overlay: web3.md (auto)
    sub_signals:
      wallet: [KMS, HSM, key derivation, MPC, threshold, custodial]
      overlay: web3-wallet.md (conditional)

  Payment:
    signals: [stripe, payment gateway, checkout, PG, settlement, refund, invoice]
    overlay: payment.md (auto)

  Commerce:
    signals: [cart, order, product catalog, inventory, coupon, discount, SKU]
    overlay: commerce.md (auto)

  AI_Agent:
    signals: [langchain, openai, anthropic, embedding, vector DB, RAG, agent framework]
    overlay: ai-agent.md (auto)

  Cloud:
    signals: [terraform, cloudformation, IAM, aws_*, gcloud, azurerm_*]
    overlay: cloud.md (auto)
    sub_signals:
      aws: [aws_*, @aws-sdk/*, eksctl, .aws/]
      overlay: cloud-aws.md (conditional)
      k8s: [helm, kustomize, kubectl, Chart.yaml, k8s/]
      overlay: cloud-k8s.md (conditional)

  TEE:
    signals: [SGX, TrustZone, enclave, TEE, secure world]
    overlay: tee-enclave.md (conditional)

  Domain_Gap_Audit: |
    ⚠️ Tier 1 레이어에서 도메인 시그널이 감지되었으나 registry.yaml 조건 미충족으로
    Tier 2 오버레이가 비활성화된 경우, Domain Gap 경고를 발행한다.
    이 경고는 FP-006(도메인 감지 O + 도메인 지식 비활성화 시 확증편향)을 방지한다.
    예: Web3 키워드가 코드에 존재하나 smart contract 파일이 없는 경우
    → "Web3 시그널 감지, web3.md 비활성화 — 일반 차원 체크만 적용됨" 경고.
```

---

## Phase 0-2.5. 프로젝트 레벨 판별 (Project Level Determination)

Phase 0-2에서 탐지된 활성 도메인과 기술 스택을 기반으로 프로젝트 레벨을 자동 판별합니다.

```yaml
Level_Determination:
  regulated:
    description: "금융/의료/규제 산업 — OWASP Top 10 + API Top 10 + Secure Coding + NIST 800-53"
    criteria:
      - "Web3 도메인 활성 (가상자산/지갑/서명/스마트 컨트랙트)"
      - "금융 거래 처리 코드 존재 (결제, 정산, 출금, 자산 이전)"
      - "TEE/Enclave/HSM 관련 코드 존재"
      - "KMS/키 관리/암호화 키 라이프사이클 관련 코드 존재"
      - "의료 데이터(PHI) 처리 코드 존재"
      - "사용자에게 --level regulated가 명시된 경우"
    match: "1개 이상 해당 시 regulated"

  standard:
    description: "BaaS/API 기반 서비스 — OWASP Top 10 + API Top 10 + Secure Coding"
    criteria:
      - "BaaS/DB 도메인 활성 (Supabase, Firebase 등 직접 DB 접근)"
      - "Backend 도메인에서 API 엔드포인트 5개 이상"
      - "AI/ML 도메인 활성 (LLM API 호출, 벡터 DB)"
      - "SDK 도메인 활성 (외부 개발자 대상 라이브러리)"
      - "멀티테넌시 구조 존재"
      - "사용자에게 --level standard가 명시된 경우"
    match: "1개 이상 해당 시 standard (regulated 미해당 시)"

  basic:
    description: "일반 웹/모바일 앱 — OWASP Top 10 중심"
    criteria:
      - "위 두 레벨의 조건에 해당하지 않는 모든 프로젝트"
    match: "기본값"

  override: |
    사용자가 --level 옵션으로 강제 지정한 경우 자동 판별을 무시하고
    지정된 레벨을 적용한다. 자동 판별 결과와 불일치 시 로그에 기록한다.
```

---

## Phase 0-3. 공격 표면 맵 (Attack Surface Map)

Phase 1 이후 각 서비스의 차원별 리뷰에 입력으로 사용되는 공격 표면 맵을 생성합니다.

```yaml
Attack_Surface_Map:
  Entry_Points:
    collect: |
      외부 입력이 시스템에 진입하는 모든 지점을 식별하고,
      각 지점을 (PROTOCOL, OPERATION, AUTH_required)로 기록
    method: |
      1. 프레임워크의 라우팅/핸들러 등록 구조를 파악
      2. 외부 입력을 받는 모든 핸들러 식별 (프로토콜 무관)
      3. 각 핸들러에 인증 호출 존재 여부 태깅
      Note: "HTTP REST뿐 아니라 감지된 모든 통신 프로토콜의 진입점 수집"
    output_example: |
      HTTP REST:
        POST /api/users          → AUTH: yes
        GET  /api/users/[id]     → AUTH: yes
        POST /api/referral/click → AUTH: no   ← 검토 필요
      GraphQL (감지 시):
        QUERY  users             → AUTH: yes
        MUTATION createUser      → AUTH: yes
      WebSocket (감지 시):
        MSG chat.send            → AUTH: yes
        CONNECT /ws              → AUTH: no   ← 검토 필요

  Data_Stores:
    collect: "DB, 캐시, 파일 스토리지, 세션 저장소 식별"
    verify: "각 저장소의 접근 제어 메커니즘"

  Shared_State_Map:
    collect: "동일 저장소에 접근하는 코드 위치(writer/reader)와 동시 접근 후보"
    method:
      1_저장소별_접근자: |
        "이 저장소(테이블/키/큐)에 쓰기하는 코드는 어디인가? 읽기하는 코드는?"
        Data_Stores에서 식별된 각 저장소에 대해 Grep으로 접근 코드를 식별한다.
      2_동시_접근_후보: |
        "동일 저장소에 writer가 2개 이상 존재하는가?"
        존재하면 concurrency_candidate로 태그한다.
        Concurrency 모듈(C1 TOCTOU)의 직접 입력이 된다.
      3_캐시_DB_쌍: |
        "동일 데이터에 대해 캐시와 DB 양쪽에 접근하는 코드가 있는가?"
        존재하면 cache_db_pair로 태그한다.
        Concurrency 모듈(C4 Cache-DB Consistency)의 직접 입력이 된다.
    output_variables:
      - "store_id (저장소 식별자)"
      - "writers (쓰기 접근 코드 위치)"
      - "readers (읽기 접근 코드 위치)"
      - "concurrency_candidate (동시 접근 후보 여부)"
      - "cache_db_pair (캐시-DB 쌍 여부)"
    note: |
      저장소 유형(RDBMS, Redis, MQ, 파일 등)에 따라
      AI가 접근 패턴 탐지 방법을 자율 결정한다.
      위 변수는 수집할 정보 카테고리이며 고정 포맷이 아니다.

  Trust_Boundaries:
    collect: "미들웨어, API 게이트웨이, 인증 레이어 식별"
    verify: "각 경계에서 무엇이 검증되고 무엇이 통과되는지"

  Proxy_Gateway_Architecture:
    collect: "리버스 프록시, API 게이트웨이, BFF, 사이드카 패턴 식별"
    method: |
      다음 패턴으로 프록시/게이트웨이 역할을 감지한다:
      - 다른 서비스로 HTTP 요청 후 응답을 클라이언트에 중계하는 코드
      - Express/Fastify/Go 핸들러에서 upstream fetch → res.send 패턴
      - http-proxy, http-proxy-middleware, httputil.ReverseProxy 등 프록시 라이브러리
      - 응답 헤더를 루프로 복사하는 코드 (for..of headers.entries())
      - 라우트 명에 proxy, gateway, forward, relay 등이 포함된 경로
    output_variables:
      - "proxy_endpoints (프록시 역할 엔드포인트 목록)"
      - "upstream_targets (프록시 대상 서비스 출처 — 환경변수/Redis/DB/하드코딩)"
      - "response_passthrough (응답 헤더/바디 패스스루 방식 — allowlist/denylist/전체)"
    trigger: |
      감지 시 Phase 1 A3 Upstream_Response_Reflection 및
      A6 Proxy_Gateway_Response_Trust 분석을 필수 활성화한다.
      프록시 엔드포인트가 3개 이상이면 depth/data-flow.md 로딩을 권고한다.

  External_Services:
    collect: "서드파티 API 호출, 웹훅, OAuth 제공자 식별"
    verify: "외부 응답이 검증/새니타이징 되는지"

  Client_Exposure:
    collect: "클라이언트 번들에 포함되는 환경 변수, API 키, 설정 식별"
    method: |
      프레임워크별 클라이언트 노출 접두사 식별
      (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ 등)
      빌드 시 번들에 포함되는 모든 설정도 추적

  Auth_Topology:
    collect: "인증/인가 미들웨어의 적용 구조, 실행 순서, 적용 범위"
    method:
      1_미들웨어_실행_순서: |
        "요청이 핸들러에 도달하기까지 어떤 보안 미들웨어를 어떤 순서로 거치는가?"
        AI가 프레임워크의 미들웨어 등록 구조를 파악하여 자율 추적한다.
        순서가 보안에 영향: 파싱 에러가 인증 전에 발생하면 인증 우회 가능.
      2_인증_적용_범위: |
        "모든 엔드포인트에 인증이 적용되는가? 제외된 경로가 있는가?"
        글로벌 적용 + 예외 목록, 그룹별 적용, 핸들러 내 수동 호출 —
        어떤 패턴이든 AI가 프레임워크에 맞게 자율 탐지한다.
      3_인증_분기: |
        "동일 엔드포인트에 여러 인증 방식이 존재하는가? 실패 시 fallback이 있는가?"
        JWT + API Key 병용, 인증 실패 시 anonymous fallthrough 등을 식별.
      4_토큰_흐름: |
        "토큰/세션의 발급 → 전달 → 검증 → 갱신 → 폐기 경로는?"
    output_variables:
      - "middleware_chain_order (보안 미들웨어 실행 순서)"
      - "auth_protected_routes (인증 적용 경로 그룹)"
      - "auth_unprotected_routes (인증 미적용 경로)"
      - "auth_opt_out_routes (명시적 제외 경로 — Phase 1 A1 검토 후보)"
      - "auth_fallback (인증 실패 시 동작 — anonymous 허용 여부)"
      - "token_lifecycle (발급~폐기 경로 요약)"
    note: |
      출력 구조는 프로젝트의 기술 스택에 따라 AI가 자율 조정한다.
      위 변수는 수집할 정보의 카테고리이며, 고정 스키마가 아니다.

  SDK_Surface:
    condition: "SDK 도메인이 활성인 경우에만 수집"
    collect: "SDK 공개 API 표면, 생명주기, 백엔드 통신, 로컬 저장, 배포 구조"
    method: |
      SDK 도메인이 감지되면 아래 항목을 추가로 수집한다:

      1. Public API Surface (공개 API 표면):
         - 외부에 export되는 클래스, 함수, 타입, 상수 전체 목록
         - 초기화(init/configure/setup) 진입점과 필수/선택 파라미터
         - 개발자가 설정 가능한 옵션(Options/Config 객체)과 각 기본값
         - 내부 전용으로 의도되었으나 접근 가능한 API (접근 제어 누락 후보)

      2. SDK Lifecycle (생명주기):
         - 초기화 → 설정 → 인증 → 사용 → 해제 흐름
         - 각 단계의 상태 전이 조건
         - 싱글톤 패턴 또는 다중 인스턴스 지원 여부

      3. Backend Communication (백엔드 통신):
         - SDK가 통신하는 백엔드 엔드포인트 목록과 베이스 URL 설정 방식
         - 인증 방식 (API Key 헤더, OAuth 토큰, 커스텀 서명)
         - 전송 프로토콜 (HTTPS, WebSocket, gRPC)
         - 재시도/폴백 로직과 타임아웃 설정
         - Certificate Pinning 적용 여부

      4. Local Storage (로컬 저장):
         - SDK가 로컬에 저장하는 데이터 종류 (캐시, 토큰, 설정, 로그)
         - 저장 매체 (메모리, 파일, DB, Keychain/Keystore, SharedPreferences)
         - 저장 데이터의 암호화 여부와 방식

      5. Distribution & Packaging (배포/패키징):
         - 빌드 출력물 구성 (소스맵, 심볼 파일, 디버그 정보 포함 여부)
         - 배포 채널 설정 (패키지 레지스트리, CDN, 직접 배포)
         - 아티팩트 서명/무결성 검증 설정
         - 난독화/최소화 적용 여부
```

---

## Phase 0-3.5. Asset Identification (자산 식별)

프로젝트의 핵심 보호 대상을 코드에서 식별하고 가치를 평가합니다.

```yaml
Asset_Identification:
  methodology: |
    코드 구조와 DB 스키마에서 비즈니스 엔티티를 추출하여
    보안 분석의 비즈니스 컨텍스트를 제공한다.
    ⚠️ 분석 깊이를 조절하지 않는다 — 모든 차원은 동일 깊이로 분석.
    자산 가치는 Finding에 태그되어 우선순위와 비즈니스 영향 판단에 사용.

  탐지_대상:
    Financial_Assets: "결제, 잔액, 포인트, 토큰, 지갑, 거래 관련 엔티티"
    User_Accounts: "인증, 세션, 프로필, 역할/권한 관련 엔티티"
    PII: "개인식별정보 — 이름, 이메일, 전화, 주소, 주민번호 등"
    Secrets: "API 키, 서명 키, 암호화 키, 자격증명"
    Business_Logic: "핵심 비즈니스 규칙을 구현하는 서비스/함수"
    Content: "사용자 생성 콘텐츠, 지적재산, 설정"

  가치_등급:
    CROWN_JEWEL: "침해 시 사업 존속 위협 (예: 결제 키, 전체 사용자 DB, 서명 키)"
    HIGH: "침해 시 중대한 비즈니스 손실 (예: 개별 계정, PII, 거래 기록)"
    MEDIUM: "침해 시 제한적 손실 (예: 비핵심 설정, 공개 콘텐츠 메타데이터)"
    LOW: "침해 시 최소 영향 (예: UI 설정, 캐시 데이터)"

  output: |
    Asset_Register:
      - entity: "엔티티명"
        type: "Financial | Account | PII | Secret | Logic | Content"
        value: "CROWN_JEWEL | HIGH | MEDIUM | LOW"
        location: "주요 코드 위치 (file:line 또는 디렉토리)"
        cia_impact:
          confidentiality: "유출 시 영향"
          integrity: "변조 시 영향"
          availability: "접근 불가 시 영향"
```

---

## Phase 0-4. API 엔드포인트 인벤토리

프레임워크별 라우트 등록 패턴을 탐색하여 전체 API 엔드포인트 목록을 생성합니다.

```yaml
프레임워크별_라우트_탐색:
  방법론: |
    "특정 프레임워크 구문에 의존하지 않는다.
     프레임워크의 라우팅/핸들러 등록 구조를 파악하고,
     AI가 감지된 스택에 맞는 패턴을 자율적으로 결정한다."

  대표적_패턴: # 참고용 예시, 이에 한정되지 않음
    Next.js:
      - "src/app/**/route.ts → App Router API Routes"
      - "pages/api/**/*.ts → Pages Router API Routes"
    Express:
      - "router.get/post/put/patch/delete() 패턴"
    Go_HTTP:
      - "라우터 라이브러리(chi, gin, mux 등)의 라우트 등록 함수"
    Python_Web:
      - "FastAPI 데코레이터, Django urlpatterns, Flask route"
```

### 자동 노출 엔드포인트 추론 (Auto_Exposed_Endpoints)

코드에 명시된 라우트 외에, **프레임워크/라이브러리/설정이 자동 노출하는 엔드포인트**를 추론합니다.
이 추론 결과는 후속 Phase의 입력이 되며, 후속 Phase는 자체 추론하지 않습니다 (재현성 보장 + 책임 분리).

```yaml
Auto_Exposed_Endpoints_Inference:
  목적: |
    프레임워크가 코드 명시 없이 자동 노출하는 엔드포인트를 추론한다.
    이 결과는 다음의 입력이 된다:
    - VA Phase 1 A2(인가): 관리자/디버그 엔드포인트 보호 검토
    - VA Phase 1 A5 Active_State_Management: 프로덕션 디버그/내부 비활성화 검토
    - api.yaml API-INV-002: 문서화되지 않은 엔드포인트 검토
    - Pentest Phase 6.0 Sweep_3: 라이브 검증 (--url 시)

  방법론:
    No_Pattern_List: |
      "고정 카탈로그를 외부 파일에서 로드하지 않는다.
       Phase 0-1에서 감지된 프레임워크/의존성/설정에서 AI가 자율 추론한다.
       프레임워크 버전 변경 시 카탈로그 갱신 필요 없음."

    Evidence_Required: |
      "각 후보에 의존성/설정/코드 증거(file:line 또는 dependency 참조) 필수.
       증거 없는 추론은 출력하지 않는다 (오탐 방지)."

    Reachability_Check: |
      "비활성화 설정 발견 시 후보에서 제외.
       (예: management.endpoints.web.exposure.exclude=* 설정 → /actuator/* 미출력)"

  탐색_차원:
    1_의존성_분석: |
      Phase 0-1의 의존성 파일을 분석하여 자동 노출 라이브러리 식별:
      - 의존성 자체가 엔드포인트를 자동 등록하는가?
      - AI는 프레임워크 동작 원리에서 추론 (패턴 목록 아님)
      
      대표 예시 (참고, 이에 한정되지 않음):
      - spring-boot-starter-actuator → /actuator/* (헬스/메트릭/env/beans 등)
      - springdoc-openapi-ui → /swagger-ui/, /v3/api-docs
      - @nestjs/swagger → SwaggerModule.setup() 호출 경로
      - fastapi → /docs, /redoc, /openapi.json (기본)
      - django.contrib.admin → /admin/
      - flask-admin → /admin/
      - express-actuator → /info, /metrics, /health

    2_설정_파일_분석: |
      프레임워크 설정에서 자동 노출 활성/비활성 여부 확인:
      - Spring: application.{properties,yml}의 management.endpoints.web.exposure
      - NestJS: main.ts의 SwaggerModule.setup() 호출 경로
      - FastAPI: FastAPI(docs_url=, redoc_url=) 설정
      - Django: settings.py의 INSTALLED_APPS, DEBUG, urls.py의 admin 등록
      - Express: app.use(swaggerUi.serve, ...) 호출 경로

    3_프레임워크_명세_지식: |
      AI가 감지된 프레임워크의 기본 노출 동작을 추론한다.
      - 프레임워크 미감지 시 추론하지 않음 (오탐 방지)
      - 버전별 기본값 차이가 있으면 의존성 버전 참조

    4_명시적_비활성화_확인: |
      비활성화 코드/설정 발견 시 해당 후보 제거:
      - production 프로파일에서 swagger 비활성화
      - DEBUG=False 시 Django debug toolbar 미노출
      - actuator endpoint exclude 설정

  출력_형식:
    Auto_Exposed_Endpoints:
      - path: "/actuator/health"
        framework: "Spring Boot"
        confidence: "high | medium | low"
        evidence:
          - "spring-boot-starter-actuator (pom.xml:42)"
          - "management.endpoints.web.exposure 미명시 (application.properties)"
        config_check: "기본 노출 (명시적 비활성화 없음)"
        sensitivity: "low (헬스만) — env/beans/mappings 추가 노출 시 high"
        downstream:
          - "VA A5 Active_State_Management 입력"
          - "Pentest Sweep_3 검증 대상"

      - path: "/swagger-ui/"
        framework: "Spring Boot + springdoc-openapi"
        confidence: "high"
        evidence:
          - "springdoc-openapi-ui (pom.xml:67)"
        config_check: "production 프로파일 비활성화 미확인"
        sensitivity: "API 명세 노출 (medium)"

  미감지_시:
    출력: "Auto_Exposed_Endpoints: []"
    의미: |
      자동 노출 라이브러리 미감지 — 프레임워크가 자동 노출하지 않거나
      ch015가 추론할 수 있는 증거 부재. 후속 Phase는 자체 추론하지 않음.

  Anti_Patterns:
    - "고정 카탈로그를 외부 파일에서 로드 (가변성 부담, 철학 위반)"
    - "감지되지 않은 프레임워크에 대해 추측으로 후보 생성 (오탐)"
    - "증거(의존성/설정 file:line) 없이 후보 출력"
    - "활성화 여부 확인 없이 의존성만 보고 후보 생성"
```

---

## Phase 0-5. 환경 변수 참조 수집

코드 전체에서 환경 변수 참조를 수집하여 민감 정보 후보를 식별합니다.

```yaml
탐색_방법론: |
  "특정 접두사(sk-, AKIA 등)만 검색하는 것은 불충분하다.
   AI가 컨텍스트와 엔트로피를 기반으로 시크릿 존재를 자율적으로 판단한다."

탐색_대상:
  - "환경 변수 접근 코드 (언어별 관용 패턴)"
  - "설정 파일 (.env.example, config.toml, config.yaml)"
  - "하드코딩 후보 (높은 엔트로피 문자열, 자격 증명 컨텍스트)"
```

---

## Phase 0-6. 디렉토리 구조 분석

```yaml
분석_항목:
  - 전체 디렉토리 트리 (주요 디렉토리만)
  - 컴포넌트별 분류 (프론트엔드, 백엔드, DB, 인프라)
  - 진입점 파일 식별 (main, index, app, server)
  - 설정 파일 목록
  - 테스트 디렉토리 존재 여부
```

---

## Context Binding: Phase 0 → Phase 1 Bridge

Phase 0에서 탐지된 환경 변수와 도메인 정보는 Phase 1의 아키텍처 판단에 직접 영향을 미칩니다.

```yaml
Binding_Rules:
  DEPLOY_Cross_Judgment:
    description: |
      Phase 0에서 탐지된 배포 환경(DEPLOY)은 Phase 1 모든 차원의
      보안 메커니즘 적합성 판단에 교차 적용됩니다.

    principle: |
      "보안 메커니즘이 배포 환경의 특성과 호환되는가?"
      동일한 코드라도 배포 환경에 따라 안전/위험 판정이 달라질 수 있습니다.

    examples:
      - "인메모리 상태(Map, 전역 변수)에 의존하는 보안 메커니즘이 있는가?"
      - "해당 상태가 배포 환경에서 인스턴스 간 공유/영속되는가?"
      - "Serverless에서 인메모리 상태를 공유 스토리지(Redis, DB 등)로 이전해야 하는가?"

  Domain_Traversal:
    description: |
      각 아키텍처 차원 분석 시 모든 활성 도메인을 순회합니다.
      도메인은 "어디를 볼 것인가" 컨텍스트일 뿐, 조직 원리가 아닙니다.

  Domain_Knowledge_Injection:
    description: |
      활성 도메인에 대응하는 Tier 2 오버레이 파일이 knowledge-base/tier2-overlays/에
      존재하는 경우, Phase 1~2 분석에 해당 체크리스트를 추가 적용합니다.
    mechanism: |
      1. Phase 0에서 Tier 1 레이어 + Tier 2 서비스 도메인 시그널이 결정되면
         knowledge-base/tier2-overlays/registry.yaml을 참조한다.
      2. registry.yaml의 signal 패턴과 매칭되는 오버레이를 로드한다.
         - auto: 도메인 시그널 감지 즉시 로드
         - conditional: 세부 시그널 매칭 시에만 로드
      3. 매칭된 오버레이의 8차원 체크를 Phase 1 해당 차원과
         Phase 2 심층 분석에 추가 질문으로 주입한다.
    available_overlays:
      auto:
        - "web3.md — Web3 공통 (DeFi, Wallet, DEX, DAO, NFT)"
        - "payment.md — 결제 플랫폼 (PG, 정산, 환불, FDS)"
        - "sdk.md — SDK 전 플랫폼 (JS/Android/iOS/Unity/Unreal)"
        - "ai-agent.md — AI/Agent 플랫폼 (LLM, RAG, 도구 호출)"
        - "commerce.md — 커머스 (상품/재고/카트/주문)"
        - "cloud.md — 클라우드 공통 (IAM, 네트워크, 시크릿)"
      conditional:
        - "web3-wallet.md — 임베디드 월렛 (KMS/HSM/MPC 감지 시)"
        - "cloud-aws.md — AWS 특화 (AWS 리소스 감지 시)"
        - "cloud-k8s.md — Kubernetes 특화 (K8s 매니페스트 감지 시)"
        - "tee-enclave.md — TEE/Enclave (SGX/TrustZone 감지 시)"
    note: |
      Tier 2 오버레이는 Tier 1 차원의 방법론과 원칙을 변경하지 않는다.
      해당 도메인에 특화된 추가 질문만 주입한다.
      도메인 시그널 감지 O + 오버레이 비활성화 시 Domain Gap 경고를 발행한다 (FP-006).
```

---

## 정찰 결과 출력 포맷

```
┌─────────────────────────────────────────────────────────────┐
│ PROJECT DISCOVERY REPORT                                    │
├─────────────────────────────────────────────────────────────┤
│ Language:   {LANG}                                          │
│ Framework:  {FRAMEWORK}                                     │
│ Auth:       {AUTH}                                           │
│ DB:         {DB}                                             │
│ Deployment: {DEPLOY}                                        │
│ Active Domains: Backend ☐/☑  Frontend ☐/☑  BaaS/DB ☐/☑    │
│                 Web3 ☐/☑    Infra ☐/☑                      │
│                 Mobile ☐/☑  AI/ML ☐/☑    SDK ☐/☑           │
│                 NativeClient ☐/☑                            │
│ Level:      [basic / standard / regulated]                  │
│ Domain KB:  [로드된 도메인 지식 파일 목록 또는 "none"]       │
├─────────────────────────────────────────────────────────────┤
│ API Count:   [엔드포인트 수]                                │
│ Env Vars:    [환경 변수 수 / 민감 변수 후보 수]              │
│ Entry Points: [인증 필요: X / 비인증: Y]                    │
│ Data Stores:  [저장소 수]                                   │
│ External Services: [외부 서비스 수]                         │
├─────────────────────────────────────────────────────────────┤
│ Auth Topology:                                              │
│   Middleware Chain: [미들웨어 실행 순서]                      │
│   Protected Routes: [인증 적용 경로 수]                      │
│   Unprotected:      [인증 미적용 경로 수]                    │
│   Opt-out:          [명시적 제외 경로 수] ← A1 검토 후보     │
│   Fallback:         [인증 실패 시 동작]                      │
├─────────────────────────────────────────────────────────────┤
│ Shared State:                                               │
│   Stores: [저장소 수]                                       │
│   Concurrency Candidates: [동시 접근 후보 수]                │
│   Cache-DB Pairs: [캐시-DB 쌍 수]                           │
├─────────────────────────────────────────────────────────────┤
│ Asset Register:                                             │
│   CROWN_JEWEL: [수]  HIGH: [수]  MEDIUM: [수]  LOW: [수]   │
│   Top Assets: [상위 자산명 나열]                             │
├─────────────────────────────────────────────────────────────┤
│ SDK Info (SDK 도메인 활성 시):                               │
│   Platform:     [Client_Web / Client_iOS / ...]             │
│   Distribution: [npm / Maven / CocoaPods / ...]             │
│   Type:         [Client SDK / Server SDK / Utility]         │
│   Public API:   [exported 클래스/함수 수]                    │
│   Lifecycle:    [init → configure → use → teardown]         │
│   Backend Comm: [엔드포인트 수 / 프로토콜]                   │
│   Local Storage:[저장 항목 수 / 암호화 여부]                  │
└─────────────────────────────────────────────────────────────┘

## Attack Surface Map
| Protocol | Operation | Auth | Notes |
|----------|-----------|------|-------|
| ...      | ...       | ...  | ...   |

## Active Domain Summary
| Domain | Status | Key Components |
|--------|--------|----------------|
| ...    | ...    | ...            |

## Auth Topology
| Layer | Middleware | Applied To | Notes |
|-------|-----------|------------|-------|
| ...   | ...       | ...        | ...   |

## Shared State Map
| Store | Writers | Readers | Concurrency | Cache-DB |
|-------|---------|---------|-------------|----------|
| ...   | ...     | ...     | ...         | ...      |

## Asset Register
| Entity | Type | Value | Location |
|--------|------|-------|----------|
| ...    | ...  | ...   | ...      |

[컴포넌트별 디렉토리 트리]
```

---

## Recon Self-Validation (Phase 0 완료 직후)

Recon 결과는 하류 전체(체크리스트 로딩, depth 파일 선택, 차원별 분석 범위)를 결정하는 기초 데이터다.
Phase 0.5 Binding 진입 전에 아래 7개 검증을 수행하고, FAIL 항목이 있으면 조치 후 진행한다.

```yaml
Recon_Self_Validation:

  V1_Workspace_Boundary:
    check: "target_source_path가 engagement에서 허용된 workspace 경계 안인가?"
    method: |
      target_source_path를 realpath로 해석하고,
      AGENT_ENGAGEMENT_DIR 또는 사용자가 지정한 프로젝트 루트의 하위인지 확인한다.
      심볼릭 링크가 경계 밖을 가리키면 FAIL.
    on_fail: "Phase 0 중단. 경로 오류를 사용자에게 보고."

  V2_AST_Parse_Coverage:
    check: "AST 파싱 실패 파일 비율이 허용 임계치 이내인가?"
    method: |
      --mode ast 사용 시, ast-context.yaml의 parse_errors 또는
      context-builder.js 로그에서 실패 파일 수를 추출한다.
      실패율 = 파싱 실패 파일 수 / 전체 소스 파일 수
    thresholds:
      warn: "> 20% 실패"
      fail: "> 50% 실패"
    on_warn: |
      경고 기록 + 실패 파일 목록을 Recon 출력에 포함.
      Phase 1에서 해당 파일들은 Grep/Read 기반 보완 탐색 대상으로 표시.
    on_fail: |
      AST 모드 포기 → LLM-only 폴백.
      폴백 시 잃어버린 데이터 유형(call_graph, data_flows, entry_points, semgrep)을
      Recon 출력의 ast_fallback_impact 필드에 명시 기록.

  V3_Entry_Point_Completeness:
    check: "발견된 엔트리포인트 수가 프로젝트 규모 대비 합리적인가?"
    method: |
      1. 라우트 파일 수 기반 기대치 산출:
         Glob으로 라우트/컨트롤러 패턴 파일 수를 센다
         (예: **/route.ts, **/controller.*, **/api/**/*.go)
      2. Recon이 발견한 Entry Points 수와 비교
      3. 발견 수 < 라우트 파일 수 × 0.5 이면 누락 의심
    on_fail: |
      누락 의심 프레임워크/디렉토리를 식별하여 추가 탐색 수행.
      재탐색 후에도 차이가 크면 recon_gaps 필드에 기록하고 Phase 1 진행.

  V4_Language_Framework_Cross_Check:
    check: "감지된 언어/프레임워크가 실제 import문·코드 패턴과 일치하는가?"
    method: |
      1. 의존성 파일 기반 탐지 결과 (Language, Framework)
      2. 실제 소스 파일의 import/require/use 문에서 프레임워크 시그널 Grep
      3. 불일치 감지:
         - 의존성에 express 있는데 import문에 fastify만 있으면 → 프레임워크 오탐
         - import에 django 있는데 의존성 파일에 없으면 → 의존성 파일 불완전
    on_fail: |
      import 기반 재판별 수행. 양쪽 결과를 병기하고 import 기반을 우선.

  V5_Scale_Metrics_Recording:
    check: "프로젝트 규모 수치(source_file_count, LOC, subproject_count)가 측정·기록되었는가?"
    method: |
      Recon 완료 시 아래를 반드시 산출하여 출력에 포함:
      - source_file_count: find로 소스 파일 수 (제외 디렉터리 적용 후)
      - loc_estimate: wc -l 또는 cloc 기반 추정치
      - subproject_count: 독립 빌드 파일(package.json, go.mod 등) 기준
    on_fail: "수치 산출 실패 시 'unknown'으로 기록. Large Scale Flow 판별을 보수적(full)으로 적용."
    cross_check: |
      source_file_count < 10 이면 경로 오류 또는 제외 규칙 과다 의심 → V6 재확인.

  V6_Exclusion_Audit:
    check: "제외된 디렉터리 규칙이 소스 코드를 과도하게 배제하지 않았는가?"
    method: |
      1. 제외 적용된 디렉터리 목록을 기록:
         기본 제외: node_modules, vendor, dist, build, .git, __pycache__, .next, .nuxt
      2. 제외 디렉터리 내 소스 파일 존재 여부 샘플 확인:
         예: vendor/ 안에 프로젝트 자체 코드가 있으면 (monorepo vendor 패턴) 과다 제외
      3. 제외 후 남은 소스 파일 수가 V5의 기대치와 현저히 다르면 FAIL
    on_fail: |
      과다 제외 의심 디렉터리를 제외 목록에서 복원하고 Recon 재수행.
      복원 불가 시 exclusion_overrides 필드에 사유 기록.

  V7_Empty_Result_Gate:
    check: "Recon 핵심 필드가 빈 값이 아닌가?"
    method: |
      아래 필드 중 하나라도 빈 값(null, empty, 0)이면 FAIL:
      - Language
      - Framework (unknown 허용, empty 불가)
      - Entry Points (0이면 FAIL)
      - Active Domains (최소 1개)
    on_fail: |
      Phase 0.5 진입 차단.
      "⛔ Recon 결과가 불완전합니다. 대상 경로와 프로젝트 구조를 확인하세요."
      target_source_path, 실행된 Glob/Grep 패턴, 결과를 사용자에게 보고.

Validation_Output:
  형식: |
    Recon 출력 말미에 검증 결과 섹션 추가:

    ## Recon Self-Validation
    | Check | Result | Detail |
    |-------|--------|--------|
    | V1 Workspace Boundary | PASS/FAIL | ... |
    | V2 AST Parse Coverage | PASS/WARN/FAIL/SKIP | 실패율 N%, 실패 파일 수 |
    | V3 Entry Point Completeness | PASS/WARN | 발견 N / 기대 M |
    | V4 Language/Framework | PASS/WARN | ... |
    | V5 Scale Metrics | PASS | files: N, LOC: ~M, subprojects: K |
    | V6 Exclusion Audit | PASS/WARN | 제외 디렉터리 N개, 복원 M개 |
    | V7 Empty Result Gate | PASS/FAIL | ... |

  차단_조건: "V1 FAIL 또는 V7 FAIL → Phase 0.5 진입 불가"
  경고_조건: "V2-V6 WARN/FAIL → 기록 후 진행 (하류 Phase에서 보완 탐색)"
```
