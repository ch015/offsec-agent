---
phases: [va, pentest, verify]
keywords: [sdk, library, api-client]
---
# Tier 2 Overlay: SDK 전 플랫폼 통합

> SDK/라이브러리 프로젝트에 적용.
> JS, Android(Kotlin), iOS(Swift), Unity(C#), Unreal(C++) 전 플랫폼 커버.
> 기존 unreal-sdk.md 내용을 흡수하고 전 플랫폼으로 확장.

---

## 공통 — 모든 SDK 플랫폼

```yaml
SDK_Key_Hardcoding:
  question: "API 키/시크릿이 SDK 바이너리에 하드코딩되는가?"
  trace: |
    1. Public Key(pk_)만 SDK에 포함되고 Secret Key(sk_)는 포함되지 않는가?
    2. 환경별 URL(dev/stg/prod)이 바이너리에 하드코딩되어 있는가?
    3. 문자열 난독화 없이 평문으로 키가 포함되는가?
    4. 리버스 엔지니어링으로 추출 가능한 민감 정보가 있는가?

SDK_Distribution_Security:
  question: "SDK 빌드/배포 산출물이 안전한가?"
  trace: |
    1. 디버그 심볼이 릴리스 빌드에서 스트립되는가?
    2. Development/Debug 전용 코드가 조건부 컴파일로 제외되는가?
    3. CI/CD에서 시크릿이 안전하게 관리되는가?
    4. 아티팩트 서명/체크섬이 제공되는가?
    5. 서드파티 라이브러리 버전이 고정(pinned)되어 알려진 CVE가 없는가?

SDK_Permission_Scope:
  question: "SDK가 요구하는 권한이 최소 권한 원칙을 따르는가?"
  trace: |
    1. 모바일: 요구하는 시스템 권한(카메라, 위치, 연락처 등)이 SDK 기능에 필수적인가?
    2. 서버: 요구하는 IAM/DB 권한이 최소인가?
    3. 브라우저: 요구하는 API 접근(localStorage, cookies, geolocation)이 최소인가?

SDK_Resource_Impact:
  question: "SDK가 호스트 앱의 리소스를 과도하게 사용하지 않는가?"
  trace: |
    1. SDK 초기화 시 블로킹 네트워크 호출이 있는가?
    2. 백그라운드 폴링/하트비트의 주기와 배터리 영향이 적절한가?
    3. 메모리 사용량이 호스트 앱 대비 과도하지 않은가?
    4. SDK 해제(destroy/dispose) 시 모든 리소스가 정리되는가?

SDK_Host_Dependency_Conflict:
  question: "호스트 앱과 SDK 의존성이 충돌하지 않는가?"
  trace: |
    1. SDK가 특정 라이브러리 버전을 강제하여 호스트 앱과 충돌하는가?
    2. 의존성이 내부에 격리(shade/relocate)되는가?
    3. 전역 상태(싱글톤, static 변수)가 호스트 앱과 간섭하는가?

SDK_TLS_Pinning:
  question: "SDK↔서버 간 TLS 핀닝이 구현되는가?"
  trace: |
    1. 인증서 핀닝이 구현되어 MITM이 방지되는가?
    2. 핀 갱신 메커니즘이 있는가? (인증서 만료 시 SDK 업데이트 없이 갱신)
    3. 디버그 모드에서 핀닝 비활성화 코드가 릴리스에 남아있는가?
```

## JS SDK

```yaml
JS_NPM_Supply_Chain:
  question: "npm 패키지 공급망이 안전한가?"
  trace: |
    1. package-lock.json이 커밋되고 CI에서 npm ci로 설치되는가?
    2. postinstall 스크립트에 의심스러운 코드가 있는가?
    3. 의존성에 알려진 CVE가 있는가? (npm audit)

JS_Browser_API_Exposure:
  question: "브라우저 API 노출이 최소화되는가?"
  trace: |
    1. localStorage/sessionStorage에 민감 정보(토큰, 키)가 저장되는가?
    2. window 전역 객체에 SDK 내부 메서드가 노출되는가?
    3. postMessage 핸들러에서 origin 검증이 있는가?
    4. eval/Function 생성자가 사용되는가?

JS_SDK_Iframe:
  question: "iframe 기반 SDK의 격리가 올바른가?"
  trace: |
    1. iframe의 sandbox 속성이 적절히 설정되는가?
    2. 부모↔iframe 통신이 postMessage로만 이루어지는가?
    3. origin 화이트리스트가 서버 사이드에서 관리되는가?
```

## Android SDK (Kotlin)

```yaml
Android_Secure_Storage:
  question: "Android 보안 저장소가 올바르게 사용되는가?"
  trace: |
    1. EncryptedSharedPreferences 또는 Android Keystore 래핑이 사용되는가?
    2. SharedPreferences 평문 저장 fallback이 프로덕션에 포함되는가?
    3. 저장소 실패 시 평문 파일로 폴백하는 경로가 있는가?

Android_ProGuard:
  question: "ProGuard/R8 난독화가 보안 관련 코드에 적용되는가?"
  trace: |
    1. 보안 관련 클래스가 난독화 대상에 포함되는가?
    2. keep 규칙이 과도하여 역공학이 용이한가?

Android_Intent_Exposure:
  question: "Android Intent/Activity 노출이 최소화되는가?"
  trace: |
    1. exported=true인 Activity/BroadcastReceiver가 최소인가?
    2. Intent 수신 시 caller 검증이 있는가?
    3. 딥링크 핸들러에서 입력 검증이 있는가?

Android_Permissions:
  question: "AndroidManifest 권한이 최소인가?"
  trace: |
    1. INTERNET 외에 불필요한 권한(CAMERA, LOCATION, CONTACTS 등)이 선언되는가?
    2. UPL/Gradle 플러그인에 의해 자동 추가되는 권한이 있는가?
```

## iOS SDK (Swift)

```yaml
iOS_Keychain:
  question: "iOS Keychain이 올바르게 사용되는가?"
  trace: |
    1. kSecAttrAccessibleWhenUnlockedThisDeviceOnly 이상의 접근 수준이 사용되는가?
    2. Keychain 접근 그룹이 적절히 설정되는가?
    3. 키체인 항목이 기기 간 동기화(iCloud Keychain) 대상에 포함되지 않는가?

iOS_ATS:
  question: "App Transport Security가 적절히 설정되는가?"
  trace: |
    1. NSAllowsArbitraryLoads가 YES로 설정되어 있지 않은가?
    2. 예외 도메인(NSExceptionDomains)이 최소인가?

iOS_Entitlements:
  question: "iOS entitlements에 불필요한 capability가 없는가?"
  trace: |
    1. SDK 기능에 필수적이지 않은 entitlement가 있는가?
    2. Associated Domains가 올바르게 설정되는가? (Universal Links)
```

## Unity SDK (C#)

```yaml
Unity_IL2CPP:
  question: "Unity 빌드의 코드 보호가 적절한가?"
  trace: |
    1. IL2CPP 빌드가 사용되는가? (Mono는 디컴파일 용이)
    2. Managed 코드에 민감 로직이 노출되는가?
    3. Asset Bundle에 민감 데이터가 평문으로 포함되는가?

Unity_Native_Plugin:
  question: "네이티브 플러그인의 보안이 적절한가?"
  trace: |
    1. 네이티브 플러그인(.dll/.so/.dylib)이 서명되는가?
    2. P/Invoke 호출 시 입력 검증이 있는가?
    3. 네이티브 메모리 관리(alloc/free)에서 누수/UAF가 있는가?
```

## Unreal SDK (C++)

```yaml
UE_Blueprint_Exposure:
  question: "Blueprint에 보안 민감 기능이 노출되는가?"
  trace: |
    1. BlueprintCallable로 노출된 함수 중 보안 민감 기능이 있는가?
    2. BlueprintReadWrite 프로퍼티에 토큰/키가 있는가?
    3. 에디터 전용 기능이 Shipping 빌드에 포함되는가?
       → #if WITH_EDITOR 가드 확인

UE_Module_Security:
  question: "UE 모듈 의존성이 최소 권한인가?"
  trace: |
    1. Build.cs에 불필요한 엔진 모듈이 포함되는가?
    2. ThirdParty 라이브러리 버전/취약점 추적이 가능한가?
    3. Subsystem 재초기화 시 이전 세션 토큰이 잔류하지 않는가?

UE_Platform_Bridge:
  question: "C++ ↔ Kotlin/Swift/ObjC++ 플랫폼 브리지가 안전한가?"
  trace: |
    1. JNI 호출 시 입력 파라미터 검증과 메모리 해제가 적절한가?
    2. Swift/ObjC++ 브리지에서 ARC 지연 해제로 민감 데이터가 잔류하는가?
    3. UPL XML에 과도한 Android/iOS 권한이 선언되는가?

UE_HTTP_Security:
  question: "UE 네이티브 HTTP 통신이 안전한가?"
  trace: |
    1. FHttpModule의 TLS 인증서 검증이 활성화되는가?
    2. SetVerifyPeer가 Shipping 빌드에서 true인가?
    3. Authorization 헤더가 HTTPS 전용 요청에만 첨부되는가?
    4. HTTP 로그에 Authorization 헤더가 마스킹되는가?

UE_OAuth:
  question: "UE 네이티브 OAuth 구현이 안전한가?"
  trace: |
    1. PKCE가 적용되는가?
    2. ASWebAuthenticationSession(iOS) / Custom Tabs(Android)가 사용되는가?
    3. 커스텀 URL 스킴이 Universal Links/App Links로 보호되는가?
    4. state/nonce 파라미터가 생성/검증되는가?
```
