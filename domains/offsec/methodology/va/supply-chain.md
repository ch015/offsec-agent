# Phase 1 확장: Supply Chain Analysis (공급망 분석)

> 프로젝트의 소프트웨어 공급망을 분석하여 의존성 취약점,
> 무결성 위험, 빌드 파이프라인 보안을 평가합니다.

---

## 적용 조건

```yaml
Auto_Load_Trigger:
  설명: |
    의존성 관리 파일이 존재하는 모든 프로젝트에서 자동 로드.
  조건:
    - "package.json / package-lock.json 존재"
    - "go.mod / go.sum 존재"
    - "requirements.txt / pyproject.toml / Pipfile.lock 존재"
    - "Cargo.toml / Cargo.lock 존재"
    - "pom.xml / build.gradle 존재"
  미감지_시: "이 모듈을 로드하지 않는다."
```

---

## 분석 원칙

```yaml
Principles:
  Methodology_Not_Patterns: |
    "특정 패키지 이름이나 버전 번호를 패턴 매칭하지 않는다.
     '이 의존성이 프로젝트의 보안에 어떤 영향을 미치는가?'를 질문하고,
     AI가 의존성 구조와 사용 패턴을 분석한다."
  
  Usage_Matters: |
    "의존성에 CVE가 있어도 해당 기능을 사용하지 않으면 영향 없다.
     CVE의 영향 범위와 프로젝트의 사용 패턴을 대조하여
     실제 영향을 판정한다."
  
  Transitive_Is_Real: |
    "직접 의존성만이 아니라 전이 의존성도 공격 표면이다.
     깊은 전이 의존성의 취약점도 동일한 기준으로 평가한다."
```

---

## 분석 영역

### SC1. Lock File Integrity (Lock 파일 무결성)

```yaml
Lock_File_Integrity:
  질문:
    - "Lock 파일(package-lock.json, go.sum 등)이 존재하는가?"
    - "Lock 파일이 .gitignore에 포함되어 있지 않은가?"
    - "CI/CD에서 npm ci(lock 기반 설치)를 사용하는가, npm install(범위 설치)을 사용하는가?"
    - "Lock 파일과 manifest 파일의 버전 범위가 일관적인가?"
  
  판정:
    lock_missing: "Lock 파일 미존재 → HIGH (재현 불가능한 빌드 = 의존성 변조 가능)"
    lock_ignored: "Lock 파일이 .gitignore → HIGH (위와 동일)"
    npm_install_in_ci: "CI에서 npm install 사용 → MEDIUM (lock 무시 가능)"
    consistent: "Lock 존재 + CI에서 lock 기반 설치 → 건전"
```

### SC2. Dependency Vulnerability Scan (의존성 취약점 스캔)

```yaml
Dependency_Scan:
  절차:
    1_정적_분석_우선: |
      기본 경로는 manifest와 lock 파일 정적 분석이다. va-auditor의 Bash는
      네트워크·패키지 설치·source write가 금지된 격리 환경에서만 사용할 수 있다.
      lock 파일(package-lock.json, go.sum, poetry.lock, Cargo.lock 등)을 Read하여
      고정 버전과 사용 위치를 확인한다.

      audit 도구는 이미 설치되어 있고 오프라인 실행이 가능한 경우에만 사용한다.
      취약점 DB가 없거나 오래되었으면 자동 판정을 하지 말고 버전·DB 시점과
      미검증 범위를 기록한다.
    
    2_결과_필터링: |
      CRITICAL/HIGH CVE만 상세 분석:
      - 해당 의존성이 프로젝트에서 실제 import/require되는가?
      - CVE의 영향 범위(예: 특정 함수)가 프로젝트에서 사용되는가?
      - 미사용이면 심각도 하향 (코드 내 사용 증거 없음)
    
    3_보고서_출력: |
      SBOM 요약:
      - 직접 의존성 수 + 전이 의존성 수
      - CRITICAL/HIGH CVE 수 (사용 확인/미확인 구분)
      - 최신 패치 대비 버전 지연 현황
  
  질문:
    - "알려진 CVE가 있는 의존성이 실제로 사용되는가?"
    - "CVE의 영향 범위가 이 프로젝트의 사용 패턴에 해당하는가?"
    - "패치 버전이 존재하는가? 업그레이드 시 breaking change가 있는가?"
```

### SC3. Transitive Dependency Risk (전이 의존성 위험)

```yaml
Transitive_Risk:
  질문:
    - "직접 의존성 대비 전이 의존성 비율이 과도한가? (10:1 이상이면 경고)"
    - "깊은 전이 의존성(depth ≥ 3)에 알려진 취약점이 있는가?"
    - "단일 유지보수자(bus factor 1)인 핵심 의존성이 있는가?"
    - "typosquatting 위험이 있는 패키지명이 있는가?"
  
  판정:
    abandoned_dep: "마지막 업데이트 > 2년 → LOW (보안 패치 지연 위험)"
    single_maintainer: "핵심 의존성 단일 유지보수자 → INFO (관찰 필요)"
    high_depth_cve: "depth ≥ 3 전이 의존성에 CVE → 직접 의존성과 동일 기준"
```

### SC4. Postinstall Script Risk (설치 스크립트 위험)

```yaml
Postinstall_Risk:
  질문:
    - "의존성에 postinstall/preinstall 스크립트가 있는가?"
    - "스크립트에서 네트워크 요청, 파일 쓰기, 바이너리 다운로드가 있는가?"
    - "--ignore-scripts 옵션으로 방어하고 있는가?"
  
  판정:
    dangerous_script: "네트워크 요청 + 파일 쓰기 → MEDIUM (공급망 공격 벡터)"
    binary_download: "바이너리 다운로드 → MEDIUM (무결성 미검증 시)"
    no_defense: "ignore-scripts 미사용 + 위험 스크립트 존재 → HIGH"
```

### SC5. Build Pipeline Security (빌드 파이프라인 보안)

```yaml
Build_Pipeline:
  질문:
    - "GitHub Actions에서 타사 action이 SHA로 고정(pin)되지 않고 tag로 참조되는가?"
    - "CI 환경에서 시크릿이 로그에 노출될 수 있는가? (echo, debug 모드)"
    - "빌드 아티팩트의 무결성 검증(서명, 해시)이 있는가?"
    - "CI/CD 파이프라인에서 pull_request_target 같은 위험 트리거가 사용되는가?"
  
  판정:
    unpinned_actions: "타사 action tag 참조 → MEDIUM (supply chain injection)"
    secret_leak_risk: "시크릿 echo 가능성 → HIGH"
    no_artifact_signing: "아티팩트 서명 미적용 → LOW (공개 배포 시 MEDIUM)"
```

---

## 출력

```yaml
Finding_Tagging:
  dimension: "A6 (의존성 및 외부 통합)"
  category: "supply-chain-{type}"
  types:
    - "supply-chain-lock"
    - "supply-chain-cve"
    - "supply-chain-transitive"
    - "supply-chain-postinstall"
    - "supply-chain-pipeline"

SBOM_Summary:
  위치: "보고서 부록"
  내용:
    - "직접 의존성 수 + 전이 의존성 수"
    - "알려진 CVE 수 (CRITICAL/HIGH/MEDIUM)"
    - "Lock 파일 상태 (존재/무결/불일치)"
    - "CI/CD 보안 요약"
```
