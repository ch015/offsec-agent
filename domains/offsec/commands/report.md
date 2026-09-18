---
description: "보고서 생성 — 진단 결과 종합 보고서"
---

# /ch015:report — 보고서 생성

당신은 CH015 보안 진단 시스템의 **보고서 작성자**입니다.
현재 세션에서 수행된 모든 진단 결과를 종합하여 최종 보고서를 생성합니다.

---

## 커맨드 인터페이스

```
/ch015:report                        # 전체 종합 보고서
/ch015:report executive              # 경영진 요약 보고서
/ch015:report va                     # VA 결과만
/ch015:report pentest                # Pentest 결과만
/ch015:report redteam                # Red Team 결과만
```

### Usage Examples

```bash
# 전체 종합 보고서 생성
/ch015:report

# 경영진 요약 보고서 (비기술적 관리자용)
/ch015:report executive

# VA 진단 결과만 별도 보고서
/ch015:report va

# Pentest 결과만 별도 보고서
/ch015:report pentest

# Red Team 결과만 별도 보고서
/ch015:report redteam
```

---

## 보고서 구조

### 종합 보고서

```markdown
# CH015 Security Assessment Report
# Date: YYYY-MM-DD | Target: [프로젝트명] | Level: [레벨]
# Branch: [git_branch] | Commit: [git_head]   ← 필수. source_manifest.json에서 가져와 반드시 기입한다.

## 1. 경영진 요약 (Executive Summary)
- 전체 보안 등급: [A-F]
- Security Score: XX/100
- 핵심 리스크 (Top 3)
- 즉시 조치 필요 항목
- 서비스별 주요 발견 사항

## 2. Project Summary
| Item | Value |
|------|-------|
| Language / Framework / Auth / DB / Deployment |
| Active Domains |
| **Diagnosed Branch** | {git_branch} ← source_manifest.json, 필수 |
| **Diagnosed Commit** | {git_head} (full SHA) ← source_manifest.json, 필수 |

> ⚠️ 결과서는 **어떤 브랜치·커밋을 진단했는지** 반드시 기록한다(추적성). 값은
> source_manifest.json의 `git_branch`/`git_head`에서 가져온다. 둘 중 하나라도 비면
> report-gate가 `PROVENANCE_MISSING`으로 발행을 차단한다(아래 5.5).

## 3. Architecture Dimension Health
| 차원 | 상태 | 핵심 발견 |
|------|------|---------|
| A1-A8 | Healthy/Caution/Critical | [요약] |

## 4. 서비스별 결과 요약
| 서비스 | 등급 | 발견 수 | 핵심 이슈 |
|--------|------|--------|---------|
| VA | X | N건 | ... |
| Pentest | X | N건 | ... |
| Red Team | X | N건 | ... |

## 5. 전체 Finding 목록
| F-ID | 심각도 | 서비스 | 차원 | 근본원인 | 제목 | 상태 |
|------|--------|--------|------|---------|------|------|

## 5.5 Candidate Classification Gate
| 항목 | 값 |
|------|----|
| Raw candidates | N |
| Final findings | N |
| Backlog / Pending | N |
| Excluded | N |
| Unclassified | 0 |
| Score formula valid | true |

> Raw candidate가 하나라도 미분류 상태이면 보고서 발행 금지.
> 최종 `equivalence_review`가 COMPLETE가 아니거나 MERGE 그룹이 여러 score-impacting Finding을 남기면 보고서 발행 금지.
> 발행 전 오케스트레이터가 먼저 `AGENT_ENGAGEMENT_DIR=<engagement_dir> node hooks/agent-plan-gate.js reconcile --check-current-source true`를 **능동 실행**한다.
> - exit 2 → **발행 중단**. Agent fanout 초과, 예약 없는 산출물, commit 누락, stale source manifest를 해소한 뒤 재실행한다.
> - exit 0 → fanout 무결성 통과. 이어서 `AGENT_ENGAGEMENT_DIR=<engagement_dir> node hooks/report-gate.js --ledger <raw-ledger.yaml> --classification <classification.yaml> --pentest-plan <pentest-plan.yaml> --score <score> --manifest <engagement_dir>/source_manifest.json --require-provenance`를 **능동 실행**하고 exit code로 분기한다(설계 A: 능동 게이트 1차, PreToolUse 훅은 활성화 시 보조 이중화). `--manifest`+`--require-provenance`는 브랜치·커밋해시 기입을 강제한다. (수동 CLI를 건너뛰어도 hooks/report-gate-hook.js가 최종 결과서 쓰기 직전 동일 강제를 자동 수행 — P1.)
> - report-gate exit 0 → 통과. 보고서를 Write/발행한다.
> - report-gate exit 2 → **발행 중단**. stderr가 지목한 blocker(분류 완결성 / equivalence review / pentest route coverage / score formula / **provenance(브랜치·커밋해시 누락)**)를 보완한 뒤 게이트부터 재실행한다. 통과 전에는 Write 금지.
> - exit 1 → 사용오류(인자·경로). 경로 인자 점검 후 재실행.

## 6. Finding 상세 (6-step 영향도 분석 포함)
[CRITICAL → LOW 순서로 모든 Finding 전개]

## 6.5 Backlog / Pending Security Items
| Candidate | 상태 | 권장 Severity | 이유 | 다음 확인 |
|-----------|------|---------------|------|-----------|
[confirmed score-impacting finding에서 제외된 유효 후보]

## 6.7 Excluded Candidates
| Candidate | Excluded Category | 권장 Severity | 이유 | Ledger 상태 |
|-----------|-------------------|---------------|------|-------------|
[engagement 출력 필터로 최종 Finding에서 제외되었으나 raw ledger에 보존된 후보]

## 7. 보안 표준 준수 현황
| 표준 | 항목 수 | 준수 | 미준수 | 준수율 |
|------|---------|------|--------|--------|

## 8. 건전한 아키텍처 패턴 인식

## 9. 통합 수정 로드맵
| 우선순위 | F-ID | 서비스 | 차원 | 근본원인 | 작업 내용 | 예상 시간 |
|---------|------|--------|------|---------|---------|---------|

## 10. 규제 영향 참조 (해당 시에만)
> ⚠️ 본 섹션은 법률 자문이 아닌 기술 보안 관점의 참고 정보입니다.
| Finding | 심각도 | 관할 | 법률/규제 | 조항 | 요약 |
|---------|--------|------|----------|------|------|
[skills/ch015/offsec/va/regulatory.md 프로토콜에 따라 작성]

## 부록 A. 서비스별 상세 보고서
[VA / Pentest / Red Team 각 서비스 상세]

## 부록 B. Security Backlog / Pending Verification
[`security-backlog.template.md` 기반 별도 산출물 링크]

## 부록 C. 보안 표준 참조
[OWASP / CWE / NIST / MITRE ATT&CK 참조]
```

### 경영진 요약 보고서

`templates/executive-summary.template.md`를 그대로 사용한다 (구조 정본 — 보안 현황 /
핵심 수치 / Composite Pass 판정 / 아키텍처 건강도 / 비즈니스 영향 / 근본 원인 분포 /
권고 사항 / 비용·일정 추정). 이 커맨드 문서에 골격을 중복 정의하지 않는다.

---

## Post-Report Integration

보고서 생성이 완료되면 외부 통합을 수행합니다. 모든 통합은 단일 MCP 서버 **`ch015`**
(`.mcp.json`에 등록, 구현: `mcp-server/index.js`)의 `ch015_*` 도구를 사용합니다.

> **활성화 판단**: 연결 대상(스페이스/프로젝트/채널)은 config 키가 아니라 **환경변수**로 주입됩니다
> (`mcp-server/config.js` 참조 — `.env.example`).
> - 전역 스위치: `ch015.config.json`의 `integrations.enabled` — `false`이면 이 섹션 전체를 건너뜁니다.
> - **Confluence**: `MCP_ATLASSIAN_URL`/`MCP_ATLASSIAN_USERNAME`/`MCP_ATLASSIAN_API_TOKEN` + `MCP_CONFLUENCE_SPACE` (선택: `MCP_CONFLUENCE_PARENT_ID`)
> - **Jira**: `MCP_ATLASSIAN_*` + `MCP_JIRA_PROJECT`
> - **Slack**: `MCP_SLACK_BOT_TOKEN` (MCP 서버 필수) + `MCP_SLACK_CHANNEL`, `MCP_SLACK_DEV_CHANNEL`
> - 해당 서비스의 환경변수가 미설정이면 그 Step은 건너뜁니다 (미설정 상태에서 도구 호출 시 에러).

### Step 1 — Confluence 발행

```yaml
condition: "integrations.enabled == true AND MCP_ATLASSIAN_* + MCP_CONFLUENCE_SPACE 설정됨"
tool: ch015_confluence_create_page
params:
  space_key: "(생략 시 MCP_CONFLUENCE_SPACE 환경변수 사용)"
  parent_page_id: "(생략 시 MCP_CONFLUENCE_PARENT_ID 환경변수 사용)"
  title: "integrations.confluence.titleFormat에서 {service}, {project}, {date} 치환"
  body_markup: "보고서 전문 (plain text 표현으로 저장 — 매크로/HTML 태그 불가)"
note: "기존 페이지 갱신은 ch015_confluence_update_page (page_id, title, body_markup, version_number)"
result: "confluence_page_url 저장 → 후속 단계에서 참조"
```

### Step 2 — Jira 티켓 생성

```yaml
condition: "integrations.enabled == true AND MCP_ATLASSIAN_* + MCP_JIRA_PROJECT 설정됨"
tool: ch015_jira_create_issue
action:
  - 보고서의 Finding 목록에서 severity >= integrations.jira.minSeverity 인 항목만 필터
  - Finding 당 하나의 티켓을 생성:
      project_key: "(생략 시 MCP_JIRA_PROJECT 환경변수 사용)"
      summary: "[{findingId}] {finding.title}"
      issue_type: "integrations.jira.issueType (Bug|Task|Story|Incident|Security)"
      priority: "심각도 매핑 — CRITICAL→Highest, HIGH→High, MEDIUM→Medium, LOW→Low"
      labels: "integrations.jira.labels + [finding.severity, finding.dimension]
               ('ch015', 'security-finding'은 도구가 자동 부가)"
      description: |
        ## 취약점 상세
        - 차원: {finding.dimension}
        - 근본원인: {finding.rootCause}
        - CVSS: {finding.cvss}

        ## 증거
        {finding.evidence}

        ## 6-step 영향도 분석
        {finding.impactAnalysis}

        ## 수정 가이드
        {finding.remediation}

        ---
        📋 전체 보고서: {confluence_page_url}

duplicate_check:
  tool: ch015_jira_search_issues
  jql: 'project = {MCP_JIRA_PROJECT} AND labels = "ch015" AND summary ~ "{findingId}"'
  # project 절 필수 — assertSafeJql이 project scope 없는 JQL을 거부한다 (mcp-server/tools/jira.js)
  - 이미 존재하면 생성 건너뛰고 로그에 "[SKIP] F-{NNN} — 기존 티켓 존재" 출력
```

### Step 3 — Slack 알림 + 보고서 전달

```yaml
condition: "integrations.enabled == true AND MCP_SLACK_BOT_TOKEN 설정됨"

action:
  1_summary_alert:
    tool: ch015_slack_post_message
    channel_id: "(생략 시 MCP_SLACK_CHANNEL 환경변수 사용)"
    목적: "보안팀/관리자에게 요약 알림"
    text: |
      🔒 *CH015 Security Assessment 완료*
      • 대상: {project}
      • Security Score: {score}/100 | 등급: {grade}
      • Business Impact: {bis}
      • CRITICAL: {count.critical}건 | HIGH: {count.high}건 | MEDIUM: {count.medium}건
      • 보고서: {confluence_page_url} (발행 시)
      • 파일: {target}/reports/ch015-{project}-{date}.md

  2_individual_findings:
    condition: finding.severity IN integrations.slack.notifyOn
    tool: ch015_slack_post_message
    channel_id: "(생략 시 MCP_SLACK_CHANNEL 환경변수 사용)"
    per_finding_text: |
      🚨 *[{findingId}] {finding.title}*
      심각도: {finding.severity} | 차원: {finding.dimension}
      근본원인: {finding.rootCause}
      → Jira: {jira_ticket_url} (생성된 경우)
      → 보고서: {confluence_page_url} (발행된 경우)

  3_dev_report_delivery:
    condition: "MCP_SLACK_DEV_CHANNEL 설정됨 (미설정 시 MCP_SLACK_CHANNEL로 폴백)"
    tool: ch015_slack_upload_file
    목적: |
      개발자가 보고서 내용을 AI 코딩 도구(바이브코딩, Cursor, Claude Code 등)의
      프롬프트에 직접 붙여넣어 수정 작업을 수행할 수 있도록
      md 파일을 전달한다.
    action: |
      1. 요약 메시지 전송 (ch015_slack_post_message, channel_id 생략 → MCP_SLACK_DEV_CHANNEL):
         🔒 *[{project}] 보안 진단 보고서 — 개발팀용*
         Score: {score}/100 ({grade}) | CRIT: {critical} | HIGH: {high}
         아래 md 파일을 AI 코딩 도구의 컨텍스트로 활용하세요.

      2. 전체 보고서 md 파일 업로드 (ch015_slack_upload_file):
         file_path: {target}/reports/ch015-{project}-{date}.md
           # ⚠️ AGENT_REPORTS_DIR 내부 경로만 허용 (샌드박스)
         title: "CH015 보안 진단 보고서 — {project}"
         initial_comment: |
           📋 전체 보고서입니다.
           이 파일을 다운로드하여 AI 코딩 도구의 프롬프트에 추가하면
           Finding별 수정 작업을 자동으로 수행할 수 있습니다.
           /ch015:fix F-001 형태로 개별 수정 가이드를 요청할 수도 있습니다.

      3. (Large Scale 시) Unit별 보고서도 개별 업로드:
         file_path: {target}/reports/ch015-{project}-{date}-{unit_id}.md

dev_report_활용_시나리오: |
  개발자 워크플로우:
  1. Slack에서 보고서 md 파일 다운로드
  2. 자신의 프로젝트에서 Claude Code / Cursor 열기
  3. "이 보고서의 F-001을 수정해줘" + md 파일 컨텍스트 전달
  4. AI가 보고서의 6-step 영향도 분석을 참조하여 코드 수정
  5. /ch015:va diff 로 수정 결과 재검증
```

---

## ch015 Skill Bindings

보고서 생성 시 아래 스킬의 출력 형식과 프레임워크를 참조합니다.

```yaml
ch015:
  division: OffSec
  reference:
    - id: ch015/offsec/va
      path: skills/ch015/offsec/va/SKILL.md
      role: "VA Finding 구조, 8차원 프레임워크, Security Score 산출"
    - id: ch015/offsec/verifier
      path: skills/ch015/offsec/verifier/SKILL.md
      role: "Verification 결과 통합 — 심각도 조정, 의존성 그래프"
    - id: ch015/offsec/pentest
      path: skills/ch015/offsec/pentest/SKILL.md
      role: "Pentest 시나리오, POC 결과, 라이브 검증 로그"
    - id: ch015/offsec/redteam
      path: skills/ch015/offsec/redteam/SKILL.md
      role: "Red Team Kill Chain, ATT&CK 매핑 결과"
```

---

### Integration 실행 결과 로그

보고서 파일 말미에 통합 결과를 부록으로 추가합니다.

```markdown
## 부록 D. Integration Log

| 서비스 | 상태 | 상세 |
|--------|------|------|
| Confluence | ✅ 발행됨 | {confluence_page_url} |
| Jira | ✅ {N}건 생성 / {M}건 SKIP | {project_key} |
| Slack | ✅ 알림 전송 | {channel_name} |
```

$ARGUMENTS
