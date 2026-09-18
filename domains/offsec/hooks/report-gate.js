#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const {
  getCandidateId,
  getCandidates,
  getFinalStatus,
  groupByRootCause,
  isScoreIncludedCandidate,
  validateLedger,
  summarizeCandidates,
  calculatePentestRouteCoverage,
} = require('../lib/ch015/candidate-ledger');
const {
  validateScoreConsistency,
} = require('../lib/ch015/scoring');
const { applyCiteCheck } = require('../lib/ch015/refuter-cite-check');
const { verifyConfirmed } = require('../lib/ch015/poc-gate');
const { makeSourceReaders } = require('../lib/ch015/source-reader');

function readStructured(filePath) {
  const text = fs.readFileSync(filePath, 'utf8');
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.json') return JSON.parse(text);
  return yaml.load(text);
}

function getScenarios(input) {
  if (!input || typeof input !== 'object') return [];
  if (Array.isArray(input)) return input;
  for (const key of ['scenarios', 'pentest_scenarios', 'tests', 'routes']) {
    if (Array.isArray(input[key])) return input[key];
  }
  return [];
}

// [P1-7] Strict Formula Write-시점 검증(fail-soft):
// classification/ledger에 "숫자" security_score(또는 reported_score|score)가 있으면
// findings 역산(validateScoreConsistency)과 대조한다. 숫자가 아닌 값(빈 문자열,
// 템플릿 placeholder 등)은 "부재"로 취급해 requireScore 정책(훅 경로는 false →
// warning)에 위임한다 — 비숫자 슬롯 때문에 발행이 차단되는 과차단을 막기 위함.
function toNumericScore(value) {
  if (value == null || typeof value === 'object' || typeof value === 'boolean') return undefined;
  if (typeof value === 'string' && value.trim() === '') return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function getReportedScore(input) {
  if (!input || typeof input !== 'object') return undefined;
  for (const key of ['reported_score', 'security_score', 'score']) {
    const n = toNumericScore(input[key]);
    if (n !== undefined) return n;
  }
  if (input.summary) {
    const n = toNumericScore(input.summary.security_score);
    if (n !== undefined) return n;
  }
  return undefined;
}

function mergeCandidateClassifications(ledgerInput, classificationInput) {
  const ledgerCandidates = getCandidates(ledgerInput);
  const classificationCandidates = getCandidates(classificationInput);
  if (classificationCandidates.length === 0) return ledgerCandidates;

  const merged = [];
  const byId = new Map();
  for (const classification of classificationCandidates) {
    byId.set(getCandidateId(classification), classification);
  }

  for (const candidate of ledgerCandidates) {
    const id = getCandidateId(candidate);
    const classification = byId.get(id);
    if (!classification) {
      merged.push(candidate);
      continue;
    }
    merged.push({
      ...candidate,
      ...classification,
      evidence: {
        ...(candidate.evidence || {}),
        ...(classification.evidence || {}),
      },
      routing: {
        ...(candidate.routing || {}),
        ...(classification.routing || {}),
      },
      final_mapping: {
        ...(candidate.final_mapping || {}),
        ...(classification.final_mapping || {}),
      },
    });
    byId.delete(id);
  }

  for (const classification of byId.values()) {
    merged.push(classification);
  }

  return merged;
}

function getEquivalenceReview(ledgerInput, classificationInput) {
  return classificationInput?.equivalence_review ||
    ledgerInput?.equivalence_review ||
    classificationInput?.duplicate_equivalence_review ||
    ledgerInput?.duplicate_equivalence_review ||
    null;
}

function normalizeDecision(value) {
  return String(value || '').trim().toUpperCase();
}

// 템플릿이 빈 placeholder로 렌더한 슬롯({method:"",...})이 분쟁 해소로
// 오인되지 않도록, 실제 내용이 있는 값만 해소 증거로 인정한다.
function hasResolutionContent(value) {
  if (value == null) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.some(hasResolutionContent);
  if (typeof value === 'object') return Object.values(value).some(hasResolutionContent);
  return Boolean(value);
}

function normalizeIdList(value) {
  if (value == null) return [];
  if (Array.isArray(value)) return value.flatMap(normalizeIdList);
  return String(value)
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean);
}

function getReviewGroups(review) {
  if (!review || typeof review !== 'object') return [];
  for (const key of ['groups', 'duplicate_groups', 'equivalence_groups']) {
    if (Array.isArray(review[key])) return review[key];
  }
  return [];
}

function getReviewUnresolved(review) {
  if (!review || typeof review !== 'object') return [];
  for (const key of ['unresolved', 'unresolved_groups', 'ciso_review_required']) {
    if (Array.isArray(review[key])) return review[key];
  }
  return [];
}

function getReviewedCandidateCount(review) {
  if (!review || typeof review !== 'object') return null;
  for (const key of ['reviewed_candidate_count', 'reviewed_finding_count', 'reviewed_final_finding_count']) {
    if (review[key] != null && review[key] !== '') {
      const parsed = Number(review[key]);
      return Number.isFinite(parsed) ? parsed : null;
    }
  }
  if (Array.isArray(review.reviewed_candidates)) return review.reviewed_candidates.length;
  if (Array.isArray(review.reviewed_findings)) return review.reviewed_findings.length;
  return null;
}

function getCandidateById(candidates) {
  const byId = new Map();
  for (const candidate of candidates) {
    byId.set(getCandidateId(candidate), candidate);
  }
  return byId;
}

function hasAffectedInstances(candidate, group) {
  return Boolean(
    (Array.isArray(candidate?.affected_instances) && candidate.affected_instances.length > 0) ||
    (Array.isArray(candidate?.final_mapping?.affected_instances) && candidate.final_mapping.affected_instances.length > 0) ||
    (Array.isArray(group?.affected_instances) && group.affected_instances.length > 0)
  );
}

function validateEquivalenceReview(review, candidates, { requireEquivalenceReview = true } = {}) {
  const errors = [];
  const warnings = [];
  const scoreIncluded = candidates.filter(isScoreIncludedCandidate);

  if (!review) {
    const item = {
      code: 'EQUIVALENCE_REVIEW_MISSING',
      message: 'Final equivalence review is missing; duplicate/overcount gate cannot verify contextual merge/split decisions.',
    };
    (requireEquivalenceReview ? errors : warnings).push(item);
    return { errors, warnings };
  }

  const status = normalizeDecision(review.status || review.review_status);
  if (status !== 'COMPLETE') {
    errors.push({
      code: 'EQUIVALENCE_REVIEW_INCOMPLETE',
      message: `Final equivalence review status must be COMPLETE, got "${status || 'MISSING'}".`,
    });
  }

  const reviewedCount = getReviewedCandidateCount(review);
  if (reviewedCount == null) {
    errors.push({
      code: 'EQUIVALENCE_REVIEW_COUNT_MISSING',
      message: 'Final equivalence review must include reviewed_candidate_count or reviewed_candidates.',
    });
  } else if (reviewedCount < scoreIncluded.length) {
    errors.push({
      code: 'EQUIVALENCE_REVIEW_COVERAGE_INCOMPLETE',
      message: `Final equivalence review covered ${reviewedCount} candidates, but ${scoreIncluded.length} score-included candidates remain.`,
    });
  }

  const unresolved = getReviewUnresolved(review);
  if (unresolved.length > 0) {
    errors.push({
      code: 'EQUIVALENCE_REVIEW_UNRESOLVED',
      message: `Final equivalence review has unresolved merge/split decisions: ${unresolved.length}.`,
      unresolved,
    });
  }

  const groups = getReviewGroups(review);
  const byId = getCandidateById(candidates);
  for (const group of groups) {
    const groupId = group.group_id || group.id || 'UNKNOWN';
    const decision = normalizeDecision(group.decision || group.status);
    const members = normalizeIdList(group.members || group.candidate_ids || group.finding_ids);
    const representative = String(group.representative || group.primary_candidate || group.primary_finding || '').trim();

    if (!['MERGE', 'SPLIT', 'KEEP'].includes(decision)) {
      errors.push({
        code: 'EQUIVALENCE_GROUP_DECISION_INVALID',
        message: `Equivalence group ${groupId} has invalid decision "${decision || 'MISSING'}".`,
      });
      continue;
    }

    if (members.length === 0) {
      errors.push({
        code: 'EQUIVALENCE_GROUP_MEMBERS_MISSING',
        message: `Equivalence group ${groupId} must list members.`,
      });
      continue;
    }

    if (decision === 'MERGE') {
      if (!representative || !members.includes(representative)) {
        errors.push({
          code: 'EQUIVALENCE_MERGE_REPRESENTATIVE_INVALID',
          message: `MERGE group ${groupId} must name a representative included in members.`,
        });
      }

      const memberCandidates = members.map((id) => byId.get(id)).filter(Boolean);
      const groupScoreIncluded = memberCandidates.filter(isScoreIncludedCandidate);
      if (groupScoreIncluded.length > 1) {
        errors.push({
          code: 'MERGED_GROUP_MULTIPLE_SCORE_INCLUDED',
          message: `MERGE group ${groupId} still has multiple score-included findings: ${groupScoreIncluded.map(getCandidateId).join(', ')}.`,
          candidates: groupScoreIncluded.map(getCandidateId),
        });
      }

      const primary = byId.get(representative);
      if (!hasAffectedInstances(primary, group)) {
        errors.push({
          code: 'MERGE_AFFECTED_INSTANCES_MISSING',
          message: `MERGE group ${groupId} must record affected_instances on the group or representative finding.`,
        });
      }
    }

    if (decision === 'SPLIT' && !group.split_reason && !group.rationale && !group.reason) {
      errors.push({
        code: 'EQUIVALENCE_SPLIT_REASON_MISSING',
        message: `SPLIT group ${groupId} must include split_reason, rationale, or reason.`,
      });
    }

    // KEEP도 "별개 취약점"이라는 명시 판정이므로 사유를 강제한다(SPLIT과 대칭, F-A).
    // 무근거 KEEP으로 중복 backstop을 우회하지 못하게 한다.
    if (decision === 'KEEP' && !group.keep_reason && !group.rationale && !group.reason) {
      errors.push({
        code: 'EQUIVALENCE_KEEP_REASON_MISSING',
        message: `KEEP group ${groupId} must include keep_reason, rationale, or reason (distinct-vulnerability justification).`,
      });
    }
  }

  return { errors, warnings };
}

// 결과서 추적성: 진단 대상의 브랜치+커밋해시 출처. source_manifest.json(git_branch/git_head)
// 또는 classification/ledger의 provenance 필드에서 해석한다.
// P4: 소스별 "객체 존재"가 아니라 "필드 단위"로 폴백한다 — manifest가 있어도 git 필드가
// 비어 있으면(예: 비-git) classification/ledger.provenance에서 채운다.
function getProvenance(manifest, classification, ledger) {
  const sources = [manifest, classification?.provenance, ledger?.provenance];
  const pick = (...keys) => {
    for (const src of sources) {
      if (!src || typeof src !== 'object') continue;
      for (const k of keys) {
        const v = src[k];
        if (v != null && String(v).trim()) return String(v).trim();
      }
    }
    return null;
  };
  return {
    git_branch: pick('git_branch', 'branch'),
    git_commit: pick('git_head', 'git_commit', 'commit'),
  };
}

// 결정론 게이트 배선(로드맵 #2): merge된 후보에 cite-check(#3)+poc-gate(#4)를 적용한다.
// validateReportGate가 validateLedger 전에 호출 → 강등이 기존 게이트 로직으로 자연히 흘러든다
// (poc-gate CANDIDATE 강등 → CANDIDATE_UNCLASSIFIED, cite-check DISPUTED 강등 →
//  DISPUTED_UNRESOLVED_AT_PUBLISH). 후보의 canonical 상태 필드는 final_status이므로 강등은
// final_status에 기록한다.
//
// 안전 규율(과차단 방지):
//  - cite-check: sourceRoot가 있을 때만 파일 실재성 검증(없으면 스킵 — 인용 파일을 확인할 수
//      없는데 강등하면 실 finding을 대량 오강등). FALSE_POSITIVE가 소스-guard 반증을 대는데 그
//      인용이 소스에 실재하지 않으면 → DISPUTED 강등(자동 기각 취소, CISO 재판정).
//  - poc-gate: CONFIRMED의 self-stamp verifiedAt은 항상 제거(치팅 차단). poc_artifact가 있으면
//      바인딩 검증 후 시그니처 미관측 시 CANDIDATE 강등. poc_artifact "부재"는
//      requirePocBinding=true일 때만 강등(기본은 무변경) — 파이프라인이 아직 poc_artifact를
//      방출하지 않아도 기존 CONFIRMED를 깨지 않는다(HANDOFF #4: 활성화는 poc 방출에 종속).
function applyDeterministicGates(candidates, {
  sourceRoot = null,
  artifactRoot = null,
  requirePocBinding = false,
  now = undefined,
} = {}) {
  const readers = makeSourceReaders(sourceRoot);
  // poc 산출물은 보통 engagement 디렉터리(≠ 대상 소스)에 있으므로 루트를 분리한다.
  // artifactRoot 미제공 시 source 리더로 폴백(단일 루트 엔게이지먼트). inline observed는 루트 무관.
  const artifactReaders = artifactRoot ? makeSourceReaders(artifactRoot) : readers;
  const gateWarnings = [];
  const gateSummary = {
    source_backed: Boolean(readers),
    require_poc_binding: Boolean(requirePocBinding),
    cite_check: { checked: 0, passed: 0, downgraded: 0 },
    poc_gate: { confirmed: 0, verified: 0, downgraded: 0, self_stamped: 0, missing_artifact: 0 },
  };

  const out = candidates.map((original) => {
    let cand = original;
    const id = getCandidateId(cand);

    // --- cite-check: FALSE_POSITIVE의 소스-guard 반증 실재성 (sourceRoot 필요) ---
    if (readers && getFinalStatus(cand) === 'FALSE_POSITIVE') {
      const r = applyCiteCheck(cand, {
        readFile: readers.readFile,
        resolve: readers.resolve,
        getStatus: getFinalStatus,
        getCounterEvidence: (c) => c.counter_evidence ?? c.final_mapping?.counter_evidence,
      });
      if (r.applicable) {
        gateSummary.cite_check.checked += 1;
        if (r.passed) {
          gateSummary.cite_check.passed += 1;
          cand = { ...cand, cite_check: r.citeCheck };
        } else {
          gateSummary.cite_check.downgraded += 1;
          cand = {
            ...cand,
            final_status: 'DISPUTED',
            cite_check: r.citeCheck,
            cite_check_downgrade: `FALSE_POSITIVE→DISPUTED: 반증 인용 미실재(${r.citeCheck.reason})`,
            // DISPUTE_REASON_MISSING을 피하되(구조적 필드), DISPUTED_UNRESOLVED_AT_PUBLISH로
            // CISO 사인오프는 여전히 요구한다(자동 기각 취소, 재판정 필요).
            dispute_reason: cand.dispute_reason
              || `cite-check: 반증 인용이 소스에 미실재(${r.citeCheck.reason}) — 자동 기각 취소, CISO 재판정 필요`,
          };
        }
      }
    }

    // --- poc-gate: CONFIRMED의 poc 바인딩 기계검증 ---
    if (getFinalStatus(cand) === 'CONFIRMED') {
      // poc-gate는 candidate.status를 직접 읽으므로 canonical status를 뷰로 주입한다.
      const view = { ...cand, status: 'CONFIRMED' };
      const r = verifyConfirmed(view, {
        readArtifact: artifactReaders ? artifactReaders.readArtifact : undefined,
        now,
      });
      if (r.applicable) {
        gateSummary.poc_gate.confirmed += 1;
        if (r.selfStampRejected) {
          gateSummary.poc_gate.self_stamped += 1;
          gateWarnings.push({
            code: 'POC_SELF_STAMP_REJECTED',
            candidate_id: id,
            message: `CONFIRMED ${id}가 verifiedAt를 자체 부여(self-stamp)했다 — 게이트가 무효화한다. verifiedAt writer는 poc-gate뿐.`,
          });
        }
        const stripped = { ...cand };
        delete stripped.verifiedAt; // self-stamp는 항상 제거; 정당한 값은 게이트만 재부여
        if (r.verified) {
          gateSummary.poc_gate.verified += 1;
          cand = { ...stripped, verifiedAt: r.verifiedAt, poc_gate: { verified: true, reason: r.reason } };
        } else if (r.reason === 'no_poc_artifact' && !requirePocBinding) {
          // 파이프라인이 poc_artifact를 방출하지 않는 현 단계 — 강등하지 않고 요약에만 기록.
          gateSummary.poc_gate.missing_artifact += 1;
          cand = stripped;
        } else {
          // 시그니처 미관측 / no_signature / (requirePocBinding && no_poc_artifact) → 강등.
          gateSummary.poc_gate.downgraded += 1;
          cand = {
            ...stripped,
            final_status: r.downgradeTo,
            poc_gate: { verified: false, reason: r.reason },
            poc_gate_downgrade: `CONFIRMED→${r.downgradeTo}: ${r.reason}`,
          };
        }
      }
    }

    return cand;
  });

  return { candidates: out, gateSummary, gateWarnings };
}

function validateReportGate({
  ledger,
  classification,
  pentestPlan,
  reportedScore,
  manifest,
  requireScore = true,
  requireEquivalenceReview = true,
  requireProvenance = false,
  sourceRoot = null,
  artifactRoot = null,
  requirePocBinding = false,
  allowEmptyCandidates = false,
} = {}) {
  const mergedCandidates = mergeCandidateClassifications(ledger || [], classification || []);
  const errors = [];
  const warnings = [];

  const gate = applyDeterministicGates(mergedCandidates, { sourceRoot, artifactRoot, requirePocBinding });
  const candidates = gate.candidates;
  warnings.push(...gate.gateWarnings);

  if (candidates.length === 0 && !allowEmptyCandidates) {
    errors.push({
      code: 'RAW_LEDGER_MISSING',
      message: 'Raw candidate ledger or final classification contains no candidates.',
    });
  }

  // 결과서 출처 강제: 브랜치+커밋해시가 비어 있으면 발행 차단(추적성 필수).
  // requireProvenance=false(기본)면 누락 시 경고만 — lib 직접 호출/기존 테스트 하위호환.
  const provenance = getProvenance(manifest, classification, ledger);
  if (!provenance.git_branch || !provenance.git_commit) {
    const missing = [
      !provenance.git_branch ? 'git_branch' : null,
      !provenance.git_commit ? 'git_commit' : null,
    ].filter(Boolean).join(', ');
    const item = {
      code: 'PROVENANCE_MISSING',
      message: `결과서 출처 누락(${missing}). source_manifest.json의 git_branch/git_head 또는 ` +
        `classification.provenance로 브랜치+커밋해시를 반드시 기입해야 발행할 수 있다.`,
    };
    (requireProvenance ? errors : warnings).push(item);
  }

  // GAP-1 하드 backstop: 기계적으로 같은 root_cause/remediation을 공유하는 클러스터를
  // LLM이 (a) MERGE(FOLDED_INTO)하지도, (b) 선언된 SPLIT/KEEP 그룹으로 명시 판정하지도
  // 않은 채 2건 이상을 점수에 포함시킨 경우 → 발행 차단(과거 warning에서 승격).
  // LLM은 equivalence_review에 SPLIT/KEEP + 사유를 선언하면 언제든 override할 수 있다.
  // SPLIT/KEEP override는 "사유가 있는" 명시 판정만 인정한다. 무근거 KEEP/SPLIT 한 줄로
  // 하드 backstop을 우회하는 것을 막는다(F-A). 사유 없는 그룹은 declaredDistinct에 넣지 않아
  // UNFOLDED_ROOT_CAUSE_GROUP이 그대로 발화한다(+ 아래 review 검증이 *_REASON_MISSING도 보고).
  const review = getEquivalenceReview(ledger, classification);
  const declaredDistinctIds = new Set();
  for (const group of getReviewGroups(review)) {
    const decision = normalizeDecision(group.decision || group.status);
    const hasRationale = hasResolutionContent(
      group.split_reason || group.keep_reason || group.rationale || group.reason
    );
    if ((decision === 'SPLIT' || decision === 'KEEP') && hasRationale) {
      for (const id of normalizeIdList(group.members || group.candidate_ids || group.finding_ids)) {
        declaredDistinctIds.add(id);
      }
    }
  }

  const rootCauseGroups = groupByRootCause(candidates);
  for (const [key, group] of rootCauseGroups) {
    if (group.length <= 1) continue;
    const ids = group.map(getCandidateId);
    const hasFolded = group.some((c) => normalizeDecision(getFinalStatus(c)) === 'FOLDED_INTO');
    if (hasFolded) continue; // MERGE가 일어남 — 정상

    const scoreIncludedIds = group.filter(isScoreIncludedCandidate).map(getCandidateId);
    const allDeclaredDistinct = scoreIncludedIds.every((id) => declaredDistinctIds.has(id));

    if (scoreIncludedIds.length >= 2 && !allDeclaredDistinct) {
      // 기계적으로 자명한 중복을 LLM이 무시 → 과대계상(overcount) 차단.
      errors.push({
        code: 'UNFOLDED_ROOT_CAUSE_GROUP',
        message:
          `${scoreIncludedIds.length} score-included candidates share root/remediation clue "${key}" ` +
          `but none are FOLDED_INTO and they are not declared SPLIT/KEEP (with rationale) in equivalence_review: ` +
          `${scoreIncludedIds.join(', ')}. MERGE them, or declare an explicit SPLIT/KEEP group with rationale.`,
        candidates: scoreIncludedIds,
      });
    } else if (!allDeclaredDistinct) {
      // 단일 score_included 또는 일부만 미선언 — 맥락 검토 권고(비차단).
      // 정상적으로 SPLIT/KEEP(+사유) 선언된 그룹은 무경고(F-C: 노이즈 제거).
      warnings.push({
        code: 'UNFOLDED_ROOT_CAUSE_GROUP',
        message: `${ids.length} candidates share root/remediation clue "${key}" but none are FOLDED_INTO: ${ids.join(', ')}. Review equivalence context.`,
        candidates: ids,
      });
    }
  }

  const equivalence = validateEquivalenceReview(
    review,
    candidates,
    { requireEquivalenceReview }
  );
  errors.push(...equivalence.errors);
  warnings.push(...equivalence.warnings);

  // DISPUTED는 점수에서 제외되는 미해결 분쟁 상태다. 피드백 루프가 max-iteration으로
  // 종료되며 남긴 DISPUTED가 CISO 결정 없이 그대로 발행되면 CRITICAL급 분쟁이 점수에서
  // 사라진 채 보고서로 나간다 — 발행 시점에 CISO 사인오프를 강제한다.
  const disputedUnresolved = candidates.filter((c) => {
    const status = normalizeDecision(c?.final_status || c?.status || c?.final_mapping?.status);
    if (status !== 'DISPUTED') return false;
    const resolved = [
      c?.ciso_decision, c?.ciso_acknowledged, c?.dispute_resolution, c?.resolution,
      c?.final_mapping?.ciso_decision, c?.final_mapping?.ciso_acknowledged,
      c?.final_mapping?.dispute_resolution,
    ].some(hasResolutionContent);
    return !resolved;
  });
  if (disputedUnresolved.length > 0) {
    errors.push({
      code: 'DISPUTED_UNRESOLVED_AT_PUBLISH',
      message: `${disputedUnresolved.length} DISPUTED candidate(s) lack a CISO decision/acknowledgement and are excluded from the score; resolve before publication: ${disputedUnresolved.map(getCandidateId).join(', ')}.`,
      candidates: disputedUnresolved.map(getCandidateId),
    });
  }

  const ledgerValidation = validateLedger(candidates);
  errors.push(...ledgerValidation.errors);
  // validateLedger의 fail-soft 지적(CONFIRMED_VALIDITY_PARTIAL 등)은 경고로 전달
  warnings.push(...(ledgerValidation.warnings || []));

  const scenarios = getScenarios(pentestPlan);
  const routeCoverage = calculatePentestRouteCoverage(candidates, scenarios);
  if (routeCoverage.coverage < 1) {
    errors.push({
      code: 'PENTEST_ROUTE_COVERAGE_INCOMPLETE',
      message: `Pending pentest candidates lack route/scenario coverage: ${routeCoverage.missing.join(', ')}`,
      missing: routeCoverage.missing,
    });
  }

  const effectiveReportedScore =
    reportedScore != null
      ? reportedScore
      : (getReportedScore(classification) ?? getReportedScore(ledger));
  let score = null;
  if (effectiveReportedScore != null) {
    score = validateScoreConsistency(candidates, effectiveReportedScore);
    if (!score.valid) {
      errors.push({
        code: 'SCORE_FORMULA_MISMATCH',
        message: `Reported security score ${score.reported} does not match CH015 formula result ${score.expected}.`,
        expected: score.expected,
        reported: score.reported,
        counts: score.counts,
      });
    }
  } else {
    const message = 'Security score was not provided; score formula gate cannot run.';
    if (requireScore) {
      errors.push({
        code: 'SCORE_NOT_PROVIDED',
        message,
      });
    } else {
      warnings.push({
        code: 'SCORE_NOT_PROVIDED',
        message,
      });
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    summary: summarizeCandidates(candidates),
    route_coverage: routeCoverage,
    score,
    provenance,
    gate_summary: gate.gateSummary,
  };
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      i += 1;
    }
  }
  return args;
}

function cliMain(argv) {
  const args = parseArgs(argv.slice(2));
  if (args.help || (!args.ledger && !args.classification)) {
    console.error('Usage: report-gate.js --ledger <yaml|json> [--classification <yaml|json with equivalence_review>] [--pentest-plan <yaml|json>] [--score <number>] [--manifest <source_manifest.json>] [--require-provenance] [--source-root <dir>] [--require-poc-binding]');
    process.exit(64);
  }

  const ledger = args.ledger ? readStructured(args.ledger) : [];
  const classification = args.classification ? readStructured(args.classification) : undefined;
  const pentestPlan = args['pentest-plan'] ? readStructured(args['pentest-plan']) : undefined;
  const reportedScore = args.score != null ? Number(args.score) : undefined;
  const manifest = args.manifest ? readStructured(args.manifest) : undefined;
  const requireProvenance = args['require-provenance'] === true;
  const sourceRoot = typeof args['source-root'] === 'string' ? args['source-root'] : null;
  const requirePocBinding = args['require-poc-binding'] === true;

  const result = validateReportGate({
    ledger, classification, pentestPlan, reportedScore, manifest, requireProvenance,
    sourceRoot, requirePocBinding,
  });
  if (!result.ok) {
    console.error('[CH015] Report gate failed');
    for (const error of result.errors) {
      const candidate = error.candidate_id ? ` ${error.candidate_id}` : '';
      console.error(`- ${error.code}${candidate}: ${error.message}`);
    }
    process.exit(2);
  }

  console.log('[CH015] Report gate passed');
}

if (require.main === module) {
  cliMain(process.argv);
}

module.exports = {
  readStructured,
  getScenarios,
  mergeCandidateClassifications,
  getEquivalenceReview,
  validateEquivalenceReview,
  applyDeterministicGates,
  validateReportGate,
};
