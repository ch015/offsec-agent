'use strict';

const fs = require('fs');
const path = require('path');

const FILE_LINE_REGEX = /(?:^|\s|["'`(,])([a-zA-Z0-9_./-]+\.[a-zA-Z0-9]+):(\d+)(?:[-–](\d+))?/gm;

/**
 * Extract file:line references from markdown text
 * @param {string} text - markdown content
 * @returns {Array<{file: string, line: number, endLine: number|null, raw: string}>}
 */
function extractFileLineRefs(text) {
  const refs = [];
  const seen = new Set();
  let match;

  FILE_LINE_REGEX.lastIndex = 0;
  while ((match = FILE_LINE_REGEX.exec(text)) !== null) {
    const file = match[1];
    const line = parseInt(match[2], 10);
    const endLine = match[3] ? parseInt(match[3], 10) : null;
    const key = `${file}:${line}`;

    if (seen.has(key)) continue;
    seen.add(key);

    if (isLikelyCodePath(file)) {
      refs.push({ file, line, endLine, raw: match[0].trim() });
    }
  }

  return refs;
}

const CODE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.go', '.py', '.rs', '.java',
  '.sql', '.yaml', '.yml', '.toml', '.json', '.md', '.sh',
  '.cpp', '.c', '.h', '.hpp', '.cc', '.mm', '.m', '.kt', '.swift',
  '.cs', '.sol', '.proto', '.graphql', '.env', '.cfg', '.conf',
  '.dockerfile'
]);

function isLikelyCodePath(filepath) {
  if (filepath.startsWith('http')) return false;
  if (filepath.includes(' ')) return false;
  const ext = path.extname(filepath).toLowerCase();
  if (ext && CODE_EXTENSIONS.has(ext)) return true;
  if (filepath.includes('/') && !filepath.startsWith('.')) return true;
  if (filepath === 'Dockerfile' || filepath === 'Makefile') return true;
  return false;
}

/**
 * Extract evidence manifest from a VA report markdown file
 * Groups references by Finding ID (F-XXX pattern)
 * @param {string} reportPath - path to VA report .md file
 * @returns {Array<{finding_id: string, evidences: Array}>}
 */
function extractEvidenceManifest(reportPath) {
  const content = fs.readFileSync(reportPath, 'utf8');
  const lines = content.split('\n');

  const manifest = [];
  let currentFinding = null;
  const findingRegex = /^#+\s*(F-\d{3})/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const findingMatch = findingRegex.exec(line);

    if (findingMatch) {
      if (currentFinding && currentFinding.evidences.length > 0) {
        manifest.push(currentFinding);
      }
      currentFinding = {
        finding_id: findingMatch[1],
        evidences: []
      };
      continue;
    }

    if (currentFinding) {
      const refs = extractFileLineRefs(line);
      for (const ref of refs) {
        const contextStart = Math.max(0, i - 1);
        const contextEnd = Math.min(lines.length - 1, i + 1);
        const context = lines.slice(contextStart, contextEnd + 1).join(' ').trim();

        currentFinding.evidences.push({
          ref: `${ref.file}:${ref.line}${ref.endLine ? '-' + ref.endLine : ''}`,
          file: ref.file,
          line: ref.line,
          endLine: ref.endLine,
          claim: context.substring(0, 200)
        });
      }
    }
  }

  if (currentFinding && currentFinding.evidences.length > 0) {
    manifest.push(currentFinding);
  }

  return manifest;
}

// prose가 아닌 "코드 토큰"만 추출한다(dotted 접근, camelCase, snake_case, 따옴표 스니펫, 함수호출).
// 자연어 단어는 claim 설명에 흔하므로 매칭 요구 대상에서 제외 → CONTENT_MISMATCH 오탐 최소화.
function extractCodeTokens(claim) {
  const s = String(claim || '');
  const tokens = new Set();
  const add = (t) => { if (t && t.length >= 3) tokens.add(t.toLowerCase()); };
  // 따옴표/백틱 스니펫 내부 식별자
  for (const m of s.matchAll(/[`'"]([^`'"]{2,})[`'"]/g)) {
    for (const id of m[1].matchAll(/[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*/g)) add(id[0]);
  }
  for (const m of s.matchAll(/[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+/g)) add(m[0]); // dotted: req.body
  for (const m of s.matchAll(/\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b/g)) add(m[0]); // snake_case
  for (const m of s.matchAll(/\b[a-z]+[A-Z][A-Za-z0-9]*\b/g)) add(m[0]); // camelCase
  for (const m of s.matchAll(/\b([A-Za-z_$][\w$]{2,})\s*\(/g)) add(m[1]); // foo(
  return [...tokens];
}

/**
 * Step 3 (CONTENT_MISMATCH): claim이 설명하는 코드 패턴이 참조 영역에 실재하는지.
 * 보수적: 코드 토큰이 2개 미만이면 검사 생략(VERIFIED 유지). 2개 이상인데 영역에
 * 하나도(점 표기 마지막 세그먼트 포함) 없으면 mismatch.
 */
function checkClaimContent(claim, regionContent) {
  const tokens = extractCodeTokens(claim);
  if (tokens.length < 2) return { checked: false, mismatch: false, tokens, present: [] };
  const hay = String(regionContent || '').toLowerCase();
  const present = tokens.filter((t) => {
    if (hay.includes(t)) return true;
    const last = t.split('.').pop();
    return last && last.length >= 3 && hay.includes(last);
  });
  return { checked: true, mismatch: present.length === 0, tokens, present };
}

/**
 * Verify a single file:line reference against the filesystem
 * @param {string} projectRoot - project root directory
 * @param {Object} evidence - { file, line, endLine, claim }
 * @param {number} tolerance - line number tolerance (default ±10)
 * @param {Object} [options] - { contentMatch=true } claim↔코드 내용 일치 검사 활성화
 * @returns {Object} verification result
 */
function verifyEvidence(projectRoot, evidence, tolerance = 10, options = {}) {
  const contentMatch = options.contentMatch !== false;
  const invalid = (reason, detail) => ({
    ...evidence,
    status: 'INVALIDATED',
    reason,
    detail
  });

  const rawFile = evidence && typeof evidence.file === 'string' ? evidence.file : '';
  if (!rawFile || path.isAbsolute(rawFile) || rawFile.split(/[\\/]+/).includes('..')) {
    return invalid('PATH_OUTSIDE_PROJECT', `Evidence path is outside project scope: ${rawFile}`);
  }

  let rootReal;
  try {
    rootReal = fs.realpathSync(projectRoot);
  } catch (e) {
    return invalid('PROJECT_ROOT_NOT_FOUND', `Project root not found: ${projectRoot}`);
  }

  const fullPath = path.resolve(rootReal, rawFile);

  if (!fs.existsSync(fullPath)) {
    return invalid('FILE_NOT_FOUND', `File not found: ${fullPath}`);
  }

  let fullReal;
  try {
    fullReal = fs.realpathSync(fullPath);
  } catch (e) {
    return invalid('FILE_READ_ERROR', e.message);
  }

  if (fullReal !== rootReal && !fullReal.startsWith(rootReal + path.sep)) {
    return invalid('PATH_OUTSIDE_PROJECT', `Evidence path escapes project root: ${rawFile}`);
  }

  let fileContent;
  try {
    fileContent = fs.readFileSync(fullReal, 'utf8');
  } catch (e) {
    return invalid('FILE_READ_ERROR', e.message);
  }

  const fileLines = fileContent.split('\n');
  const totalLines = fileLines.length;

  if (evidence.line > totalLines + tolerance) {
    return {
      ...evidence,
      status: 'INVALIDATED',
      reason: 'LINE_OUT_OF_RANGE',
      detail: `Line ${evidence.line} exceeds file length ${totalLines}`
    };
  }

  const correctedLine = Math.min(evidence.line, totalLines);
  // endLine이 있으면 line..endLine 범위를, 없으면 단일 라인을 기준으로 ±tolerance 영역을 본다.
  const refEnd = (typeof evidence.endLine === 'number' && evidence.endLine >= correctedLine)
    ? Math.min(evidence.endLine, totalLines)
    : correctedLine;
  const startIdx = Math.max(0, correctedLine - 1 - tolerance);
  const endIdx = Math.min(totalLines - 1, refEnd - 1 + tolerance);

  const regionContent = fileLines.slice(startIdx, endIdx + 1).join('\n');

  // Step 3: claim 내용 일치 검사 (CONTENT_MISMATCH) — 문서 프로토콜 요구사항
  if (contentMatch) {
    const cc = checkClaimContent(evidence.claim, regionContent);
    if (cc.mismatch) {
      return {
        ...evidence,
        status: 'INVALIDATED',
        reason: 'CONTENT_MISMATCH',
        actual_line: correctedLine,
        detail: `Claim references code tokens [${cc.tokens.join(', ')}] not found within ±${tolerance} lines of line ${correctedLine}`,
        region_preview: regionContent.substring(0, 300)
      };
    }
  }

  return {
    ...evidence,
    status: 'VERIFIED',
    actual_line: correctedLine,
    line_corrected: correctedLine !== evidence.line,
    region_preview: regionContent.substring(0, 300)
  };
}

/**
 * Verify all evidences in a manifest against a project
 * @param {string} projectRoot
 * @param {Array} manifest - from extractEvidenceManifest
 * @param {number} tolerance
 * @returns {Object} verification summary
 */
function verifyManifest(projectRoot, manifest, tolerance = 10, options = {}) {
  let totalEvidences = 0;
  let verified = 0;
  let invalidated = { FILE_NOT_FOUND: 0, LINE_OUT_OF_RANGE: 0, FILE_READ_ERROR: 0, CONTENT_MISMATCH: 0 };
  const findingResults = [];

  for (const finding of manifest) {
    const results = [];
    for (const ev of finding.evidences) {
      totalEvidences++;
      const result = verifyEvidence(projectRoot, ev, tolerance, options);
      results.push(result);

      if (result.status === 'VERIFIED') {
        verified++;
      } else if (result.reason) {
        invalidated[result.reason] = (invalidated[result.reason] || 0) + 1;
      }
    }
    findingResults.push({
      finding_id: finding.finding_id,
      total: results.length,
      verified: results.filter(r => r.status === 'VERIFIED').length,
      invalidated: results.filter(r => r.status === 'INVALIDATED').length,
      results
    });
  }

  const totalInvalidated = Object.values(invalidated).reduce((s, v) => s + v, 0);

  return {
    total_evidences: totalEvidences,
    verified,
    invalidated: totalInvalidated,
    invalidated_breakdown: invalidated,
    hallucination_rate: totalEvidences === 0 ? 0 : totalInvalidated / totalEvidences,
    findings: findingResults
  };
}

/**
 * Normalize a ledger/finding object's evidence references into a uniform
 * [{ file, line, endLine, claim }] list. Mirrors runner.js normalizeFindingEvidences
 * so the CLI verifies the same shapes the runner does, reusing extractFileLineRefs.
 */
function normalizeFindingEvidences(finding) {
  const out = [];
  const pushRefString = (value, claim) => {
    for (const ref of extractFileLineRefs(String(value || ''))) {
      out.push({ file: ref.file, line: ref.line, endLine: ref.endLine || null, claim: claim || '' });
    }
  };

  if (Array.isArray(finding.evidences)) {
    for (const ev of finding.evidences) {
      if (ev && typeof ev === 'object' && ev.file) {
        out.push({ file: ev.file || '', line: ev.line || 0, endLine: ev.endLine || null, claim: ev.claim || '' });
      } else if (typeof ev === 'string') {
        pushRefString(ev);
      }
    }
  }

  const single = finding.evidence;
  if (typeof single === 'string') {
    pushRefString(single);
  } else if (single && typeof single === 'object') {
    if (Array.isArray(single.locations)) for (const loc of single.locations) pushRefString(loc);
    if (Array.isArray(single.live_evidence)) for (const live of single.live_evidence) pushRefString(live);
    if (single.file) {
      out.push({ file: single.file, line: single.line || 0, endLine: single.endLine || null, claim: single.claim || '' });
    }
  }

  if (Array.isArray(finding.affected_instances)) {
    for (const instance of finding.affected_instances) {
      if (typeof instance === 'string') pushRefString(instance);
      else if (instance && typeof instance === 'object' && instance.evidence) pushRefString(instance.evidence);
    }
  }

  const seen = new Set();
  return out.filter((ev) => {
    const key = `${ev.file}:${ev.line}:${ev.endLine || ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = {
  extractFileLineRefs,
  extractEvidenceManifest,
  verifyEvidence,
  verifyManifest,
  normalizeFindingEvidences,
  isLikelyCodePath
};

// ---------------------------------------------------------------------------
// CLI 진입점 (오케스트레이터가 `node lib/ch015/evidence.js verify ...`).
// exit code 계약: 0=통과, 2=차단(hallucination rate 초과), 1=사용오류.
// max-rate 기본: ch015.config.json harness.eval.maxHallucinationRate, 없으면 0.05.
// ---------------------------------------------------------------------------
function getFindingId(f) {
  return f.id || f.finding_id || f.final_finding_id || f.candidate_id || 'unknown';
}

function parseEvidenceArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--ledger') opts.ledger = argv[++i];
    else if (a === '--target') opts.target = argv[++i];
    else if (a === '--max-rate') opts.maxRate = argv[++i];
    else if (!a.startsWith('--') && !opts.command) opts.command = a;
  }
  return opts;
}

function resolveMaxRate(optValue) {
  if (optValue !== undefined) {
    const n = Number(optValue);
    if (Number.isFinite(n)) return n;
  }
  try {
    const { getConfig } = require('../core/config');
    const cfg = getConfig('harness.eval.maxHallucinationRate', undefined);
    if (typeof cfg === 'number') return cfg;
  } catch { /* fall through */ }
  return 0.05;
}

function runEvidenceCli(argv) {
  const opts = parseEvidenceArgs(argv);

  if (opts.command !== 'verify' || !opts.ledger || !opts.target) {
    process.stderr.write('USAGE: evidence.js verify --ledger <yaml> --target <srcdir> [--max-rate <0.05>]\n');
    return 1;
  }

  let doc;
  try {
    const yaml = require('js-yaml');
    doc = yaml.load(fs.readFileSync(opts.ledger, 'utf8'));
  } catch (e) {
    process.stderr.write(`USAGE_ERROR: cannot read/parse ${opts.ledger}: ${e.message}\n`);
    return 1;
  }

  if (!fs.existsSync(opts.target)) {
    process.stderr.write(`USAGE_ERROR: target directory not found: ${opts.target}\n`);
    return 1;
  }

  let findings = [];
  if (Array.isArray(doc)) {
    findings = doc;
  } else if (doc && typeof doc === 'object') {
    const keys = ['findings', 'candidates', 'raw_candidates', 'classifications',
      'candidate_classifications', 'final_classification'];
    for (const k of keys) {
      if (Array.isArray(doc[k])) { findings = doc[k]; break; }
    }
  }

  const manifest = findings
    .map((f) => ({ finding_id: getFindingId(f), evidences: normalizeFindingEvidences(f) }))
    .filter((f) => f.evidences.length > 0);

  const maxRate = resolveMaxRate(opts.maxRate);
  const result = verifyManifest(opts.target, manifest);
  const rate = result.hallucination_rate;

  if (rate > maxRate) {
    process.stderr.write(`EVIDENCE_HALLUCINATION_EXCEEDED: rate=${rate} max=${maxRate}\n`);
    return 2;
  }

  process.stdout.write(JSON.stringify({
    total_evidences: result.total_evidences,
    verified: result.verified,
    invalidated: result.invalidated,
    hallucination_rate: rate,
    max_rate: maxRate,
  }) + '\n');
  return 0;
}

if (require.main === module) {
  process.exit(runEvidenceCli(process.argv.slice(2)));
}
