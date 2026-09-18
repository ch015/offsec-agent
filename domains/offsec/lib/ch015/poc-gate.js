'use strict';

/**
 * PoC 바인딩 게이트 (로드맵 #4). CONFIRMED을 기계검증화.
 *
 * 문제: CONFIRMED이 에이전트의 자기주장(prose)으로 정해지고, "verified"를 스스로 도장 찍을 수 있음.
 * 규율(T3MP3ST verify-finding.mjs:198 observed.includes(signature) + evidence/gate.ts self-stamp 불가 이식):
 *   CONFIRMED 후보는 반드시 poc_artifact(관측 산출물)를 갖고, 그 observed 내용에 finding 시그니처가
 *   실재해야 한다. 그 바인딩이 성립할 때만 **게이트가** verifiedAt을 부여한다.
 *   - poc_artifact 없음 / 시그니처 미관측 → 기계검증 실패 → CONFIRMED → CANDIDATE 강등.
 *   - 후보가 verifiedAt을 스스로 달고 오면(self-stamp) 게이트가 거부(무효화). verifiedAt writer는 게이트뿐.
 *
 * 기존 evidence.js(file:line↔소스 CONTENT_MISMATCH)와 상보적: evidence.js는 "인용이 소스에 실재",
 * poc-gate는 "CONFIRMED이 관측 산출물로 재현/증명"을 강제.
 *
 * 결정론적. CLI: node lib/ch015/poc-gate.js --self-test
 */

// 시그니처: 후보를 poc 산출물에 묶는 결정론 토큰. 명시 poc_signature 우선, 없으면 primary location(file:line).
function deriveSignature(candidate) {
  if (candidate.poc_signature) return String(candidate.poc_signature);
  const loc = candidate.location
    || (candidate.evidence && candidate.evidence.locations && candidate.evidence.locations[0])
    || (candidate.vuln_lines && Object.keys(candidate.vuln_lines).length
      ? `${Object.keys(candidate.vuln_lines)[0]}:${candidate.vuln_lines[Object.keys(candidate.vuln_lines)[0]][0]}`
      : null);
  return loc ? String(loc) : null;
}

// poc_artifact의 관측 내용 텍스트를 얻는다. inline(observed 문자열) 또는 ref(경로) → readArtifact(ref).
function artifactObserved(candidate, readArtifact) {
  const a = candidate.poc_artifact;
  if (a == null) return null;
  if (typeof a === 'string') { // 경로로 간주
    if (typeof readArtifact !== 'function') return null;
    try { return readArtifact(a); } catch { return null; }
  }
  if (typeof a === 'object') {
    if (typeof a.observed === 'string') return a.observed;
    if (a.path && typeof readArtifact === 'function') { try { return readArtifact(a.path); } catch { return null; } }
  }
  return null;
}

const norm = (s) => String(s).replace(/\s+/g, ' ').trim().toLowerCase();

/**
 * CONFIRMED 후보 하나를 기계검증.
 * opts.readArtifact(path)→내용|null, opts.now(게이트 소유 타임스탬프; 미주입 시 gate가 생성).
 * 반환 { applicable, verified, verifiedAt?, downgradeTo?, selfStampRejected, reason }.
 */
function verifyConfirmed(candidate, { readArtifact, now } = {}) {
  const status = String(candidate.status || '').toUpperCase();
  if (status !== 'CONFIRMED') return { applicable: false };

  const selfStampRejected = candidate.verifiedAt != null; // 후보가 자체 도장 → 거부 대상
  const sig = deriveSignature(candidate);
  if (!sig) return { applicable: true, verified: false, downgradeTo: 'CANDIDATE', selfStampRejected, reason: 'no_signature' };

  const observed = artifactObserved(candidate, readArtifact);
  if (observed == null) return { applicable: true, verified: false, downgradeTo: 'CANDIDATE', selfStampRejected, reason: 'no_poc_artifact' };

  if (norm(observed).includes(norm(sig))) {
    const stamp = now != null ? now : `gate:${Date.now()}`; // ★ 게이트 소유. 후보 self-stamp는 무시.
    return { applicable: true, verified: true, verifiedAt: stamp, selfStampRejected, reason: 'signature_observed' };
  }
  return { applicable: true, verified: false, downgradeTo: 'CANDIDATE', selfStampRejected, reason: 'signature_not_observed' };
}

/**
 * 후보 배열에 게이트 적용(불변). 검증 성공 → verifiedAt(게이트 소유) 부여. 실패 → CANDIDATE 강등.
 * self-stamp된 verifiedAt은 항상 제거 후 게이트 값으로만 대체.
 */
function applyPocGate(candidates, opts = {}) {
  let confirmed = 0, verified = 0, downgraded = 0, selfStamped = 0;
  const out = (candidates || []).map((c) => {
    const r = verifyConfirmed(c, opts);
    if (!r.applicable) return c;
    confirmed++;
    if (r.selfStampRejected) selfStamped++;
    const base = { ...c };
    delete base.verifiedAt; // self-stamp 무효화 — verifiedAt은 게이트만 쓴다
    if (r.verified) { verified++; return { ...base, verifiedAt: r.verifiedAt, poc_gate: { verified: true, reason: r.reason } }; }
    downgraded++;
    return { ...base, status: r.downgradeTo, poc_gate: { verified: false, reason: r.reason }, poc_gate_downgrade: `CONFIRMED→${r.downgradeTo}: ${r.reason}` };
  });
  return { candidates: out, summary: { confirmed, verified, downgraded, selfStamped } };
}

function selfTest() {
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  const NOW = 'gate:TEST';

  // 시그니처가 poc observed에 실재 → verified, 게이트 verifiedAt
  const good = verifyConfirmed({ status: 'CONFIRMED', location: 'auth.go:42', poc_artifact: { observed: 'curl → 200; sink reached at auth.go:42 with tainted input' } }, { now: NOW });
  ok('시그니처 관측됨 → verified', good.verified === true && good.verifiedAt === NOW);

  // poc_artifact 없음 → 강등
  const noPoc = verifyConfirmed({ status: 'CONFIRMED', location: 'auth.go:42' }, { now: NOW });
  ok('poc 없음 → CANDIDATE 강등', noPoc.verified === false && noPoc.downgradeTo === 'CANDIDATE' && noPoc.reason === 'no_poc_artifact');

  // 시그니처 미관측 → 강등
  const noSig = verifyConfirmed({ status: 'CONFIRMED', location: 'auth.go:42', poc_artifact: { observed: 'curl → 200 OK, nothing relevant' } }, { now: NOW });
  ok('시그니처 미관측 → 강등', noSig.verified === false && noSig.reason === 'signature_not_observed');

  // self-stamp 거부: 후보가 verifiedAt 달고 와도 게이트가 무효화하고 자기 값으로
  const selfStamp = verifyConfirmed({ status: 'CONFIRMED', location: 'x.go:1', verifiedAt: 'agent:cheat', poc_artifact: { observed: 'reached x.go:1' } }, { now: NOW });
  ok('self-stamp 감지', selfStamp.selfStampRejected === true);
  ok('self-stamp 무효화·게이트 값', selfStamp.verified === true && selfStamp.verifiedAt === NOW);

  // 경로 기반 artifact + readArtifact
  const viaPath = verifyConfirmed({ status: 'CONFIRMED', location: 'db.go:10', poc_artifact: 'poc/out.txt' }, { readArtifact: (p) => (p === 'poc/out.txt' ? 'trace: db.go:10 SQLi triggered' : null), now: NOW });
  ok('경로 artifact readArtifact 해소', viaPath.verified === true);

  // 명시 poc_signature 우선
  const explicitSig = verifyConfirmed({ status: 'CONFIRMED', poc_signature: 'CANARY-7Z', poc_artifact: { observed: 'output contains CANARY-7Z marker' } }, { now: NOW });
  ok('poc_signature 명시 우선', explicitSig.verified === true);

  // CONFIRMED 아님 → 비대상
  ok('DOWNGRADED → 비대상', verifyConfirmed({ status: 'DOWNGRADED', location: 'a:1' }, { now: NOW }).applicable === false);

  // applyPocGate 배열
  const batch = applyPocGate([
    { id: 'a', status: 'CONFIRMED', location: 'a.go:1', poc_artifact: { observed: 'reached a.go:1' } },       // verified
    { id: 'b', status: 'CONFIRMED', location: 'b.go:2' },                                                     // 강등
    { id: 'c', status: 'CONFIRMED', location: 'c.go:3', verifiedAt: 'agent:cheat', poc_artifact: { observed: 'nope' } }, // self-stamp+미관측→강등
    { id: 'd', status: 'CANDIDATE' },                                                                          // skip
  ], { now: NOW });
  ok('applyPocGate summary', batch.summary.confirmed === 3 && batch.summary.verified === 1 && batch.summary.downgraded === 2 && batch.summary.selfStamped === 1);
  ok('verified 후보 게이트 verifiedAt', batch.candidates.find((c) => c.id === 'a').verifiedAt === NOW);
  ok('강등 후보 status=CANDIDATE', batch.candidates.find((c) => c.id === 'b').status === 'CANDIDATE');
  ok('self-stamp 강등 후보 verifiedAt 제거', batch.candidates.find((c) => c.id === 'c').verifiedAt === undefined && batch.candidates.find((c) => c.id === 'c').status === 'CANDIDATE');
  ok('CANDIDATE 후보 불변', batch.candidates.find((c) => c.id === 'd').poc_gate === undefined);

  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  return fail === 0 ? 0 : 1;
}

if (require.main === module) {
  if (process.argv.includes('--self-test')) process.exit(selfTest());
  console.error('usage: node lib/ch015/poc-gate.js --self-test');
  process.exit(2);
}

module.exports = { deriveSignature, artifactObserved, verifyConfirmed, applyPocGate };
