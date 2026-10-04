import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { handleInvoice } from './fixture/server.mjs';
import locations from './paths.cjs';

const exec = promisify(execFile);
export const DEMO = path.dirname(fileURLToPath(import.meta.url));
const REPOS = locations.repos;
const RUNS = path.join(DEMO, 'runs');
const RUNTIME = path.join(DEMO, '.runtime');
const PORT = Number(process.env.DEMO_PORT || 8765);
const TARGET_PORT = Number(process.env.DEMO_TARGET_PORT || 8766);
export const targetUrl = `http://127.0.0.1:${TARGET_PORT}`;
const origin = `http://127.0.0.1:${PORT}`;
for (const dir of [RUNS, RUNTIME]) fs.mkdirSync(dir, { recursive: true });
const read = (file, fallback = null) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } };
const save = (file, data) => { fs.writeFileSync(file + '.tmp', JSON.stringify(data, null, 2)); fs.renameSync(file + '.tmp', file); };
const cleanError = error => String(error?.message || error).replace(/sk-ant-[\w-]+/g, '[redacted]').slice(0, 900);
let busy = null;
let webChild = null;
let results = read(path.join(RUNS, 'latest.json'), {});
let events = [];
function event(kind, text, detail = {}) {
  events.push({ at: new Date().toISOString(), kind, text, ...detail });
  events = events.slice(-160);
  console.log(`[${kind}] ${text}`);
}
function persist(kind, result) {
  results[kind] = result; save(path.join(RUNS, 'latest.json'), results);
  save(path.join(result.directory, 'result.json'), result);
  return result;
}
function start(kind) {
  const started = new Date().toISOString();
  const directory = path.join(RUNS, `${started.replace(/[:.]/g, '-')}-${kind}`);
  fs.mkdirSync(directory, { recursive: true });
  event(kind, '실제 실행을 시작했습니다.');
  return { kind, source: 'live', status: 'running', started, directory };
}
function finish(result, status, more = {}) {
  Object.assign(result, { status, finished: new Date().toISOString(), ...more });
  event(result.kind, status === 'completed' ? '실행을 완료했습니다.' : '실행 결과를 확인해 주세요.', { status });
  return persist(result.kind, result);
}
function subprocessEnv() {
  return Object.fromEntries(Object.entries(process.env).filter(([k]) => ['PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'TMPDIR', 'DISPLAY', 'SECURITY_PROJECT_ROOT', 'DEMO_OFFSEC_DIR', 'DEMO_SOC_DIR', 'DEMO_CODE_DIR', 'DEMO_WEB_DIR'].includes(k)));
}

export function createTargetServer() {
  return http.createServer((req, res) => {
    const url = new URL(req.url, targetUrl);
    if (url.pathname === '/health') { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ service: 'security-automation-demo-target' })); return; }
    if (url.pathname.startsWith('/api/invoices/') || url.pathname.startsWith('/fixed/invoices/')) { handleInvoice(req, res); return; }
    if (url.pathname === '/') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(fs.readFileSync(path.join(DEMO, 'sample.html'))); return;
    }
    res.writeHead(404); res.end('Not found');
  });
}
async function ensureTarget() {
  try {
    const r = await fetch(targetUrl + '/health', { signal: AbortSignal.timeout(700) });
    if ((await r.json()).service !== 'security-automation-demo-target') throw Error('시연 대상 포트를 다른 서비스가 사용 중입니다.');
    return null;
  } catch (error) {
    if (error.message.includes('다른 서비스')) throw error;
  }
  const server = createTargetServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(TARGET_PORT, '127.0.0.1', resolve); });
  return server;
}

async function code() {
  const r = start('code');
  const node20 = path.join(os.homedir(), '.nvm/versions/node/v20.0.0/bin/node');
  const command = fs.existsSync(node20) ? node20 : process.execPath;
  const { stdout, stderr } = await exec(command, [path.join(DEMO, 'code-context.cjs'), r.directory], { env: subprocessEnv(), timeout: 60000, maxBuffer: 4 * 1024 * 1024 });
  fs.writeFileSync(path.join(r.directory, 'execution.log'), stdout + stderr);
  const ast = read(path.join(r.directory, 'ast-result.json'));
  const contextFile = ast?.outputPath || path.join(r.directory, 'ast/ast-context.yaml');
  const stats = ast?.stats || ast?.context?.stats || {};
  return finish(r, ast?.ok === false ? 'incomplete' : 'completed', {
    title: '코드 구조와 분석 근거 수집', stats, artifact: path.join(r.directory, 'ast-result.json'),
    note: 'code-pentester의 실제 AST 전처리 결과입니다. 최종 취약점 판단은 Codex/Claude Code에서 독립 분석·검증 역할을 실행합니다.',
    nativePrompt: `$ch015-va ${path.join(DEMO, 'fixture')}\n로컬 합성 송장 서비스의 인증·소유권 검사를 진단하고 파일·줄 근거와 보완책을 제시해줘. 외부 대상 요청은 수행하지 마.`,
    contextAvailable: fs.existsSync(contextFile),
  });
}

async function web() {
  const r = start('web');
  const requests = [];
  for (const route of ['/api/invoices/INV-A', '/api/invoices/INV-B', '/fixed/invoices/INV-B']) {
    const response = await fetch(targetUrl + route, { headers: { Authorization: 'Bearer demo-alice' } });
    const body = await response.json();
    requests.push({ url: targetUrl + route, principal: 'alice', status: response.status, body });
  }
  const verified = requests[0].status === 200 && requests[1].status === 200 && requests[1].body.owner === 'bob' && requests[2].status === 403;
  return finish(r, verified ? 'completed' : 'incomplete', { title: '타인 송장 조회와 수정 후 차단 재현', requests,
    note: '로컬 샘플 서비스에 실제 HTTP 요청 3회를 보낸 결과입니다. Web Pentester 앱에서 Traffic·Repeater·보안 헤더 검사를 이어서 보여줍니다.' });
}

async function offsec() {
  if (!process.env.ANTHROPIC_API_KEY) throw Error('실제 AI 실행에는 ANTHROPIC_API_KEY가 설정된 터미널이 필요합니다. 실행 기록 보기는 키 없이 사용할 수 있습니다.');
  const r = start('offsec');
  const { createOffsecAgent } = await import(path.join(REPOS.offsec, 'dist/src/index.js'));
  const engagementDir = path.join(r.directory, 'engagement');
  const phases = [], tools = [];
  const agent = createOffsecAgent({ apiKey: process.env.ANTHROPIC_API_KEY,
    defaults: { model: 'sonnet', reviewModel: 'haiku', effort: 'low', maxTurns: 45, maxBudgetUsd: 4, maxConcurrency: 1, maxFollowupHypotheses: 0, semgrepMode: 'off' },
    onStderr(chunk) { fs.appendFileSync(path.join(r.directory, 'provider-stderr.log'), String(chunk).replace(/sk-ant-[\w-]+/g, '[redacted]')); },
    onMetrics(metric) { phases.push(metric); event('offsec', `${metric.phase}: ${metric.validationPassed ? '검증 통과' : '검증 실패'}`, { phase: metric.phase }); },
    onLedger(row) { if (row.tool) { tools.push({ tool: row.tool, decision: row.decision }); } },
  });
  try {
    const output = await agent.run({ target: path.join(DEMO, 'fixture'), engagementDir,
      scope: '로컬 합성 송장 서비스의 인증·소유권 검사만 정적으로 진단한다. 모든 계정과 금액은 시연용이다. /api와 /fixed 경로의 차이를 설명하라. 외부 요청이나 런타임 공격은 수행하지 않는다. 최종 보고서를 한국어로 작성하고 원장의 심각도와 finding ID를 정확하게 보존하라.' },
      { signal: AbortSignal.timeout(900000) });
    const report = fs.readFileSync(output.finalReport, 'utf8');
    const findingDir = path.join(engagementDir, 'standard-findings');
    const findings = fs.existsSync(findingDir) ? fs.readdirSync(findingDir).filter(n => n.endsWith('.json')).map(n => read(path.join(findingDir, n))) : [];
    const state = read(path.join(engagementDir, 'run-state.json'));
    save(path.join(r.directory, 'phase-metrics.json'), phases);
    return finish(r, output.status === 'published' && output.publicationStatus === 'published' ? 'completed' : 'incomplete', {
      title: '소스 분석 → 독립 검토 → 평가 → 보고서', publicationStatus: output.publicationStatus,
      phases: state?.completedPhases || [], phaseMetrics: phases, toolCalls: tools.length,
      findings: findings.map(({ id, title, severity, confidence, evidence, remediation }) => ({ id, title, severity, confidence, evidence, remediation })),
      report, artifact: output.finalReport, coverage: output.coverage,
      attempts: Object.values(state?.attempts || {}).map(({ phase, attempt, status, failureReason }) => ({ phase, attempt, status, failureReason })),
      note: '실제 Anthropic 모델·OffSec 공개 API·발행 게이트를 사용했습니다. 입력은 합성 코드이며 Semgrep과 동적 공격은 실행하지 않습니다.',
    });
  } catch (error) { return finish(r, 'incomplete', { error: cleanError(error) }); }
}

async function soc() {
  if (!process.env.ANTHROPIC_API_KEY) throw Error('실제 AI 실행에는 ANTHROPIC_API_KEY 환경변수가 필요합니다.');
  const r = start('soc');
  const { createSocAgent, SocLlmClient } = await import(path.join(REPOS.soc, 'dist/src/index.js'));
  const observed = results.web?.status === 'completed' && Date.now() - Date.parse(results.web.finished) < 60000 ? results.web : await web();
  const evidenceEvents = observed.requests.map((request, i) => ({ eventId: `demo-request-${i + 1}`, timestamp: observed.finished,
    actor: request.principal, resourceOwner: request.body.owner || 'bob', resource: new URL(request.url).pathname,
    status: request.status, sourceIp: '127.0.0.1', type: 'api_access', requestSource: 'loopback-demo-probe' }));
  const counts = {
    total: evidenceEvents.length,
    own: evidenceEvents.filter(e => e.actor === e.resourceOwner).length,
    other: evidenceEvents.filter(e => e.actor !== e.resourceOwner).length,
    otherSuccess: evidenceEvents.filter(e => e.actor !== e.resourceOwner && e.status === 200).length,
    otherDenied: evidenceEvents.filter(e => e.actor !== e.resourceOwner && e.status === 403).length,
  };
  const countSentence = `확인한 요청은 총 ${counts.total}건으로, 본인 송장 ${counts.own}건과 타인 송장 ${counts.other}건(성공 ${counts.otherSuccess}건, 차단 ${counts.otherDenied}건)입니다.`;
  const signal = { signalId: `demo-access-${Date.now()}`, signalType: 'alert', source: 'local-demo-access-log', severity: 'high',
    timestamp: new Date().toISOString(), subject: { type: 'user', value: 'alice' },
    tenantId: 'synthetic-demo', rule: { id: 'cross-owner-invoice', name: '타인 소유 송장 조회 성공', category: 'access-control' },
    tags: ['synthetic-demo', 'observed-local-http'] };
  const calls = [];
  const identities = [
    { id: 'alice', role: 'customer', owns: ['INV-A'], canReadOtherCustomers: false },
    { id: 'bob', role: 'customer', owns: ['INV-B'], canReadOtherCustomers: false },
  ];
  const capabilities = ['get_signal', 'get_rule', 'get_event_fields', 'search_events', 'get_threat_intel', 'get_identity', 'investigate_entity', 'get_entity_graph'];
  const connector = { capabilities, async execute(name, parameters) {
    calls.push({ name, parameters }); event('soc', `근거 조회: ${name}`);
    const common = { complete: true, synthetic: true, dataScope: 'Only the three local HTTP requests in this exercise; no external telemetry or credential-theft evidence.', exerciseCounts: counts };
    switch (name) {
      case 'get_signal': return { ...common, ...signal, events: evidenceEvents };
      case 'get_rule': return { ...common, id: signal.rule.id, logic: 'Authenticated actor differs from resource owner and HTTP status is 200.', enabled: true };
      case 'get_event_fields': return { ...common, fields: ['actor', 'resourceOwner', 'resource', 'status', 'sourceIp'], querySyntax: 'field:value joined with AND' };
      case 'search_events': {
        const conditions = parameters.query.split(/\s+AND\s+/i).map(part => {
          const match = /^(actor|resourceOwner|resource|status|sourceIp):(?:"([^"]+)"|([^\s]+))$/.exec(part.trim());
          if (!match) throw Error('Unsupported demo query. Use field:value joined with AND; read get_event_fields for available fields.');
          return { field: match[1], value: match[2] || match[3] };
        });
        const from = Date.parse(signal.timestamp) - parameters.minutesBefore * 60000;
        const to = Date.parse(signal.timestamp) + parameters.minutesAfter * 60000;
        const matched = evidenceEvents.filter(e => Date.parse(e.timestamp) >= from && Date.parse(e.timestamp) <= to && conditions.every(c => String(e[c.field]) === c.value));
        const start = (parameters.page - 1) * parameters.size;
        return { ...common, events: matched.slice(start, start + parameters.size), total: matched.length, hasMore: start + parameters.size < matched.length };
      }
      case 'get_threat_intel': return { ...common, indicators: [], note: 'Loopback source in an isolated synthetic exercise; external reputation is not evidence of this authorization flaw.' };
      case 'get_identity': {
        const identity = identities.find(item => item.id === parameters.identityId);
        if (!identity) throw Error('No such identity in this exercise');
        return { ...common, identity };
      }
      case 'investigate_entity': {
        if (parameters.entityType !== 'principal' || !identities.some(item => item.id === parameters.entityValue)) throw Error('This demo supports only the observed alice/bob principals');
        return { ...common, entity: parameters.entityValue, events: evidenceEvents.filter(item => item.actor === parameters.entityValue || item.resourceOwner === parameters.entityValue), approvedCrossTenantAccess: false };
      }
      case 'get_entity_graph': return { ...common, nodes: [{ id: 'alice', type: 'user' }, { id: 'INV-B', type: 'invoice', owner: 'bob' }], edges: [{ from: 'alice', to: 'INV-B', action: 'read', eventId: 'demo-request-2', httpStatus: 200 }] };
      default: throw Error('Unsupported fixture tool');
    }
  } };
  const modelTurns = [];
  const llm = new SocLlmClient({ apiKey: process.env.ANTHROPIC_API_KEY, maxTokens: 3000, timeoutMs: 60000 });
  const completeTurn = llm.completeTurn.bind(llm);
  llm.completeTurn = async input => {
    const started = Date.now();
    try {
      const response = await completeTurn(input);
      modelTurns.push({ turn: modelTurns.length + 1, durationMs: Date.now() - started, ...response });
      save(path.join(r.directory, 'model-turns.json'), modelTurns);
      return response;
    } catch (error) {
      modelTurns.push({ turn: modelTurns.length + 1, durationMs: Date.now() - started, error: cleanError(error) });
      save(path.join(r.directory, 'model-turns.json'), modelTurns);
      throw error;
    }
  };
  const agent = createSocAgent({ llm,
    dataSource: { createConnector: () => connector }, limits: { maxTurns: 8, maxToolCalls: 10, timeoutMs: 180000 },
    assessmentGuard({ assessment }) {
      const issues = [];
      const prose = [assessment.title, assessment.summary, ...assessment.findings.map(f => f.description), ...Object.values(assessment.recommendation).filter(Boolean)];
      if (prose.some(value => !/[가-힣]/.test(value))) issues.push('제목·요약·각 권고를 한국어로 작성하세요. JSON 키와 evidence ID는 유지하세요.');
      if (assessment.mitreTactics.length) issues.push('이 IDOR 시연에는 ATT&CK 기술을 검증한 근거가 없습니다. 계정 탈취·브라우저 자격증명 탈취 등 관측하지 않은 행위를 매핑하지 말고 mitreTactics를 빈 배열로 반환하세요.');
      if (!assessment.summary.startsWith(countSentence)) issues.push(`실제 관측 건수와 요약을 일치시켜야 합니다. summary를 다음 문장으로 시작하세요: ${countSentence} 이후에는 건수를 반복 서술하지 말고 권한과 응답의 의미를 설명하세요.`);
      return issues.length ? issues.join(' ') + ' 이미 완료한 조회를 반복하지 마세요.' : undefined;
    },
  });
  const output = await agent.run(signal, { context: `이 조사는 로컬 합성 서비스에서 수집한 실제 HTTP 시연 요청에 관한 것이다. alice는 고객이며 bob의 송장을 조회할 권한이 없다. 한국어로 판단 근거와 권고를 작성한다. 운영 환경이나 외부 침해사고에 대한 결론으로 확대하지 않는다. 관측 집계는 다음과 같으며, summary를 이 문장으로 시작한다: ${countSentence}` });
  return finish(r, output.status, { title: '접근 경보 → 관련 로그·계정 조회 → 판단 근거', assessment: output.result,
    reason: output.reason, modelCalls: output.modelCalls, calls, observations: output.observations, actions: output.actions,
    usage: output.usage, signal, sourceRun: observed.directory, counts, countSentence,
    note: '실제 모델과 SOC 조사 루프를 사용했습니다. 데이터 어댑터는 로컬 시연 요청과 합성 계정 정보를 제공하며, SIEM 차단·메시지 전송은 수행하지 않습니다.' });
}
const jobs = { code, web, offsec, soc };
function printResult(result, full = false) {
  console.log(`\n${result.kind} | ${result.status} | ${result.source === 'recording' ? '저장된 실제 실행 기록' : '실제 실행 결과'}`);
  console.log(`실행 시각: ${result.started} → ${result.finished}`);
  if (result.kind === 'code') {
    console.log(JSON.stringify(result.stats, null, 2));
    console.log('AST는 코드 구조 수집 단계입니다. 에이전트 진단 실행문은 다음 명령으로 확인합니다: bash demo.sh prompt');
  }
  if (result.kind === 'web') {
    for (const request of result.requests || []) console.log(`${request.principal} | ${new URL(request.url).pathname} | HTTP ${request.status} | ${request.body.owner || request.body.error}`);
  }
  if (result.kind === 'offsec') {
    console.log(`보고서 발행: ${result.publicationStatus || '미발행'}`);
    for (const item of result.phaseMetrics || []) console.log(`${item.phase} | ${item.validationPassed ? '검증 통과' : '검증 실패'}`);
    for (const finding of result.findings || []) console.log(`${finding.id} | ${finding.severity} | ${finding.title}`);
    if (full && result.report) console.log('\n' + result.report);
  }
  if (result.kind === 'soc' && result.assessment) {
    const assessment = result.assessment;
    console.log(`${assessment.decision} | 모델 ${result.modelCalls}회 | 도구 ${result.calls?.length || 0}회`);
    console.log(assessment.title + '\n' + assessment.summary);
    for (const finding of assessment.findings) console.log(`- ${finding.description} [근거: ${finding.evidence.join(', ')}]`);
    for (const [key, value] of Object.entries(assessment.recommendation)) if (value) console.log(`${key}: ${value}`);
    if (full) console.log('\n도구 조회 이력\n' + JSON.stringify(result.calls, null, 2));
  }
  if (result.reason || result.error) console.log(`확인 사항: ${result.reason || result.error}`);
  console.log(`근거 디렉토리: ${result.directory}`);
  if (result.artifact) console.log(`산출물: ${result.artifact}`);
  if (result.note) console.log(result.note);
}
function help() {
  console.log(`보안 진단 자동화 CLI 시연

현재 디렉토리: demo/security-automation
  bash demo.sh prepare            에이전트 라이브러리 빌드
  bash demo.sh code               code-pentester AST 전처리 (모델 호출 없음)
  bash demo.sh prompt             code-pentester 에이전트 진단 실행문 출력
  bash demo.sh web                로컬 HTTP 요청: 200 / 200 / 403 비교
  bash demo.sh offsec             실제 AI 분석 → 검토 → 평가 → 보고서
  bash demo.sh soc                실제 AI 경보 조사 → 근거 → 한국어 권고
  bash demo.sh show offsec        최근 OffSec 보고서 전문
  bash demo.sh show soc           최근 SOC 판단과 도구 조회 이력
  bash demo.sh show soc --json    원본 JSON (리다이렉션·jq 사용 가능)
  bash demo.sh status             네 구성요소의 최근 실행 상태
  bash demo.sh rehearse           code → web → soc → offsec 순서 실행
  bash demo.sh snapshot           성공한 실행 4종을 발표용 기록으로 저장
  bash demo.sh verify             CLI 명령·저장 기록·실행 근거 검증
  bash demo.sh show offsec --recorded  보관된 보고서 보기 (API 키 불필요)
  bash demo.sh target             curl 시연용 샘플 API 실행 (Ctrl+C 종료)
  bash demo.sh web-app            기존 Web Pentester 앱으로 동일 사례 확인

OffSec·SOC 실제 실행: ANTHROPIC_API_KEY 환경변수 필요.
OffSec: 최대 $4·15분. SOC: 8턴·도구 10회·전체 3분, 모델 호출당 60초.
새 결과는 runs/<실행시각>-<종류>/에 보관합니다.
전체 진행 순서·직접 실행 명령·예상 결과: CLI-GUIDE.txt`);
}
async function run(kind) {
  if (!Object.hasOwn(jobs, kind)) throw Error('Unknown demo');
  if (busy) throw Error(`${busy} 실행이 진행 중입니다.`);
  busy = kind;
  try { return await jobs[kind](); }
  catch (error) { event(kind, cleanError(error)); throw error; }
  finally { busy = null; }
}
function recordings() { return read(path.join(DEMO, 'recordings/index.json'), {}); }
function publicState() { return { demoId: 'security-automation-local-demo', busy, events, results, recordings: recordings(), webApp: read(path.join(RUNTIME, 'web-demo-proof.json')), aiAvailable: Boolean(process.env.ANTHROPIC_API_KEY), targetUrl, origin }; }
function json(res, code, value) { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); }
async function openWeb(check = false) {
  if (!check && webChild && webChild.exitCode === null) return webChild.pid;
  const executable = path.join(REPOS.web, 'node_modules/.bin/electron');
  const log = fs.openSync(path.join(RUNTIME, 'web-app.log'), 'a');
  const child = spawn(executable, [path.join(DEMO, 'web-demo.cjs'), ...(check ? ['--check'] : [])], {
    cwd: REPOS.web, env: { ...subprocessEnv(), DEMO_TARGET_URL: targetUrl }, stdio: ['ignore', log, log],
  });
  webChild = child;
  fs.closeSync(log);
  if (check) await new Promise((resolve, reject) => { child.on('error', reject); child.on('exit', code => code === 0 ? resolve() : reject(Error(`Web demo exited ${code}; see .runtime/web-app.log`))); });
  else child.on('error', error => event('web', cleanError(error)));
  return child.pid;
}
async function serve(open) {
  try {
    const existing = await fetch(origin + '/state', { signal: AbortSignal.timeout(700) });
    if (existing.ok && (await existing.json()).demoId === 'security-automation-local-demo') {
      console.log(`시연 서버가 이미 실행 중입니다: ${origin}`);
      if (open) await exec('open', [origin]);
      return;
    }
  } catch { /* Start a new server when the demo is not running. */ }
  const target = await ensureTarget();
  const server = http.createServer(async (req, res) => {
    if (req.headers.host !== `127.0.0.1:${PORT}`) { json(res, 403, { error: 'Use the loopback demo URL' }); return; }
    const url = new URL(req.url, origin);
    try {
      if (req.method === 'GET' && url.pathname === '/state') { json(res, 200, publicState()); return; }
      if (req.method === 'POST') {
        if (req.headers.origin !== origin) { json(res, 403, { error: 'Invalid demo origin' }); return; }
        const kind = url.pathname.slice('/run/'.length);
        if (url.pathname === '/open-web') { json(res, 200, { pid: await openWeb() }); return; }
        if (url.pathname.startsWith('/run/') && Object.hasOwn(jobs, kind)) {
          if (busy) { json(res, 409, { error: `${busy} 실행 중` }); return; }
          void run(kind).catch(() => {}); json(res, 202, { accepted: kind }); return;
        }
      }
      const files = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'], '/guide': ['guide.html', 'text/html'] };
      if (req.method === 'GET' && files[url.pathname]) {
        const [name, type] = files[url.pathname];
        res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8`, 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'", 'Cache-Control': 'no-store' });
        res.end(fs.readFileSync(path.join(DEMO, name))); return;
      }
      json(res, 404, { error: 'Not found' });
    } catch (error) { json(res, 500, { error: cleanError(error) }); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(PORT, '127.0.0.1', resolve); });
  save(path.join(RUNTIME, 'server.json'), { pid: process.pid, origin, targetUrl, started: new Date().toISOString() });
  console.log(`시연 화면: ${origin}\n샘플 서비스: ${targetUrl}\n종료: Ctrl+C`);
  if (open) execFile('open', [origin], () => {});
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => { server.close(); target?.close(); process.exit(0); });
}
async function main() {
  const command = process.argv[2] || 'help';
  if (['help', '--help', '-h'].includes(command)) { help(); return; }
  if (command === 'status') {
    for (const kind of Object.keys(jobs)) {
      const result = results[kind];
      console.log(`${kind.padEnd(7)} | ${result?.status || '실행 전'} | ${result?.finished || '-'} | ${result?.directory || '-'}`);
    }
    return;
  }
  if (command === 'prompt') {
    console.log(`Codex의 CH015 스킬 입력창에 아래 내용을 입력하세요 (셸 명령이 아닙니다).\n\n$ch015-va ${path.join(DEMO, 'fixture')}\n로컬 합성 송장 서비스의 인증·소유권 검사를 진단하고 파일·줄 근거와 보완책을 제시해줘. 외부 대상 요청은 수행하지 마.\n\nClaude Code에 설치된 CH015 플러그인에서는:\n/ch015:va --target ${path.join(DEMO, 'fixture')} --mode ast`);
    return;
  }
  if (command === 'show') {
    const kind = process.argv[3];
    if (!Object.hasOwn(jobs, kind)) throw Error('show 뒤에는 code, web, offsec, soc 중 하나를 지정하세요.');
    const result = (process.argv.includes('--recorded') ? recordings() : results)[kind];
    if (!result) throw Error(`${kind} 실행 기록이 없습니다.`);
    if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
    else printResult(result, true);
    return;
  }
  if (command === 'target') {
    const target = await ensureTarget();
    if (!target) { console.log(`샘플 API가 이미 실행 중입니다: ${targetUrl}`); return; }
    console.log(`샘플 API: ${targetUrl}\n종료: Ctrl+C`);
    for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => target.close());
    return;
  }
  if (command === 'serve') { await serve(process.argv.includes('--open')); return; }
  if (command === 'verify') { await import('./verify-cli.mjs'); return; }
  if (command === 'prepare') {
    for (const repo of [REPOS.offsec, REPOS.soc]) {
      console.log(`빌드: ${repo}`);
      await exec(process.execPath, ['scripts/build-library.mjs'], { cwd: repo, env: process.env, timeout: 120000 });
    }
    console.log(`시연 라이브러리 빌드 완료 | Node ${process.version} | API 키: ${process.env.ANTHROPIC_API_KEY ? '설정됨' : '미설정'}`); return;
  }
  if (command === 'snapshot') {
    const directory = path.join(DEMO, 'recordings'); fs.mkdirSync(directory, { recursive: true });
    const snapshots = {};
    for (const kind of Object.keys(jobs)) {
      const r = results[kind]; if (r?.status !== 'completed') throw Error(`${kind}의 성공한 실제 실행 결과가 필요합니다.`);
      snapshots[kind] = { ...r, source: 'recording', recordedAt: new Date().toISOString() };
      if (r.artifact && fs.existsSync(r.artifact)) snapshots[kind].artifactSha256 = createHash('sha256').update(fs.readFileSync(r.artifact)).digest('hex');
    }
    save(path.join(directory, 'index.json'), snapshots); console.log('실제 성공 결과 4종의 재생 기록을 저장했습니다.'); return;
  }
  if (command !== 'rehearse' && command !== 'web-app' && !Object.hasOwn(jobs, command)) throw Error('알 수 없는 명령입니다. bash demo.sh help를 확인하세요.');
  const target = ['web', 'soc', 'rehearse', 'web-app'].includes(command) ? await ensureTarget() : null;
  try {
    if (command === 'web-app') {
      const check = process.argv.includes('--check'); await openWeb(check);
      if (!check && target && webChild?.exitCode === null) await new Promise(resolve => webChild.once('exit', resolve));
      return;
    }
    for (const kind of command === 'rehearse' ? ['code', 'web', 'soc', 'offsec'] : [command]) {
      const result = await run(kind); printResult(result);
      if (result.status !== 'completed') process.exitCode = 1;
    }
  } finally { target?.close(); }
}
main().catch(error => { console.error(cleanError(error)); process.exitCode = 1; });
