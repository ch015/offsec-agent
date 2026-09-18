'use strict';

const { extractDataFlows } = require('./data-flow');

// User-controlled input markers seen in call arguments and framework entry points.
const SOURCE_ARGUMENT_PATTERNS = [
  /\b(req|request)\.(body|query|params|headers|cookies)\b/i,
  /\b(ctx|context)\.(request|query|params|headers|cookies)\b/i,
  /\bevent\.(body|queryStringParameters|pathParameters|headers)\b/i,
  /\b(input|stdin|argv|process\.argv)\b/i,
  /\$_(GET|POST|REQUEST|COOKIE|SERVER)\b/,
  // Python Flask/Django — request.form/args/json/values/files/GET/POST/data
  /\b(request|self\.request)\.(form|args|json|values|files|data|GET|POST)\b/,
  // Ruby Rails / Sinatra — params[:id] / params['id']
  /\bparams\[/,
  // Java Spring — @RequestBody / @RequestParam / @PathVariable / @RequestHeader
  /@(RequestBody|RequestParam|PathVariable|RequestHeader)\b/,
  // Go net/http + gorilla/mux — r.FormValue / r.URL.Query() / mux.Vars(r)
  /\br\.(FormValue|PostFormValue|Form|URL\.Query)\b/,
  /\bmux\.Vars\b/,
  // Environment-sourced input (SSRF/injection via env-configured values)
  /\bprocess\.env\b/,
  /\bos\.environ\b/,
];

const SINK_PATTERNS = {
  sql: [
    'query', 'execute', 'raw', '$queryRaw', 'createQueryBuilder',
    'findBySql', 'sequelize.query',
  ],
  command: [
    'exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'system',
    'popen', 'shell_exec', 'passthru',
    // Python subprocess — check_output/check_call/Popen are the common OS-command
    // injection sinks (shell=True). Bare 'run' is omitted (too generic → FP).
    'check_output', 'check_call', 'Popen',
  ],
  file: [
    'readFile', 'writeFile', 'appendFile', 'createReadStream',
    'createWriteStream', 'open', 'unlink', 'rm', 'rename',
  ],
  response: [
    'send', 'write', 'end', 'render',
  ],
  deserialize: [
    'JSON.parse', 'yaml.load', 'deserialize', 'unserialize', 'pickle.loads',
  ],
  redirect: [
    'redirect', 'location.assign', 'location.replace',
  ],
  eval: [
    'eval', 'Function', 'setTimeout', 'setInterval', 'execScript',
  ],
  // SSRF (CWE-918): server-side HTTP clients. Dotted patterns only — a bare
  // `get`/`request` token would match Map.get/redis.get/this.request (FP).
  ssrf: [
    'axios.get', 'axios.post', 'axios.put', 'axios.delete', 'axios.request',
    'http.get', 'http.request', 'https.get', 'https.request',
    'fetch', 'got.get', 'got.post', 'superagent.get',
    'requests.get', 'requests.post', 'requests.request',
    'urllib.request.urlopen', 'urlopen',
  ],
  // NoSQL injection (CWE-943): Mongo-style operators. `find` is deliberately
  // excluded — Array.prototype.find would flood FPs; only the less-ambiguous
  // findOne/aggregate/findOneAnd* selectors are used.
  nosql: [
    'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace',
    'aggregate', 'mapReduce',
  ],
};

// Functions that sanitize/validate input.
const SANITIZER_PATTERNS = [
  'escape', 'sanitize', 'validate', 'clean', 'purify', 'encode',
  'encodeURI', 'encodeURIComponent', 'htmlspecialchars',
  // Numeric/boolean coercion genuinely neutralizes injection through that value,
  // so it is retained as a sanitizer (removing it would inflate false positives).
  'parseInt', 'parseFloat', 'Number', 'Boolean',
  'DOMPurify', 'xss', 'bleach',
  'parameterize', 'placeholder', 'prepare',
  // NOTE: password-hashing (createHash/hash/bcrypt/scrypt) is intentionally NOT a
  // sanitizer — hashing does not neutralize injection into a downstream sink, and
  // crediting it here suppressed genuine tainted-flow findings.
];

const SINK_CWE_MAP = {
  sql: 'CWE-89',
  command: 'CWE-78',
  file: 'CWE-22',
  response: 'CWE-79',
  deserialize: 'CWE-502',
  redirect: 'CWE-601',
  eval: 'CWE-94',
  ssrf: 'CWE-918',
  nosql: 'CWE-943',
};

const MAX_PATHS = 50;
const SANITIZER_CONTEXT_WINDOW_LINES = 50;

// taint 소스로 인정하지 않는 entry point 타입 — 네트워크/외부 입력 표면이 아님.
// (http/graphql/websocket/serverless/worker/file_route 등은 소스로 인정)
const NON_SOURCE_ENTRY_TYPES = new Set([
  'sdk_export', 'angular_component', 'react_route', 'react_component',
]);

function computeTaintPaths(callGraph, options = {}) {
  if (!callGraph) return [];

  const maxPaths = options.maxPaths || MAX_PATHS;
  const dataFlows = options.dataFlows || extractDataFlows(callGraph);
  const taintedVars = buildTaintedVars(callGraph);
  const paths = [];

  for (const flow of dataFlows) {
    if (paths.length >= maxPaths) break;

    // 소스 모델 정밀화: taint 소스는 신뢰 불가한 외부 입력 표면만 인정한다.
    // sdk_export(라이브러리 공개 함수)·Angular/React 컴포넌트는 네트워크 입력이 아니라
    // 내부/클라이언트 진입점이므로 taint 소스에서 제외한다(저신뢰 FP 방지).
    if (flow.entry?.type && NON_SOURCE_ENTRY_TYPES.has(flow.entry.type)) continue;

    const sink = classifyTerminal(flow.terminal);
    if (!sink) continue;

    const source = {
      file: flow.entry.file,
      line: flow.entry.line,
      expr: formatEntryExpression(flow.entry),
      type: 'entry_point',
    };

    const sanitizers = findSanitizersForFlow(flow, callGraph);
    const taintedArguments = identifyTaintedArguments(flow, taintedVars);
    const confidence = computeConfidence(source, sink, sanitizers, flow.hops || 0, taintedArguments.length > 0);
    if (confidence < 0.1) continue;

    paths.push({
      source,
      sink,
      via: flow.via || [],
      sanitizers,
      hops: flow.hops || 0,
      confidence,
      // 사용자 입력이 sink 인자에 실제 도달했다는 증거 유무 — 다운스트림 verifier 우선순위용
      source_reaches_sink: taintedArguments.length > 0,
      potential_cwe: SINK_CWE_MAP[sink.category] || null,
      tainted_arguments: taintedArguments,
    });
  }

  return dedupePaths(paths)
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, maxPaths);
}

function identifySources(callGraph) {
  const sources = [];

  for (const ep of callGraph.entryPoints || []) {
    sources.push({
      file: ep.file,
      line: ep.line,
      expr: formatEntryExpression(ep),
      type: 'entry_point',
    });
  }

  for (const edge of callGraph.edges || []) {
    const sourceArgs = (edge.arguments || []).filter(arg => isSourceExpression(arg.expr));
    for (const arg of sourceArgs) {
      sources.push({
        file: edge.file,
        line: edge.line,
        expr: arg.expr,
        type: 'user_input_argument',
      });
    }
  }

  return dedupeItems(sources, item => `${item.file}:${item.line}:${item.expr}:${item.type}`);
}

function identifySinks(callGraph) {
  const sinks = [];
  for (const edge of callGraph.edges || []) {
    const sink = classifyCall(edge);
    if (sink) sinks.push(sink);
  }
  return sinks;
}

function classifyTerminal(terminal) {
  if (!terminal) return null;
  const edge = {
    file: terminal.file,
    line: terminal.line,
    callee: terminal.expr,
    arguments: (terminal.arguments || []).map(expr => ({ expr })),
  };
  return classifyCall(edge);
}

function classifyCall(edge) {
  const category = classifySink(edge.callee);
  if (!category) return null;

  return {
    file: edge.file,
    line: edge.line,
    function: edge.callee,
    category,
    arguments: (edge.arguments || []).map(arg => arg.expr),
  };
}

function classifySink(callee) {
  if (!callee) return null;

  for (const [category, patterns] of Object.entries(SINK_PATTERNS)) {
    if (patterns.some(pattern => matchesCallee(callee, pattern))) {
      return category;
    }
  }

  return null;
}

function matchesCallee(callee, pattern) {
  const value = String(callee);
  const lowerValue = value.toLowerCase();
  const lowerPattern = String(pattern).toLowerCase();

  // 점 표기 패턴(JSON.parse, yaml.load 등)은 정규화된 full-name 일치만 허용한다.
  // last-segment 단독 매칭을 허용하면 'JSON.parse'→'parse' 축약으로
  // url.parse/Date.parse가 CWE-502 후보로 오인되는 FP가 발생한다.
  if (lowerPattern.includes('.')) {
    return lowerValue === lowerPattern
      || lowerValue.endsWith(`.${lowerPattern}`);
  }

  // 단일 토큰 패턴(eval, query, exec 등)은 기존 동작 유지 — last-segment 일치 허용 (FN 방지)
  const simpleValue = lowerValue.split('.').pop();
  return lowerValue === lowerPattern
    || lowerValue.endsWith(`.${lowerPattern}`)
    || simpleValue === lowerPattern;
}

function findSanitizersForFlow(flow, callGraph) {
  const pathFiles = new Set([
    flow.entry?.file,
    flow.terminal?.file,
    ...((flow.via || []).map(parseViaFile).filter(Boolean)),
  ]);
  const minLineByFile = {};
  const maxLineByFile = {};

  addLineRange(minLineByFile, maxLineByFile, flow.entry?.file, flow.entry?.line);
  addLineRange(minLineByFile, maxLineByFile, flow.terminal?.file, flow.terminal?.line);
  for (const via of flow.via || []) {
    const parsed = parseViaStep(via);
    addLineRange(minLineByFile, maxLineByFile, parsed?.file, parsed?.line);
  }

  const sanitizers = [];
  for (const edge of callGraph.edges || []) {
    if (!pathFiles.has(edge.file)) continue;
    if (!isSanitizer(edge.callee)) continue;
    if (!lineIsInPathRange(edge, minLineByFile, maxLineByFile)) continue;

    sanitizers.push({
      function: edge.callee,
      file: edge.file,
      line: edge.line,
    });
  }

  return dedupeItems(sanitizers, item => `${item.file}:${item.line}:${item.function}`);
}

function addLineRange(minLineByFile, maxLineByFile, file, line) {
  if (!file || typeof line !== 'number') return;
  minLineByFile[file] = Math.min(minLineByFile[file] || line, line);
  maxLineByFile[file] = Math.max(maxLineByFile[file] || line, line);
}

function lineIsInPathRange(edge, minLineByFile, maxLineByFile) {
  const min = minLineByFile[edge.file];
  const max = maxLineByFile[edge.file];
  if (typeof min !== 'number' || typeof max !== 'number') return true;
  return edge.line >= Math.max(1, min - SANITIZER_CONTEXT_WINDOW_LINES)
    && edge.line <= max + SANITIZER_CONTEXT_WINDOW_LINES;
}

function identifyTaintedArguments(flow, taintedVars) {
  const terminalArgs = flow.terminal?.arguments || [];
  const direct = terminalArgs.filter(isSourceExpression);
  if (direct.length > 0) return direct;

  // 변수 경유 해석: sink 인자에 소스에서 파생된 변수(const t = req.query.x)가 있으면 taint.
  // taintedVars는 파일별 소스-파생 변수명 집합(단일 대입 fixpoint).
  const file = flow.terminal?.file;
  const fileVars = (taintedVars && file) ? taintedVars.get(file) : null;
  if (fileVars && fileVars.size > 0) {
    const viaVar = terminalArgs.filter((arg) => {
      const ids = String(arg).match(/[A-Za-z_$][\w$]*/g) || [];
      return ids.some((id) => fileVars.has(id));
    });
    if (viaVar.length > 0) return viaVar;
  }

  const via = (flow.via || []).join(' ');
  if (isSourceExpression(via)) {
    return terminalArgs;
  }

  return [];
}

// 소스에서 파생된 변수명을 파일별로 수집한다(단일 대입 근사 + fixpoint).
//   const t = req.query.url;   → t
//   const u = t;               → u (u가 t를 참조 → 전이)
// 함수 경계를 넘지 않는 파일-단위 근사이므로 동명 변수 재사용 시 과탐 가능(휴리스틱).
const EMPTY_SET = new Set();

function buildTaintedVars(callGraph) {
  const assignments = (callGraph && callGraph.assignments) || [];
  const edges = (callGraph && callGraph.edges) || [];
  const nodes = (callGraph && callGraph.nodes) || {};

  // 파일별 대입 목록.
  const assignsByFile = new Map();
  for (const a of assignments) {
    if (!a || !a.file || !a.name) continue;
    if (!assignsByFile.has(a.file)) assignsByFile.set(a.file, []);
    assignsByFile.get(a.file).push(a);
  }

  // 함수명 → [{file, params}] 색인 (파라미터 전파 대상 해석용).
  const byName = new Map();
  for (const node of Object.values(nodes)) {
    if (!node || !node.name) continue;
    if (!byName.has(node.name)) byName.set(node.name, []);
    byName.get(node.name).push({ file: node.file, params: node.params || [] });
  }

  const byFile = new Map();
  const getSet = (f) => {
    if (!byFile.has(f)) byFile.set(f, new Set());
    return byFile.get(f);
  };

  // 전역 fixpoint: (1) 대입 전파(파일 내), (2) 파라미터 전파(함수 간).
  // tainted 인자를 위치 i로 넘기면 callee 함수의 param[i]를 tainted로 표시한다.
  for (let iter = 0; iter < 8; iter++) {
    let changed = false;

    for (const [file, assigns] of assignsByFile) {
      const set = getSet(file);
      for (const a of assigns) {
        if (set.has(a.name)) continue;
        if (isSourceExpression(a.expr) || referencesTaintedVar(a.expr, set)) {
          set.add(a.name);
          changed = true;
        }
      }
    }

    for (const e of edges) {
      const args = e.arguments || [];
      if (args.length === 0) continue;
      const calleeName = String(e.callee || '').split('.').pop();
      const targets = byName.get(calleeName);
      if (!targets) continue;
      const callerSet = byFile.get(e.file) || EMPTY_SET;
      for (let i = 0; i < args.length; i++) {
        const expr = args[i] && (args[i].expr != null ? args[i].expr : args[i]);
        if (!expr) continue;
        if (!isSourceExpression(expr) && !referencesTaintedVar(expr, callerSet)) continue;
        for (const t of targets) {
          const p = t.params[i];
          if (p && /^[A-Za-z_$][\w$]*$/.test(p)) {
            const tset = getSet(t.file);
            if (!tset.has(p)) { tset.add(p); changed = true; }
          }
        }
      }
    }

    if (!changed) break;
  }

  return byFile;
}

function referencesTaintedVar(expr, taintedSet) {
  if (!expr || taintedSet.size === 0) return false;
  const ids = String(expr).match(/[A-Za-z_$][\w$]*/g) || [];
  return ids.some((id) => taintedSet.has(id));
}

function isSourceExpression(expr) {
  if (!expr) return false;
  return SOURCE_ARGUMENT_PATTERNS.some(pattern => pattern.test(String(expr)));
}

// 위험-인접(의미가 모호한) 패턴 — 접두 매칭 시 무관한 함수를 sanitizer로 오인하기 쉬워
// 정확일치만 허용한다 (예: 'numberOfItems'→'Number', 'validateNothing'→'validate' FP 차단).
const SANITIZER_EXACT_ONLY = new Set(['validate', 'number', 'boolean', 'clean']);

function isSanitizer(callee) {
  if (!callee) return false;
  const original = String(callee).split('.').pop();
  const name = original.toLowerCase();

  // 매칭 규칙 (FP 축소, 기존 의도 — 'unescape' FP 차단 — 유지):
  //   1) 정확일치(case-insensitive)는 항상 sanitizer.
  //   2) 위험-인접 패턴(SANITIZER_EXACT_ONLY)은 정확일치만 허용.
  //   3) 그 외 패턴은 접두 매칭을 허용하되 단어 경계 필요 — 접두 직후 문자가
  //      대문자(camelCase 경계)/숫자/'_'/'-' 여야 한다.
  //      예: 'sanitizeInput' ✓, 'escapeHtml' ✓, 'unescape' ✗(접두 아님), 'cleanup' ✗(경계 없음)
  return SANITIZER_PATTERNS.some(pattern => {
    const value = String(pattern).toLowerCase();
    if (name === value) return true;
    if (SANITIZER_EXACT_ONLY.has(value)) return false;
    if (!name.startsWith(value)) return false;
    const next = original.charAt(value.length);
    return next === '_' || next === '-'
      || (next >= 'A' && next <= 'Z')
      || (next >= '0' && next <= '9');
  });
}

function computeConfidence(source, sink, sanitizers, hops, hasTaintedArg = true) {
  let score = 0.85;

  score -= Math.min(hops, 5) * 0.08;

  if (sanitizers.length > 0) {
    score -= Math.min(sanitizers.length, 3) * 0.25;
  }

  if (source.type === 'user_input_argument') {
    score += 0.1;
  }

  if (['sql', 'command', 'eval', 'deserialize', 'ssrf', 'nosql'].includes(sink.category)) {
    score += 0.1;
  }

  // 사용자 입력이 sink 인자에 도달했다는 증거가 없으면(상수/내부값으로 채워진 sink 등)
  // 구조적 도달성만으로 high-confidence를 주지 않는다 — 드롭하지 않되 강하게 다운랭크.
  if (!hasTaintedArg) {
    score *= 0.45;
  }

  return Math.max(0, Math.min(1, Number(score.toFixed(2))));
}

function formatEntryExpression(entry) {
  if (!entry) return 'entry(unknown)';
  const method = entry.method || entry.type || 'entry';
  const route = entry.route ? ` ${entry.route}` : '';
  const handler = entry.handler ? ` -> ${entry.handler}` : '';
  return `${method}${route}${handler}`;
}

function parseViaFile(via) {
  return parseViaStep(via)?.file || null;
}

function parseViaStep(via) {
  if (!via) return null;
  const match = String(via).match(/^(.+):(\d+)\s+/);
  if (!match) return null;
  return { file: match[1], line: Number(match[2]) };
}

function dedupePaths(paths) {
  return dedupeItems(paths, path => [
    path.source.file,
    path.source.line,
    path.sink.file,
    path.sink.line,
    path.sink.function,
    path.via.join('>'),
  ].join(':'));
}

function dedupeItems(items, keyFn) {
  const seen = new Set();
  const out = [];

  for (const item of items) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }

  return out;
}

module.exports = {
  computeTaintPaths,
  identifySources,
  identifySinks,
  classifySink,
  isSanitizer,
  SOURCE_ARGUMENT_PATTERNS,
  SINK_PATTERNS,
  SANITIZER_PATTERNS,
  SINK_CWE_MAP,
};
