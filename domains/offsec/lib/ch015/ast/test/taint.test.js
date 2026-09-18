'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { parseFiles } = require('../parser');
const { extractCallGraph } = require('../call-graph');
const { computeTaintPaths, isSanitizer, classifySink, SINK_CWE_MAP } = require('../taint');

const FIXTURES = path.join(__dirname, 'fixtures', 'simple-express');

function getTaintPaths() {
  const files = [
    path.join(FIXTURES, 'index.js'),
    path.join(FIXTURES, 'db.js'),
    path.join(FIXTURES, 'auth.js'),
  ];
  const { parsed } = parseFiles(files);
  const callGraph = extractCallGraph(parsed, FIXTURES);
  return computeTaintPaths(callGraph);
}

describe('taint', () => {
  describe('computeTaintPaths', () => {
    it('finds taint paths in vulnerable code', () => {
      const paths = getTaintPaths();
      assert.ok(paths.length > 0, 'should find at least one taint path');
    });

    it('taint paths have required fields', () => {
      const paths = getTaintPaths();
      for (const tp of paths) {
        assert.ok(tp.source, 'should have source');
        assert.ok(tp.source.file, 'source should have file');
        assert.ok(tp.source.line, 'source should have line');
        assert.ok(tp.sink, 'should have sink');
        assert.ok(tp.sink.file, 'sink should have file');
        assert.ok(typeof tp.confidence === 'number', 'should have confidence');
        assert.ok(tp.confidence >= 0 && tp.confidence <= 1, 'confidence should be 0-1');
      }
    });

    it('detects SQL injection sinks', () => {
      const paths = getTaintPaths();
      const sqlPaths = paths.filter(p => p.sink.category === 'sql');
      assert.ok(sqlPaths.length > 0, 'should find SQL injection paths');
    });

    it('assigns CWE to taint paths', () => {
      const paths = getTaintPaths();
      const withCwe = paths.filter(p => p.potential_cwe);
      assert.ok(withCwe.length > 0, 'some paths should have CWE assigned');
    });

    it('paths are sorted by confidence descending', () => {
      const paths = getTaintPaths();
      if (paths.length > 1) {
        for (let i = 1; i < paths.length; i++) {
          assert.ok(paths[i].confidence <= paths[i - 1].confidence,
            'paths should be sorted by confidence descending');
        }
      }
    });
  });

  describe('classifySink', () => {
    it('matches dotted dangerous patterns by full name', () => {
      assert.equal(classifySink('JSON.parse'), 'deserialize');
      assert.equal(classifySink('obj.JSON.parse'), 'deserialize');
      assert.equal(classifySink('yaml.load'), 'deserialize');
      assert.equal(classifySink('pickle.loads'), 'deserialize');
    });

    it('does not reduce dotted patterns to last segment (url.parse/Date.parse FP)', () => {
      // 'JSON.parse'가 'parse'로 축약되어 url.parse/Date.parse가 CWE-502 후보가 되면 안 된다
      assert.equal(classifySink('url.parse'), null);
      assert.equal(classifySink('Date.parse'), null);
      assert.equal(classifySink('querystring.parse'), null);
      // 'yaml.load' 축약('load')로 무관한 load 호출이 매칭되면 안 된다
      assert.equal(classifySink('config.load'), null);
      assert.equal(classifySink('loader.load'), null);
    });

    it('keeps last-segment matching for single-token patterns (no FN regression)', () => {
      assert.equal(classifySink('eval'), 'eval');
      assert.equal(classifySink('db.query'), 'sql');
      assert.equal(classifySink('connection.query'), 'sql');
      assert.equal(classifySink('child_process.exec'), 'command');
      assert.equal(classifySink('res.redirect'), 'redirect');
    });
  });

  describe('isSanitizer', () => {
    it('recognizes known sanitizers', () => {
      assert.ok(isSanitizer('escape'));
      assert.ok(isSanitizer('sanitizeInput'));
      assert.ok(isSanitizer('validator.validate'));
      assert.ok(isSanitizer('DOMPurify.sanitize'));
      assert.ok(isSanitizer('parseInt'));
    });

    it('does not flag non-sanitizers', () => {
      assert.ok(!isSanitizer('getUser'));
      assert.ok(!isSanitizer('query'));
      assert.ok(!isSanitizer('send'));
    });

    it('does not flag intent-reversing substring names', () => {
      // 'unescape'/'deEscape'는 'escape'를 substring으로 포함하지만 sanitizer가 아니다
      assert.ok(!isSanitizer('unescape'));
      assert.ok(!isSanitizer('deEscape'));
    });

    it('requires word boundary for prefix matches', () => {
      // 접두 뒤에 camelCase 경계가 없으면 매칭하지 않는다 ('escaped', 'cleanup' 등)
      assert.ok(!isSanitizer('escaped'));
      assert.ok(!isSanitizer('cleanup'));
      // 경계가 있으면 매칭 ('escapeHtml', 'sanitize_input')
      assert.ok(isSanitizer('escapeHtml'));
      assert.ok(isSanitizer('sanitize_input'));
    });

    it('risk-adjacent ambiguous patterns require exact match', () => {
      // 'numberOfItems'→'Number', 'validateNothing'→'validate' 과잉 매칭 차단
      assert.ok(!isSanitizer('numberOfItems'));
      assert.ok(!isSanitizer('validateNothing'));
      // 정확일치는 유지
      assert.ok(isSanitizer('Number'));
      assert.ok(isSanitizer('validate'));
      assert.ok(isSanitizer('validator.validate'));
    });

    it('handles null/undefined', () => {
      assert.ok(!isSanitizer(null));
      assert.ok(!isSanitizer(undefined));
    });
  });

  describe('SINK_CWE_MAP', () => {
    it('maps all sink categories', () => {
      assert.equal(SINK_CWE_MAP.sql, 'CWE-89');
      assert.equal(SINK_CWE_MAP.command, 'CWE-78');
      assert.equal(SINK_CWE_MAP.file, 'CWE-22');
      assert.equal(SINK_CWE_MAP.response, 'CWE-79');
      assert.equal(SINK_CWE_MAP.eval, 'CWE-94');
      assert.equal(SINK_CWE_MAP.ssrf, 'CWE-918');
      assert.equal(SINK_CWE_MAP.nosql, 'CWE-943');
    });
  });

  // Detection-rate boost: SSRF/NoSQL sink coverage + precision guards.
  describe('extended sink coverage', () => {
    const BOOST = path.join(__dirname, 'fixtures', 'detection-boost');

    function taintOf(file) {
      const { parsed } = parseFiles([path.join(BOOST, file)]);
      return computeTaintPaths(extractCallGraph(parsed, BOOST));
    }

    it('classifies SSRF HTTP-client sinks (CWE-918)', () => {
      assert.equal(classifySink('axios.get'), 'ssrf');
      assert.equal(classifySink('http.request'), 'ssrf');
      assert.equal(classifySink('fetch'), 'ssrf');
      assert.equal(classifySink('requests.get'), 'ssrf');
    });

    it('classifies NoSQL selectors (CWE-943)', () => {
      assert.equal(classifySink('findOne'), 'nosql');
      assert.equal(classifySink('users.findOneAndUpdate'), 'nosql');
      assert.equal(classifySink('aggregate'), 'nosql');
    });

    it('classifies Python subprocess command sinks (CWE-78)', () => {
      assert.equal(classifySink('subprocess.check_output'), 'command');
      assert.equal(classifySink('Popen'), 'command');
    });

    it('does NOT misclassify benign lookups (precision guard)', () => {
      assert.equal(classifySink('Map.get'), null);   // not SSRF
      assert.equal(classifySink('redis.get'), null);  // not SSRF
      assert.equal(classifySink('arr.find'), null);    // 'find' excluded from nosql
      assert.equal(classifySink('url.parse'), null);   // not deserialize (JSON.parse only)
    });

    it('detects SSRF taint paths in the fixture', () => {
      const ssrf = taintOf('ssrf.js').filter(p => p.sink.category === 'ssrf');
      assert.ok(ssrf.length >= 1, 'should detect at least one SSRF sink');
      assert.ok(ssrf.every(p => p.potential_cwe === 'CWE-918'));
    });

    it('detects NoSQL taint path in the fixture', () => {
      const nosql = taintOf('nosql.js').filter(p => p.sink.category === 'nosql');
      assert.ok(nosql.length >= 1, 'should detect NoSQL selector sink');
      assert.equal(nosql[0].potential_cwe, 'CWE-943');
    });

    it('connects source→sink through variable assignment (#14)', () => {
      // ssrf.js: const target = req.query.url; axios.get(target) — 변수 경유.
      const connected = taintOf('ssrf.js').filter(p => p.sink.category === 'ssrf' && p.source_reaches_sink);
      assert.ok(connected.length >= 1, 'variable-indirected source should reach SSRF sink');
    });

    it('connects destructured source→sink (const {file}=req.query)', () => {
      const connected = taintOf('destructure.js').filter(p => p.sink.category === 'file' && p.source_reaches_sink);
      assert.ok(connected.length >= 1, 'destructured source binding should reach file sink');
    });

    it('propagates taint across function calls to a parameter (interprocedural)', () => {
      // serveFile(req.params.file) → function serveFile(f){ fs.readFile(f) }
      const connected = taintOf('interproc.js').filter(p => p.sink.category === 'file' && p.source_reaches_sink);
      assert.ok(connected.length >= 1, 'tainted argument should reach callee parameter sink');
    });
  });
});
