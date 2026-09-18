'use strict';

// 단일 소스화 검증 — objection_weights(P1-10) / scoring weights(P1-11)가
// config(ch015.config.json)를 읽고 하드코딩은 fallback으로만 쓰이는지 확인한다.
//
// 주의: CLAUDE_PLUGIN_ROOT는 lib/core/platform.js가 require 시점에 읽으므로
// 어떤 lib 모듈도 require하기 *전에* fixture plugin root를 가리켜야 한다.
// node --test는 테스트 파일별 프로세스를 띄우므로 다른 테스트와 간섭하지 않는다.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const FIXTURE_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-config-override-'));
process.on('exit', () => {
  try { fs.rmSync(FIXTURE_ROOT, { recursive: true, force: true }); } catch {}
});

fs.writeFileSync(path.join(FIXTURE_ROOT, 'ch015.config.json'), JSON.stringify({
  feedbackLoop: {
    objection_weights: {
      false_positive: 7,          // 기본 3 → 7로 override
      brand_new_type: 4,          // fallback에 없는 신규 타입도 config로 추가 가능
      severity_dispute: 'bogus',  // 숫자가 아니면 fallback(2) 유지 (fail-soft)
      missing_finding: -1         // 음수면 fallback(1) 유지 (fail-soft)
    }
  },
  scoring: {
    securityScore: {
      weights: {
        critical: 40,             // 기본 25 → 40로 override
        high: 'not-a-number',     // fallback(10) 유지
        unknown_bucket: 9         // 알 수 없는 severity 키는 무시
      }
    }
  }
}, null, 2));

process.env.CLAUDE_PLUGIN_ROOT = FIXTURE_ROOT;

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { calculateObjectionWeight, getObjectionWeights, OBJECTION_WEIGHTS } = require('../feedback');
const { getSeverityWeights, getSeverityWeight, calculateSecurityScore, SEVERITY_WEIGHTS } = require('../scoring');

// --- feedbackLoop.objection_weights override (P1-10) ---

test('objection weights: config override takes precedence over hardcoded fallback', () => {
  const weights = getObjectionWeights();
  assert.equal(weights.false_positive, 7);
  assert.equal(OBJECTION_WEIGHTS.false_positive, 3); // fallback 상수는 불변

  const result = calculateObjectionWeight([{ type: 'false_positive' }]);
  assert.equal(result.totalWeight, 7);
});

test('objection weights: config can introduce new types beyond the fallback set', () => {
  const result = calculateObjectionWeight([{ type: 'brand_new_type' }]);
  assert.equal(result.totalWeight, 4);
});

test('objection weights: invalid config values fall back per-key (fail-soft)', () => {
  const weights = getObjectionWeights();
  assert.equal(weights.severity_dispute, 2); // 'bogus' → fallback
  assert.equal(weights.missing_finding, 1);  // -1 → fallback
  // override되지 않은 키는 fallback 그대로
  assert.equal(weights.evidence_gap, 2);
});

// --- scoring.securityScore.weights override (P1-11) ---

test('severity weights: config override takes precedence over hardcoded fallback', () => {
  const weights = getSeverityWeights();
  assert.equal(weights.CRITICAL, 40);
  assert.equal(SEVERITY_WEIGHTS.CRITICAL, 25); // fallback 상수는 불변
  assert.equal(getSeverityWeight('CRITICAL'), 40);
});

test('severity weights: invalid/unknown config entries fall back per-key (fail-soft)', () => {
  const weights = getSeverityWeights();
  assert.equal(weights.HIGH, 10);   // 'not-a-number' → fallback
  assert.equal(weights.MEDIUM, 3);  // 미지정 → fallback
  assert.equal(weights.LOW, 1);
  assert.equal(weights.unknown_bucket, undefined); // 알 수 없는 키는 유입되지 않음
});

test('calculateSecurityScore: uses config-overridden weights', () => {
  // critical=40(override), high=10(fallback): 100 - (1*40 + 1*10) = 50
  assert.equal(calculateSecurityScore({ critical: 1, high: 1, medium: 0, low: 0 }), 50);
});
