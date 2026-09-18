'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { initFanoutPlan, reserveAgents } = require('../../lib/ch015/agent-plan');

const ROOT = path.resolve(__dirname, '..', '..');
const HOOK = path.join(ROOT, 'hooks', 'on-stop.js');

test('on-stop: reports fanout integrity violation and writes marker', () => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-stop-target-'));
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'main.go'), 'package main\n');
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-stop-eng-'));
  initFanoutPlan({ target, engagementDir: engagement });
  fs.writeFileSync(path.join(engagement, '01_va_result-1st.md'), '# VA\n');

  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ engagement_dir: engagement }),
    env: { ...process.env, AGENT_ENGAGEMENT_DIR: engagement },
    encoding: 'utf8',
    timeout: 15000,
  });

  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Agent Fanout: INTEGRITY_VIOLATION/);
  assert.ok(fs.existsSync(path.join(engagement, 'INTEGRITY_VIOLATION.json')));

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});

test('on-stop: defers a matching artifact until the host commits its pending reservation', () => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-stop-target-'));
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'main.go'), 'package main\n');
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-stop-eng-'));
  initFanoutPlan({ target, engagementDir: engagement });
  reserveAgents(engagement, {
    phase: 'va',
    role: 'va-auditor',
    count: 1,
    expectedArtifacts: ['01_va_result-1st.md'],
  });
  fs.writeFileSync(path.join(engagement, '01_va_result-1st.md'), '# VA\n');

  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ engagement_dir: engagement }),
    env: { ...process.env, AGENT_ENGAGEMENT_DIR: engagement },
    encoding: 'utf8',
    timeout: 15000,
  });

  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Agent Fanout: PENDING_HOST_COMMIT/);
  assert.equal(fs.existsSync(path.join(engagement, 'INTEGRITY_VIOLATION.json')), false);

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});
