import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import locations from './paths.cjs';
const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(locations.repos.offsec, 'package.json'));
const { chromium } = require('playwright-core');
const base = `http://127.0.0.1:${process.env.DEMO_PORT || 8765}`;
const out = path.join(here, '.runtime/screenshots'); fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const checks = [], errors = [];
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1060 }, deviceScaleFactor: 1 });
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(base); await page.waitForSelector('[data-project="web"]');
  assert.equal(await page.locator('[data-project]').count(), 4); checks.push('four project views');
  const state = await (await page.request.get(base + '/state')).json();
  for (const key of ['code', 'web', 'soc', 'offsec']) {
    assert.equal(state.recordings[key]?.status, 'completed');
    assert.equal(state.recordings[key]?.source, 'recording');
  }
  checks.push('four actual successful recordings, explicitly labeled');
  await page.screenshot({ path: path.join(out, 'overview.png'), fullPage: true });
  assert.equal(await page.locator('#result tbody tr').count(), 3);
  assert.deepEqual(state.recordings.web.requests.map(r => r.status), [200, 200, 403]);
  checks.push('recorded HTTP comparison');
  for (const kind of ['code', 'offsec', 'soc']) {
    await page.click(`[data-project="${kind}"]`);
    await page.screenshot({ path: path.join(out, kind + '.png'), fullPage: true });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  }
  assert.equal(state.recordings.offsec.publicationStatus, 'published');
  assert(/[가-힣]/.test(state.recordings.soc.assessment.summary));
  assert.deepEqual(state.recordings.soc.assessment.mitreTactics, []);
  checks.push('published OffSec report and Korean evidence-bound SOC result');
  await page.getByText('도구 호출과 실제 반환 근거', { exact: true }).click();
  await page.waitForTimeout(2800);
  assert(await page.locator('#result details').getAttribute('open') !== null); checks.push('expanded evidence survives refresh');
  await page.click('#live-mode');
  assert(await page.locator('#run-button').isVisible());
  await page.click('#recording-mode');
  assert(!await page.locator('#run-button').isVisible()); checks.push('recording/live mode separation');
  const denied = await page.request.post(base + '/run/web', { headers: { Origin: 'https://outside.invalid' } });
  assert.equal(denied.status(), 403); checks.push('cross-origin control request denied');
  await page.goto(base + '/guide');
  assert((await page.locator('body').innerText()).includes('bash demo.sh serve --open'));
  await page.screenshot({ path: path.join(out, 'guide.png'), fullPage: true }); checks.push('presenter guide');
  await page.goto(state.targetUrl);
  for (const [route, status] of [['/api/invoices/INV-A', 200], ['/api/invoices/INV-B', 200], ['/fixed/invoices/INV-B', 403]]) {
    await page.click(`[data-route="${route}"]`);
    await page.waitForFunction(({route,status}) => document.querySelector('#status').textContent === route + ' → HTTP ' + status, { route, status });
  }
  checks.push('sample service buttons execute real authenticated requests');
  assert.deepEqual(errors, []); checks.push('no browser runtime errors');
  fs.writeFileSync(path.join(here, '.runtime/ui-verification.json'), JSON.stringify({ passed: true, at: new Date().toISOString(), checks, screenshots: out }, null, 2));
  console.log(JSON.stringify({ passed: true, checks, screenshots: out }));
} finally { await browser.close(); }
