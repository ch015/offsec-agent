const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { app, BrowserWindow, webContents } = require('electron');
const { web: repo } = require('./paths.cjs').repos;
const runtime = path.join(__dirname, '.runtime');
fs.mkdirSync(runtime, { recursive: true });
const data = fs.mkdtempSync(path.join(runtime, 'web-session-'));
process.env.ISEKAI_DATA_DIR = data;
for (const name of ['ISEKAI_AI_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'ISEKAI_AI_PROVIDER', 'ISEKAI_AI_MODEL']) delete process.env[name];
app.setPath('userData', path.join(data, 'electron'));
const base = process.env.DEMO_TARGET_URL || 'http://127.0.0.1:8766';
let main, guest;
app.on('browser-window-created', (_event, window) => { if (!main) main = window; });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const js = code => main.webContents.executeJavaScript(code);
const rpc = (method, params = {}) => js(`window.isekaiBackend.invoke(${JSON.stringify(method)},${JSON.stringify(params)})`);
async function until(fn, name) { const end = Date.now() + 15000; while (Date.now() < end) { if (await fn()) return; await pause(75); } throw Error('Timed out: ' + name); }
async function input(selector, value) { await js(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)throw Error('Missing input');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}));})()`); await pause(100); }
async function click(text) { await js(`(()=>{const b=[...document.querySelectorAll('button')].find(e=>e.offsetParent!==null&&e.textContent.trim()===${JSON.stringify(text)});if(!b)throw Error('Missing button');b.click();})()`); await pause(150); }
const deadline = setTimeout(() => { console.error('Web demo preparation deadline'); app.exit(2); }, 60000);
app.whenReady().then(async () => {
  require(path.join(repo, 'electron-dist/main.js'));
  await until(() => main && !main.webContents.isLoading(), 'window');
  await until(() => js(`!!document.querySelector('[aria-label="Target URL"]')`), 'renderer');
  await until(() => { guest = webContents.getAllWebContents().find(c => c.getType() === 'webview'); return guest; }, 'target browser');
  await click('Projects');
  await input('[aria-label="Project name"]', '송장 소유권 진단 · 로컬 시연');
  await input('[aria-label="Project target URL"]', base + '/');
  await click('Create project');
  await until(async () => (await rpc('get_projects')).length > 0, 'project creation');
  if (await js(`!!document.querySelector('[role="dialog"]')`)) await click('Close');
  await until(() => guest.getURL() === base + '/' && !guest.isLoadingMainFrame(), 'sample service');
  const responses = [];
  for (const route of ['/api/invoices/INV-A', '/api/invoices/INV-B', '/fixed/invoices/INV-B']) {
    await guest.executeJavaScript(`document.querySelector('[data-route="${route}"]').click();true`);
    await until(() => guest.executeJavaScript(`document.querySelector('#status').textContent.includes(${JSON.stringify(route + ' → HTTP')})`), route);
    responses.push(await guest.executeJavaScript(`({status:document.querySelector('#status').textContent,body:document.querySelector('#result').textContent})`));
  }
  assert(responses[0].status.endsWith('200')); assert(responses[1].status.endsWith('200')); assert(responses[2].status.endsWith('403'));
  await click('Blue Team'); await click('Hdrs');
  await until(() => js(`document.body.innerText.includes('Missing')`), 'real header analysis');
  await js(`window.dispatchEvent(new KeyboardEvent('keydown',{key:'s',metaKey:true}));true`);
  await pause(300);
  const projects = await rpc('get_projects');
  const saved = await rpc('load_project_state', { projectId: projects[0].id });
  assert(saved);
  const screenshot = path.join(runtime, 'web-demo.png');
  fs.writeFileSync(screenshot, (await main.webContents.capturePage()).toPNG());
  fs.writeFileSync(path.join(runtime, 'web-demo-proof.json'), JSON.stringify({ passed: true, at: new Date().toISOString(),
    checks: ['production Electron UI and Rust backend', 'isolated project and profile', 'sample navigation', 'three authenticated browser requests', '200/200/403 comparison', 'real security header scan', 'project saved'],
    responses, screenshot, profile: data }, null, 2));
  clearTimeout(deadline); main.show(); main.focus();
  console.log('Web Pentester demo ready');
  if (process.argv.includes('--check')) app.quit();
}).catch(error => { console.error(error.stack); clearTimeout(deadline); app.exit(1); });
