// Real-browser end-to-end test. Runs the actual extension and the actual phone
// page in Chrome for Testing, against the local relay as Claude Code starts it,
// a local ntfy stand-in and a test login site:
//   Claude (MCP) -> relay -> extension finds the tab -> ntfy -> phone page
//   -> you type the password -> ntfy -> extension decrypts, fills, submits -> status.
// Run with: npm run test:browser (from the repo root).
import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, readFileSync, existsSync } from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import puppeteer from 'puppeteer';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { startFakeNtfy } from '../fake-ntfy.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..', '..');
const EXT_DIR = path.join(root, 'extension');
const RELAY_PORT = 19000 + Math.floor(Math.random() * 1000);
const SECRET = { password: 'hunter2-correct-horse', otp: '492817' };
const assert = (c, m) => { if (!c) { console.error('FAIL:', m); process.exitCode = 1; throw new Error(m); } console.log('ok -', m); };
const cleanups = [];

// ---------- TLS for the test sites (Chrome runs with --ignore-certificate-errors) ----------
const certDir = path.join(here, '.cache', 'tls');
mkdirSync(certDir, { recursive: true });
if (!existsSync(path.join(certDir, 'cert.pem'))) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=relay.test',
    '-keyout', path.join(certDir, 'key.pem'), '-out', path.join(certDir, 'cert.pem')], { stdio: 'ignore' });
}
const tls = { key: readFileSync(path.join(certDir, 'key.pem')), cert: readFileSync(path.join(certDir, 'cert.pem')) };

// ---------- test login site + the phone page, on one https server ----------
const recorded = [];
const phoneServing = { tamper: false }; // true: serve a modified phone page, as if its host were compromised
const LOGIN_PAGE = `<!doctype html><title>Test Login</title>
<form id="pw"><input name="email" value="me@example.com"><input type="password" name="password"><button>Sign in</button></form>
<script>
  // Behaves like a React-controlled form: state follows input events.
  let state = '';
  const pwInput = document.querySelector('[name=password]');
  pwInput.addEventListener('input', (e) => { state = e.target.value; });
  document.getElementById('pw').addEventListener('submit', async (e) => {
    e.preventDefault();
    await fetch('/record', { method: 'POST', body: JSON.stringify({ password: state }) });
    document.body.insertAdjacentHTML('beforeend',
      '<form id="otp">' + Array.from({ length: 6 }, (_, i) => '<input inputmode="numeric" maxlength="1" data-i="' + i + '">').join('') + '<button>Verify</button></form>');
    document.getElementById('otp').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const code = [...document.querySelectorAll('#otp input')].map((i) => i.value).join('');
      await fetch('/record', { method: 'POST', body: JSON.stringify({ otp: code }) });
      document.title = 'Signed in';
    });
  });
</script>`;
// A plain HTML form, and a script that checks the password field on every task
// it can get. If the fill and the clear happen in one step, it never sees the value.
const CLASSIC_PAGE = `<!doctype html><title>Classic Login</title>
<form method="post" action="/classic-done"><input name="email" value="me@example.com"><input type="password" name="password"><button>Sign in</button></form>
<script>
  sessionStorage.removeItem('saw');
  const pw = document.querySelector('[name=password]');
  const ch = new MessageChannel();
  ch.port1.onmessage = () => { if (pw.value) sessionStorage.setItem('saw', '1'); ch.port2.postMessage(0); };
  ch.port2.postMessage(0);
</script>`;
// A site whose script runs a bot check before it reads the password field and
// posts the form, as reCAPTCHA-style logins do.
const SLOW_PAGE = `<!doctype html><title>Slow Login</title>
<form method="post" action="/slow-done"><input name="email" value="me@example.com"><input type="password" name="password"><button>Sign in</button></form>
<script>
  const form = document.querySelector('form');
  form.addEventListener('submit', (e) => { e.preventDefault(); setTimeout(() => form.submit(), 3000); });
</script>`;
const site = https.createServer(tls, (req, res) => {
  const url = new URL(req.url, 'https://x');
  if (req.method === 'POST' && url.pathname === '/record') {
    let b = '';
    req.on('data', (c) => (b += c));
    return req.on('end', () => { recorded.push(JSON.parse(b)); res.end('{}'); });
  }
  if (req.method === 'POST' && url.pathname === '/classic-done') {
    let b = '';
    req.on('data', (c) => (b += c));
    return req.on('end', () => {
      recorded.push({ classic: new URLSearchParams(b).get('password') });
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><title>Signed in</title>');
    });
  }
  if (req.method === 'POST' && url.pathname === '/slow-done') {
    let b = '';
    req.on('data', (c) => (b += c));
    return req.on('end', () => {
      recorded.push({ slow: new URLSearchParams(b).get('password') });
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><title>Signed in</title>');
    });
  }
  if (url.pathname === '/slow') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(SLOW_PAGE); }
  if (url.pathname === '/classic') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(CLASSIC_PAGE); }
  if (url.pathname.startsWith('/phone/')) {
    const file = path.join(root, 'phone', url.pathname.slice('/phone/'.length) || 'index.html');
    if (!file.startsWith(path.join(root, 'phone')) || !existsSync(file)) { res.writeHead(404); return res.end(); }
    const type = { '.html': 'text/html', '.js': 'text/javascript', '.webmanifest': 'application/manifest+json' }[path.extname(file)];
    // GitHub Pages sends this too; the extension fetches the files to check them.
    res.writeHead(200, { 'content-type': type, 'access-control-allow-origin': '*' });
    const body = readFileSync(file);
    return res.end(phoneServing.tamper && file.endsWith('app.js') ? Buffer.concat([body, Buffer.from('\n// changed\n')]) : body);
  }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(LOGIN_PAGE);
});
await new Promise((r) => site.listen(0, '127.0.0.1', r));
cleanups.push(() => site.close());
const SITE_PORT = site.address().port;
// Pages other than the front tab get no animation frames in headless Chrome, so every wait polls on an interval.
const LOGIN_URL = `https://login.relay.test:${SITE_PORT}/signin`;
const CLASSIC_URL = `https://login.relay.test:${SITE_PORT}/classic`;
const SLOW_URL = `https://login.relay.test:${SITE_PORT}/slow`;
const APPROVE_URL = `https://phone.approve.test:${SITE_PORT}/phone/`;

const ntfy = await startFakeNtfy({ tls, host: 'ntfy.relay.test' });
cleanups.push(ntfy.close);

// ---------- Claude Code's side: the plugin's MCP server over stdio ----------
const transport = new StdioClientTransport({
  command: 'node', args: [path.join(root, 'server', 'local.js')],
  env: { ...process.env, REMOTE_AUTH_KIT_PORT: String(RELAY_PORT), GUARD_AFTER_FILL_SECONDS: '1' }, stderr: 'inherit',
});
const claude = new Client({ name: 'browser-test', version: '0' });
await claude.connect(transport);
cleanups.push(() => claude.close());
let sw = null;
// Each step here is a separate login, so the rate limit is reset unless a step tests it.
const requestLogin = async (args, { keepRateLimit = false } = {}) => {
  if (sw && !keepRateLimit) await sw.evaluate(() => chrome.storage.local.remove('sentLog'));
  const r = await claude.callTool({ name: 'request_login', arguments: args }, undefined, { timeout: 150_000 });
  return { text: r.content[0].text, ...JSON.parse(r.content[0].text) };
};

// The plugin's hook, as Claude Code would run it before a Claude in Chrome tool call.
const hook = (tool, toolInput, event = 'PreToolUse') => new Promise((resolve) => {
  const p = spawn('node', [path.join(root, 'hooks', 'guard.js')], { env: { ...process.env, REMOTE_AUTH_KIT_PORT: String(RELAY_PORT) } });
  let out = '';
  p.stdout.on('data', (d) => (out += d));
  p.on('close', () => resolve(out ? JSON.parse(out).hookSpecificOutput?.permissionDecision : 'allow'));
  p.stdin.end(JSON.stringify({ hook_event_name: event, tool_name: `mcp__claude-in-chrome__${tool}`, tool_input: toolInput }));
});
const jsTool = (tabId) => hook('javascript_tool', { action: 'javascript_exec', tabId, text: '1' });

// ---------- Chrome with the real extension ----------
const browser = await puppeteer.launch({
  headless: process.env.HEADFUL ? false : true,
  pipe: true,
  enableExtensions: [EXT_DIR],
  args: [
    '--ignore-certificate-errors', '--host-resolver-rules=MAP *.test 127.0.0.1',
    ...(process.env.CI ? ['--no-sandbox'] : []), // Ubuntu CI runners block Chrome's sandbox
  ],
});
cleanups.push(() => browser.close());

try {
  const swTarget = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().endsWith('/background.js'));
  const extId = new URL(swTarget.url()).host;
  sw = await swTarget.worker();
  if (process.env.DEBUG) sw.on('console', (m) => console.log(new Date().toISOString().slice(17, 23), '[extension]', m.text()));
  await sw.evaluate((cfg) => chrome.storage.local.set(cfg), {
    relayUrl: `ws://127.0.0.1:${RELAY_PORT}`, allowedDomains: 'login.relay.test', ntfyServer: ntfy.url, approveUrl: APPROVE_URL,
  });

  // Options page: the user's view of the extension.
  const options = await browser.newPage();
  await options.goto(`chrome-extension://${extId}/options.html`);
  await options.click('#save');
  await options.waitForFunction(() => document.getElementById('status').textContent === 'connected', { timeout: 15000, polling: 100 });
  assert(true, 'extension connected to the relay started by Claude Code');
  assert(await options.$eval('#saveMsg', (e) => e.textContent) === 'Saved ✓', 'options page confirms the save');
  await options.$eval('#approveUrl', (e) => { e.value = 'http://plain.test/'; });
  await options.click('#save');
  assert(/^Not saved/.test(await options.$eval('#saveMsg', (e) => e.textContent)), 'options page says when a save is refused');
  await options.$eval('#approveUrl', (e, v) => { e.value = v; }, APPROVE_URL);
  await options.click('#save');
  await sleep(300); // the save reconnects the extension
  await options.waitForFunction(() => document.getElementById('status').textContent === 'connected', { timeout: 15000, polling: 100 });

  const unpaired = await requestLogin({ domain: 'relay.test', fields: ['password'] });
  assert(unpaired.status === 'failed' && /no phone is paired/.test(unpaired.detail), `refuses requests until a phone is paired (${JSON.stringify(unpaired)})`);

  await options.click('#showPair');
  await options.waitForFunction(() => document.getElementById('qr').src.startsWith('data:image/gif'), { polling: 100 });
  assert(true, 'options page shows a pairing QR code');
  const link = await options.evaluate(async (approveUrl) => {
    const { pairingLink } = await import('./lib/relay-crypto.js');
    return pairingLink(approveUrl, await chrome.runtime.sendMessage({ type: 'pairing' }));
  }, APPROVE_URL);

  // Phone: open the pairing link (as scanning the QR would).
  const phone = await browser.newPage();
  if (process.env.DEBUG) { phone.on('console', (m) => console.log('[phone]', m.text())); phone.on('pageerror', (e) => console.log('[phone error]', e.message)); phone.on('requestfailed', (r) => console.log('[phone reqfail]', r.url(), r.failure()?.errorText)); }
  await phone.goto(link);
  await phone.waitForFunction(() => document.body.innerText.includes('Paired ✓'), { polling: 100 });
  assert(!phone.url().includes('pair='), 'phone page removes the key from the address bar');
  await options.waitForFunction(() => document.getElementById('phoneState').textContent === 'Paired ✓', { timeout: 15000, polling: 100 });
  assert(true, 'extension learned the phone is paired');

  // A notification can open the page in another browser (or an app's built-in
  // one) with storage of its own: pasting the saved link pairs it there too.
  const other = await browser.createBrowserContext();
  const otherPhone = await other.newPage();
  await otherPhone.goto(APPROVE_URL);
  await otherPhone.waitForFunction(() => document.body.innerText.includes('This browser is not paired'), { polling: 100 });
  await otherPhone.type('input', 'not a link');
  await otherPhone.click('button.pair');
  assert(await otherPhone.evaluate(() => document.body.innerText.includes('That is not a pairing link')), 'pasting something else is refused');
  await otherPhone.type('input', link);
  await otherPhone.click('button.pair');
  await otherPhone.waitForFunction(() => document.body.innerText.includes('Paired ✓'), { polling: 100 });
  assert(await otherPhone.evaluate(() => !!localStorage.getItem('loginRelayPairing') && !document.querySelector('input')?.value), 'pasting the saved link pairs a browser that opened the page unpaired');
  await other.close();

  // The login tab Claude would have opened in Chrome.
  const tab = await browser.newPage();
  await tab.goto(LOGIN_URL);

  async function approveOnPhone(fieldLabel, value) {
    await phone.bringToFront(); // you're looking at your phone now
    await phone.waitForFunction((label) => [...document.querySelectorAll('label')].some((l) => l.textContent === label && !l.nextElementSibling.disabled), { timeout: 20000, polling: 100 }, fieldLabel);
    const card = await phone.evaluateHandle(() => document.querySelector('.card:has(input:not([disabled]))'));
    const cardText = await card.evaluate((c) => c.innerText);
    const input = await card.$('input:not([disabled])');
    await input.type(value);
    const send = await card.$('button.primary');
    await send.click();
    return cardText;
  }

  // ---- password ----
  const pwCall = requestLogin({ domain: 'relay.test', fields: ['password'], note: 'browser test' });
  const cardText = await approveOnPhone('Password', SECRET.password);
  assert(cardText.includes('relay.test') && cardText.includes('login.relay.test') && cardText.includes('browser test'), 'phone card shows the domain, the real tab and the note');
  const pw = await pwCall;
  assert(pw.status === 'filled', `request_login returned filled (${pw.detail})`);
  assert(!pw.text.includes(SECRET.password), 'tool result contains no password');
  assert(recorded.some((r) => r.password === SECRET.password), 'site received the password through its own submit handler');
  // This page stays put after the submit (it asks for a code next), so the
  // password is wiped once the extension's 30-second limit runs out.
  await tab.waitForFunction(() => document.querySelector('[name=password]').value === '', { timeout: 35000, polling: 200 });
  assert(true, 'password is gone from the page DOM when the page stays put');
  await phone.waitForFunction(() => document.body.innerText.includes('Filled ✓'), { polling: 100 });
  assert(true, 'phone shows the fill result');

  // ---- split one-box-per-digit OTP ----
  const otpCall = requestLogin({ domain: 'relay.test', fields: ['otp'] });
  await approveOnPhone('Verification code', SECRET.otp);
  const otp = await otpCall;
  assert(otp.status === 'filled' && !otp.text.includes(SECRET.otp), 'OTP filled, no code in the tool result');
  assert(recorded.some((r) => r.otp === SECRET.otp), 'site received the 6-digit code across split inputs');
  await tab.waitForFunction(() => document.title === 'Signed in', { polling: 100 });

  // ---- deny ----
  await tab.goto(LOGIN_URL);
  const denyCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await phone.bringToFront();
  await phone.waitForFunction(() => document.querySelector('.card button.secondary:not([disabled])'), { timeout: 20000, polling: 100 });
  await phone.click('.card button.secondary:not([disabled])');
  assert((await denyCall).status === 'denied', 'deny on the phone returns denied');

  // ---- tab navigates away before the user answers: nothing is filled ----
  const awayCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await phone.bringToFront();
  await phone.waitForFunction(() => [...document.querySelectorAll('.card input')].some((i) => !i.disabled), { timeout: 20000, polling: 100 });
  await tab.goto(`https://other.test:${SITE_PORT}/signin`);
  const before = recorded.length;
  await approveOnPhone('Password', SECRET.password);
  const away = await awayCall;
  assert(away.status === 'failed' && /navigated away/.test(away.detail) && recorded.length === before, 'refuses to fill once the tab left the approved domain');

  // ---- domain outside the allowlist ----
  const blocked = await requestLogin({ domain: 'other.test', fields: ['password'] });
  assert(blocked.status === 'failed' && /allowed sites/.test(blocked.detail), 'refuses domains outside the allowlist');

  // ---- no matching field open ----
  const none = await requestLogin({ domain: 'relay.test', fields: ['password'] });
  assert(none.status === 'failed' && /no open tab/.test(none.detail), 'reports when no tab shows the field');

  const tabIdOf = (url) => sw.evaluate(async (u) => (await chrome.tabs.query({})).find((t) => t.url.startsWith(u))?.id, url);
  async function denyOnPhone() {
    await phone.bringToFront();
    await phone.waitForFunction(() => document.querySelector('.card button.secondary:not([disabled])'), { timeout: 20000, polling: 100 });
    await phone.click('.card button.secondary:not([disabled])');
  }

  // ---- exact hostnames: a subdomain that isn't listed is refused ----
  await tab.goto(`https://shared.relay.test:${SITE_PORT}/signin`);
  const shared = await requestLogin({ domain: 'relay.test', fields: ['password'] });
  assert(shared.status === 'failed' && /shared\.relay\.test, which isn't in/.test(shared.detail), 'refuses a subdomain that is not listed exactly, and says which host to add');

  // ---- a page script ran after the login page loaded ----
  await tab.goto(LOGIN_URL);
  const loginTab = await tabIdOf(LOGIN_URL);
  assert((await jsTool(loginTab)) === 'allow', 'hook allows a page script while no login is open');
  await tab.evaluate(() => { window.watcher = setInterval(() => {}, 100); }); // what that script could leave behind
  const watched = await requestLogin({ domain: 'relay.test', fields: ['password'] });
  assert(watched.status === 'failed' && /ran a script/.test(watched.detail), 'refuses to fill a page a script ran in after it loaded');
  await tab.reload();
  const reloadedCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await denyOnPhone();
  assert((await reloadedCall).status === 'denied', 'after a reload the request reaches the phone again');

  // ---- the hook guard, with real Chrome tab ids ----
  const guardedCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await phone.bringToFront();
  await phone.waitForFunction(() => [...document.querySelectorAll('.card input')].some((i) => !i.disabled), { timeout: 20000, polling: 100 });
  assert((await jsTool(loginTab)) === 'deny' && (await jsTool(99999)) === 'deny', 'while a login is open, page scripts are refused in every tab');
  await approveOnPhone('Password', SECRET.password);
  assert((await guardedCall).status === 'filled', 'filled while the guard was on');
  await sleep(1300); // GUARD_AFTER_FILL_SECONDS=1 for this test
  assert((await jsTool(99999)) === 'allow', 'after the fill, other tabs are allowed again');
  assert((await jsTool(loginTab)) === 'deny', 'the filled tab stays guarded while the same page is loaded');
  await tab.goto(LOGIN_URL);
  await sleep(300);
  assert((await jsTool(loginTab)) === 'allow', 'a new page in that tab lifts the guard');
  await tab.reload(); // the script just allowed counts as having run in the old page only

  // ---- plain HTML form: fill, submit and clear in one step ----
  await tab.goto(CLASSIC_URL);
  const classicCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await approveOnPhone('Password', SECRET.password);
  assert((await classicCall).status === 'filled', 'plain form filled and submitted');
  await tab.waitForFunction(() => document.title === 'Signed in', { polling: 100 });
  assert(recorded.some((r) => r.classic === SECRET.password), 'site received the password in the form post');
  assert(await tab.evaluate(() => sessionStorage.getItem('saw') === null), 'a script watching the page never saw the password in the field');

  // ---- a site that reads the field seconds after the submit ----
  await tab.goto(SLOW_URL);
  const slowCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await approveOnPhone('Password', SECRET.password);
  assert((await slowCall).status === 'filled', 'slow form filled and submitted');
  await tab.waitForFunction(() => document.title === 'Signed in', { timeout: 15000, polling: 100 });
  assert(recorded.some((r) => r.slow === SECRET.password), 'a site that reads the field after a delay still gets the password');

  // ---- one request at a time ----
  await tab.goto(LOGIN_URL);
  const firstCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await phone.bringToFront();
  await phone.waitForFunction(() => document.querySelector('.card button.secondary:not([disabled])'), { timeout: 20000, polling: 100 });
  const second = await requestLogin({ domain: 'relay.test', fields: ['password'] });
  assert(second.status === 'failed' && /another login request/.test(second.detail), 'a second request is refused while one is waiting');
  await phone.click('.card button.secondary:not([disabled])');
  assert((await firstCall).status === 'denied', 'the first request is unaffected');

  // ---- deny and pause from the phone ----
  const pauseCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await phone.bringToFront();
  await phone.waitForFunction(() => document.querySelector('.card button.pause:not([disabled])'), { timeout: 20000, polling: 100 });
  await phone.click('.card button.pause:not([disabled])');
  assert((await pauseCall).status === 'denied', 'deny and pause denies the request');
  await phone.waitForFunction(() => document.body.innerText.includes('Login requests are paused until'), { polling: 100 });
  await sw.evaluate(() => new Promise((r) => { const t = setInterval(async () => { if ((await chrome.storage.local.get('pausedUntil')).pausedUntil > Date.now()) { clearInterval(t); r(); } }, 100); }));
  const cards = await phone.evaluate(() => document.querySelectorAll('.card input').length);
  const whilePaused = await requestLogin({ domain: 'relay.test', fields: ['password'] });
  assert(whilePaused.status === 'failed' && /paused/.test(whilePaused.detail), 'requests are refused while paused');
  await sleep(500);
  assert((await phone.evaluate(() => document.querySelectorAll('.card input').length)) === cards, 'nothing reached the phone while paused');
  await options.waitForFunction(() => !document.getElementById('paused').hidden, { polling: 100 });
  assert(true, 'options page shows the pause');
  await phone.click('button.resume');
  await sw.evaluate(() => new Promise((r) => { const t = setInterval(async () => { if (!(await chrome.storage.local.get('pausedUntil')).pausedUntil) { clearInterval(t); r(); } }, 100); }));
  const resumedCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await denyOnPhone();
  assert((await resumedCall).status === 'denied', 'resume on the phone lets requests through again');

  // ---- rate limit ----
  await sw.evaluate(() => chrome.storage.local.set({ sentLog: Array(6).fill(Date.now()) }));
  const limited = await requestLogin({ domain: 'relay.test', fields: ['password'] }, { keepRateLimit: true });
  assert(limited.status === 'failed' && /too many login requests/.test(limited.detail), 'refuses more than 6 requests in 15 minutes');

  // ---- the approval page changed ----
  phoneServing.tamper = true;
  const pushesBefore = ntfy.messages.length;
  const tampered = await requestLogin({ domain: 'relay.test', fields: ['password'] });
  assert(tampered.status === 'failed' && /approval page .* has changed/.test(tampered.detail), 'refuses to use an approval page whose code changed');
  const sinceTamper = ntfy.messages.slice(pushesBefore);
  assert(sinceTamper.length === 1 && sinceTamper[0].headers.title === 'Remote Auth Kit warning', 'warns on the phone, and sends no request');
  await options.waitForFunction(() => !document.getElementById('pageWarning').hidden, { polling: 100 });
  assert(true, 'options page shows the approval page warning');
  phoneServing.tamper = false;
  const restoredCall = requestLogin({ domain: 'relay.test', fields: ['password'] });
  await denyOnPhone();
  assert((await restoredCall).status === 'denied', 'once the page is back to a trusted version, requests go through');

  const all = ntfy.messages.map((m) => m.message).join('\n');
  assert(!all.includes(SECRET.password) && !all.includes(SECRET.otp), 'ntfy never saw a password or code');

  console.log('\nall passed');
} finally {
  for (const c of cleanups.reverse()) { try { await c(); } catch {} }
  setTimeout(() => process.exit(), 200).unref();
}
