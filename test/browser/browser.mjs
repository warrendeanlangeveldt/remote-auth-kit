// Real-browser end-to-end test. Runs the actual extension and the actual phone
// page in Chrome for Testing, against the local relay as Claude Code starts it,
// a local ntfy stand-in and a test login site:
//   Claude (MCP) -> relay -> extension finds the tab -> ntfy -> phone page
//   -> you type the password -> ntfy -> extension decrypts, fills, submits -> status.
// Run with: npm run test:browser (from the repo root).
import { execFileSync } from 'node:child_process';
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
const site = https.createServer(tls, (req, res) => {
  const url = new URL(req.url, 'https://x');
  if (req.method === 'POST' && url.pathname === '/record') {
    let b = '';
    req.on('data', (c) => (b += c));
    return req.on('end', () => { recorded.push(JSON.parse(b)); res.end('{}'); });
  }
  if (url.pathname.startsWith('/phone/')) {
    const file = path.join(root, 'phone', url.pathname.slice('/phone/'.length) || 'index.html');
    if (!file.startsWith(path.join(root, 'phone')) || !existsSync(file)) { res.writeHead(404); return res.end(); }
    const type = { '.html': 'text/html', '.js': 'text/javascript', '.webmanifest': 'application/manifest+json' }[path.extname(file)];
    res.writeHead(200, { 'content-type': type });
    return res.end(readFileSync(file));
  }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(LOGIN_PAGE);
});
await new Promise((r) => site.listen(0, '127.0.0.1', r));
cleanups.push(() => site.close());
const SITE_PORT = site.address().port;
// Pages other than the front tab get no animation frames in headless Chrome, so every wait polls on an interval.
const LOGIN_URL = `https://login.relay.test:${SITE_PORT}/signin`;
const APPROVE_URL = `https://phone.approve.test:${SITE_PORT}/phone/`;

const ntfy = await startFakeNtfy({ tls, host: 'ntfy.relay.test' });
cleanups.push(ntfy.close);

// ---------- Claude Code's side: the plugin's MCP server over stdio ----------
const transport = new StdioClientTransport({
  command: 'node', args: [path.join(root, 'server', 'local.js')],
  env: { ...process.env, LOGIN_RELAY_PORT: String(RELAY_PORT) }, stderr: 'inherit',
});
const claude = new Client({ name: 'browser-test', version: '0' });
await claude.connect(transport);
cleanups.push(() => claude.close());
const requestLogin = async (args) => {
  const r = await claude.callTool({ name: 'request_login', arguments: args }, undefined, { timeout: 150_000 });
  return { text: r.content[0].text, ...JSON.parse(r.content[0].text) };
};

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
  const sw = await swTarget.worker();
  if (process.env.DEBUG) sw.on('console', (m) => console.log(new Date().toISOString().slice(17, 23), '[extension]', m.text()));
  await sw.evaluate((cfg) => chrome.storage.local.set(cfg), {
    relayUrl: `ws://127.0.0.1:${RELAY_PORT}`, allowedDomains: 'relay.test', ntfyServer: ntfy.url, approveUrl: APPROVE_URL,
  });

  // Options page: the user's view of the extension.
  const options = await browser.newPage();
  await options.goto(`chrome-extension://${extId}/options.html`);
  await options.click('#save');
  await options.waitForFunction(() => document.getElementById('status').textContent === 'connected', { timeout: 15000, polling: 100 });
  assert(true, 'extension connected to the relay started by Claude Code');

  const unpaired = await requestLogin({ domain: 'relay.test', fields: ['password'] });
  assert(unpaired.status === 'failed' && /no phone is paired/.test(unpaired.detail), 'refuses requests until a phone is paired');

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
  await sleep(2000);
  assert(await tab.evaluate(() => document.querySelector('[name=password]').value === ''), 'password is gone from the page DOM after submit');
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
  assert(blocked.status === 'failed' && /allowed domains/.test(blocked.detail), 'refuses domains outside the allowlist');

  // ---- no matching field open ----
  const none = await requestLogin({ domain: 'relay.test', fields: ['password'] });
  assert(none.status === 'failed' && /no open tab/.test(none.detail), 'reports when no tab shows the field');

  const all = ntfy.messages.map((m) => m.message).join('\n');
  assert(!all.includes(SECRET.password) && !all.includes(SECRET.otp), 'ntfy never saw a password or code');

  console.log('\nall passed');
} finally {
  for (const c of cleanups.reverse()) { try { await c(); } catch {} }
  setTimeout(() => process.exit(), 200).unref();
}
