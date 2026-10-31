// End-to-end protocol test:
//   Claude (MCP client) -> local relay (as Claude Code starts it, over stdio)
//   -> extension (protocol stand-in using the real shared crypto) -> ntfy -> phone
//   -> ntfy -> extension decrypts -> status back to Claude.
// Also: several Claude Code sessions sharing one relay, hub hand-over when a
// session ends, origin checks, and the optional hosted mode.
// The real extension is exercised in Chrome by test/browser/browser.mjs.
import { spawn } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import WebSocket from 'ws';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { startFakeNtfy } from './fake-ntfy.mjs';
import {
  newPairingKey, topicsFor, pairingLink, parsePairing, seal, unseal, encryptValues, decryptValues, publish, subscribe,
} from '../extension/lib/relay-crypto.js';

globalThis.crypto ??= webcrypto;
globalThis.WebSocket ??= WebSocket; // Node 20 has no global WebSocket

const PORT = 18000 + Math.floor(Math.random() * 1000);
const SECRET = { password: 'hunter2-correct-horse', otp: '123456' };
const assert = (c, m) => { if (!c) { console.error('FAIL:', m); process.exitCode = 1; throw new Error(m); } console.log('ok -', m); };
const toolText = (r) => r.content[0].text;
const toolJson = (r) => JSON.parse(toolText(r));
const cleanups = [];

async function session(env = {}) {
  const transport = new StdioClientTransport({
    command: 'node', args: ['server/local.js'],
    env: { ...process.env, LOGIN_RELAY_PORT: String(PORT), EXTENSION_WAIT_SECONDS: '3', ...env },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'test', version: '0' });
  await client.connect(transport);
  const stderr = [];
  transport.stderr.on('data', (d) => stderr.push(d.toString()));
  cleanups.push(() => client.close().catch(() => {}));
  return { client, stderr };
}

// ---- extension stand-in: same messages and crypto as extension/background.js ----
async function fakeExtension({ url, ntfy, k, token = '' }) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const topics = await topicsFor(k);
  const pending = new Map();
  const state = { ws: null, fills: [], decrypted: null, closed: false, connects: 0 };

  const toPhone = async (msg) => publish(ntfy.url, topics.data, await seal(k, 'e2p', msg));
  const status = (id, s, detail) => state.ws?.readyState === 1 && state.ws.send(JSON.stringify({ type: 'status', id, status: s, detail }));

  const sub = subscribe(ntfy.url, topics.data, '1m', async (text) => {
    const msg = await unseal(k, 'p2e', text);
    const p = msg && pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    if (msg.type === 'deny') { status(msg.id, 'denied', 'declined on phone'); return toPhone({ type: 'status', id: msg.id, status: 'denied' }); }
    status(msg.id, 'submitted');
    state.decrypted = await decryptValues(privateJwk, msg.payload, msg.id, p.domain);
    state.fills.push(msg.id);
    status(msg.id, 'filled', `filled ${Object.keys(state.decrypted).join(', ')} and submitted`);
    await toPhone({ type: 'status', id: msg.id, status: 'filled' });
  });

  const connect = () => {
    if (state.closed) return;
    const ws = new WebSocket(url, { origin: 'chrome-extension://abcdefghijklmnop' });
    ws.on('open', () => ws.send(JSON.stringify({ type: 'hello', token })));
    ws.on('message', async (raw) => {
      const m = JSON.parse(raw);
      if (m.type === 'welcome') { state.ws = ws; state.connects++; }
      if (m.type === 'login_request') {
        pending.set(m.id, m);
        await toPhone({ type: 'request', id: m.id, domain: m.domain, fields: m.fields, note: m.note, expires_at: m.expires_at,
          context: { tab_url: 'https://appstoreconnect.apple.com/login', tab_title: 'App Store Connect', frame_host: 'idmsa.apple.com' } });
        await publish(ntfy.url, topics.notify, `Claude needs ${m.fields.join(' + ')} for ${m.domain}`, { Title: 'Login request' });
        status(m.id, 'awaiting_user');
      }
    });
    ws.on('close', (code) => { if (state.ws === ws) state.ws = null; state.lastClose = code; if (!state.closed) setTimeout(connect, 200); });
    ws.on('error', () => {});
  };
  connect();
  state.jwk = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y };
  state.close = () => { state.closed = true; sub.close(); state.ws?.close(); };
  state.waitConnected = async (n = 1) => { for (let i = 0; i < 100 && state.connects < n; i++) await sleep(50); return state.connects >= n; };
  cleanups.push(state.close);
  return state;
}

// ---- phone stand-in: what phone/app.js does ----
async function fakePhone({ link, action = 'submit', values = SECRET }) {
  const pairing = parsePairing(new URL(link).hash);
  const topics = await topicsFor(pairing.k);
  await publish(pairing.server, topics.data, await seal(pairing.k, 'p2e', { type: 'paired' }));
  const seen = { requests: [], statuses: [] };
  const sub = subscribe(pairing.server, topics.data, '1m', async (text) => {
    const msg = await unseal(pairing.k, 'e2p', text);
    if (!msg) return;
    if (msg.type === 'status') return seen.statuses.push(msg);
    if (msg.type !== 'request' || seen.requests.some((r) => r.id === msg.id)) return;
    seen.requests.push(msg);
    if (action === 'deny') return publish(pairing.server, topics.data, await seal(pairing.k, 'p2e', { type: 'deny', id: msg.id }));
    const payload = await encryptValues(pairing.jwk, msg.id, msg.domain, values);
    await publish(pairing.server, topics.data, await seal(pairing.k, 'p2e', { type: 'submit', id: msg.id, payload }));
  });
  cleanups.push(() => sub.close());
  return { seen, close: () => sub.close() };
}

const ntfy = await startFakeNtfy();
cleanups.push(ntfy.close);

try {
  // ---------- local mode ----------
  const k = newPairingKey();
  const s1 = await session();
  const tools = await s1.client.listTools();
  assert(tools.tools.map((t) => t.name).sort().join() === 'login_status,request_login', 'tools listed');

  const health = await (await fetch(`http://127.0.0.1:${PORT}/healthz`)).json();
  assert(health.ok && health.extension_connected === false, 'first session became the hub on 127.0.0.1');

  const offline = toolJson(await s1.client.callTool({ name: 'request_login', arguments: { domain: 'apple.com', fields: ['otp'] } }));
  assert(offline.status === 'failed' && /not connected/.test(offline.detail), 'fails clearly when the extension is not connected');

  // A web page can't pose as the extension or as another Claude Code session.
  const rejected = async (path, origin) => new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}${path}`, origin ? { origin } : {});
    ws.on('open', () => { ws.close(); resolve(false); });
    ws.on('error', () => resolve(true));
  });
  assert(await rejected('/ext', 'https://evil.example'), '/ext rejects web origins');
  assert(await rejected('/ext'), '/ext rejects clients without an extension origin');
  assert(await rejected('/peer', 'https://evil.example'), '/peer rejects browser connections');

  const ext = await fakeExtension({ url: `ws://127.0.0.1:${PORT}/ext`, ntfy, k });
  assert(await ext.waitConnected(), 'extension connected to the local relay');

  const link = pairingLink('https://phone.example/login-relay/', { k, server: ntfy.url, jwk: ext.jwk });
  assert(new URL(link).search === '' && new URL(link).hash.startsWith('#pair='), 'pairing key travels only in the URL fragment');
  const phone = await fakePhone({ link });

  const result = await s1.client.callTool({ name: 'request_login', arguments: { domain: 'https://appstoreconnect.apple.com/x', fields: ['password', 'otp'], note: 'test' } });
  const status = toolJson(result);
  assert(status.status === 'filled' && status.domain === 'appstoreconnect.apple.com', `tool returned filled (${status.detail})`);
  assert(!toolText(result).includes(SECRET.password) && !toolText(result).includes(SECRET.otp), 'tool result contains no secret values');
  assert(ext.decrypted?.password === SECRET.password && ext.decrypted?.otp === SECRET.otp, 'extension decrypted the values');
  assert(phone.seen.requests[0]?.context?.frame_host === 'idmsa.apple.com', 'phone saw the tab context from the extension');

  const topics = await topicsFor(k);
  const dataBodies = ntfy.messages.filter((m) => m.topic === topics.data).map((m) => m.message).join('\n');
  const allBodies = ntfy.messages.map((m) => m.message).join('\n');
  assert(!allBodies.includes(SECRET.password) && !allBodies.includes(SECRET.otp), 'ntfy never saw the secret values');
  assert(!dataBodies.includes('apple.com') && !dataBodies.includes('idmsa'), 'ntfy data topic carries only sealed messages');
  assert(ntfy.messages.some((m) => m.topic === topics.notify && m.message === 'Claude needs password + otp for appstoreconnect.apple.com'), 'push notification names the domain only');

  // Envelopes can't be forged without the pairing key, or reflected back.
  const forged = await seal(newPairingKey(), 'p2e', { type: 'submit' });
  assert((await unseal(k, 'p2e', forged)) === null, 'envelope from another key is rejected');
  const reflected = await seal(k, 'e2p', { type: 'submit' });
  assert((await unseal(k, 'p2e', reflected)) === null, 'envelope sent the other way is rejected');

  // ---------- a second Claude Code session shares the hub ----------
  const s2 = await session();
  await sleep(200);
  assert(s2.stderr.join('').includes('forwarding to the hub'), 'second session forwards to the existing hub');
  const r2 = toolJson(await s2.client.callTool({ name: 'request_login', arguments: { domain: 'apple.com', fields: ['otp'] } }));
  assert(r2.status === 'filled', 'request from the second session filled through the hub');

  // ---------- hub's session ends: the other session takes over ----------
  await s1.client.close();
  for (let i = 0; i < 100 && !s2.stderr.join('').includes('hub listening'); i++) await sleep(50);
  assert(s2.stderr.join('').includes('hub listening'), 'second session took over the port when the first ended');
  assert(await ext.waitConnected(2), 'extension reconnected to the new hub');
  const r3 = toolJson(await s2.client.callTool({ name: 'request_login', arguments: { domain: 'apple.com', fields: ['password'] } }));
  assert(r3.status === 'filled', 'request filled after hub hand-over');

  // ---------- user denies on the phone ----------
  phone.close();
  const denier = await fakePhone({ link, action: 'deny' });
  const r4 = toolJson(await s2.client.callTool({ name: 'request_login', arguments: { domain: 'apple.com', fields: ['password'] } }));
  assert(r4.status === 'denied', 'deny on the phone reaches Claude as denied');
  denier.close();

  // login_status for an unknown id
  const unknown = await s2.client.callTool({ name: 'login_status', arguments: { request_id: 'nope' } });
  assert(unknown.isError, 'login_status rejects unknown ids');
  const fills = ext.fills.length;
  ext.close();

  // ---------- hosted mode ----------
  const HPORT = PORT + 1000;
  const env = { ...process.env, PORT: String(HPORT), MCP_PATH_SECRET: 'm'.repeat(32), EXTENSION_TOKEN: 'e'.repeat(32), EXTENSION_WAIT_SECONDS: '3' };
  const hosted = spawn('node', ['server/hosted.js'], { env, stdio: ['ignore', 'pipe', 'inherit'] });
  cleanups.push(() => hosted.kill());
  await new Promise((r) => hosted.stdout.on('data', (d) => d.toString().includes('listening') && r()));
  const base = `http://127.0.0.1:${HPORT}`;
  assert((await fetch(`${base}/mcp/wrong`, { method: 'POST' })).status === 404, 'hosted MCP path requires the secret');
  const page = await fetch(`${base}/`);
  assert(page.ok && /connect-src https: wss:/.test(page.headers.get('content-security-policy')) && (await page.text()).includes('app.js'), 'hosted relay serves the phone page');

  const badExt = await fakeExtension({ url: `ws://127.0.0.1:${HPORT}/ext`, ntfy, k, token: 'wrong' });
  for (let i = 0; i < 40 && badExt.lastClose !== 4001; i++) await sleep(50);
  assert(badExt.lastClose === 4001, 'hosted relay rejects a wrong extension token');
  badExt.close();

  const hExt = await fakeExtension({ url: `ws://127.0.0.1:${HPORT}/ext`, ntfy, k, token: env.EXTENSION_TOKEN });
  assert(await hExt.waitConnected(), 'extension connected to the hosted relay with its token');
  await fakePhone({ link: pairingLink('https://phone.example/', { k, server: ntfy.url, jwk: hExt.jwk }) });
  const hc = new Client({ name: 'test', version: '0' });
  await hc.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp/${env.MCP_PATH_SECRET}`)));
  cleanups.push(() => hc.close().catch(() => {}));
  const hr = await hc.callTool({ name: 'request_login', arguments: { domain: 'apple.com', fields: ['password', 'otp'] } });
  assert(toolJson(hr).status === 'filled' && !toolText(hr).includes(SECRET.password), 'hosted mode: filled, no secret in the result');
  assert(fills === 3, 'each approved request was filled exactly once');

  console.log('\nall passed');
} finally {
  for (const c of cleanups.reverse()) { try { await c(); } catch {} }
  setTimeout(() => process.exit(), 200).unref();
}
