// Login Relay hub: owns the WebSocket to the companion extension and the
// request store. It never sees a password or code: the phone encrypts them to
// the extension's key and sends them through ntfy straight to the extension.
// The hub only learns the status (filled, failed, denied, expired).
//
// It also keeps the guard state the plugin's PreToolUse hook (hooks/guard.js)
// asks for: while a login is open, and until the filled page is replaced, Claude
// in Chrome's page-script tools are refused. The hook reports every page script
// Claude runs, and the extension refuses to fill a page that a script ran in
// after it loaded.

import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';

const seconds = (name, fallback) => Number(process.env[name] || fallback) * 1000;
export const REQUEST_TTL_MS = seconds('REQUEST_TTL_SECONDS', 180);
// How long a new request waits for the extension to (re)connect. Chrome puts the
// extension's service worker to sleep and wakes it at least every 30 seconds.
const EXTENSION_WAIT_MS = seconds('EXTENSION_WAIT_SECONDS', 40);
const SUBMITTED_GRACE_MS = 60_000;
// After a fill, every tab is guarded until the filled page is replaced or this
// passes; the filled tab itself stays guarded until its page is replaced.
const GUARD_ALL_AFTER_FILL_MS = seconds('GUARD_AFTER_FILL_SECONDS', 180);
const GUARD_TAB_MAX_MS = 60 * 60_000;

// status: pending_extension -> awaiting_user -> submitted -> filled | failed
//         (or denied | expired at any point)
const TERMINAL = new Set(['filled', 'failed', 'denied', 'expired']);
const FROM_EXTENSION = new Set(['awaiting_user', 'submitted', 'filled', 'failed', 'denied']);

export const safeEq = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};

export function normaliseDomain(input) {
  let d = String(input).trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, '').split(/[/?#:]/)[0];
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) throw new Error(`invalid domain: ${input}`);
  return d;
}

function view(r) {
  return {
    request_id: r.id,
    domain: r.domain,
    fields: r.fields,
    status: r.status,
    detail: r.detail ?? null,
    expires_in_s: Math.max(0, Math.round((r.expiresAt - Date.now()) / 1000)),
  };
}

export function createRelay({ log = console.error } = {}) {
  const requests = new Map();
  let ext = null; // WebSocket of the connected extension
  const extWaiters = new Set();
  const guards = new Map(); // request id -> { domain, tabId, allUntil, tabUntil }
  let lastScriptAt = 0; // when Claude last ran a script in a page (reported by the hook)

  function update(r, patch) {
    Object.assign(r, patch);
    const waiters = [...r.waiters];
    r.waiters.clear();
    waiters.forEach((w) => w());
  }

  function sendExt(msg) {
    if (!ext || ext.readyState !== 1) return false;
    ext.send(JSON.stringify(msg));
    return true;
  }

  function extensionReady(ms) {
    if (ext) return Promise.resolve(true);
    return new Promise((resolve) => {
      const done = (ok) => { clearTimeout(timer); extWaiters.delete(done); resolve(ok); };
      const timer = setTimeout(() => done(false), ms);
      extWaiters.add(done);
    });
  }

  const sweep = setInterval(() => {
    const now = Date.now();
    for (const r of requests.values()) {
      if (!TERMINAL.has(r.status) && now > r.expiresAt) {
        update(r, { status: 'expired', detail: 'no response in time' });
        sendExt({ type: 'cancel', id: r.id, reason: 'expired' });
      }
      if (now - r.createdAt > 15 * 60_000) requests.delete(r.id);
    }
    for (const [id, g] of guards) if (now > g.tabUntil) guards.delete(id);
  }, 1000);
  sweep.unref();

  async function create({ domain, fields, note, submit }) {
    const r = {
      id: crypto.randomUUID(),
      domain: normaliseDomain(domain),
      fields: [...new Set(fields)],
      note: String(note || '').slice(0, 140),
      submit: submit !== false,
      status: 'pending_extension',
      createdAt: Date.now(),
      expiresAt: Date.now() + REQUEST_TTL_MS,
      waiters: new Set(),
    };
    requests.set(r.id, r);
    if (!(await extensionReady(EXTENSION_WAIT_MS))) {
      update(r, { status: 'failed', detail: 'the Login Relay extension is not connected (is Chrome open with the extension installed and pointed at this relay?)' });
      return view(r);
    }
    sendExt({
      type: 'login_request', id: r.id, domain: r.domain, fields: r.fields,
      note: r.note, submit: r.submit, expires_at: r.expiresAt, last_script_at: lastScriptAt,
    });
    return view(r);
  }

  function wait(id, ms) {
    const r = requests.get(id);
    if (!r) return Promise.resolve(null);
    return new Promise((resolve) => {
      if (TERMINAL.has(r.status)) return resolve(view(r));
      const timer = setTimeout(() => { r.waiters.delete(check); resolve(view(r)); }, ms);
      function check() {
        if (TERMINAL.has(r.status)) { clearTimeout(timer); resolve(view(r)); }
        else r.waiters.add(check);
      }
      r.waiters.add(check);
    });
  }

  function guardFor(r) {
    const now = Date.now();
    const g = guards.get(r.id) || { domain: r.domain, tabId: null };
    guards.set(r.id, { ...g, allUntil: now + GUARD_ALL_AFTER_FILL_MS, tabUntil: now + GUARD_TAB_MAX_MS });
    return guards.get(r.id);
  }

  function onExtMessage(msg) {
    const r = msg?.id ? requests.get(msg.id) : null;
    if (!r) return;
    // The extension is about to put a value into this tab (or has).
    if (msg.type === 'guard') { guardFor(r).tabId = Number.isInteger(msg.tab_id) ? msg.tab_id : null; return; }
    // The page that held the value is gone, or no value reached it.
    if (msg.type === 'guard_clear') { guards.delete(r.id); return; }
    if (msg.type !== 'status' || TERMINAL.has(r.status) || !FROM_EXTENSION.has(msg.status)) return;
    const patch = { status: msg.status, detail: msg.detail ? String(msg.detail).slice(0, 300) : null };
    if (msg.status === 'submitted') { patch.expiresAt = Date.now() + SUBMITTED_GRACE_MS; guardFor(r); }
    update(r, patch);
  }

  // What the hook enforces. While any request is open, or a filled page may still
  // hold the value, page scripts are refused in every tab; after that, only in
  // the filled tab until its page is replaced.
  function guardState() {
    const now = Date.now();
    const open = [...requests.values()].filter((r) => !TERMINAL.has(r.status));
    const live = [...guards.values()].filter((g) => now <= g.tabUntil);
    const all = open.length > 0 || live.some((g) => now <= g.allUntil);
    return {
      block_all: all,
      tab_ids: [...new Set(live.map((g) => g.tabId).filter((t) => t != null))],
      domains: [...new Set([...open.map((r) => r.domain), ...live.map((g) => g.domain)])],
    };
  }

  function scriptRan(at = Date.now()) {
    lastScriptAt = Math.max(lastScriptAt, at);
    sendExt({ type: 'script_ran', at: lastScriptAt });
  }

  function attachExtension(ws) {
    if (ext && ext !== ws) ext.close(4000, 'replaced by newer connection');
    ext = ws;
    log('extension connected');
    if (lastScriptAt) sendExt({ type: 'script_ran', at: lastScriptAt });
    [...extWaiters].forEach((w) => w(true));
    ws.on('close', () => {
      if (ext === ws) { ext = null; log('extension disconnected'); }
    });
  }

  return {
    create,
    wait,
    onExtMessage,
    attachExtension,
    guardState,
    scriptRan,
    extensionConnected: () => !!ext,
    close: () => clearInterval(sweep),
  };
}

// WebSocket endpoints on an http.Server:
//   /ext   the companion extension. Only chrome-extension:// origins, so a web
//          page in the browser can't pose as the extension.
//   /peer  other local Claude Code sessions forwarding tool calls to this hub.
//          Browsers always send an Origin header, so requiring none keeps web
//          pages out.
export function attachSockets(httpServer, relay, { extensionToken = '', allowPeers = false, log = console.error } = {}) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

  httpServer.on('upgrade', (req, socket, head) => {
    const { pathname } = new URL(req.url, 'http://x');
    const origin = req.headers.origin;
    const ok =
      (pathname === '/ext' && typeof origin === 'string' && origin.startsWith('chrome-extension://')) ||
      (pathname === '/peer' && allowPeers && origin === undefined);
    if (!ok) {
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => (pathname === '/ext' ? onExtension(ws) : onPeer(ws)));
  });

  function onExtension(ws) {
    let authed = false;
    const authTimer = setTimeout(() => !authed && ws.close(4001, 'auth timeout'), 5000);
    ws.on('close', () => clearTimeout(authTimer));
    ws.on('message', (data) => {
      let msg;
      try { msg = JSON.parse(data.toString()); } catch { return; }
      if (!authed) {
        if (msg.type === 'hello' && (!extensionToken || safeEq(msg.token || '', extensionToken))) {
          authed = true;
          clearTimeout(authTimer);
          relay.attachExtension(ws);
          ws.send(JSON.stringify({ type: 'welcome' }));
        } else {
          ws.close(4001, 'unauthorized');
        }
        return;
      }
      if (msg.type === 'ping') return ws.send('{"type":"pong"}');
      relay.onExtMessage(msg);
    });
  }

  function onPeer(ws) {
    ws.on('message', async (data) => {
      let msg;
      try { msg = JSON.parse(data.toString()); } catch { return; }
      if (msg.type !== 'rpc') return;
      try {
        let result;
        if (msg.method === 'create') result = await relay.create(msg.params);
        else if (msg.method === 'wait') result = await relay.wait(msg.params.id, msg.params.ms);
        else throw new Error(`unknown method ${msg.method}`);
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'rpc_result', rid: msg.rid, result }));
      } catch (e) {
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'rpc_result', rid: msg.rid, error: e.message }));
      }
    });
    log('peer session connected');
  }

  return wss;
}
