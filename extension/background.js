// Login Relay companion extension (MV3 service worker).
// - Connects to the relay (local Claude Code by default) and receives login requests.
// - Finds the tab and frame showing the field, on an allowlisted domain only.
// - Sends the request to your phone through ntfy, sealed with the pairing key.
// - Decrypts the phone's answer with a private key that never leaves this
//   browser, re-checks the tab is still on the approved domain, fills, and
//   reports only a status back to the relay.

import { newPairingKey, topicsFor, seal, unseal, decryptValues, publish, subscribe } from './lib/relay-crypto.js';

const DEFAULT_RELAY_URL = 'ws://127.0.0.1:47823';
const DEFAULT_NTFY_SERVER = 'https://ntfy.sh';
const DEFAULT_APPROVE_URL = 'https://warrendeanlangeveldt.github.io/login-relay/';
const PENDING_MAX_AGE_MS = 5 * 60_000;

let ws = null;
let connecting = false;
let retryTimer = null;
let phoneSub = null;

async function settings() {
  const s = await chrome.storage.local.get(['relayUrl', 'token', 'allowedDomains', 'ntfyServer', 'approveUrl']);
  return {
    relayUrl: s.relayUrl || DEFAULT_RELAY_URL,
    token: s.token || '',
    allowedDomains: s.allowedDomains || '',
    ntfyServer: (s.ntfyServer || DEFAULT_NTFY_SERVER).replace(/\/$/, ''),
    approveUrl: s.approveUrl || DEFAULT_APPROVE_URL,
  };
}

// ---------- keys and pairing ----------
async function getKeys() {
  const { keyPair } = await chrome.storage.local.get('keyPair');
  if (keyPair) return keyPair;
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const stored = { publicJwk: { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y }, privateJwk: priv };
  await chrome.storage.local.set({ keyPair: stored });
  return stored;
}

async function getPairing({ create = false } = {}) {
  let { pairingKey } = await chrome.storage.local.get('pairingKey');
  if (!pairingKey && create) {
    pairingKey = newPairingKey();
    await chrome.storage.local.set({ pairingKey, phonePaired: false });
  }
  return pairingKey || null;
}

// ---------- pending requests (survive service-worker restarts) ----------
async function allPending() {
  const { pending = {} } = await chrome.storage.session.get('pending');
  const now = Date.now();
  for (const [k, v] of Object.entries(pending)) if (now - v.at > PENDING_MAX_AGE_MS) delete pending[k];
  return pending;
}
async function getPending(id) {
  return (await allPending())[id] || null;
}
async function setPending(id, value) {
  const pending = await allPending();
  if (value) pending[id] = value; else delete pending[id];
  await chrome.storage.session.set({ pending });
  return Object.keys(pending).length;
}

// ---------- domain checks ----------
function hostOk(url, domain) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && (u.hostname === domain || u.hostname.endsWith('.' + domain));
  } catch { return false; }
}
async function domainAllowed(domain) {
  const { allowedDomains } = await settings();
  const allow = allowedDomains.split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  return allow.some((a) => domain === a || domain.endsWith('.' + a));
}
const cleanUrl = (url) => { try { const u = new URL(url); return u.origin + u.pathname; } catch { return ''; } };

// ---------- page agent (serialised into the page; must be self-contained) ----------
function pageAgent(mode, values, submit) {
  const visible = (el) => {
    const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled && !el.readOnly;
  };
  const q = (sel) => [...document.querySelectorAll(sel)].filter(visible);
  const findPassword = () => q('input[type="password"]')[0] || null;
  const findOtp = () => {
    const otc = q('input[autocomplete="one-time-code"]');
    if (otc.length === 1 && otc[0].maxLength !== 1) return [otc[0]];
    const boxes = q('input').filter((i) => i.maxLength === 1 && ['text', 'tel', 'number', ''].includes(i.type));
    if (boxes.length >= 4) return boxes; // split "one box per digit" UIs (e.g. Apple)
    if (otc.length) return otc;
    const named = q('input').filter((i) => i.type !== 'password' && i.type !== 'hidden' &&
      /otp|one.?time|code|token|2fa|mfa|verif/i.test(`${i.name} ${i.id} ${i.getAttribute('aria-label') || ''} ${i.placeholder || ''}`));
    return named.length ? [named[0]] : null;
  };
  const nativeSet = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const setVal = (el, v) => {
    el.focus();
    nativeSet.call(el, v); // works with React-controlled inputs
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };

  if (mode === 'probe') return { host: location.hostname, password: !!findPassword(), otp: !!findOtp() };

  if (mode === 'fill') {
    const filled = []; let last = null; let pw = null;
    if (values.password != null) {
      const el = findPassword(); if (!el) return { ok: false, error: 'password field not found' };
      setVal(el, values.password); filled.push('password'); last = el; pw = el;
    }
    if (values.otp != null) {
      const els = findOtp(); if (!els) return { ok: false, error: 'code field not found' };
      const code = String(values.otp).replace(/\s+/g, '');
      if (els.length > 1) els.forEach((el, i) => setVal(el, code[i] || '')); else setVal(els[0], code);
      filled.push('otp'); last = els[els.length - 1];
    }
    values = null;
    if (submit && last) {
      const form = last.form;
      const btn = form && [...form.querySelectorAll('button[type="submit"], input[type="submit"], button:not([type])')].find(visible);
      if (btn) btn.click();
      else if (form?.requestSubmit) form.requestSubmit();
      else last.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true }));
      // Once submitted, take the password out of the DOM so nothing else reading
      // the page (including Claude) can read it back. No input event: the site
      // already has the value, and an event could reset its own state mid-login.
      if (pw) setTimeout(() => { if (pw.isConnected) nativeSet.call(pw, ''); }, 1500);
    }
    // If a filled password field is still showing later (e.g. wrong password), wipe it fully.
    setTimeout(() => {
      for (const el of document.querySelectorAll('input[type="password"]')) {
        if (el.value) { nativeSet.call(el, ''); el.dispatchEvent(new Event('input', { bubbles: true })); }
      }
    }, 8000);
    return { ok: true, filled };
  }
  return { ok: false, error: 'unknown mode' };
}

// ---------- find the tab/frame showing the requested fields ----------
async function findTarget(domain, fields) {
  const tabs = (await chrome.tabs.query({}))
    .filter((t) => t.url && hostOk(t.url, domain))
    .sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0));
  for (const tab of tabs) {
    let frames;
    try { frames = await chrome.webNavigation.getAllFrames({ tabId: tab.id }); } catch { continue; }
    const frameIds = (frames || []).filter((f) => hostOk(f.url, domain)).map((f) => f.frameId);
    if (!frameIds.length) continue;
    let results;
    try { results = await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func: pageAgent, args: ['probe', null, false] }); }
    catch { continue; }
    for (const r of results) {
      if (r.result && fields.every((f) => r.result[f])) {
        return { tabId: tab.id, frameId: r.frameId, tabUrl: cleanUrl(tab.url), title: tab.title || '', frameHost: r.result.host };
      }
    }
  }
  return null;
}

// ---------- relay connection ----------
const sendRelay = (msg) => ws && ws.readyState === 1 && ws.send(JSON.stringify(msg));
const relayStatus = (id, status, detail) => sendRelay({ type: 'status', id, status, detail });

async function toPhone(msg) {
  const k = await getPairing();
  const { ntfyServer } = await settings();
  const { data } = await topicsFor(k);
  await publish(ntfyServer, data, await seal(k, 'e2p', msg));
}

async function finish(id, status, detail) {
  relayStatus(id, status, detail);
  await toPhone({ type: 'status', id, status, detail }).catch(() => {});
}

async function onLoginRequest({ id, domain, fields, note, submit, expires_at }) {
  const k = await getPairing();
  if (!k || !(await chrome.storage.local.get('phonePaired')).phonePaired) {
    return relayStatus(id, 'failed', 'no phone is paired yet: open the Login Relay extension options and scan the pairing code with your phone');
  }
  if (!(await domainAllowed(domain))) {
    return relayStatus(id, 'failed', `${domain} is not in the Login Relay extension's allowed domains`);
  }
  const t = await findTarget(domain, fields);
  if (!t) return relayStatus(id, 'failed', `no open tab on ${domain} is showing a ${fields.join(' + ')} field`);

  await setPending(id, { domain, fields, submit: submit !== false, tabId: t.tabId, frameId: t.frameId, at: Date.now() });
  await ensurePhoneSubscription();
  try {
    const { ntfyServer, approveUrl } = await settings();
    const { notify } = await topicsFor(k);
    await toPhone({
      type: 'request', id, domain, fields, note: note || '', expires_at,
      context: { tab_url: t.tabUrl.slice(0, 300), tab_title: t.title.slice(0, 200), frame_host: t.frameHost.slice(0, 200) },
    });
    // The push itself carries no secrets or tab details.
    const headers = { Title: 'Login request', Priority: 'high', Tags: 'key' };
    if (approveUrl) headers.Click = approveUrl;
    await publish(ntfyServer, notify, `Claude needs ${fields.join(' + ')} for ${domain}`, headers);
  } catch (e) {
    await setPending(id, null);
    return relayStatus(id, 'failed', `could not reach ntfy to notify your phone (${e.message})`);
  }
  relayStatus(id, 'awaiting_user');
}

async function onPhoneSubmit({ id, payload }) {
  const p = await getPending(id);
  if (!p) return; // unknown, expired or already used (ntfy replays cached messages)
  await setPending(id, null); // single use
  relayStatus(id, 'submitted');

  let values;
  try { values = await decryptValues((await getKeys()).privateJwk, payload, id, p.domain); }
  catch { return finish(id, 'failed', 'could not decrypt (re-pair the phone?)'); }

  const clean = {};
  for (const f of p.fields) if (typeof values?.[f] === 'string' && values[f]) clean[f] = values[f];
  values = null;
  if (Object.keys(clean).length !== p.fields.length) return finish(id, 'failed', 'missing values');

  // Re-verify: the tab and frame must still be on the approved domain right now.
  const tab = await chrome.tabs.get(p.tabId).catch(() => null);
  const frame = await chrome.webNavigation.getFrame({ tabId: p.tabId, frameId: p.frameId }).catch(() => null);
  if (!tab || !frame || !hostOk(tab.url, p.domain) || !hostOk(frame.url, p.domain)) {
    return finish(id, 'failed', 'tab navigated away from the approved domain; nothing was filled');
  }

  let res;
  try {
    [res] = await chrome.scripting.executeScript({ target: { tabId: p.tabId, frameIds: [p.frameId] }, func: pageAgent, args: ['fill', clean, p.submit] });
  } catch (e) {
    res = { result: { ok: false, error: 'could not run in page: ' + e.message } };
  }
  for (const k in clean) clean[k] = '';
  const r = res?.result || { ok: false, error: 'no result' };
  if (r.ok) await finish(id, 'filled', `filled ${r.filled.join(', ')}${p.submit ? ' and submitted' : ''}`);
  else await finish(id, 'failed', r.error);
}

async function onPhoneDeny({ id }) {
  if (!(await getPending(id))) return;
  await setPending(id, null);
  await finish(id, 'denied', 'declined on phone');
}

async function onCancel({ id, reason }) {
  if (!(await getPending(id))) return;
  await setPending(id, null);
  await toPhone({ type: 'status', id, status: reason || 'expired' }).catch(() => {});
}

// ---------- phone -> extension (ntfy data topic) ----------
// Subscribed only while a request is pending. The ntfy WebSocket also keeps
// this service worker awake while you're answering on the phone.
let subStarting = null;
async function ensurePhoneSubscription() {
  if (subStarting) return subStarting;
  subStarting = startPhoneSubscription().finally(() => { subStarting = null; });
  return subStarting;
}
async function startPhoneSubscription() {
  const pending = await allPending();
  if (!Object.keys(pending).length) {
    phoneSub?.close(); phoneSub = null;
    return;
  }
  if (phoneSub) return;
  const k = await getPairing();
  if (!k) return;
  const { ntfyServer } = await settings();
  const { data } = await topicsFor(k);
  const { phoneSince } = await chrome.storage.session.get('phoneSince');
  const since = phoneSince || String(Math.floor(Math.min(...Object.values(pending).map((p) => p.at)) / 1000) - 5);
  // One message at a time, so a duplicate submit can't race past the single-use check.
  let queue = Promise.resolve();
  phoneSub = subscribe(ntfyServer, data, since, (message, msgId) => {
    queue = queue.then(async () => {
      await chrome.storage.session.set({ phoneSince: msgId });
      const msg = await unseal(k, 'p2e', message);
      if (msg?.type === 'submit') await onPhoneSubmit(msg);
      else if (msg?.type === 'deny') await onPhoneDeny(msg);
      else if (msg?.type === 'paired') await chrome.storage.local.set({ phonePaired: true });
      await ensurePhoneSubscription();
    }).catch(() => {});
  });
}

// While the options page shows the pairing code, listen for the phone's "paired" hello.
let pairingSub = null;
async function watchPairing(on) {
  pairingSub?.close(); pairingSub = null;
  if (!on) return;
  const k = await getPairing({ create: true });
  const { ntfyServer } = await settings();
  const { data } = await topicsFor(k);
  pairingSub = subscribe(ntfyServer, data, '10m', async (message) => {
    const msg = await unseal(k, 'p2e', message);
    if (msg?.type === 'paired') await chrome.storage.local.set({ phonePaired: true });
  });
}

// ---------- connection ----------
async function setStatus(status) { await chrome.storage.local.set({ status, statusAt: Date.now() }); }
const toWsUrl = (u) => u.replace(/\/$/, '').replace(/^http/, 'ws');

async function connect() {
  if (connecting || (ws && ws.readyState <= 1)) return;
  clearTimeout(retryTimer);
  connecting = true; // before any await, so overlapping calls can't open two sockets
  try {
    const { relayUrl, token } = await settings();
    const sock = new WebSocket(toWsUrl(relayUrl) + '/ext');
    ws = sock;
    let opened = false;
    let pingTimer = null;
    sock.onopen = () => {
      opened = true;
      sock.send(JSON.stringify({ type: 'hello', token }));
      // Regular traffic keeps the MV3 service worker alive (Chrome 116+).
      pingTimer = setInterval(() => sock.readyState === 1 && sock.send('{"type":"ping"}'), 20_000);
    };
    sock.onmessage = async (e) => {
      let msg; try { msg = JSON.parse(e.data); } catch { return; }
      if (msg.type === 'welcome') return setStatus('connected');
      if (msg.type === 'login_request') return onLoginRequest(msg);
      if (msg.type === 'cancel') return onCancel(msg);
    };
    sock.onclose = (e) => {
      clearInterval(pingTimer);
      if (ws && ws !== sock) return; // replaced by a newer socket (e.g. after Save)
      ws = null;
      const local = /^wss?:\/\/(127\.0\.0\.1|localhost)[:/]/.test(toWsUrl(relayUrl));
      setStatus(e.code === 4001 ? 'unauthorized (check the extension token)'
        : !opened && local ? 'waiting for Claude Code (no session running)'
        : 'disconnected');
      retryTimer = setTimeout(connect, e.code === 4001 ? 60_000 : opened ? 1_000 : 5_000);
    };
    sock.onerror = () => {};
  } finally {
    connecting = false;
  }
}

chrome.runtime.onInstalled.addListener(() => { getKeys(); connect(); });
chrome.runtime.onStartup.addListener(connect);
chrome.alarms.create('keepalive', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'keepalive') { connect(); ensurePhoneSubscription(); } });
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg?.type === 'reconnect') {
    if (ws) ws.close(); ws = null; connect();
    reply({ ok: true });
  } else if (msg?.type === 'pairing') {
    (async () => {
      const k = await getPairing({ create: true });
      const { publicJwk } = await getKeys();
      const { ntfyServer, approveUrl } = await settings();
      reply({ k, jwk: publicJwk, server: ntfyServer, approveUrl, topics: await topicsFor(k) });
    })();
    return true;
  } else if (msg?.type === 'reset_pairing') {
    (async () => {
      await chrome.storage.local.set({ pairingKey: newPairingKey(), phonePaired: false });
      await chrome.storage.session.remove('phoneSince');
      phoneSub?.close(); phoneSub = null;
      reply({ ok: true });
    })();
    return true;
  } else if (msg?.type === 'watch_pairing') {
    watchPairing(!!msg.on).then(() => reply({ ok: true }));
    return true;
  }
});
connect();
ensurePhoneSubscription();
