// Phone approval page. Static: it talks only to ntfy, never to a server of ours.
// Requests arrive sealed with the pairing key; passwords and codes are
// encrypted here, in your phone's browser, to the extension's key (pinned at
// pairing), so ntfy and the relay only ever carry ciphertext.
import { parsePairing, topicsFor, seal, unseal, encryptValues, publish, subscribe } from './relay-crypto.js';

const PAIR_KEY = 'loginRelayPairing';
const PAUSE_KEY = 'loginRelayPausedUntil';
const PAUSE_SECONDS = 3600;
const TERMINAL = new Set(['filled', 'failed', 'denied', 'expired']);
const app = document.getElementById('app');
const footer = document.getElementById('footer');

const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) n.append(kid); // append() treats strings as text (no HTML injection)
  return n;
};

function loadPairing() {
  try { return JSON.parse(localStorage.getItem(PAIR_KEY) || 'null'); } catch { return null; }
}

function showUnpaired(msg) {
  app.replaceChildren(el('div', { class: 'card' },
    msg ? el('div', { class: 'warn' }, msg) : null,
    el('div', {}, 'This phone is not paired.'),
    el('div', { class: 'muted' }, 'On your computer, open the Remote Auth Kit extension options, choose "Pair a phone", and scan the code with your camera (or open the pairing link you saved).')));
  footer.replaceChildren();
}

// "Deny and pause": the extension refuses new requests until then, without
// notifying you. The banner lets you resume early.
const pauseBanner = el('div', { class: 'card', hidden: '' });
function showPause(send) {
  const until = Number(localStorage.getItem(PAUSE_KEY) || 0);
  if (until <= Date.now()) { pauseBanner.hidden = true; return; }
  const at = new Date(until).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  pauseBanner.replaceChildren(
    el('div', {}, `Login requests are paused until ${at}.`),
    el('div', { class: 'btns' }, el('button', { class: 'plain resume', onclick: async () => {
      localStorage.removeItem(PAUSE_KEY);
      showPause(send);
      await send({ type: 'resume' }).catch(() => {});
    } }, 'Resume now')));
  pauseBanner.hidden = false;
}

const statuses = new Map(); // id -> { status, detail }
const cards = new Map(); // id -> { el, sent, finish }

function emptyState() {
  const live = [...cards.values()].some((c) => c.el.isConnected);
  if (!live && !app.querySelector('.empty')) app.append(el('div', { class: 'empty' }, 'No login requests right now.'));
  if (live) app.querySelector('.empty')?.remove();
}

function buildCard(pairing, topics, r, send) {
  const inputs = {};
  const fieldEls = r.fields.flatMap((f) => {
    const i = f === 'password'
      ? el('input', { type: 'password', autocomplete: 'current-password', autocapitalize: 'off', spellcheck: 'false' })
      : el('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9]*' });
    inputs[f] = i;
    return [el('label', {}, f === 'password' ? 'Password' : 'Verification code'), i];
  });

  const status = el('div', { class: 'status' });
  const expiry = el('div', { class: 'muted' });
  const sendBtn = el('button', { class: 'primary' }, 'Send to browser');
  const denyBtn = el('button', { class: 'secondary' }, 'Deny');
  const pauseBtn = el('button', { class: 'plain pause' }, 'Deny and pause requests for an hour');
  const card = el('div', { class: 'card' },
    el('div', { class: 'muted' }, 'Claude wants to sign in to'),
    el('div', { class: 'domain' }, r.domain),
    r.note ? el('div', { class: 'row' }, r.note) : null,
    el('div', { class: 'row' }, el('b', {}, 'Tab: '), r.context?.tab_url || '?'),
    r.context?.tab_title ? el('div', { class: 'row' }, el('b', {}, 'Title: '), r.context.tab_title) : null,
    el('div', { class: 'row' }, el('b', {}, 'Field found in: '), r.context?.frame_host || '?'),
    ...fieldEls,
    el('div', { class: 'btns' }, denyBtn, sendBtn), el('div', { class: 'btns' }, pauseBtn), status, expiry);

  const entry = { el: card, sent: false, done: false };
  let noAnswer = null;
  const lock = () => {
    sendBtn.disabled = denyBtn.disabled = pauseBtn.disabled = true;
    Object.values(inputs).forEach((i) => { i.value = ''; i.disabled = true; });
    clearInterval(tick);
    expiry.textContent = '';
  };
  entry.finish = (text, cls) => {
    entry.done = true;
    clearTimeout(noAnswer);
    status.textContent = text;
    status.className = 'status ' + (cls || '');
    lock();
  };
  const tick = setInterval(() => {
    const s = Math.max(0, Math.round((r.expires_at - Date.now()) / 1000));
    if (!entry.sent) expiry.textContent = `Expires in ${s}s`;
    if (s === 0 && !entry.sent) entry.finish('Expired', 'bad');
  }, 1000);

  sendBtn.addEventListener('click', async () => {
    const values = {};
    for (const f of r.fields) { const v = inputs[f].value; if (!v) { inputs[f].focus(); return; } values[f] = v; }
    entry.sent = true;
    sendBtn.disabled = denyBtn.disabled = pauseBtn.disabled = true;
    try {
      const payload = await encryptValues(pairing.jwk, r.id, r.domain, values);
      for (const k in values) values[k] = '';
      lock();
      await send({ type: 'submit', id: r.id, payload });
      status.textContent = 'Sent. Waiting for the browser…';
      noAnswer = setTimeout(() => !entry.done && entry.finish('No answer from the browser. Is the computer on?', 'bad'), 75_000);
    } catch (e) {
      entry.finish('Could not send: ' + e.message, 'bad');
    }
  });
  denyBtn.addEventListener('click', async () => {
    entry.sent = true;
    entry.finish('Denied', 'bad');
    await send({ type: 'deny', id: r.id }).catch(() => {});
  });
  pauseBtn.addEventListener('click', async () => {
    entry.sent = true;
    entry.finish('Denied, and requests paused for an hour', 'bad');
    localStorage.setItem(PAUSE_KEY, String(Date.now() + PAUSE_SECONDS * 1000));
    showPause(send);
    await send({ type: 'deny', id: r.id }).catch(() => {});
    await send({ type: 'pause', seconds: PAUSE_SECONDS }).catch(() => {});
  });
  return entry;
}

function onStatus(id, s) {
  const c = cards.get(id);
  if (!c || c.done) return;
  if (s.status === 'filled') c.finish('Filled ✓ ' + (s.detail || ''), 'ok');
  else if (TERMINAL.has(s.status)) c.finish(`${s.status}${s.detail ? ': ' + s.detail : ''}`, 'bad');
}

async function start(pairing, justPaired) {
  const topics = await topicsFor(pairing.k);
  const send = async (msg) => publish(pairing.server, topics.data, await seal(pairing.k, 'p2e', msg));
  app.prepend(pauseBanner);
  showPause(send);
  setInterval(() => showPause(send), 30_000);
  footer.replaceChildren(
    el('div', { class: 'muted' }, 'Push notifications: in the ntfy app, subscribe to server ', el('code', {}, pairing.server), ' topic ', el('code', {}, topics.notify), '.'),
    el('div', { class: 'btns' }, el('button', { class: 'plain', onclick: () => {
      localStorage.removeItem(PAIR_KEY);
      location.reload();
    } }, 'Unpair this phone')));

  if (justPaired) {
    app.prepend(el('div', { class: 'card' }, el('div', { class: 'status ok' }, 'Paired ✓'),
      el('div', { class: 'muted' }, 'Keep the pairing link somewhere private (for example, your password manager) in case this browser clears its storage.')));
    // Tells the extension a phone is set up, so it starts accepting login requests.
    await publish(pairing.server, topics.data, await seal(pairing.k, 'p2e', { type: 'paired' }))
      .catch((e) => app.prepend(el('div', { class: 'warn' }, `Could not reach ntfy (${e.message}). Reload to try again.`)));
  }

  const conn = el('div', { class: 'muted' }, 'Connecting…');
  app.append(conn);
  let queue = Promise.resolve();
  subscribe(pairing.server, topics.data, '15m', (text) => {
    queue = queue.then(async () => {
      const msg = await unseal(pairing.k, 'e2p', text);
      if (!msg?.id) return;
      if (msg.type === 'status') {
        statuses.set(msg.id, msg);
        onStatus(msg.id, msg);
      } else if (msg.type === 'request' && Array.isArray(msg.fields) && !cards.has(msg.id)) {
        if (TERMINAL.has(statuses.get(msg.id)?.status) || msg.expires_at < Date.now()) return;
        const entry = buildCard(pairing, topics, msg, send);
        cards.set(msg.id, entry);
        pauseBanner.after(entry.el);
      }
      emptyState();
    });
  }, (state) => {
    conn.textContent = state === 'open' ? '' : 'Reconnecting…';
    if (state === 'open') emptyState();
  });
}

if (!window.isSecureContext || !crypto.subtle) {
  app.textContent = 'This page must be opened over HTTPS.';
} else {
  const hash = location.hash;
  const fromLink = parsePairing(hash);
  // Take the key out of the address bar and history.
  if (hash) history.replaceState(null, '', location.pathname + location.search);
  if (fromLink) localStorage.setItem(PAIR_KEY, JSON.stringify(fromLink));
  const pairing = fromLink || loadPairing();
  if (pairing) start(pairing, !!fromLink);
  else showUnpaired(hash ? 'That pairing link is not valid.' : null);
}
