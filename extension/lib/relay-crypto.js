// Shared by the extension, the phone page (copied to phone/ by `npm run build`)
// and the tests. Dependency-free; needs WebCrypto, fetch and WebSocket.
//
// Pairing key K (32 random bytes) is made by the extension and given to the phone
// in a QR code. From K both sides derive:
//   - two ntfy topics: `notify` (human-readable pushes, no secrets) and `data`
//   - an AES-GCM key that seals every message on the data topic, so ntfy only
//     ever stores ciphertext and nobody without K can read or forge messages.
// Passwords and codes are additionally encrypted to the extension's own ECDH
// key (pinned on the phone at pairing), so only the extension can open them.
//
// The "login-relay" labels below are protocol constants from the project's
// first name. Changing them would break every existing pairing, so they stay.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64u = (bytes) => {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
export const unb64u = (s) => {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(t + '='.repeat((4 - (t.length % 4)) % 4)), (c) => c.charCodeAt(0));
};

// ---------- pairing ----------
export const newPairingKey = () => b64u(crypto.getRandomValues(new Uint8Array(32)));

export async function topicsFor(k) {
  const key = unb64u(k);
  const input = new Uint8Array(key.length + 17);
  input.set(key);
  input.set(enc.encode('login-relay topic'), key.length);
  const id = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', input)).slice(0, 16));
  return { notify: `lr_${id}`, data: `lr_${id}_d` };
}

export function pairingLink(approveUrl, { k, server, jwk }) {
  const blob = b64u(enc.encode(JSON.stringify({ k, s: server, x: jwk.x, y: jwk.y })));
  return `${String(approveUrl).replace(/#.*$/, '')}#pair=${blob}`;
}

export function parsePairing(hash) {
  const m = /[#&]pair=([A-Za-z0-9_-]+)/.exec(hash || '');
  if (!m) return null;
  try {
    const p = JSON.parse(dec.decode(unb64u(m[1])));
    if (typeof p.k !== 'string' || unb64u(p.k).length !== 32) return null;
    if (typeof p.s !== 'string' || !/^https?:\/\//.test(p.s)) return null;
    if (typeof p.x !== 'string' || typeof p.y !== 'string') return null;
    return { k: p.k, server: p.s.replace(/\/$/, ''), jwk: { kty: 'EC', crv: 'P-256', x: p.x, y: p.y } };
  } catch {
    return null;
  }
}

// ---------- sealed envelopes on the data topic ----------
// dir is 'e2p' (extension -> phone) or 'p2e' (phone -> extension). It is bound
// into the AAD so a message can't be reflected back to its sender.
async function envelopeKey(k, usage) {
  const base = await crypto.subtle.importKey('raw', unb64u(k), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('login-relay-v2 envelope') },
    base, { name: 'AES-GCM', length: 256 }, false, [usage]);
}

export async function seal(k, dir, msg) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode('login-relay-v2|' + dir) },
    await envelopeKey(k, 'encrypt'), enc.encode(JSON.stringify(msg)));
  return JSON.stringify({ v: 2, d: dir, iv: b64u(iv), ct: b64u(ct) });
}

export async function unseal(k, dir, text) {
  try {
    const e = JSON.parse(text);
    if (e?.v !== 2 || e.d !== dir) return null;
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64u(e.iv), additionalData: enc.encode('login-relay-v2|' + dir) },
      await envelopeKey(k, 'decrypt'), unb64u(e.ct));
    return JSON.parse(dec.decode(pt));
  } catch {
    return null;
  }
}

// ---------- values encrypted to the extension's key ----------
async function valuesKey(bits, id, usage) {
  const hk = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(id), info: enc.encode('login-relay-v1') },
    hk, { name: 'AES-GCM', length: 256 }, false, [usage]);
}

export async function encryptValues(extJwk, id, domain, values) {
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const pub = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: extJwk.x, y: extJwk.y }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, eph.privateKey, 256);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // AAD binds the ciphertext to this request and domain, so it can't be replayed elsewhere.
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(id + '|' + domain) },
    await valuesKey(bits, id, 'encrypt'), enc.encode(JSON.stringify(values)));
  const epk = await crypto.subtle.exportKey('jwk', eph.publicKey);
  return { epk: { x: epk.x, y: epk.y }, iv: b64u(iv), ct: b64u(ct) };
}

export async function decryptValues(privateJwk, payload, id, domain) {
  const priv = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const pub = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: payload.epk.x, y: payload.epk.y }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64u(payload.iv), additionalData: enc.encode(id + '|' + domain) },
    await valuesKey(bits, id, 'decrypt'), unb64u(payload.ct));
  return JSON.parse(dec.decode(pt));
}

// ---------- ntfy ----------
export async function publish(server, topic, body, headers) {
  const res = await fetch(`${server}/${topic}`, { method: 'POST', body, headers });
  if (!res.ok) throw new Error(`ntfy returned ${res.status}`);
}

// Streams messages from a topic, reconnecting from the last message seen.
// `since` is anything ntfy accepts: a duration ("15m"), a unix time, or a message id.
export function subscribe(server, topic, since, onMessage, onState = () => {}) {
  let ws = null;
  let closed = false;
  let last = since;
  const open = () => {
    if (closed) return;
    ws = new WebSocket(`${server.replace(/^http/, 'ws')}/${topic}/ws?since=${encodeURIComponent(last)}`);
    ws.onopen = () => onState('open');
    ws.onmessage = (e) => {
      let m;
      try { m = JSON.parse(e.data); } catch { return; }
      if (m.event !== 'message') return;
      last = m.id;
      onMessage(m.message, m.id);
    };
    ws.onclose = () => {
      onState('closed');
      if (!closed) setTimeout(open, 3000);
    };
    ws.onerror = () => {};
  };
  open();
  return {
    close() { closed = true; ws?.close(); },
    get last() { return last; },
  };
}
