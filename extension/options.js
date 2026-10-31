import qrcode from './vendor/qrcode.mjs';
import { pairingLink } from './lib/relay-crypto.js';

const ids = ['relayUrl', 'token', 'allowedDomains', 'ntfyServer', 'approveUrl'];
const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);
let pairingShown = false;
let wasPaired = null;

async function refresh() {
  const s = await chrome.storage.local.get([...ids, 'status', 'phonePaired']);
  for (const id of ids) if (document.activeElement !== $(id)) $(id).value = s[id] || '';
  $('status').textContent = s.status || 'unknown';
  $('phoneState').textContent = s.phonePaired ? 'Paired ✓' : 'No phone paired yet.';
  $('phoneState').className = s.phonePaired ? 'ok' : 'warn';
  if (wasPaired === false && s.phonePaired && pairingShown) hidePairing(); // the phone just checked in
  wasPaired = !!s.phonePaired;
}

function validUrl(v, { ws = false } = {}) {
  if (!v) return true;
  if (/^https:\/\//.test(v) || (ws && /^wss:\/\//.test(v))) return true;
  return /^(https?|wss?):\/\/(127\.0\.0\.1|localhost)([:/]|$)/.test(v); // local relay or local ntfy
}

$('save').addEventListener('click', async () => {
  const v = Object.fromEntries(ids.map((id) => [id, $(id).value.trim()]));
  v.relayUrl = v.relayUrl.replace(/\/$/, '');
  v.ntfyServer = v.ntfyServer.replace(/\/$/, '');
  if (!validUrl(v.relayUrl, { ws: true })) return ($('status').textContent = 'Relay URL must be https://, wss:// or on this computer');
  if (!validUrl(v.ntfyServer)) return ($('status').textContent = 'ntfy server must be https://');
  if (v.approveUrl && !/^https:\/\//.test(v.approveUrl)) return ($('status').textContent = 'Approval page URL must be https://');
  await chrome.storage.local.set(v);
  await send({ type: 'reconnect' });
  if (pairingShown) await showPairing();
  setTimeout(refresh, 1000);
});

async function showPairing() {
  const p = await send({ type: 'pairing' });
  const link = pairingLink(p.approveUrl, p);
  const qr = qrcode(0, 'M');
  qr.addData(link);
  qr.make();
  $('qr').src = qr.createDataURL(4, 4);
  $('copyLink').onclick = async () => { await navigator.clipboard.writeText(link); $('copyLink').textContent = 'Copied'; };
  $('ntfyHost').textContent = p.server;
  $('notifyTopic').textContent = p.topics.notify;
  $('pairBox').hidden = false;
  pairingShown = true;
  await send({ type: 'watch_pairing', on: true });
}

function hidePairing() {
  $('pairBox').hidden = true;
  $('qr').removeAttribute('src');
  pairingShown = false;
  send({ type: 'watch_pairing', on: false });
}

$('showPair').addEventListener('click', showPairing);
$('reset').addEventListener('click', async () => {
  await send({ type: 'reset_pairing' });
  await refresh();
  if (pairingShown) await showPairing();
});
window.addEventListener('pagehide', () => pairingShown && send({ type: 'watch_pairing', on: false }));

chrome.storage.onChanged.addListener(refresh);
refresh();
