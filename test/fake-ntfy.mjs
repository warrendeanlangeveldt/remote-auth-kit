// Minimal ntfy server for tests: POST /<topic> publishes, /<topic>/ws streams
// (with ?since= replay of cached messages). Keeps every body it saw so tests can
// assert nothing secret ever reached it.
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';

export function startFakeNtfy({ tls, host = '127.0.0.1' } = {}) {
  const messages = []; // { id, time, topic, message, headers }
  const subs = new Set(); // { topic, ws }
  const handler = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (req.method === 'OPTIONS') { res.setHeader('Access-Control-Allow-Headers', '*'); return res.end(); }
    const topic = req.url.slice(1).split('?')[0];
    if (req.method !== 'POST' || !/^[\w-]+$/.test(topic)) { res.writeHead(404); return res.end(); }
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const m = { id: crypto.randomBytes(6).toString('hex'), time: Math.floor(Date.now() / 1000), event: 'message', topic, message: body };
      messages.push({ ...m, headers: { title: req.headers.title, click: req.headers.click } });
      for (const s of subs) if (s.topic === topic && s.ws.readyState === 1) s.ws.send(JSON.stringify(m));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(m));
    });
  };
  const server = tls ? https.createServer(tls, handler) : http.createServer(handler);
  const wss = new WebSocketServer({ server });
  wss.on('connection', (ws, req) => {
    const u = new URL(req.url, 'http://x');
    const [, topic, kind] = u.pathname.split('/');
    if (kind !== 'ws') return ws.close();
    const since = u.searchParams.get('since') || '';
    let from = Infinity;
    if (/^\d+[smh]$/.test(since)) from = Date.now() / 1000 - Number(since.slice(0, -1)) * { s: 1, m: 60, h: 3600 }[since.slice(-1)];
    else if (/^\d+$/.test(since)) from = Number(since);
    ws.send(JSON.stringify({ event: 'open', topic }));
    const cached = messages.filter((m) => m.topic === topic);
    const idx = cached.findIndex((m) => m.id === since);
    const replay = idx >= 0 ? cached.slice(idx + 1) : cached.filter((m) => m.time >= from);
    for (const { headers, ...m } of replay) ws.send(JSON.stringify(m));
    const sub = { topic, ws };
    subs.add(sub);
    ws.on('close', () => subs.delete(sub));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    url: `${tls ? 'https' : 'http'}://${host}:${server.address().port}`,
    messages,
    close: () => { for (const c of wss.clients) c.terminate(); server.close(); },
  })));
}
