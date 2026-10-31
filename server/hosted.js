// Hosted mode (optional): for claude.ai and the Claude mobile app, which can only
// reach MCP servers on the internet. Run it on your own host (see fly.toml) and
// add PUBLIC_URL/mcp/<MCP_PATH_SECRET> as a custom connector. Claude Code users
// don't need this: the plugin runs server/local.js on their own machine.
//
// Same hub as local mode, plus: MCP over HTTP behind a secret path, an extension
// token (the hub is public), and the phone approval page.

import express from 'express';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createRelay, attachSockets } from './hub.js';
import { buildMcp } from './mcp.js';

function required(k) {
  const v = process.env[k];
  if (!v || v.length < 24) {
    console.error(`${k} must be set and at least 24 characters`);
    process.exit(1);
  }
  return v;
}
const PORT = Number(process.env.PORT || 8080);
const MCP_PATH_SECRET = required('MCP_PATH_SECRET');
const EXTENSION_TOKEN = required('EXTENSION_TOKEN');

const relay = createRelay();
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

const mcpPath = `/mcp/${MCP_PATH_SECRET}`;
app.post(mcpPath, async (req, res) => {
  const server = buildMcp(async () => relay);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => { transport.close(); server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error('mcp error', e);
    if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'internal error' }, id: null });
  }
});
app.all(mcpPath, (_req, res) => res.status(405).set('Allow', 'POST').end());

app.get('/healthz', (_req, res) => res.json({ ok: true, extension_connected: relay.extensionConnected() }));

// Phone approval page (static; it talks only to ntfy).
const phoneDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'phone');
app.use((_req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; connect-src https: wss:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  next();
});
app.use(express.static(phoneDir));

const httpServer = http.createServer(app);
attachSockets(httpServer, relay, { extensionToken: EXTENSION_TOKEN });
httpServer.listen(PORT, () => console.log(`login-relay (hosted) listening on :${PORT}`));
