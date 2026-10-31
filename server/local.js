#!/usr/bin/env node
// Local mode: Claude Code starts this over stdio (see .mcp.json). Nothing is hosted.
//
// The extension connects to ws://127.0.0.1:<port>/ext. Several Claude Code
// sessions can run at once, so the first one to bind the port becomes the hub
// and the others forward their tool calls to it over /peer. When the hub's
// session ends, another session takes the port over and the extension reconnects.
// stdout belongs to the MCP protocol: log to stderr only.

import http from 'node:http';
import crypto from 'node:crypto';
import WebSocket from 'ws';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createRelay, attachSockets } from './hub.js';
import { buildMcp } from './mcp.js';

const PORT = Number(process.env.LOGIN_RELAY_PORT || 47823);
const HOST = '127.0.0.1';
const log = (...a) => console.error(new Date().toISOString().slice(17, 23), '[login-relay]', ...a);

let backend = null; // { create, wait }
let lastError = null;
const readyWaiters = new Set();
const setBackend = (b) => { backend = b; if (b) { lastError = null; [...readyWaiters].forEach((w) => w()); } };

function getRelay() {
  if (backend) return Promise.resolve(backend);
  return new Promise((resolve, reject) => {
    const done = () => { clearTimeout(timer); readyWaiters.delete(done); backend ? resolve(backend) : reject(new Error(lastError || 'login relay is still starting, try again')); };
    const timer = setTimeout(done, 5000);
    readyWaiters.add(done);
  });
}

function becomeHub() {
  return new Promise((resolve, reject) => {
    const relay = createRelay({ log });
    const json = (res, v) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };
    const server = http.createServer((req, res) => {
      if (req.url === '/healthz') return json(res, { ok: true, extension_connected: relay.extensionConnected() });
      // For hooks/guard.js only. Browsers always send an Origin header on these
      // requests, so requiring none keeps web pages from reading or setting them.
      if (req.headers.origin === undefined) {
        if (req.method === 'GET' && req.url === '/guard') return json(res, relay.guardState());
        if (req.method === 'POST' && req.url === '/script-ran') { relay.scriptRan(); return res.writeHead(204).end(); }
      }
      res.writeHead(404).end();
    });
    attachSockets(server, relay, { allowPeers: true, log });
    server.once('error', (e) => { relay.close(); reject(e); });
    server.listen(PORT, HOST, () => resolve(relay));
  });
}

function becomePeer() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://${HOST}:${PORT}/peer`);
    const calls = new Map();
    const call = (method, params) => new Promise((res, rej) => {
      if (ws.readyState !== 1) return rej(new Error('lost the connection to the login relay hub, try again'));
      const rid = crypto.randomUUID();
      calls.set(rid, { res, rej });
      ws.send(JSON.stringify({ type: 'rpc', rid, method, params }));
    });
    ws.on('message', (data) => {
      let msg;
      try { msg = JSON.parse(data.toString()); } catch { return; }
      const c = msg.type === 'rpc_result' && calls.get(msg.rid);
      if (!c) return;
      calls.delete(msg.rid);
      msg.error ? c.rej(new Error(msg.error)) : c.res(msg.result);
    });
    ws.once('open', () => resolve({
      create: (args) => call('create', args),
      wait: (id, ms) => call('wait', { id, ms }),
      onClose: (fn) => ws.on('close', fn),
    }));
    ws.on('close', () => {
      for (const c of calls.values()) c.rej(new Error('the login relay hub restarted; call request_login again'));
      calls.clear();
    });
    ws.on('error', reject);
  });
}

async function elect() {
  try {
    setBackend(await becomeHub());
    log(`hub listening on ${HOST}:${PORT}`);
    return;
  } catch (e) {
    if (e.code !== 'EADDRINUSE') {
      lastError = `could not start the login relay on port ${PORT}: ${e.message}`;
      log(lastError);
      return setTimeout(elect, 5000);
    }
  }
  try {
    const peer = await becomePeer();
    setBackend(peer);
    log(`forwarding to the hub on port ${PORT}`);
    peer.onClose(() => {
      setBackend(null);
      setTimeout(elect, 100 + Math.random() * 400);
    });
  } catch (e) {
    lastError = `port ${PORT} is in use by something other than Login Relay (set LOGIN_RELAY_PORT to change it)`;
    log(lastError, e.message);
    setTimeout(elect, 2000);
  }
}

await elect();
await buildMcp(getRelay).connect(new StdioServerTransport());
process.stdin.on('close', () => process.exit(0));
