// The two MCP tools Claude sees. `relay` is anything with
//   create(args) -> view        and        wait(id, ms) -> view | null
// (the in-process hub, or a client forwarding to the hub in another session).
// A view only ever carries a status; there is no field a secret could travel in.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

const TOOL_WAIT_MS = Number(process.env.TOOL_WAIT_SECONDS || 100) * 1000;

export function buildMcp(getRelay) {
  const server = new McpServer({ name: 'remote-auth-kit', version: '0.3.0' });
  const text = (v) => ({ content: [{ type: 'text', text: JSON.stringify(v) }] });
  const error = (message) => ({ isError: true, content: [{ type: 'text', text: message }] });

  server.registerTool(
    'request_login',
    {
      title: 'Request a login from the user',
      description:
        "Use when a tab in the user's Chrome is showing a password or verification-code (OTP/2FA) field you need filled. " +
        'First type the username/email yourself and advance to the step that shows the field. ' +
        'The user gets a phone notification showing the domain and the exact tab the Remote Auth Kit extension found, enters the value on their phone, ' +
        'and the extension fills it (and submits by default) directly in the page. You never receive the values; the result is only a status. ' +
        'Call once per step (e.g. password, then again for the 2FA code). If the status is still awaiting_user or submitted, call login_status. ' +
        'Never ask the user to type passwords or codes into the chat, and do not read password fields back out of the page. ' +
        'Do not run JavaScript on the login page: the extension refuses to fill a page a script ran in after it loaded (reload it and ask again), ' +
        'and page-script tools are paused while a login is in progress. If the result says requests are paused or rate-limited, stop and tell the user rather than retrying.',
      inputSchema: {
        domain: z.string().describe('Registrable domain of the login page, e.g. "apple.com" for appstoreconnect.apple.com / idmsa.apple.com'),
        fields: z.array(z.enum(['password', 'otp'])).min(1).describe('Which fields are visible on the current step'),
        note: z.string().max(140).optional().describe('Short context shown to the user, e.g. "App Store Connect - upload build 1.4.2"'),
        submit: z.boolean().optional().describe('Submit after filling (default true)'),
      },
    },
    async (args) => {
      try {
        const relay = await getRelay();
        const created = await relay.create(args);
        return text((await relay.wait(created.request_id, TOOL_WAIT_MS)) || created);
      } catch (e) {
        return error(e.message);
      }
    },
  );

  server.registerTool(
    'login_status',
    {
      title: 'Check a login request',
      description: 'Wait for (up to ~60s) and return the status of a request_login call. Never returns secret values.',
      inputSchema: { request_id: z.string() },
    },
    async ({ request_id }) => {
      try {
        const v = await (await getRelay()).wait(request_id, Math.min(TOOL_WAIT_MS, 60_000));
        return v ? text(v) : error('unknown or expired request_id');
      } catch (e) {
        return error(e.message);
      }
    },
  );

  return server;
}
