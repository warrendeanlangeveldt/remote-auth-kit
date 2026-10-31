#!/usr/bin/env node
// Claude Code hook (see hooks/hooks.json). A web page Claude reads can try to
// talk it into reading a password out of the login page. This hook is code, so
// it can't be talked round:
//   - While a login is open, and until the filled page is replaced, it refuses
//     Claude in Chrome's tools that can run scripts in a page or read its
//     network traffic.
//   - It reports every page script Claude runs to the relay, so the extension
//     can refuse to fill a page a script ran in after it loaded (a script could
//     have left a listener behind to catch the value).
//   - It refuses shell commands and edits that would get round it: scripting
//     Chrome through AppleScript, opening Chrome's debugging port, or changing
//     the installed plugin's own files.
// If no relay is running, no login can be filled, so page tools are allowed.

import path from 'node:path';

const PORT = Number(process.env.LOGIN_RELAY_PORT || 47823);
const BASE = `http://127.0.0.1:${PORT}`;
const CHROME = /^mcp__claude-in-chrome__/;
// Tools that run code in the page, and tools that can read what the page sent.
const SCRIPT_TOOLS = new Set(['javascript_tool', 'shortcuts_execute']);
const READ_TOOLS = new Set(['read_network_requests']);

const out = (decision, reason) => {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason },
  }));
};
const deny = (reason) => out('deny', `Login Relay: ${reason}`);

async function relay(method, route) {
  try {
    const res = await fetch(BASE + route, { method, signal: AbortSignal.timeout(1000) });
    return res.status === 200 ? await res.json() : res.ok ? {} : null;
  } catch {
    return null; // no relay running
  }
}

// Claude in Chrome items in this call (browser_batch carries several).
function chromeItems(name, input) {
  const short = name.replace(CHROME, '');
  if (short === 'browser_batch') {
    return (Array.isArray(input?.actions) ? input.actions : []).map((a) => ({ name: String(a?.name || '').replace(CHROME, ''), input: a?.input || {} }));
  }
  return [{ name: short, input: input || {} }];
}
const runsScript = (it) => SCRIPT_TOOLS.has(it.name) || (it.name === 'navigate' && /^\s*javascript:/i.test(String(it.input.url || '')));
const readsPage = (it) => runsScript(it) || READ_TOOLS.has(it.name);

// The installed plugin's files. A plugin loaded from a working folder (--plugin-dir)
// is being developed, so its files are left editable.
const root = process.env.CLAUDE_PLUGIN_ROOT || '';
const installed = /[\\/]\.claude[\\/]plugins[\\/]/.test(root);
const pluginFiles = /[\\/]\.claude[\\/]plugins[\\/][^\s'"]*login-relay/;
const touchesPlugin = (p) => installed && (pluginFiles.test(p) || (root && path.resolve(String(p)).startsWith(root)));

function shellBypass(cmd) {
  if (/osascript/.test(cmd) && /javascript/i.test(cmd) && /chrom/i.test(cmd)) return 'running JavaScript in Chrome through AppleScript is blocked by the Login Relay plugin';
  if (/remote-debugging-(port|pipe)/.test(cmd)) return "opening Chrome's debugging port is blocked by the Login Relay plugin";
  if (touchesPlugin(cmd) || (installed && root && cmd.includes(root))) return "the Login Relay plugin's own files can't be changed from a session it guards";
  return null;
}

const input = JSON.parse(await new Promise((resolve) => {
  let s = '';
  process.stdin.on('data', (c) => (s += c)).on('end', () => resolve(s || '{}'));
}));
const { hook_event_name: event, tool_name: name = '', tool_input: toolInput = {} } = input;

if (CHROME.test(name)) {
  const items = chromeItems(name, toolInput);
  if (event === 'PreToolUse' && items.some(readsPage)) {
    const guard = await relay('GET', '/guard');
    const hit = guard && (guard.block_all || items.some((it) => readsPage(it) && guard.tab_ids?.includes(it.input.tabId)));
    if (hit) {
      deny(`a login is in progress on ${guard.domains?.join(', ') || 'a site you allowed'}, so tools that run scripts in a page or read its network requests are paused until the login page is replaced. Use clicks, typing, read_page and screenshots in the meantime. Don't ask the user to turn this off.`);
    } else if (items.some(runsScript)) {
      await relay('POST', '/script-ran');
    }
  } else if (event !== 'PreToolUse' && items.some(runsScript)) {
    // After the tool ran: covers a batch that navigated and then ran a script.
    await relay('POST', '/script-ran');
  }
} else if (event === 'PreToolUse' && name === 'Bash') {
  const why = shellBypass(String(toolInput.command || ''));
  if (why) deny(why);
} else if (event === 'PreToolUse' && ['Edit', 'Write', 'MultiEdit', 'NotebookEdit'].includes(name)) {
  if (touchesPlugin(toolInput.file_path || toolInput.notebook_path || '')) deny("the Login Relay plugin's own files can't be changed from a session it guards");
}
