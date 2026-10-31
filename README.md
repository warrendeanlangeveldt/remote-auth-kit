# Login Relay

Login Relay lets Claude get past a browser login while you're away from your computer. Claude asks for the login, your phone shows you which site and which tab, you type the password or 2FA code on the phone, and a Chrome extension fills it into the page. Claude never receives the value; its tool call returns only a status.

It's a Claude Code plugin. The plugin runs the relay on your own computer, so there is no server to host. The phone talks to the extension through [ntfy](https://ntfy.sh), which only ever carries encrypted messages and a "Claude needs a password for apple.com" push.

```
Claude Code ──request_login("apple.com", ["password"])──► relay (local, started by the plugin)
                                                             │
                                                             ▼
Your phone ◄── sealed request + push ── ntfy ◄──────── Chrome extension: finds the tab and field,
   │ you check the domain and tab,                         checks the allowlist
   │ type the password
   └── password encrypted to the extension's key ──► ntfy ──► extension: re-checks the tab,
                                                                  decrypts, fills, submits
Claude Code ◄── {"status":"filled"} ◄── relay ◄── status only ──┘
```

## What it protects, and what it doesn't

- Claude's tool result has no field a secret could travel in. It gets `filled`, `failed`, `denied` or `expired`, with a short reason.
- The phone encrypts each value to the extension's own key (ECDH P-256, HKDF, AES-GCM, bound to the request ID and domain). The extension's public key is pinned on the phone when you pair, so a changed key can't slip in later.
- Every message on ntfy is also sealed with the pairing key that only your phone and the extension hold. Without it nobody can read the requests (including the tab URL) or forge an answer.
- The extension decides where to fill. It only fills on domains you allowlist, only in the tab and frame it found and showed you, and it checks the tab is still on that domain right before filling.
- Each request expires after 3 minutes and can be filled once.
- After submitting, the extension clears the password from the page's DOM within about 1.5 seconds, and wipes any password field still filled after 8 seconds (for example, after a wrong password).

There is one gap you should know about. Once the password is in the page, Claude in Chrome can read the field's value with JavaScript until the page submits and the field is cleared. A Claude that was manipulated by content on a web page could do that in the short window. The guarantee is that Claude never receives the secret from this tool, and that the window in which the page holds it is short. If that window is not acceptable for a site, don't allowlist that site.

## Requirements

- Claude Code with [Claude in Chrome](https://code.claude.com/docs/en/chrome), on the computer that stays at home.
- Node.js 20 or later on that computer (the plugin's relay is a Node script).
- Chrome 120 or later. Install the extension in the same Chrome profile Claude in Chrome uses, so the session cookies land where Claude browses.
- The ntfy app on your phone (iOS or Android).

## Setup

### 1. Install the plugin

```
/plugin marketplace add warrendeanlangeveldt/login-relay
/plugin install login-relay@login-relay
```

The relay starts with your Claude Code session and listens on `127.0.0.1:47823`. If you run several sessions, they share one relay. Set `LOGIN_RELAY_PORT` in your environment to use a different port, and set the same port in the extension's Relay URL.

### 2. Load the extension

Download or clone this repository, then in Chrome go to `chrome://extensions`, turn on Developer mode, choose **Load unpacked**, and pick the `extension/` folder.

Open the extension's options and set **Allowed domains**, such as `apple.com, github.com`. Logins are only filled on these domains and their subdomains.

The phone approval page defaults to the copy published from this repository at `https://warrendeanlangeveldt.github.io/login-relay/`. To use your own copy instead, see "Publishing your own approval page" below.

Leave the Relay URL empty. The status shows "connected" while a Claude Code session is running and "waiting for Claude Code" when none is.

### 3. Pair your phone

In the extension options, choose **Pair a phone** and scan the QR code with your phone's camera. The approval page opens, stores the pairing key in the browser on your phone, and tells the extension it's paired.

Then do two things on the phone:

- In the ntfy app, subscribe to the server and topic the options page shows. That's how you get the push notification.
- Use **Copy pairing link** on the computer and keep the link somewhere private on your phone, such as your password manager. Safari can clear a site's storage if you don't visit it for about a week, and the link lets you re-pair from anywhere.

Choosing Reset pairing makes a new key, and the old phone stops working until it scans the new code.

### Publishing your own approval page

Whoever controls the approval page's JavaScript could change it to send your password elsewhere. If you'd rather not trust the default copy, publish `phone/` yourself. It's a static page with no backend, so any HTTPS host works. In a fork on GitHub, turn on Settings → Pages → Source: GitHub Actions, and `.github/workflows/phone-page.yml` deploys it on every push that changes `phone/`. Then set the extension's Phone approval page URL to your copy and pair again.

## How a login goes

Taking App Store Connect as the example:

1. Claude opens appstoreconnect.apple.com in your Chrome and types your Apple ID email.
2. Claude calls `request_login(domain="apple.com", fields=["password"])`.
3. Your phone buzzes. You check it says apple.com and that the tab is `appstoreconnect.apple.com`, type the password, and tap Send.
4. Apple asks for a 2FA code, so Claude calls `request_login(domain="apple.com", fields=["otp"])`. You type the code (iOS can fill it from SMS) and tap Send.
5. Claude carries on, signed in. The session cookie persists, so you only do this again when it expires.

## Limits

- The computer must be on with Chrome open and a Claude Code session running.
- The fill rules cover standard password fields, `one-time-code` fields, and split one-box-per-digit code inputs. Unusual login pages may need a site-specific rule in `pageAgent()` in `extension/background.js`. For those, Chrome Remote Desktop from your phone is a workable fallback.
- Passkeys need you at the computer, so Login Relay can't help with them.
- `host_permissions` is `https://*/*` so you can change the allowlist without reinstalling. Narrow it in `extension/manifest.json` if you prefer.

## claude.ai and the Claude mobile app (optional)

claude.ai and the mobile app can only reach MCP servers on the internet, so using Login Relay from them needs a hosted relay. `server/hosted.js` is the same relay with MCP over HTTP behind a secret path and a token for the extension. It also serves the phone page.

```bash
for k in MCP_PATH_SECRET EXTENSION_TOKEN; do doppler secrets set $k="$(openssl rand -hex 24)"; done
fly apps create login-relay-CHANGE-ME          # and set `app` in fly.toml
doppler secrets download --no-file --format env | fly secrets import
fly deploy --ha=false
```

Then set the extension's Relay URL to `https://login-relay-CHANGE-ME.fly.dev` and its token to `EXTENSION_TOKEN`, and add `https://login-relay-CHANGE-ME.fly.dev/mcp/<MCP_PATH_SECRET>` as a custom connector in claude.ai. Request state is in memory, so run one machine.

## Tests

```bash
npm install
npm test               # protocol: Claude Code sessions, relay hand-over, ntfy, phone, hosted mode
npm run test:browser   # the real extension and phone page in Chrome for Testing, against a test login site
```

`npm test` drives the relay exactly as Claude Code starts it, with a second session sharing it and taking over when the first ends. It checks that neither the tool result nor anything sent to ntfy contains a secret. `npm run test:browser` downloads Chrome for Testing into `test/browser/.cache/` and runs the full flow: pairing by QR link, a password fill through the site's own submit handler, a split 6-digit code, deny, a tab that navigates away before you answer, and a domain outside the allowlist.

After changing `extension/lib/relay-crypto.js`, run `npm run build` to copy it to `phone/`. `npm test` fails if the copy is out of date.
