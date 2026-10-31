# Remote Auth Kit

Remote Auth Kit lets Claude get past a browser login while you're away from your computer. Claude asks for the login, your phone shows you which site and which tab, you type the password or 2FA code on the phone, and a Chrome extension fills it into the page. Claude never receives the value; its tool call returns only a status.

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

Your password goes from your phone to the login page, and nowhere else in readable form. Nothing fills without you approving it on your phone.

- Claude's tool result has no field a secret could travel in. It gets `filled`, `failed`, `denied` or `expired`, with a short reason.
- The phone encrypts each value to the extension's own key (ECDH P-256, HKDF, AES-GCM, bound to the request ID and domain). The extension's public key is pinned on the phone when you pair, so a changed key can't slip in later.
- Every message on ntfy is also sealed with the pairing key that only your phone and the extension hold. Without it nobody can read the requests (including the tab URL) or forge an answer.
- The extension decides where to fill. It only fills on the exact hostnames you allow, only in the tab and frame it found and showed you, and it checks that frame is still on the same host right before filling.
- Each request expires after 3 minutes and can be filled once. Only one request waits on your phone at a time, and at most 6 reach it in any 15 minutes.
- On a plain HTML login form, the extension fills, submits and clears the field in one step, so nothing else on the page ever sees the field with the password in it. Where the site's own script handles the submit, it may read the field only after other work such as a bot check, so the password stays in the field until the page moves on, or for at most 30 seconds. During that time the hook refuses the tools that read or change form fields in that tab.

The page itself is where the risk sits. The password has to be in the page for the site to receive it, and Claude in Chrome can run scripts in pages. A Claude that was manipulated by something it read on a web page could try to read the field, or leave a script on the login page to catch the value when it arrives. The plugin closes that off in three ways:

- The plugin's hook (`hooks/guard.js`) runs before every Claude in Chrome tool call. While a login is open, and until the filled page is replaced, it refuses the tools that can run scripts in a page or read its network requests, in every tab. After 3 minutes it narrows to the filled tab, which stays guarded until that page is replaced. Clicks, typing and screenshots still work, and password fields show as dots in screenshots. In the filled tab, `read_page`, `get_page_text`, `find` and `form_input` are refused too, until the page is replaced.
- The hook records every page script Claude runs, and the extension won't fill a page that a script ran in after it loaded. Claude has to reload the login page and ask again, which clears anything a script left behind.
- The hook also refuses the obvious ways round it: scripting Chrome through AppleScript, opening Chrome's debugging port, and editing the installed plugin's own files.

The approval page on your phone is the other thing you have to trust. Whoever controls its code could change it to send your password elsewhere. The extension ships with the SHA-256 digests of the approval page versions it trusts, and checks the published page against them before every request and every 6 hours. If the page has changed, it refuses logins and sends your phone a warning not to type passwords into it. GitHub Pages serves the same files to everyone, so a changed page can't show the extension one version and your phone another. A self-hosted page could, which is one reason to keep the default unless you run your own copy end to end.

What's left: the hook only runs in Claude Code, so it doesn't guard Claude in Chrome driven from claude.ai or the desktop app (which can't use the local plugin anyway). On sites whose own script keeps the password in memory after submitting, that memory is only cleared when the page is replaced. The filled tab stays guarded until then, but that part of the guard assumes Claude in Chrome uses the same Chrome tab IDs as this extension. Both are extensions in the same browser, so they should, but the tests can't run Claude in Chrome to confirm it. The shell checks match command text, so they stop the obvious routes rather than every possible one.

## Requirements

- Claude Code with [Claude in Chrome](https://code.claude.com/docs/en/chrome), on the computer that stays at home.
- Node.js 20 or later on that computer (the plugin's relay is a Node script).
- Chrome 120 or later. Install the extension in the same Chrome profile Claude in Chrome uses, so the session cookies land where Claude browses.
- The ntfy app on your phone (iOS or Android).

## Setup

### 1. Install the plugin

```
/plugin marketplace add warrendeanlangeveldt/remote-auth-kit
/plugin install remote-auth-kit@remote-auth-kit
```

The relay starts with your Claude Code session and listens on `127.0.0.1:47823`. If you run several sessions, they share one relay. Set `REMOTE_AUTH_KIT_PORT` in your environment to use a different port, and set the same port in the extension's Relay URL.

### 2. Load the extension

Download or clone this repository, then in Chrome go to `chrome://extensions`, turn on Developer mode, choose **Load unpacked**, and pick the `extension/` folder.

Open the extension's options and set **Allowed sites**: the exact hostnames that show the login fields, such as `idmsa.apple.com, github.com`. If you aren't sure which host a site uses, ask for a login anyway: the failure names the host to add. `*.apple.com` allows apple.com and every subdomain, which is only safe where nobody else can host pages on a subdomain. `*.google.com`, for example, includes sites.google.com, where anyone can publish a page.

The phone approval page defaults to the copy published from this repository at `https://warrendeanlangeveldt.github.io/remote-auth-kit/`. To use your own copy instead, see "Publishing your own approval page" below.

Leave the Relay URL empty. The status shows "connected" while a Claude Code session is running and "waiting for Claude Code" when none is.

### 3. Pair your phone

In the extension options, choose **Pair a phone** and scan the QR code with your phone's camera. The approval page opens, stores the pairing key in the browser on your phone, and tells the extension it's paired.

Then do two things on the phone:

- In the ntfy app, subscribe to the server and topic the options page shows. That's how you get the push notification.
- Use **Copy pairing link** on the computer and keep the link somewhere private on your phone, such as your password manager. Safari can clear a site's storage if you don't visit it for about a week, and the link lets you re-pair from anywhere.

Choosing Reset pairing makes a new key, and the old phone stops working until it scans the new code.

If requests start arriving that you didn't expect, tap "Deny and pause requests for an hour" on the phone. The extension refuses new requests until then without notifying you, and Claude is told to stop and tell you. Resume early from the banner on the phone or from the extension's options.

### Publishing your own approval page

Whoever controls the approval page's JavaScript could change it to send your password elsewhere. If you'd rather not trust the default copy, publish `phone/` yourself. It's a static page with no backend, so any HTTPS host works. In a fork on GitHub, turn on Settings → Pages → Source: GitHub Actions, and `.github/workflows/phone-page.yml` deploys it on every push that changes `phone/`. Then set the extension's Phone approval page URL to your copy and pair again. The extension checks your copy against the same digests, so publish `phone/` unchanged, or change it and load the extension from your fork after running `npm run build`.

### Changing the phone page

`npm run build` adds the digest of the current `phone/` files to `extension/lib/phone-pins.js`, keeping the last few, and `npm test` fails if it's missing. Extensions people already have only trust the versions they shipped with, so release the extension with the new pin first and publish the changed page after it has rolled out. Publishing the page first makes every installed extension refuse logins until it updates.

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
- Passkeys need you at the computer, so Remote Auth Kit can't help with them.
- `host_permissions` is `https://*/*` so you can change the allowed sites without reinstalling. Narrow it in `extension/manifest.json` if you prefer.
- With a hosted relay (below), the hook can't see the relay, so the script guard doesn't apply. The exact-host, page-pin and rate checks in the extension still do.

## claude.ai and the Claude mobile app (optional)

claude.ai and the mobile app can only reach MCP servers on the internet, so using Remote Auth Kit from them needs a hosted relay. `server/hosted.js` is the same relay with MCP over HTTP behind a secret path and a token for the extension. It also serves the phone page.

```bash
for k in MCP_PATH_SECRET EXTENSION_TOKEN; do doppler secrets set $k="$(openssl rand -hex 24)"; done
fly apps create remote-auth-kit-CHANGE-ME          # and set `app` in fly.toml
doppler secrets download --no-file --format env | fly secrets import
fly deploy --ha=false
```

Then set the extension's Relay URL to `https://remote-auth-kit-CHANGE-ME.fly.dev` and its token to `EXTENSION_TOKEN`, and add `https://remote-auth-kit-CHANGE-ME.fly.dev/mcp/<MCP_PATH_SECRET>` as a custom connector in claude.ai. Request state is in memory, so run one machine.

## Tests

```bash
npm install
npm test               # protocol: Claude Code sessions, relay hand-over, ntfy, phone, hosted mode
npm run test:browser   # the real extension and phone page in Chrome for Testing, against a test login site
```

`npm test` drives the relay exactly as Claude Code starts it, with a second session sharing it and taking over when the first ends. It runs the hook as Claude Code does, before and during a login, and checks that neither the tool result nor anything sent to ntfy contains a secret.

`npm run test:browser` downloads Chrome for Testing into `test/browser/.cache/` and runs the real extension and phone page against a test login site:

- pairing by QR link
- a password filled through the site's own submit handler, and a split 6-digit code
- a plain HTML form where a script polling the field never sees the password
- deny, deny and pause, resume, one request at a time, and the rate limit
- a tab that navigates away before you answer
- an unlisted subdomain
- a page a script ran in after it loaded
- the hook guard with real tab IDs
- a changed approval page

After changing `extension/lib/relay-crypto.js` or anything in `phone/`, run `npm run build`. `npm test` fails if a copy or the phone page pin is out of date.
