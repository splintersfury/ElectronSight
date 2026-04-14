---
title: Discord RCE Chain
description: Masato Kinugawa's complete Discord exploitation — Markdown XSS to DiscordNative preload to DANGEROUS_openExternal to cmd.exe
---

# Discord RCE Chain — Complete Technical Analysis

Masato Kinugawa is one of the most thorough XSS researchers working today — the kind of researcher who doesn't just pop an alert box and call it done. When he found an XSS in Discord's Markdown renderer, he kept pulling the thread until he had cmd.exe opening on the victim's machine through a chain that most people would have dismissed at each step.

The insight that made this work came from reading function names. Discord's native module had a function called `DANGEROUS_openExternal`. When developers name their own functions `DANGEROUS_*`, they're telling you exactly where validation might be missing.

---

## Environment

| Component | Details |
|-----------|---------|
| App | Discord Desktop (Windows) |
| Electron version | Legacy (pre-12, contextIsolation:false era) |
| Attack type | Stored XSS → preload abuse → OS execution |
| Required access | Ability to send Discord messages |
| User interaction | Zero-click — victim just opens Discord |
| Payout | $10,000 |

---

## The Chain in One Line

Crafted Discord message → Markdown renderer XSS → `window.DiscordNative` access (via contextIsolation:false) → `requireModule('discord_utils')` → `DANGEROUS_openExternal('file:///cmd.exe')` → OS executes binary.

---

## Step 1: The XSS

Discord's message rendering pipeline took message text through a Markdown processor, then inserted the resulting HTML into the DOM. The Markdown parser had a gap — certain constructs or entity sequences produced output that the parser considered safe but the browser's HTML parser treated as executable.

The result was stored XSS. Send a crafted message through Discord's API, it lands on Discord's servers, and every client that renders that message triggers the payload:

```
Attacker sends message via Discord API
         │
         └─→ Stored on Discord servers
                      │
                      └─→ Victim opens Discord
                                   │
                                   └─→ Messages fetched and rendered
                                                │
                                                └─→ XSS fires in renderer
```

This is zero-click: no link to click, no file to open. The payload fires the moment Discord loads the channel.

---

## Step 2: Why contextIsolation:false Made Everything Accessible

Discord was using an older Electron version where `contextIsolation: false` was the default. This matters enormously.

With contextIsolation *on*, a preload script's internal variables are invisible to the page. The page can only call functions the preload explicitly exported via `contextBridge.exposeInMainWorld`. An XSS in the page gets... the page's JavaScript context. Privileged — but contained.

With contextIsolation *off*, the preload runs in the *same* V8 context as the page. Anything the preload added to `window` is directly accessible from XSS. This is the older, legacy behavior, and it's what Discord had.

Discord's preload exposed a large API surface as `window.DiscordNative`. The XSS payload could call any of it.

---

## Step 3: DiscordNative.nativeModules

Among the things `DiscordNative` exposed was a module loader:

```javascript
// DiscordNative exposed on window, including:
window.DiscordNative.nativeModules.requireModule('discord_utils');
```

This loaded Discord's own native `.node` addon — a compiled binary extension, not JavaScript. Native addons run completely outside the V8 sandbox. Whatever they do, they do with full OS access.

---

## Step 4: The Name That Gave It Away

Masato extracted Discord's ASAR, found the preload, found `DiscordNative.nativeModules`, then ran strings analysis on the native `.node` module. He found: `DANGEROUS_openExternal`.

```javascript
// From discord_utils (decompiled):
// DANGEROUS_openExternal(url) {
//   shell.openExternal(url);  // no URL validation
// }
```

Discord's own developers had named this function with a warning. They knew it was risky. But knowing a function is risky doesn't fix it — and without XSS in the picture, they may have assumed only trusted code would ever call it.

---

## Step 5: The Final Payload

```javascript
// Executes via XSS in renderer:
const utils = window.DiscordNative.nativeModules.requireModule('discord_utils');
utils.DANGEROUS_openExternal('file:///C:/Windows/System32/cmd.exe');
```

`shell.openExternal` passes the URL to Windows' shell handler. Windows sees a `file://` URL pointing to an executable. It opens cmd.exe as the victim user.

---

## The Full Chain

```
Attacker's crafted Discord message
        │  (sent via Discord API, stored server-side)
        ▼
Victim opens Discord, navigates to channel
        │  (Discord fetches messages, renders via Markdown processor)
        ▼
XSS payload executes in renderer
        │  (contextIsolation:false → preload vars directly accessible)
        ▼
window.DiscordNative.nativeModules.requireModule('discord_utils')
        │  (loads native .node module — outside V8 sandbox)
        ▼
DANGEROUS_openExternal('file:///C:/Windows/System32/cmd.exe')
        │  (no URL validation in the function)
        ▼
shell.openExternal → Windows shell → cmd.exe opens
```

---

## Masato's Methodology

The interesting part isn't just the vulnerability — it's how he found it:

1. **Extract the ASAR** and read the preload script first
2. **Catalog what DiscordNative exposes** — flag broad APIs for deeper investigation
3. **Grep for danger signals** — `DANGEROUS`, `unsafe`, `_raw`, `_internal` in native modules
4. **Find the XSS** — Discord's Markdown renderer was the entry point
5. **Chain them** — XSS access → `DiscordNative` → `DANGEROUS_openExternal` → OS execution

The grep that probably found it:

```bash
strings discord_utils.node | grep -i "DANGEROUS\|exec\|spawn\|open"
```

The lesson isn't just "check for functions named DANGEROUS." It's: **developers annotate their own security concerns in code.** When they're worried about something, they often say so in comments, in naming conventions, in internal documentation. Reading their warnings literally is often the fastest path to finding what's exploitable.

---

## Finding Similar Patterns

```bash
# Self-documented dangerous functions:
grep -r "DANGEROUS_\|unsafe_\|_raw\|_internal" --include="*.js" . | grep -v node_modules

# Native module loading exposed to renderer:
grep -r "requireModule\|loadNative\|nativeModules\|dlopen\|bindings" \
  --include="*.js" . | grep -v node_modules

# Strings analysis on all .node files:
for f in $(find . -name "*.node" 2>/dev/null); do
  echo "=== $f ==="
  strings "$f" | grep -iE "exec|spawn|open|shell|cmd|dangerous" | head -10
done

# Where does the app expose native functionality to the renderer?
grep -r "exposeInMainWorld" --include="*.js" . -A 30 | \
  grep -E "require\b|nativeModule|dlopen|node_modules" | grep -v "^--"
```

Any Electron app that loads native `.node` addons and exposes their functions through the contextBridge is worth examining closely. The JavaScript validation can look fine while the native layer does whatever it wants underneath.
