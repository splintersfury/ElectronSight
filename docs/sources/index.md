---
title: Sources
description: Complete taxonomy of attacker-controlled input in Electron apps — where taint originates
---

# Sources

A source is wherever attacker-controlled data enters the application. It's the starting point of every vulnerability chain. You can know every dangerous operation in a codebase, but without knowing where the attacker can inject data, you can't build a chain — you just have a list of potentially dangerous functions.

Electron apps have more sources than web apps. The main process can read files, environment variables, and command-line arguments. The renderer can receive data from the network, from storage, from IPC callbacks, from protocol handlers, from `postMessage`. The attack surface is wider because the app straddles both worlds.

---

## Source Categories

<div class="es-card-grid">

<div class="es-card">
<div class="es-card-title">🌐 URL & Navigation</div>
<div class="es-card-desc">URL parameters, hash fragments, custom protocol parameters (`myapp://`), navigation events. Custom protocols are cross-origin invocable — any website can trigger them.</div>
<div class="es-card-meta"><span class="badge badge-source">SOURCE</span> <span class="badge badge-high">HIGH</span></div>
</div>

<div class="es-card">
<div class="es-card-title">📨 DOM & Messaging</div>
<div class="es-card-desc">postMessage, BroadcastChannel, WebSocket messages. The killer: apps often forget to check `event.origin` before acting on postMessage data.</div>
<div class="es-card-meta"><span class="badge badge-source">SOURCE</span> <span class="badge badge-high">HIGH</span></div>
</div>

<div class="es-card">
<div class="es-card-title">💾 Storage (Stored XSS)</div>
<div class="es-card-desc">localStorage, IndexedDB, userData config files. Data written by an earlier XSS payload becomes a source the next time the app reads it. The time delay makes these easy to miss.</div>
<div class="es-card-meta"><span class="badge badge-source">SOURCE</span> <span class="badge badge-critical">CRITICAL</span></div>
</div>

<div class="es-card">
<div class="es-card-title">🌍 Network</div>
<div class="es-card-desc">Server responses, auto-updater YAML, WebSocket events. If the update server is HTTP or the response isn't validated, network data is fully attacker-controlled.</div>
<div class="es-card-meta"><span class="badge badge-source">SOURCE</span> <span class="badge badge-high">HIGH</span></div>
</div>

<div class="es-card">
<div class="es-card-title">📁 File System</div>
<div class="es-card-desc">User-opened files, config files from userData, watched directories. Opening a malicious project file is a common social engineering vector for Electron apps.</div>
<div class="es-card-meta"><span class="badge badge-source">SOURCE</span> <span class="badge badge-medium">MEDIUM</span></div>
</div>

<div class="es-card">
<div class="es-card-title">🔌 IPC Callbacks</div>
<div class="es-card-desc">Data sent from main process back to renderer via `webContents.send`. If main fetched it from the network or config, it's tainted data arriving in renderer-land.</div>
<div class="es-card-meta"><span class="badge badge-source">SOURCE</span> <span class="badge badge-high">HIGH</span></div>
</div>

<div class="es-card">
<div class="es-card-title">⚙️ Environment & CLI</div>
<div class="es-card-desc">process.env, process.argv, NODE_OPTIONS. If the fuses aren't set, an attacker who can set env variables before launch has pre-renderer code execution.</div>
<div class="es-card-meta"><span class="badge badge-source">SOURCE</span> <span class="badge badge-medium">MEDIUM</span></div>
</div>

<div class="es-card">
<div class="es-card-title">📡 Side Channels</div>
<div class="es-card-desc">Clipboard, SharedArrayBuffer timing, resource timing API. Lower impact individually but useful as primitives or for information disclosure.</div>
<div class="es-card-meta"><span class="badge badge-source">SOURCE</span> <span class="badge badge-low">LOW</span></div>
</div>

</div>

---

## Tracing the Taint

The goal is to follow the data from where it enters to where it causes harm. At each step, the question is: is the data still attacker-controlled?

<div class="es-flow">
  <div class="es-flow-box es-flow-source">Source<br><code>fetch(url).then(r => r.json())</code></div>
  <div class="es-flow-arrow">→</div>
  <div class="es-flow-box es-flow-taint">Propagation<br><code>data.message → state → template</code></div>
  <div class="es-flow-arrow">→</div>
  <div class="es-flow-box es-flow-sink">Sink<br><code>element.innerHTML = data.message</code></div>
</div>

A `JSON.parse()` doesn't sanitize — the resulting object is just as tainted as the string. A `toString()` doesn't sanitize. An intermediate variable doesn't sanitize. Taint clears only when data goes through something that actually validates or encodes it for the specific sink it's heading to.

Things that look like sanitization but aren't:
- `JSON.stringify()` → then using that JSON in a `script` tag context
- `escape()` or `encodeURIComponent()` → then using in innerHTML
- Checking `typeof x === 'string'` → the string can still contain `<script>alert(1)</script>`
- Length limiting → still XSS payload, just shorter

---

## Taint Flow Examples

| Source | Typical Path | Where It Bites |
|--------|-------------|----------------|
| `location.hash` | hash → router → template | innerHTML with route fragment |
| `fetch()` response | JSON → React state → Markdown render | Markdown → innerHTML |
| `localStorage.getItem()` | stored payload → display | Earlier XSS wrote it; now it renders |
| `ipcRenderer.on` callback | main → renderer → DOM update | Network data laundered through IPC |
| `process.env.VAR` | env → config → shell command | Template literal in `exec()` call |
| File dialog result | file → parse → display | YAML `!!js/function` or JSON → template |
| `postMessage` (no origin check) | any frame → app logic | Frame injects into page logic |

---

## The Patterns That Pay Off

### Stored XSS Sources

This is the highest-value source pattern because the impact is often zero-click. One user's data, rendered for another (or stored and rendered later), creates the XSS — no interaction with the attacker required at render time.

```javascript
// Phase 1 — attacker's message is stored:
const messages = await api.getMessages();   // network fetch
localStorage.setItem('msgs', JSON.stringify(messages));  // written to storage

// Phase 2 — another session renders it:
const msgs = JSON.parse(localStorage.getItem('msgs'));   // read from storage
msgs.forEach(m => chatDiv.innerHTML += m.content);       // XSS fires here
```

Slack's $30,000 zero-click followed this pattern exactly. A malicious workspace name stored in one place, rendered in another, fired XSS in every client that connected to that workspace.

### Protocol Handler Sources

Custom protocols (`myapp://`) are cross-origin invocable — any webpage can trigger them:

```javascript
// A website the victim visits:
<a href="myapp://open?file=../../.ssh/id_rsa">Click here</a>

// The app's protocol handler:
app.on('open-url', (event, url) => {
  const file = new URL(url).searchParams.get('file');  // fully attacker-controlled
  openFile(file);  // path traversal
});
```

No XSS needed. The source is the URL scheme itself.

### IPC Callbacks as Re-Entry Source

Data flowing from main process back into renderer via IPC is often forgotten:

```javascript
// main.js — fetches from network and sends to renderer:
const config = await fetch('https://api.myapp.com/config').then(r => r.json());
mainWindow.webContents.send('config-loaded', config);  // ← source re-enters renderer

// renderer.js:
ipcRenderer.on('config-loaded', (event, config) => {
  welcomeDiv.innerHTML = `Welcome to ${config.productName}`;  // sink
});
```

If the API server is compromised, or served over HTTP (MITM), the config is attacker-controlled. The fact that it came from "the main process" doesn't make it trusted.

---

## Finding Sources Quickly

```bash
# URL parameter reads:
grep -rn "location\.\(href\|hash\|search\|pathname\)\|URLSearchParams\|searchParams\.get" \
  --include="*.js" . | grep -v node_modules

# postMessage listeners (check for origin validation):
grep -rn "addEventListener.*message\|addEventListener.*'message'" \
  --include="*.js" . | grep -v node_modules

# Storage reads:
grep -rn "localStorage\.getItem\|sessionStorage\.getItem\|getAll\|openDB" \
  --include="*.js" . | grep -v node_modules

# Network response handling:
grep -rn "\.json()\|\.text()\|response\.data\b" \
  --include="*.js" . | grep -v node_modules

# IPC callbacks to renderer:
grep -rn "webContents\.send\|ipcRenderer\.on\b" \
  --include="*.js" . | grep -v node_modules

# Environment and CLI:
grep -rn "process\.env\.\|process\.argv\[" \
  --include="*.js" . | grep -v node_modules

# Custom protocol handlers:
grep -rn "protocol\.handle\|setAsDefaultProtocolClient\|open-url" \
  --include="*.js" . | grep -v node_modules
```
