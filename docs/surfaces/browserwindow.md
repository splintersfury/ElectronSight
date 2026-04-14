---
title: BrowserWindow Attack Surface
description: Security-relevant BrowserWindow configuration options and their impact on attack surface
---

# BrowserWindow Attack Surface

`BrowserWindow`'s `webPreferences` object is the single most important configuration surface in an Electron app. One wrong key and the entire security model collapses — XSS becomes RCE, sandboxed renderers get Node.js, local files become readable cross-origin. It's the first place to look.

The complication: Electron's defaults have changed significantly across major versions. A lot of apps in the wild were written against Electron 4, 6, or 9 — where `contextIsolation` defaulted to `false` and `sandbox` didn't exist as a concept. Those apps have been updated in place, often without revisiting the security config they shipped with originally. The `package.json` might say Electron 28, but the `webPreferences` might still reflect 2018's defaults.

---

## The Security-Relevant webPreferences

```javascript
new BrowserWindow({
  webPreferences: {
    // CRITICAL — Controls JS world separation:
    contextIsolation: true,     // Default: true (v12+) — MUST be true
    
    // CRITICAL — Controls Node.js in renderer:
    nodeIntegration: false,     // Default: false (v5+) — MUST be false
    
    // CRITICAL — OS-level sandbox:
    sandbox: true,              // Default: true (v20+) — MUST be true
    
    // IMPORTANT — SOP enforcement:
    webSecurity: true,          // Default: true — MUST be true
    
    // IMPORTANT — Subframe Node.js:
    nodeIntegrationInSubFrames: false,  // Default: false — MUST be false
    
    // IMPORTANT — Worker Node.js:
    nodeIntegrationInWorker: false,     // Default: false — keep false
    
    // DEPRECATED — Never use:
    enableRemoteModule: false,  // Default: false (removed in v14)
    
    // IMPORTANT — Insecure content:
    allowRunningInsecureContent: false, // Default: false — keep false
    
    // REQUIRED — Bridge to main:
    preload: path.join(__dirname, 'preload.js'),
  }
});
```

---

## contextIsolation

**Default:** `true` since Electron 12

This is the one to check first. When `contextIsolation: false`, the preload and the page share a V8 context — the preload's variables, Node.js APIs, and anything on `window` or `global` are directly accessible to page JavaScript. Post-XSS, an attacker doesn't need to bypass anything; they just call what's there.

```javascript
// contextIsolation: false — DANGEROUS:
// preload.js:
global.secureAPI = { execute: (cmd) => exec(cmd) };

// renderer.js (attacker post-XSS):
secureAPI.execute('calc.exe');  // Direct access to preload's scope
window.require('child_process').exec('calc.exe');  // require available in renderer
```

The reason you still find `contextIsolation: false` in production: it was the default until Electron 12 (2021), and refactoring away from it is costly. Legacy preloads that relied on shared context need to be rewritten using `contextBridge`. Teams often defer that work indefinitely.

```bash
grep -rn "contextIsolation\s*:\s*false" --include="*.js" . | grep -v node_modules
```

---

## nodeIntegration

**Default:** `false` since Electron 5

When `true`, the renderer process has full access to Node.js APIs — `require()`, `child_process`, `fs`, all of it. There's no contextBridge to cross; XSS directly executes system commands.

```javascript
// nodeIntegration: true — DANGEROUS:
// Any JavaScript in the renderer can:
const { exec } = require('child_process');    // → RCE
const fs = require('fs');                      // → arbitrary file access
const { ipcRenderer } = require('electron');   // → direct IPC (no bridge needed)
```

This was the default until Electron 5 (2019). Signal Desktop, WhatsApp Desktop (CVE-2019-18426), Element/Matrix (CVE-2022-23597), RocketChat — all had `nodeIntegration: true` baked in from early development. The ElectroVolt research (Black Hat 2022) found `nodeIntegration: true` or effective equivalents in multiple shipping apps even years after the defaults changed. It persists because old codebases never updated the pattern, teams re-enabled it when they hit errors, and it's required by some legacy preload architectures.

```bash
grep -rn "nodeIntegration\s*:\s*true" --include="*.js" . | grep -v node_modules
```

---

## nodeIntegrationInSubFrames

**Default:** `false`

When `true`, iframes and child frames also get Node.js access. This is a force multiplier: the main frame might be locked down, but if an attacker can get any iframe loaded in the app, they get Node.js.

CVE-2022-23597 (Element Desktop) exploited exactly this — Element used `nodeIntegrationInSubFrames: true` for widget functionality, and a crafted widget URL could reach a frame with full Node.js access.

```javascript
// nodeIntegrationInSubFrames: true — DANGEROUS:
<iframe src="https://attacker-controlled-widget.com"></iframe>
// The cross-origin iframe gets require(), exec(), etc.
```

```bash
grep -rn "nodeIntegrationInSubFrames\s*:\s*true" --include="*.js" . | grep -v node_modules
```

---

## sandbox

**Default:** `true` since Electron 20

When `false`, the renderer process runs without OS-level isolation — no seccomp-BPF on Linux, no Seatbelt on macOS, no Job Objects or integrity level downgrade on Windows.

Developers disable it for a legitimate reason: native `.node` addons are incompatible with the sandbox because they need raw syscall access. But "incompatible with our native module" is a real problem that gets resolved by disabling a critical security control rather than rewriting the module. That tradeoff is often made without understanding the security implications.

Combined with `nodeIntegration: true`: full OS access from renderer. Even without `nodeIntegration`: native code execution may still be achievable via memory corruption in a compromised renderer.

```bash
grep -rn "sandbox\s*:\s*false" --include="*.js" . | grep -v node_modules
```

---

## webSecurity

**Default:** `true`

When `false`, disables Same-Origin Policy, CORS, and mixed content restrictions. Almost every instance of `webSecurity: false` in production code exists because a developer hit a CORS error and searched Stack Overflow. That's not speculation — look at the git blame when you find it, and the commit message will usually confirm it.

The concrete attack surface it opens:

```javascript
// webSecurity: false — DANGEROUS:
// Renderer can:
fetch('file:///etc/passwd')          // Read local files
fetch('http://localhost:8080/admin') // Access local services (SSRF-in-renderer)
fetch('https://internal.corp.com')  // Access internal network resources
// CORS restrictions removed → cross-origin reads succeed
```

```bash
grep -rn "webSecurity\s*:\s*false" --include="*.js" . | grep -v node_modules
```

---

## allowRunningInsecureContent

**Default:** `false`

When `true`, HTTPS pages in the renderer can load HTTP resources — scripts, stylesheets, iframes. That HTTP traffic is unencrypted, which means anyone on the same network can intercept and modify it.

```javascript
// allowRunningInsecureContent: true:
<script src="http://cdn.example.com/app.js"></script>
// → HTTP traffic → MitM on same WiFi → script replaced → renderer compromise
```

Severity is real but requires an on-path attacker. Check for it but it's not the headline finding.

---

## enableRemoteModule

**Deprecated in Electron 14, removed in Electron 15**

The `remote` module gave renderers synchronous access to the entire main process API — an architectural mistake that Electron eventually removed. But old apps may still have dead `remote.require()` calls in code paths that were never cleaned up after migration.

```javascript
// enableRemoteModule: true (old apps):
const { remote } = require('electron');
const { exec } = remote.require('child_process');
exec('calc.exe');  // RCE directly from renderer
```

```bash
grep -rn "enableRemoteModule\s*:\s*true\|remote\.require\|remote\.getCurrentWindow" \
  --include="*.js" . | grep -v node_modules
```

---

## Navigation Policies

Not `webPreferences`, but not optional either. Without navigation restrictions, a renderer with XSS can navigate itself to an attacker-controlled page — which then loads in the same Electron window with the same capabilities. Navigation is an attack primitive.

```javascript
win.webContents.on('will-navigate', (event, url) => {
  const allowedUrl = 'file://' + path.join(__dirname, 'index.html');
  if (url !== allowedUrl) {
    event.preventDefault();  // Block navigation to any other URL
  }
});

win.webContents.setWindowOpenHandler(({ url }) => {
  // Without this: window.open() creates a new BrowserWindow
  // which inherits the same webPreferences (including nodeIntegration)
  shell.openExternal(url);  // Open in browser instead
  return { action: 'deny' }; // Never create new Electron windows from renderer
});
```

---

## Complete Attack Surface Audit

```bash
# Find all BrowserWindow configurations:
grep -rn "new BrowserWindow\|webPreferences" --include="*.js" . | grep -v node_modules

# Find all dangerous settings in one grep:
grep -rn "contextIsolation\s*:\s*false\|nodeIntegration\s*:\s*true\|sandbox\s*:\s*false\|webSecurity\s*:\s*false\|enableRemoteModule\s*:\s*true\|allowRunningInsecureContent\s*:\s*true\|nodeIntegrationInSubFrames\s*:\s*true" \
  --include="*.js" . | grep -v node_modules

# Find missing navigation policies:
grep -rn "new BrowserWindow" --include="*.js" . | \
  while IFS=: read file line rest; do
    grep -q "will-navigate\|setWindowOpenHandler" "$file" || \
      echo "MISSING NAVIGATION POLICY: $file"
  done
```

---

## Risk Summary

| Setting | Default (v20+) | Dangerous Value | Impact |
|---------|---------------|-----------------|--------|
| `contextIsolation` | `true` | `false` | Preload scope exposed to renderer |
| `nodeIntegration` | `false` | `true` | Node.js in renderer → XSS = RCE |
| `sandbox` | `true` | `false` | No OS isolation |
| `webSecurity` | `true` | `false` | SOP disabled → SSRF, file read |
| `nodeIntegrationInSubFrames` | `false` | `true` | iframes get Node.js |
| `enableRemoteModule` | removed | `true` (old) | Full main process from renderer |
| `allowRunningInsecureContent` | `false` | `true` | Mixed content → MitM |
