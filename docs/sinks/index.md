---
title: Sinks
description: Complete taxonomy of dangerous operations in Electron apps — where attacker-controlled data causes harm
---

# Sinks

A sink is where the damage happens. If a source is where attacker data enters the system, a sink is where that data causes a security impact — code execution, file access, privilege escalation, information leakage.

Sink severity isn't fixed. `innerHTML` in a standalone web app is a high-severity XSS. `innerHTML` in an Electron app with `nodeIntegration: true` is a critical RCE because the XSS gives you `require('child_process')`. Same sink, completely different blast radius depending on configuration.

---

## Sink Categories

<div class="es-card-grid">

<a class="es-card" href="rce.md">
<div class="es-card-title">💀 RCE Sinks</div>
<div class="es-card-desc">child_process.exec, eval, Function constructor, dynamic require, process.dlopen, vm.runInNewContext. Attacker-controlled input reaching any of these is game over.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span> <span class="badge badge-sink">SINK</span></div>
</a>

<a class="es-card" href="filesystem.md">
<div class="es-card-title">📂 File System Sinks</div>
<div class="es-card-desc">fs.writeFile to traversal paths, symlink abuse, arbitrary reads. A write-anywhere primitive gets you persistence. A read-anywhere gets you credentials and private keys.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span> <span class="badge badge-sink">SINK</span></div>
</a>

<a class="es-card" href="html-injection.md">
<div class="es-card-title">🖥️ HTML Injection Sinks</div>
<div class="es-card-desc">innerHTML, dangerouslySetInnerHTML, Markdown rendering. The starting point for XSS chains — not Critical on its own, but the prerequisite for everything that follows.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span> <span class="badge badge-sink">SINK</span></div>
</a>

<a class="es-card" href="navigation.md">
<div class="es-card-title">🔗 Navigation & Open Sinks</div>
<div class="es-card-desc">shell.openExternal with attacker URLs. On Windows: ms-msdt, search-ms, file:// executables. On macOS: file:// apps. This one gets underestimated constantly.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span> <span class="badge badge-sink">SINK</span></div>
</a>

<a class="es-card" href="ipc-escalation.md">
<div class="es-card-title">🔌 IPC Escalation Sinks</div>
<div class="es-card-desc">ipcMain handlers that call exec/spawn/openExternal with renderer input. The modern XSS→RCE path: XSS fires, calls contextBridge API, which calls privileged IPC handler.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span> <span class="badge badge-sink">SINK</span></div>
</a>

<a class="es-card" href="process-system.md">
<div class="es-card-title">⚙️ Process & System Sinks</div>
<div class="es-card-desc">process.dlopen, shell.openPath, dynamic require on filesystem paths. Often overlooked — process.dlopen bypasses require() safety entirely and loads arbitrary native code.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span> <span class="badge badge-sink">SINK</span></div>
</a>

<a class="es-card" href="crypto-secrets.md">
<div class="es-card-title">🔐 Crypto & Secrets Sinks</div>
<div class="es-card-desc">Hardcoded API keys in ASAR, TLS validation disabled, plaintext credential storage. The secrets you extract from app.asar are often immediately usable — no exploitation required.</div>
<div class="es-card-meta"><span class="badge badge-medium">MEDIUM</span> <span class="badge badge-sink">SINK</span></div>
</a>

</div>

---

## Process Context Changes Everything

The same sink has very different severity depending on which process it runs in:

```
Main process (no OS sandbox):
  child_process.exec()   → shell command runs on OS
  fs.writeFile()         → write to arbitrary paths (persistence, backdoor)
  shell.openExternal()   → OS protocol dispatch (includes RCE protocols)

Renderer process (sandboxed, but...):
  innerHTML              → XSS — but XSS leads somewhere if there's an escalation path
  eval()                 → JS execution in renderer only — unless contextIsolation: false
  shell.openExternal()   → still calls the main process under the hood
```

The classic mistake is rating a renderer-side `eval()` as Critical when the app has `nodeIntegration: false` and `contextIsolation: true`. In that configuration, `eval()` runs sandboxed JS — annoying, but not RCE. The chain stops there unless the app has over-privileged IPC handlers. Check both.

---

## Severity Matrix

| Sink | CWE | Severity | Notes |
|------|-----|----------|-------|
| `exec(userInput)` in main | CWE-78 | **Critical** | Immediate RCE |
| `eval(userInput)` | CWE-95 | **Critical** (main) / High (renderer) | Depends on where it runs |
| `require(userInput)` | CWE-706 | **Critical** | Path traversal → arbitrary module load |
| `process.dlopen(_, path)` | CWE-706 | **Critical** | Loads native code, bypasses require() |
| `shell.openExternal(url)` no validation | CWE-601 | **High** | ms-msdt, file://, search-ms → RCE |
| IPC handler → exec with renderer args | CWE-284 | **Critical** | The modern XSS→RCE path |
| `innerHTML = userInput` | CWE-79 | **High/Critical** | Critical if escalation path exists |
| `fs.writeFile(userPath, ...)` | CWE-22 | **High** | Write-anywhere → persistence |
| `fs.readFile(userPath, ...)` | CWE-22 | **High** | Read-anywhere → credential theft |
| `vm.runInNewContext(userInput)` | CWE-95 | **High** | Escapable in most real scenarios |
| `loadURL(userInput)` | CWE-601 | **High** | Loads attacker content in Electron window |
| Hardcoded API key in ASAR | CWE-798 | **High** | Extractable in 3 commands |

---

## The Five Patterns That Actually Win Bugs

### 1. exec() with Template Literal

```javascript
// main.js — ipcMain handler:
ipcMain.handle('convert', async (event, inputPath, codec) => {
  const cmd = `ffmpeg -i "${inputPath}" -c:v ${codec} output.mp4`;
  return exec(cmd);
  // inputPath = '"; calc.exe; echo "'  → shell injection
  // codec = 'libx264; rm -rf ~'        → shell injection
});
```

Find these by grepping for exec() calls that contain template literals with variables.

### 2. innerHTML Chain to IPC

```javascript
// renderer.js:
chatContainer.innerHTML += `<div>${message.body}</div>`;
// Payload: <img src=x onerror="window.api.runScript('calc.exe')">

// preload.js:
contextBridge.exposeInMainWorld('api', {
  runScript: (s) => ipcRenderer.invoke('run-script', s)
});

// main.js:
ipcMain.handle('run-script', async (event, s) => exec(s));
```

Three files. The XSS is in the renderer, the sink is in main. They're connected by the bridge.

### 3. shell.openExternal Without URL Validation

```javascript
ipcMain.handle('open-link', async (event, url) => {
  shell.openExternal(url);  // no check on url
  // url = 'ms-msdt://-id PCWDiagnostic ...' → Follina/MSDT RCE
  // url = 'file:///C:/Windows/System32/calc.exe' → executes binary
  // url = 'search-ms:query=...' → Windows search handler abuse
});
```

### 4. Path Traversal to Startup Folder Write

```javascript
ipcMain.handle('save-config', async (event, filename, content) => {
  const savePath = path.join(configDir, filename);
  fs.writeFileSync(savePath, content);
  // filename = '../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.bat'
  // content = '@start /b calc.exe'
  // → persistence on next Windows login
});
```

### 5. Hardcoded Secret in ASAR

```bash
# Three commands. Works on any Electron app:
asar extract app.asar /tmp/src/
grep -r "key\|secret\|password\|token\|api_" /tmp/src/ -i | \
  grep -E "=\s*['\"][A-Za-z0-9+/=_-]{16,}" | grep -v node_modules
```

You'd be surprised how often this turns up a Stripe live key, Twilio auth token, or AWS access key. No exploitation needed — just extraction.

---

## Finding Sinks

```bash
# RCE sinks:
grep -rn "\.exec\b\|\.execSync\|\.spawn\b\|\.spawnSync\|execFile\b" \
  --include="*.js" . | grep -v node_modules

# eval/Function:
grep -rn "\beval\s*(\|new Function\s*(\|vm\.run" \
  --include="*.js" . | grep -v node_modules

# Dynamic require:
grep -rn "require\s*([^'\"]" --include="*.js" . | grep -v node_modules

# HTML injection:
grep -rn "\.innerHTML\b\|\.outerHTML\b\|document\.write\|insertAdjacentHTML\|dangerouslySetInnerHTML" \
  --include="*.js" . | grep -v node_modules

# Navigation sinks:
grep -rn "shell\.openExternal\|window\.open\b\|\.loadURL\b" \
  --include="*.js" . | grep -v node_modules

# File system sinks:
grep -rn "writeFileSync\|writeFile\s*(\|appendFile\|unlink\b" \
  --include="*.js" . | grep -v node_modules

# IPC handlers with dangerous operations (the high-yield query):
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 15 | \
  grep -E "exec\b|spawn\b|eval\b|openExternal|writeFile|readFile" | grep -v node_modules
```
