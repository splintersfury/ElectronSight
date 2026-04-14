---
title: Preload Scripts
description: Preload script execution model, scope, contextBridge patterns, and security attack vectors
---

# Preload Scripts

The preload script is the most important file in an Electron app's security model. It runs in the renderer process before the page loads, with access to both Node.js APIs and the DOM. It's where the developer decides what the untrusted web page is allowed to do with privileged functionality. Get it right and you have a real security boundary. Get it wrong and XSS goes straight to the main process.

From an auditing perspective, the preload script is almost always the first file you should read. It tells you the entire attack surface in one place — every API the renderer can reach, every IPC channel it can invoke, every dangerous operation it might accidentally expose.

---

## Execution Order

```javascript
// BrowserWindow configuration
const win = new BrowserWindow({
  webPreferences: {
    preload: path.join(__dirname, 'preload.js'),  // the bridge
    contextIsolation: true,   // separate V8 worlds
    sandbox: true,            // OS sandbox
    nodeIntegration: false    // page cannot require()
  }
});
```

What actually happens when a window opens:

1. Electron spawns the renderer process
2. Chromium initializes
3. **Preload script executes** — in World 999, with limited Node.js access
4. Web page HTML begins loading
5. Page JS executes — in World 0, no Node.js, no access to preload's internal variables
6. Page JS can only reach whatever the preload explicitly exposed via `contextBridge`

That last point is the key: with `contextIsolation: true`, the preload's internal scope is completely invisible to the page. The page can only call functions the preload deliberately put on `window` via `contextBridge.exposeInMainWorld`. The bridge is the entire attack surface.

With `contextIsolation: false` — legacy behavior, still found in older apps — that isolation goes away. The preload's `window` variables are the page's `window` variables. XSS can call anything the preload defined.

---

## What Preloads Can Access

```javascript
// preload.js — available APIs:
const { contextBridge, ipcRenderer, shell } = require('electron');
const fs = require('fs');        // Node.js fs (limited by sandbox)
const path = require('path');

process.platform    // 'win32', 'darwin', 'linux'
process.versions    // electron, node, chrome versions
process.env         // environment variables — dangerous to expose
```

`sandbox: true` limits this further — `child_process` is blocked, some `fs` operations may be restricted. `sandbox: false` gives the preload fuller Node.js access but reduces OS-level isolation if the renderer is compromised.

---

## The Correct Pattern

A secure preload is deliberately narrow. Every function it exposes should be a specific, typed operation — not a generic "call whatever IPC channel you want" relay:

```javascript
// preload.js — the right approach
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Expose only what the page actually needs:
  platform: process.platform,
  
  // Named operations — not raw IPC access:
  openFileDialog: () => ipcRenderer.invoke('dialog:open-file'),
  
  saveData: (key, value) => {
    // Validate here AND in the ipcMain handler:
    if (typeof key !== 'string' || key.length > 64) return;
    if (typeof value !== 'string' || value.length > 10000) return;
    return ipcRenderer.invoke('storage:set', { key, value });
  },
  
  onUpdateAvailable: (callback) => {
    if (typeof callback !== 'function') return;
    ipcRenderer.on('update-available', (_event, info) => callback(info));
  }
});
```

Note that validation in the preload still isn't enough on its own — an XSS attacker who finds a direct path to `ipcRenderer.invoke` bypasses preload validation entirely. But narrow exposure at least limits what's reachable.

---

## The Anti-Patterns That Show Up Everywhere

### Anti-Pattern 1: Exposing ipcRenderer Directly

The most common and most dangerous mistake:

```javascript
// preload.js — VULNERABLE
const { contextBridge, ipcRenderer } = require('electron');

// Variant A: expose the whole object
contextBridge.exposeInMainWorld('ipc', ipcRenderer);

// Variant B: expose a relay that accepts arbitrary channels
contextBridge.exposeInMainWorld('ipc', {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args)
});
```

Either way, XSS in the page can now call any registered `ipcMain` handler with any data. The renderer is effectively just reading the bundled JS to find handler names, then invoking them.

**Real-world example:** Discord's old preload exposed the entire `DiscordNative.ipc` surface. Masato Kinugawa used an XSS to call `DANGEROUS_openExternal` with a crafted URL. CVE-2020-15174.

---

### Anti-Pattern 2: Exposing require()

```javascript
// preload.js — CRITICAL
contextBridge.exposeInMainWorld('nodeAPI', {
  require: require  // full Node.js in the page
});

// Any XSS:
window.nodeAPI.require('child_process').exec('calc.exe');
```

This is rare in modern apps but still appears in repos that were built with `nodeIntegration: true` and then "fixed" by switching to a preload without fully understanding what the bridge should and shouldn't expose.

---

### Anti-Pattern 3: Passing Unfiltered Paths to IPC

```javascript
// preload.js — VULNERABLE
contextBridge.exposeInMainWorld('fs', {
  readFile: (p) => ipcRenderer.invoke('fs:read', p),
  writeFile: (p, c) => ipcRenderer.invoke('fs:write', p, c)
});
```

The page controls `p`. Without path validation in the `ipcMain` handler (not the preload — the handler), this is arbitrary file read/write:

```javascript
// XSS in page:
window.fs.readFile('../../../.ssh/id_rsa').then(exfiltrate);
```

---

### Anti-Pattern 4: Exposing process.env

```javascript
// preload.js — DANGEROUS
contextBridge.exposeInMainWorld('env', process.env);
```

Production apps that do this expose `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, internal service URLs, database connection strings — whatever happened to be in the environment when the app launched — to any XSS attacker. And unlike most bugs, this one doesn't require a chain: one XSS, one `window.env` read, exfiltrate the dump.

---

## How to Find Preloads During an Assessment

```bash
# Find all preload references in main process code:
grep -rn "preload" --include="*.js" . | grep -v node_modules

# Common patterns:
# preload: path.join(__dirname, 'preload.js')
# preload: `${__dirname}/preload.js`
# preload: path.resolve(app.getAppPath(), 'preload.js')

# After asar extraction, search directly:
find . -name "preload*.js" -not -path "*/node_modules/*"
find . -name "*bridge*.js" -not -path "*/node_modules/*"
```

One thing to watch for: apps with multiple windows often have multiple preload scripts. A secure admin window might load `preload-admin.js` (fine) while a chat display window loads `preload-chat.js` that exposes more (the problem). Always catalog all preloads and which windows they attach to.

---

## Triage Checklist

When you open a preload script, go through these in order:

- [ ] Does it expose `ipcRenderer.send`, `ipcRenderer.invoke`, or `ipcRenderer` directly?
- [ ] Does it expose `require` or any Node.js module?
- [ ] Does it expose `process.env` or individual env variables?
- [ ] Does it expose `shell.openExternal` without URL scheme validation?
- [ ] Do any exposed functions accept arbitrary file paths without validation?
- [ ] Do any exposed functions accept arbitrary IPC channel names?
- [ ] Are callbacks validated as actual functions before being passed to IPC?
- [ ] Is `contextIsolation: true` confirmed for this window?

A "yes" on the first three is critical. A "yes" on the others is high-severity, exploitability depending on what the IPC handlers do with the input.
