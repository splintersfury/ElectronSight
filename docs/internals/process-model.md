---
title: Process Model
description: Electron's multi-process architecture — main process, renderer processes, utility processes, and what each can do
---

# Process Model

Electron inherits its process model from Chromium, and it's the foundation of everything you need to understand when auditing these apps. The fundamental rule is: **main process has full OS access, renderer process is sandboxed.** The IPC layer between them is the security boundary. Every interesting vulnerability either breaks that boundary or exploits the handlers that legitimately cross it.

---

## The Main Process

The main process is what runs when you launch the app — it's the file referenced by `"main"` in `package.json`. It has full Node.js access:

```javascript
// main.js — runs with full OS access
const { app, BrowserWindow, ipcMain } = require('electron');

app.on('ready', () => {
  const win = new BrowserWindow({
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false
    }
  });
  win.loadFile('index.html');
});
```

What the main process can do: open files, spawn processes, make network requests, access environment variables, load native modules, control the OS-level window manager. Everything.

For an attacker, the main process is the target. If you get code execution in the main process, there's no further privilege escalation needed — you already have whatever the user has.

---

## The Renderer Process

Each `BrowserWindow` spawns a separate renderer process. It runs Chromium's rendering engine (Blink/V8) and displays your HTML, CSS, and JavaScript.

```javascript
// renderer.js — what the renderer can do depends on configuration:

// With contextIsolation: true, sandbox: true (modern, correct):
// window.require is undefined
// process.versions.electron is undefined
// ipcRenderer is not directly accessible

// With nodeIntegration: true (dangerous, old default):
const { exec } = require('child_process');  // full Node.js — any XSS = RCE
exec('calc.exe');
```

The renderer is the attack surface for XSS. What the XSS lets you do depends entirely on the renderer's configuration:

- `nodeIntegration: true` → XSS gets `require()`, game over
- `contextIsolation: false` → XSS can access anything the preload put on `window`
- `contextIsolation: true`, sandbox on → XSS is limited to Chromium's sandbox; escalation requires finding over-privileged IPC handlers

This is why reading `webPreferences` on every `BrowserWindow` is the first thing you do. It tells you the severity multiplier for any XSS you find.

---

## The Preload Script

Not a separate process — the preload runs inside the renderer process but in a separate V8 context (World 999) with access to some Node.js APIs. It's the bridge:

```
World 999 (preload): has ipcRenderer, limited Node.js
                         ↕ contextBridge (if contextIsolation: true)
World 0 (page):     has whatever the preload exposed
```

When contextIsolation is off, these worlds merge and the distinction disappears.

---

## GPU and Network Processes

The GPU process handles hardware-accelerated rendering. The network service process handles all network requests. Both are sandboxed. Neither is typically a direct research target — attacking them requires browser-class exploits (type confusion, heap corruption). If you find one, it's spectacular, but it's not the Electron-specific vulnerability class.

---

## Utility Processes (Electron 21+)

`UtilityProcess` creates worker processes that can optionally have Node.js access. Used for file parsing, network operations that shouldn't block the main process:

```javascript
// Utility process with Node.js access:
const child = utilityProcess.fork('worker.js', [], {
  serviceName: 'file-parser'
});
```

Security implication: if attacker-controlled data reaches `worker.js` as input, code execution in the utility process (which may have Node.js access) is potentially achievable. Worth checking what apps pass to utility processes.

---

## The Process Boundary in Practice

```
OS process boundary
┌─────────────────────────────────────────────┐
│ Main Process (PID 1234)                     │
│ Memory: main.js + Node.js heap              │
│ Can: fs, child_process, net, native modules │
└────────────────┬────────────────────────────┘
                 │ IPC — named pipe / socket
                 │ Only serialized messages cross
┌────────────────▼────────────────────────────┐
│ Renderer Process (PID 5678)                 │
│ Memory: V8 heap + Chromium internals        │
│ Cannot: direct syscalls (sandboxed)         │
│ Can: JavaScript, IPC messages               │
└─────────────────────────────────────────────┘
```

The only way to get from renderer to main process is IPC. This makes IPC handler security — input validation, origin checks, allowlists — the most critical control in any Electron app. Break that, and the OS-level process isolation becomes meaningless.

---

## Mapping the Process Model During an Assessment

This is always the first step:

```bash
# 1. Find the main process entry point:
cat package.json | grep '"main"'

# 2. Find all BrowserWindow creations:
grep -rn "new BrowserWindow" --include="*.js" . | grep -v node_modules

# 3. Check webPreferences on each window:
grep -rn "webPreferences" --include="*.js" . -A 10 | grep -v node_modules

# 4. Find all preload scripts:
grep -rn "preload:" --include="*.js" . | grep -v node_modules

# 5. Find all IPC handlers:
grep -rn "ipcMain\.\(on\|handle\|once\)" --include="*.js" . | grep -v node_modules
```

Draw this as a rough map: main.js → which windows → which preloads → what each preload exposes → which IPC handlers. The attack surface is that graph.
