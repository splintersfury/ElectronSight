---
title: IPC Architecture
description: Electron IPC internals — ipcMain, ipcRenderer, invoke/handle, contextBridge, Mojo, and the security boundaries
---

# IPC Architecture

IPC is the single most important thing to understand when auditing an Electron app, because it's both the *only* legitimate path from the renderer into privileged territory and the most common place where that privilege escalates into something it shouldn't.

Think of it this way: Chromium already has a decent sandbox story. If Electron apps were just browsers, we'd be talking about Chromium VRP. But Electron apps bolt Node.js onto the back of the browser process and give the renderer a way to ask it things. That ask-and-answer mechanism — IPC — is where the interesting bugs live.

---

## Two Layers, One Attack Surface

There's a distinction worth knowing even though you'll spend 95% of your time on just one of them:

**Layer 1: Electron IPC** — the JavaScript API (`ipcMain.handle`, `ipcRenderer.invoke`, `contextBridge`). This is what app developers write, what gets audited, and where virtually all exploitable bugs are found.

**Layer 2: Mojo** — Chromium's underlying C++ IPC framework. `.mojom` files define message schemas; the browser and renderer talk over named pipes. This is what Chromium VRP hunters look at. Not accessible from JavaScript.

When someone says "IPC bug in Electron," they mean Layer 1. Always.

---

## How Messages Actually Flow

The normal (correct) flow looks like this:

```
Web page JS
    │  window.api.readFile('/etc/passwd')
    ▼
contextBridge boundary  (World 0 → World 999)
    │  ipcRenderer.invoke('read-file', '/etc/passwd')
    ▼
Named pipe to main process
    │  ipcMain.handle('read-file', handler)
    ▼
Main process handler runs
    │  (hopefully validates the path first)
    ▼
Result returned to renderer
```

The security model assumes that contextBridge is the chokepoint — the place where validation happens before anything dangerous is called. In practice, many apps either skip the validation entirely or put it in the wrong place (preload only, not main), which we'll get to.

---

## ipcMain / ipcRenderer API

### Fire-and-forget (one-way)

```javascript
// Renderer sends, main receives — no response, no await
// preload.js:
contextBridge.exposeInMainWorld('api', {
  doSomething: (data) => ipcRenderer.send('do-something', data)
});

// main.js:
ipcMain.on('do-something', (event, data) => {
  // event.sender = the WebContents that sent this
  // data = whatever the renderer passed — treat it as hostile
  doPrivilegedOperation(data);  // dangerous if unvalidated
});
```

`ipcMain.on` handlers don't return anything to the renderer, which sometimes creates a false sense of safety. The handler still runs, still has full OS access, still does whatever it does. No response doesn't mean no impact.

### Request-response (invoke/handle)

```javascript
// Renderer awaits a response from main
// preload.js:
contextBridge.exposeInMainWorld('api', {
  readFile: (path) => ipcRenderer.invoke('read-file', path)
});

// main.js:
ipcMain.handle('read-file', async (event, filePath) => {
  // filePath is from the renderer — fully attacker-controlled post-XSS
  return fs.readFileSync(filePath, 'utf8');  // path traversal → arbitrary file read
});
```

`ipcMain.handle` is the more common pattern in modern Electron apps because it supports async and returns values. It's also the higher-priority audit target because it tends to be used for the meaty operations — file reads, shell commands, dialog interactions.

---

## event.sender — The Piece Everyone Forgets

Every IPC message arrives with an `event` object. Buried inside it is information about *who sent the message*. Almost nobody validates this.

```javascript
ipcMain.on('sensitive-operation', (event, data) => {
  // event.sender — the WebContents instance (the renderer window)
  // event.sender.getURL() — the URL that renderer has currently loaded
  // event.senderFrame.url — the specific frame URL (Electron 17+, more precise)

  // If you skip this check, any renderer can call this handler:
  if (!event.senderFrame.url.startsWith('file://' + app.getAppPath())) {
    return;  // reject: not our app
  }
  
  doSensitiveOperation(data);
});
```

Why does this matter? Because after an XSS, the compromised renderer can call any registered IPC handler directly via `ipcRenderer.invoke('channel-name', malicious_data)` — completely bypassing whatever validation you put in the preload/contextBridge. The main process handler is the *only* place validation actually counts.

---

## contextBridge

`contextBridge.exposeInMainWorld` is how you give the renderer access to things it needs without giving it everything. The key property: objects passed through contextBridge are *deep-cloned* via structured clone — the renderer gets a copy, not a reference into preload's scope.

```javascript
// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Good: returns a fixed value, no user input
  openFile: () => ipcRenderer.invoke('dialog:openFile'),
  
  // Okay: passes data but the preload bounds it
  sendMessage: (msg) => {
    if (typeof msg !== 'string') return;
    ipcRenderer.send('chat:message', msg.slice(0, 1000));
  },
  
  // Bad: renderer controls the channel name — calls any registered handler
  sendArbitrary: (channel, data) => ipcRenderer.send(channel, data)
});
```

That last pattern — passing the channel name as a parameter — turns every registered `ipcMain.on` handler in the entire app into part of the renderer's attack surface. You'd be surprised how many apps do exactly this.

### What contextBridge Actually Buys You

- Prototype pollution can't cross the boundary (structured clone doesn't transfer `__proto__`)
- `window.require` is undefined in page context (when `contextIsolation: true`)
- Preload variables and closures are not accessible to page JS

### What contextBridge Does NOT Buy You

- Any protection if you expose `ipcRenderer` itself directly
- Any protection against badly designed APIs (a `run-command` handler is still dangerous)
- Any protection if `contextIsolation: false` (the whole thing is moot)

---

## The World System

This is the mechanism behind contextIsolation:

```
contextIsolation: true (correct)

V8 Context "World 0"              V8 Context "World 999"
┌─────────────────┐               ┌────────────────────────┐
│ Page JS         │               │ Preload Script         │
│ window.foo      │ ◀──bridge───▶ │ contextBridge          │
│ document.write  │               │ ipcRenderer            │
│ fetch()         │               │ limited Node.js        │
└─────────────────┘               └────────────────────────┘
```

```
contextIsolation: false (wrong)

V8 Context (merged)
┌─────────────────────────────────────┐
│ Page JS + Preload Script            │
│ window === preload's window         │
│ Page JS can call ipcRenderer.send() │
│ Prototype pollution reaches preload │
└─────────────────────────────────────┘
```

With `contextIsolation: false`, the renderer doesn't need your contextBridge API. It just calls `ipcRenderer.invoke('any-channel', anything)` directly. Any XSS in the renderer becomes a direct line to every IPC handler in the app.

---

## The Five Patterns That Actually Get Exploited

### 1. The Open Relay

```javascript
// preload.js — exposes full IPC to the page
contextBridge.exposeInMainWorld('ipc', {
  send: ipcRenderer.send.bind(ipcRenderer),
  invoke: ipcRenderer.invoke.bind(ipcRenderer)
});
// Now every registered ipcMain handler is callable from the renderer
// This pattern shows up more often than you'd think
```

### 2. Missing Sender Validation

```javascript
// main.js — no check on who's calling
ipcMain.handle('execute-shell', async (event, cmd) => {
  return exec(cmd);  // any renderer, any origin, any URL
});
// Post-XSS: ipcRenderer.invoke('execute-shell', 'calc.exe')
```

### 3. Path Traversal

```javascript
// main.js — path.join doesn't save you
ipcMain.handle('read-config', async (event, name) => {
  const p = path.join('/app/configs/', name);
  // name = '../../etc/passwd' → normalizes to /etc/passwd
  return fs.readFileSync(p, 'utf8');
});
```

### 4. Object.assign Prototype Pollution

```javascript
// main.js — spreads renderer input into an object
ipcMain.on('set-preferences', (event, prefs) => {
  Object.assign(defaults, prefs);
  // prefs from renderer: { "__proto__": { "isAdmin": true } }
  // Now {}.isAdmin === true everywhere in main process
});
```

### 5. TOCTOU Between Check and Use

```javascript
// main.js — passes path check, loses the race
ipcMain.handle('safe-open', async (event, filePath) => {
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith('/app/safe/')) return null;  // CHECK
  
  await someAsyncOperation();  // race window opens here
  
  return fs.readFileSync(resolved, 'utf8');  // USE — symlink could have been placed
});
```

---

## Finding IPC Handlers

```bash
# All ipcMain listeners in the app:
grep -r "ipcMain\.\(on\|handle\|once\)" --include="*.js" . | grep -v node_modules

# All ipcRenderer sends (from preload — shows what channels are used):
grep -r "ipcRenderer\.\(send\|invoke\|sendSync\)" --include="*.js" . | grep -v node_modules

# contextBridge exposures — the bridge surface:
grep -r "contextBridge\.exposeInMainWorld" --include="*.js" . | grep -v node_modules

# Look for the dangerous passthrough pattern:
grep -r "invoke\b.*channel\|send\b.*channel" --include="*.js" . | grep -v node_modules
```

For each handler you find, work through four questions:

1. What can the renderer actually send here? (types, structure, bounds)
2. Is the sender validated before anything happens?
3. What does the handler do with the input? (map it to a sink category)
4. Is there any path between the input and the sink that isn't properly checked?

That's IPC auditing. Everything else is just doing it systematically at scale.
