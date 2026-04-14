---
title: IPC Sources
description: IPC callbacks, renderer-to-main messages, and bidirectional channel data as attack sources
---

# IPC Sources

IPC sources are arguments passed from the renderer process to the main process via `ipcRenderer.send`, `ipcRenderer.invoke`, or `contextBridge`-exposed functions. From the main process's perspective, all IPC arguments are **attacker-controlled** if the renderer can be compromised.

---

## The Renderer-as-Attacker Model

The fundamental assumption for IPC security:

```
If the renderer is compromised (XSS, malicious URL, malicious file),
the attacker has full control over:
  - Which IPC channels are called
  - What arguments are passed
  - How many times handlers are called
  - The order of calls

The main process MUST validate as if the renderer is a hostile process.
```

This is why IPC arguments are always classified as sources in taint analysis.

---

## ipcMain.on / ipcMain.handle Arguments

Every argument received from the renderer is a source:

```javascript
// Main process handler:
ipcMain.handle('process-input', async (event, arg1, arg2, arg3) => {
  // event.sender — SOURCE: the WebContents that sent this
  // arg1, arg2, arg3 — SOURCE: fully attacker-controlled
  
  return processInput(arg1, arg2, arg3);  // Sources flow to processing
});

// Common dangerous patterns:
ipcMain.handle('save-file', async (event, filePath, content) => {
  fs.writeFileSync(filePath, content);  // SOURCE(filePath) → SINK(writeFileSync)
});

ipcMain.handle('open-url', async (event, url) => {
  shell.openExternal(url);  // SOURCE(url) → SINK(openExternal)
});

ipcMain.handle('run-command', async (event, cmd) => {
  return exec(cmd);  // SOURCE(cmd) → SINK(exec) — immediate RCE
});
```

---

## contextBridge-Exposed Functions

The preload script defines which IPC channels can be called from the renderer. Each exposed function is a potential source-to-sink bridge:

```javascript
// preload.js — defines the attack surface:
contextBridge.exposeInMainWorld('api', {
  
  // NARROW — only invokes specific channel, no user data:
  getVersion: () => ipcRenderer.invoke('app:version'),
  
  // MEDIUM — passes user data but to a specific channel:
  saveNote: (title, content) => ipcRenderer.invoke('note:save', title, content),
  // SOURCE: title, content → ipcMain handler
  
  // WIDE — passes arbitrary channel name (dangerous):
  call: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  // SOURCE: channel name + all args → can invoke ANY registered handler
  
  // WIDEST — exposes ipcRenderer directly (extremely dangerous):
  ipc: ipcRenderer  // SOURCE: full ipcRenderer API exposed to web content
});
```

---

## event.sender as Source

The IPC event's sender property can be used to extract renderer state:

```javascript
ipcMain.handle('get-resource', async (event, resourcePath) => {
  // event.sender — the WebContents sending this request
  // event.sender.getURL() — SOURCE: what URL the sender has loaded
  // event.sender.id — SOURCE: numeric ID
  // event.senderFrame.url — SOURCE: more precise than sender.getURL()
  
  // If sender.getURL() is used for trust but the renderer is compromised:
  const senderUrl = event.sender.getURL();
  // Attacker can navigate renderer to any URL they control
  // then invoke IPC handlers with their URL as the "sender"
});
```

---

## IPC Argument Types — What Attackers Can Send

All JavaScript primitives and structured-cloneable types can be sent:

```javascript
// Attacker in renderer (post-XSS):
window.api.save(
  "../../etc/cron.d/evil",          // string: path traversal
  "*/1 * * * * root rm -rf /"       // string: cron injection
);

window.api.openUrl(
  "ms-msdt://-id PCWDiagnostic..."  // string: protocol attack
);

window.api.setConfig({
  updateUrl: "http://attacker.com", // object: config injection
  preScript: "rm -rf ~",           // object: script injection
  __proto__: { isAdmin: true }     // object: prototype pollution
});

window.api.processData(
  Array(1e8).fill('A'),             // array: memory exhaustion DoS
  { depth: { depth: { depth: ... }}} // deeply nested: parser bomb
);
```

---

## Prototype Pollution via IPC

IPC arguments can contain prototype-poisoning payloads:

```javascript
// Renderer sends:
window.api.updateSettings({ "__proto__": { "isAdmin": true } });

// Main process handler:
ipcMain.handle('update-settings', async (event, settings) => {
  Object.assign(currentSettings, settings);  // SINK: pollutes Object.prototype
  // Now: ({}).isAdmin === true everywhere in main process
  
  if (currentSettings.isAdmin) {           // Bypassed by pollution
    performPrivilegedAction();
  }
});
```

---

## Two-Way IPC — Main→Renderer as Source

The main process can also send data to the renderer, which then processes it:

```javascript
// Main sends data to renderer:
mainWindow.webContents.send('data-update', {
  html: serverResponse.html,    // SOURCE: network data → renderer via IPC
  script: config.displayScript  // SOURCE: config data → renderer via IPC
});

// Renderer receives:
ipcRenderer.on('data-update', (event, data) => {
  // data — SOURCE: from main process, but originally from network/config
  contentDiv.innerHTML = data.html;        // SINK: server data → innerHTML
  eval(data.script);                       // SINK: config data → eval
});
```

---

## IPC Flooding / DoS

A compromised renderer can overwhelm the main process:

```javascript
// Renderer (post-XSS) floods IPC with expensive operations:
for (let i = 0; i < 100000; i++) {
  window.api.readLargeFile('/dev/zero');  // Each call blocks main process
}

// Or with async flooding:
const promises = Array(1000).fill(0).map(() => 
  window.api.compressData(new Uint8Array(10_000_000))
);
await Promise.all(promises);  // OOM or CPU exhaustion
```

---

## Detection Patterns

```bash
# Find all ipcMain handlers (the entry points):
grep -rn "ipcMain\.\(on\|handle\|once\)(" \
  --include="*.js" . | grep -v node_modules

# Find handlers with no argument validation:
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 5 | \
  grep -v "node_modules\|typeof\|instanceof\|\.startsWith\|isString\|validate" | \
  head -30

# Find contextBridge exposures (the preload attack surface):
grep -rn "exposeInMainWorld\|contextBridge" --include="*.js" . | grep -v node_modules

# Find over-broad bridge patterns:
grep -rn "exposeInMainWorld" --include="*.js" . -A 10 | \
  grep "ipcRenderer\b" | grep -v "invoke\|send\|on\b" | head -10
# Looking for: ipcRenderer exposed directly

# Find handlers that use IPC args in dangerous operations:
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 20 | \
  grep -E "exec\b|spawn\b|eval\b|openExternal|writeFile|readFile|loadURL" | \
  grep -v node_modules

# Find Object.assign with IPC args:
grep -rn "Object\.assign\|Object\.merge\|\.extend(" \
  --include="*.js" . -B 5 | grep "ipc\|args\|data\|event" | grep -v node_modules
```

---

## Risk Matrix

| IPC Source | Risk | Notes |
|-----------|------|-------|
| `ipcMain.handle(_, async (e, ...args))` args | Critical | Any renderer can send post-XSS |
| Direct `ipcRenderer` exposure | Critical | Full IPC access from web content |
| Wildcard channel passthrough | Critical | Any handler callable from renderer |
| `Object.assign(target, ipcArg)` | High | Prototype pollution |
| `event.sender.getURL()` for auth | Medium | Renderer can be navigated |
| Main→renderer data reflected | Medium | Network data via IPC to renderer DOM |
| IPC flooding | Low | DoS only |
