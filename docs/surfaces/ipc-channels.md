---
title: IPC Channels Attack Surface
description: Mapping and auditing all IPC handlers as the primary privilege escalation surface
---

# IPC Channels Attack Surface

The contextBridge is not a security gate. It's a convenience wrapper. The real security decision happens in the IPC handler itself — in the main process — and a compromised renderer skips the bridge entirely. Post-XSS, an attacker calls `ipcRenderer.invoke('any-registered-channel', attacker_data)` directly. Every handler in the app is reachable.

This is why IPC channels are the primary attack surface for privilege escalation. The question isn't "can the renderer call this handler?" (it always can) — the question is "what does the handler do with attacker-controlled data?"

Most Electron apps have anywhere from 10 to 50+ registered IPC channels. Developers audit the ones they remember writing. They rarely audit all of them.

---

## The IPC Attack Surface Model

```
From renderer's perspective (post-XSS):
┌─────────────────────────────────────────────┐
│ Every registered channel is callable        │
│                                             │
│ Direct (bypasses contextBridge entirely):   │
│   ipcRenderer.invoke('any-channel', data)   │
│                                             │
│ Via contextBridge (legitimate path):        │
│   window.api.exposedFunction(data)          │
│   → ipcRenderer.invoke('channel', ...)      │
└─────────────────────────────────────────────┘
```

The contextBridge validation doesn't protect the handler. The handler must protect itself.

---

## Mapping the IPC Surface

First step in any IPC audit: enumerate everything. Count before you classify.

```bash
# Find all ipcMain.handle registrations:
grep -rn "ipcMain\.handle(" --include="*.js" . | grep -v node_modules

# Find all ipcMain.on registrations (fire-and-forget):
grep -rn "ipcMain\.on(" --include="*.js" . | grep -v node_modules

# Find all ipcMain.once registrations:
grep -rn "ipcMain\.once(" --include="*.js" . | grep -v node_modules

# All IPC entry points:
grep -rn "ipcMain\.\(handle\|on\|once\)(" --include="*.js" . | grep -v node_modules
```

A high channel count is a red flag. An app with 50 channels has 50 entry points into the main process. Not all of them were written with an adversarial caller in mind.

---

## Channel Risk Classification

Once mapped, classify each channel by what it can do.

### Tier 1 — Direct RCE (5/5)

```javascript
// Calls exec/spawn/eval with renderer-controlled data:
ipcMain.handle('run', async (event, cmd) => exec(cmd));
ipcMain.handle('eval', async (event, code) => eval(code));
ipcMain.handle('require', async (event, mod) => require(mod));
```

Finding one of these is a confirmed critical. The chain is one call: `ipcRenderer.invoke('run', 'calc.exe')`. These channels exist more often than you'd expect — usually debug code that never got removed.

### Tier 2 — File System Access (4/5)

```javascript
// Reads or writes files with renderer-controlled paths:
ipcMain.handle('read', async (event, path) => fs.readFileSync(path));
ipcMain.handle('write', async (event, path, data) => fs.writeFileSync(path, data));
```

Arbitrary write is often indirect RCE. Writing to startup folders, cron directories, PATH-adjacent locations, or shell config files converts a "file write" finding into code execution.

### Tier 3 — Navigation/Protocol (4/5)

```javascript
// Invokes OS protocol handlers or navigates windows:
ipcMain.handle('open', async (event, url) => shell.openExternal(url));
ipcMain.handle('navigate', async (event, url) => win.loadURL(url));
```

No URL validation → Windows protocol handlers (`ms-msdt://`, `search-ms:`, `file://`) → RCE. This was the Slack zero-click ($30k) and the Discord RCE ($10k).

### Tier 4 — Config/State (3/5)

```javascript
// Changes app configuration:
ipcMain.handle('set-config', async (event, config) => {
  Object.assign(appConfig, config);  // Prototype pollution risk
});
```

`Object.assign` with `{"__proto__": {"isAdmin": true}}` poisons the prototype chain. Whether that's exploitable depends on what the app does with those keys downstream.

### Tier 5 — Informational (1-2/5)

```javascript
// Returns data, takes no dangerous action:
ipcMain.handle('get-version', async () => app.getVersion());
ipcMain.handle('get-platform', async () => process.platform);
```

---

## Handler Audit Checklist

For each handler:

```
Channel: 'channel-name'
Location: src/ipc/handlers.js:45

□ What arguments does it accept? (type, structure)
□ Is event.senderFrame.url validated?
□ Is each argument type-checked?
□ Are paths resolved and checked against a base directory?
□ Are URLs parsed and protocol-checked?
□ Are shell commands avoided? If not, is input allowlisted?
□ Is the return value safe to send back (no secrets)?
□ Can this channel be called in a loop (DoS risk)?
```

---

## Sender Validation

Every handler should validate who's calling before doing anything privileged:

```javascript
function validateSender(event) {
  const url = event.senderFrame?.url || event.sender?.getURL() || '';
  const expected = 'file://' + path.join(app.getAppPath(), 'index.html');
  
  if (url !== expected && !url.startsWith('app://main')) {
    throw new Error(`Unauthorized sender: ${url}`);
  }
}

ipcMain.handle('any-channel', async (event, ...args) => {
  validateSender(event);  // First line, always
  // ... rest of handler
});
```

Without sender validation, any renderer — including one loaded from a URL via path traversal or navigation attack — can invoke the handler.

---

## Dangerous Patterns to Grep For

### The Generic Handler (Game Over)

```javascript
// One handler that routes to any function:
ipcMain.handle('invoke', async (event, fnName, ...args) => {
  const fn = handlers[fnName];  // fnName from renderer
  return fn(...args);           // Calls arbitrary handler with arbitrary args
});
```

Call: `ipcRenderer.invoke('invoke', 'exec', 'calc.exe')`. This collapses the entire IPC surface into a single finding. It's been found in real production apps — usually in apps that built their own "flexible IPC framework" during development.

```bash
# Find generic routing handlers:
grep -rn "handlers\[" --include="*.js" . | grep -v node_modules | grep "ipcMain\|invoke"
```

### Debug Channels in Production

```javascript
// Debug channel added during development, never removed:
if (process.env.DEBUG_MODE) {
  ipcMain.handle('admin:exec', async (event, cmd) => exec(cmd));
}
```

If `DEBUG_MODE` is set in production, this is reachable. Check whether any existing IPC channel can set env vars.

### Channels Without UI Triggers

Cross-reference your channel list against the actual UI. Every channel that has no corresponding UI element is a candidate — either dead code that never got unregistered, or a developer utility that got forgotten.

```bash
# Find registered channels vs called channels:
grep -rn "ipcMain\.\(handle\|on\)(" --include="*.js" . | \
  sed "s/.*('\(.*\)'.*/\1/" | sort > /tmp/handlers.txt

grep -rn "ipcRenderer\.\(invoke\|send\)(" --include="*.js" . | \
  sed "s/.*('\(.*\)'.*/\1/" | sort > /tmp/callers.txt

comm -23 /tmp/handlers.txt /tmp/callers.txt  # Registered but never called from renderer
```

---

## ipcMain.on vs ipcMain.handle

`ipcMain.on` channels are still callable from a compromised renderer — don't skip them because there's no return value:

```javascript
// ipcMain.on — no return value, but still dangerous:
ipcMain.on('execute', (event, cmd) => {
  exec(cmd);  // RCE, no reply needed
});
```

---

## Example IPC Surface Map

```
Target: example-app v2.1.0
IPC Handler Inventory (8 channels):

┌─────────────────────────┬──────────┬────────────────────────────────┐
│ Channel                 │ Risk     │ Finding                        │
├─────────────────────────┼──────────┼────────────────────────────────┤
│ app:get-version         │ 1/5      │ Clean, no args                 │
│ app:quit                │ 2/5      │ DoS risk, no auth              │
│ dialog:open-file        │ 2/5      │ User confirms path             │
│ file:read               │ 4/5      │ No path traversal check!       │
│ file:write              │ 5/5      │ No path check, no sender check │
│ shell:open-external     │ 4/5      │ No URL scheme validation       │
│ exec:run-script         │ 5/5      │ Direct exec() with user cmd    │
│ config:update           │ 3/5      │ Object.assign → pollution risk │
└─────────────────────────┴──────────┴────────────────────────────────┘

Critical: file:write and exec:run-script are direct RCE paths
```
