---
title: IPC Hardening
description: Securing Electron IPC handlers — sender validation, input validation, narrow bridge design
---

# IPC Hardening

IPC handlers are the most critical control point in any Electron app's security model. They're where attacker-controlled input from the renderer meets privileged main process operations. Getting them right requires three things: validating who sent the message, validating what they sent, and minimizing what they can reach in the first place.

---

## Rule 1: Validate the Sender

Post-XSS, an attacker calls `ipcRenderer.invoke('your-channel', ...)` directly. They skip the preload entirely. The IPC handler is the only thing standing between them and the dangerous operation.

Check who's asking before doing anything privileged:

```javascript
// Helper — validate sender frame URL:
function validateSender(event) {
  const frameUrl = event.senderFrame?.url;
  if (!frameUrl) throw new Error('Cannot determine sender origin');
  
  const appPath = app.getAppPath();
  const trusted = [
    'file://' + path.join(appPath, 'index.html'),
    'file://' + path.join(appPath, 'renderer', 'index.html'),
  ];
  
  if (!trusted.includes(frameUrl)) {
    throw new Error(`Untrusted sender: ${frameUrl}`);
  }
}

// Use it at the top of every sensitive handler:
ipcMain.handle('read-config', async (event, key) => {
  validateSender(event);  // ← first thing
  return getConfig(key);
});
```

For Electron < 17, use `event.sender.getURL()` instead of `event.senderFrame.url`.

---

## Rule 2: Validate All Input

Type, bounds, format — validate everything before using it:

```javascript
ipcMain.handle('save-note', async (event, title, content) => {
  validateSender(event);
  
  // Types:
  if (typeof title !== 'string' || typeof content !== 'string') {
    throw new TypeError('Expected strings');
  }
  
  // Bounds:
  if (title.length > 500) throw new RangeError('Title too long');
  if (content.length > 100_000) throw new RangeError('Content too large');
  
  // Path construction — must use resolve + startsWith:
  const notesDir = path.join(app.getPath('userData'), 'notes');
  const safeTitle = title.replace(/[^a-zA-Z0-9\s\-_.]/g, '').slice(0, 100);
  const filePath = path.resolve(notesDir, `${safeTitle}.md`);
  
  // Critical: verify the resolved path is within the allowed directory:
  if (!filePath.startsWith(notesDir + path.sep)) {
    throw new Error('Path traversal detected');
  }
  
  return fs.promises.writeFile(filePath, content, 'utf8');
});
```

Note `path.resolve` + `startsWith` + `path.sep`. Not `path.join`. Not `includes`. The `path.sep` prevents `../safe` matching against `../safeDir`.

---

## Rule 3: Narrow the Bridge

The preload bridge should expose specific operations, not generic IPC access:

```javascript
// ✅ Narrow API — renderer can only do what it needs:
contextBridge.exposeInMainWorld('notes', {
  save: (title, content) => ipcRenderer.invoke('note:save', title, content),
  list: () => ipcRenderer.invoke('note:list'),
  delete: (id) => {
    if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) return;
    return ipcRenderer.invoke('note:delete', id);
  }
});

// ❌ Wide-open relay — entire IPC surface accessible post-XSS:
contextBridge.exposeInMainWorld('ipc', {
  call: (channel, ...args) => ipcRenderer.invoke(channel, ...args)
});
```

The difference: with the narrow API, XSS can only invoke `note:save`, `note:list`, `note:delete`. With the relay, XSS can invoke any registered channel.

If you need a more flexible bridge, use a channel allowlist:

```javascript
const ALLOWED_CHANNELS = ['note:save', 'note:list', 'dialog:open-file', 'app:version'];

contextBridge.exposeInMainWorld('ipc', {
  invoke: (channel, ...args) => {
    if (!ALLOWED_CHANNELS.includes(channel)) throw new Error('Channel not permitted');
    return ipcRenderer.invoke(channel, ...args);
  }
});
```

---

## Rule 4: Avoid the Confused Deputy Pattern

The main process should control its own actions. It shouldn't blindly execute whatever the renderer requests:

```javascript
// ❌ Main process as confused deputy:
ipcMain.handle('open-file', async (event, filePath) => {
  return shell.openPath(filePath);  // renderer decides what opens
});

// ✅ Main process decides:
ipcMain.handle('open-selected-file', async (event) => {
  validateSender(event);
  // Main process shows dialog — user chooses, renderer doesn't control the path:
  const result = await dialog.showOpenDialog({ properties: ['openFile'] });
  if (!result.canceled) {
    return shell.openPath(result.filePaths[0]);
  }
});
```

When the renderer must specify a target (e.g., open a specific file from the user's data), validate the path strictly — allowlist directory, resolve and check prefix.

---

## Rule 5: Fail Closed

When validation fails, return nothing and log the rejection:

```javascript
ipcMain.handle('sensitive-op', async (event, data) => {
  try {
    validateSender(event);
    validateInput(data);
    return await performOperation(data);
  } catch (error) {
    // Log for security monitoring:
    console.warn('IPC rejected', { error: error.message, sender: event.senderFrame?.url });
    // Don't expose details to renderer:
    return null;
  }
});
```

Don't throw — that leaks error details to the renderer. Return `null` or a generic error object.

---

## Verification

```bash
# Find handlers missing sender validation:
grep -r "ipcMain\.\(on\|handle\)" --include="*.js" . -A 5 | \
  grep -v "senderFrame\|getURL\|node_modules" | \
  grep -E "exec\b|spawn\b|openExternal|writeFile|readFile"
# Expected: empty — these should all have validation visible in context

# Find bridge relay patterns (no channel restriction):
grep -r "exposeInMainWorld" --include="*.js" . -A 20 | \
  grep "ipcRenderer\.\(send\|invoke\)" | \
  grep -v "ALLOWED\|allowlist\|channel\b.*includes" | grep -v node_modules
# Expected: empty

# Find openExternal without URL validation:
grep -rn "openExternal" --include="*.js" . -B 10 | \
  grep -E "protocol\b|allowedSchemes\|new URL" | grep -v node_modules
# Expected: URL parse + scheme check visible before each openExternal call
```
