---
title: DevTools Tricks
description: Using Chrome DevTools in Electron for runtime security analysis — JavaScript REPL, network inspection, storage audit
---

# DevTools Tricks

Chrome DevTools embedded in Electron provides runtime access to the renderer process — useful for validating findings, exploring the app's runtime state, and building PoCs.

---

## Opening DevTools

```javascript
// If the app exposes DevTools (many do in development mode):
// Keyboard: F12, Ctrl+Shift+I (Windows/Linux), Cmd+Option+I (macOS)

// From app menu: View → Developer Tools (if enabled)

// Programmatically (in main process):
win.webContents.openDevTools();

// Force-open via electron CLI flag:
/path/to/app --inspect-devtools

// Via app's existing keyboard shortcut:
// Many apps: F12 or Ctrl+Shift+I
```

---

## Accessing DevTools When Locked

### Method 1: NODE_OPTIONS (if fuse not disabled)

```bash
# Inject a script that opens DevTools:
NODE_OPTIONS="--require /tmp/devtools.js" /path/to/app

# /tmp/devtools.js:
setTimeout(() => {
  const { BrowserWindow } = require('@electron/remote') || require('electron');
  BrowserWindow.getAllWindows().forEach(w => w.webContents.openDevTools());
}, 2000);
```

### Method 2: --inspect Flag (if fuse not disabled)

```bash
/path/to/app --inspect=9229
# → Connect Chrome DevTools to localhost:9229
# → Full JS REPL in main process context
```

### Method 3: ASAR Modification (if no integrity check)

```bash
# Extract, add DevTools opener to main.js, repack:
asar extract app.asar /tmp/app/
echo "setTimeout(() => BrowserWindow.getAllWindows()[0].webContents.openDevTools(), 3000);" \
  >> /tmp/app/main.js
asar pack /tmp/app/ app.asar
```

---

## Console Tricks

### Check Runtime Configuration

```javascript
// In DevTools console (renderer process):

// Electron version:
process.versions.electron

// Node.js access?
typeof require  // 'function' → nodeIntegration:true; 'undefined' → false

// Context isolation?
// If contextIsolation:true: require is undefined in page context
// If contextIsolation:false: require may be accessible

// What's exposed on window by preload?
Object.keys(window).filter(k => !['window', 'document', 'location'].includes(k))

// Check for contextBridge exposures:
// Look for custom properties added by preload:
Object.entries(window)
  .filter(([k,v]) => typeof v === 'object' && v !== null)
  .filter(([k]) => !['performance', 'crypto', 'history'].includes(k))
  .map(([k]) => k)
```

### Explore IPC Surface

```javascript
// If ipcRenderer is accessible (contextIsolation:false or exposed):

// Listen to ALL IPC messages coming from main:
const orig = ipcRenderer.on.bind(ipcRenderer);
const channels = new Set();
ipcRenderer.on = function(channel, ...args) {
  channels.add(channel);
  return orig(channel, ...args);
};
setTimeout(() => console.log('IPC channels:', [...channels]), 5000);

// Send to known channels:
ipcRenderer.invoke('get-app-path').then(console.log);
ipcRenderer.invoke('get-version').then(console.log);
```

### Storage Inspection

```javascript
// Check localStorage for sensitive data:
for (let i = 0; i < localStorage.length; i++) {
  const key = localStorage.key(i);
  console.log(key, localStorage.getItem(key).slice(0, 200));
}

// IndexedDB:
indexedDB.databases().then(dbs => console.log(dbs));

// Electron store (if using electron-store):
// Usually persisted to AppData/Application Support
// Read via IPC or direct fs access
```

### Network Inspection

In the Network tab:
- Look for API endpoints receiving user-controlled data
- Check for sensitive data in request/response bodies
- Look for API tokens in Authorization headers (screenshot and report)
- Check WebSocket messages for protocol-level data

---

## Remote Debugging

If the app is running with `--inspect`:

```bash
# Check if a debug port is open:
ss -tlnp | grep 9229        # Linux
netstat -ano | findstr 9229  # Windows
lsof -i :9229                # macOS

# Connect via Chrome:
# chrome://inspect → Configure → Add localhost:9229
# → Inspect → Full DevTools in main process context

# Connect via node CLI:
node inspect localhost:9229
```

---

## Security Testing with DevTools

### Test XSS Impact

```javascript
// If you found an XSS vector, test what's accessible:

// Test 1: Is require() available?
typeof require !== 'undefined' && require('child_process')

// Test 2: What's the preload bridge?
window.electronAPI  // or window.api, window.app, etc.
Object.keys(window).join('\n')

// Test 3: Can we call IPC?
window.electronAPI && Object.keys(window.electronAPI)

// Test 4: Shell operations?
window.electronAPI?.openExternal?.('https://example.com')
```

### Session and Cookie Inspection

```javascript
// DevTools → Application tab → Storage → Cookies
// Look for: session tokens, API keys, auth cookies
// Are they HttpOnly? Accessible to JS?
document.cookie  // only non-HttpOnly cookies

// Chrome extension DevTools shows all cookies including HttpOnly
```
