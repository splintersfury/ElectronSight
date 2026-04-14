---
title: Context Isolation
description: How contextIsolation separates JS worlds, what it prevents, and documented bypass techniques
---

# Context Isolation

Context isolation is the defense that, when it works correctly, prevents an XSS payload from touching anything privileged. When it's off — or when the API exposed through it is poorly designed — that same XSS lands directly in a position to call into privileged operations.

Understanding exactly what it does (and doesn't) prevent is important because a lot of developers think "contextIsolation:true" means they're safe. It's a necessary condition, not a sufficient one.

---

## The Problem It Solves

Before context isolation existed (or when it's disabled), the preload script and the web page share a single JavaScript context. One `window` object, one `Object.prototype`, one set of globals.

```javascript
// preload.js (contextIsolation: false) — attacker reads these:
const { ipcRenderer } = require('electron');
window.sendMessage = (msg) => ipcRenderer.send('chat', msg);

// XSS payload in page:
window.sendMessage('payload');         // direct IPC call
window.ipcRenderer.send('exec', 'calc');  // if ipcRenderer was exposed at all

// Or: prototype pollution crosses into preload:
Object.prototype.toString = function() {
  require('child_process').exec('calc');
};
// Now every toString() call in preload also runs exec()
```

The attack surface with `contextIsolation: false` is the entire preload script. Whatever variables exist in preload's scope, whatever Node.js modules it required, whatever it put on `window` — all accessible to the XSS payload.

---

## How It Works

With `contextIsolation: true`, Electron creates two entirely separate V8 contexts in the same renderer process:

```
BrowserWindow renderer process
├── V8 Context "World 0" — the page
│   ├── window (page's window)
│   ├── document
│   ├── page JS, React, Vue, etc.
│   └── only sees: what contextBridge explicitly exposes
│
└── V8 Context "World 999" — the preload
    ├── window (different object, separate heap)
    ├── preload script code
    ├── ipcRenderer, contextBridge
    └── limited Node.js APIs
```

The key property: these contexts don't share an `Object.prototype`. Prototype pollution in World 0 stays in World 0. `window` in one context is not `window` in the other. The preload's `require()` is not accessible from the page.

The only crossing point is `contextBridge.exposeInMainWorld` — and objects that cross are **deep-cloned** via structured clone, not shared by reference. You get a copy of the data, not a live reference into the preload's scope.

---

## What contextIsolation: false Opens Up

```javascript
// page-script.js (contextIsolation: false, post-XSS):

// If preload put ipcRenderer on window:
window.ipcRenderer.invoke('run-command', 'calc.exe');

// If preload didn't — it doesn't matter, you still have access to everything
// the preload put in the shared scope:
window.__preloadSendFn('dangerous-channel', malicious_args);

// Prototype pollution now affects the entire context, including preload:
Object.prototype.isAdmin = true;
// Now any code in preload that checks: if (options.isAdmin) { ... }
// finds isAdmin = true without actually going through auth
```

---

## What contextIsolation: true Prevents

```javascript
// page-script.js (contextIsolation: true):

window.ipcRenderer     // undefined
window.require         // undefined
require('child_process') // ReferenceError: require is not defined

// Prototype pollution is sandboxed to the page's heap:
Object.prototype.foo = 'poisoned';
// Preload's Object.prototype.foo is unaffected — different prototype chain
```

The XSS payload runs in an empty environment — it only has access to `window.api` (or whatever name you chose for `exposeInMainWorld`), nothing else.

---

## The contextBridge Crossing Point

`contextBridge.exposeInMainWorld` is the only sanctioned way to give the page access to preload functionality:

```javascript
// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // Good: no user input, fixed operation
  getVersion: () => ipcRenderer.invoke('app:version'),
  
  // Good: validates before sending
  submitForm: (data) => {
    if (typeof data !== 'object' || data === null) throw new Error('invalid');
    return ipcRenderer.invoke('form:submit', data);
  }
});
```

**What can cross the bridge:**
- Primitives (string, number, boolean, null, undefined)
- Plain objects and arrays (deep-cloned — no prototype preserved)
- TypedArrays, Dates, Maps, Sets
- Functions (top-level only — called cross-context, closure not accessible to page)

**What can't:**
- Class instances (prototype chain is lost on clone)
- DOM nodes
- Anything from a circular reference graph

---

## Documented Bypass Techniques

These were real bugs, most now patched. Understanding them tells you what assumptions the protection makes.

### The Over-Exposed API (Design Bypass)

Not a technical bypass — the app simply designs a bridge that defeats the purpose:

```javascript
// preload.js — technically "uses contextBridge correctly" but:
contextBridge.exposeInMainWorld('shell', {
  send: (channel, ...args) => ipcRenderer.send(channel, ...args)
});

// Page (post-XSS):
window.shell.send('exec-system-cmd', 'calc.exe');
// contextIsolation provided no protection — the bridge just forwards everything
```

This is by far the most common real-world bypass. Discord, Notion, and others shipped exactly this pattern — a perfectly correct `contextBridge` call wrapping an over-permissive operation.

### Getter/Setter Interception (Old Electron, Patched)

Early implementations of the structured clone in contextBridge would call property getters during the clone process. Getters can execute arbitrary code:

```javascript
// page world (old Electron):
const malicious = {};
Object.defineProperty(malicious, 'key', {
  get() {
    require('child_process').exec('calc');
    return 'safe';
  }
});
window.api.process(malicious);  // getter fires during cloning
```

This was fixed by cloning at a layer that doesn't invoke getters.

### Prototype Chain Leak (Old Electron, Patched)

Early contextBridge could return objects that still carried their prototype chain from the preload world, allowing the page to traverse it and access preload-world constructors.

### Prototype Pollution Through Functions (Pre-2022 Fix)

Functions exposed through the bridge receive arguments from the page. Before a fix, those arguments could carry prototype pollution:

```javascript
// preload.js:
contextBridge.exposeInMainWorld('api', {
  process: (obj) => {
    const result = obj.type;  // if Object.prototype.type = 'evil', this reads 'evil'
    return someOperation(result);
  }
});

// page:
Object.prototype.type = 'evil';
window.api.process({});  // obj.type = 'evil' due to pollution
```

Modern Electron clones arguments before the bridge function receives them, breaking this.

---

## Auditing

```bash
# Find contextIsolation: false (the immediate red flag):
grep -rn "contextIsolation.*false\|contextIsolation\s*:\s*false" \
  --include="*.js" . | grep -v node_modules

# Find every contextBridge exposure (audit each one):
grep -rn "exposeInMainWorld" --include="*.js" . | grep -v node_modules

# For each exposure, check what's being passed to invoke/send:
grep -rn "exposeInMainWorld" --include="*.js" . -A 40 | \
  grep "invoke\|send\b" | grep -v node_modules

# Electronegativity check:
electronegativity -i . -r CONTEXT_ISOLATION_JS_CHECK
```

For each `exposeInMainWorld` call, work through:

1. What functions are exposed? (that's the renderer's entire API — treat it as the attack surface)
2. Do any accept arbitrary arguments without validating them?
3. Do any pass those arguments directly to `ipcRenderer.invoke`?
4. Can any exposed function reach `exec`, `openExternal`, `writeFile`, or similar?
5. Is any channel name passed as a parameter (the generic relay pattern)?
