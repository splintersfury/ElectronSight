---
title: contextBridge as Sanitizer
description: How contextBridge enforces context isolation and its limitations as a security boundary
---

# contextBridge as Sanitizer

`contextBridge.exposeInMainWorld` is the designated API for safely exposing functionality from the preload script (World 999) to the renderer (World 0). When used correctly, it acts as a type-enforcing, clone-creating boundary between V8 worlds.

---

## How contextBridge Sanitizes

When you expose a value via `contextBridge`:

1. **Objects are deep-cloned** — the renderer gets a copy, not a reference to the preload's object
2. **Functions are wrapped** — calls from renderer trigger preload functions but can't access preload's scope
3. **Prototype chain is not transferred** — prototypes from preload don't exist in renderer world
4. **Closures are isolated** — renderer can't access variables closed over in preload functions

```javascript
// preload.js:
const secret = "super-secret-value";

contextBridge.exposeInMainWorld('api', {
  greet: (name) => `Hello ${name}`,  // name validated here, not in renderer
  getVersion: () => app.getVersion(), // app not accessible in renderer
  // secret is NOT exposed — contextBridge only exposes what you explicitly give it
});

// renderer.js:
window.api.greet("World");   // Works — calls preload function
window.api.secret;            // undefined — secret not exposed
window.api.greet.__closure;  // undefined — closure not accessible
```

---

## What contextBridge Enforces

| Property | Behavior |
|----------|----------|
| Type enforcement | Only primitives, objects, arrays, Buffers, and functions are allowed |
| Object cloning | Plain objects are deep-cloned; references not shared |
| Function wrapping | Calls cross-world boundary safely |
| Prototype isolation | `Object.prototype` chains not transferred |
| Class instances | NOT directly cloneable — convert to plain objects first |

---

## Limitations — When contextBridge Fails

### 1. Exposed Functions That Accept Arbitrary Data

The bridge enforces *structure*, not *semantics*. If you expose a function that does something dangerous with its arguments, the bridge doesn't help:

```javascript
// contextBridge is no protection here:
contextBridge.exposeInMainWorld('api', {
  run: (cmd) => exec(cmd)  // contextBridge exposes it safely, but exec is still dangerous
});

// Renderer:
window.api.run('rm -rf /');  // contextBridge just calls exec('rm -rf /')
```

### 2. Getter/Setter Interception

When preload exposes an object and then reads properties from it:

```javascript
// preload.js:
contextBridge.exposeInMainWorld('api', {
  processConfig: (config) => {
    // config arrives as a deep clone — this is safe
    // BUT if we pass config to a function that reads it multiple times:
    if (config.type === 'safe') {
      doSafeOperation(config.value);  // config.type could have changed between reads
    }
    // Actually: with contextBridge cloning, the clone is immutable from renderer's side
    // This attack requires contextIsolation:false (no contextBridge)
  }
});
```

### 3. Class Instances Not Cloneable

```javascript
// preload.js:
class SecureBuffer {
  constructor(data) { this._data = data; }
  get() { return this._data; }
}

contextBridge.exposeInMainWorld('api', {
  getBuffer: () => new SecureBuffer('secret')  // ERROR: class instances not allowed
  // contextBridge throws: "An object could not be cloned."
});

// Fix: return plain objects:
getBuffer: () => ({ data: 'secret' })  // Works — but SecureBuffer methods lost
```

### 4. Callback Arguments Not Validated

When preload accepts callbacks from the renderer:

```javascript
// preload.js:
contextBridge.exposeInMainWorld('api', {
  onUpdate: (callback) => {
    if (typeof callback !== 'function') return;  // Good: validates type
    
    ipcRenderer.on('update', (_event, data) => {
      callback(data);  // data from main process → passed to renderer callback
      // If data is attacker-controlled, callback receives it
    });
  }
});

// The callback itself runs in renderer world — contextBridge doesn't sanitize
// data passed TO the callback. If callback does innerHTML = data, still vulnerable.
```

---

## Effective Use Patterns

### Pattern 1: Narrow API with Type Guards

```javascript
contextBridge.exposeInMainWorld('api', {
  saveNote: (title, content) => {
    // Validate in preload before IPC:
    if (typeof title !== 'string' || title.length > 200) {
      throw new TypeError('Invalid title');
    }
    if (typeof content !== 'string' || content.length > 100_000) {
      throw new TypeError('Invalid content');
    }
    return ipcRenderer.invoke('note:save', title, content);
  }
});
```

### Pattern 2: Enum-Based Channel Restriction

```javascript
const ALLOWED_ACTIONS = ['save', 'load', 'delete', 'list'] as const;
type Action = typeof ALLOWED_ACTIONS[number];

contextBridge.exposeInMainWorld('api', {
  perform: (action: Action, ...args: unknown[]) => {
    if (!ALLOWED_ACTIONS.includes(action)) {
      throw new Error(`Unknown action: ${action}`);
    }
    return ipcRenderer.invoke(`note:${action}`, ...args);
  }
});
```

### Pattern 3: No Passthrough — Explicit Arguments Only

```javascript
// ❌ Bad: passes args array directly (attacker can add extra properties):
contextBridge.exposeInMainWorld('api', {
  call: (channel, ...args) => ipcRenderer.invoke(channel, ...args)
});

// ✅ Good: explicitly construct each argument:
contextBridge.exposeInMainWorld('api', {
  sendMessage: (to, body) => ipcRenderer.invoke('chat:send', {
    to: String(to).slice(0, 100),   // Coerce and bound
    body: String(body).slice(0, 5000)
  })
});
```

---

## Checking contextBridge Usage

```bash
# Find all exposeInMainWorld calls:
grep -rn "exposeInMainWorld\|contextBridge" --include="*.js" . | grep -v node_modules

# Find over-broad exposures (ipcRenderer or require directly exposed):
grep -rn "exposeInMainWorld" --include="*.js" . -A 20 | \
  grep -E "ipcRenderer\b|require\b" | grep -v "ipcRenderer\.\(invoke\|send\|on\)" | \
  grep -v node_modules

# Find missing type validation before IPC:
grep -rn "exposeInMainWorld" --include="*.js" . -A 30 | \
  grep "invoke\|send\b" | grep -v "typeof\|instanceof" | grep -v node_modules
```

---

## Summary

| contextBridge Protects Against | Does NOT Protect Against |
|-------------------------------|--------------------------|
| Renderer accessing preload scope | Dangerous operations in exposed functions |
| Prototype pollution (from renderer) | Insufficient argument validation |
| Direct IPC access from renderer | Attacker-controlled data passed to sinks |
| Node.js APIs in renderer | Overly broad API surface |
| World 0 ↔ World 999 prototype chain | Callback data from main process |
