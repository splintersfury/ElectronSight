---
title: Process & System Sinks
description: Process spawning, environment manipulation, and OS-level sinks in Electron apps
---

# Process & System Sinks

Process and system sinks involve interactions with the operating system at a level beyond file I/O — spawning processes, manipulating the environment, loading native modules, and issuing system calls. These sinks are typically one step from full RCE.

---

## child_process Family

The most direct RCE sinks in Node.js:

```javascript
const { exec, execSync, execFile, spawn, spawnSync, fork } = require('child_process');

// exec — shell string, highest risk:
exec(userInput);                          // SINK: shell injection
exec(`convert "${userInput}" output.png`); // SINK: quote escape → RCE

// execSync — synchronous, same risk:
const result = execSync(`git log ${branch}`); // SINK: branch = '; rm -rf /'

// execFile — no shell, but arg injection still possible:
execFile('/usr/bin/ffmpeg', ['-i', userInput, 'output.mp4']);  
// execFile with array args — no shell injection, but:
// if userInput = '-vf scale=0:0 -vcodec libx264 /etc/shadow' → arg injection

// spawn — lower risk than exec but not safe with shell:true:
spawn('bash', ['-c', userInput]);              // shell:true equivalent
spawn(userInput, [], { shell: true });          // SINK: shell spawned

// fork — Node.js child process:
fork(userInput);                               // SINK: arbitrary module execution
fork(path.join(__dirname, userInput));         // SINK: path traversal → arbitrary module
```

### Taint Pattern — exec String Concatenation

```javascript
// Classic injection via template literal:
ipcMain.handle('run-task', async (event, args) => {
  const cmd = `node scripts/${args.script} --env ${args.env}`;
  //                         ^^^^^^^^^^^^        ^^^^^^^^^
  //                         path traversal      env injection
  return exec(cmd);
});

// Attack:
// args.script = "../../malicious.js"
// args.env    = "prod; calc.exe; echo "
```

---

## process Object Manipulation

The Node.js `process` object exposes dangerous APIs:

```javascript
// process.env — read and write:
const apiKey = process.env.SECRET_API_KEY;   // SOURCE (if reflected to renderer)
process.env.PATH = userInput + ':' + process.env.PATH;  // PATH hijack

// process.chdir — change working directory:
process.chdir(userInput);  // SINK: changes cwd for subsequent relative paths
                            // subsequent exec('node script.js') loads from attacker path

// process.dlopen — load native module:
process.dlopen({ exports: {} }, userInput);   // SINK: arbitrary .node/.so/.dll load
                                               // bypasses require() safety checks

// process.abort / process.exit — DoS:
process.exit(0);   // SINK: terminates app (DoS)
process.abort();   // SINK: crash with core dump

// process.kill — signal sending:
process.kill(parseInt(userPid), 'SIGKILL');  // SINK: kill arbitrary process
```

### process.dlopen — Arbitrary Native Code

```javascript
// This bypasses ASAR integrity checks:
ipcMain.handle('load-plugin', async (event, pluginPath) => {
  const mod = { exports: {} };
  process.dlopen(mod, pluginPath);  // SINK: loads .node file from attacker path
  return mod.exports.run();
});

// Attack: craft a .node file (shared library) with malicious code
// Copy to accessible path, call load-plugin with its path
// → arbitrary native code execution, bypasses V8 entirely
```

---

## Module Loading Sinks

Dynamic module loading is often overlooked as a sink:

```javascript
// require() with dynamic path:
const plugin = require(userInput);           // SINK: arbitrary module
const mod = require(`./plugins/${name}`);    // SINK: path traversal

// Without contextIsolation, renderer can call:
window.require('child_process').exec('calc'); // Full RCE if nodeIntegration:true

// Dynamic import():
import(userInput).then(mod => mod.execute()); // SINK: dynamic module load

// vm.runInNewContext — isolated but still dangerous:
const vm = require('vm');
vm.runInNewContext(userCode, {});             // SINK: code execution (escapes sandbox)
vm.runInThisContext(userCode);                // SINK: executes in current context
```

### vm Escape

The `vm` module is **not** a security boundary:

```javascript
// vm.runInNewContext can be escaped:
const code = `
  (function() {
    const process = this.constructor.constructor('return process')();
    return process.mainModule.require('child_process').execSync('id').toString();
  })()
`;
vm.runInNewContext(code, {});  // Escapes the "sandbox"
```

---

## Shell Integration Sinks

Beyond `child_process`, Electron and Node.js provide additional shell-integration APIs:

```javascript
const { shell } = require('electron');

// shell.openPath — OS file opener:
shell.openPath(userInput);          // SINK: opens arbitrary file with default app
                                     // .exe/.app → execution, .html → browser/renderer

// shell.openExternal — see navigation sinks for full details:
shell.openExternal(userInput);      // SINK: OS protocol handler dispatch

// shell.moveItemToTrash:
shell.moveItemToTrash(userInput);   // SINK: arbitrary file deletion (DoS)

// shell.showItemInFolder:
shell.showItemInFolder(userInput);  // Low-risk but path traversal for disclosure
```

### shell.openPath vs openExternal

```
openPath(p)    → OS opens p as if double-clicked (Run dialog equivalent)
               → .exe → execute, .bat → cmd.exe, .html → browser
               → RISK: arbitrary file execution on Windows via .bat/.cmd/.vbs

openExternal(url) → Dispatches URL to protocol handler
               → file:///path/to/evil.html → load local HTML
               → ms-msdt://... → Windows MSDT RCE (Follina)
```

---

## Environment Injection via process.env

When an Electron app spawns child processes using inherited environment:

```javascript
// App reads config from env:
const nodeFlags = process.env.NODE_OPTIONS;

// If NODE_OPTIONS fuse is disabled but app spawns node processes:
const child = spawn('node', [scriptPath], {
  env: { ...process.env, ...userConfig }  // SINK: userConfig pollutes child's env
});

// Attack: if userConfig.NODE_OPTIONS = '--require /malicious.js'
// The spawned node process will load attacker's module on startup
```

---

## OS-Level APIs via Native Modules

Apps using `.node` native addons expose OS-level operations:

```javascript
// Example: native file watcher addon used as file read primitive:
const watcher = require('./native_modules/file_watcher.node');
watcher.watch(userPath, callback);  // SINK: arbitrary file read/monitor

// Example: native crypto addon:
const crypto = require('./crypto_addon.node');
crypto.sign(userPrivateKeyPath, data);  // SINK: reads arbitrary key file

// Example: shell command via native binding:
const shellBridge = require('./shell_bridge.node');
shellBridge.run(userCommand);  // SINK: native exec
```

---

## Finding Process/System Sinks

```bash
# Find all child_process usage:
grep -r "exec\|spawn\|execFile\|fork\b" --include="*.js" . | \
  grep -v "node_modules\|//.*exec\|addEventListener" | \
  grep -v "\.regexp\|\.exec(" | head -50

# Find dynamic require/import:
grep -rn "require(\s*[^'\"]" --include="*.js" . | grep -v node_modules
grep -rn "import(" --include="*.js" . | grep -v "node_modules\|import('" | head -20

# Find process object usage:
grep -rn "process\.\(dlopen\|chdir\|env\[" --include="*.js" . | grep -v node_modules

# Find shell.openPath:
grep -rn "shell\.openPath\|openPath(" --include="*.js" . | grep -v node_modules

# Find vm module usage (potential sandbox escape):
grep -rn "require('vm')\|require(\"vm\")\|runInNewContext\|runInThisContext" \
  --include="*.js" . | grep -v node_modules
```

---

## Risk Matrix

| Sink | Risk | Shell? | Attacker Control Required |
|------|------|--------|--------------------------|
| `exec(userInput)` | Critical | Yes | String in shell |
| `spawn(shell, ['-c', userInput])` | Critical | Yes | String in shell |
| `process.dlopen(_, path)` | Critical | No | Path to .node file |
| `fork(userInput)` | Critical | No | Module path |
| `require(userInput)` | Critical | No | Module path |
| `vm.runInNewContext(code)` | Critical | No | JS string |
| `shell.openPath(path)` | High | OS-dep | File path |
| `shell.openExternal(url)` | High | OS-dep | URL string |
| `process.kill(pid, sig)` | Medium | No | PID (integer) |
| `process.chdir(dir)` | Medium | No | Directory path |
| `process.exit()` | Low | No | — (DoS only) |
