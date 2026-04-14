---
title: Environment & CLI Sources
description: Environment variables, command-line arguments, and process arguments as attack sources
---

# Environment & CLI Sources

Environment variables and command-line arguments are read by the Electron main process at startup — before any renderer loads. An attacker who can influence these (by launching the app with controlled arguments, or by modifying the environment before launch) has a pre-renderer source of injection.

---

## Command-Line Arguments

Electron apps accept command-line arguments which are often processed by the main process:

```javascript
// process.argv — SOURCE: fully attacker-controlled at launch
const args = process.argv.slice(2);  // Skip 'electron' and script path

// Common patterns:
const configFile = args[0];                         // SOURCE
const debug = args.includes('--debug');             // SOURCE (boolean)
const logLevel = args.find(a => a.startsWith('--log='))?.split('=')[1];  // SOURCE

// Dangerous usage:
exec(`myapp --config ${configFile}`);               // SINK: shell injection
fs.readFileSync(configFile, 'utf8');                // SINK: arbitrary file read
require(configFile);                                // SINK: arbitrary module load
```

### electron-builder and argv

Some Electron apps process `--squirrel-*` installer arguments on Windows:

```javascript
// Windows installer event handling:
if (process.argv[1] === '--squirrel-install') {
  createDesktopShortcut();
} else if (process.argv[1] === '--squirrel-firstrun') {
  openWelcomePage();
}

// Dangerous: if argv is used to construct paths:
const installPath = process.argv[2];  // SOURCE: attacker-controlled on Windows
createShortcut(installPath);          // SINK: creates shortcut to attacker path
```

---

## Environment Variables

`process.env` is populated from the shell environment when the app is launched:

```javascript
// SOURCE: environment variables
const apiEndpoint = process.env.API_ENDPOINT;     // SOURCE
const logPath = process.env.LOG_PATH;             // SOURCE
const preScript = process.env.MYAPP_PRE_SCRIPT;  // SOURCE

// Dangerous usage:
fetch(apiEndpoint + '/api/user');                 // SINK: if endpoint attacker-controlled
fs.appendFileSync(logPath, logEntry);             // SINK: arbitrary file write
exec(preScript);                                  // SINK: arbitrary command execution

// NODE_OPTIONS injection (if fuse not disabled):
// NODE_OPTIONS=--require /malicious.js myapp
// → Node.js loads /malicious.js before app code
```

### NODE_OPTIONS — Pre-Code Execution Source

One of the most dangerous environment variables in Node.js:

```javascript
// If EnableNodeOptionsEnvironmentVariable fuse is ON (default before Electron 12):
// Attacker sets: NODE_OPTIONS=--require /attacker.js
// Effect: /attacker.js runs before any app code, in main process

// /attacker.js:
const cp = require('child_process');
cp.execSync('calc.exe');  // Runs as the app's user before app code executes
```

**Mitigation:** Set the `EnableNodeOptionsEnvironmentVariable` fuse to `false`.

---

## ELECTRON_RUN_AS_NODE

A particularly dangerous environment variable:

```bash
# Forces Electron to behave as a plain Node.js interpreter:
ELECTRON_RUN_AS_NODE=1 /path/to/electron -e "require('child_process').execSync('calc')"

# Allows bypassing app-level security checks entirely
# The "app" never loads — just raw Node.js execution
```

**Mitigation:** Set the `RunAsNode` fuse to `false`.

---

## --inspect / --inspect-brk (Debugger)

Node.js debugger flags enable a WebSocket-based debug API:

```bash
# Launch with debugger:
/path/to/myapp --inspect=9229
# or:
/path/to/myapp --inspect-brk=9229

# Attacker connects to ws://127.0.0.1:9229 from localhost (or via SSRF):
# Chrome DevTools Protocol → arbitrary code execution in main process
```

```javascript
// From any local process after debugger attached:
// Send CDP message: Runtime.evaluate
{
  "method": "Runtime.evaluate",
  "params": {
    "expression": "require('child_process').execSync('calc')"
  }
}
// → RCE in main process
```

**Mitigation:** Set the `EnableNodeCliInspectArguments` fuse to `false`.

---

## Command-Line Switches via app.commandLine

Electron supports chromium switches that affect security:

```javascript
// At startup (before app.ready):
app.commandLine.appendSwitch('--disable-web-security');    // Disables CORS/SOP
app.commandLine.appendSwitch('--allow-running-insecure-content');
app.commandLine.appendSwitch('--no-sandbox');              // Disables Chromium sandbox

// If these are conditionally set based on env:
if (process.env.MYAPP_DEBUG === '1') {
  app.commandLine.appendSwitch('--disable-web-security');  // SOURCE → SINK
  // Attacker sets MYAPP_DEBUG=1 → defeats web security
}
```

---

## App Path Arguments

Some Electron apps accept a file/URL to open directly (like editors):

```javascript
// E.g., VS Code: `code /path/to/file`
// Electron equivalent:
const fileToOpen = process.argv[2];  // SOURCE

// If opened files are trusted:
const content = fs.readFileSync(fileToOpen, 'utf8');  // SOURCE
win.loadFile(fileToOpen);                              // SINK: loads arbitrary file
win.loadURL(`file://${fileToOpen}`);                   // SINK: arbitrary file load
exec(`open "${fileToOpen}"`);                          // SINK: shell injection
```

---

## Squirrel Installer Arguments (Windows)

On Windows, Electron apps using Squirrel for updates receive startup arguments:

```javascript
const squirrelEvent = process.argv[1];

switch (squirrelEvent) {
  case '--squirrel-install':
  case '--squirrel-updated':
    // Install/update handlers — argv[2] may be the install path
    const installPath = process.argv[2];   // SOURCE
    runPostInstall(installPath);           // SINK if not validated
    break;
}
```

---

## Detection Patterns

```bash
# Find process.argv usage:
grep -rn "process\.argv\b" --include="*.js" . | grep -v node_modules

# Find process.env reads:
grep -rn "process\.env\." --include="*.js" . | grep -v node_modules | head -40

# Find NODE_OPTIONS or ELECTRON_RUN_AS_NODE guards (should exist):
grep -rn "NODE_OPTIONS\|ELECTRON_RUN_AS_NODE" \
  --include="*.js" . | grep -v node_modules

# Find dangerous env-to-exec patterns:
grep -rn "process\.env\." --include="*.js" . -A 2 | \
  grep -E "exec\b|spawn\b|require\b|readFile\b" | grep -v node_modules

# Find --inspect flag guards (should block this if set):
grep -rn "inspect\|debugger\|devtools" --include="*.js" . | \
  grep "process\.argv\|commandLine\|switch" | grep -v node_modules

# Find app.commandLine.appendSwitch:
grep -rn "commandLine\.appendSwitch\|commandLine\.appendArgument" \
  --include="*.js" . | grep -v node_modules
```

---

## Risk Matrix

| Source | Risk | Attacker Access Required |
|--------|------|--------------------------|
| `NODE_OPTIONS=--require` | Critical | Shell env before launch |
| `ELECTRON_RUN_AS_NODE=1` | Critical | Shell env before launch |
| `--inspect=9229` flag | Critical | CLI arg + local port access |
| `process.argv` file path | High | CLI arg (or shortcut modification) |
| `process.env.MYAPP_CONFIG` | High | Shell env or `.env` file write |
| `app.commandLine.appendSwitch` from env | High | Env before launch |
| Squirrel installer args | Medium | Installer invocation |
| `--disable-web-security` switch | High | CLI arg or env |
