---
title: Sandbox & Process Isolation
description: OS-level sandboxing, process separation, and their limitations as security boundaries
---

# Sandbox & Process Isolation

The Chromium sandbox and Electron's process model create OS-level isolation between the renderer and the main process. This is the deepest defense layer — it limits what a compromised renderer can do even if all JavaScript-level defenses fail.

---

## The Sandbox Boundary

```
┌─────────────────────────────────────────┐
│ Main Process (no sandbox)               │
│ - Full Node.js + OS access              │
│ - exec(), fs.readFile(), shell.*        │
│ - ipcMain handlers                      │
│                                         │
│         ▲ IPC (the choke point)         │
│         │                               │
├─────────┼───────────────────────────────┤
│ Renderer Process (sandboxed)            │  ← Chromium sandbox active
│ - No direct OS access                   │
│ - No Node.js (if nodeIntegration:false) │
│ - Must go through IPC for privileged ops│
└─────────────────────────────────────────┘
```

When the sandbox is **active**, a compromised renderer must exploit:
1. A vulnerable IPC handler (most common)
2. A Chromium sandbox escape bug (rare, high-value)
3. A kernel vulnerability (extremely rare)

---

## What the Sandbox Restricts

### Linux (seccomp-BPF)

Chromium's Linux sandbox uses seccomp-BPF to filter system calls:

```
Blocked syscalls in renderer (partial list):
- execve / execveat     → No new processes
- fork / clone          → No child processes  
- ptrace               → No debugging
- socket (most)         → No raw network
- open (direct)         → No direct file access
- kill (most PIDs)      → Limited signal sending
- mmap (exec+write)     → No RWX mappings
```

An attacker in the renderer cannot call `exec()` directly — they must go through IPC.

### macOS (App Sandbox + Seatbelt)

Chromium on macOS uses `sandbox_init()` with Seatbelt profiles:

- No filesystem access outside allowed paths
- No network connections outside declared entitlements
- No process spawning
- No Mach port access to other processes

### Windows (Job Objects + ACL)

Chromium on Windows uses:
- **Job Objects**: limits process creation, UI interaction, clipboard
- **Low-integrity process**: can't write most HKLM keys, Program Files, etc.
- **Restricted token**: limits what kernel objects the process can access

---

## Sandbox Default Changes in Electron History

| Version | Default | Notes |
|---------|---------|-------|
| < Electron 5 | Off | Explicit `sandbox: true` needed |
| Electron 5-19 | Optional | `sandbox: false` default, opt-in |
| Electron 20+ | **On** | `sandbox: true` by default |

For apps built before Electron 20:
```javascript
// Many old apps explicitly disabled sandbox:
new BrowserWindow({
  webPreferences: {
    sandbox: false,  // Legacy — disables entire OS sandbox
    nodeIntegration: true  // Also grants Node.js access
  }
});
```

---

## sandbox: false — What It Enables

When `sandbox: false`:

1. The renderer process is NOT isolated by the OS
2. Chromium's renderer still runs but without syscall filtering
3. Combined with `nodeIntegration: true`: full OS access from renderer
4. Even without nodeIntegration: native modules can be loaded, some OS calls work

```javascript
// With sandbox:false + nodeIntegration:true:
// Any XSS in renderer = immediate RCE:
const { exec } = require('child_process');  // Available in renderer
exec('calc.exe');  // Direct OS execution — no IPC needed
```

---

## Process Isolation vs Context Isolation

These are different defenses, often confused:

```
contextIsolation: true
  → V8-level: preload and renderer JS can't access each other's scope
  → Does NOT protect against Node.js access (that's nodeIntegration)
  → Does NOT protect the OS (that's sandbox)

sandbox: true
  → OS-level: renderer process cannot access OS directly
  → Does NOT prevent JS execution in renderer
  → Does NOT prevent IPC calls from renderer

Both together → defense in depth:
  → Attacker can run JS in renderer (XSS)
  → But can't access preload scope (contextIsolation)
  → And can't access OS directly (sandbox)
  → Must go through validated IPC (contextBridge)
```

---

## The IPC Choke Point

When both `contextIsolation: true` and `sandbox: true` are in effect, all privilege escalation must go through IPC. This is why **IPC handler auditing is so important**:

```
XSS in renderer
    │
    │ Only path: contextBridge-exposed functions
    ▼
Preload validation (type checks, bounds)
    │
    │ Only if passes validation
    ▼
ipcRenderer.invoke('channel', validatedArgs)
    │
    ├── ipcMain validates sender (event.senderFrame.url)
    ├── ipcMain validates arguments again (defense in depth)
    └── Performs operation

If ANY ipcMain handler has no validation → sandbox bypass via IPC
```

---

## Sandbox Escapes (Real Examples)

True sandbox escapes (not IPC abuse) are rare and high-value:

### Chromium IPC Mojo Bug

Mojo is Chromium's internal IPC mechanism. Bugs in Mojo message parsing can allow:
- Type confusion in IPC message deserialization
- Out-of-bounds read/write in browser process
- Browser process compromise → full OS access

These are typically rated Critical by Chrome VRP.

### V8 Type Confusion

V8 bugs that corrupt the heap can allow:
- Addrof/fakeobj primitives in JavaScript
- Arbitrary read/write of browser process memory
- Bypassing sandbox via heap exploitation

Example flow:
```javascript
// Trigger V8 type confusion:
const a = [1.1, 2.2, 3.3];
// ... exploit V8 bug to get arbitrary read/write ...
// Write shellcode to browser process memory
// Call it via function pointer overwrite
```

---

## Verifying Sandbox Status

```javascript
// In main process — check if renderer is sandboxed:
const { webContents } = require('electron');

webContents.getAllWebContents().forEach(wc => {
  console.log(`[${wc.id}] sandboxed: ${wc.isCrashed()}`);  // Not quite right
  // Use: process.sandboxed from renderer
});

// In renderer process:
process.sandboxed  // true if sandbox is active
```

```bash
# Check BrowserWindow config for sandbox:false:
grep -rn "sandbox\s*:\s*false" --include="*.js" . | grep -v node_modules

# Check if nodeIntegration is enabled without sandbox:
grep -rn "nodeIntegration\s*:\s*true" --include="*.js" . | grep -v node_modules
```

---

## Sandbox as Defense Layer

| Threat | Sandbox Effectiveness |
|--------|----------------------|
| XSS → direct exec() | ✅ Blocks (no execve in renderer) |
| XSS → direct file read | ✅ Blocks (no open() in renderer) |
| XSS → over-privileged IPC handler | ❌ Does NOT block (IPC crosses boundary) |
| Malicious native module in renderer | ⚠️ Partially blocks (depends on .node capabilities) |
| Chromium renderer bug | ❌ Requires separate sandbox escape |
| V8 exploit | ❌ V8 runs in renderer, sandbox escape needed for OS |

**The sandbox doesn't help if IPC handlers are over-privileged.** It's necessary but not sufficient.
