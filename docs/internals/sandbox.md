---
title: Sandbox Architecture
description: Chromium's process sandbox in Electron — seccomp-BPF, Windows Job Objects, macOS Seatbelt, and bypass research
---

# Sandbox Architecture

The sandbox is the OS-level defense that limits what a compromised renderer process can do. It's the reason XSS in a modern Electron app with `sandbox: true` isn't immediately game over — even if an attacker achieves code execution in the renderer, they can't directly open files, spawn processes, or make network connections. They're stuck inside Chromium's restricted process environment.

The important qualifier: "stuck inside the sandbox" doesn't mean "stuck." It means they have to find another way out. In Electron apps, that way out is usually the main process IPC handlers.

---

## How the Sandbox Works by Platform

### Linux: seccomp-BPF

The renderer runs under a seccomp-BPF syscall filter. Allowed syscalls are those needed to run JavaScript and communicate with the main process:

```
Allowed: read, write, mmap, munmap, brk, close, select, poll,
         futex, nanosleep, clock_gettime, gettid, exit, exit_group
         
Blocked: open, openat, execve, fork, clone (restricted), socket,
         connect, bind, listen, ptrace, chroot, and most others
```

A blocked syscall kills the renderer with SIGSYS. Even with arbitrary code execution in the renderer, the attacker cannot:

- Open files (`openat` blocked)
- Create network connections (`socket` blocked)
- Spawn processes (`execve` blocked)
- Read other processes' memory (`ptrace` blocked)

To escape, they need to exploit either a kernel vulnerability (hard, browser-class exploit) or find an IPC path to a main process handler that does these things on their behalf (common in Electron apps with unvalidated IPC handlers).

### macOS: Seatbelt

macOS uses `sandbox-exec` with a custom Chromium profile that denies most operations by default, then allowlists specific IPC channels and file paths needed for rendering. The profile broadly prevents direct file access and system calls that would let the attacker escape.

### Windows: Job Objects + Integrity Levels

Windows uses multiple mechanisms layered together:

- **Job Objects** — restrict process abilities: no admin access, no desktop creation, no elevated UI
- **Integrity Levels** — the renderer runs at Low integrity, below the user's data directories
- **Token Restrictions** — restricted SIDs and deny-only SIDs reduce privilege further

---

## Sandbox Configuration

```javascript
const win = new BrowserWindow({
  webPreferences: {
    sandbox: true    // OS sandbox enabled (default since Electron 20)
  }
});
```

`sandbox: true` is the default since Electron 20. Before that, it was off.

With `sandbox: false`:

- No seccomp filter on Linux
- No Seatbelt profile on macOS  
- Full medium-integrity token on Windows
- The renderer process has unrestricted OS access

`sandbox: false` combined with `nodeIntegration: true` is the worst possible configuration. The renderer has both `require('child_process')` and no OS restrictions. Any XSS immediately reaches full OS code execution with nothing in the way.

---

## The "Sandbox Escape" That's Not a Sandbox Escape

Most Electron "sandbox bypass" CVEs aren't kernel exploits or IPC-layer vulnerabilities. They're over-privileged main process handlers.

```
[Sandboxed renderer]  ──IPC──▶  [Main process handler]
 cannot exec() directly              calls exec() on renderer's behalf
 cannot open files                   opens arbitrary files on request
 cannot make connections             makes network calls as proxy
```

The OS sandbox is intact. The renderer really can't open files. But the main process, which has no sandbox, calls `fs.readFile(renderer_supplied_path)` because an IPC handler does that without validation.

From the OS's perspective: the sandbox held. From the application's perspective: the attacker read any file they wanted. The distinction matters for CVE classification but not for impact.

This is why IPC handler security is more important than sandbox configuration in practice. The sandbox works. The sandbox relies on the main process handlers being correctly implemented. They often aren't.

---

## Preload Scripts Under sandbox: true

With `sandbox: true`, preload scripts still execute in the renderer but have reduced Node.js access:

```javascript
// preload.js with sandbox: true — what's available:
const { contextBridge, ipcRenderer } = require('electron');
process.platform    // works
process.versions    // works

// What's NOT available:
require('child_process')  // throws
require('fs')             // throws in strict mode
require('net')            // throws
```

This is why many older apps set `sandbox: false` — their preloads used `require('fs')` or `require('path')` directly, and upgrading would break them. Upgrading these preloads to use IPC instead is the right fix; `sandbox: false` is the shortcut.

---

## Auditing Sandbox Configuration

```bash
# Find sandbox: false:
grep -rn "sandbox.*false\|sandbox:false" --include="*.js" . | grep -v node_modules

# On Linux, verify at runtime — check the actual seccomp state:
cat /proc/<renderer_pid>/status | grep Seccomp
# 2 = filter mode (sandboxed)
# 0 = not sandboxed

# nodeIntegration:true with sandbox:false is worst-case:
grep -rn "nodeIntegration.*true" --include="*.js" . | grep -v node_modules
grep -rn "sandbox.*false" --include="*.js" . | grep -v node_modules
# Finding both in the same BrowserWindow is Critical
```

`sandbox: false` alone is a security regression but needs context — it has limited direct impact if `nodeIntegration` is also off. The combination `sandbox: false` + `nodeIntegration: true` is the critical configuration to flag.
