---
title: Internals
description: Electron architecture deep-dive — process model, IPC, context isolation, ASAR, fuses, V8 snapshots
---

# Electron Internals

You can't audit what you don't understand. Every exploitable Electron pattern — whether it's an unvalidated IPC handler, a missing fuse, or an over-wide contextBridge — makes sense once you see the architecture behind it. Without that, you're just grepping for `nodeIntegration: true` and hoping.

This section covers the mechanics. Not everything will be immediately relevant to every engagement, but reading it once will make you significantly faster at everything that follows.

---

## Architecture at a Glance

Electron bundles two very different runtimes into one application:

- **Chromium** — the browser engine (renderer process, GPU process, networking, OS sandbox)
- **Node.js** — the system runtime with full OS access, no restrictions

These run in separate OS processes and communicate over IPC. The whole security model comes down to one question: *which runtime is running in which process, and what is that process allowed to do?*

```
┌─────────────────────────────────────────────────────┐
│  Main Process (Node.js + Chromium internals)        │
│  ■ Full Node.js API (fs, child_process, net, ...)   │
│  ■ Creates/manages BrowserWindows                   │
│  ■ Handles app lifecycle, menus, tray, dialogs      │
│  ■ Owns native OS integrations                      │
└───────────────────┬─────────────────────────────────┘
                    │  Named pipes (Windows)
                    │  Unix domain sockets (macOS/Linux)
                    │  Mojo IPC (Chromium internal)
┌───────────────────▼─────────────────────────────────┐
│  Renderer Process(es) (Chromium renderer)           │
│  ■ Runs HTML/CSS/JS — like a browser tab            │
│  ■ sandboxed: true → no Node.js API                 │
│  ■ nodeIntegration: true → full Node.js API (bad)   │
│  ■ contextIsolation: true → separate JS worlds      │
└───────────────────┬─────────────────────────────────┘
                    │  contextBridge API
                    │  (controlled channel)
┌───────────────────▼─────────────────────────────────┐
│  Web Content / Preload Script                       │
│  ■ Preload: executes in renderer before page JS     │
│  ■ Exposes explicitly allowed APIs to page          │
│  ■ Attack surface: too-wide bridge = privilege esc  │
└─────────────────────────────────────────────────────┘
```

---

## Pages in This Section

| Page | What It Covers |
|------|----------------|
| [Process Model](process-model.md) | Main vs. renderer process, worker threads, GPU process, utility process |
| [IPC Architecture](ipc.md) | `ipcMain`/`ipcRenderer`, invoke/handle, contextBridge, Mojo wire format |
| [Context Isolation](context-isolation.md) | JS world separation, World IDs, prototype pollution prevention |
| [Preload Scripts](preload.md) | Execution timing, scope, contextBridge patterns, attack vectors |
| [Sandbox Architecture](sandbox.md) | Chromium sandbox, seccomp-BPF, Windows Job Objects, macOS Seatbelt |
| [Electron Fuses](fuses.md) | Binary-level feature flags, which fuses matter, how to audit |
| [ASAR Format](asar.md) | Archive structure, integrity validation, extraction attacks |
| [V8 Snapshots](v8-snapshots.md) | Heap serialization, precompiled code, snapshot backdooring (CVE-2025-55305) |
| [Session & Protocols](sessions.md) | Session partitioning, custom protocols, `registerFileProtocol` |
| [Native Modules](native-modules.md) | `.node` addons, N-API, native binding attack surface |

---

## Security-Critical Configuration Summary

The following `BrowserWindow` and app options directly determine the attack surface:

| Option | Secure Value | Dangerous Value | Impact |
|--------|-------------|-----------------|--------|
| `contextIsolation` | `true` | `false` | Renderer JS can access Node.js globals directly |
| `nodeIntegration` | `false` | `true` | Renderer has full Node.js API (RCE from XSS) |
| `sandbox` | `true` | `false` | Renderer runs without OS sandbox |
| `webSecurity` | `true` | `false` | Disables SOP, CORS, mixed content checks |
| `allowRunningInsecureContent` | `false` | `true` | HTTP resources in HTTPS context |
| `enableRemoteModule` | `false` | `true` | Legacy `remote` module (deprecated, dangerous) |
| `nodeIntegrationInWorker` | `false` | `true` | Web Workers get Node.js |
| `nodeIntegrationInSubFrames` | `false` | `true` | Subframes/iframes get Node.js |

!!! danger "The dangerous default era"
    Before Electron 5.0, `nodeIntegration: true` was the default. Before Electron 12, `contextIsolation: false` was the default. Apps that were built on those versions and never explicitly set these options — or just bumped the Electron version without a security review — are running with those old defaults today. That's a lot of legacy apps still in production.

---

## Electron Version Security Timeline

| Version | Change |
|---------|--------|
| 1.x–4.x | `nodeIntegration: true`, `contextIsolation: false` by default |
| 5.0 | `nodeIntegration: false` becomes default |
| 12.0 | `contextIsolation: true` becomes default |
| 14.0 | `remote` module removed from core |
| 20.0 | `sandbox: true` becomes default |
| 22.0 | `webContents.executeJavaScript` requires `allowRunningInsecureContent` for HTTP |

---

## How to Find the Electron Version

```bash
# From the binary
strings app.asar | grep "Electron/"
strings resources/app.asar | grep "Chrome/"

# From package.json inside asar
asar extract resources/app.asar /tmp/app
cat /tmp/app/package.json | grep electron

# DevTools (if accessible)
# In console: process.versions.electron

# From binary resources section
grep -a "electron/" path/to/app | head -5
```

The Electron version tells you which defaults were in effect when the app was built, which CVEs potentially affect it unpatched, and what to expect from its configuration. It's the first thing to check on any engagement.
