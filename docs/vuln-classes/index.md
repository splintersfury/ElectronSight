---
title: Vulnerability Classes
description: 12 distinct Electron vulnerability patterns with CVEs, exploitation payloads, and detection methods
---

# Vulnerability Classes

Electron has a finite set of ways things go wrong. The specific apps change, the specific code changes, but the patterns repeat. Once you recognize them, you'll start seeing the same structures everywhere — the ipcMain handler calling exec() with renderer input, the Markdown sink with no DOMPurify, the workspace name rendered without sanitization.

These are the 12 classes that show up in real CVEs across real apps. Each one has been found — not theorized — in production software that people actually use.

---

## Class Overview

<div class="es-card-grid">

<a class="es-card" href="xss-to-rce.md">
<div class="es-card-title">💥 XSS → RCE</div>
<div class="es-card-desc">DOM injection in a misconfigured renderer reaches Node.js. The classic Electron chain. Requires: contextIsolation:false OR nodeIntegration:true OR over-privileged preload.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span> <span class="badge badge-info">Most Common</span></div>
</a>

<a class="es-card" href="context-isolation-false.md">
<div class="es-card-title">🔓 contextIsolation=false</div>
<div class="es-card-desc">Disabling context isolation merges the preload and page JS contexts. XSS gains direct access to ipcRenderer, Node.js globals, and preload-defined functions.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span></div>
</a>

<a class="es-card" href="node-integration-true.md">
<div class="es-card-title">🔩 nodeIntegration=true</div>
<div class="es-card-desc">Enabling Node.js in the renderer process. Any XSS immediately becomes RCE via require('child_process'). The most dangerous single option in Electron.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span></div>
</a>

<a class="es-card" href="protocol-handler-rce.md">
<div class="es-card-title">🔗 Protocol Handler RCE</div>
<div class="es-card-desc">Custom or OS protocol handlers open URLs in the OS. Attacker-controlled protocol URLs can launch executables, trigger Follina, or capture NTLM hashes.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span></div>
</a>

<a class="es-card" href="asar-tampering.md">
<div class="es-card-title">📦 ASAR Tampering</div>
<div class="es-card-desc">Modifying the app.asar archive to inject malicious code. Effective without ASAR integrity validation. Enables persistence, local LPE, and supply chain attacks.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span></div>
</a>

<a class="es-card" href="update-poisoning.md">
<div class="es-card-title">🔄 Update Poisoning</div>
<div class="es-card-desc">Compromising the auto-update mechanism to deliver malicious updates. electron-updater misconfigurations allow downgrade attacks and unsigned package delivery.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span></div>
</a>

<a class="es-card" href="prototype-pollution.md">
<div class="es-card-title">🧬 Prototype Pollution</div>
<div class="es-card-desc">Poisoning Object.prototype reaches security checks in the main process or preload. Can bypass auth, corrupt config, or enable code execution via gadget chains.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span></div>
</a>

<a class="es-card" href="ipc-injection.md">
<div class="es-card-title">📡 IPC Injection</div>
<div class="es-card-desc">Sending crafted messages to IPC handlers that perform privileged operations without validating input or sender origin. The most common post-XSS escalation path.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span></div>
</a>

<a class="es-card" href="open-external.md">
<div class="es-card-title">🔗 shell.openExternal Abuse</div>
<div class="es-card-desc">Passing attacker-controlled URLs to shell.openExternal. Exploits OS protocol handlers (ms-msdt, search-ms, file://) for RCE without requiring renderer compromise.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span></div>
</a>

<a class="es-card" href="fuse-misconfig.md">
<div class="es-card-title">⚡ Fuse Misconfiguration</div>
<div class="es-card-desc">Dangerous Electron fuses left enabled: RunAsNode, NodeOptions, NodeCliInspect. Enables arbitrary Node.js execution via environment variables or command-line flags.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span></div>
</a>

<a class="es-card" href="websecurity-false.md">
<div class="es-card-title">🌐 webSecurity=false</div>
<div class="es-card-desc">Disabling web security bypasses Same-Origin Policy, CORS, and mixed content blocking. Enables CSRF, cross-origin data theft, and local file access from the web.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span></div>
</a>

<a class="es-card" href="preload-bypass.md">
<div class="es-card-title">🔀 Preload Script Bypass</div>
<div class="es-card-desc">Techniques to execute code in the preload script's isolated world or subvert its security controls: prototype pollution, exposed functions, over-privileged bridge.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span></div>
</a>

</div>

---

## Severity vs. Prevalence

```
          HIGH SEVERITY
               │
               │  Protocol Handler RCE
               │  nodeIntegration=true
               │  IPC Injection          XSS→RCE
               │  Update Poisoning
               │  ASAR Tampering         contextIsolation=false
               │  shell.openExternal     Preload Bypass
               │  Prototype Pollution    
               │  webSecurity=false      Fuse Misconfig
               │
               └────────────────────────────────────
          LOW  │                                  HIGH
         PREV. │                              PREVALENCE
```

---

## Quick Detection Checklist

For any Electron app, check these in order:

```bash
# 1. Electron version (determines defaults):
grep -r "\"electron\":" package.json

# 2. Critical misconfigs:
grep -r "nodeIntegration.*true\|contextIsolation.*false\|webSecurity.*false\|sandbox.*false" \
  --include="*.js" .

# 3. Dangerous preload patterns:
grep -r "exposeInMainWorld" --include="*.js" . -A 20 | \
  grep -E "ipcRenderer|require|child_process|shell"

# 4. Over-privileged IPC handlers:
grep -r "ipcMain\.\(on\|handle\)" --include="*.js" . -A 10 | \
  grep -E "exec|spawn|readFile|writeFile|eval"

# 5. Unvalidated shell.openExternal:
grep -r "openExternal" --include="*.js" . -B 5 | grep -v "^--"

# 6. Fuse state:
npx @electron/fuses read --app .

# 7. Markdown rendering:
grep -r "marked\|showdown\|commonmark\|DOMPurify" --include="*.js" . | grep -v node_modules
```

---

## How Much Work Each Class Takes

| Class | What You Need | Steps | Typical Payout Tier |
|-------|--------------|-------|---------------------|
| nodeIntegration=true + XSS | Any DOM XSS | 1 | Critical — P1 |
| contextIsolation=false + XSS | Any DOM XSS | 2 | Critical — P1 |
| Protocol Handler RCE | Crafted URL | 1 | Critical — P1 |
| IPC Injection | XSS + open channel | 2-3 | Critical — P1 |
| Preload Bypass | XSS | 2-3 | Critical — P1 |
| Update Poisoning | MitM or server compromise | 1 | Critical — P1 |
| ASAR Tampering | Local write access | 1 (local) | High — P2 (LPE) |
| webSecurity=false | XSS or CSRF | 2-3 | High — P2 |
| shell.openExternal abuse | XSS | 2 | High — P2 |
| Prototype Pollution | XSS or stored data | 3-5 | High — P2/P3 |
| Fuse Misconfig | Env var or CLI access | 1 | Medium — P3 |

The short-step ones are usually worth finding first. A two-step chain (XSS + IPC injection) is still a high-impact finding with a clear, reproducible PoC — much easier to validate and write up than a five-step prototype pollution gadget chain.
