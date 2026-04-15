---
title: Sanitizers
description: What breaks taint chains in Electron — contextBridge, CSP, sandbox, input validation, DOMPurify, and bypass techniques
---

# Sanitizers

A sanitizer is anything that breaks the link between a source and a sink. Good sanitizers actually prevent attacker-controlled data from causing harm. Bad sanitizers — or sanitizers applied in the wrong place — create the illusion of protection while leaving the actual taint chain intact.

This section documents what the real sanitizers are, what each one actually protects against, and — most usefully — how each one commonly fails in practice. Because finding a bug often means finding the gap between "this sanitizer exists" and "this sanitizer actually covers this path."

---

## The Sanitizers

<div class="es-card-grid">

<a class="es-card" href="context-bridge.md">
<div class="es-card-title">🌉 contextBridge</div>
<div class="es-card-desc">The architectural gateway between preload and page. Enforces that only explicitly exposed APIs are accessible. Useless if the exposed API itself is dangerous — it doesn't validate semantics, only structure.</div>
<div class="es-card-meta"><span class="badge badge-sanitizer">SANITIZER</span> <span class="badge badge-high">Design-Bypassable</span></div>
</a>

<a class="es-card" href="csp.md">
<div class="es-card-title">🛡️ Content Security Policy</div>
<div class="es-card-desc">Blocks inline script execution and restricts script sources. The browser's primary XSS defense. In Electron, apps must opt in — there's no automatic CSP. JSONP endpoints on allowlisted domains bypass it.</div>
<div class="es-card-meta"><span class="badge badge-sanitizer">SANITIZER</span> <span class="badge badge-medium">Partial</span></div>
</a>

<a class="es-card" href="sandbox-isolation.md">
<div class="es-card-title">🏗️ Sandbox & Process Isolation</div>
<div class="es-card-desc">OS-level process sandbox (seccomp-BPF, Seatbelt, Job Objects) plus contextIsolation. Limits what a compromised renderer can do without going through IPC. Strong — but IPC handlers still need independent validation.</div>
<div class="es-card-meta"><span class="badge badge-sanitizer">SANITIZER</span> <span class="badge badge-high">Strong</span></div>
</a>

<a class="es-card" href="input-validation.md">
<div class="es-card-title">✅ Input Validation</div>
<div class="es-card-desc">Type checks, allowlists, bounds checks applied in IPC handlers. The last line of defense — validation in main process handlers is the only validation that actually counts, since preload-only validation is skippable post-XSS.</div>
<div class="es-card-meta"><span class="badge badge-sanitizer">SANITIZER</span> <span class="badge badge-medium">Depends on Implementation</span></div>
</a>

<a class="es-card" href="dompurify.md">
<div class="es-card-title">🧹 DOMPurify</div>
<div class="es-card-desc">HTML sanitization library. The right tool for when you genuinely need innerHTML. Has had historical bypasses via mXSS (mutation XSS — where the parsed tree looks safe but transforms when moved). Must be kept current.</div>
<div class="es-card-meta"><span class="badge badge-sanitizer">SANITIZER</span> <span class="badge badge-high">Strong (if current)</span></div>
</a>

<a class="es-card" href="anti-patterns.md">
<div class="es-card-title">🚫 Anti-Patterns</div>
<div class="es-card-desc">Things that feel like sanitization but aren't: regex HTML stripping, denylist-based filtering, client-side-only validation, JSON.stringify before innerHTML, textContent-then-innerHTML. These create false confidence.</div>
<div class="es-card-meta"><span class="badge badge-high">Watch Out</span></div>
</a>

</div>

---

## What Each Sanitizer Actually Covers

No single sanitizer stops everything. The goal is layered coverage where each layer catches what the previous one misses:

| Sanitizer | Stops XSS | Stops IPC Injection | Stops Protocol Abuse | Stops ASAR Tamper |
|-----------|-----------|---------------------|---------------------|-------------------|
| Tight contextBridge API | Partially | Yes | Partially | No |
| contextIsolation: true | Partially | Yes | No | No |
| sandbox: true | No (renderer) | Yes (renderer→main) | No | No |
| CSP (strict) | Yes | No | No | No |
| DOMPurify | Yes | No | No | No |
| IPC input validation | No | Yes | No | No |
| URL allowlist in openExternal | No | No | Yes | No |
| ASAR integrity fuse | No | No | No | Yes |

Reading this table, you can see: if an app only has DOMPurify and CSP, it blocks XSS but does nothing about IPC injection or protocol handler abuse. An attacker who finds a CSP bypass or a Markdown sink that DOMPurify doesn't cover still has a path to an unvalidated IPC handler.

---

## The Assumption Audit

The most useful skill when analyzing sanitizers is asking: *what does this sanitizer assume, and can those assumptions be violated?*

**DOMPurify** assumes the browser and DOMPurify parse HTML identically. Mutation XSS (mXSS) violates this by using HTML that looks safe when parsed once but mutates when moved into the DOM or re-serialized. Most DOMPurify bypasses over the years have exploited exactly this.

**contextBridge** assumes the bridge is narrow. The bridge clones objects and prevents prototype pollution — but if the bridge exposes `(channel, ...args) => ipcRenderer.invoke(channel, ...args)`, the assumption that it limits access is completely violated by design.

**Input validation** assumes all input comes through the validated path. But post-XSS, an attacker calls `ipcRenderer.invoke('channel', args)` directly, bypassing whatever validation sits in the preload. Validation only counts when it's in the `ipcMain` handler.

**Sender validation** (`event.senderFrame.url`) assumes the app controls which URLs can be loaded in renderers. If `webSecurity: false` allows loading any `file://` URL, or if navigation policies are missing, the URL check can be satisfied by navigating the renderer first.

The pattern is always: find the sanitizer, find what it assumes, check whether those assumptions hold.

---

## Finding Sanitizers (and Gaps)

```bash
# Find DOMPurify (is it present? what version?):
grep -rn "DOMPurify\|dompurify" --include="*.js" . | grep -v node_modules
cat node_modules/dompurify/package.json | grep '"version"'

# Find CSP configuration (or lack of it):
grep -rn "Content-Security-Policy\|onHeadersReceived\|defaultSrc\|scriptSrc" \
  --include="*.js" --include="*.html" . | grep -v node_modules

# Find IPC handlers WITH validation (shows what's protected):
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 10 | \
  grep -E "typeof|instanceof|startsWith|\.includes\b|validate|allowlist" | grep -v node_modules

# Find IPC handlers WITHOUT validation (the gaps):
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 5 | \
  grep -v "node_modules\|typeof\|instanceof\|validate\|senderFrame" | \
  grep -E "exec\b|spawn\b|writeFile|openExternal" | head -20

# Find URL validation before openExternal:
grep -rn "openExternal" --include="*.js" . -B 10 | \
  grep -E "new URL|protocol\b|allowedSchemes\|startsWith.*https" | grep -v node_modules
```
