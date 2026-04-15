---
title: Attack Surfaces
description: Every external interface of an Electron app — where attackers can interact and inject data
---

# Attack Surfaces

Here's the thing about Electron apps from an attacker's perspective: you're not looking at a web app with some desktop chrome bolted on. You're looking at a full Chromium renderer, a Node.js runtime with filesystem and shell access, OS-level protocol integrations, and an auto-update mechanism — all bundled into a single process hierarchy with a privilege boundary that the developer drew themselves, in JavaScript, usually without a security review. That's an extraordinarily rich target.

The reason Electron apps get popped so consistently isn't because Electron is uniquely broken. It's because most teams shipping an Electron app are web developers who didn't realize they were also shipping a desktop app with native code privileges. When you pick up a new Electron target, don't ask "is there a bug?" — ask "which surface category does this team's blind spot live in?"

Start with BrowserWindow config. Always. One misconfigured `webPreferences` key can invalidate every other defense in the app. Then work outward to IPC channels, protocol handlers, and the update mechanism. File system and native bindings are slower to pop but important for LPE or when the first three come up clean.

---

## Surface Categories

<div class="es-card-grid">

<a class="es-card" href="browserwindow.md">
<div class="es-card-title">🖼️ BrowserWindow Config</div>
<div class="es-card-desc">webPreferences settings that determine renderer capabilities. The most critical configuration surface — a single wrong option opens the entire attack surface.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span></div>
</a>

<a class="es-card" href="ipc-channels.md">
<div class="es-card-title">📡 IPC Channels</div>
<div class="es-card-desc">ipcMain handlers exposed to any renderer. Each handler is an attack surface — a compromised renderer can call any handler it can discover.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span></div>
</a>

<a class="es-card" href="protocol-handlers.md">
<div class="es-card-title">🔗 Protocol Handlers</div>
<div class="es-card-desc">Custom URL schemes registered with the OS. Attackers can trigger these from web pages, emails, or other apps. Parameters are fully attacker-controlled.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span></div>
</a>

<a class="es-card" href="update-mechanism.md">
<div class="es-card-title">🔄 Update Mechanism</div>
<div class="es-card-desc">Auto-update infrastructure. If the update channel is compromised or MitM'd, the attacker delivers code that runs with the app's full identity.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span></div>
</a>

<a class="es-card" href="webcontents.md">
<div class="es-card-title">🌐 webContents API</div>
<div class="es-card-desc">Main process API for controlling renderers — executeJavaScript, loadURL, navigation events. Over-use = privilege boundary violations.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span></div>
</a>

<a class="es-card" href="asar-surface.md">
<div class="es-card-title">📦 ASAR Package</div>
<div class="es-card-desc">The application archive on disk. Without integrity validation, local attackers can modify app code. Unpacked files are never validated.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span></div>
</a>

<a class="es-card" href="devtools.md">
<div class="es-card-title">🔧 Developer Tools</div>
<div class="es-card-desc">DevTools enabled in production, --inspect CLI flags not disabled by fuses, debug ports accessible. Gives JS REPL in the main process.</div>
<div class="es-card-meta"><span class="badge badge-high">HIGH</span></div>
</a>

<a class="es-card" href="filesystem.md">
<div class="es-card-title">📁 File System</div>
<div class="es-card-desc">Apps that read user-provided file paths or monitor directories. File parsing of untrusted content (Markdown, PDF, images) may trigger code execution.</div>
<div class="es-card-meta"><span class="badge badge-medium">MEDIUM</span></div>
</a>

<a class="es-card" href="native-bindings.md">
<div class="es-card-title">🔩 Native Bindings</div>
<div class="es-card-desc">.node native addons processing attacker-controlled data. C/C++ code with memory safety bugs = memory corruption in the main process.</div>
<div class="es-card-meta"><span class="badge badge-medium">MEDIUM</span></div>
</a>

</div>

---

## Attack Surface Coverage Checklist

Run this before you open a single source file. The grep output tells you which surfaces exist; the absence of output tells you which ones the developer thought about. Both are signal.

```bash
# 1. BrowserWindow config — most critical:
grep -r "webPreferences\|new BrowserWindow" --include="*.js" . -A 15

# 2. IPC channels — count first, then enumerate:
grep -r "ipcMain\.\(on\|handle\)" --include="*.js" . | wc -l && \
grep -r "ipcMain\.\(on\|handle\)" --include="*.js" .

# 3. Protocol handlers:
grep -r "setAsDefaultProtocolClient\|registerFileProtocol\|registerStringProtocol" \
  --include="*.js" .

# 4. Update config:
cat electron-builder.yml | grep -A 10 "publish:"

# 5. DevTools / debug ports:
npx @electron/fuses read --app . | grep -E "RunAsNode|Inspect"

# 6. ASAR integrity:
npx @electron/fuses read --app . | grep -E "AsarIntegrity|OnlyLoad"

# 7. Native modules:
find . -name "*.node" | grep -v node_modules | head -10
```
