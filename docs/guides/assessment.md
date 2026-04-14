---
title: Assessing an Electron App
description: Complete methodology for security-assessing an Electron desktop application from scratch
---

# Assessing an Electron App

Here's the honest version of an Electron assessment methodology — not the idealized flow chart, but what actually happens when you sit down with an app you've never seen before and need to find something worth reporting.

The short version: Electron apps are usually JavaScript with a thin native wrapper. Once you have the source, you're doing JS code review. The Electron-specific part is understanding which JS patterns are dangerous *because of the runtime*, not just in the abstract.

---

## Phase 1: Confirm It's Electron, Get the Version

Before anything else, confirm the target is actually Electron and find out which version. The version changes what the defaults were — which determines how much work you're going to have to do.

```bash
# Quick check:
strings /path/to/binary | grep -E "Electron/|electron_version" | head -5

# macOS:
otool -L /Applications/Target.app/Contents/MacOS/Target | grep -i electron
ls /Applications/Target.app/Contents/Frameworks/ | grep Electron

# Windows:
strings "C:\Program Files\MyApp\MyApp.exe" | findstr "Electron/"
```

Then get the version from the ASAR:

```bash
asar extract /path/to/app.asar /tmp/app-source/
cat /tmp/app-source/package.json | grep -E '"electron"|"version"'
```

**Why the version matters:**

| Before Electron 5 | `nodeIntegration: true` by default — any XSS is RCE |
|---|---|
| Before Electron 12 | `contextIsolation: false` by default — merged JS contexts |
| Before Electron 20 | `sandbox: false` by default — no OS-level isolation |

An app built against Electron 4 that hasn't explicitly set these in their `webPreferences` is running with all three dangerous defaults. That's not common today but it shows up in older codebase that just bumped the Electron version without reviewing security implications.

---

## Phase 2: Extract the Source

```bash
# Find the ASAR:
# macOS: /Applications/<App>.app/Contents/Resources/app.asar
# Windows: C:\Program Files\<App>\resources\app.asar
# Linux: /opt/<app>/resources/app.asar

# Extract:
asar extract /path/to/app.asar /tmp/app-source/

# Note what's in the unpacked directory — these files are NOT integrity-checked:
ls /path/to/app.asar.unpacked/
```

If the app is minified, you'll want to run it through a prettifier before doing much analysis. The logic is still there; it's just harder to read. For symbol-stripped or compiled apps (rare — most Electron apps are plain JS), check if there's a source map in the bundle.

---

## Phase 3: Quick Automated Scan

Run these before reading a single line of code. They give you the lay of the land in under 5 minutes:

```bash
cd /tmp/app-source/

# Electronegativity — catches many misconfigs automatically:
electronegativity -i . -o /tmp/report.csv
cat /tmp/report.csv

# Fuse audit — check what's been locked down at the binary level:
npx @electron/fuses read --app /Applications/Target.app

# Critical misconfiguration grep:
echo "=== DANGEROUS SETTINGS ==="
grep -rn "nodeIntegration.*true\|contextIsolation.*false\|webSecurity.*false\|sandbox.*false" \
  --include="*.js" . | grep -v node_modules

# Count IPC handlers (attack surface size):
echo "=== IPC SURFACE ==="
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . | grep -v node_modules

# Dangerous sinks:
echo "=== DANGEROUS OPERATIONS ==="
grep -rn "\.exec\b\|\.spawn\b\|eval\b\|openExternal\|writeFileSync" \
  --include="*.js" . | grep -v node_modules | wc -l
```

By the end of this, you'll know: are there obvious misconfigs? How large is the IPC surface? How many dangerous operations exist? That shapes where you spend your time.

---

## Phase 4: Build a Mental Map

You need to understand the app's structure before diving into individual files. This is the archaeology phase.

**Find the entry point:**
```bash
cat package.json | python3 -c "import json,sys; p=json.load(sys.stdin); print('main:', p.get('main','index.js'))"
cat main.js | head -80  # or whatever package.json says
```

**Map every window:**
```bash
grep -rn "new BrowserWindow" --include="*.js" . -A 20 | \
  grep -E "new BrowserWindow|preload:|nodeIntegration|contextIsolation|sandbox|webSecurity"
```

For every `new BrowserWindow` you find, note its `webPreferences`. Missing settings mean the version default applies. If you know the app's Electron version and `contextIsolation` isn't explicitly set, you know whether the renderer gets the preload's scope.

**Map the IPC surface:**
```bash
# Every handler = potential privilege escalation path
grep -rn "ipcMain\.\(on\|handle\|once\)" --include="*.js" . | \
  grep -v node_modules | sort > /tmp/ipc_handlers.txt

# Every contextBridge exposure = renderer's attack surface
grep -rn "exposeInMainWorld" --include="*.js" . -A 20 | \
  grep -v node_modules
```

**Read each preload script:**

The preload is the most important file in the app. It defines exactly what the renderer can do. Read it completely. Look for: anything being exposed via `contextBridge`, any channels it invokes, any validation (or lack of it) on arguments.

---

## Phase 5: Prioritize What to Look At

By now you have a picture. Use it to rank your investigation targets:

| Priority | What You Found | What You Do |
|----------|---------------|-------------|
| Critical | `nodeIntegration: true` | Find any XSS — that's your RCE |
| Critical | `contextIsolation: false` | Find any XSS — renderer can call ipcRenderer directly |
| High | ipcMain handler calling `exec` or `spawn` | Find any renderer path to that handler |
| High | Preload exposes `ipcRenderer` directly | Find XSS anywhere in the app |
| High | `shell.openExternal(url)` with no URL validation | Find where `url` comes from |
| Medium | Path operations without traversal check | Find attacker-controlled path input |
| Low-Medium | Fuses not set | Document as configuration finding |
| Low | HTTP update server | Document as MITM risk |

Don't try to audit everything at once. Pick the highest priority item and trace it completely before moving on.

---

## Phase 6: Trace the Chain

For each priority finding, you're doing one of two things:

**If you found a dangerous setting (nodeIntegration:true, contextIsolation:false):**

1. Read the main entry file and every preload
2. Find every `innerHTML`, Markdown render, `dangerouslySetInnerHTML`, `document.write`
3. For each: trace backward to its data source — is the content user-controlled?
4. If yes, you have XSS → (dangerous setting) → impact. Verify the XSS fires, then verify the escalation.

**If you found a dangerous IPC handler:**

1. Read the handler completely
2. Answer: what operation does it perform? (exec, fs.write, openExternal, etc.)
3. What arguments does it accept from the renderer?
4. Is the sender validated? Are the arguments validated?
5. If not: from a compromised renderer (post-XSS), can you call this handler with malicious arguments?
6. If yes: you have an IPC escalation chain.

The pattern repeats. Source → taint propagation → sink. The specific APIs change; the structure doesn't.

---

## Phase 7: Build the PoC

A good PoC is the minimum payload that demonstrates the impact without causing harm. For Electron:

```javascript
// Tier 1 — confirms XSS fires (harmless):
<img src=x onerror="document.title='XSS-confirmed'">

// Tier 2 — confirms escalation path exists (opens URL, not shell):
<img src=x onerror="window.api.openURL('https://example.com')">

// Tier 3 — confirms RCE (calculator, universal PoC):
<img src=x onerror="require('child_process').exec('calc.exe')">
// or via IPC:
<img src=x onerror="window.api.runCommand('calc.exe')">
```

Document everything in the engagement folder:

```markdown
# Finding: XSS → RCE via nodeIntegration:true

## Source
chat.js:145 — `messageDiv.innerHTML = message.content`
message.content comes from WebSocket (ws://realtime.myapp.com/events)

## Sink
main.js:23 — `new BrowserWindow({ webPreferences: { nodeIntegration: true } })`
Any code execution in renderer has full Node.js access

## Chain
Server WebSocket message → message.content → innerHTML (line 145) →
onerror attribute executes → require('child_process').exec('calc.exe')

## ACID
- A: Anyone who can send a message to this user controls message.content
- C: No sanitization between WebSocket receive (line 143) and innerHTML (line 145)
- I: Full RCE as the logged-in user, cross-platform
- D: No CSP, no DOMPurify, nodeIntegration not disabled

## PoC
Send the following as a chat message:
<img src=x onerror="require('child_process').exec('calc.exe')">
Calculator opens when the recipient's client renders the message.
```

---

## Common Surprises

A few things that catch researchers off guard on first Electron engagement:

**The app is minified.** Expected. Prettify and continue — the logic is all there.

**There are multiple preload scripts.** Each window can have its own preload. Some windows might have dangerous configurations that the main window doesn't. Check every `new BrowserWindow`.

**The contextBridge surface is huge.** Large apps expose 50+ functions. Don't try to read them all — grep for the dangerous ones first (`exec`, `spawn`, `openExternal`, `writeFile`), then audit those specifically.

**Electronegativity flags false positives.** It's a grep-based tool at heart. It'll flag `nodeIntegration: true` even in comments. Verify everything manually.

**The update mechanism is HTTP.** More common than it should be. Report it — it's a valid finding even if it requires a network position to exploit.
