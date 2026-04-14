---
title: ElectroVolt — Black Hat 2022
description: Aaditya Purani's systematic IPC vulnerability research — finding RCE in multiple Electron apps with a repeatable methodology
---

# ElectroVolt (Black Hat 2022)

Aaditya Purani's ElectroVolt research, presented at Black Hat USA 2022, changed how the security community thinks about Electron vulnerability research. The insight wasn't "here's a bug in this app" — it was "here's a pattern that exists across almost every Electron app, and here's a systematic way to find it."

The impact: RCE in Mattermost, Bitwarden, GitHub Desktop, Basecamp, and more — all from the same methodology, all from the same fundamental pattern.

---

## The Pattern

ElectroVolt identified that most Electron apps share the same vulnerability architecture:

```
Preload script
  → exposes a bridge function that calls ipcRenderer.invoke(channel, args)
  → args come from the renderer (attacker-controlled post-XSS)
  
Main process
  → ipcMain.handle(channel, handler)
  → handler calls exec/spawn/readFile/openExternal with args
  → no input validation, no sender origin check
  
Result
  → XSS → bridge function → IPC handler → privileged operation
```

The genius of the research: this pattern isn't app-specific. It's structural. Every app that has a preload bridge and an unvalidated IPC handler in the main process is vulnerable to the same class of attack. Systematically detect the pattern, systematically find bugs.

---

## The Three-Phase Methodology

### Phase 1: Index the Attack Surface

After extracting the ASAR, index everything security-relevant:

```bash
# IPC handlers and what they call:
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 15 | \
  grep -E "exec|spawn|openExternal|readFile|writeFile" | grep -v node_modules

# Preload bridge exposures:
grep -rn "exposeInMainWorld" --include="*.js" . -A 20 | \
  grep "ipcRenderer" | grep -v node_modules

# XSS sinks:
grep -rn "innerHTML\|dangerouslySetInnerHTML\|marked\b\|document\.write" \
  --include="*.js" . | grep -v node_modules
```

The output is a map: which bridge functions exist, which IPC channels they invoke, what those channels do.

### Phase 2: Cross-Reference for Chains

Look at the intersections:
- Which bridge functions call `ipcRenderer.invoke`?
- Which IPC handlers call dangerous operations on those channels?
- Is there validation between the bridge call and the dangerous operation?

This gives you a list of candidate chains: `window.api.X() → channel:Y → exec(args)`.

### Phase 3: Find the XSS Entry Point

For each candidate chain, find a way to trigger it from attacker-controlled content:
- Search for `innerHTML` with network/storage/IPC data as input
- Check Markdown renderers for missing DOMPurify
- Check URL parameters rendered without sanitization

Verify: XSS payload → `window.api.X(payload)` → privileged operation.

---

## Mattermost: The Primary Case Study

Mattermost Desktop's preload exposed:

```javascript
// Mattermost preload (pre-fix, simplified):
contextBridge.exposeInMainWorld('mattermost', {
  openExternal: (url) => ipcRenderer.invoke('mattermost:open-url', url)
});
```

Main process handler:

```javascript
ipcMain.handle('mattermost:open-url', async (event, url) => {
  await shell.openExternal(url);  // no URL validation
});
```

XSS in Mattermost's message renderer (Markdown without sufficient sanitization):

```html
<!-- Attacker's message: -->
<img src=x onerror="window.mattermost.openExternal('file:///C:/Windows/System32/calc.exe')">
```

Victim views the channel. The `onerror` fires. `openExternal` passes the `file://` URL to Windows. Calculator opens. The full chain from attacker-posted message to victim code execution.

---

## Other Apps in the Research

The same methodology applied to:

**Bitwarden Desktop** — preload exposed IPC channel for clipboard operations. XSS in vault item display → clipboard-based exfiltration chain.

**GitHub Desktop** — protocol handler registration (custom scheme for opening repos). Crafted repository URL triggered IPC with attacker-controlled arguments.

**Basecamp** — Markdown rendering with insufficient sanitization + exposed IPC for notification handling.

Multiple others that went through coordinated disclosure and haven't been publicly named.

---

## What Changed After ElectroVolt

Before ElectroVolt, Electron security advice was mostly "don't use `nodeIntegration: true`." The configuration problems. After ElectroVolt:

- **The IPC handler validation problem became central.** Correct configuration without validated handlers is insufficient. You need both.
- **Bug bounty programs updated their scope.** IPC injection is now explicitly in-scope for most Electron app programs.
- **Electronegativity added new checks.** Static analysis tools started flagging missing sender validation.
- **Apps started auditing their IPC surfaces.** The research prompted internal audits at multiple major Electron projects.

The research moved the conversation from "what settings should be on/off" to "how do you validate what comes through your IPC handlers" — which is the harder, more nuanced, and ultimately more important problem.

---

## Using the ElectroVolt Methodology

This is what we do with every Electron app now. The implementation is in this toolkit:

```bash
# Index the attack surface:
python3 scripts/extract_electron.py <path> --output-dir <engagement>/extracted/

# Build source-to-sink chains:
python3 scripts/build_chains.py <extracted-dir> --taxonomy taxonomy/electron/

# Read the chains — prioritize Critical/High:
cat engagements/<folder>/chains.json | python3 -m json.tool | \
  grep -A 5 '"severity": "Critical"'
```

The patterns haven't changed. Apps keep being written with the same bridge architecture, and main process handlers keep getting written without sender validation or input validation. ElectroVolt made the pattern famous; it hasn't made apps fix it.
