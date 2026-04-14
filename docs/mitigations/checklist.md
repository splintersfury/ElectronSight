---
title: Security Checklist
description: Complete Electron security hardening checklist — every control, verified and actionable
---

# Electron Security Checklist

Use this for both app development and security assessment. Each item has a verification command so you can check it rather than just guess.

---

## Process Configuration

- [ ] `nodeIntegration: false` for all BrowserWindows
- [ ] `contextIsolation: true` for all BrowserWindows
- [ ] `sandbox: true` for all BrowserWindows (especially those loading external content)
- [ ] `webSecurity: true` — never set to `false`
- [ ] `allowRunningInsecureContent: false`
- [ ] `nodeIntegrationInWorker: false` (unless explicitly required and understood)
- [ ] `nodeIntegrationInSubFrames: false` (unless explicitly required)
- [ ] `enableRemoteModule: false` (deprecated, should be off)

```bash
# Verify all at once:
grep -rn "nodeIntegration\|contextIsolation\|sandbox\|webSecurity\|allowRunningInsecure\|enableRemoteModule" \
  --include="*.js" . | grep -v node_modules
# Expected: only "false" after the dangerous ones, only "true" after the safe ones
```

---

## Preload Script

- [ ] Does not expose `require`, `process`, or Node.js modules directly
- [ ] Does not expose `ipcRenderer.send/invoke` directly (no relay bridge)
- [ ] contextBridge API is narrow — specific operations, not generic IPC access
- [ ] All exposed functions validate argument types before invoking IPC
- [ ] No arbitrary IPC channel names accepted from the page
- [ ] `process.env` is not exposed in any form
- [ ] File paths from the page are validated before use

```bash
# Red flags in preloads:
grep -rn "exposeInMainWorld" --include="*.js" . -A 20 | \
  grep -E "ipcRenderer|require\b|process\.env|child_process" | grep -v node_modules
# Expected: empty output
```

---

## IPC Handlers

- [ ] Every `ipcMain.handle/on` validates `event.senderFrame.url` for sensitive operations
- [ ] All arguments are type-checked before use
- [ ] File path arguments use `path.resolve()` + `startsWith(safeBase + path.sep)` validation
- [ ] No `exec/spawn` with template literals containing user input (use array args)
- [ ] `shell.openExternal` calls check scheme against an allowlist before calling

```bash
# Find handlers that call dangerous operations without sender validation:
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 10 | \
  grep -v "senderFrame\|getURL\|node_modules" | \
  grep -E "exec\b|spawn\b|openExternal|writeFile|readFile"
# Expected: empty (or each result should have validation visible in context)

# Find shell.openExternal without URL validation:
grep -rn "openExternal" --include="*.js" . -B 10 | \
  grep -E "protocol\b|allowedSchemes\|new URL" | grep -v node_modules
# Expected: scheme check visible before each openExternal call
```

---

## Navigation and Window Policies

- [ ] `setWindowOpenHandler` implemented — denies new windows by default
- [ ] `webContents.on('will-navigate')` validates destination URL
- [ ] External URLs go through validated `shell.openExternal` (not loaded in Electron windows)

```javascript
// The correct policy:
win.webContents.setWindowOpenHandler(({ url }) => {
  // Open externally in browser (with scheme validation):
  if (safeOpenExternal(url)) return { action: 'deny' };
  return { action: 'deny' };  // deny everything else
});

win.webContents.on('will-navigate', (event, url) => {
  // Only allow navigation to known origins:
  if (!url.startsWith('file://') && !url.startsWith('https://yourapp.com')) {
    event.preventDefault();
  }
});
```

---

## Content Security Policy

- [ ] CSP is configured via `Content-Security-Policy` header or meta tag
- [ ] `script-src 'self'` — no `'unsafe-inline'`, no `'unsafe-eval'`
- [ ] `object-src 'none'`
- [ ] `base-uri 'self'` (prevents base tag injection)
- [ ] `default-src 'none'` or equivalent restrictive default

```bash
# Find CSP configuration:
grep -rn "Content-Security-Policy\|content-security-policy" \
  --include="*.js" --include="*.html" . | grep -v node_modules

# Check for dangerous directives:
grep -rn "unsafe-inline\|unsafe-eval" \
  --include="*.html" --include="*.js" . | grep -v node_modules
# Expected: empty
```

---

## HTML Rendering

- [ ] No `innerHTML = userInput` without DOMPurify
- [ ] DOMPurify version is current (check for mXSS bypasses in old versions)
- [ ] Markdown rendering runs DOMPurify on the HTML output
- [ ] `dangerouslySetInnerHTML` in React never receives user content directly

```bash
# Find potentially unsafe innerHTML:
grep -rn "innerHTML\s*=" --include="*.js" . | grep -v node_modules | \
  grep -v "DOMPurify\|sanitize\|'<\|\"<\|= '<\|= \"<"
# Results: each should be reviewed — some may be setting static HTML

# Check DOMPurify version:
cat node_modules/dompurify/package.json 2>/dev/null | grep '"version"'
```

---

## Electron Fuses

```bash
# Run this. The output tells you what's wrong:
npx @electron/fuses read --app /path/to/app
```

- [ ] `RunAsNode` — Disabled
- [ ] `EnableNodeOptionsEnvironmentVariable` — Disabled
- [ ] `EnableNodeCliInspectArguments` — Disabled
- [ ] `EnableCookieEncryption` — Enabled
- [ ] `EnableEmbeddedAsarIntegrityValidation` — Enabled
- [ ] `OnlyLoadAppFromAsar` — Enabled
- [ ] `GrantFileProtocolExtraPrivileges` — Disabled

Most apps fail most of these. They're all fixable at build time with one `flipFuses` call.

---

## Auto-Update

- [ ] Update server URL uses HTTPS
- [ ] Windows: `publisherName` configured in electron-builder (Authenticode verification)
- [ ] macOS: Hardened Runtime enabled, no dangerous entitlements
- [ ] `electron-updater` is current (CVE-2024-46992 is path traversal in old versions)
- [ ] Release notes rendered as text (not innerHTML)

```bash
cat electron-builder.yml | grep -E "publisherName|hardenedRuntime|provider:|url:"
cat node_modules/electron-updater/package.json | grep '"version"'
```

---

## ASAR and File Integrity

- [ ] ASAR enabled in packaging
- [ ] ASAR integrity fuse enabled
- [ ] `OnlyLoadAppFromAsar` fuse enabled
- [ ] Files in `app.asar.unpacked/` are only what's necessary (native modules)
- [ ] V8 snapshots (if used) have independent integrity validation at startup
- [ ] File permissions on `app.asar` are not world-writable

```bash
ls -la /path/to/app/resources/app.asar
# Not writable by the current user if app runs elevated
```

---

## Scoring

Count your checkmarks. Rough guideline for triage:

| Score | Status |
|-------|--------|
| 35/35 | Excellent — move to review logic-level bugs |
| 28-34 | Good — address the gaps, likely still reportable |
| 20-27 | Moderate risk — several high-value findings probably exist |
| < 20 | High risk — configuration issues alone are likely Critical/High |

Most real-world apps score in the 15-25 range. The fuse items alone account for 7 checks, and most apps fail all of them.
