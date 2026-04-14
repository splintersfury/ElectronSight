---
title: Protocol Handler Attack Surface
description: Custom URL schemes, OS protocol registration, and deep links as attack entry points
---

# Protocol Handler Attack Surface

Protocol handlers are externally invocable. That's the key property that makes them different from every other Electron attack surface. Any website, any email client, any other app on the system can trigger your custom URL scheme just by navigating to it. No XSS needed. No preload bypass needed. The OS handles the dispatch, and your app receives a URL that the attacker wrote.

Most developers who implement deep linking think about it as an internal feature — "we need to support `myapp://open?file=...` so users can click links from our website." They don't think about what happens when an attacker on a different website navigates to `myapp://execute?cmd=calc.exe`. That's the threat model gap.

---

## Types of Protocol Handlers in Electron

### 1. Custom Scheme via `protocol.handle()`

```javascript
// main.js — register app:// scheme:
const { protocol, net } = require('electron');

app.whenReady().then(() => {
  protocol.handle('app', (request) => {
    // request.url — SOURCE: full URL, path, query — all attacker-controlled
    const url = new URL(request.url);
    const filePath = url.pathname;   // SOURCE
    const params = url.searchParams; // SOURCE
    
    // Common pattern: serve local files:
    return net.fetch('file://' + path.join(app.getAppPath(), filePath));
    // SINK: if filePath = '../../.ssh/id_rsa' → arbitrary file read
  });
});
```

### 2. OS Deep Link via `setAsDefaultProtocolClient`

```javascript
// Register as OS-level handler for myapp:// URLs:
app.setAsDefaultProtocolClient('myapp');

// Handle incoming URLs:
app.on('open-url', (event, url) => {
  event.preventDefault();
  // url — SOURCE: fully attacker-controlled, from browser click or OS
  handleDeepLink(url);
});

// macOS: open-url event
// Windows: second-instance event with process.argv:
app.on('second-instance', (event, commandLine, workingDirectory) => {
  const url = commandLine.pop();  // SOURCE: deep link URL from argv
  handleDeepLink(url);
});
```

### 3. `file://` Protocol (Default)

Apps loading from `file://` inherit its security properties — including, with the `GrantFileProtocolExtraPrivileges` fuse enabled, elevated trust that lets file:// pages access Node.js capabilities.

---

## Cross-Origin Protocol Invocation — No XSS Needed

This is the attack property that makes protocol handlers unique:

```html
<!-- Attacker's website — any registered protocol is callable: -->
<a href="myapp://execute?cmd=calc.exe">Click here</a>
<iframe src="myapp://admin/delete-all"></iframe>

<!-- Or silently via JavaScript: -->
<script>location.href = 'myapp://evil-path?payload=...'</script>
```

The attack chain:
1. User visits attacker's website in their browser
2. Website redirects to `myapp://...`
3. OS dispatches to the Electron app (no user prompt in most cases)
4. App processes the attacker-controlled URL

**No XSS required.** No preload bypass required. No IPC injection required. The protocol handler is the entry point, and it's externally reachable by design.

This is exactly how CVE-2018-1000006 worked — a webpage triggered a `myapp://` URL that injected `--inspect=9229` into the Electron process's argument list, opening a debug port that gave the attacker a full Node.js REPL.

---

## Protocol Handler Vulnerability Patterns

### Path Traversal via Custom Scheme

```javascript
// Vulnerable handler:
protocol.handle('app', (request) => {
  const url = new URL(request.url);
  const filePath = url.pathname;  // SOURCE: "/../../../etc/passwd"
  
  return net.fetch('file://' + path.join(appDir, filePath));
  // path.join('app/dir', '/../../../etc/passwd') → '/etc/passwd'
});

// Attack URL: app://host/../../../etc/passwd
```

Fix: `path.resolve` + `startsWith` check:

```javascript
protocol.handle('app', (request) => {
  const url = new URL(request.url);
  const staticDir = path.resolve(app.getAppPath(), 'static');
  const filePath = path.resolve(staticDir, url.pathname.slice(1));
  
  if (!filePath.startsWith(staticDir + path.sep)) {
    return new Response('Forbidden', { status: 403 });
  }
  return net.fetch('file://' + filePath);
});
```

### Argument Injection (Windows — CVE-2018-1000006)

Before Electron 1.8.2, protocol handler registration on Windows was vulnerable. The Windows registry entry for a custom protocol looked like:

```
HKEY_CLASSES_ROOT\myapp\shell\open\command
"C:\path\to\myapp.exe" "%1"
```

An attacker could craft a URL like `myapp:// --inspect=9229 --no-sandbox` and Windows shell expansion would pass those as actual arguments to Electron. The `--inspect=9229` flag opens a remote debug port. The fix was adding `--` before `%1`:

```
"C:\path\to\myapp.exe" -- "%1"
```

In code:

```javascript
// Correct registration with -- separator:
app.setAsDefaultProtocolClient('myapp', process.execPath, ['--']);
```

### Query Parameter Injection

Developers think of query parameters as coming from their own backend. They don't think about an attacker directly constructing the URL with arbitrary params.

```javascript
// Vulnerable: query params used without sanitization:
app.on('open-url', (event, rawUrl) => {
  const url = new URL(rawUrl);
  const token = url.searchParams.get('token');  // SOURCE: attacker-controlled
  const redirect = url.searchParams.get('redirect');  // SOURCE: attacker-controlled
  
  autoLogin(token);                // auth bypass if token trusted
  win.loadURL(redirect);           // arbitrary URL load if redirect trusted
});
```

### Fragment/Hash Attacks

```javascript
// Hash portion used for routing in renderer:
app.on('open-url', (event, url) => {
  const hash = new URL(url).hash;  // SOURCE: #<attacker-content>
  win.webContents.send('route', decodeURIComponent(hash.slice(1)));
});

// In renderer:
ipcRenderer.on('route', (event, path) => {
  document.querySelector('main').innerHTML = renderRoute(path);  // SINK: XSS
});
```

Read the full `handleDeepLink()` function body before classifying any parameter as safe. These functions are inconsistent: some parameters validated, others not — often in the same function.

---

## Auditing Protocol Handlers

```bash
# Find all protocol.handle registrations:
grep -rn "protocol\.handle\|protocol\.registerFile\|protocol\.registerString\|protocol\.registerBuffer" \
  --include="*.js" . | grep -v node_modules

# Find setAsDefaultProtocolClient (OS-level registration):
grep -rn "setAsDefaultProtocolClient" --include="*.js" . | grep -v node_modules

# Find open-url handler (entry point for deep links):
grep -rn "'open-url'\|\"open-url\"" --include="*.js" . | grep -v node_modules

# Find second-instance handler (Windows deep link path):
grep -rn "second-instance" --include="*.js" . | grep -v node_modules

# Check for missing -- separator in Windows protocol registration:
grep -rn "setAsDefaultProtocolClient" --include="*.js" . -A 2 | \
  grep -v "node_modules\|'--'\|\"--\"" | head -10
```

---

## Protocol Handler Security Checklist

- [ ] Is the URL parsed with `new URL()` (not string operations)?
- [ ] Is the path component validated against a base directory (resolve + startsWith)?
- [ ] Are query parameters type-checked before use?
- [ ] Is the fragment/hash decoded and sanitized if used for routing?
- [ ] Is `--` separator used in `setAsDefaultProtocolClient`?
- [ ] Are authentication/authorization checks performed?
- [ ] Does it handle malformed URLs gracefully without crashing?

---

## Risk Matrix

| Handler Type | Invocable From | Risk | Notes |
|-------------|---------------|------|-------|
| `setAsDefaultProtocolClient` + `open-url` | Any app/website | Critical | OS-wide registration |
| `protocol.handle('app', ...)` | Within app | High | Internal, but path traversal risk |
| `file://` with GrantFileProtocol fuse | Within app | High | Extra privilege from fuse |
| Windows `second-instance` deep link | Any app/website | Critical | Must validate |
| `protocol.interceptFileProtocol` | Within app | High | Can intercept all file:// requests |
