---
title: Network Sources
description: HTTP responses, WebSockets, native fetch, and server-sent data as attacker-controlled sources
---

# Network Sources

Network sources involve data received from external servers. While the data origin is typically a server the app trusts, these become attacker-controlled when:
1. The server is **compromised**
2. The **TLS certificate** is not validated (allows MitM)
3. The **update/API server** is served over HTTP
4. The app fetches from **attacker-controlled URLs** (SSRF)
5. The app uses **third-party CDNs** or embeds external content

---

## fetch / XMLHttpRequest

Standard HTTP responses are the most common network source:

```javascript
// Basic fetch (SOURCE: response body):
const response = await fetch('/api/user/profile');
const user = await response.json();  // SOURCE

// Unsafe patterns:
document.body.innerHTML = user.bio;         // SINK: stored XSS via server data
eval(user.customScript);                    // SINK: server-provided code execution
exec(user.shellCommand);                    // SINK: explicit RCE

// Rendered notification:
const notification = await fetch('/api/notifications/latest').then(r => r.json());
notificationDiv.innerHTML = notification.message;  // SINK: server → innerHTML
```

### Third-Party API Responses

```javascript
// Third-party CDN content:
const content = await fetch('https://cdn.thirdparty.com/widget.js').then(r => r.text());
eval(content);         // SINK: executing third-party JS (CDN compromise → RCE)
// Or: append as script tag — same effect as eval for remote JS

// Translation API:
const translated = await fetch(`https://translate-api.com/?text=${userQuery}`);
const result = await translated.json();
displayElement.innerHTML = result.translatedText;  // SINK: translation API → HTML
```

---

## net.request (Electron Main Process)

Electron's main process uses `net.request` for HTTP in the main process context — where there is no sandbox:

```javascript
const { net } = require('electron');

// Main process HTTP (SOURCE):
const request = net.request('https://api.myapp.com/config');
request.on('response', (response) => {
  response.on('data', (chunk) => {
    const config = JSON.parse(chunk.toString());  // SOURCE: network data in main process
    
    // In main process — these are actual dangerous sinks:
    exec(config.postInstallScript);    // SINK: RCE from network data
    fs.writeFileSync(config.outPath, config.content);  // SINK: arbitrary write
    protocol.registerFileProtocol(config.scheme, ...); // SINK: protocol registration
  });
});
```

---

## Electron Auto-Updater

The update mechanism downloads and executes code — the highest-impact network source:

```javascript
const { autoUpdater } = require('electron-updater');

// Update check (SOURCE: response from update server):
autoUpdater.on('update-downloaded', (info) => {
  // info.releaseName — SOURCE: from update server YAML
  // info.releaseNotes — SOURCE: from update server (often rendered as HTML)
  
  // Dangerous: rendering release notes without sanitization:
  releaseNotesDiv.innerHTML = info.releaseNotes;  // SINK: stored XSS
  
  // The downloaded installer: already a SINK by definition
  autoUpdater.quitAndInstall();  // Executes downloaded binary
});
```

### electron-updater YAML Parsing

The `latest.yml` file on the update server is parsed and its fields used:

```yaml
# latest.yml — all fields are SOURCE:
version: 1.2.3
files:
  - url: ../../../malicious.exe   # CVE-2024-46992: path traversal
    sha512: abc123
    size: 12345
path: ../../../malicious.exe
sha512: abc123
```

---

## WebSocket Messages

Server-pushed data over WebSocket connections:

```javascript
const ws = new WebSocket('wss://realtime.myapp.com/events');

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);  // SOURCE: server-pushed data
  
  // Common patterns:
  switch (message.type) {
    case 'notification':
      showNotification(message.body);         // SOURCE → innerHTML if not escaped
      break;
    case 'command':
      executeAdminCommand(message.command);   // SOURCE → exec if not validated
      break;
    case 'update-config':
      applyConfig(message.config);            // SOURCE → config injection
      break;
  }
};
```

---

## Server-Sent Events (SSE)

```javascript
const source = new EventSource('/api/stream');

source.addEventListener('notification', (event) => {
  const data = JSON.parse(event.data);  // SOURCE: SSE data
  notificationsList.insertAdjacentHTML('beforeend', `
    <li>${data.message}</li>           // SINK: HTML injection
  `);
});
```

---

## CORS and Cross-Origin Fetch

When Electron apps disable CORS (via `webSecurity: false`), they can fetch from any origin:

```javascript
// With webSecurity: false in BrowserWindow:
const data = await fetch('http://localhost:8080/admin/config');  // SSRF in renderer
const fileContent = await fetch('file:///etc/passwd');           // Local file read
```

### webRequest Interception as Source

Intercepting and modifying responses creates a source from network data:

```javascript
session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
  // details.url — SOURCE: the URL being requested
  // details.requestHeaders — SOURCE: request headers
  
  // If app modifies URLs or reads them for logic:
  if (details.url.includes('download')) {
    processDownload(details.url);  // SOURCE → could be attacker-influenced
  }
  callback({});
});
```

---

## Embedded iframes / WebViews

Loading external URLs in iframes creates a web-origin source:

```javascript
// <webview> tag (deprecated but still used):
const webview = document.querySelector('webview');
webview.src = externalUrl;  // Loads remote content

// IPC from webview to parent:
webview.addEventListener('ipc-message', (event) => {
  handleWebviewMessage(event.channel, event.args);  // SOURCE: from remote web content
});

// <iframe> with external content:
const iframe = document.createElement('iframe');
iframe.src = 'https://partner-site.com/widget';  // Loads remote content
// postMessage from this frame → SOURCE
```

---

## Detection Patterns

```bash
# Find all fetch() calls:
grep -rn "fetch(\|axios\.\|request(\|\.get(\|\.post(" \
  --include="*.js" . | grep -v "node_modules\|\.test\." | head -40

# Find response body processing:
grep -rn "\.json()\|\.text()\|response\.data\b" \
  --include="*.js" . | grep -v node_modules

# Find net.request (main process HTTP):
grep -rn "net\.request\|require('electron').*net\b" \
  --include="*.js" . | grep -v node_modules

# Find autoUpdater response handling:
grep -rn "autoUpdater\.\|update-downloaded\|update-available" \
  --include="*.js" . | grep -v node_modules

# Find WebSocket onmessage handlers:
grep -rn "\.onmessage\s*=\|ws\.on('message'" \
  --include="*.js" . | grep -v node_modules

# Find SSE:
grep -rn "EventSource\|addEventListener('message'" \
  --include="*.js" . | grep "EventSource\|SSE" | grep -v node_modules

# Find webview ipc-message:
grep -rn "ipc-message\|webview.*src" \
  --include="*.js" . | grep -v node_modules
```

---

## Risk Matrix

| Source | Risk | MitM Risk | Notes |
|--------|------|-----------|-------|
| autoUpdater response | Critical | High if HTTP | Executes code |
| `net.request` in main process | High | Yes | Main process → no sandbox |
| `eval(networkResponse)` | Critical | Yes | Direct code execution |
| `innerHTML = networkData` | High | Yes | XSS via server data |
| WebSocket `onmessage` | High | TLS-dep | Real-time injection |
| `fetch()` + JSON parse | Medium | TLS-dep | Depends on usage |
| SSE response data | Medium | TLS-dep | Same as fetch |
| Third-party CDN scripts | High | CDN-dep | CDN compromise → RCE |
