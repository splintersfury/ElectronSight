---
title: Session & Protocols
description: Electron session management, custom protocol registration, and security implications
---

# Session & Protocols

Electron's `session` module manages cookies, cache, proxy settings, and custom protocol handlers. It's not usually the first thing you audit, but custom protocol registration and permission handling both create attack surface worth understanding.

---

## Session Basics

Each BrowserWindow uses a session to manage network state. All windows share `defaultSession` by default:

```javascript
const { session } = require('electron');

const defaultSession = session.defaultSession;

// Partitioned sessions — isolated state:
const userSession = session.fromPartition('persist:user');  // saved to disk
const sandboxSession = session.fromPartition('temp:sandbox'); // ephemeral
```

Sessions control cookie storage, cache, proxy settings, network request interception, and permission grants for the renderer. They're also where custom URL schemes are registered.

---

## Custom Protocol Handlers

Apps register custom URL schemes to serve local content — `app://`, `resource://`, etc.:

```javascript
// main.js — register 'app://' scheme:
protocol.registerFileProtocol('app', (request, callback) => {
  const url = request.url.substr(6);  // strip 'app://'
  const filePath = path.normalize(path.join(__dirname, url));
  callback({ path: filePath });
});
```

This is the same attack surface as OS-level protocol handlers, but app-internal. The security issues are predictable:

### Path Traversal in Protocol Handler

```javascript
// VULNERABLE — no path validation:
protocol.registerFileProtocol('app', (request, callback) => {
  const url = new URL(request.url);
  const filePath = path.join('/app/static/', url.pathname);
  // url.pathname = '/../../../etc/passwd' → traversal to arbitrary file
  callback({ path: filePath });
});

// FIX:
protocol.registerFileProtocol('app', (request, callback) => {
  const url = new URL(request.url);
  const staticDir = path.resolve('/app/static');
  const filePath = path.resolve(staticDir, url.pathname.slice(1));
  
  if (!filePath.startsWith(staticDir + path.sep)) {
    callback({ statusCode: 403 });  // path traversal blocked
    return;
  }
  callback({ path: filePath });
});
```

### Protocol Handler as Open Redirect

```javascript
// VULNERABLE — protocol handler passes URL to openExternal:
protocol.registerStringProtocol('x-open', (request, callback) => {
  const target = request.url.replace('x-open://', '');
  shell.openExternal(target);  // target is attacker-controlled
  callback({ data: 'ok' });
});
// Attacker triggers: x-open://ms-msdt://... or x-open://file:///malware.exe
```

---

## WebRequest Interception

Sessions can intercept all network requests before they go out and responses before they reach the renderer:

```javascript
session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
  // details.url — the request URL
  // details.method — HTTP method
  // details.requestHeaders — headers being sent
  
  // Can block, allow, or redirect:
  if (details.url.includes('attacker.com')) {
    callback({ cancel: true });
  } else {
    callback({ cancel: false });
  }
});
```

From a research perspective: if you can execute code in the main process, `webRequest` hooks are useful for intercepting API calls made by the app, seeing authentication tokens, capturing internal protocol traffic.

---

## Permission Request Handling

Renderers can request permissions (camera, microphone, geolocation, notifications). Apps that handle this incorrectly grant access to compromised renderers:

```javascript
// VULNERABLE — grants all permissions to anyone:
session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
  callback(true);  // always allow — bad
});

// SECURE — validates origin before granting:
session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
  const url = webContents.getURL();
  
  // Only grant to trusted origins:
  if (url.startsWith('file://') && url.includes('/app/')) {
    callback(true);
  } else {
    callback(false);
  }
});
```

An XSS that navigates the renderer to attacker-controlled content, combined with a permissive handler, can gain camera/microphone access.

---

## Auditing During Assessment

```bash
# Find all custom protocol registrations:
grep -rn "registerFileProtocol\|registerStringProtocol\|registerHttpProtocol\|registerBufferProtocol\|protocol\.handle" \
  --include="*.js" . | grep -v node_modules

# Find permission handlers (or lack thereof — missing is risky):
grep -rn "setPermissionRequestHandler\|setPermissionCheckHandler" \
  --include="*.js" . | grep -v node_modules

# Find webRequest hooks (may reveal security controls or lack thereof):
grep -rn "webRequest\.\(onBeforeRequest\|onHeadersReceived\)" \
  --include="*.js" . | grep -v node_modules

# Find session partitioning (isolation between windows):
grep -rn "fromPartition\|defaultSession" --include="*.js" . | grep -v node_modules
```

For each custom protocol handler:
1. Does it serve files? → Check for path traversal
2. Does it call `shell.openExternal` or `exec`? → Check for injection
3. Does it get `file://` equivalent trust? → Check `GrantFileProtocolExtraPrivileges` fuse state
4. Can attacker-controlled URLs trigger it? → Check if scheme is registered in OS as well
