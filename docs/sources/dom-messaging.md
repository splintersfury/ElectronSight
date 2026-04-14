---
title: DOM & Messaging Sources
description: postMessage, BroadcastChannel, WebSockets, and cross-frame communication as attack sources
---

# DOM & Messaging Sources

Messaging sources involve data transmitted between JavaScript contexts — frames, workers, windows, and the network. In Electron, these are particularly dangerous because multiple trust boundaries exist (renderer/main, frame/parent, web/local), and messages cross them without automatic trust labeling.

---

## postMessage

`window.postMessage` enables cross-origin communication in browsers and is heavily used in Electron apps that embed third-party content or use web workers.

```javascript
// Receiver — this is the SOURCE:
window.addEventListener('message', (event) => {
  // event.data — SOURCE: sent by any window that has a reference to this window
  // event.origin — should be validated but often isn't
  // event.source — the sender window
  
  handleMessage(event.data);  // SOURCE: process without origin check
});
```

### Origin Validation Failures

```javascript
// ❌ No origin check — accepts messages from any frame:
window.addEventListener('message', (event) => {
  if (event.data.type === 'exec') {
    executeCommand(event.data.cmd);  // SOURCE → SINK: no validation
  }
});

// ❌ Weak origin check — string.includes() is bypassable:
window.addEventListener('message', (event) => {
  if (event.origin.includes('myapp.com')) {  // attacker.com?src=myapp.com bypasses
    processData(event.data);
  }
});

// ✅ Strict origin check:
const TRUSTED_ORIGIN = 'https://app.myapp.com';
window.addEventListener('message', (event) => {
  if (event.origin !== TRUSTED_ORIGIN) return;
  processData(event.data);
});
```

### Electron-Specific: ipcRenderer.postMessage

```javascript
// In preload — bridges postMessage to IPC:
window.addEventListener('message', (event) => {
  // If preload forwards messages to main without validation:
  ipcRenderer.send('message', event.data);  // SOURCE → IPC SINK
});

// This creates a path: attacker frame → postMessage → preload → IPC handler
// even when nodeIntegration is disabled
```

---

## BroadcastChannel

BroadcastChannel enables one-to-many messaging across same-origin contexts (tabs, iframes, workers):

```javascript
// Publisher (potentially attacker-controlled frame):
const bc = new BroadcastChannel('app-updates');
bc.postMessage({ action: 'navigate', url: 'javascript:alert(1)' });  // SOURCE

// Subscriber (victim):
const channel = new BroadcastChannel('app-updates');
channel.onmessage = (event) => {
  // event.data — SOURCE: any same-origin page can post here
  handleUpdate(event.data);  // SOURCE: if app has XSS anywhere, BroadcastChannel
                             // becomes a pivot to affect other contexts
};
```

**Why it matters in Electron:** If an Electron app loads any web content that has XSS, and the app uses `BroadcastChannel` for internal communication, the XSS payload can post to any channel.

---

## WebSockets

WebSocket connections receive data from external servers — a network-based source:

```javascript
const ws = new WebSocket('wss://api.myapp.com/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);  // SOURCE: network data
  
  // Common dangerous patterns:
  updateUI(data.html);                  // SOURCE → innerHTML SINK
  eval(data.script);                    // SOURCE → eval SINK
  exec(data.command);                   // SOURCE → exec SINK
  require(data.module);                 // SOURCE → require SINK
};
```

### WebSocket Auth Bypass

In Electron apps, WebSocket connections often lack proper authentication:

```javascript
// Server-side WebSocket handler:
wss.on('connection', (ws, req) => {
  // If app only checks that WS connects from localhost:
  if (req.socket.remoteAddress === '127.0.0.1') {
    // Trusted — but any local process or XSS in renderer can connect
    ws.on('message', (msg) => {
      exec(msg);  // SOURCE → SINK: "trusted" local WS abused by renderer XSS
    });
  }
});
```

---

## SharedArrayBuffer / Atomics (Side-Channel)

In Electron 15+ (when `crossOriginIsolated` is enabled), SharedArrayBuffer is available as a high-resolution timer for side-channel attacks:

```javascript
// Renderer: high-resolution timing via SharedArrayBuffer:
const sharedBuffer = new SharedArrayBuffer(4);
const sharedArray = new Int32Array(sharedBuffer);

// Measure cache timing:
const start = Atomics.load(sharedArray, 0);
// ... access target memory ...
const end = Atomics.load(sharedArray, 0);
const elapsed = end - start;  // SOURCE: timing side-channel data
```

---

## iframe / Frame Messaging

Electron apps frequently embed frames — local HTML fragments, OAuth flows, or documentation:

```javascript
// Parent listening to child frame:
const iframe = document.getElementById('content-frame');
iframe.contentWindow.postMessage({ action: 'getToken' }, '*');  // sends to frame

// Frame receives and responds:
window.addEventListener('message', (event) => {
  if (event.data.action === 'getToken') {
    // If parent doesn't validate origin, attacker iframe responds:
    event.source.postMessage({ token: stolenToken }, event.origin);
  }
});

// Parent receives response:
window.addEventListener('message', (event) => {
  // event.data.token — SOURCE: could come from attacker frame
  authenticate(event.data.token);  // SOURCE → authentication bypass
});
```

### nodeIntegrationInSubFrames Risk

When `nodeIntegrationInSubFrames: true`:

```javascript
// In a child frame (even cross-origin content!):
const { ipcRenderer } = require('electron');  // Available in subframe!

// Child frame can directly call privileged IPC:
ipcRenderer.invoke('execute-command', 'calc.exe');  // SOURCE bypasses parent
```

---

## Web Workers

Workers receive messages from the main thread — which can be attacker-influenced:

```javascript
// Main thread → worker (potential source):
const worker = new Worker('./worker.js');
worker.postMessage({ script: userInput });  // SOURCE: passes user data to worker

// worker.js:
self.onmessage = (event) => {
  // event.data — SOURCE: from main thread
  eval(event.data.script);  // SINK: execute arbitrary code in worker context
  
  // If worker has nodeIntegration (nodeIntegrationInWorker:true):
  const cp = require('child_process');
  cp.exec(event.data.cmd);  // Full RCE from worker
};
```

---

## Detection Patterns

```bash
# Find postMessage listeners:
grep -rn "addEventListener('message'\|addEventListener(\"message\"" \
  --include="*.js" . | grep -v node_modules

# Find WebSocket message handlers:
grep -rn "\.onmessage\s*=\|addEventListener('message'" --include="*.js" . | \
  grep -v "window\.\|document\." | grep -v node_modules

# Find BroadcastChannel usage:
grep -rn "BroadcastChannel\|broadcastChannel" --include="*.js" . | grep -v node_modules

# Find missing origin validation in message handlers:
grep -rn "addEventListener('message'" --include="*.js" . -A 5 | \
  grep -v "origin\|source\|node_modules" | head -20

# Find ipcRenderer.postMessage (renderer→main bridge):
grep -rn "ipcRenderer\.postMessage\|ipcRenderer\.send\b" \
  --include="*.js" . | grep -v node_modules
```

---

## Risk Matrix

| Source | Risk | Cross-Origin? | Notes |
|--------|------|--------------|-------|
| `postMessage` no origin check | Critical | Yes | Any frame can send |
| `ws.onmessage` (network) | High | External | Server compromise → RCE |
| Worker `onmessage` with nodeIntegration | High | No | Worker has Node.js access |
| `BroadcastChannel` | Medium | Same-origin | XSS pivot across tabs |
| `postMessage` with origin check | Low | Yes | Depends on check quality |
| `SharedArrayBuffer` timing | Low | Sandbox-dep | Side-channel, not direct |
