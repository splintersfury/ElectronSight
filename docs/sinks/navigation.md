---
title: Navigation & Open Sinks
description: shell.openExternal, window.open, loadURL, and URL injection attacks in Electron
---

# Navigation & Open Sinks

Navigation sinks open URLs, files, or protocol handlers in the OS or in Electron windows. When attacker-controlled URLs reach these sinks, the impact ranges from phishing to RCE via protocol handlers.

---

## shell.openExternal

`shell.openExternal(url)` passes a URL to the operating system to open with the appropriate handler. It is the most dangerous navigation sink in Electron.

```javascript
const { shell } = require('electron');
shell.openExternal(url);  // OS handles the URL
```

### Why It's Dangerous

The OS can handle many protocol schemes, each potentially dangerous:

| Protocol | Platform | Attack Vector |
|----------|----------|---------------|
| `file://` | All | Open local executables |
| `javascript:` | Some OS contexts | Code execution |
| `ms-msdt:` | Windows | Follina (CVE-2022-30190) |
| `search-ms:` | Windows | Protocol handler RCE |
| `ms-officecmd:` | Windows | Office protocol RCE |
| `tel:`, `mailto:` | All | Phishing, CSRF |
| `ssh://` | All | Launch SSH client with args |
| `ftp://` | All | Open FTP client |
| `smb://` | Windows | NTLM hash capture |
| Custom schemes | App-specific | App-defined protocol handlers |

### CVE-2020-15174: Discord

Discord's preload script exposed `DiscordNative.ipc.send`. An attacker with XSS could call:

```javascript
// Renderer XSS → IPC → shell.openExternal:
DiscordNative.nativeModules.requireModule('discord_utils')
  .getGPUDriverVersions()  // just one example of the exposed surface

// Actual attack used DANGEROUS_openExternal channel:
ipcRenderer.send('DANGEROUS_openExternal', 'file:///C:/Windows/System32/calc.exe');
```

This opened the local Windows executable. With crafted protocol handler arguments, this became RCE.

### Safe Usage

```javascript
// Validate URL before opening:
function safeOpenExternal(url) {
  const parsed = new URL(url);
  const allowedProtocols = ['https:', 'http:', 'mailto:'];
  
  if (!allowedProtocols.includes(parsed.protocol)) {
    console.error(`Blocked unsafe protocol: ${parsed.protocol}`);
    return;
  }
  
  shell.openExternal(url);
}
```

Electron 8.0+ returns a Promise from `shell.openExternal`, allowing better error handling.

---

## window.open

Opens a new browser window or Electron window:

```javascript
// Renderer:
window.open(url, '_blank');
// url = 'javascript:...' → code execution in new window context
// url = 'file://...' → open local file

// Electron handles window.open via new-window event:
// main.js:
win.webContents.setWindowOpenHandler(({ url }) => {
  // Validate before allowing:
  if (url.startsWith('https://')) {
    return { action: 'allow' };
  }
  return { action: 'deny' };
});
```

---

## location.href Assignment

```javascript
// Redirect the current window to attacker URL:
location.href = userInput;
location.assign(userInput);
location.replace(userInput);

// Danger: javascript: URLs execute code:
location.href = 'javascript:require("child_process").exec("calc")';
// (Chromium blocks this in most contexts but historically was an issue)

// file:// navigation loads local content:
location.href = 'file:///etc/passwd';
```

---

## webContents.loadURL

Main process loading a renderer from attacker-controlled URL:

```javascript
// main.js — VULNERABLE:
ipcMain.on('navigate', (event, url) => {
  win.loadURL(url);  // loads arbitrary URL in main window
});

// Risks:
// url = 'file:///path/to/local/file.html' → phishing or XSS via local file
// url = 'https://attacker.com' → loads external content in Electron context
// url = 'data:text/html,<script>...' → inline HTML execution
```

---

## Protocol Handler Registration as a Sink

Custom protocol handlers handle inbound protocol-scheme URLs. The handler function itself is a sink:

```javascript
protocol.registerFileProtocol('myapp', (request, callback) => {
  const url = request.url;
  const filePath = url.replace('myapp://', '');
  
  // SINK: callback with attacker-controlled path
  callback({ path: filePath });
  // Path traversal: myapp://../../../etc/passwd → reads /etc/passwd
});
```

---

## iframe src Injection

Loading attacker URLs in iframes within the app:

```javascript
// Setting iframe src to attacker URL:
iframe.src = userInput;
// In Electron with nodeIntegration in subframes:
// userInput frame gets Node.js access if nodeIntegrationInSubFrames: true

// document.createElement for dynamic iframe:
const frame = document.createElement('iframe');
frame.src = attacker_url;
document.body.appendChild(frame);
```

---

## Grep Patterns

```bash
# shell.openExternal — always audit:
grep -rn "shell\.openExternal\b\|openExternal\b" --include="*.js" . | grep -v node_modules

# window.open calls:
grep -rn "window\.open\b" --include="*.js" . | grep -v node_modules

# location navigation:
grep -rn "location\.\(href\|assign\|replace\)\s*=" --include="*.js" . | grep -v node_modules

# loadURL in main process:
grep -rn "\.loadURL\b\|\.loadFile\b" --include="*.js" . | grep -v node_modules

# Protocol handler callbacks:
grep -rn "registerFileProtocol\|registerStringProtocol\|registerBufferProtocol" \
  --include="*.js" . | grep -v node_modules

# iframe src assignment:
grep -rn "iframe\b.*src\|\.src\s*=" --include="*.js" . | grep -v node_modules
```
