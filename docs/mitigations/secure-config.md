---
title: Secure Configuration
description: Complete reference for secure Electron BrowserWindow and app configuration
---

# Secure Configuration

This page collects the secure configuration templates for the most common Electron security patterns. Use these as a starting point — they represent the baseline you need before any feature-specific security decisions.

The templates are intentionally opinionated: they set every security-relevant option explicitly, even when the value matches the current default. Defaults change between Electron versions. An explicit value doesn't.

---

## The Secure BrowserWindow Template

```javascript
const path = require('path');
const { app, BrowserWindow, shell } = require('electron');

function createSecureWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    
    webPreferences: {
      // === CRITICAL: Context Separation ===
      contextIsolation: true,           // JS worlds separated (default since v12)
      nodeIntegration: false,           // No Node.js in renderer (default since v5)
      nodeIntegrationInWorker: false,   // Workers don't get Node.js
      nodeIntegrationInSubFrames: false, // Subframes don't get Node.js
      
      // === CRITICAL: Sandbox ===
      sandbox: true,                    // OS sandbox active (default since v20)
      
      // === CRITICAL: Security Policies ===
      webSecurity: true,                // Same-Origin Policy enforced
      allowRunningInsecureContent: false, // No HTTP in HTTPS context
      
      // === DEPRECATED: Never Use ===
      enableRemoteModule: false,        // remote module is dead, don't use it
      
      // === PRELOAD: The Bridge ===
      preload: path.join(__dirname, 'preload.js'),
    },
    
    show: false,  // Show after ready-to-show (prevents flash)
  });
  
  win.once('ready-to-show', () => win.show());
  
  // === NAVIGATION POLICY: Required ===
  // Without this: XSS can navigate to attacker-controlled pages
  win.webContents.on('will-navigate', (event, url) => {
    const appURL = 'file://' + path.join(__dirname, 'index.html');
    if (url !== appURL && !url.startsWith('app://')) {
      event.preventDefault();
    }
  });
  
  // === WINDOW OPEN POLICY: Required ===
  // Without this: window.open() creates new Electron window inheriting same webPreferences
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://') || url.startsWith('mailto:')) {
      shell.openExternal(url);  // Open in system browser
    }
    return { action: 'deny' };  // Never create new Electron window from renderer
  });
  
  return win;
}
```

---

## The Secure Preload Template

The preload is the bridge. Keep it narrow — expose only what the page actually needs, type-check everything, and don't expose anything that accepts arbitrary IPC channels.

```javascript
// preload.js — minimal, typed, validated API
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // File dialogs — main process shows picker, no path injection possible:
  openFileDialog: () => ipcRenderer.invoke('dialog:open-file'),
  saveFileDialog: () => ipcRenderer.invoke('dialog:save-file'),
  
  // App info (no user input):
  getAppVersion: () => ipcRenderer.invoke('app:get-version'),
  getPlatform: () => process.platform,
  
  // Typed data submission with explicit field extraction:
  submitForm: (data) => {
    if (!data || typeof data !== 'object') throw new Error('Invalid data');
    if (Object.keys(data).length > 20) throw new Error('Too many fields');
    if (data.name && typeof data.name !== 'string') throw new Error('Invalid name');
    if (data.name && data.name.length > 200) throw new Error('Name too long');
    
    return ipcRenderer.invoke('form:submit', {
      name: data.name,    // Explicitly copy expected fields only
      email: data.email   // Spread operator risks prototype pollution
    });
  },
  
  // Event callbacks — validate callback type:
  onUpdateAvailable: (callback) => {
    if (typeof callback !== 'function') return;
    ipcRenderer.on('update:available', (_event, info) => callback(info));
  },
  
  // Cleanup:
  removeUpdateListener: () => {
    ipcRenderer.removeAllListeners('update:available');
  }
});
```

---

## The Secure IPC Handler Template

IPC handlers are where attacker-controlled input meets privileged operations. Validate the sender first. Type-check every argument. Validate paths before using them.

```javascript
// main.js — strict IPC handlers
const { ipcMain, app, shell } = require('electron');
const path = require('path');
const fs = require('fs');

// Validate sender origin — call at the top of every sensitive handler
function validateSender(event) {
  const senderURL = event.senderFrame?.url || event.sender?.getURL() || '';
  const appPath = 'file://' + path.join(app.getAppPath(), 'index.html');
  
  if (senderURL !== appPath && !senderURL.startsWith('app://')) {
    throw new Error(`Unauthorized sender: ${senderURL}`);
  }
}

// Validate and resolve a path against an allowed base directory
function safeResolvePath(userPath, allowedBase) {
  const resolved = path.resolve(allowedBase, userPath);
  // path.sep prevents '../safeDir' matching against '../safeDirEvil':
  if (!resolved.startsWith(path.resolve(allowedBase) + path.sep) &&
      resolved !== path.resolve(allowedBase)) {
    throw new Error('Path traversal detected');
  }
  return resolved;
}

// File read — validates path, validates sender:
ipcMain.handle('file:read', async (event, filePath) => {
  validateSender(event);
  
  if (typeof filePath !== 'string') throw new TypeError('Invalid path type');
  
  const SAFE_BASE = path.join(app.getPath('userData'), 'notes');
  const safePath = safeResolvePath(filePath, SAFE_BASE);
  
  return fs.promises.readFile(safePath, 'utf8');
});

// Shell open — validates URL scheme, never passes arbitrary protocols to OS:
ipcMain.handle('shell:open-external', async (event, url) => {
  validateSender(event);
  
  const ALLOWED_SCHEMES = ['https:', 'http:', 'mailto:'];
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid URL');
  }
  
  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    throw new Error(`Blocked scheme: ${parsed.protocol}`);
  }
  
  return shell.openExternal(url);
});
```

---

## Content Security Policy

Add CSP to prevent XSS payload execution. Even if XSS exists, a strict CSP blocks inline script execution — an important layer when other defenses might fail.

```html
<!-- In your index.html: -->
<meta http-equiv="Content-Security-Policy" content="
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' https://api.myapp.com;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
">
```

Or enforce via `webRequest` in main process:

```javascript
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      'Content-Security-Policy': ["default-src 'self'; script-src 'self'; object-src 'none'"]
    }
  });
});
```

**Critical:** never include `unsafe-inline` in `script-src`. That directive is what prevents inline XSS payloads from running; `unsafe-inline` negates it entirely.
