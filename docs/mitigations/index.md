---
title: Mitigations
description: Comprehensive Electron security hardening — secure configuration, fuse hardening, CSP, IPC security, and checklist
---

# Mitigations

Effective Electron security requires defense in depth. This section covers every significant mitigation, how to implement it, and how to verify it's working.

---

## The Hardened Electron Configuration

Every `BrowserWindow` should be configured with:

```javascript
const win = new BrowserWindow({
  webPreferences: {
    // === CRITICAL ===
    contextIsolation: true,        // Default since Electron 12 — never set to false
    nodeIntegration: false,        // Default since Electron 5 — never set to true
    sandbox: true,                 // Default since Electron 20 — enforce in older versions
    webSecurity: true,             // Default — never set to false
    
    // === IMPORTANT ===
    allowRunningInsecureContent: false,    // Prevent HTTP in HTTPS context
    nodeIntegrationInWorker: false,        // Workers don't need Node.js
    nodeIntegrationInSubFrames: false,     // Subframes/iframes don't need Node.js
    enableRemoteModule: false,             // Remote module is deprecated and dangerous
    
    // === NARROW PRELOAD ===
    preload: path.join(__dirname, 'preload.js'),  // Required, but keep the API minimal
  },
  
  // === WINDOW POLICY ===
  webPreferences: {
    // Handle window.open — don't allow unrestricted new windows:
  }
});

// Set window open handler:
win.webContents.setWindowOpenHandler(({ url }) => {
  // Only allow HTTPS to trusted domains:
  if (url.startsWith('https://myapp.com')) {
    return { action: 'allow' };
  }
  // Everything else: open in system browser or deny:
  shell.openExternal(url);
  return { action: 'deny' };
});
```

---

## Sections in This Chapter

| Page | What It Covers |
|------|----------------|
| [Secure Configuration](secure-config.md) | BrowserWindow options, webPreferences, complete reference |
| [Security Checklist](checklist.md) | Complete hardening checklist with verifiable checks |
| [Fuse Hardening](fuse-hardening.md) | Which fuses to disable, electron-builder integration |
| [CSP Configuration](csp.md) | Content Security Policy for Electron — headers, meta tags, directives |
| [IPC Hardening](ipc-hardening.md) | Sender validation, input validation, narrow bridge patterns |

---

## Quick Reference: Security Defaults by Electron Version

| Setting | Pre-5 Default | Pre-12 Default | Pre-20 Default | Current Default |
|---------|--------------|----------------|----------------|-----------------|
| nodeIntegration | **true** | false | false | false |
| contextIsolation | false | **false** | true | true |
| sandbox | false | false | **false** | true |
| webSecurity | true | true | true | true |

Apps on old Electron versions must explicitly set all of these. Apps on current Electron versions should verify they haven't overridden defaults.

---

## Defense in Depth: Layer Priority

```
Layer 1 (Runtime): contextIsolation:true + sandbox:true + nodeIntegration:false
         → Limits what a compromised renderer can access
         
Layer 2 (Bridge): Narrow contextBridge API with input validation
         → Limits what XSS can do via the preload bridge
         
Layer 3 (IPC): Origin validation + input validation in every handler
         → Limits what any renderer can accomplish via IPC
         
Layer 4 (Input): DOMPurify on user content + strict CSP
         → Prevents XSS from triggering in the first place
         
Layer 5 (Binary): Fuses (RunAsNode:false, NodeOptions:false, ASAR integrity)
         → Prevents local tamper and env-based attacks
         
Layer 6 (Update): HTTPS update server + code signature verification
         → Prevents update poisoning
```

A vulnerability at Layer 4 (XSS) is not exploitable to RCE if Layers 1-3 are solid. Defense in depth means attackers need to bypass multiple independent controls.
