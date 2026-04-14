---
title: webSecurity=false
description: Disabling Electron's web security — SOP bypass, CORS removal, local file access from web context
---

# webSecurity=false

`webSecurity: false` turns off Chromium's Same-Origin Policy, CORS enforcement, and mixed content blocking in the renderer. It's a setting that exists almost exclusively because developers ran into CORS issues during development and chose the nuclear option instead of fixing their API server headers.

The thing is, CORS and SOP exist for a reason. Without them, any JavaScript executing in the renderer — whether it's the app's own code or an attacker's XSS payload — can read cross-origin responses, access internal network services, and load local files from disk. The browser's foundational security model, which web users depend on, is simply gone.

---

## What This Setting Actually Disables

```javascript
new BrowserWindow({
  webPreferences: {
    webSecurity: false  // Turns off ALL of:
    // - Same-Origin Policy
    // - CORS header enforcement
    // - Mixed content blocking (HTTP in HTTPS context)
    // - Cross-origin cookie restrictions
    // - Sandboxing of cross-origin iframes
    // - Restrictions on file:// access from remote pages
  }
});
```

One setting, many consequences.

---

## What an Attacker Does With It

### Cross-Origin Data Theft

Normally, CORS prevents a page from reading cross-origin responses even if it can make the request. With `webSecurity: false`, that check is gone:

```javascript
// With webSecurity: false — cross-origin reads succeed:
fetch('https://api.internal.company.com/employees', { credentials: 'include' })
  .then(r => r.json())
  .then(data => exfiltrate(data));
// Normally blocked by CORS — attacker now has the data

// Internal admin panel:
fetch('http://localhost:8080/admin/export', { credentials: 'include' })
  .then(r => r.text())
  .then(data => { /* admin data, no auth required beyond the session */ });
```

### Internal Network Access

The renderer becomes an SSRF pivot:

```javascript
// AWS metadata service — only accessible from the instance:
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  .then(r => r.json())
  .then(creds => exfiltrate(creds));

// Other internal hosts not exposed to the internet:
fetch('http://192.168.1.1/admin').then(r => r.text()).then(console.log);
```

If the app runs on a company laptop with internal VPN, the renderer with `webSecurity: false` can reach anything on the internal network that the laptop can reach.

### Local File Access from Remote Context

```javascript
// Remote page loading local files — normally completely blocked:
fetch('file:///etc/passwd').then(r => r.text()).then(console.log);
fetch('file:///home/user/.ssh/id_rsa').then(r => r.text()).then(exfiltrate);
fetch('file:///C:/Users/user/AppData/Roaming/credentials.json')
  .then(r => r.json()).then(exfiltrate);
```

---

## Why This Gets Shipped

The honest answer: someone hit a CORS error, searched Stack Overflow, found `webSecurity: false`, it made the error go away, and it shipped. The CORS error was a symptom of an API server that didn't have the right headers — the fix was one line on the server side, but this felt faster.

It also shows up as a "development only" setting that got copied into production config:

```javascript
// Intended to be dev-only, but shipped:
new BrowserWindow({
  webPreferences: {
    webSecurity: !app.isPackaged  // false in dev — but also false during local testing
    // and sometimes app.isPackaged is false in production builds too
  }
});
```

```bash
# Check if webSecurity: false is gated on dev mode (and whether that gating works):
grep -r "webSecurity" --include="*.js" . -B 5 | \
  grep -E "isDev|isPackaged|NODE_ENV" | grep -v node_modules
```

---

## The Dangerous Combination

`webSecurity: false` alone is a High finding — SSRF, data theft, local file access. Combined with `nodeIntegration: true` it becomes Critical: remote content loads without SOP restrictions, and any loaded script has `require('child_process')` access. SiYuan CVE-2026-39846 demonstrated this exact combination.

Even without `nodeIntegration`, an XSS in an app with `webSecurity: false` has a larger blast radius than a normal renderer XSS: the attacker's script can make SSRF requests, read internal API responses, and pull local credential files.

---

## Detection

```bash
# Direct search:
grep -rn "webSecurity.*false\|webSecurity:false" --include="*.js" . | grep -v node_modules

# Check if it's conditional (dev-mode gating):
grep -rn "webSecurity" --include="*.js" . -B 3 -A 3 | grep -v node_modules
```

---

## The Correct Fix

Don't use `webSecurity: false`. For CORS issues:

**Option 1: Fix CORS headers on the API server.** This is always the right answer for external APIs you control.

**Option 2: Proxy through the main process.** The renderer calls an IPC handler, the main process makes the fetch, returns the result. No CORS issue because the main process isn't a browser:

```javascript
// main.js:
ipcMain.handle('fetch-data', async (event, url) => {
  // Validate url here first:
  const response = await fetch(url);
  return response.json();
});

// renderer: calls window.api.fetchData(url) instead of fetch() directly
```

**Option 3: Use Electron's session.webRequest to add CORS headers in development:**

```javascript
// main.js (dev only):
if (!app.isPackaged) {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Access-Control-Allow-Origin': ['*']
      }
    });
  });
}
```

Any of these is better than shipping `webSecurity: false`.
