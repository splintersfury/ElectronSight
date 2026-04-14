---
title: HTML Injection Sinks
description: XSS sinks in Electron apps — innerHTML, dangerouslySetInnerHTML, Markdown rendering, and the path to RCE
---

# HTML Injection Sinks

HTML injection sinks are properties and methods that interpret strings as HTML and execute embedded JavaScript. In a normal browser, XSS is "just" session hijacking and credential theft. In Electron, XSS can escalate to full OS code execution.

---

## The XSS → RCE Escalation

```
XSS in renderer
      ↓
JavaScript execution in renderer context
      ↓ (one of these paths)
      ├── nodeIntegration: true → require('child_process').exec()
      ├── contextIsolation: false → access preload's ipcRenderer
      └── contextBridge over-privileged → call IPC handler that runs exec()
      ↓
RCE in main process (or renderer with Node.js)
```

Without an escalation path, XSS in a sandboxed renderer is still serious (cookie theft, stored data exfil, phishing within the app) but not RCE.

---

## innerHTML

The most common XSS sink. Parses the string as HTML and injects it into the DOM, executing any `<script>` tags and event handlers.

```javascript
// VULNERABLE:
element.innerHTML = userMessage;
element.innerHTML = `<div>${userName}</div>`;
chatDiv.innerHTML += newMessage;

// innerHTML XSS payloads:
// Simple:
'<img src=x onerror=alert(1)>'

// With nodeIntegration: true:
'<img src=x onerror="require(\'child_process\').exec(\'calc\')">'

// Via event handler:
'<svg onload=eval(atob("BASE64_ENCODED_PAYLOAD"))>'

// Style injection:
'<div style="background:url(javascript:alert(1))">'  // old IE, some Chromium contexts
```

### innerHTML in React

React's JSX uses DOM text nodes by default (safe). The dangerous equivalent is:

```jsx
// SAFE — React escapes this:
<div>{userContent}</div>

// VULNERABLE — bypasses React escaping:
<div dangerouslySetInnerHTML={{ __html: userContent }} />
```

---

## document.write

Writes directly to the document stream, parsing HTML:

```javascript
document.write(userInput);
document.writeln(userInput);
// Same risks as innerHTML, often worse context
```

---

## insertAdjacentHTML

```javascript
element.insertAdjacentHTML('beforeend', userInput);
element.insertAdjacentHTML('afterbegin', userInput);
// 'beforebegin', 'afterbegin', 'beforeend', 'afterend' — all dangerous
```

---

## outerHTML

Replaces the element itself with parsed HTML:

```javascript
element.outerHTML = userInput;  // same as innerHTML risk
```

---

## Attribute Injection

Injecting into HTML strings before they hit innerHTML:

```javascript
// VULNERABLE — attribute injection:
element.innerHTML = `<a href="${userURL}">click</a>`;
// userURL = 'javascript:require("child_process").exec("calc")'
// → href="javascript:..." → onclick executes the JS

element.innerHTML = `<img src="${userSrc}">`;
// userSrc = 'x" onerror="eval(atob(...))'
// → onerror fires with our payload
```

---

## Markdown Rendering Sinks

Many Electron apps render Markdown (Discord, Notion, Obsidian, Joplin, etc.). Markdown renderers are particularly risky because:

1. User-controlled Markdown is common
2. Many renderers allow raw HTML
3. The output is fed to innerHTML or equivalent

```javascript
// marked (popular Markdown library):
const html = marked.parse(userMarkdown);
element.innerHTML = html;
// If marked allows raw HTML (default in older versions):
// userMarkdown = '<script>alert(1)</script>' → XSS

// marked sanitize option (deprecated in v5+):
marked.setOptions({ sanitize: true });  // was never effective

// Safe marked usage:
const html = marked.parse(userMarkdown, { mangle: false, headerIds: false });
const clean = DOMPurify.sanitize(html);  // MUST sanitize
element.innerHTML = clean;
```

### Obsidian CVE-2023-2110

Obsidian renders Markdown notes to the DOM. A crafted note containing:
```markdown
<img src=x onerror="require('child_process').exec('open -a Calculator')">
```
Executed code because Obsidian's Markdown renderer allowed raw HTML with insufficient sanitization, and `nodeIntegration` was available.

---

## Electron-Specific: webContents.executeJavaScript

Not a traditional sink, but the main process can inject arbitrary JS into any renderer:

```javascript
// main.js — CRITICAL if attacker reaches this code:
ipcMain.handle('run-script', async (event, code) => {
  return win.webContents.executeJavaScript(code);
  // code is attacker-controlled → JS execution in renderer
});
```

---

## Bypassing Sanitization

### DOMPurify Bypasses (Historical)

DOMPurify is the gold standard for HTML sanitization, but specific versions had bypasses:

```javascript
// mXSS (mutation XSS) — DOMPurify < 2.4.1:
// Browser parses HTML differently than DOMPurify's parser
// Crafted input passes sanitization but mutates to XSS on DOM insertion

// SVG/namespace confusion (DOMPurify < 2.0.17):
'<svg><p><style><g title="</style><img src=x onerror=alert(1)>">'
```

Always use the latest DOMPurify and test against mXSS payloads.

### CSP Bypasses

CSP `script-src 'self'` can be bypassed if the app serves any user-uploadable files from the same origin (JavaScript file upload → CSP bypass).

---

## Grep Patterns

```bash
# innerHTML variants:
grep -rn "\.innerHTML\b\|\.outerHTML\b\|insertAdjacentHTML\b\|document\.write\b" \
  --include="*.js" --include="*.jsx" --include="*.tsx" . | grep -v node_modules

# React dangerouslySetInnerHTML:
grep -rn "dangerouslySetInnerHTML" \
  --include="*.jsx" --include="*.tsx" --include="*.js" . | grep -v node_modules

# Marked/showdown/commonmark without sanitization:
grep -rn "marked\.parse\|marked(\|showdown\|commonmark" --include="*.js" . | grep -v node_modules

# Check if DOMPurify is used after Markdown rendering:
grep -rn "DOMPurify\|dompurify" --include="*.js" . | grep -v node_modules
```
