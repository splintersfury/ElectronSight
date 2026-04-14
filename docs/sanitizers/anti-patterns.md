---
title: Sanitizer Anti-Patterns
description: Broken sanitization patterns that look protective but don't actually break taint chains
---

# Sanitizer Anti-Patterns

The most dangerous sanitizers are the ones that *look* correct but don't actually block exploitation. These false sanitizers create a false sense of security — developers believe the chain is broken when it isn't.

---

## 1. Using textContent as HTML Sanitization

`textContent` is safe for *displaying* text, but if developers confuse when to use it:

```javascript
// ✅ textContent is safe for display:
element.textContent = userInput;  // Treats content as literal text — no HTML parsed

// ❌ Common mistake: using textContent to "sanitize" then inserting as HTML:
const "sanitized" = document.createElement('div');
sanitized.textContent = userInput;
const safe = sanitized.innerHTML;     // WRONG: this re-encodes the HTML entities
element.innerHTML = safe;             // Still XSS because innerHTML decodes them

// Example:
// userInput = '<img src=x onerror=alert(1)>'
// sanitized.textContent = '<img src=x onerror=alert(1)>'
// sanitized.innerHTML = '&lt;img src=x onerror=alert(1)&gt;'  ← looks escaped
// element.innerHTML = '&lt;img...' → rendered as text ← Actually safe in this case
// But: next step could be eval(safe) or insertAdjacentHTML(safe) → XSS
```

**Rule:** Don't use `.innerHTML` on a div as a way to "escape" for later re-use. Use DOMPurify or set `.textContent` directly.

---

## 2. Regex-Based HTML Stripping

Removing HTML tags with regex is notoriously broken:

```javascript
// ❌ Regex HTML stripping — easily bypassed:
function stripTags(html) {
  return html.replace(/<[^>]+>/g, '');
}

// Bypass examples:
// <<img src=x onerror=alert(1)>>  → first < stripped: <img src=x onerror=alert(1)>
// <img src=x onerror="alert(1)">  → may survive depending on regex
// <script>alert(1)</script>        → might work, but < > alone are stripped
// <sc<script>ript>alert(1)</sc</script>ript>  → after stripping inner <script>: <script>alert(1)</script>

// All these work because HTML parsers are more permissive than regex:
// <ImG/src=x\tonerror=alert(1)>  → valid HTML, regex may not strip attributes
```

---

## 3. Denylist-Based Command Sanitization

Blocking specific dangerous strings instead of allowlisting safe ones:

```javascript
// ❌ Denylist for shell commands:
function safeExec(cmd) {
  const BLOCKED = ['rm', 'del', 'wget', 'curl', '|', ';', '&', '`'];
  for (const block of BLOCKED) {
    if (cmd.includes(block)) throw new Error('Blocked');
  }
  return exec(cmd);
}

// Bypasses:
// 'r'+'m' → string concat evades includes()
// '\x72m' → hex encoding
// 'Rm -rf' → case (if Linux)
// 'r\tm -rf' → tab in command (bash ignores)
// Using IFS: ${IFS}rm${IFS}-rf${IFS}/
// Unicode normalization: ｒｍ → may normalize to rm
```

---

## 4. String Sanitization Before Parameterization Attempt

When developers sanitize to remove characters but then construct strings:

```javascript
// ❌ Sanitize then concatenate:
function safeQuery(tableName) {
  const safe = tableName.replace(/[^a-z]/gi, '');  // Remove non-alpha chars
  return db.query(`SELECT * FROM ${safe}`);         // Still injection if tableName tricks it
}

// This is actually OK for simple cases — but gives false confidence.
// What if tableName comes through a pipeline where sanitization is lost?
// What if another developer adds a field that bypasses this function?

// ✅ Better: parameterized queries + schema validation:
function safeQuery(tableName) {
  const ALLOWED_TABLES = ['users', 'posts', 'comments'];
  if (!ALLOWED_TABLES.includes(tableName)) throw new Error('Unknown table');
  return db.query(`SELECT * FROM ${tableName}`);  // Only one of 3 safe values
}
```

---

## 5. Client-Side-Only Validation

For Electron, the "client side" is the renderer — which an attacker can bypass entirely via IPC:

```javascript
// preload.js — validation in exposed function:
contextBridge.exposeInMainWorld('api', {
  deleteFile: (filename) => {
    // ❌ Validation only in preload:
    if (filename.includes('..')) throw new Error('No traversal');
    return ipcRenderer.invoke('file:delete', filename);
  }
});

// main.js — NO validation:
ipcMain.handle('file:delete', async (event, filename) => {
  fs.unlinkSync(path.join(notesDir, filename));  // SINK: no validation in main!
});

// Attack: post-XSS, attacker bypasses preload entirely:
// ipcRenderer.invoke('file:delete', '../../important.txt')
// This call goes directly to ipcMain, skipping preload validation
```

**Rule:** Always validate in ipcMain handlers. Preload validation is defense-in-depth, not the primary control.

---

## 6. JSON.stringify as Sanitizer

Developers sometimes think JSON.stringify prevents injection:

```javascript
// ❌ JSON.stringify doesn't prevent HTML/shell injection:
const userInput = '<script>alert(1)</script>';
const json = JSON.stringify(userInput);
// json = '"<script>alert(1)</script>"'
element.innerHTML = json;
// Renders: "<script>alert(1)</script>" — the quotes appear but:

// In a JS context:
eval(`var data = ${json}`);
// data = "<script>alert(1)</script>" → no XSS in this case
// But: if json contains </script>:
const evil = 'x</script><script>alert(1)</script>';
document.write(`<script>var data = ${JSON.stringify(evil)}</script>`);
// JSON.stringify produces: "x</script><script>alert(1)</script>"
// The </script> closes the parent script tag → XSS!
```

---

## 7. HTML Entity Encoding in Wrong Context

HTML encoding prevents XSS in HTML context but not in JavaScript/URL/CSS contexts:

```javascript
function htmlEncode(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ❌ HTML-encoded value in JavaScript context:
const encoded = htmlEncode(userInput);
element.innerHTML = `<button onclick="doAction('${encoded}')">Click</button>`;
// userInput = "'); alert(1); //"
// encoded = "&#39;); alert(1); //"
// innerHTML parses &# entities → onclick = "'): alert(1); //"  → XSS!
// HTML decodes entities before JS execution
```

---

## 8. Shallow Validation (Only Checking First Level)

```javascript
// ❌ Only validates top-level properties:
function validateConfig(config) {
  if (typeof config.name !== 'string') throw new Error('Invalid name');
  if (typeof config.version !== 'string') throw new Error('Invalid version');
  return config;
}

// Bypass: valid top-level, dangerous nested:
validateConfig({
  name: "safe-name",
  version: "1.0.0",
  __proto__: { isAdmin: true },           // Prototype pollution
  constructor: { prototype: { x: 1 } },  // Constructor pollution
  settings: {
    script: "rm -rf /",                   // Nested dangerous value not checked
    url: "javascript:alert(1)"
  }
});
```

---

## 9. Trusting `event.sender.getURL()` as Sanitizer

```javascript
// ❌ Using sender URL as sole validation:
ipcMain.handle('sensitive-op', async (event, data) => {
  const senderUrl = event.sender.getURL();
  if (!senderUrl.startsWith('file:///')) {
    throw new Error('Untrusted');
  }
  // Assumes all file:// renderers are trusted
  // But: renderer can navigate to file:///attacker-controlled.html
  // Or: webSecurity:false allows loading any file:// URL
  doSensitiveOperation(data);
});

// ✅ Check for exact expected URL:
const EXPECTED_URL = 'file://' + path.join(app.getAppPath(), 'index.html');
if (senderUrl !== EXPECTED_URL) throw new Error('Untrusted sender');
```

---

## Detection Patterns

```bash
# Find regex-based HTML stripping:
grep -rn "replace.*<.*>\|stripTags\|removeTags" --include="*.js" . | grep -v node_modules

# Find denylist patterns (should use allowlist):
grep -rn "includes.*rm\b\|includes.*exec\|includes.*eval" \
  --include="*.js" . | grep -v node_modules

# Find JSON.stringify used near innerHTML:
grep -rn "JSON\.stringify" --include="*.js" . -A 3 | \
  grep "innerHTML\|insertAdjacentHTML\|document\.write" | grep -v node_modules

# Find client-only validation (validation in preload but not in ipcMain):
# This requires cross-file analysis — check preload validation against ipcMain handlers

# Find htmlEncode used in script context:
grep -rn "encode.*html\|htmlEncode\|escapeHtml" --include="*.js" . -A 5 | \
  grep "onclick\|script\|href.*javascript" | grep -v node_modules
```
