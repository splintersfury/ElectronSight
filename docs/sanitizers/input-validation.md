---
title: Input Validation
description: Type checking, allowlisting, bounds checking, and path validation as sanitizer patterns
---

# Input Validation

Input validation is the most direct way to break a taint chain — if the data is validated before reaching a sink, it's no longer attacker-controlled in a dangerous sense. But validation is only a sanitizer if it's **correct**, **complete**, and **applied at the right place**.

---

## The Validation Hierarchy

Not all validation is equal. From strongest to weakest:

```
1. Reject-if-not-allowlisted     ← Strongest: only known-good values pass
2. Type coercion + bounds check  ← Strong: converts and limits
3. Type check only               ← Medium: typeof/instanceof
4. Denylist                      ← Weak: known-bad values blocked
5. Regex on complex input        ← Fragile: often bypassable
6. Length check only             ← Minimal: prevents overflow, not injection
```

---

## Type Validation

```javascript
// Type checking — necessary but not sufficient:
ipcMain.handle('save-note', async (event, title, content) => {
  // ❌ Insufficient — type only:
  if (typeof title !== 'string') throw new TypeError('Invalid title');
  
  // ✅ Better — type + bounds + sanitize:
  if (typeof title !== 'string') throw new TypeError('Invalid title');
  if (title.length > 200) throw new RangeError('Title too long');
  const safeTitle = title.replace(/[^\w\s\-_.]/g, '');  // Allowlist chars
  
  // For numbers:
  if (!Number.isInteger(page)) throw new TypeError('Invalid page');
  if (page < 1 || page > 10000) throw new RangeError('Page out of range');
});
```

---

## Path Validation

One of the most critical — and most often incorrectly implemented — validations:

```javascript
const path = require('path');

// ❌ WRONG — path.join doesn't prevent traversal:
function readNote(noteName) {
  const notesDir = path.join(app.getPath('userData'), 'notes');
  const filePath = path.join(notesDir, noteName);  // "../../.ssh/id_rsa" traverses!
  return fs.readFileSync(filePath);
}

// ✅ CORRECT — resolve + startsWith:
function safeReadNote(noteName) {
  const notesDir = path.resolve(app.getPath('userData'), 'notes');
  const filePath = path.resolve(notesDir, noteName);
  
  // CRITICAL: use path.sep to prevent /home/usernotes/ matching /home/user/
  if (!filePath.startsWith(notesDir + path.sep)) {
    throw new Error('Path traversal detected');
  }
  
  return fs.readFileSync(filePath, 'utf8');
}

// ❌ ALSO WRONG — checking before resolve:
function incorrectCheck(noteName) {
  if (noteName.includes('..')) throw new Error('No traversal');
  // Bypass: 'notes/..%2F..%2F.ssh' → decoded after check
  // Or: Unicode normalization: 'notes/\u002e\u002e/'
}
```

---

## URL Validation

For `shell.openExternal` and `loadURL`:

```javascript
// ❌ String-based URL check (bypassable):
if (url.startsWith('https://')) {
  shell.openExternal(url);  // "https://evil.com" still malicious
  // Also: "https:\\/\\/evil.com" might bypass startsWith
}

// ✅ URL parsing + protocol allowlist:
function safeOpenExternal(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid URL');
  }
  
  const ALLOWED_PROTOCOLS = ['https:', 'http:', 'mailto:'];
  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    throw new Error(`Blocked protocol: ${parsed.protocol}`);
  }
  
  // Optional: restrict to known domains:
  const ALLOWED_HOSTS = ['myapp.com', 'www.myapp.com', 'help.myapp.com'];
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    // Open in browser (user-visible) or block entirely
    throw new Error(`Unknown host: ${parsed.hostname}`);
  }
  
  return shell.openExternal(url);
}
```

---

## Allowlist vs Denylist

Always prefer allowlisting:

```javascript
// ❌ Denylist (bypassable):
function sanitizeCommand(cmd) {
  const DANGEROUS = ['rm', 'del', 'format', 'sudo'];
  if (DANGEROUS.some(d => cmd.includes(d))) {
    throw new Error('Dangerous command');
  }
  return exec(cmd);
}
// Bypass: 'r\rm', 'rm\t', unicode equivalent, etc.

// ✅ Allowlist (robust):
function runApprovedScript(scriptName) {
  const ALLOWED_SCRIPTS = ['build', 'test', 'lint', 'format'];
  if (!ALLOWED_SCRIPTS.includes(scriptName)) {
    throw new Error(`Unknown script: ${scriptName}`);
  }
  return exec(`npm run ${scriptName}`);  // scriptName is now one of 4 safe values
}
```

---

## JSON Schema Validation

For complex IPC arguments, JSON schema validation provides strong guarantees:

```javascript
const Ajv = require('ajv');
const ajv = new Ajv();

// Define expected schema:
const noteSchema = {
  type: 'object',
  required: ['title', 'content'],
  additionalProperties: false,  // CRITICAL: blocks extra properties
  properties: {
    title: { type: 'string', maxLength: 200, pattern: '^[\\w\\s\\-_.]+$' },
    content: { type: 'string', maxLength: 100000 },
    tags: {
      type: 'array',
      maxItems: 20,
      items: { type: 'string', maxLength: 50 }
    }
  }
};

const validateNote = ajv.compile(noteSchema);

ipcMain.handle('note:save', async (event, noteData) => {
  if (!validateNote(noteData)) {
    throw new Error(`Validation failed: ${ajv.errorsText(validateNote.errors)}`);
  }
  // noteData now matches schema exactly — safe to use
  return saveNote(noteData.title, noteData.content, noteData.tags);
});
```

---

## Structural Validation Anti-Patterns

### 1. Validation After Use

```javascript
// ❌ Use before validate:
ipcMain.handle('process', async (event, data) => {
  const result = riskyOperation(data);  // Used first
  validateData(data);                   // Validated after — too late!
  return result;
});
```

### 2. Validation on a Copy While Using Original

```javascript
// ❌ Clone-then-validate (if original is a reference):
ipcMain.handle('process', async (event, obj) => {
  const copy = { ...obj };
  if (!isValid(copy)) return;
  
  processObject(obj);  // Still using original — could have prototype pollution
  // Fix: processObject(copy) — use the validated copy
});
```

### 3. Mutable Object Validation

```javascript
// ❌ Validate then use — object mutated between:
if (isValid(userConfig)) {
  // In multi-threaded/async context, userConfig could change here
  setTimeout(() => apply(userConfig), 0);  // TOCTOU
}

// ✅ Validate and freeze:
if (isValid(userConfig)) {
  const frozenConfig = Object.freeze({ ...userConfig });
  setTimeout(() => apply(frozenConfig), 0);
}
```

---

## Integer Validation

Integer overflows and underflows in Node.js are less dangerous than C (due to 64-bit floats) but still matter:

```javascript
// Safe integer check:
function validatePageNumber(page) {
  if (!Number.isInteger(page)) throw new TypeError('Not an integer');
  if (!Number.isSafeInteger(page)) throw new RangeError('Integer too large');
  if (page < 1 || page > MAX_PAGE) throw new RangeError('Out of range');
  return page;
}

// Array length attacks:
function validateArray(arr) {
  if (!Array.isArray(arr)) throw new TypeError('Not an array');
  if (arr.length > 1000) throw new RangeError('Array too large');
  // Also validate each element:
  arr.forEach((item, i) => {
    if (typeof item !== 'string') throw new TypeError(`Item ${i} not string`);
  });
}
```

---

## Detection — Finding Missing Validation

```bash
# Find IPC handlers with no typeof/instanceof/length check:
grep -rn "ipcMain\.\(on\|handle\)" --include="*.js" . -A 15 | \
  grep -v "node_modules\|typeof\|instanceof\|\.length\|isString\|validate\|schema" | \
  grep -E "exec\b|spawn\b|writeFile|readFile|openExternal|loadURL" | head -20

# Find path operations without startsWith guard:
grep -rn "path\.join\|path\.resolve" --include="*.js" . -A 5 | \
  grep -v "node_modules\|startsWith\|includes\b" | head -20

# Find shell.openExternal without URL parsing:
grep -rn "openExternal" --include="*.js" . -B 10 | \
  grep -v "node_modules\|new URL\|\.protocol\|startsWith" | head -20

# Find regex-based validation (fragile):
grep -rn "\.match(\|\.test(\|\.replace(" --include="*.js" . | \
  grep -v node_modules | grep "path\|url\|file\|cmd\|command" | head -20
```
