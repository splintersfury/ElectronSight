---
title: Storage Sources
description: localStorage, IndexedDB, cookies, and file-based storage as attacker-controlled data sources
---

# Storage Sources

Storage sources are data that has been persisted to disk or browser storage and is later read back and processed. They're often overlooked because the attacker isn't providing the data *in real time* — but if an attacker has ever influenced what was stored, reading from storage is reading attacker-controlled data.

---

## The Stored XSS Mental Model

Storage sources follow the stored XSS pattern:

```
Phase 1 (data write):  
  Attacker provides malicious data → app stores it without sanitization

Phase 2 (data read):
  App reads stored data → processes it → dangerous operation
  
This creates a *time-delayed* taint flow:
  write time: attacker_data → localStorage.setItem(key, attacker_data)
  read time:  localStorage.getItem(key) → innerHTML / exec / IPC handler
```

---

## localStorage

```javascript
// SOURCE — data originally written from user input:
const username = localStorage.getItem('username');      // SOURCE
const settings = JSON.parse(localStorage.getItem('app-settings'));  // SOURCE
const lastUrl = localStorage.getItem('lastVisitedUrl'); // SOURCE

// Common unsafe usage:
document.getElementById('greeting').innerHTML = `Welcome, ${username}`;  
// → stored XSS if username contained HTML

const template = localStorage.getItem('customTemplate');
document.body.insertAdjacentHTML('beforeend', template);  
// → stored XSS

// Dangerous: stored shell commands
exec(localStorage.getItem('userScript'));  // → stored RCE
```

### When localStorage Becomes Attacker-Controlled

1. **Persistent XSS**: An earlier XSS payload wrote to localStorage
2. **Shared storage**: Multiple renderer windows share the same origin's localStorage
3. **Import feature**: App allows importing settings files → attacker provides malicious JSON
4. **URL parameters stored without sanitization**: `localStorage.setItem('redirect', location.search.get('r'))`

---

## IndexedDB

IndexedDB is used for larger structured data — same trust model as localStorage:

```javascript
// SOURCE:
const db = await openDB('AppDatabase', 1);
const messages = await db.getAll('messages');  // SOURCE: all stored messages

messages.forEach(msg => {
  // msg.body — SOURCE: user messages could contain HTML/scripts
  chatContainer.innerHTML += `<div class="message">${msg.body}</div>`;  // SINK
});

// Stored template pattern:
const template = await db.get('templates', templateId);  // SOURCE
renderTemplate(template.html);  // SINK if renderTemplate uses innerHTML
```

### Electron-Specific: userData Directory

Electron apps use `app.getPath('userData')` for persistent storage — this maps to:
- Windows: `%APPDATA%\AppName\`
- macOS: `~/Library/Application Support/AppName/`
- Linux: `~/.config/AppName/`

Files in userData persist between sessions and are readable by local processes:

```javascript
// Reading stored config (SOURCE):
const configPath = path.join(app.getPath('userData'), 'config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));  // SOURCE

// If config was written from untrusted input earlier:
shell.openExternal(config.updateServer);  // SINK
exec(config.preHook);                     // SINK
win.loadURL(config.homeUrl);              // SINK
```

---

## Cookies

Cookies are read by both the renderer (document.cookie) and the main process (Electron's session API):

```javascript
// Renderer-side:
const sessionId = document.cookie                              // SOURCE
  .split(';')
  .find(c => c.trim().startsWith('session='))
  ?.split('=')[1];

// Main process via Electron session API:
session.defaultSession.cookies.get({ name: 'authToken' }, (err, cookies) => {
  const token = cookies[0]?.value;  // SOURCE
  makeApiCall(token);               // SOURCE (less risky — token use)
  logToFile(`Auth: ${token}`);      // SINK: credentials in logs
});
```

### Cookie Poisoning via XSS

If an earlier XSS payload sets a cookie:

```javascript
// XSS payload sets malicious cookie:
document.cookie = 'redirect=javascript:alert(1); path=/';

// Later, app reads the cookie:
const redirectUrl = getCookie('redirect');
window.location.href = redirectUrl;  // SINK: stored XSS via cookie
```

---

## Electron Session State

The `session` API persists state beyond localStorage:

```javascript
// session.defaultSession.storedData — not a real API but illustrative
// Actual: session.clearStorageData(), cookies, protocol handlers, etc.

// Custom protocol registered from stored config:
const registeredHandlers = loadHandlers();  // SOURCE: from disk
registeredHandlers.forEach(({ scheme, handler }) => {
  protocol.registerStringProtocol(scheme, handler);  // SINK: registers code from storage
});
```

---

## File-Based Storage

Apps that write and read their own file formats create file-based sources:

```javascript
// Read a user-created project file:
ipcMain.handle('open-project', async (event, filePath) => {
  const data = fs.readFileSync(filePath, 'utf8');  // SOURCE: file content
  const project = JSON.parse(data);                // SOURCE: parsed project
  
  return project;  // Sends SOURCE data to renderer
});

// Renderer processes the project:
win.webContents.send('project-loaded', project);

// In renderer:
ipcRenderer.on('project-loaded', (event, project) => {
  // project.name, project.script, project.htmlTemplate — all SOURCE
  document.title = project.name;                   // Low risk
  document.body.innerHTML = project.htmlTemplate;  // SINK: stored XSS via file
  exec(project.buildScript);                       // SINK: RCE via project file
});
```

### Configuration Files (YAML, JSON, TOML)

```javascript
// YAML is particularly dangerous — can contain JS expressions in some parsers:
const config = yaml.load(fs.readFileSync('config.yml'));  // SOURCE
// js-yaml safeLoad is safe; yaml.load() can execute code with !!js/function tags

// JSON is safer but values are still attacker-controlled:
const settings = JSON.parse(fs.readFileSync('settings.json'));
shell.openExternal(settings.updateUrl);  // SINK
```

---

## Clipboard

System clipboard contents are often attacker-controlled:

```javascript
const { clipboard } = require('electron');

// Main process:
const text = clipboard.readText();         // SOURCE: OS clipboard
const html = clipboard.readHTML();         // SOURCE: rich clipboard content
const image = clipboard.readImage();       // Less risky but path could leak

// Usage patterns:
editor.insertHTML(clipboard.readHTML());   // SINK: if not sanitized
eval(clipboard.readText());                // SINK: explicit code execution
exec(clipboard.readText());                // SINK: shell command from clipboard
```

---

## Detection Patterns

```bash
# Find localStorage reads followed by unsafe use:
grep -rn "localStorage\.getItem\|sessionStorage\.getItem" \
  --include="*.js" . | grep -v node_modules

# Find IndexedDB reads:
grep -rn "\.getAll\|\.get(\|idb\.\|openDB" --include="*.js" . | grep -v node_modules

# Find userData file reads:
grep -rn "getPath.*userData\|userData.*getPath" --include="*.js" . | grep -v node_modules
grep -rn "readFileSync\|readFile(" --include="*.js" . | \
  grep "userData\|config\|settings\|project" | grep -v node_modules

# Find cookie reads:
grep -rn "document\.cookie\|cookies\.get\b" --include="*.js" . | grep -v node_modules

# Find clipboard reads:
grep -rn "clipboard\.read\|readText()\|readHTML()" --include="*.js" . | grep -v node_modules

# Find YAML/JSON file parsing (check for unsafe yaml.load):
grep -rn "yaml\.load\b\|require('js-yaml')" --include="*.js" . | grep -v node_modules
```

---

## Risk Matrix

| Source | Risk | Attacker Write Path |
|--------|------|---------------------|
| localStorage after stored XSS | High | Prior XSS writes payload |
| userData config file | High | Malicious project file import |
| Project/document file | High | Social engineering — open malicious file |
| IndexedDB after stored XSS | High | Prior XSS writes payload |
| Cookie after XSS | Medium | Prior XSS sets cookie |
| Clipboard | Medium | User pastes attacker content |
| `yaml.load()` | Critical | YAML !!js/function tag → code execution |
| Session cookies | Low-Med | Cookie theft required |
