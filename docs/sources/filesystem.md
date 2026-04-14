---
title: Filesystem Sources
description: File reads, directory listings, and filesystem events as attacker-controlled input sources
---

# Filesystem Sources

Filesystem sources involve data read from disk that can be influenced by an attacker. In Electron, this is particularly significant because:

1. The main process runs with **full filesystem access** (no sandbox)
2. Apps process **user-provided files** (project files, attachments, imports)
3. Apps read **config files** from predictable locations
4. Symlink attacks can redirect reads to attacker-controlled locations

---

## User-Provided Files

The most obvious filesystem source — files the user explicitly opens:

```javascript
// via Electron dialog:
ipcMain.handle('open-file', async (event) => {
  const { filePaths } = await dialog.showOpenDialog({
    properties: ['openFile'],
    filters: [{ name: 'Projects', extensions: ['proj', 'json'] }]
  });
  
  if (filePaths.length > 0) {
    const content = fs.readFileSync(filePaths[0], 'utf8');  // SOURCE: file content
    return JSON.parse(content);  // SOURCE: parsed object
  }
});

// If the returned object is used dangerously in renderer:
// project.buildScript → exec()
// project.htmlContent → innerHTML
// project.updateUrl → shell.openExternal()
```

---

## Configuration Files

Apps read config from predictable paths — an attacker who can write these files controls subsequent behavior:

```javascript
// App config from userData:
const configPath = path.join(app.getPath('userData'), 'settings.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));  // SOURCE

// Dangerous usage patterns:
shell.openExternal(config.updateServer);          // SINK
exec(config.preStartScript);                      // SINK
win.loadURL(config.startPage);                    // SINK
new BrowserWindow({ ...config.windowOptions });   // SINK: sets webPreferences?

// System-wide config (readable by unprivileged users):
const globalConfig = JSON.parse(
  fs.readFileSync('/etc/myapp/config.json', 'utf8')  // SOURCE: writable by local user?
);
```

### YAML Config — Code Execution Risk

```javascript
const yaml = require('js-yaml');

// js-yaml's .load() can execute JavaScript:
const config = yaml.load(fs.readFileSync('config.yml', 'utf8'));
// config.yml:
// command: !!js/function 'function() { return require("child_process").execSync("calc") }'

// Safe: use yaml.safeLoad() (deprecated) or yaml.load() with schema: yaml.CORE_SCHEMA
const safeConfig = yaml.load(content, { schema: yaml.CORE_SCHEMA });
```

---

## Path Traversal in File Reads

When the read path is derived from user input, path traversal becomes a source amplifier:

```javascript
// ipcMain handler that reads files by name:
ipcMain.handle('read-note', async (event, noteName) => {
  // noteName — SOURCE: from renderer
  const notesDir = path.join(app.getPath('userData'), 'notes');
  
  // ❌ path.join doesn't prevent traversal:
  const notePath = path.join(notesDir, noteName);
  // noteName = "../../../../../../etc/passwd"
  // notePath = "/etc/passwd" — traverses out of notesDir!
  
  return fs.readFileSync(notePath, 'utf8');  // SOURCE: arbitrary file read
});
```

**Fix:**
```javascript
const safePath = path.resolve(notesDir, noteName);
if (!safePath.startsWith(notesDir + path.sep)) {
  throw new Error('Path traversal detected');
}
```

---

## Filesystem Events (Watchers)

File watchers process filesystem events — event paths can be attacker-influenced:

```javascript
const chokidar = require('chokidar');

const watcher = chokidar.watch(watchDir, { recursive: true });

watcher.on('change', (filePath) => {
  // filePath — SOURCE: file that changed
  // If attacker can create files in watchDir:
  const content = fs.readFileSync(filePath, 'utf8');  // SOURCE
  processContent(content);  // SOURCE → processing pipeline
});

watcher.on('add', (filePath) => {
  if (filePath.endsWith('.plugin')) {
    loadPlugin(filePath);  // SINK: auto-load any .plugin file created in dir
  }
});
```

---

## Symlink TOCTOU

Time-of-Check to Time-of-Use via symlinks — the path is validated at check time but different at use time:

```javascript
// Classic TOCTOU pattern:
const targetPath = path.resolve(safeDir, userInput);

// Check phase:
if (!fs.existsSync(targetPath)) {
  throw new Error('File not found');
}
// Attacker replaces targetPath with a symlink to /etc/shadow here

// Use phase:
const content = fs.readFileSync(targetPath, 'utf8');  // Reads /etc/shadow!
```

### Symlink Attacks in Electron File Processing

```javascript
// App extracts uploaded ZIP file:
unzipTo(uploadedZip, extractDir);
// If ZIP contains entry: ../../../../.bashrc (symlink or path traversal)
// Extraction writes to arbitrary path

// App processes all files in a directory:
const files = fs.readdirSync(pluginDir);
files.forEach(f => {
  const content = fs.readFileSync(path.join(pluginDir, f));  // SOURCE
  // If pluginDir/evil.js → symlink → /root/.ssh/id_rsa → reads key
});
```

---

## Native Module File Loading

`.node` native addons are loaded from filesystem paths:

```javascript
// require() with user-provided path:
const addon = require(path.join(pluginDir, userInput + '.node'));  // SOURCE → code exec
addon.doSomething();

// If pluginDir is writable by attacker → drop malicious .node → arbitrary native code
```

---

## File Metadata as Source

Even file metadata (not content) can be a source:

```javascript
// File listing:
const files = fs.readdirSync(userDir);  // SOURCE: filenames
files.forEach(filename => {
  listElement.innerHTML += `<li>${filename}</li>`;  // SINK: filename → XSS
});

// File stats:
const stats = fs.statSync(userPath);  // SOURCE: metadata
displayElement.textContent = stats.size;  // Safe
displayElement.innerHTML = `Size: ${stats.size}`;  // Safer than filename case
```

---

## Detection Patterns

```bash
# Find all file reads:
grep -rn "readFileSync\|readFile(\|createReadStream" \
  --include="*.js" . | grep -v node_modules | head -40

# Find file reads with dynamic paths:
grep -rn "readFileSync\|readFile(" --include="*.js" . | \
  grep -v "node_modules\|__dirname\|__filename\|app\.getPath\b" | head -20

# Find directory traversal risk (path.join but not path.resolve + startsWith):
grep -rn "path\.join" --include="*.js" . -A 2 | \
  grep -v "node_modules\|resolve\|startsWith" | head -20

# Find file watchers:
grep -rn "chokidar\|fs\.watch\|fs\.watchFile" --include="*.js" . | grep -v node_modules

# Find YAML loading (check for unsafe yaml.load):
grep -rn "yaml\.load\b" --include="*.js" . | grep -v "safeLoad\|CORE_SCHEMA\|FAILSAFE\|JSON_SCHEMA"

# Find plugin/addon loading from filesystem:
grep -rn "require(.*plugin\|require(.*addon\|\.node'" \
  --include="*.js" . | grep -v node_modules
```

---

## Risk Matrix

| Source | Risk | Attacker Control Requirement |
|--------|------|------------------------------|
| User-opened file (dialog) | High | Social engineering — open malicious file |
| `yaml.load()` on user file | Critical | Craft YAML with `!!js/function` |
| Path traversal in read | High | Control read path argument |
| Symlink TOCTOU | High | Write access to watched dir |
| Config file from writable path | High | Write access to config location |
| File listing → innerHTML | Medium | Create files with HTML names |
| Watcher on attacker-writable dir | High | Create malicious files in dir |
| Native `.node` file loading | Critical | Write .node to plugin dir |
