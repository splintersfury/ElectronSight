---
title: Filesystem Attack Surface
description: Filesystem access in Electron — direct reads, dialog-opened files, and path traversal vectors
---

# Filesystem Attack Surface

Electron's main process runs with full filesystem access — no sandbox, no restrictions beyond the OS's own permission model. Every `fs.readFile`, `fs.writeFile`, and `exec` in the main process is a potential attack surface when the path or content is influenced by anything outside the main process.

The interesting attack vectors are usually not the obvious "read arbitrary file" cases (those are caught in code review). They're the subtle path construction bugs where a developer correctly sanitizes the filename but not the directory, or validates the path at one point in the code and uses it at another (TOCTOU), or concatenates user-supplied data with `path.join` instead of `path.resolve`.

---

## The Filesystem Threat Model

```
Main Process (full filesystem access)
         │
         │ Reads/writes files based on:
         ├── IPC arguments (attacker-controlled via XSS)
         ├── Protocol handler parameters (attacker-controlled externally)
         ├── User-opened files (social engineering)
         ├── Config files (writable by attacker prior)
         └── Auto-discovered paths (symlink attacks)
```

Unlike web apps, there's no OS-level restriction on what files can be accessed.

---

## File Read Attack Surface

### IPC-Triggered File Reads

```javascript
// Any IPC handler that reads files with renderer-controlled paths:
ipcMain.handle('read-file', async (event, filePath) => {
  // filePath — SOURCE from renderer
  return fs.readFileSync(filePath, 'utf8');  // SINK: arbitrary file read
  
  // Attack:
  // ipcRenderer.invoke('read-file', '/etc/shadow')
  // ipcRenderer.invoke('read-file', 'C:\\Windows\\System32\\SAM')
});
```

### Path Traversal

The fundamental filesystem vulnerability pattern:

```javascript
// ❌ path.join doesn't prevent traversal:
const notesDir = '/home/user/.config/myapp/notes';
const userFile = '../../.ssh/id_rsa';  // attacker input

path.join(notesDir, userFile);
// → '/home/user/.config/myapp/notes/../../.ssh/id_rsa'
// → normalizes to: '/home/user/.ssh/id_rsa'  ← TRAVERSAL

// ✅ path.resolve + startsWith:
const resolved = path.resolve(notesDir, userFile);
if (!resolved.startsWith(notesDir + path.sep)) {
  throw new Error('Path traversal detected');
}
// resolved = '/home/user/.ssh/id_rsa'
// '/home/user/.ssh/id_rsa'.startsWith('/home/user/.config/myapp/notes/') → false → blocked
```

---

## File Write Attack Surface

File writes are more dangerous than reads — they can create persistence:

```javascript
// Arbitrary write primitive:
ipcMain.handle('write-note', async (event, title, content) => {
  const notesDir = app.getPath('userData') + '/notes';
  const filePath = path.join(notesDir, title + '.md');  // VULNERABLE: no traversal check
  
  fs.writeFileSync(filePath, content);
  // Attack: title = '../../.bashrc', content = 'exec malware.sh\n$(cat ~/.bashrc)'
  // → writes to ~/.bashrc → persistence on shell open
  
  // On Windows:
  // title = '../../AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.bat'
  // → writes to Startup folder → executes on next login
});
```

### Startup Persistence Targets

```
Windows:
  %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\evil.bat
  C:\Windows\System32\Tasks\evil.xml (requires admin)
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run (registry — not filesystem)

macOS:
  ~/Library/LaunchAgents/com.evil.plist
  /Library/LaunchDaemons/ (requires root)
  ~/Library/Application Support/com.apple.backgroundtaskmanagementd/

Linux:
  ~/.bashrc / ~/.profile / ~/.config/autostart/evil.desktop
  /etc/cron.d/ (requires root)
  ~/.config/systemd/user/evil.service
```

---

## Symlink TOCTOU Attacks

When the filesystem is used with TOCTOU patterns:

```javascript
// Pattern: check → use (time gap is the vulnerability):
async function safeRead(userPath) {
  const resolved = path.resolve(safeDir, userPath);
  
  // CHECK phase:
  if (!resolved.startsWith(safeDir)) throw new Error('Traversal');
  if (!fs.existsSync(resolved)) throw new Error('Not found');
  
  // RACE WINDOW: attacker can replace resolved with a symlink here
  
  // USE phase:
  return fs.readFileSync(resolved, 'utf8');  // Reads symlink target!
}
```

**Practical attack:**
1. App checks that `/tmp/app-cache/file.dat` is valid
2. Attacker: `rm /tmp/app-cache/file.dat && ln -s /etc/shadow /tmp/app-cache/file.dat`
3. App reads `/etc/shadow` through the now-replaced symlink

**Mitigation:**
```javascript
// Open with O_NOFOLLOW flag (prevents symlink following):
const fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
// Or check for symlink first:
const stat = fs.lstatSync(filePath);
if (stat.isSymbolicLink()) throw new Error('Symlinks not allowed');
```

---

## Directory Traversal in Archive Extraction

Apps that extract ZIP/TAR files:

```javascript
const AdmZip = require('adm-zip');

// Vulnerable extraction:
const zip = new AdmZip(userUploadedZip);
zip.extractAllTo(extractDir, true);  // Extracts to extractDir
// But ZIP entries can contain: ../../evil.js, ../../../etc/cron.d/backdoor
// → writes outside extractDir → arbitrary write

// Safe extraction:
zip.getEntries().forEach(entry => {
  const entryPath = path.resolve(extractDir, entry.entryName);
  if (!entryPath.startsWith(extractDir + path.sep)) {
    throw new Error(`Zip slip: ${entry.entryName}`);
  }
  // Extract only if path is within extractDir
});
```

**CVE reference:** This class of vulnerability is called "Zip Slip" — well-documented, many libraries still vulnerable.

---

## Filesystem as Audit Target

```bash
# Find all fs module usage:
grep -rn "require('fs')\|require(\"fs\")\|fs/promises" \
  --include="*.js" . | grep -v node_modules

# Find readFileSync/writeFileSync with dynamic paths:
grep -rn "readFileSync\|writeFileSync\|createReadStream\|createWriteStream" \
  --include="*.js" . | grep -v "__dirname\|__filename\|app\.getPath\b\|node_modules" | head -30

# Find path.join without path.resolve + startsWith:
grep -rn "path\.join" --include="*.js" . -A 3 | \
  grep -v "node_modules\|startsWith\|resolve\b" | \
  grep "readFile\|writeFile\|require\|exec" | head -20

# Find archive extraction:
grep -rn "extractAllTo\|unzip\|extract\|decompress" \
  --include="*.js" . | grep -v node_modules

# Find fs.watch / chokidar (file watcher → source):
grep -rn "fs\.watch\|fs\.watchFile\|chokidar" --include="*.js" . | grep -v node_modules

# Find lstat/stat usage (check if symlink protection present):
grep -rn "lstatSync\|O_NOFOLLOW" --include="*.js" . | grep -v node_modules
```

---

## Filesystem Permissions Audit

Beyond the code, check actual filesystem permissions:

```bash
# Who can write to app resources? (macOS/Linux):
ls -la /Applications/MyApp.app/Contents/Resources/
find /Applications/MyApp.app -writable 2>/dev/null | grep -v ".Trash"

# Who can write to app data? (common misconfiguration):
# App writes config as root → makes it root-owned → user can't write → safe
# App writes config as user → user can modify → depends on what config does

# Check for world-writable files in app dir:
find /opt/myapp -perm -o+w -not -path "*/userData/*" 2>/dev/null

# Windows: check ACLs (PowerShell):
# Get-Acl "C:\Program Files\MyApp" | Select-Object -ExpandProperty Access
```

---

## Risk Matrix

| Attack | Requires | Impact |
|--------|----------|--------|
| Path traversal file read | IPC call | Arbitrary file read |
| Path traversal file write | IPC call | Arbitrary write → persistence |
| Symlink TOCTOU file read | Write to watched dir | Arbitrary file read |
| Archive extraction Zip Slip | Upload malicious ZIP | Arbitrary write |
| Config file injection | Write access to config | Code execution on app start |
| Startup folder write | Write + path traversal | Persistence on login |
| Native module replacement | Write to unpacked dir | Code execution |
