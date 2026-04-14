---
title: File System Sinks
description: Arbitrary file read/write sinks in Electron — path traversal, symlink abuse, and config injection
---

# File System Sinks

File system sinks are Node.js `fs` module operations that, when fed attacker-controlled paths or data, result in unauthorized file access. In the main process or a renderer with `nodeIntegration: true`, the full `fs` module is available.

---

## Arbitrary File Read

Reading files at attacker-controlled paths leaks sensitive data:

```javascript
const fs = require('fs');

// VULNERABLE — no path validation:
ipcMain.handle('read-config', async (event, configName) => {
  return fs.readFileSync(`/app/configs/${configName}`, 'utf8');
  // configName = '../../etc/passwd' → reads /etc/passwd
  // configName = '../../../.ssh/id_rsa' → reads SSH private key
});
```

### High-Value File Targets

On macOS/Linux:
```
/etc/passwd              — user list
~/.ssh/id_rsa            — SSH private key
~/.aws/credentials       — AWS credentials
~/.config/              — various app configs
~/.gnupg/               — PGP keys
~/Library/Keychains/    — macOS keychain
```

On Windows:
```
C:\Users\<user>\AppData\Roaming\   — app data (browser profiles, tokens)
C:\Windows\System32\drivers\etc\hosts — hosts file
%APPDATA%\Mozilla\Firefox\Profiles\ — Firefox session data
```

---

## Arbitrary File Write

Writing to attacker-controlled paths enables:
- **Persistence** — write to startup locations
- **DLL/dylib planting** — write to paths where apps search for libraries
- **Config injection** — overwrite app configuration

```javascript
// VULNERABLE — attacker controls path:
ipcMain.handle('save-file', async (event, filePath, content) => {
  fs.writeFileSync(filePath, content);
  // filePath = 'C:\\Windows\\System32\\cmd.exe' → overwrites system binary (if admin)
  // filePath = '~/.bashrc' → persistence via shell profile
  // filePath = '/etc/cron.d/evil' → cron persistence
});

// VULNERABLE — controlled filename in fixed directory:
ipcMain.handle('save-log', async (event, filename, data) => {
  const p = path.join('/var/log/app/', filename);
  fs.writeFileSync(p, data);
  // filename = '../../../etc/cron.d/evil' → still escapes
});
```

---

## Path Traversal

The core vulnerability in most file system sinks:

```javascript
// Naive fix attempt — STILL VULNERABLE:
function safeRead(userPath) {
  const fullPath = path.join('/app/data/', userPath);
  // path.join normalizes but doesn't prevent traversal:
  // path.join('/app/data/', '../../../etc/passwd') = '/etc/passwd'
  return fs.readFileSync(fullPath, 'utf8');
}

// Safe fix — check after resolving:
function safeRead(userPath) {
  const baseDir = '/app/data/';
  const fullPath = path.resolve(baseDir, userPath);
  
  if (!fullPath.startsWith(path.resolve(baseDir))) {
    throw new Error('Access denied: path traversal detected');
  }
  
  return fs.readFileSync(fullPath, 'utf8');
}
```

**Note:** `path.join` does NOT prevent traversal — it just normalizes separators. `path.resolve` + startsWith check is the correct pattern.

---

## Symlink Attacks (TOCTOU)

A symlink at a trusted path pointing to a sensitive target:

```javascript
// "Safe" code that checks the path — VULNERABLE to symlink race:
async function safeWrite(userPath, data) {
  const fullPath = path.resolve('/app/safe-dir/', userPath);
  
  // Check: path must be inside safe-dir
  if (!fullPath.startsWith('/app/safe-dir/')) throw new Error('denied');
  
  // TOCTOU: between check and write, attacker can:
  // rm /app/safe-dir/file.txt
  // ln -s /etc/cron.d/persistence /app/safe-dir/file.txt
  
  await fs.promises.writeFile(fullPath, data);  // writes to /etc/cron.d/persistence
}
```

**Mitigation:** Use `O_NOFOLLOW` flag (not directly available in Node.js fs, requires custom native addon or `fs.lstat` + handle check).

---

## fs.unlink / fs.rename — Arbitrary Deletion/Move

```javascript
// Arbitrary file deletion:
ipcMain.handle('delete-file', async (event, filePath) => {
  await fs.promises.unlink(filePath);  // attacker controls filePath
  // Can delete system files, user data, security tools
});

// Arbitrary file move (rename):
ipcMain.handle('move-file', async (event, src, dest) => {
  await fs.promises.rename(src, dest);
  // src → dest can move malware into trusted locations
});
```

---

## Config File Injection

Many Electron apps store configuration in JSON/TOML/YAML files. If an attacker can write to the config file, they can inject arbitrary values:

```javascript
// App reads config on startup:
const config = JSON.parse(fs.readFileSync('./app-config.json'));
exec(config.startupScript);  // attacker modified startupScript in config

// Or via update mechanism:
electron-updater reads package.json from a server response
// If server is compromised, package.json → "main": "/tmp/malicious.js"
```

---

## Grep Patterns

```bash
# File read operations:
grep -rn "fs\.readFile\|fs\.readFileSync\|fs\.promises\.readFile\|createReadStream" \
  --include="*.js" . | grep -v node_modules

# File write operations:
grep -rn "fs\.writeFile\|fs\.writeFileSync\|fs\.appendFile\|createWriteStream" \
  --include="*.js" . | grep -v node_modules

# File delete/move:
grep -rn "fs\.unlink\|fs\.rename\|fs\.rmdir\|fs\.rm\b" --include="*.js" . | grep -v node_modules

# Path manipulation (check if sanitized):
grep -rn "path\.join\|path\.resolve\|path\.normalize" --include="*.js" . | grep -v node_modules

# IPC handlers that touch the filesystem:
grep -A 20 "ipcMain\.\(on\|handle\)" --include="*.js" -r . | \
  grep -E "readFile|writeFile|unlink|path\.join" | grep -v node_modules
```
