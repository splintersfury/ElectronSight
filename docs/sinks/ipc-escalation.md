---
title: IPC Escalation Sinks
description: IPC channels that perform privileged operations — the primary post-XSS escalation path in Electron
---

# IPC Escalation Sinks

IPC escalation sinks are `ipcMain` handlers that perform privileged operations — file system access, command execution, URL opening — on behalf of renderers. When a renderer is compromised (via XSS), these handlers are the path to escalating renderer-level access to main-process capabilities.

---

## The Escalation Model

```
Renderer compromise (XSS)
         │
         │ ipcRenderer.invoke('privileged-channel', attacker_data)
         ▼
ipcMain handler (main process, no sandbox)
         │
         │ exec(attacker_data) / fs.writeFile(attacker_data) / shell.openExternal(attacker_data)
         ▼
OS-level impact (RCE, arbitrary file access)
```

The IPC layer is the **privilege boundary** between the sandboxed renderer and the main process with full OS access.

---

## High-Risk Handler Patterns

### Execute-Command Handlers

```javascript
// Highest risk — any variation of this:
ipcMain.handle('execute', async (event, command) => {
  return exec(command);  // RCE
});

ipcMain.handle('run-script', async (event, script) => {
  return exec(`node -e "${script}"`);  // Shell injection + RCE
});

ipcMain.handle('build-project', async (event, config) => {
  return exec(`npm run ${config.script}`);  // config.script injection
});
```

### File Operation Handlers

```javascript
// Arbitrary write:
ipcMain.handle('write-file', async (event, path, content) => {
  fs.writeFileSync(path, content);  // path traversal → arbitrary write
});

// Arbitrary read:
ipcMain.handle('read-file', async (event, path) => {
  return fs.readFileSync(path, 'utf8');  // path traversal → arbitrary read
});
```

### Navigation Handlers

```javascript
// Protocol handler abuse:
ipcMain.on('open-url', (event, url) => {
  shell.openExternal(url);  // url = 'ms-msdt://...' → RCE
});

// Window loading:
ipcMain.on('navigate', (event, url) => {
  win.loadURL(url);  // url = 'file:///malicious.html' → load local content
});
```

---

## Finding IPC Escalation Sinks

```bash
# Find all IPC handlers that call dangerous operations:
grep -r "ipcMain\.\(on\|handle\)" --include="*.js" . -A 20 | \
  grep -E "exec\b|spawn\b|execSync|execFile|fork\b|eval\b|openExternal|readFileSync|writeFileSync|\.readFile|\.writeFile|shell\." | \
  grep -v node_modules

# More focused: handlers within 10 lines of exec():
grep -r "exec\s*(\|exec\s*(\`" --include="*.js" . | grep -v node_modules | \
  while IFS=: read file line rest; do
    # Check if an ipcMain handler is within 20 lines above:
    start=$((line - 20))
    if [ $start -lt 1 ]; then start=1; fi
    sed -n "${start},${line}p" "$file" | grep -q "ipcMain\." && \
      echo "POSSIBLE IPC→exec: $file:$line: $rest"
  done
```

---

## Auditing Each Handler

For each high-risk handler found:

1. **What data comes from the renderer?** (the arguments to the handler)
2. **Is `event.sender.getURL()` or `event.senderFrame.url` checked?** (sender validation)
3. **Is the data validated before use?** (input validation)
4. **Is the operation reversible?** (impact assessment)
5. **Can I reach this from a compromised renderer?** (exploitability)

---

## Example Audit Output

```markdown
## IPC Sink: 'run-converter' (HIGH RISK)

**Location:** src/converter.js:45
**Handler:**
```javascript
ipcMain.handle('run-converter', async (event, inputPath, codec) => {
  const cmd = `ffmpeg -i "${inputPath}" -c:v ${codec} /tmp/output.mp4`;
  return exec(cmd);
});
```

**Issues:**
1. No sender validation — any renderer can call this
2. `inputPath` used in shell command string → injection via `"` character
3. `codec` interpolated directly → `codec = 'libx264; calc.exe; echo'` → RCE

**PoC:** `window.api.convert('"; calc.exe; echo "', 'mp3')`

**Impact:** RCE as the app user
```
