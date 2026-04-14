---
title: ASAR Extraction & Analysis
description: Complete workflow for extracting and analyzing Electron app.asar archives for security research
---

# ASAR Extraction & Analysis

Every Electron security assessment starts here. The ASAR is the app. Extract it, read it, understand what's in it — then you know your attack surface.

---

## Find and Extract

```bash
# Find app.asar:
find /Applications -name "app.asar" 2>/dev/null         # macOS
find "C:\Program Files" -name "app.asar" 2>/dev/null   # Windows
find /opt /usr -name "app.asar" 2>/dev/null             # Linux

# Check size — gives you a sense of code complexity:
ls -lh /Applications/Target.app/Contents/Resources/app.asar

# Extract (needs @electron/asar installed: npm install -g @electron/asar):
asar extract /Applications/Target.app/Contents/Resources/app.asar /tmp/target-app/
cd /tmp/target-app/
```

---

## Orient Yourself

Before reading any code in depth, figure out what you're working with:

```bash
# App name, version, and main entry point:
cat package.json | python3 -c "
import json, sys
p = json.load(sys.stdin)
print('Name:', p.get('name', 'unknown'))
print('Version:', p.get('version', 'unknown'))
print('Main:', p.get('main', 'index.js'))
"

# How many JS files are we dealing with (outside node_modules)?
find . -name "*.js" -not -path "*/node_modules/*" | wc -l

# Top-level structure:
ls -la

# Are there any minified/bundled files (makes reading harder)?
find . -name "*.js" -not -path "*/node_modules/*" -exec wc -c {} \; | \
  sort -n | tail -10
```

A small app (10-30 JS files) can be read end-to-end. A large app (200+ files) needs a more targeted approach — focus on main process and preloads first.

---

## The Fast Security Scan

This gets you an initial picture of the security configuration in a few seconds:

```bash
# BrowserWindow security settings:
echo "=== nodeIntegration ===" && \
  grep -rn "nodeIntegration" --include="*.js" . | grep -v node_modules
echo "=== contextIsolation ===" && \
  grep -rn "contextIsolation" --include="*.js" . | grep -v node_modules
echo "=== sandbox ===" && \
  grep -rn "\bsandbox\b" --include="*.js" . | grep -v node_modules | grep -v "//.*sandbox"
echo "=== webSecurity ===" && \
  grep -rn "webSecurity" --include="*.js" . | grep -v node_modules

# Preload scripts (find them all):
echo "=== preloads ===" && \
  grep -rn "preload:" --include="*.js" . | grep -v node_modules
```

What you're looking for:
- `nodeIntegration: true` → any XSS is RCE
- `contextIsolation: false` → XSS gets preload access
- `sandbox: false` → no OS-level restriction on renderer
- `webSecurity: false` → SOP/CORS disabled

---

## Map the IPC Surface

```bash
# All main process handlers (the attack surface):
grep -rn "ipcMain\.\(on\|handle\|once\)" --include="*.js" . | \
  grep -v node_modules | sort > /tmp/ipc_handlers.txt

echo "Total handlers: $(wc -l < /tmp/ipc_handlers.txt)"

# All contextBridge exposures (what the renderer can reach):
grep -rn "exposeInMainWorld" --include="*.js" . | grep -v node_modules

# All ipcRenderer.invoke calls (what the renderer actually calls):
grep -rn "ipcRenderer\.\(invoke\|send\|sendSync\)" --include="*.js" . | \
  grep -v node_modules
```

Save these to a file and review. You're looking for IPC handlers that call dangerous operations and that are reachable through the contextBridge surface.

---

## Find the Dangerous Operations

```bash
# RCE sinks:
echo "=== exec/spawn ===" && \
  grep -rn "\.exec\b\|\.execSync\|\.spawn\b\|\.spawnSync\|new Function\|\beval\b" \
    --include="*.js" . | grep -v node_modules

# HTML injection sinks:
echo "=== innerHTML ===" && \
  grep -rn "\.innerHTML\b\|\.outerHTML\b\|insertAdjacentHTML\|document\.write" \
    --include="*.js" . | grep -v node_modules

# Navigation sinks:
echo "=== openExternal/loadURL ===" && \
  grep -rn "shell\.openExternal\|\.loadURL\b\|window\.open\b" \
    --include="*.js" . | grep -v node_modules

# File system sinks:
echo "=== writeFile ===" && \
  grep -rn "fs\.writeFile\|writeFileSync\|createWriteStream" \
    --include="*.js" . | grep -v node_modules
```

The intersection of "callable via IPC from renderer" and "calls a dangerous operation" is your finding list.

---

## Check What's Outside the ASAR

```bash
# Files outside ASAR integrity checking:
ls -la /Applications/Target.app/Contents/Resources/app.asar.unpacked/ 2>/dev/null || \
  echo "No unpacked directory"

# Native modules (never integrity-checked, run outside V8 sandbox):
find /Applications/Target.app -name "*.node" 2>/dev/null

# V8 snapshot files (loaded before ASAR integrity check):
find /Applications/Target.app -name "*.bin" -o -name "*snapshot*" 2>/dev/null | \
  grep -v ".pyc"
```

Anything in `app.asar.unpacked/` bypasses integrity validation. If you find `.node` files there, those are modifiable without triggering the ASAR integrity check.

---

## Automated Scan with Electronegativity

```bash
# Electronegativity flags common misconfigs and dangerous patterns:
electronegativity -i /tmp/target-app/ -o /tmp/en_report.csv 2>/dev/null

# Filter for high-severity findings:
cat /tmp/en_report.csv | awk -F',' '$4 == "ERROR" {print $0}' | head -20
```

Electronegativity is useful for quick coverage but has false positive rates. Use it to generate a starting list, not as the final word.

---

## The Analysis Workflow

Run through this in order on a fresh target:

```
1. asar extract → get the source
2. cat package.json → find main entry point, version
3. Read main.js → find all BrowserWindow configs → note security settings
4. Find and read all preload scripts → note bridge API surface
5. grep for ipcMain handlers → list all channels
6. grep for dangerous sinks → cross-reference with IPC handlers
7. grep for HTML injection sinks → find XSS candidates
8. grep for data sources (fetch, WebSocket, ipcRenderer.on) → trace to sinks
9. Electronegativity scan → catches anything obvious you missed
10. For each high-signal finding: read the full handler, trace source → sink
```

The goal at the end of this is a ranked list of candidate vulnerabilities, prioritized by: severity of the operation (exec > openExternal > writeFile > readFile > HTML injection), and likelihood that attacker-controlled data reaches it.
