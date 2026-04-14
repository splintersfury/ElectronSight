---
title: asar CLI
description: Extracting, listing, and creating Electron ASAR archives for security research
---

# asar CLI

The `@electron/asar` CLI is the primary tool for working with Electron's ASAR archive format. For security research, it's the first tool to run on any Electron app — extraction gives you full JavaScript source access.

---

## Installation

```bash
npm install -g @electron/asar

# Verify:
asar --version
```

---

## Core Operations

### Extract (most common for research)

```bash
# Extract entire archive to directory:
asar extract app.asar /tmp/extracted/

# Extract to current directory (creates app/ folder):
asar extract app.asar .

# Extract a single file:
asar extract-file app.asar main.js
asar extract-file app.asar package.json
```

### List Contents

```bash
# List all files:
asar list app.asar

# With file sizes:
asar list app.asar | head -50

# Find specific files:
asar list app.asar | grep -E "preload|ipc|main"
```

### Create Archive (for tampering testing)

```bash
# After modifying extracted files:
asar pack /tmp/extracted/ /tmp/modified.asar

# Replace original (DANGEROUS — backup first!):
cp app.asar app.asar.bak
cp /tmp/modified.asar app.asar
```

---

## Finding app.asar

```bash
# Windows:
%LOCALAPPDATA%\Programs\<AppName>\resources\app.asar
%ProgramFiles%\<AppName>\resources\app.asar

# macOS:
/Applications/<AppName>.app/Contents/Resources/app.asar

# Linux:
/opt/<appname>/resources/app.asar
/usr/lib/<appname>/resources/app.asar
find / -name "app.asar" 2>/dev/null

# Snap packages (Linux):
/snap/<appname>/current/resources/app.asar
```

---

## Post-Extraction Research Workflow

```bash
# After: asar extract app.asar /tmp/app/
cd /tmp/app/

# 1. Find the entry point:
cat package.json | python3 -c "import json,sys; p=json.load(sys.stdin); print(p.get('main','index.js'))"

# 2. Find all preload scripts:
grep -r "preload:" --include="*.js" . | grep -v node_modules

# 3. Find all BrowserWindow configs:
grep -r "new BrowserWindow\|webPreferences" --include="*.js" . -A 10 | head -100

# 4. Find security misconfigs:
grep -r "nodeIntegration.*true\|contextIsolation.*false\|webSecurity.*false\|sandbox.*false" \
  --include="*.js" .

# 5. Find IPC handlers:
grep -r "ipcMain\.\(on\|handle\)" --include="*.js" . | grep -v node_modules

# 6. Find contextBridge exposures:
grep -r "exposeInMainWorld" --include="*.js" . -A 20 | grep -v node_modules

# 7. Find dangerous sinks:
grep -r "\.exec\b\|\.spawn\b\|child_process\|eval\b\|innerHTML\|shell\.openExternal" \
  --include="*.js" . | grep -v node_modules | grep -v "//.*eval"

# 8. Run Electronegativity:
electronegativity -i . -o /tmp/report.csv
```

---

## ASAR Integrity Verification

If the app uses ASAR integrity validation:

```bash
# Check fuse state:
npx @electron/fuses read --app /path/to/app

# If EnableEmbeddedAsarIntegrityValidation is Enabled:
# The app validates app.asar against embedded hashes
# Tampering with app.asar will be detected
# BUT: files in app.asar.unpacked/ are not validated
```

---

## app.asar.unpacked

Some files live outside the ASAR:

```bash
# Find unpacked files:
ls /path/to/app/resources/app.asar.unpacked/

# Common unpacked files:
# - Native .node addons
# - Large binary assets
# - FFmpeg/media codecs
# These are NOT covered by ASAR integrity validation
```

---

## Programmatic Access

For scripted analysis:

```javascript
const asar = require('@electron/asar');

// List all files:
const files = asar.listPackage('app.asar');
files.forEach(f => console.log(f));

// Read a file from ASAR without full extraction:
const content = asar.extractFile('app.asar', 'main.js');
console.log(content.toString('utf8'));

// Get header (file index):
const header = JSON.parse(
  asar.getRawHeader('app.asar').header
);
```

This enables scripted analysis of ASAR contents without needing full disk extraction.
