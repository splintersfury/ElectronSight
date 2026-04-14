---
title: Update Poisoning
description: Compromising Electron auto-update mechanisms — electron-updater misconfigs, CVE-2024-46992, and MitM delivery
---

# Update Poisoning

The auto-updater is one of the highest-impact attack surfaces in any Electron app, and it's often one of the least scrutinized. A compromised update mechanism gives you code execution on every machine that has the app installed — not as a post-exploitation step, but as the initial access. The update itself is the payload.

What makes this interesting from a bug bounty perspective: you don't usually need to compromise the update server to demonstrate impact. Misconfigurations alone — HTTP instead of HTTPS, missing signature verification, path traversal in the YAML filename — can be demonstrated without touching any live infrastructure.

---

## How Electron Auto-Update Works

```
App startup
  ├─ App polls update server: GET /latest.yml
  ├─ Server returns version info + download URL + SHA512 hash
  ├─ App downloads the update package
  ├─ App verifies SHA512 hash (and maybe code signature)
  └─ App installs the update (replaces app.asar or runs installer)
```

The security story is almost entirely in steps 4 and 5. If verification is missing, weak, or bypassable — that's the bug.

---

## electron-updater: What Most Apps Use

```javascript
// main.js:
const { autoUpdater } = require('electron-updater');

autoUpdater.setFeedURL('https://updates.myapp.com/');
autoUpdater.checkForUpdatesAndNotify();
```

The update server serves a YAML file — `latest.yml` on Windows, `latest-mac.yml` on macOS:

```yaml
version: 2.5.0
files:
  - url: MyApp-Setup-2.5.0.exe
    sha512: BASE64_HASH_HERE
    size: 87654321
path: MyApp-Setup-2.5.0.exe
sha512: BASE64_HASH_HERE
releaseDate: '2026-01-15T00:00:00.000Z'
```

electron-updater downloads the file and verifies the SHA512 before installing. This sounds robust. The failure modes are in the gaps around that verification.

---

## Vulnerability 1: HTTP Update Server

```javascript
// VULNERABLE:
autoUpdater.setFeedURL('http://updates.myapp.com/');
```

HTTP means no transport security. A MitM attacker on the same network (coffee shop, corporate network, ISP) intercepts the YAML request and replaces the response. They point to their own malicious installer, provide a valid SHA512 for it, and electron-updater happily downloads and installs it.

electron-updater doesn't reject HTTP by default. This shows up in enterprise apps deployed internally over HTTP more often than you'd expect. Check the feed URL in both the code and in `electron-builder.yml`.

---

## Vulnerability 2: CVE-2024-46992 — Path Traversal in electron-updater

This one is elegant. The `path` field in `latest.yml` controls the filename used when downloading the update. Before the fix, electron-updater used this value directly without stripping directory components:

```yaml
# Attacker-controlled latest.yml:
version: 2.5.0
path: ../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.exe
sha512: VALID_SHA512_OF_MALICIOUS_EXE
```

electron-updater downloads the file at the SHA512-verified URL and writes it to `path` relative to the update cache directory. Because `path` isn't sanitized, it traverses up and lands in the Windows startup folder.

Next time Windows boots, it executes `evil.exe` as the user. The app "failed to update" — so the user doesn't even notice the update happened.

**Fix:** electron-updater now runs the `path` field through `path.basename()` before using it as a filename. If you're auditing an app, check:

```bash
cat node_modules/electron-updater/package.json | grep '"version"'
# Versions before the 2024 patch are vulnerable
```

---

## Vulnerability 3: SHA512 Verification Is Only as Good as the YAML Source

This is a conceptual gap that's worth understanding. If an attacker controls the update server (MitM or actual server compromise), they control both the YAML and the binary. They can provide:

```yaml
version: 2.5.0
path: MyApp-Setup-2.5.0.exe
sha512: SHA512_OF_THEIR_MALICIOUS_EXE  # valid — they computed it
```

The SHA512 check passes. The installer is "verified." electron-updater runs it.

SHA512 verification prevents corruption in transit — it doesn't provide authenticity guarantees when the hash itself can be replaced. Authenticity requires code signing (Authenticode on Windows, Apple Developer ID on macOS) checked against a trusted certificate chain.

---

## Vulnerability 4: No Code Signature Verification

```javascript
// electron-builder.yml — MISSING signature config:
publish:
  provider: generic
  url: https://updates.myapp.com/
  # No publisherName → no Authenticode verification on Windows
```

Without `publisherName` in the electron-builder config, Windows Authenticode checking isn't enforced. An attacker controlling the YAML can substitute any binary, as long as the SHA512 matches.

The correct configuration:

```yaml
# electron-builder.yml:
win:
  publisherName: "MyApp, Inc."  # Enforces Authenticode signer match
publish:
  provider: github
  releaseType: release
```

---

## Vulnerability 5: Downgrade Attacks

electron-updater installs whatever version the server says is "latest." If the server says the latest version is 1.0.0 (an old vulnerable version), and the app trusts that, it will downgrade to 1.0.0:

```yaml
# Attacker-controlled latest.yml:
version: 1.0.0   # old version with known vulnerabilities
path: MyApp-Setup-1.0.0.exe
sha512: VALID_HASH_OF_v1.0.0_INSTALLER
```

The old installer is legitimately signed — it was the real version 1.0.0. Signature verification passes. The downgrade proceeds. The attacker then exploits whatever vulnerability existed in 1.0.0.

No minimum version enforcement is the default. This is reportable when combined with a known vulnerability in older versions.

---

## Vulnerability 6: Release Notes XSS

This one often gets overlooked. electron-updater receives `releaseNotes` from the YAML and makes it available to the app. If the app renders release notes as HTML:

```javascript
// renderer.js — VULNERABLE:
autoUpdater.on('update-available', (info) => {
  releaseNotesDiv.innerHTML = info.releaseNotes;  // XSS if notes contain HTML
});
```

And the update server is compromised or uses HTTP, the attacker controls `releaseNotes` and gets XSS in the renderer. If the renderer has an escalation path (over-privileged IPC handlers, `nodeIntegration: true`), release notes XSS becomes update-triggered RCE.

---

## Auditing the Update Mechanism

```bash
# Find update configuration:
grep -rn "setFeedURL\|autoUpdater\|checkForUpdates\|electron-updater" \
  --include="*.js" . | grep -v node_modules

# Check electron-builder.yml for publish config:
cat electron-builder.yml | grep -A 15 "publish:"

# Check for HTTP (not HTTPS):
grep -r "http://" package.json electron-builder.yml *.yml 2>/dev/null | grep -i update

# Check for signature verification:
grep -r "publisherName\|verifyUpdateCodeSignature\|allowDowngrade" \
  --include="*.js" --include="*.yml" . | grep -v node_modules

# electron-updater version check:
cat node_modules/electron-updater/package.json 2>/dev/null | grep '"version"'

# Release notes rendering:
grep -rn "releaseNotes\|release_notes\|changelog" --include="*.js" . -A 3 | \
  grep -E "innerHTML|dangerouslySetInnerHTML" | grep -v node_modules
```

---

## Secure Update Configuration

```javascript
// main.js:
const { autoUpdater } = require('electron-updater');

autoUpdater.logger = require('electron-log');

autoUpdater.setFeedURL({
  provider: 'generic',
  url: 'https://updates.myapp.com/',  // HTTPS required
  channel: 'latest'
});

// Handle release notes safely:
autoUpdater.on('update-available', (info) => {
  // Don't use innerHTML with release notes — use textContent:
  releaseNotesEl.textContent = info.releaseName || 'Update available';
});

autoUpdater.checkForUpdatesAndNotify();
```

```yaml
# electron-builder.yml:
win:
  publisherName: "MyApp, Inc."  # Authenticode enforcement

publish:
  provider: github
  releaseType: release
  # GitHub Releases: binaries served over HTTPS from GitHub's CDN
  # Attacker can't substitute their own binary without compromising the release
```

The gold standard is GitHub Releases or a similar CDN with immutable release artifacts. Even if an attacker finds YAML injection, they can't substitute a binary at a GitHub Release URL.
