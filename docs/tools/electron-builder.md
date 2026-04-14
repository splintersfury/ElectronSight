---
title: electron-builder
description: Auditing electron-builder configuration for security issues — update signing, ASAR settings, fuses
---

# electron-builder Security Audit

`electron-builder` is the most popular Electron app packaging tool. Its configuration file (`electron-builder.yml` or `build` section in `package.json`) contains security-critical settings. When you have access to an app's source, auditing this configuration reveals its security posture.

---

## Configuration File Locations

```bash
# Check for electron-builder config:
cat electron-builder.yml
cat electron-builder.json
cat package.json | python3 -c "import json,sys; p=json.load(sys.stdin); print(json.dumps(p.get('build', {}), indent=2))"
```

---

## Security-Relevant Settings

### ASAR Configuration

```yaml
# electron-builder.yml

# ASAR enabled (should be true):
asar: true          # ✅ enables ASAR packaging
asar: false         # ❌ app is just a directory — no archive protection at all

# Files excluded from ASAR (not integrity-checked):
asarUnpack:
  - "**/*.node"     # native modules — always unpacked
  - "ffmpeg.dll"    # media libs — always unpacked
  # Everything listed here is outside integrity validation
```

### Code Signing (Windows)

```yaml
win:
  publisherName: "MyApp Corp"   # ✅ enforces Authenticode signer on updates
  # OR:
  certificateFile: cert.pfx
  certificatePassword: "${WIN_CERT_PASSWORD}"
  
  # No publisherName → electron-updater won't verify publisher on downloads
```

### Code Signing (macOS)

```yaml
mac:
  identity: "Developer ID Application: MyApp Corp (TEAMID)"   # ✅
  hardenedRuntime: true     # ✅ enables hardened runtime
  gatekeeperAssess: false   # (build machine may not have network for Gatekeeper)
  entitlements: entitlements.plist
  entitlementsInherit: entitlements.plist
```

**Entitlements to watch:**

```xml
<!-- entitlements.plist — dangerous if present: -->
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<!-- Allows loading unsigned dylibs — DLL hijacking risk -->

<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<!-- Allows JIT / unsigned code execution — weakens Hardened Runtime -->
```

### Update Configuration

```yaml
publish:
  provider: github          # ✅ GitHub Releases — trusted CDN + GitHub signature
  releaseType: release
  
  # OR:
  provider: generic
  url: https://updates.myapp.com/   # ✅ HTTPS
  # url: http://...                 # ❌ HTTP — MitM possible

  # Dangerous: no signature verification
  # electron-updater uses SHA512 from latest.yml
  # But if the YAML server is compromised, SHA512 is also compromised
  # → Need: code-signing + SHA512
```

### Fuse Configuration

```yaml
electronFuses:
  runAsNode: false                          # ✅
  enableCookieEncryption: true             # ✅
  enableNodeOptionsEnvironmentVariable: false  # ✅
  enableNodeCliInspectArguments: false     # ✅
  enableEmbeddedAsarIntegrityValidation: true  # ✅
  onlyLoadAppFromAsar: true                # ✅
  grantFileProtocolExtraPrivileges: false  # ✅
```

If `electronFuses` section is absent → all dangerous fuses are at Electron defaults (most enabled).

---

## Complete Security Audit Checklist

```bash
# For each field, note whether it's present and secure:

# 1. ASAR enabled?
grep "asar:" electron-builder.yml

# 2. asarUnpack contents (what's outside integrity):
grep -A 10 "asarUnpack:" electron-builder.yml

# 3. Update provider (HTTP? Signed?):
grep -A 5 "publish:" electron-builder.yml

# 4. Windows publisherName (signature enforcement):
grep "publisherName" electron-builder.yml

# 5. macOS hardenedRuntime:
grep "hardenedRuntime" electron-builder.yml

# 6. macOS entitlements (check for dangerous ones):
cat entitlements.plist 2>/dev/null | grep -A 1 "disable-library\|allow-unsigned"

# 7. Fuse configuration:
grep -A 20 "electronFuses:" electron-builder.yml

# 8. electron-updater version (for known CVEs):
cat node_modules/electron-updater/package.json | grep '"version"'
```

---

## Common Misconfigurations

| Setting | Vulnerable | Secure |
|---------|-----------|--------|
| `asar` | `false` | `true` |
| `publish.url` | `http://...` | `https://...` |
| `win.publisherName` | absent | present |
| `mac.hardenedRuntime` | absent/false | `true` |
| `electronFuses.runAsNode` | `true` | `false` |
| `electronFuses.enableEmbeddedAsarIntegrityValidation` | absent/false | `true` |
| macOS entitlement `disable-library-validation` | present | absent |
