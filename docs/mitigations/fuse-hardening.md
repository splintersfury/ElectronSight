---
title: Fuse Hardening
description: Disabling dangerous Electron fuses at build time — electron-builder integration and complete reference
---

# Fuse Hardening

Fuses are the simplest security improvement you can make to an Electron app that you're building. One build-time configuration, applied during packaging, permanently disables attack vectors that otherwise require runtime code to mitigate. The fuse audit command takes five seconds. The fix takes ten minutes. Most apps haven't done it.

If you're assessing an app (not building one), see the [Fuse Auditing guide](../guides/fuse-auditing.md) and the [Fuse Misconfiguration vulnerability class](../vuln-classes/fuse-misconfig.md).

---

## electron-builder Integration

The cleanest approach: configure fuses in an `afterPack` script called by electron-builder after the app is packaged.

```javascript
// afterPack.js
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');
const path = require('path');

module.exports = async function afterPack(context) {
  const { electronPlatformName, appOutDir, packager } = context;
  
  let electronPath;
  
  if (electronPlatformName === 'darwin') {
    electronPath = path.join(
      appOutDir,
      `${packager.appInfo.productFilename}.app`,
      'Contents',
      'MacOS',
      packager.appInfo.productFilename
    );
  } else if (electronPlatformName === 'win32') {
    electronPath = path.join(appOutDir, `${packager.appInfo.productFilename}.exe`);
  } else {
    electronPath = path.join(appOutDir, packager.appInfo.productFilename);
  }
  
  console.log('Applying security fuses to:', electronPath);
  
  await flipFuses(electronPath, {
    version: FuseVersion.V1,
    
    // === DISABLE DANGEROUS FEATURES ===
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
    
    // === ENABLE SECURITY FEATURES ===
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
  });
  
  console.log('Fuses applied successfully');
};
```

Reference in `electron-builder.yml`:
```yaml
afterPack: scripts/afterPack.js
```

---

## CI Verification

Don't just apply fuses — verify them in CI. If the afterPack script silently fails, you'll ship a build with dangerous defaults and not know it.

```javascript
// package.json build script:
{
  "scripts": {
    "build": "electron-builder && node scripts/verify-fuses.js"
  }
}

// scripts/verify-fuses.js — CI verification:
const { readFuses } = require('@electron/fuses');

async function verify() {
  const appPath = process.argv[2] || './dist/mac/MyApp.app';
  const fuses = await readFuses(appPath);
  
  const required = {
    RunAsNode: false,
    EnableNodeOptionsEnvironmentVariable: false,
    EnableNodeCliInspectArguments: false,
    EnableEmbeddedAsarIntegrityValidation: true,
    OnlyLoadAppFromAsar: true,
  };
  
  let failed = false;
  for (const [fuse, expectedValue] of Object.entries(required)) {
    if (fuses[fuse] !== expectedValue) {
      console.error(`FUSE MISMATCH: ${fuse} is ${fuses[fuse]}, expected ${expectedValue}`);
      failed = true;
    }
  }
  
  if (failed) {
    process.exit(1);  // Fail the build
  } else {
    console.log('All fuses correctly configured');
  }
}

verify().catch(e => { console.error(e); process.exit(1); });
```

A CI check that fails the build on fuse misconfiguration means no one accidentally ships without them.

---

## ASAR Integrity Setup

Enabling `EnableEmbeddedAsarIntegrityValidation` requires generating integrity hashes at build time:

```yaml
# electron-builder.yml:
asarIntegrity: true   # Generates and embeds ASAR hashes at build time
```

This configuration:
1. Computes SHA256 hashes for all files inside `app.asar` during packaging
2. Embeds those hashes in the Electron binary
3. At runtime, the `EnableEmbeddedAsarIntegrityValidation` fuse causes Electron to verify the ASAR contents against those embedded hashes

Note: ASAR integrity does NOT cover `app.asar.unpacked/` or V8 snapshot files. See [CVE-2025-55305](../cves/CVE-2025-55305.md) for what that gap enables. If your app relies on ASAR integrity as a security boundary, audit whether snapshot files and unpacked natives are also covered independently.

---

## Fuse Reference Card

| Fuse | Set To | What It Prevents |
|------|--------|-----------------|
| RunAsNode | `false` | `ELECTRON_RUN_AS_NODE=1` code execution |
| NodeOptions | `false` | `NODE_OPTIONS=--require /evil.js` injection |
| NodeCliInspect | `false` | `--inspect=9229` debug port opening |
| CookieEncryption | `true` | Session cookies readable from disk |
| AsarIntegrity | `true` | ASAR tamper without detection |
| OnlyLoadAppFromAsar | `true` | Directory fallback when ASAR renamed |
| FileProtocolPrivileges | `false` | Elevated file:// trust from path traversal |

---

## Verification After Build

```bash
# Verify fuses were applied correctly:
npx @electron/fuses read --app dist/mac/MyApp.app

# Expected output:
# RunAsNode is Disabled             ← good
# EnableCookieEncryption is Enabled  ← good
# EnableNodeOptionsEnvironmentVariable is Disabled ← good
# EnableNodeCliInspectArguments is Disabled ← good
# EnableEmbeddedAsarIntegrityValidation is Enabled ← good
# OnlyLoadAppFromAsar is Enabled ← good
# GrantFileProtocolExtraPrivileges is Disabled ← good
```

Any "Enabled" on the first three or "Disabled" on the last four is a misconfiguration to fix before shipping.
