---
title: "@electron/fuses"
description: Reading and writing Electron fuse states — audit and configure binary-level security flags
---

# @electron/fuses

The `@electron/fuses` npm package provides tooling to read and write Electron's binary-level feature flags (fuses). For security researchers, it's the tool to audit whether dangerous features are enabled in a shipping app.

---

## Installation

```bash
# For reading fuse state (research):
npm install -g @electron/fuses

# As a dev dependency (for build-time configuration):
npm install --save-dev @electron/fuses
```

---

## Reading Fuse State (Research)

```bash
# Read fuse state from an installed app:
npx @electron/fuses read --app /Applications/Discord.app

# Example output:
# Electron Fuses: v1.0.0
# RunAsNode is Enabled
# EnableCookieEncryption is Disabled
# EnableNodeOptionsEnvironmentVariable is Enabled
# EnableNodeCliInspectArguments is Enabled
# EnableEmbeddedAsarIntegrityValidation is Disabled
# OnlyLoadAppFromAsar is Disabled
# LoadBrowserProcessSpecificV8Snapshot is Disabled
# GrantFileProtocolExtraPrivileges is Enabled
```

### What the Output Tells You

| Fuse | Enabled = Risk? |
|------|----------------|
| `RunAsNode` | Yes — allows arbitrary Node.js execution |
| `EnableCookieEncryption` | Disabled = risk (cookies stored plaintext) |
| `EnableNodeOptionsEnvironmentVariable` | Yes — NODE_OPTIONS injection |
| `EnableNodeCliInspectArguments` | Yes — debugger attachment |
| `EnableEmbeddedAsarIntegrityValidation` | Disabled = risk (no ASAR check) |
| `OnlyLoadAppFromAsar` | Disabled = risk (directory fallback) |
| `GrantFileProtocolExtraPrivileges` | Enabled = risk (file:// gets extra trust) |

---

## Programmatic Fuse Reading

```javascript
const { readFuses } = require('@electron/fuses');
const path = require('path');

async function auditFuses(appPath) {
  const fuses = await readFuses(appPath);
  
  const risks = [];
  
  if (fuses.RunAsNode) risks.push('RunAsNode enabled — arbitrary Node.js via ELECTRON_RUN_AS_NODE');
  if (!fuses.EnableCookieEncryption) risks.push('Cookie encryption disabled — cookies stored plaintext');
  if (fuses.EnableNodeOptionsEnvironmentVariable) risks.push('NODE_OPTIONS honored — code injection via env');
  if (fuses.EnableNodeCliInspectArguments) risks.push('--inspect honored — debugger attachment');
  if (!fuses.EnableEmbeddedAsarIntegrityValidation) risks.push('No ASAR integrity — tamper undetected');
  if (!fuses.OnlyLoadAppFromAsar) risks.push('Directory fallback — ASAR bypass possible');
  if (fuses.GrantFileProtocolExtraPrivileges) risks.push('file:// gets elevated trust');
  
  return risks;
}

auditFuses('/Applications/Discord.app').then(risks => {
  if (risks.length === 0) console.log('All fuses properly configured');
  else risks.forEach(r => console.log('⚠️', r));
});
```

---

## Writing Fuses (Build Time)

```javascript
// In your app's build script (NOT at runtime):
const { flipFuses, FuseV1Options, FuseVersion } = require('@electron/fuses');
const path = require('path');
const { execSync } = require('child_process');

const electronPath = require('electron');

await flipFuses(electronPath, {
  version: FuseVersion.V1,
  [FuseV1Options.RunAsNode]: false,                          // Disable ELECTRON_RUN_AS_NODE
  [FuseV1Options.EnableCookieEncryption]: true,              // Encrypt cookies
  [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false, // Disable NODE_OPTIONS
  [FuseV1Options.EnableNodeCliInspectArguments]: false,       // Disable --inspect
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,// Enable ASAR integrity
  [FuseV1Options.OnlyLoadAppFromAsar]: true,                 // Require ASAR
  [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,   // Remove file:// extra perms
});
```

This is typically called during the `electron-builder` build process.

---

## Integration with electron-builder

```yaml
# electron-builder.yml:
afterPack: scripts/afterPack.js

# scripts/afterPack.js:
```

```javascript
// scripts/afterPack.js:
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

module.exports = async function(context) {
  const { electronPlatformName, appOutDir } = context;
  
  // Find Electron binary:
  let electronBinary;
  if (electronPlatformName === 'win32') {
    electronBinary = path.join(appOutDir, `${context.packager.appInfo.productFilename}.exe`);
  } else if (electronPlatformName === 'darwin') {
    electronBinary = path.join(appOutDir, `${context.packager.appInfo.productFilename}.app`, 
      'Contents', 'MacOS', context.packager.appInfo.productFilename);
  }
  
  await flipFuses(electronBinary, {
    version: FuseVersion.V1,
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
  });
};
```

---

## Fuse Audit Script

```bash
#!/bin/bash
# audit_fuses.sh — audit fuse state for multiple apps

APPS=(
  "/Applications/Discord.app"
  "/Applications/Slack.app"
  "/Applications/Signal.app"
  "/Applications/Notion.app"
  "/Applications/Obsidian.app"
)

for app in "${APPS[@]}"; do
  if [ -d "$app" ]; then
    echo "=== $app ==="
    npx @electron/fuses read --app "$app" 2>/dev/null || echo "Not an Electron app or fuses not readable"
    echo ""
  fi
done
```
