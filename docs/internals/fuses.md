---
title: Electron Fuses
description: Binary-level feature flags in Electron — what each fuse controls, security implications, and how to audit
---

# Electron Fuses

Fuses are binary-level feature flags baked into the Electron runtime at build time. Unlike JavaScript configuration that lives in `main.js` and can theoretically be tampered with, fuses are embedded in the actual `electron` binary and can't be changed without rebuilding the app.

The promise is: once a fuse is disabled, it stays disabled. Attacker code in the renderer can't re-enable it. A compromised main process can't flip it. It's the closest thing Electron has to hardware-enforced security policy.

The reality: most shipping apps haven't set most fuses, because fuse tooling was introduced relatively recently and developers didn't go back to retrofit it. Running `npx @electron/fuses read` on a random Electron app and finding `RunAsNode` enabled is completely normal. That's your opening.

---

## How Fuses Work

Fuses are stored as a sentinel structure embedded in the Electron binary. The `@electron/fuses` package reads and writes this structure at build/package time:

```javascript
const { FuseV1Options, FuseVersion } = require('@electron/fuses');

// Flip fuses during app packaging:
await flipFuses(require('electron'), {
  version: FuseVersion.V1,
  [FuseV1Options.RunAsNode]: false,
  [FuseV1Options.EnableCookieEncryption]: true,
  [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
  [FuseV1Options.EnableNodeCliInspectArguments]: false,
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
  [FuseV1Options.OnlyLoadAppFromAsar]: true,
  [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
});
```

---

## Fuse Reference

### RunAsNode — Default: Enabled

When enabled, setting `ELECTRON_RUN_AS_NODE=1` makes the Electron binary behave as a Node.js interpreter. You can run arbitrary JavaScript files using the app's identity, its signing certificate, and any OS entitlements the app has:

```bash
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord \
  -e "require('child_process').exec('open -a Calculator')"
```

This isn't just a theoretical technique — it's used in real privilege escalation chains. An app that runs with elevated privileges and has `RunAsNode` enabled can have its process identity hijacked by anyone who can set environment variables in its launch context (launchd plists, installer scripts, etc.).

**Set to:** `false`

---

### EnableNodeOptionsEnvironmentVariable — Default: Enabled

The `NODE_OPTIONS` environment variable controls Node.js runtime behavior. When this fuse is enabled, it applies to the Electron process too. An attacker who can set environment variables gets code execution before the app even starts:

```bash
NODE_OPTIONS="--require /tmp/exploit.js" /path/to/app
# exploit.js runs in the main process before any app code
```

Less exotic uses: `--inspect=9229` opens a debugger port, `--max-old-space-size=99999` causes out-of-memory. All controllable by environment.

**Set to:** `false`

---

### EnableNodeCliInspectArguments — Default: Enabled

Honors `--inspect` and `--inspect-brk` when passed on the command line. Lets anyone who can influence the app's launch arguments attach a Chrome DevTools debugger to the main process:

```bash
/path/to/app --inspect=9229
# Chrome DevTools at chrome://inspect → connect to localhost:9229
# Full Node.js REPL in main process context
# Read files, execute commands, exfiltrate anything
```

This is how CVE-2018-1000006 worked: protocol handler registration put the URL (attacker-controlled) into the command line, which Electron parsed as flags, which opened the debugger.

**Set to:** `false`

---

### EnableEmbeddedAsarIntegrityValidation — Default: Disabled

This is the one you enable, not disable. When enabled, Electron validates `app.asar` against SHA256 hashes that were embedded in the Electron binary at build time. If the ASAR has been modified since packaging, the app refuses to start.

Without this, an attacker with local write access to the ASAR file can modify `main.js` or `preload.js`, repack the archive, and have their code execute on the next app launch with full app identity and privileges.

Caveat: this fuse requires generating integrity hashes at build time — it doesn't work automatically. And even with it enabled, V8 snapshots bypass it entirely (see [V8 Snapshots](v8-snapshots.md) and CVE-2025-55305).

**Set to:** `true` (with proper build tooling)

---

### OnlyLoadAppFromAsar — Default: Disabled

When disabled (the default), Electron falls back to loading from an `app/` directory if `app.asar` is missing or renamed:

```bash
# Attack: rename the ASAR, create a malicious directory:
mv /opt/app/resources/app.asar /opt/app/resources/app.asar.bak
mkdir -p /opt/app/resources/app/
echo '{"main":"main.js","name":"app"}' > /opt/app/resources/app/package.json
echo 'require("child_process").exec("bash /tmp/shell.sh")' > /opt/app/resources/app/main.js
# Next launch: executes attacker code
```

With `OnlyLoadAppFromAsar` enabled, this fallback doesn't exist. Combined with ASAR integrity validation, this closes the local tampering vector.

**Set to:** `true`

---

### GrantFileProtocolExtraPrivileges — Default: Enabled (legacy)

Historically, pages loaded via `file://` got elevated trust in Electron — they could access `node:` modules and had permissions that web pages don't get. This made legacy behavior work, but it means any `file://` page an attacker can load (via path traversal, symlink, or `loadURL` with attacker-controlled path) gets elevated access.

Disabling this removes the extra privileges and makes `file://` behave like a normal web origin.

**Set to:** `false`

---

### EnableCookieEncryption — Default: Disabled

Without this, Electron's session cookies are stored in plaintext SQLite databases on disk. An attacker with local read access — which is often achievable before you have full code execution — can extract active session tokens:

```bash
# Cookie database location (varies by app):
cat ~/.config/AppName/Session Storage/...
# or: ~/Library/Application Support/AppName/...
```

With this fuse enabled, cookies are encrypted using the OS keychain (same as Chrome's implementation). Extraction requires the keychain master key.

**Set to:** `true`

---

## Reading Fuses on a Target App

```bash
# The easy way — @electron/fuses CLI:
npx @electron/fuses read --app /Applications/Slack.app
npx @electron/fuses read --app /path/to/app.exe

# Output looks like:
# Electron Fuses: v1
# RunAsNode is Enabled           ← finding
# EnableCookieEncryption is Disabled
# EnableNodeOptionsEnvironmentVariable is Enabled   ← finding
# EnableNodeCliInspectArguments is Enabled          ← finding
# EnableEmbeddedAsarIntegrityValidation is Disabled ← finding
# OnlyLoadAppFromAsar is Disabled                   ← finding
# GrantFileProtocolExtraPrivileges is Enabled       ← finding
```

---

## Fuse Audit Table

| Fuse | Secure state | Impact if wrong |
|------|-------------|-----------------|
| RunAsNode | `false` | Arbitrary Node.js via `ELECTRON_RUN_AS_NODE=1` |
| EnableNodeOptionsEnvironmentVariable | `false` | Pre-startup code injection via `NODE_OPTIONS` |
| EnableNodeCliInspectArguments | `false` | Main process debugger via `--inspect` flag |
| EnableEmbeddedAsarIntegrityValidation | `true` | ASAR tampering for persistence/LPE |
| OnlyLoadAppFromAsar | `true` | Directory fallback code injection |
| GrantFileProtocolExtraPrivileges | `false` | Elevated file:// access from attacker-loaded pages |
| EnableCookieEncryption | `true` | Session cookie theft from disk |

Most apps fail at least half this table. `RunAsNode` and `EnableNodeOptionsEnvironmentVariable` enabled is a valid finding when the app runs with elevated privileges or is part of an LPE chain.
