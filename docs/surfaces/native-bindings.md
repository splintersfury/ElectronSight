---
title: Native Bindings Attack Surface
description: Node.js native modules (.node addons), DLL hijacking, and native code attack surfaces
---

# Native Bindings Attack Surface

Native bindings (`.node` files, Node.js addons) are compiled C/C++ code loaded directly into the Node.js process. They run outside the V8 sandbox, have direct OS access, and introduce memory safety vulnerabilities into what is otherwise a memory-safe JavaScript environment.

For an attacker, native bindings are interesting for three reasons: they're excluded from ASAR integrity validation (the `app.asar.unpacked/` directory is never checked), they can be targeted by DLL search order hijacking (Windows), and if they process attacker-controlled data, memory corruption in C/C++ code is potentially exploitable to escape even a well-configured Electron sandbox. Discord's `discord_utils.node` is the canonical example — it was the native module that contained `DANGEROUS_openExternal`, the function Masato Kinugawa used to achieve RCE in CVE-2020-15174.

---

## What Native Modules Enable (and Risk)

```
JavaScript (V8)                Native Module (.node / .so / .dll)
    │                                    │
    │ require('./native.node')            │
    ▼                                    ▼
V8 type safety                  Full C/C++ memory access
Promise/async safety            No bounds checking (unless coded)
Garbage collection              Manual memory management
    │                                    │
    └──────────── Combined ──────────────┘
                      │
                      ▼
              Full OS access
              + Memory safety bugs if native code is buggy
```

---

## Common Native Module Usage in Electron

```bash
# Detect native modules in an app:
find /path/to/app -name "*.node" | grep -v node_modules
find /path/to/app.asar.unpacked -name "*.node"

# Common native modules in real apps:
# - keytar (keychain access)
# - node-gyp built addons (crypto, compression, database)
# - @electron/rebuild targets (native modules rebuilt for Electron's Node version)
# - serialport, usb, midi (hardware access)
# - node-sqlite3 (database)
# - node-canvas (image processing)
```

---

## DLL / .dylib Hijacking

When native modules or the Electron binary load DLLs from search paths:

```
Windows DLL search order (simplified):
1. Application directory (where .exe is)
2. System32
3. Windows directory
4. PATH directories

Attack:
- If attacker can write to application directory:
  Drop evil.dll with same name as a dependency
  → App loads attacker's DLL instead of system DLL
  → Native code execution at app's privilege level
```

```bash
# Windows: find all DLLs the app tries to load (Process Monitor / Sysinternals):
# Run app → Process Monitor filter: Operation=LoadImage AND Result=NAME NOT FOUND
# Any missing DLL loaded from a user-writable path = DLL hijacking target

# macOS: dyld environment variable injection:
DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /path/to/MyApp.app/Contents/MacOS/MyApp
# If RunAsNode fuse is off and app doesn't strip env, this may work in some contexts

# Linux: LD_PRELOAD:
LD_PRELOAD=/tmp/evil.so /path/to/myapp
# Same — environment-based code injection into process
```

---

## ASAR Unpacked — The Native Module Bypass

ASAR integrity verification does NOT cover unpacked files:

```bash
# Even with EnableEmbeddedAsarIntegrityValidation fuse enabled:
# Files in app.asar.unpacked/ are NEVER verified

# Common unpacked targets:
ls /Applications/MyApp.app/Contents/Resources/app.asar.unpacked/
# → node_modules/keytar/build/Release/keytar.node   ← replace with malicious
# → node_modules/serialport/build/Release/serialport.node
# → node_modules/sqlite3/build/Release/node_sqlite3.node

# Attack: replace with malicious .node that runs shellcode on require()
```

---

## Memory Safety Bugs in Native Modules

Native modules written in C/C++ can have memory corruption bugs:

```javascript
// JavaScript calls into native module with attacker-controlled input:
const nativeAddon = require('./build/Release/addon.node');

// If nativeAddon has a buffer overflow:
nativeAddon.parseData(Buffer.alloc(10000).fill('A'));  // Large buffer → overflow
nativeAddon.processInput('\x00'.repeat(1000));          // Null bytes in C string
nativeAddon.decode(specialChars);                       // Format string via snprintf

// Memory safety bugs in native modules → heap/stack overflow → code execution
// Bypasses all JavaScript-level security
```

### Finding Memory Safety Issues

```bash
# Check if native modules are present:
find . -name "*.node" 2>/dev/null | grep -v node_modules

# For each .node file, check:
# 1. Source is available → review C/C++ code for:
#    - Unchecked buffer sizes (memcpy, strcpy without length)
#    - Integer overflow in allocation size
#    - Use-after-free patterns
#    - Format string bugs

# Run with AddressSanitizer (development):
ASAN_OPTIONS=detect_leaks=0 node -e "require('./addon.node')" 

# Or use native fuzzing (libFuzzer):
# Not trivial but possible for critical modules
```

---

## keytar — Keychain Native Module

`keytar` is used for OS keychain access — it's a critical native module:

```javascript
const keytar = require('keytar');

// Reads passwords from OS keychain:
const password = await keytar.getPassword('MyApp', username);

// If username is attacker-controlled:
keytar.getPassword('MyApp', attacker_username);  // Can enumerate all keychain entries for 'MyApp'

// keytar stores:
keytar.setPassword('MyApp', 'apiKey', secretApiKey);
// Visible in: Security.app on macOS, Windows Credential Manager, kwallet on Linux
```

---

## Rebuild and Native Module Compatibility

Electron uses its own version of Node.js, so native modules must be rebuilt:

```bash
# electron-rebuild:
npx @electron/rebuild -f -w <module-name>

# If native modules are built for wrong Node.js version:
# Error: The module was compiled against a different Node.js version
# → App won't load the module (DoS) but not a security issue

# If native modules are pre-built binaries downloaded from npm:
# The binary could be tampered with if the npm package is compromised
# → Supply chain attack vector
```

---

## Supply Chain via Native Modules

```bash
# Native modules in package.json may be downloaded as pre-built binaries:
# Example: node-pre-gyp downloads pre-built .node files from GitHub releases
# If attacker compromises the GitHub release:
# → Malicious .node installed via npm install → code execution on install

# Check for pre-built binary downloads:
grep -rn "node-pre-gyp\|node-addon-api\|binary.*host\|binary.*remote_path" \
  package.json node_modules/*/package.json 2>/dev/null | head -20

# Mitigation: lockfile (package-lock.json / yarn.lock) + npm audit
```

---

## Auditing Native Modules

```bash
# Find all native modules:
find . -name "*.node" 2>/dev/null | grep -v "node_modules" | head -20

# Find require() calls to .node files:
grep -rn "require.*\.node['\"]" --include="*.js" . | grep -v node_modules

# Find native modules in package.json dependencies:
cat package.json | python3 -c "
import json, sys
p = json.load(sys.stdin)
deps = {**p.get('dependencies', {}), **p.get('devDependencies', {})}
print([k for k, v in deps.items() if 'native' in k.lower() or k.startswith('node-')])"

# Check for DLL search path vulnerabilities (Windows):
# Run Sysinternals Process Monitor while launching app
# Filter: Operation = LoadImage, Result = NAME NOT FOUND

# Check ASAR unpacked directory:
ls -la /path/to/app.asar.unpacked/

# Verify native module permissions:
find /path/to/app.asar.unpacked -name "*.node" -perm -o+w
```

---

## Risk Matrix

| Attack | Requires | Impact |
|--------|----------|--------|
| DLL hijacking | Write to app dir | Code execution at app privilege |
| .node file replacement (unpacked) | Write to .unpacked dir | Code execution (not checked by ASAR integrity) |
| Memory safety bug in native module | Exploit via IPC | Memory corruption → code execution |
| LD_PRELOAD / DYLD_INSERT | Env control before launch | Code injection into process |
| Native module supply chain | Compromised npm package | Code on install/run |
| keytar username enumeration | IPC access | Keychain entry enumeration |
