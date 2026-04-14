---
title: Native Modules
description: Node.js native addons (.node files) in Electron — security implications, attack vectors, and auditing
---

# Native Modules

Native modules are compiled C/C++ addons (`.node` files) that Node.js loads via `require()`. They exist because some things — file system operations, OS integrations, cryptography, hardware access — are too slow or too platform-specific to implement in pure JavaScript.

In Electron apps, native modules run in the main process with full OS access. They're interesting from a security perspective for three reasons: they bypass the V8 sandbox entirely (running native code, not JavaScript), they're outside the ASAR integrity boundary, and they can contain classic C/C++ memory safety bugs that JavaScript-level security controls don't touch.

---

## Where They Live and Why It Matters

```
resources/
├── app.asar                    ← ASAR integrity checked (if fuse enabled)
└── app.asar.unpacked/
    ├── native_addon.node       ← NOT integrity checked — ever
    └── ffmpeg.dll              ← NOT integrity checked — ever
```

Native modules in `app.asar.unpacked/` are explicitly excluded from ASAR integrity validation. Even with `EnableEmbeddedAsarIntegrityValidation` enabled, these files can be modified without triggering the integrity check. Replacing a `.node` file with a malicious one means arbitrary code execution in the main process on next load.

This is a reliable ASAR integrity bypass for any app with unpacked native addons.

---

## The Discord Case: Native Module as Attack Surface

The Discord RCE (CVE-2020-15174) is the canonical example of native modules as an attack surface. Discord's preload exposed `DiscordNative.nativeModules.requireModule('discord_utils')`. The `discord_utils` module was a compiled `.node` addon that contained `DANGEROUS_openExternal` — a function Discord's own developers flagged as risky but which had no URL validation.

XSS → call `requireModule('discord_utils')` → call `DANGEROUS_openExternal(file:///cmd.exe)` → RCE. The native module was the bridge between JavaScript and the OS.

---

## Memory Safety Bugs in Native Code

JavaScript has no buffer overflows. C/C++ does. Native modules that process external input — image parsers, archive extractors, protocol decoders, database drivers — can have classic memory safety vulnerabilities:

```c
// Simplified vulnerable native addon:
NAN_METHOD(ParseData) {
  v8::String::Utf8Value input(info[0]);
  char buffer[256];
  strcpy(buffer, *input);  // stack overflow if input > 255 bytes
  // buffer is now overwritten with attacker content
}
```

If attacker-controlled data flows to a native module — through IPC, through file content, through network responses — and the native code doesn't validate sizes and types, you have memory corruption in the main process. No JavaScript sandbox, no contextIsolation, nothing between the attacker and OS execution primitives.

---

## DLL Search Order Hijacking (Windows)

On Windows, native modules load as DLLs. The DLL search path can include directories that non-admin users can write to:

```
Windows DLL search order (simplified):
1. Application directory
2. System32
3. PATH environment variable directories

If PATH includes C:\Users\Public\ or similar writable location:
  → Attacker writes C:\Users\Public\sqlite3.dll
  → App loads attacker's DLL instead of the real one
  → Code executes in main process context
```

On macOS, the equivalent is `DYLD_INSERT_LIBRARIES` — if an attacker can set environment variables for the app's launch context (through shell profiles, launchd, etc.), they can inject a malicious dylib.

---

## Finding Native Modules in a Target App

```bash
# All .node files in the app:
find /path/to/app -name "*.node" 2>/dev/null

# What functions does each module export?
nm -D module.node | grep -v "^$" | head -20

# Strings analysis — what does it call?
strings module.node | grep -E "exec|popen|system|fork|dlopen|CreateProcess|ShellExecute"

# Check npm ecosystem vulnerabilities:
cd /tmp/extracted-asar && npm audit --audit-level=moderate 2>/dev/null | \
  grep -E "high|critical"

# What does each native module expose to JavaScript?
grep -r "requireModule\|require.*\.node\|bindings\b\|node-pre-gyp" \
  --include="*.js" . | grep -v node_modules
```

For each `.node` file found:

1. Is it in `app.asar.unpacked/`? → ASAR integrity doesn't cover it
2. What does `strings` reveal about its capabilities?
3. What JavaScript code calls it? (Trace back from `require('./native/...')`)
4. Does the calling code pass attacker-controlled input to it?
5. On Windows: is the containing directory in PATH ahead of System32?

---

## Supply Chain Risk

Many Electron apps use third-party npm packages that contain pre-built native binaries downloaded at install time (via `node-pre-gyp` or `node-gyp-build`). The binary is fetched from a URL, not compiled locally.

```bash
# Check for packages fetching pre-built binaries:
cat package.json | grep -E "node-pre-gyp|node-gyp|bindings|prebuild"

# Check if a package uses pre-built binaries (look for binary config):
cat node_modules/some-native-package/package.json | grep -A 5 '"binary":'
```

A pre-built binary from an npm package is only as trustworthy as:
- The npm package (npm account security, dependency confusion attacks)
- The download URL (CDN compromise, S3 misconfiguration)
- The integrity hash (does `node-pre-gyp` verify it?)

For high-assurance apps (password managers, security tools), pre-built native binaries from third-party npm packages are a real supply chain risk. Worth flagging when you see them.
