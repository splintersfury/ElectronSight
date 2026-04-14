---
title: Trail of Bits
description: Security firm behind V8 snapshot backdooring research and CVE-2025-55305 (1Password)
---

# Trail of Bits

Trail of Bits is a New York security research firm known for rigorous technical assessments and original security research across cryptography, systems security, and application security. Their contribution to Electron security is the discovery of the V8 snapshot backdoor attack — a finding that proved ASAR integrity validation is weaker than it appears.

---

## V8 Snapshot Backdooring

When 1Password engaged Trail of Bits for a security assessment, one of the questions on the table was: does ASAR integrity validation actually prevent a local attacker from tampering with 1Password's code?

The answer was no. The mechanism that protects `app.asar` doesn't protect anything that loads before the integrity check runs. V8 snapshots load before the integrity check. They're not part of the ASAR. They're writable without triggering any check. And they can contain arbitrary pre-compiled JavaScript.

Trail of Bits demonstrated a complete attack chain: replace `v8_context_snapshot.bin`, hook 1Password's vault unlock flow via `Promise.prototype.then`, exfiltrate vault contents transparently. The integrity check still shows "PASSED" because `app.asar` itself is untouched.

Full technical breakdown: [V8 Snapshot Backdooring case study](../case-studies/v8-snapshot-backdoor.md).

CVE: [CVE-2025-55305](../cves/CVE-2025-55305.md)

---

## The Broader Implication

Trail of Bits' research revealed a primitive: *pre-ASAR code execution*. Anything that loads before the ASAR integrity check — and is writable by local attackers — defeats the check.

The snapshot is the most elegant example, but the principle applies to:
- Native `.node` addons in `app.asar.unpacked/` (always excluded from integrity checking)
- DLLs loaded by native modules (subject to DLL search order hijacking)
- Any configuration or preload mechanism that runs before ASAR validation

This reframed the question from "does app use ASAR integrity?" to "what's the full inventory of components that execute before ASAR integrity validates, and are all of them covered?"

That's the question worth asking on any app that advertises tamper protection as part of its security model.

---

## Reading

- [Trail of Bits blog](https://blog.trailofbits.com/) — technical research across many domains
- [GitHub: trailofbits](https://github.com/trailofbits) — tools and publications
- [1Password security assessments](https://support.1password.com/security-assessments/) — CVE-2025-55305 disclosure
