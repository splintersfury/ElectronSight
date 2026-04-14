---
title: Doyensec
description: Security firm behind Electronegativity — systematic Electron static analysis and research
---

# Doyensec

Doyensec is a boutique security research firm focused on application security assessments and research. In the Electron security world, they're known for two things: **Electronegativity** — the tool that brought systematic static analysis to Electron app auditing — and CVE-2024-46992, a path traversal in `electron-updater` that every app using electron-builder needed to patch.

---

## Electronegativity

Before Electronegativity, auditing an Electron app for basic misconfigurations meant manually grepping for `contextIsolation: false`, `nodeIntegration: true`, `webSecurity: false`, and a dozen other patterns — one by one, file by file. Experienced researchers had this workflow, but it wasn't documented, standardized, or fast.

[Electronegativity](https://github.com/doyensec/electronegativity) systematized it. One command against an app directory (or an ASAR directly) produces a prioritized list of every known Electron misconfiguration pattern. What used to take an hour of manual review takes minutes.

```bash
# Install:
npm install -g @doyensec/electronegativity

# Run against an Electron app directory:
electronegativity -i /path/to/app -o report.csv

# Run against an ASAR directly:
electronegativity -i app.asar -o report.csv

# Specific checks only:
electronegativity -i . -r CONTEXT_ISOLATION_JS_CHECK,NODE_INTEGRATION_JS_CHECK
```

### What Electronegativity Checks

| Check | Description |
|-------|-------------|
| `CONTEXT_ISOLATION_JS_CHECK` | `contextIsolation: false` in BrowserWindow |
| `NODE_INTEGRATION_JS_CHECK` | `nodeIntegration: true` |
| `SANDBOX_JS_CHECK` | `sandbox: false` |
| `WEB_SECURITY_JS_CHECK` | `webSecurity: false` |
| `OPEN_EXTERNAL_JS_CHECK` | Unvalidated `shell.openExternal` calls |
| `EVAL_JS_CHECK` | Direct `eval()` usage |
| `REMOTE_MODULE_JS_CHECK` | Deprecated `remote` module usage |
| `PROTOCOL_HANDLER_JS_CHECK` | Custom protocol handler security |
| `AUXILIARY_WINDOWS_JS_CHECK` | New window creation without restrictions |
| `NODE_INTEGRATION_SUBFRAMES` | `nodeIntegrationInSubFrames: true` |
| `DANGEROUS_FUNCTIONS_JS_CHECK` | exec, spawn, etc. with potential injection |

### Reading the Results

Electronegativity findings are candidates for investigation, not confirmed vulnerabilities. The distinction matters:

- **`CONTEXT_ISOLATION_JS_CHECK`**: If `contextIsolation: false` is confirmed, that's a critical misconfiguration. Go validate it.
- **`OPEN_EXTERNAL_JS_CHECK`**: Flag is raised whenever `shell.openExternal` appears. Read the context — is there URL validation above it? If not, that's a real finding.
- **`EVAL_JS_CHECK`**: High signal if user data reaches it. Low signal if it's a constant expression or build tool artifact.

The tool reduces false-negative risk (you won't miss a known-bad pattern) but doesn't eliminate false positives. Every flagged finding needs a 30-second manual read to confirm or dismiss.

---

## CVE-2024-46992 — electron-updater Path Traversal

Doyensec identified a path traversal in `electron-updater` — the update library used by most `electron-builder` apps — where the `path` field in `latest.yml` was used as a download destination without stripping directory components.

An attacker who could control the update server (via MitM of an HTTP update endpoint, compromised server, or DNS hijacking) could serve a `latest.yml` with a traversal path like:

```yaml
path: "../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.exe"
sha512: HASH_OF_EVIL
```

The downloaded binary would land in the Windows Startup folder, executing on next login. Persistence via update mechanism.

The fix in electron-updater 6.3.0 was `path.basename()` on the filename before constructing the download path.

See [CVE-2024-46992](../cves/CVE-2024-46992.md) for the full technical chain.

---

## Electron Security Research

Doyensec's Electron work is collected at:

- [Electronegativity GitHub](https://github.com/doyensec/electronegativity) — the tool
- [Electron Security Checklist](https://doyensec.com/resources/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security-wp.pdf) — the original research paper (DEF CON 25)
- [doyensec.com/blog](https://doyensec.com/blog) — periodic Electron security posts

---

## Research Impact

Electronegativity is now a standard part of Electron security assessments. It's used by:
- Independent security researchers during initial recon
- Bug bounty hunters for fast surface mapping before manual analysis
- Application security teams for internal auditing
- The Electron project's own security documentation as a recommended tool

The original Carettoni paper that introduced Electronegativity (DEF CON 25, 2017) is one of the foundational documents in Electron security — it established the vocabulary (webPreferences attack surface, contextBridge as security boundary) that the field still uses. If you haven't read it, read it.
