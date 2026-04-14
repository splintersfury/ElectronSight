---
title: Electronegativity
description: Doyensec's static analysis tool for Electron apps — finding misconfigurations and dangerous patterns
---

# Electronegativity

Electronegativity is a static analysis tool for Electron applications developed by Doyensec. It scans JavaScript source for known dangerous patterns, misconfigurations, and security anti-patterns — reducing the time to identify candidates for manual investigation.

---

## Installation

```bash
npm install -g @doyensec/electronegativity

# Verify:
electronegativity --version
```

---

## Basic Usage

```bash
# Scan a directory (extracted ASAR or source):
electronegativity -i /path/to/app

# Scan directly from ASAR:
electronegativity -i /path/to/app.asar

# Output to CSV for review:
electronegativity -i /path/to/app -o results.csv

# Output to SARIF (for IDE integration):
electronegativity -i /path/to/app -o results.sarif -f sarif

# Scan only specific file patterns:
electronegativity -i /path/to/app --filefilter "*.js"
```

---

## Key Checks

### Critical Severity

```bash
# Run only critical checks:
electronegativity -i . -r \
  CONTEXT_ISOLATION_JS_CHECK,\
  NODE_INTEGRATION_JS_CHECK,\
  NODE_INTEGRATION_SUBFRAMES_JS_CHECK,\
  WEB_SECURITY_JS_CHECK,\
  SANDBOX_JS_CHECK
```

| Check | Detects |
|-------|---------|
| `CONTEXT_ISOLATION_JS_CHECK` | `contextIsolation: false` |
| `NODE_INTEGRATION_JS_CHECK` | `nodeIntegration: true` |
| `NODE_INTEGRATION_SUBFRAMES_JS_CHECK` | `nodeIntegrationInSubFrames: true` |
| `WEB_SECURITY_JS_CHECK` | `webSecurity: false` |
| `SANDBOX_JS_CHECK` | `sandbox: false` |

### High Severity

| Check | Detects |
|-------|---------|
| `OPEN_EXTERNAL_JS_CHECK` | `shell.openExternal` without URL validation |
| `PROTOCOL_HANDLER_JS_CHECK` | Custom protocol handlers |
| `AUXILIARY_WINDOWS_JS_CHECK` | New windows without security restrictions |
| `REMOTE_MODULE_JS_CHECK` | Deprecated `remote` module usage |

### Medium Severity

| Check | Detects |
|-------|---------|
| `EVAL_JS_CHECK` | `eval()` usage |
| `DANGEROUS_FUNCTIONS_JS_CHECK` | `exec`, `spawn`, `execSync` usage |
| `RENDERER_OVERRIDE_JS_CHECK` | Overriding Chromium APIs in renderer |

---

## Interpreting Results

Electronegativity results are candidates for investigation, not confirmed vulnerabilities. For each finding:

```
[FINDING]
  Check: CONTEXT_ISOLATION_JS_CHECK
  File: main/windows.js
  Line: 42
  Column: 6
  Severity: ERROR
  Description: contextIsolation is explicitly set to false

→ Go investigate: read main/windows.js:42
→ Find the preload script for this window
→ Read the preload script — what does it expose?
→ Find user-controlled input that reaches innerHTML
→ Chain: XSS → bridge → IPC → exec
```

Not every finding is exploitable:
- `EVAL_JS_CHECK` on a constant string: false positive
- `OPEN_EXTERNAL_JS_CHECK` with URL validated against allowlist: not exploitable
- `CONTEXT_ISOLATION_JS_CHECK` in a window that only loads trusted content: low risk

---

## Sample Workflow

```bash
# 1. Extract the ASAR:
asar extract resources/app.asar /tmp/app/

# 2. Run Electronegativity:
electronegativity -i /tmp/app/ -o /tmp/electron_report.csv

# 3. Sort by severity, focus on Critical/High:
cat /tmp/electron_report.csv | \
  awk -F',' '$4 == "ERROR" || $4 == "WARNING"' | \
  sort -t',' -k4 | \
  head -30

# 4. Investigate each finding manually:
cat /tmp/app/main/windows.js | head -50  # around the flagged line
grep -r "exposeInMainWorld\|ipcMain" /tmp/app/main/ --include="*.js"
```

---

## Integration with CI/CD

For apps that want to prevent security regressions:

```yaml
# .github/workflows/security.yml:
- name: Electronegativity scan
  run: |
    npm install -g @doyensec/electronegativity
    electronegativity -i dist/app.asar -o electronegativity-report.sarif -f sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: electronegativity-report.sarif
```

---

## Source and Documentation

- [GitHub: doyensec/electronegativity](https://github.com/doyensec/electronegativity)
- [Issue tracker for false positives and new checks](https://github.com/doyensec/electronegativity/issues)
- [Doyensec Electron security paper](https://doyensec.com/resources/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security-wp.pdf)
