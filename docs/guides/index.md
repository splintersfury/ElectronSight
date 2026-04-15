---
title: Guides
description: Step-by-step Electron security research guides — assessment, XSS→RCE hunting, IPC testing, fuse auditing, ASAR analysis
---

# Guides

Practical step-by-step guides for Electron security research.

---

## Available Guides

<div class="es-card-grid">

<a class="es-card" href="assessment.md">
<div class="es-card-title">📋 Assessing an Electron App</div>
<div class="es-card-desc">Start-to-finish methodology for assessing a new Electron app. From initial recon to triage to finding candidates.</div>
<div class="es-card-meta"><span class="badge badge-info">Beginner</span></div>
</a>

<a class="es-card" href="xss-to-rce.md">
<div class="es-card-title">🔍 Finding XSS→RCE Chains</div>
<div class="es-card-desc">How to systematically find DOM XSS vectors, map the preload bridge, identify escalation paths, and build a working chain.</div>
<div class="es-card-meta"><span class="badge badge-high">Intermediate</span></div>
</a>

<a class="es-card" href="ipc-testing.md">
<div class="es-card-title">📡 IPC Security Testing</div>
<div class="es-card-desc">Enumerate all IPC channels, find over-privileged handlers, test sender validation, and exploit broken IPC security.</div>
<div class="es-card-meta"><span class="badge badge-high">Intermediate</span></div>
</a>

<a class="es-card" href="fuse-auditing.md">
<div class="es-card-title">⚡ Auditing Fuses</div>
<div class="es-card-desc">Read fuse state from any Electron app, understand which enabled fuses are risky, and write a fuse audit report.</div>
<div class="es-card-meta"><span class="badge badge-info">Quick</span></div>
</a>

<a class="es-card" href="asar-analysis.md">
<div class="es-card-title">📦 ASAR Extraction & Analysis</div>
<div class="es-card-desc">Extract app.asar, navigate the codebase, find security-critical files, and understand what's outside the ASAR.</div>
<div class="es-card-meta"><span class="badge badge-info">Beginner</span></div>
</a>

</div>

---

## Quick Start

**New to Electron security research? Start here:**

```bash
# 1. Find app.asar:
find /Applications -name "app.asar" 2>/dev/null | head -5   # macOS
find "C:\Program Files" -name "app.asar" 2>/dev/null          # Windows

# 2. Extract it:
asar extract /path/to/app.asar /tmp/extracted/

# 3. Run Electronegativity:
electronegativity -i /tmp/extracted/ -o /tmp/report.csv

# 4. Check fuses:
npx @electron/fuses read --app /Applications/Target.app

# 5. Find critical configs:
grep -r "nodeIntegration\|contextIsolation\|sandbox\|webSecurity" \
  --include="*.js" /tmp/extracted/ | grep -v node_modules

# 6. Find IPC surface:
grep -r "ipcMain\.\(on\|handle\)\|exposeInMainWorld" \
  --include="*.js" /tmp/extracted/ | grep -v node_modules
```

Then read the full [Assessment Guide](assessment.md).
