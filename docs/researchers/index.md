---
title: Researchers
description: Key security researchers in Electron vulnerability research — techniques, findings, and contributions
---

# Electron Security Researchers

The researchers who have shaped the field of Electron security research — through CVEs, conference talks, open-source tools, and written research.

---

## Featured Researchers

<div class="es-card-grid">

<div class="es-card">
<div class="es-card-title">Masato Kinugawa</div>
<div class="es-card-desc">Japanese researcher known for deep XSS → RCE exploitation. Discord CVE-2020-15174. Expert in browser engine quirks and Electron's JavaScript context model.</div>
<div class="es-card-meta"><span class="badge badge-critical">CVE-2020-15174</span></div>
</div>

<div class="es-card">
<div class="es-card-title">Oskars Vegeris</div>
<div class="es-card-desc">Zero-click RCE researcher. $30,000 Slack finding. Teams zero-click. Pioneered the "workspace metadata XSS → IPC → openExternal" chain across multiple apps.</div>
<div class="es-card-meta"><span class="badge badge-critical">HN-783877</span></div>
</div>

<div class="es-card">
<div class="es-card-title">Aaditya Purani</div>
<div class="es-card-desc">ElectroVolt researcher (Black Hat 2022). Systematic analysis of Electron IPC security. Created methodology for finding preload script vulnerabilities at scale.</div>
<div class="es-card-meta"><span class="badge badge-high">ElectroVolt</span></div>
</div>

<div class="es-card">
<div class="es-card-title">Doyensec</div>
<div class="es-card-desc">Security firm behind Electronegativity static analysis tool. Extensive Electron app research. electron-updater CVE. Systematic auditing methodology for Electron apps.</div>
<div class="es-card-meta"><span class="badge badge-info">Electronegativity</span></div>
</div>

<div class="es-card">
<div class="es-card-title">Trail of Bits</div>
<div class="es-card-desc">V8 snapshot backdooring research. CVE-2025-55305 (1Password). Deep Electron internals research including ASAR integrity bypass and snapshot attack primitives.</div>
<div class="es-card-meta"><span class="badge badge-high">CVE-2025-55305</span></div>
</div>

</div>

---

## Research Timeline

| Year | Researcher | Finding | Impact |
|------|-----------|---------|--------|
| 2017 | Multiple | First Electron protocol handler attacks | CVE-2018-1000006 |
| 2018 | Multiple | Signal/Mattermost/RocketChat nodeIntegration era | Mass RCE |
| 2018 | Electron team | CVE-2018-1000136 — nodeIntegration in frames bypass | Electron patch |
| 2020 | Masato Kinugawa | Discord XSS → IPC → openExternal | CVE-2020-15174, $10k |
| 2021 | Oskars Vegeris | Slack zero-click, Teams zero-click | HN-783877, $30k |
| 2022 | Aaditya Purani | ElectroVolt — systematic IPC vuln research | Black Hat 2022 |
| 2022 | Doyensec | Electronegativity v3 + electron-updater vulns | Tool release |
| 2023 | Various | Obsidian, Joplin Markdown XSS → RCE | Multiple CVEs |
| 2024 | Doyensec | CVE-2024-46992 electron-updater path traversal | electron-updater fix |
| 2025 | Trail of Bits | V8 snapshot bypasses ASAR integrity | CVE-2025-55305 |

---

## Community Resources

- **ElectroVolt (Black Hat 2022):** [aaditya-purani.github.io/electrovolt](https://aaditya-purani.github.io/) — full methodology
- **Electronegativity:** [github.com/doyensec/electronegativity](https://github.com/doyensec/electronegativity) — static analysis tool
- **Electron Security:** [electronjs.org/docs/latest/tutorial/security](https://electronjs.org/docs/latest/tutorial/security) — official security guide
- **@electron/fuses:** npm package for auditing fuse state
