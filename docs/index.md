---
title: ElectronSight
description: Comprehensive Electron desktop app security reference
hide:
  - navigation
  - toc
---

<div class="es-hero">
  <div class="es-hero-title">The <span>Electron</span> Security Pipeline</div>
  <div class="es-hero-subtitle">
    From process internals and IPC architecture to source-to-sink exploitation chains —
    a complete reference for security researchers hunting bugs in Electron desktop applications.
  </div>

  <div class="es-stats">
    <div class="es-stat">
      <span class="es-stat-number">40+</span>
      <span class="es-stat-label">CVEs Tracked</span>
    </div>
    <div class="es-stat">
      <span class="es-stat-number">20+</span>
      <span class="es-stat-label">Apps Covered</span>
    </div>
    <div class="es-stat">
      <span class="es-stat-number">12</span>
      <span class="es-stat-label">Vuln Classes</span>
    </div>
    <div class="es-stat">
      <span class="es-stat-number">50+</span>
      <span class="es-stat-label">Sinks Documented</span>
    </div>
  </div>

  <div class="es-pipeline">
    <div class="es-pipeline-step">Internals</div>
    <div class="es-pipeline-arrow">→</div>
    <div class="es-pipeline-step">Attack Surfaces</div>
    <div class="es-pipeline-arrow">→</div>
    <div class="es-pipeline-step">Sources</div>
    <div class="es-pipeline-arrow">→</div>
    <div class="es-pipeline-step">Sinks</div>
    <div class="es-pipeline-arrow">→</div>
    <div class="es-pipeline-step">Vuln Classes</div>
    <div class="es-pipeline-arrow">→</div>
    <div class="es-pipeline-step">CVEs</div>
    <div class="es-pipeline-arrow">→</div>
    <div class="es-pipeline-step">Case Studies</div>
  </div>
</div>

---

## What Is This?

**ElectronSight** is a security reference for Electron desktop apps — built for bug bounty hunters, pentesters, and researchers who want to actually understand the attack surface, not just scan for `nodeIntegration: true` and call it a day.

Electron powers **Discord**, **Slack**, **VS Code**, **Signal**, **WhatsApp Desktop**, **Notion**, **Obsidian**, **Mattermost**, and hundreds of other apps used by millions of people every day. Each one bundles Chromium's renderer engine, Node.js's runtime, and a bespoke inter-process communication layer — three different attack surfaces stapled together inside one app, often written by teams whose primary concern is shipping features fast.

The result? An ecosystem full of hardcoded API keys you can extract with three commands, IPC handlers that trust the renderer unconditionally, and update servers running over plain HTTP. This site covers all of it: how the internals actually work, where attacker-controlled data enters, what the dangerous operations are, what's supposed to stop exploitation (and why it often doesn't), and a full database of real CVEs showing how researchers have turned all of the above into paychecks.

---

## Site Map

<div class="es-card-grid">

<div class="es-card">
<div class="es-card-title">🔬 Internals</div>
<div class="es-card-desc">Process model, IPC wire format, context isolation implementation, preload script world IDs, ASAR format, Electron fuses, V8 snapshots, sandbox architecture.</div>
<div class="es-card-meta"><span class="badge badge-info">11 pages</span></div>
</div>

<div class="es-card">
<div class="es-card-title">🎯 Attack Surfaces</div>
<div class="es-card-desc">Every external interface of an Electron app: BrowserWindow webPreferences, IPC channels, custom protocol handlers, update mechanism, DevTools, native bindings.</div>
<div class="es-card-meta"><span class="badge badge-info">9 pages</span></div>
</div>

<div class="es-card">
<div class="es-card-title">📥 Sources</div>
<div class="es-card-desc">Complete taxonomy of attacker-controlled input: URL/navigation, DOM messaging, storage XSS, network responses, file input, IPC callbacks, environment variables.</div>
<div class="es-card-meta"><span class="badge badge-source">SOURCE</span> <span class="badge badge-info">8 categories</span></div>
</div>

<div class="es-card">
<div class="es-card-title">📤 Sinks</div>
<div class="es-card-desc">Every dangerous operation: RCE via child_process/eval, file system writes, HTML injection, shell.openExternal, IPC escalation, process manipulation, crypto leakage.</div>
<div class="es-card-meta"><span class="badge badge-sink">SINK</span> <span class="badge badge-info">50+ sinks</span></div>
</div>

<div class="es-card">
<div class="es-card-title">🛡️ Sanitizers</div>
<div class="es-card-desc">What breaks taint chains: contextBridge, CSP, sandbox, contextIsolation, DOMPurify, allowlist validation — and crucially, how each one can be bypassed.</div>
<div class="es-card-meta"><span class="badge badge-sanitizer">SANITIZER</span></div>
</div>

<div class="es-card">
<div class="es-card-title">💥 Vulnerability Classes</div>
<div class="es-card-desc">12 distinct vuln patterns with real CVEs, exploitation payloads, and detection methods: XSS→RCE, contextIsolation bypass, protocol handler injection, ASAR tamper, and more.</div>
<div class="es-card-meta"><span class="badge badge-critical">CRITICAL</span> <span class="badge badge-high">HIGH</span></div>
</div>

<div class="es-card">
<div class="es-card-title">📋 CVE Database</div>
<div class="es-card-desc">40+ CVEs across Discord, Slack, Teams, VS Code, Signal, WhatsApp, Notion, and more — with full technical breakdowns, exploit chains, patches, and timeline.</div>
<div class="es-card-meta"><span class="badge badge-info">40+ CVEs</span></div>
</div>

<div class="es-card">
<div class="es-card-title">🔗 Case Studies</div>
<div class="es-card-desc">Deep-dives into ElectroVolt (Black Hat 2022), Slack RCE chain, Teams zero-click, V8 snapshot backdooring (Trail of Bits), and Discord's contextIsolation bypass.</div>
<div class="es-card-meta"><span class="badge badge-info">5 studies</span></div>
</div>

<div class="es-card">
<div class="es-card-title">🔧 Tools</div>
<div class="es-card-desc">Electronegativity static analysis, asar CLI, DevTools tricks, @electron/fuses auditing, electron-builder security configuration.</div>
<div class="es-card-meta"><span class="badge badge-info">5 tools</span></div>
</div>

<div class="es-card">
<div class="es-card-title">📖 Guides</div>
<div class="es-card-desc">Step-by-step: assessing an Electron app from scratch, finding XSS→RCE chains, IPC security testing, auditing fuses, ASAR extraction and analysis.</div>
<div class="es-card-meta"><span class="badge badge-info">5 guides</span></div>
</div>

</div>

---

## Why Electron?

Here's the thing that makes Electron different from every other attack surface you've worked on: it runs a web browser and a local OS process in the same application, connected by a message-passing layer that most developers treat as an internal API rather than a security boundary.

```
Browser Process (Main)   ← Node.js + full OS access
        │
        │ IPC (named pipes / mojo)
        │
Renderer Process         ← Chromium renderer + optional Node.js
        │
        │ contextBridge API
        │
Web Content (Untrusted)  ← attacker-controlled HTML/JS
```

In a correctly configured app, XSS in the renderer is just... XSS. Annoying, but contained. The problem is that "correctly configured" is deceptively hard — a single wrong setting in `webPreferences` collapses that model entirely. And when it collapses, XSS becomes OS-level code execution because the renderer now has access to `child_process`, `fs`, and the full Node.js API.

Even with correct configuration, the **preload script** creates a JavaScript bridge between the privileged main process and the renderer. Too wide a bridge — exposing `ipcRenderer` directly, or wiring up a `run-command` handler — and a renderer XSS becomes an IPC call into a `exec()`. The attacks just got one step longer. The impact didn't change.

---

## The Classic Chain

This is the one that made Electron famous in bug bounty circles. It's not always this clean, but when it is, it's a two-step critical:

<div class="es-flow">
  <div class="es-flow-box es-flow-source">DOM XSS<br><code>innerHTML = userInput</code></div>
  <div class="es-flow-arrow">→</div>
  <div class="es-flow-box es-flow-taint">JS runs in renderer<br>(contextIsolation: false)</div>
  <div class="es-flow-arrow">→</div>
  <div class="es-flow-box es-flow-sink">RCE<br><code>require('child_process')<br>.exec('cmd')</code></div>
</div>

You need three things:

- [ ] `contextIsolation: false` OR `nodeIntegration: true` — one wrong setting is enough
- [ ] Somewhere that user-controlled data hits `innerHTML`, a Markdown renderer, or similar
- [ ] No CSP that actually blocks execution (many CSPs look strict but aren't)

In practice, older Electron apps (pre-2020) frequently had all three. Newer ones have fixed the first condition but introduced the same impact via over-privileged IPC bridges. The attack got longer; the damage didn't.

See [XSS → RCE](vuln-classes/xss-to-rce.md) for full chain mechanics, or jump straight to [case studies](case-studies/discord-rce.md) if you want to see real ones.

---

## Scope

Electron apps in scope for this reference include:

| Application | Versions Studied | Notable CVEs |
|---|---|---|
| Discord | v0.0.x – current | CVE-2020-15174 |
| Slack | Legacy Electron | HN-783877 |
| Microsoft Teams | Teams 1.x (Electron) | Zero-click RCE (2020) |
| VS Code | All versions | CVE-2023-39956, CVE-2021-43908 |
| Signal Desktop | v1.x – current | 2018 RCE, Signal-2024 |
| WhatsApp Desktop | All versions | CVE-2019-18426, CVE-2025-30401 |
| Notion | All versions | CVE-2024-23743 |
| Obsidian | All versions | CVE-2023-2110 |
| Element | v1.x – current | CVE-2022-23597 |
| Mattermost | All versions | ElectroVolt |
| RocketChat | All versions | Multiple stored XSS |
| Joplin | All versions | Multiple XSS→RCE |
| 1Password | Pre-8.11.8-40 | CVE-2025-55305 |
| SiYuan | Pre-3.6.4 | CVE-2026-39846 |
| Notesnook | Pre-3.3.11 | CVE-2026-33955 |

---

!!! warning "Responsible Use"
    This site is for **authorized security research**, bug bounty hunting under program scope, and education only. All vulnerability information is sourced from public disclosures, CVE databases, and researcher write-ups. Do not use this material against systems you do not have explicit permission to test.
