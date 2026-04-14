---
title: Case Studies
description: Deep-dives into landmark Electron security research — ElectroVolt, Slack RCE, Teams zero-click, V8 snapshot backdoor, Discord
---

# Case Studies

In-depth technical analysis of landmark Electron security findings. Each study covers the discovery methodology, technical chain, and lessons for future research.

---

## Featured Studies

<div class="es-card-grid">

<div class="es-card">
<div class="es-card-title">ElectroVolt — Black Hat 2022</div>
<div class="es-card-desc">Aaditya Purani's systematic IPC vulnerability methodology. Found RCE in Mattermost, Bitwarden, GitHub Desktop, and others using a repeatable pattern.</div>
<div class="es-card-meta"><span class="badge badge-critical">Multiple RCE</span> <span class="badge badge-info">2022</span></div>
</div>

<div class="es-card">
<div class="es-card-title">Slack RCE Chain</div>
<div class="es-card-desc">Oskars Vegeris's $30,000 zero-click Slack RCE. Stored XSS in workspace metadata → IPC → shell.openExternal → protocol handler RCE.</div>
<div class="es-card-meta"><span class="badge badge-critical">$30,000</span> <span class="badge badge-info">2021</span></div>
</div>

<div class="es-card">
<div class="es-card-title">Teams Zero-Click RCE</div>
<div class="es-card-desc">Microsoft Teams zero-click RCE via chat message content. Same fundamental pattern as Slack — cross-app validation of the stored XSS → openExternal chain.</div>
<div class="es-card-meta"><span class="badge badge-critical">Zero-click</span> <span class="badge badge-info">2021</span></div>
</div>

<div class="es-card">
<div class="es-card-title">V8 Snapshot Backdooring</div>
<div class="es-card-desc">Trail of Bits demonstrating that V8 heap snapshots bypass ASAR integrity validation. Breaks 1Password's tamper protection model.</div>
<div class="es-card-meta"><span class="badge badge-high">CVE-2025-55305</span> <span class="badge badge-info">2025</span></div>
</div>

<div class="es-card">
<div class="es-card-title">Discord RCE Chain</div>
<div class="es-card-desc">Masato Kinugawa's complete Discord RCE chain. Markdown XSS → DiscordNative preload exposure → DANGEROUS_openExternal → cmd.exe.</div>
<div class="es-card-meta"><span class="badge badge-critical">$10,000</span> <span class="badge badge-info">2020</span></div>
</div>

</div>

---

## Key Themes Across Studies

### Theme 1: Server-Provided Content is Always Suspect

Every major Electron RCE started with server-provided content reaching the DOM without sanitization:

- Discord: chat messages
- Slack: workspace metadata  
- Teams: chat messages
- Signal: received messages
- Element: Matrix room messages

**Implication:** Any app that renders user-generated content is a candidate. Prioritize finding what server data reaches `innerHTML`.

### Theme 2: The Preload Bridge is the Critical Point

Whether the attack succeeds after XSS depends entirely on what the preload script exposes:

- Discord exposed the entire `DiscordNative` module (too much)
- Slack's preload exposed an `openURL` function without validation (too broad)
- Apps with narrow, validated contextBridge APIs survived the same XSS patterns

**Implication:** The preload script is the crown jewel of Electron security analysis. Read it first.

### Theme 3: Protocol Handlers Are Consistently Underestimated

`shell.openExternal` → OS protocol handler → RCE is the most reliable escalation endpoint:

- Discord → `DANGEROUS_openExternal` → `file://` execution
- Slack → link handler IPC → `shell.openExternal` → Windows protocol handler
- Teams → similar pattern

The OS has many protocol handlers that execute code. Passing attacker-controlled URLs to `shell.openExternal` without an allowlist is reliable RCE on every platform.

### Theme 4: Zero-Click is Achievable Because Content Auto-Renders

All major messaging app Electron RCEs were zero-click because:
1. Messages render automatically when the channel is loaded
2. No user interaction needed beyond receiving the message
3. An attacker in the same channel (or sending a DM) can trigger the chain

**Implication:** For any messaging Electron app, look for stored XSS in auto-rendered content.
