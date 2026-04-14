---
title: Oskars Vegeris
description: Zero-click RCE specialist — Slack $30,000 finding and Teams zero-click RCE research
---

# Oskars Vegeris

Oskars Vegeris is a Latvian security researcher who found the Slack zero-click RCE — the $30,000 HackerOne finding that put Electron collaboration app security on the map. His methodology targets the intersection of server-rendered content, link-opening mechanisms, and unvalidated protocol handlers. It finds bugs in every collaboration app he's applied it to.

---

## Slack HN-783877 — $30,000

The defining Electron security finding of 2021. The attack required:
- Attacker has admin access to a Slack workspace the victim uses
- Victim has Slack Desktop open

That's it. No phishing, no clicking, no interaction. The victim has to open Slack. When they do, code executes on their machine.

**The chain:**

1. Attacker (workspace admin) sets workspace name via Slack API: `Legitimate Corp<img src=x onerror=slackRCE()>`
2. Slack stores this on their servers
3. Victim opens Slack; workspace name is fetched and rendered
4. XSS fires in renderer — `slackRCE()` executes
5. `window.slackDesktop.openURL(attacker_url)` called (preload bridge)
6. IPC → `ipcMain.handle('open-url', ...)` → `shell.openExternal(attacker_url)`
7. OS dispatches to `ms-msdt://` protocol handler → Follina RCE

**Why it paid $30,000:** The difference between "victim clicks a malicious link" and "victim opens the app" is 100% exploitation rate. Zero-click at Slack's scale means millions of users automatically exploitable. The payout reflected that.

---

## Microsoft Teams Zero-Click RCE (2020-2021)

Same pattern, applied to Microsoft Teams (1.x, Electron-based). Reported through MSRC rather than a public program — payout details undisclosed. The attack was:

1. Send a malicious message to any Teams channel or direct message
2. XSS fires in Teams' Electron renderer when the message loads
3. Teams' link-opening IPC bridge called with attacker URL
4. `shell.openExternal` → protocol handler → RCE

The critical difference from Slack: Teams required admin access to set workspace metadata; the XSS was in chat message content. Lower barrier. Any Teams user who could message the victim could trigger it.

---

## The Methodology

Vegeris identified that collaboration apps share a structural pattern:

**What they all have:**
- Server-rendered content (messages, metadata, profiles)
- A link-opening mechanism that reaches `shell.openExternal`
- A preload bridge connecting them

**Where the gaps are:**
- Server metadata (workspace names, channel descriptions, user profiles) often has weaker sanitization than user message content
- Link-opening bridges often accept arbitrary URLs without scheme validation

**His process:**
1. Find server-rendered metadata that's displayed in the UI outside the main message feed
2. Identify the link-opening path (preload → IPC → `shell.openExternal`)
3. Find XSS in the metadata rendering
4. Verify the chain: metadata XSS → bridge → openExternal → protocol handler

The insight that workspace names/metadata have weaker sanitization than message content is the key. Teams have hardened message sanitization. They haven't always hardened everything else.

---

## Templates for Other Collaboration Apps

The Slack chain is worth trying against:
- Mattermost Desktop
- RocketChat Desktop  
- Basecamp Desktop
- Notion Desktop
- Figma Desktop
- Any app that renders server-provided content and opens links

The chain structure is identical. The specific XSS source and IPC handler names change. The pattern doesn't.

---

## Reading

- [Slack zero-click blog post](https://medium.com/@oskarsve) — technical breakdown
- [HackerOne HN-783877](https://hackerone.com/reports/783877) — report (limited public details)
- [GitHub: oskarsve](https://github.com/oskarsve)
