---
title: Masato Kinugawa
description: Security researcher behind Discord CVE-2020-15174 — Electron XSS and IPC exploitation expert
---

# Masato Kinugawa

Masato Kinugawa (@mksben) is a Japanese security researcher with exceptional depth in browser security and XSS exploitation. His work applies the same rigor you'd expect from browser engine research — parser differentials, mutation XSS, execution-path analysis — to application-layer targets including Electron apps.

He's the kind of researcher who doesn't stop at "I found XSS." He keeps pulling the thread until the chain is complete.

---

## Discord CVE-2020-15174 — $10,000

The Discord RCE is his most well-known Electron finding, and it's instructive because of *how* he found it. The vulnerability wasn't subtle. `DANGEROUS_openExternal` was right there in Discord's internal module, named by developers who clearly knew it was risky. The insight was recognizing that function names are a research signal.

**The chain:**

1. Discord's Markdown renderer allowed HTML injection in message content
2. Discord's preload exposed `DiscordNative.nativeModules.requireModule()`
3. `discord_utils` module contained `DANGEROUS_openExternal(url)` — no URL validation
4. `contextIsolation: false` meant XSS could call `window.DiscordNative` directly

```javascript
// The payload — two lines, after XSS fires:
const utils = window.DiscordNative.nativeModules.requireModule('discord_utils');
utils.DANGEROUS_openExternal('file:///C:/Windows/System32/cmd.exe');
```

The vulnerability is zero-click: send a malicious message, victim loads Discord, cmd.exe opens.

**The grep that probably found it:**
```bash
strings discord_utils.node | grep -i "DANGEROUS\|exec\|spawn\|open"
```

---

## The Research Methodology

His approach to Electron targets follows a consistent pattern:

1. Extract the ASAR — read all JavaScript source systematically
2. Find contextBridge exposures — catalog everything accessible from the renderer
3. Grep for developer-flagged dangerous functions — `DANGEROUS_`, `unsafe_`, `_internal`, `_raw`
4. Identify XSS vectors — trace user-controlled data to `innerHTML`, Markdown renderers
5. Chain the XSS to the flagged functions

Step 3 is the one that distinguishes his methodology. Most researchers look at XSS → sink. He also looks at what developers' own naming conventions reveal about where the guardrails are absent.

---

## Browser Engine Background

Before Electron, Masato built deep expertise in browser parser differentials:

- **Mutation XSS (mXSS)** — HTML that looks sanitized but mutates when inserted into the DOM. The primary mechanism behind historical DOMPurify bypasses.
- **Parser differential attacks** — HTML that DOMPurify parses differently than Chromium's Blink. If the parser disagrees on what's safe, the sanitizer has gaps.
- **JavaScript-less XSS** — HTML constructs that execute code without `<script>` tags.

These techniques translate directly to Electron. Markdown-rendering Electron apps run DOMPurify to block XSS — mXSS bypasses it. Collaboration apps render HTML in Chromium — parser differentials apply.

---

## Reading

- [mksben.l0.cm](https://mksben.l0.cm) — technical blog, worth reading end-to-end
- [HackerOne #855618](https://hackerone.com/reports/855618) — Discord RCE report
- [@mksben on Twitter/X](https://twitter.com/mksben)
