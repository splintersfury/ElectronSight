---
title: Aaditya Purani
description: ElectroVolt researcher — systematic IPC vulnerability methodology presented at Black Hat 2022
---

# Aaditya Purani

Aaditya Purani is the researcher behind ElectroVolt — a Black Hat 2022 talk that reframed how the security community thinks about Electron vulnerability research. The contribution wasn't finding a single bug; it was finding the same class of bug across multiple major apps simultaneously, and building a methodology that makes it repeatable.

---

## ElectroVolt (Black Hat 2022)

Before ElectroVolt, Electron security research was largely app-specific. You'd find a bug in Discord, write it up, move on. The bugs were similar but the analysis started from scratch each time.

ElectroVolt's insight: Electron apps share a structural pattern. The preload bridge, the IPC handler, the dangerous sink — they appear in the same configuration across different codebases. Systematize the enumeration, and you can find vulnerabilities at scale.

**The methodology:**

1. Extract the ASAR
2. Index all `ipcMain.on/handle` registrations — these are the privileged operations
3. Map all `exposeInMainWorld` calls — these are the attacker's access points
4. Cross-reference: which bridge functions reach which handlers, which handlers do something dangerous?
5. Find XSS — user-controlled data flowing to `innerHTML`, Markdown renderers
6. Validate the chain

**Apps found vulnerable with this approach:**
- Mattermost Desktop — XSS + `openExternal` without URL validation
- Bitwarden Desktop — IPC-accessible clipboard operations
- GitHub Desktop — protocol handler with attacker-controlled arguments
- Basecamp — Markdown rendering + exposed notification IPC
- Several others in coordinated disclosure

The same methodology, different apps. That's the point.

---

## Why It Mattered

The shift ElectroVolt caused:

**Before:** "Set `nodeIntegration: false`" and `contextIsolation: true`" — configuration-focused security advice.

**After:** "Validate what comes through your IPC handlers" — logic-focused security advice. Configuration is necessary but not sufficient.

An app can have perfect configuration settings and still have a Critical vulnerability if main process IPC handlers blindly trust renderer-supplied arguments. ElectroVolt made that argument concretely, with multiple high-profile apps as evidence.

---

## Reading

- [Black Hat 2022 talk abstract and slides](https://www.blackhat.com/us-22/briefings/schedule/index.html) — ElectroVolt: Hacking Popular Desktop Apps While Staying in the Electron
- [GitHub: electrovolt toolkit](https://github.com/aaditya-purani/electrovolt)
- [purani.dev](https://aaditya-purani.github.io/) — research blog
