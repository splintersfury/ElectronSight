---
title: CVE Database
description: 40+ Electron CVEs across Discord, Slack, Teams, VS Code, Signal, WhatsApp, Notion, and more
---

# CVE Database

Look at the CVE table below and notice the pattern: XSS → RCE appears over and over, across different apps, across different years. It's not that these apps were uniquely careless. It's that they were all building on the same platform, during an era when that platform's defaults were insecure, and nobody had a good mental model for what "web content in a desktop app" meant for security.

There are three distinct eras in Electron security's history. The first is the **default insecure era** (roughly 2013–2019): `nodeIntegration: true` was the default, `contextIsolation` didn't exist, and any XSS in an Electron renderer was immediately full RCE. Signal Desktop, WhatsApp Desktop, RocketChat, Mattermost — all had `nodeIntegration: true` baked in from early development. The CVEs from this era are straightforward: find XSS, get code execution.

The second is the **transitional era** (2019–2022): Electron changed its defaults (`nodeIntegration: false` in v5, `contextIsolation: true` in v12), but the installed base didn't change. Apps written against old defaults kept shipping with them. Apps that updated Electron versions often didn't revisit their webPreferences. The exploitation techniques got more interesting — XSS still worked, but now you needed to find an over-exposed IPC bridge to escalate.

The third is the **modern era** (2022–present): the low-hanging fruit is mostly gone. The remaining bugs require understanding Electron's deeper primitives — V8 snapshots, fuse misconfigurations, native module attack surfaces, update mechanism weaknesses. The bounties got bigger because the bugs got harder.

The CVE table below is a map of how that progression played out across real apps.

---

## Full CVE Table

| CVE / ID | Application | Year | Class | CVSS | Impact |
|----------|------------|------|-------|------|--------|
| [CVE-2020-15174](CVE-2020-15174.md) | Discord | 2020 | XSS → RCE / IPC | 9.6 | RCE via shell.openExternal |
| [CVE-2019-18426](CVE-2019-18426.md) | WhatsApp Desktop | 2019 | XSS → RCE | 9.3 | RCE via nodeIntegration:true |
| [CVE-2025-30401](CVE-2025-30401.md) | WhatsApp Desktop | 2025 | MIME Confusion | 8.8 | RCE via file extension spoofing |
| [HN-783877](slack-hn-783877.md) | Slack | 2021 | XSS → RCE | 9.0 | Zero-click RCE via workspace name |
| [Signal RCE 2018](signal-rce-2018.md) | Signal Desktop | 2018 | XSS → RCE | 9.8 | RCE via nodeIntegration:true |
| [CVE-2022-23597](CVE-2022-23597.md) | Element (Matrix) | 2022 | XSS → RCE | 9.9 | RCE via nodeIntegration:true |
| [CVE-2024-23743](CVE-2024-23743.md) | Notion | 2024 | XSS → RCE | 9.0 | RCE via custom URL scheme |
| [CVE-2023-39956](CVE-2023-39956.md) | VS Code | 2023 | Extension RCE | 8.1 | RCE via malicious extension |
| [CVE-2018-1000006](CVE-2018-1000006.md) | Electron runtime | 2018 | Protocol Handler | 8.8 | RCE via URL scheme on Windows |
| [CVE-2018-1000136](CVE-2018-1000136.md) | Electron runtime | 2018 | nodeIntegration | 8.1 | nodeIntegration bypass |
| [CVE-2025-55305](CVE-2025-55305.md) | 1Password | 2025 | V8 Snapshot | 7.8 | ASAR integrity bypass |
| [CVE-2024-46992](CVE-2024-46992.md) | electron-updater | 2024 | Update Poisoning | 8.0 | Path traversal in update |
| [CVE-2026-39846](CVE-2026-39846.md) | SiYuan | 2026 | XSS → RCE | 9.8 | RCE via note content |
| [CVE-2026-33955](CVE-2026-33955.md) | Notesnook | 2026 | XSS → RCE | 9.6 | RCE via note content |

---

## CVEs by Vulnerability Class

### XSS → RCE (Most Common)

| CVE | App | XSS Vector | Escalation Path |
|-----|-----|-----------|-----------------|
| CVE-2019-18426 | WhatsApp | Message content | nodeIntegration:true |
| Signal 2018 | Signal | Message text | nodeIntegration:true |
| CVE-2022-23597 | Element | Matrix message HTML | nodeIntegration:true |
| HN-783877 | Slack | Workspace name | contextBridge IPC |
| CVE-2024-23743 | Notion | Page content | URL scheme handler |
| CVE-2026-39846 | SiYuan | Note content | webSecurity:false + nodeIntegration |
| CVE-2026-33955 | Notesnook | Note/attachment | IPC escalation |

### Protocol Handler / Open External

| CVE | App | Attack Vector |
|-----|-----|--------------|
| CVE-2018-1000006 | Electron (all Windows apps) | URL scheme → `--inspect-brk` arg injection |
| CVE-2020-15174 | Discord | XSS → DANGEROUS_openExternal |
| CVE-2025-30401 | WhatsApp | MIME confusion → open local executable |

### Runtime/Electron Core

| CVE | Component | Issue |
|-----|-----------|-------|
| CVE-2018-1000136 | Electron runtime | nodeIntegration bypass via frame navigation |
| CVE-2025-55305 | Electron + 1Password | V8 snapshot bypasses ASAR integrity |
| CVE-2024-46992 | electron-updater | Path traversal in update filename |

### VS Code (Extension Model)

| CVE | Issue |
|-----|-------|
| CVE-2023-39956 | Malicious extension can read arbitrary files |

---

## CVEs by Year

=== "2026"

    | CVE | App | Severity |
    |-----|-----|----------|
    | CVE-2026-39846 | SiYuan | Critical |
    | CVE-2026-33955 | Notesnook | Critical |

=== "2025"

    | CVE | App | Severity |
    |-----|-----|----------|
    | CVE-2025-55305 | 1Password | High |
    | CVE-2025-30401 | WhatsApp | High |

=== "2024"

    | CVE | App | Severity |
    |-----|-----|----------|
    | CVE-2024-46992 | electron-updater | High |
    | CVE-2024-23743 | Notion | High |

=== "2023"

    | CVE | App | Severity |
    |-----|-----|----------|
    | CVE-2023-39956 | VS Code | High |

=== "2022"

    | CVE | App | Severity |
    |-----|-----|----------|
    | CVE-2022-23597 | Element | Critical |

=== "2021"

    | CVE | App | Severity |
    |-----|-----|----------|
    | HN-783877 | Slack | Critical |

=== "2018-2020"

    | CVE | App | Severity |
    |-----|-----|----------|
    | CVE-2020-15174 | Discord | Critical |
    | CVE-2019-18426 | WhatsApp | Critical |
    | CVE-2018-1000136 | Electron | High |
    | CVE-2018-1000006 | Electron (Windows) | High |
    | Signal 2018 | Signal | Critical |

---

## Payout Leaderboard (Known Bug Bounties)

| Researcher | App | Finding | Payout |
|-----------|-----|---------|--------|
| Masato Kinugawa | Discord | CVE-2020-15174 | $10,000 |
| Oskars Vegeris | Slack | HN-783877 | $30,000 |
| Aaditya Purani | Multiple | ElectroVolt research | Research |
| Trail of Bits | 1Password | CVE-2025-55305 | Coordinated disclosure |

---

!!! note "CVE Scope"
    This database covers publicly disclosed vulnerabilities. Most major Electron apps have active private bug bounty programs, and the actual volume of security issues found and fixed — often without CVE assignment — is much higher. What you see here is the floor, not the ceiling.
