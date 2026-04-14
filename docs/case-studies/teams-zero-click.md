---
title: Teams Zero-Click RCE
description: Microsoft Teams zero-click RCE via chat message content — same pattern as Slack, enterprise-scale impact
---

# Microsoft Teams Zero-Click RCE

If the Slack zero-click was the bug bounty world's wake-up moment for Electron security, Teams was the enterprise world's. The same fundamental chain — chat content XSS → preload bridge → shell.openExternal → protocol handler — but with a lower barrier for attack and a user base an order of magnitude larger.

Oskars Vegeris found it in 2020-2021 and reported it through Microsoft Security Response Center. Unlike the Slack finding, payout details were never made public. The technical details remain partially undisclosed, but the attack pattern has been corroborated through public descriptions and is consistent with what we know about Teams' architecture at the time.

---

## How It Differed From Slack

| Aspect | Slack | Teams |
|--------|-------|-------|
| Disclosure | HackerOne (public) | MSRC (private) |
| Payout | $30,000 | Undisclosed |
| Who could trigger | Workspace admins (controlled workspace name) | Any Teams message sender |
| User base affected | Millions | Hundreds of millions |

The lower attacker requirement is significant. The Slack bug required admin access to set the malicious workspace name. The Teams XSS was in chat message content — anyone who can send you a message can trigger it. In Teams, that means anyone in a shared channel, any DM contact, any external user with guest access.

---

## The Attack Chain

Teams 1.x was an Electron app. It rendered rich message content in its renderer process. The message rendering pipeline had gaps — specific constructs could survive sanitization and execute JavaScript.

```
Attacker sends a crafted Teams message to victim
         │
         └─→ Stored on Microsoft's servers
                      │
                      └─→ Victim opens Teams (or Teams is already open)
                                   │
                                   └─→ Message renders in renderer
                                                │
                                                └─→ XSS fires
                                                         │
                                                         └─→ Teams internal URL handler called
                                                                  │
                                                                  └─→ shell.openExternal(attacker_url)
                                                                           │
                                                                           └─→ Windows protocol handler → RCE
```

Zero interaction from the victim beyond receiving the message. In some scenarios, no interaction at all if Teams is already open in the background and the message loads in a monitored channel.

---

## The Enterprise Scale Problem

Teams is used by:
- US Department of Defense and government agencies
- Healthcare systems with patient data
- Financial institutions with trading systems
- Critical infrastructure operators
- Essentially every large enterprise that bought Office 365

A zero-click RCE in Teams isn't a consumer app compromise. It's a potential entry point into the most sensitive corporate networks on the planet, without requiring phishing, without requiring any click, delivered through a channel the victim expects and trusts.

That context is why Microsoft patched this quickly and why MSRC handles it privately rather than through a public bounty program. The patch involved strengthened sanitization in message rendering, URL validation before `shell.openExternal` calls, and additional IPC handler hardening. Teams 2.x moved to WebView2 rather than Electron, changing the security model significantly.

---

## The Repeating Pattern in Collaboration Apps

Teams and Slack are two instances of the same template. If you're auditing any Electron-based collaboration or messaging app, run this check:

```bash
# 1. Chat/channel message rendering:
grep -r "channel\|message\|render" --include="*.js" . | \
  grep -E "innerHTML|dangerouslySetInnerHTML|marked\b|DOMPurify" | grep -v node_modules

# 2. Link/URL opening mechanism:
grep -r "openURL\|openLink\|openExternal\|open-url" --include="*.js" . | grep -v node_modules

# 3. The bridge between them:
grep -r "ipcRenderer.*open\|invoke.*url\|invoke.*link" --include="*.js" . | grep -v node_modules
```

Apps worth running this against: Mattermost Desktop, RocketChat Desktop, Basecamp Desktop, Notion Desktop, Figma Desktop. The pattern is generic. The app changes, the template doesn't.

For enterprise apps specifically, the absence of a public bug bounty doesn't mean no reward. MSRC, Cisco PSIRT, and similar programs pay competitive amounts through coordinated disclosure. The payout isn't publicly announced, but the research is worth doing.
