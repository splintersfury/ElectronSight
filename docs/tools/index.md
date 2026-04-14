---
title: Tools
description: Security tools for Electron app analysis — Electronegativity, asar CLI, DevTools, fuses, electron-builder
---

# Tools

Essential tools for Electron security research, from static analysis to runtime inspection.

---

## Quick Reference

| Tool | Purpose | Install |
|------|---------|---------|
| [Electronegativity](electronegativity.md) | Static analysis — finds misconfigs and dangerous patterns | `npm install -g @doyensec/electronegativity` |
| [asar CLI](asar-cli.md) | Extract, list, and create ASAR archives | `npm install -g @electron/asar` |
| [DevTools](devtools.md) | Runtime inspection — JS REPL, network, storage | Built into Electron (Ctrl+Shift+I) |
| [@electron/fuses](fuses-tool.md) | Read/write Electron fuse states | `npm install @electron/fuses` |
| [electron-builder](electron-builder.md) | Build tool — audit security configuration | `npm install electron-builder` |

---

## Workflow Integration

```
Target acquired
       │
       ▼
[asar extract]          ← extract source from ASAR
       │
       ▼
[Electronegativity]     ← automated misconfig detection
       │
       ▼
[@electron/fuses read]  ← check fuse state
       │
       ▼
[Manual code review]    ← trace source-to-sink chains
       │
       ▼
[DevTools]             ← runtime validation
       │
       ▼
[PoC development]      ← build the exploit
```

---

## Additional Tools

### Node.js Built-ins (for analysis)

```bash
# Read package.json from extracted app:
node -e "const p = require('./package.json'); console.log(p.main, p.version)"

# Find all require() calls:
node -e "
const fs = require('fs');
const src = fs.readFileSync('./main.js', 'utf8');
const requires = [...src.matchAll(/require\(['\"](.*?)['\"]\)/g)].map(m => m[1]);
console.log(requires.join('\n'));
"
```

### ripgrep / grep patterns

```bash
# All security-critical patterns in one pass:
rg "nodeIntegration|contextIsolation|sandbox|webSecurity|openExternal|exec\b|eval\b|innerHTML" \
  --type js -l app/

# IPC surface enumeration:
rg "ipcMain\.(on|handle)|ipcRenderer\.(send|invoke)|exposeInMainWorld" --type js app/
```

### Chrome DevTools Protocol (CDP)

When DevTools are accessible in a running app:

```bash
# If --inspect is active (check running processes):
lsof -i :9229   # or netstat -tlnp | grep 9229

# Connect with cdp client:
node -e "
const CDP = require('chrome-remote-interface');
CDP(async (client) => {
  const { Runtime } = client;
  await Runtime.enable();
  const result = await Runtime.evaluate({ expression: 'process.versions' });
  console.log(result.result.value);
  client.close();
});
"
```
