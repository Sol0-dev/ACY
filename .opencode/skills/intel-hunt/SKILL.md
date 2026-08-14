---
name: intel-hunt
description: JS intelligence, technology fingerprinting, version extraction, asset attribution. After DISCOVERY finds candidates — active testing, payload firing, CVE verification. Use when testing INTEL vulnerabilities.
---

# SKILL-INTEL-HUNT — JS Intelligence & App Understanding — HUNT
# Phase Coverage: JS-3 through JS-8
# Purpose: Analyze collected JavaScript files for secrets, credentials, auth flows,
#          DOM XSS sinks/sources, postMessage handlers, prototype pollution, and
#          service worker attack surfaces.

---

## Phase JS-3: Secrets and Credentials

```bash
# Pattern-based secret scan
grep -rhioP "(api[_-]?key|apikey|secret|token|password|passwd|auth|bearer|access_key)['\"\s:=]+['\"][a-zA-Z0-9+/=_\-]{8,}" \
  *.js | sort -u | tee ../js_secrets.txt

# AWS key patterns
grep -rhoP "AKIA[0-9A-Z]{16}" *.js | tee -a ../js_secrets.txt

# GCP API key patterns (NEW — from Agoda F1)
grep -rhoP "AIza[0-9A-Za-z_-]{35}" *.js | tee -a ../js_secrets.txt

# Generic high-entropy strings
python3 - << 'EOF'
import re, math, glob

def entropy(s):
    if not s: return 0
    counts = {}
    for c in s: counts[c] = counts.get(c, 0) + 1
    return -sum((v/len(s)) * math.log2(v/len(s)) for v in counts.values())

high_ent = []
for f in glob.glob("*.js"):
    for m in re.finditer(r'["\x27]([A-Za-z0-9+/=_\-]{20,})["\x27]',
                         open(f,'r',errors='ignore').read()):
        s = m.group(1)
        if entropy(s) > 4.2:
            high_ent.append(f"{f}: {s[:80]}")

for h in set(high_ent):
    print(h)
EOF
```

### Phase JS-3b: Browser Storage Secret Extraction (NEW)

```
SOURCE: Coinhako C1 — ECDSA private key + API key in localStorage plaintext
        This technique found a CRITICAL bug. Run this on EVERY target.

IMPACT: Any XSS on the origin can read localStorage → key exfil → full ATO
```

**Method 1: Firefox MCP evaluate_script (PREFERRED):**
```javascript
// mcp__firefox-devtools__evaluate_script
// After navigating to target and logging in:
() => {
  const results = { localStorage: {}, sessionStorage: {}, indexedDB: [] };
  
  // localStorage
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    const val = localStorage.getItem(key);
    let parsed = val;
    try { parsed = JSON.parse(val); } catch(e) {}
    results.localStorage[key] = typeof parsed === 'object' 
      ? JSON.stringify(parsed).substring(0, 300) 
      : String(val).substring(0, 300);
  }
  
  // sessionStorage  
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    results.sessionStorage[key] = String(sessionStorage.getItem(key)).substring(0, 200);
  }
  
  return results;
}
```

**Method 2: Check for structured secrets**
```bash
# After getting storage dump, flag secrets
echo "$STORAGE_DUMP" | grep -iE 'privateKey|apiKey|ECDS|secret|token|jwt|bearer|password|credential|mnemonic|seed|signing'
```

**Secret hit → immediate action:**
```
□ Secret found in localStorage → test if it grants API access
□ API key → curl API with key → does it work?
□ Private key → is there a corresponding public key endpoint?
□ Token → decode JWT → check expiry, scope, role
□ Save finding immediately if usable — CRITICAL or HIGH
```

### Phase JS-3c: HTML Source Config Extraction (NEW)

```
SOURCE: Agoda F1 — agoda.pageConfig exposes K8s pod names, sessionId, loginLvl
        Coinhako M6 — Talos platform exposes __ENV_CONFIG__ with Datadog, Mixpanel tokens
```

```bash
# Extract embedded configs from HTML source
curl -sk "$TARGET" | grep -oP '(window\.\w+Config|__\w+__|agoda\.\w+)\s*=\s*\{[^}]+\}' | head -10

# Check for base64-encoded config blobs
curl -sk "$TARGET" | grep -oP '__ENV_CONFIG__\s*=\s*"\K[^"]+' | base64 -d 2>/dev/null | jq . 2>/dev/null

# Flag sensitive fields
curl -sk "$TARGET" | grep -oP '(machineName|podName|sessionId|memberId|loginLvl|token|apiKey)"\s*:\s*"[^"]+"'
```

## Phase JS-4: Auth Flow and Token Handling Analysis

```bash
# How does the app handle auth tokens?
grep -rhi "localStorage\|sessionStorage\|cookie\|token\|jwt\|bearer\|authorization" *.js \
  | grep -iP "set|get|store|save|load|retrieve" | tee ../js_token_handling.txt

# Where are tokens sent?
grep -rhi "Authorization\|X-Auth\|X-Token\|Bearer\|apiKey" *.js \
  | grep -iP "header|fetch|axios|xhr|request" | tee ../js_auth_headers.txt

# Token decode/verify logic (client-side = bypass target)
grep -rhi "jwt.verify\|jwt.decode\|atob\|base64decode\|parseJwt\|decode_token" *.js \
  | tee ../js_jwt_logic.txt

# Client-side role/permission checks (bypass targets)
grep -rhi "isAdmin\|role\|permission\|privilege\|canAccess\|isAuthorized\|hasRole" *.js \
  | tee ../js_access_control.txt

# JS-to-Vuln Mapping from Token Analysis:
#   localStorage.setItem('token') → jwt, auth-bypass (token in localStorage = XSS exfil)
#   if (user.role === 'admin') → access-control bypass (client-side gate)
#   jwt.decode() client-side → jwt (no server verify)
#   cookie HttpOnly missing → xss (token stealable)
```

## Phase JS-5: DOM XSS Sink/Source Mapping

```bash
SINKS=(
  "innerHTML" "outerHTML" "document.write" "document.writeln"
  "eval(" "setTimeout(" "setInterval(" "Function(" "execScript"
  ".src=" ".href=" ".action=" "location.href" "location.replace"
  "insertAdjacentHTML" "insertAdjacentElement" "createContextualFragment"
)
for sink in "${SINKS[@]}"; do
  grep -rnH "$sink" *.js 2>/dev/null | grep -v "^Binary" | head -5 \
    | tee -a ../dom_sinks.txt
done

grep -rhi "location.search\|location.hash\|document.URL\|document.referrer\
           \|URLSearchParams\|window.name\|postMessage" *.js | tee ../dom_sources.txt

# Source → Sink path detection
python3 - << 'EOF'
import re, glob
sources = ["location.search", "location.hash", "document.URL", "URLSearchParams",
           "window.name", "document.referrer", "postMessage"]
sinks   = ["innerHTML", "outerHTML", "document.write", "eval(", "setTimeout(", ".src=",
           ".href=", "location.href", "insertAdjacentHTML", "Function("]
for f in glob.glob("*.js"):
    content = open(f,'r',errors='ignore').read()
    for src in sources:
        if src in content:
            for sink in sinks:
                if sink in content:
                    print(f"[POTENTIAL DOM XSS] {f}: source={src} → sink={sink}")
                    break
EOF
# → Each hit adds to XSS test queue with specific payload target
```

## Phase JS-6: PostMessage and Cross-Origin Attacks

```bash
grep -rhi "addEventListener.*message\|onmessage\|postMessage" *.js \
  | tee ../postmessage_handlers.txt

python3 - << 'EOF'
import re, glob
for f in glob.glob("*.js"):
    content = open(f,'r',errors='ignore').read()
    for m in re.finditer(r"addEventListener\(['\"]message['\"].*?}\s*[,;)]", content, re.DOTALL):
        block = m.group(0)
        has_origin_check = bool(re.search(r'event\.origin|message\.origin|origin\s*[=!]==', block))
        print(f"[{'ORIGIN CHECK OK' if has_origin_check else 'NO ORIGIN CHECK — VULNERABLE'}] {f}")
        if not has_origin_check:
            print(f"  SINK: {block[:200].strip()}")
            print(f"  → Add to postmessage test queue — chain with XSS")
EOF
```

## Phase JS-7: Prototype Pollution Sources

```bash
grep -rhi "Object.assign\|merge(\|deepMerge\|extend(\|_.merge\|jQuery.extend\
           \|__proto__\|constructor.prototype" *.js | tee ../pp_candidates.txt

grep -rhi "location.search\|queryString\|qs.parse\|query\." *.js \
  | grep -v "^Binary" | head -20 | tee -a ../pp_candidates.txt

# PP → Logic Flaw connection:
# If PP via merge → pollutes isAdmin → access-control bypass
# If PP via query → pollutes template vars → XSS or SSTI
# Add all merge points to prototype-pollution test queue
```

## Phase JS-8: Service Worker and Cache Attack Surface

```bash
grep -rhi "serviceWorker\|registerServiceWorker\|sw.js\|service-worker.js" *.js \
  | tee ../serviceworker_refs.txt

grep -rhi "cache.put\|cache.add\|caches.open\|CacheStorage" *.js | tee ../cache_patterns.txt

for swpath in "/sw.js" "/service-worker.js" "/serviceworker.js" "/sw/sw.js" "/js/sw.js"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/sw_test.js "$TARGET$swpath")
  [[ "$S" == "200" ]] && grep -q "importScripts\|self.addEventListener\|FetchEvent" /tmp/sw_test.js \
    && echo "[SERVICE WORKER] Found: $TARGET$swpath" | tee -a ../serviceworker_refs.txt
done
```

---

## Phase JS-9: CVE Weaponization Gate (hand off to Phase 48)

```
TRIGGER: any confirmed tech + exact version from JS bundles, HTML config blobs,
         package files, or headers (jQuery 1.12.4, React 16.8.6, AngularJS 1.4.0...).
RULE: DO NOT proceed to generic vuln-class hunting until Phase 48 is invoked.
      CVE-first: an exploitable known CVE beats finding new bugs.

PROCEDURE:
  1. Collect every tech + exact version into essentials/TECH_FINGERPRINT.json and
     essentials/CVE_QUEUE.json.
  2. Run Phase 48 (CVE Weaponization Pipeline, AGENTS.md) for each confirmed version:
     NVD/OSV/GitHub Advisory → PoC search → pull patch diff → adapt → test with
     minimal viable payload first.
  3. Weaponize the highest-impact CVE first (RCE > SSRF > SQLi > XSS).
  4. After the gate clears, return to the JS Intelligence → Action Decision Matrix and
     continue Phase 2 surface classification.
```

---

## JS Intelligence → Action Decision Matrix

After ALL JS phases, write ~/agents/finetune/notes/{SLUG}/js_intelligence.md:

| JS Finding | Attack Queue Entry |
|------------|-------------------|
| Hidden endpoint | add to surface queue (HIGH PRIORITY) |
| Client-side role check | auth-bypass + IDOR test queue |
| localStorage token | xss test queue (token stealable via XSS) |
| DOM source/sink pair | xss test queue with specific payload target |
| postMessage no origin | postmessage test queue + chain with XSS |
| Found secret/API key | test validity immediately |
| Hardcoded token | auth-bypass test immediately |
| Merge/deepMerge | prototype-pollution test queue |
| Service worker found | service-worker test queue |
| Admin/debug routes | access-control test queue (HIGH PRIORITY) |
| client price=qty*price | business-logic test (server recalculates?) |
| if(step >= 3) check | business-logic step bypass test |
| if(maxQty < 10) | business-logic API limit test |
| if(email.endsWith()) | auth-bypass email validation bypass |
| setTimeout(logout,...) | session-mgmt (client-only timeout) |
| jwt.decode() client | jwt test queue (is there server verify?) |
| fetch to AI/LLM endpoint | prompt-injection test queue |
| new WebAssembly.Instance | wasm test queue (memory safety) |
| chrome.runtime / browser.runtime | browser-extension test queue |
| importScripts() in SW | service-worker import chain |
| Bundle/package version confirmed | CVE queue → Phase 48 weaponization (CVE-first) |

JS-discovered surface = HIGHER CONFIDENCE TARGET than generic enumeration.
JS-discovered logic flaw = DIRECTLY TEST with Logic Flaw Engine.

---

*SKILL-INTEL-HUNT — Part of the acy Agentic Security Research System v3.0*
*v4.3 addition: Phase JS-9 CVE Weaponization Gate — confirmed tech+version hands off to Phase 48 immediately after fingerprinting, before generic hunting*
