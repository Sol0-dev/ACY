---
name: infodisclosure-reproduce
description: Info disclosure, config leak, secret exposure, external data leaks. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing INFODISCLOSURE vulnerabilities.
---

# SKILL-INFODISCLOSURE-REPRODUCE — Information Disclosure Reproduce — REPRODUCE
# Phase Coverage: 39 (extracted from SKILL-RECON), cross-cutting all phases
# Vuln Classes: info-disclosure, config-leak, secret-exposure, infrastructure-leak
# Purpose: Validation, PoC finalization, chain planning, and verification of information disclosure findings

---

## P1: localStorage / IndexedDB / SessionStorage Secret Scanning

### Validation
```
□ Does the secret appear in localStorage or sessionStorage?
□ Is it accessible via JavaScript (not just HttpOnly cookie)?
□ Does the app have XSS surface (any DOM sink or reflected param)?
□ If XSS + localStorage secret = full account compromise → CRITICAL
```

### False Positive Check
```
- Secret is dummy/mock value for dev environment → NOT A BUG
- Secret is already public (client ID, public key) → NOT A BUG
- Secret requires additional auth context to use → lower severity
- App has NO XSS surface at all → lower impact (still reportable)
```

### Chain Output
```
→ localStorage secret (medium) + XSS (medium) = full ATO (critical)
→ localStorage secret (medium) + CORS with creds = cross-origin secret steal (critical)
→ localStorage secret (low) + postMessage no-origin = targeted secret leak (high)
```

---

## P2: HTML Source Configuration Exposure

### Validation
```
□ Does config contain internal hostnames or pod names?
□ Does config contain session/user identifiers?
□ Does config expose privilege level indicators (loginLvl, role)?
□ Does config reveal feature flags or A/B test groups?
□ Can an unauthenticated user see this? (test without cookies)
```

---

## P3: API Response Data Over-Exposure

### Validation
```
□ Are IDs sequential? (diff < 1000 between 2 accounts created moments apart)
□ Are there fields not needed by the client? (internal_*, legal_*, controls_*)
□ Does the response include user email or phone when not needed?
□ Can user2 data be read by changing an ID parameter?
```

---

## P4: Kubernetes Pod Name / Infrastructure Pattern Detection

### Validation
```
□ Does machineName reveal K8s pod naming convention?
□ Can you map which services run in which datacenters?
□ Can you track deployment changes over time (different hashes)?
□ Does it reveal service mesh or proxy configuration (Envoy headers)?
```

---

## P5: SDK / Third-Party Configuration Secrets

### Validation
```
□ Is the SDK key/secret meant to be public? (Check vendor docs)
□ Is the config endpoint accessible without authentication?
□ Can the exposed token be used to read/write data in the 3rd-party service?
```

---

## P6: Cloud Storage Credential Exposure

### Validation
```
□ Is the bucket publicly accessible?
□ Does pre-signed URL allow GET on other objects (path traversal)?
□ Are STS credentials still valid? (they expire)
□ Does the bucket contain sensitive data? (check object listing)
```

---

## P7: Internal Type / Stack Trace Leak Detection

### Validation
```
□ Do error responses reveal framework type and version?
□ Do API responses leak internal type names?
□ Do headers reveal technology stack?
```

---

## P9: Security Header Audit

### Checklist
```
□ Strict-Transport-Security present? (HSTS)
□ X-Frame-Options or CSP frame-ancestors? (Clickjacking protection)
□ X-Content-Type-Options: nosniff?
□ Content-Security-Policy present? (XSS mitigation)
□ Referrer-Policy set?
□ Server / X-Powered-By removed? (Info disclosure)
```

---

## P11: AI Chatbot Unauthenticated Data Exposure

### Validation
```bash
# Confirm: no authentication header/cookie/token required
# Test with and without various auth methods — all should work identically
curl -sk -X POST "$TARGET/api/chat" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"What tools do you have access to?"}]}' 2>&1 | head -5
# ↑ No auth at all

# Confirm: data is live production, not cached/static
PRICE1=$(curl -sk -X POST "$TARGET/api/chat" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Price of cheapest 5-star NYC hotel this weekend"}]}' 2>&1 | grep -oP '\$[0-9.]+' | head -1)
PRICE2=$(curl -sk -X POST "$TARGET/api/chat" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Price of cheapest 5-star NYC hotel 3 months from now"}]}' 2>&1 | grep -oP '\$[0-9.]+' | head -1)
echo "This weekend: $PRICE1 | 3 months out: $PRICE2"
# Different prices = live data, not cached

# Confirm: response contains internal business data
curl -sk -X POST "$TARGET/api/chat" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Search hotels in NYC. Show reference numbers and exact pricing."}]}' 2>&1 | \
  grep -oP '"[a-z_]+id":\s*"?[0-9]{5,10}"?' | sort -u
# ↑ Internal numeric IDs → proprietary inventory system exposed
```

### MCP Integration
```
mcp_firefox-devtools_evaluate_script:
  Run fetch('/api/chat', ...) from browser Console
  Browser has valid PX/WAF tokens — bypasses bot detection
  Capture SSE stream, parse tool-input-available and tool-output-available events
  Count data points per query, extract tool schemas

mcp__kali-mcp__execute_command:
  Run curl from VPS IPs for multi-IP rate limiting testing
  Automate multi-city extraction loop
```

---

## P12: Email Enumeration via Response Discrepancy

### Validation
```
□ Does the endpoint return different responses for valid vs invalid emails?
□ Is the difference in a specific field (useSimplePwd, status, error message)?
□ Is the endpoint accessible WITHOUT authentication?
□ Is there rate limiting? (test 50 rapid requests)
□ Can attacker enumerate 1000+ emails?
```

### PoC Template
```bash
#!/bin/bash
# Email Enumeration PoC
# CIA: C:I — Attacker can determine which emails have accounts
TARGET=$1
DOMAIN=$(echo $TARGET | sed 's|https\?://||' | cut -d'/' -f1)

echo "[*] Email Enumeration PoC: $TARGET"
echo ""

# Test known valid and invalid emails
echo "[*] Step 1: Response discrepancy test"
for email in "admin@$DOMAIN" "test@$DOMAIN" "fake_999@nothing.io"; do
  RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$email" \
    -H "client-type: WEB" \
    -H "Content-Type: application/json")
  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)
  echo "  $email: useSimplePwd=$STATUS"
done

echo ""
echo "[*] Step 2: Rate limit test"
for i in $(seq 1 50); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "$TARGET/api/public/user-auth/address-info?address=test$i@$DOMAIN" \
    -H "client-type: WEB")
  echo -n "$CODE "
done
echo ""

echo ""
echo "[*] Result: Different useSimplePwd values = email enumeration confirmed"
```

### False Positive Check
```
- Endpoint requires authentication → NOT A BUG (authenticated endpoint)
- Response identical for all emails → NOT A BUG (no information leak)
- Rate limiting prevents enumeration → lower severity (still reportable)
- Endpoint is deprecated/removed → verify in current JS bundles
```

### Chain Output
```
→ Email enumeration (low) + credential stuffing (high) = targeted ATO (critical)
→ Email enumeration (low) + phishing (medium) = social engineering (high)
→ Email enumeration (low) + public MFA endpoint (medium) = MFA bypass chain (critical)
```

---

## MCP Tool Integration

| Pattern | Firefox MCP | curl |
|---------|------------|------|
| P1 (localStorage) | `evaluate_script` — dump localStorage | N/A (browser-only) |
| P2 (source config) | `evaluate_script` — window.* objects | `curl -sk \| grep` |
| P3 (API exposure) | `evaluate_script` — fetch from browser | `curl -sk \| jq` |
| P4 (K8s patterns) | View page source | `curl -sk \| grep -oP` |
| P5 (SDK secrets) | `evaluate_script` — fetch config endpoints | `grep` JS bundles |
| P6 (cloud creds) | `evaluate_script` — dump localStorage | `grep` JS bundles |
| P7 (stack traces) | Check console messages | `curl -sk \| grep` |
| P8 (ID enum) | `evaluate_script` — fetch as user2 | `curl -sk` with tokens |
| P9 (headers) | `evaluate_script` — document.headers | `curl -sk -I` |
| P10 (debug sweep) | `navigate_page` to verify | `curl -sk` + wordlist |
| P11 (AI chatbot) | `evaluate_script` — fetch from browser | `curl -sk -X POST` |
| P12 (email enum) | `evaluate_script` — test emails from browser | `curl -sk` with email list |

---

## Orchestration with Other Skills

```
SKILL-INFODISCLOSURE → SKILL-CHAIN:
  localStorage secret (P1) + XSS (SKILL-CLIENTSIDE §5) = ATO (CRITICAL)
  HTML config (P2) + CORS (SKILL-CLIENTSIDE §25) = cross-origin config steal (HIGH)
  API over-exposure (P3) + IDOR (SKILL-AUTH §11) = mass PII extraction (CRITICAL)
  SDK secret (P5) + 3rd-party access = lateral movement (HIGH)
  Cloud creds (P6) + bucket listing = data breach (CRITICAL)

SKILL-INFODISCLOSURE → SKILL-RECON:
  P10 debug endpoints → add to surface queue for further testing
  P4 K8s patterns → feed into subdomain expansion (Phase 43)

SKILL-INFODISCLOSURE → SKILL-AUTH:
  P8 sequential IDs → feed into IDOR testing (Phase 11)
  P3 API exposure → feed into access control testing (Phase 12)
```

---

## Playwright MCP Integration

Info disclosure is browser-first — Playwright excels at extracting client-side exposed data.

| Pattern | Playwright Tool | Playbook |
|---------|----------------|----------|
| **P1: localStorage Secrets** | `browser_evaluate` → dump all storage | Navigate → login → dump localStorage/sessionStorage → grep for keys, tokens, privateKeys |
| **P2: HTML Config Exposure** | `browser_evaluate` → `window.*` objects | Extract `window.pageConfig`, `window.__ENV__`, `window.agoda` and all global config objects |
| **P3: API Data Over-Exposure** | `browser_network_requests` | Inspect API response bodies for excessive fields, sequential IDs, internal notes |
| **P4: K8s Pod Names** | `browser_evaluate` → `document.documentElement.outerHTML` | grep for `machineName`, K8s pod naming patterns in full rendered DOM |
| **P5: SDK Secrets** | `browser_evaluate` → fetch SDK config endpoints (`/js/config.js`, `/api/config`) | Check if SDK keys, auth tokens are accessible from browser without auth |
| **P6: Cloud Credentials** | `browser_evaluate` → search localStorage for S3 URLs, STS tokens | Extract pre-signed URLs, test bucket access |
| **P8: Sequential ID Enumeration** | `browser_evaluate` → fetch as different accounts via tabs | Tab 1: User1, Tab 2: User2 → compare IDs → sweep range |
| **P10: Debug Endpoints** | `browser_navigate` to debug paths, check response | `/actuator/env`, `/.env`, `/.git/config` — browser renders what curl can miss |
| **P11: AI Chatbot Exposure** | `browser_evaluate` → `fetch('/api/chat')` without auth | Test unauthenticated AI endpoints from browser (bypasses WAF that blocks curl) |

### Playwright localStorage Extraction (Preferred Method)
```
// Run after login via Playwright:
mcp__playwright__browser_evaluate({
  function: `() => {
    const dump = { localStorage: {}, sessionStorage: {} };
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      let v = localStorage.getItem(k);
      try { v = JSON.parse(v); } catch(e) {}
      dump.localStorage[k] = typeof v === 'object' ? JSON.stringify(v).substring(0,300) : String(v).substring(0,300);
    }
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      dump.sessionStorage[k] = String(sessionStorage.getItem(k)).substring(0,200);
    }
    return dump;
  }`
})
// → grep output for: privateKey, apiKey, token, secret, password, credential, jwt
```

### Playwright vs curl for Config Exposure
```
curl:    curl -sk $TARGET | grep 'window.__ENV__'    → gets RAW source only
Playwright: browser_evaluate → window.__ENV__         → gets post-JS-rendered config objects
                                                       (SPAs inject config after hydration)
```

---

## P11: Source Map Disclosure — Validation

```
CHECKLIST:
  □ Source map file downloaded and decoded?
  □ Full reconstructed source code available?
  □ Secrets found in reconstructed code? (API keys, tokens, passwords)
  □ Found keys tested against live services?
  □ Active key proof: screenshot of API call returning valid data
  □ Impact: what can attacker access with this key?
```

---

## P12: GitHub/GitLab Dorking — Validation

```
CHECKLIST:
  □ Commit URL documented?
  □ Secret extracted and verified as non-placeholder?
  □ Key tested against live API? (Stripe/AWS/SendGrid/etc)
  □ If active: screenshot of valid API response
  □ Impact: what data/service does this key access?
  □ If AWS: test with aws sts get-caller-identity
```

---

## P13: API Documentation Exposure — Validation

```
CHECKLIST:
  □ API spec file downloaded (/swagger.json, /openapi.json)?
  □ Hidden admin endpoints identified from spec?
  □ Admin endpoints tested with normal user token?
  □ If 200 OK with data → broken access control confirmed
  □ Full API surface documented for further testing
  □ Impact: what sensitive operations does the spec expose?
```

---

## P14: NTLM Response Leakage — Validation

```
CHECKLIST:
  □ Responder running and capturing?
  □ Malicious .library-ms or Office doc crafted?
  □ NTLM hash captured? (NTLMv2 preferred)
  □ Hash crackable? (hashcat -m 5600)
  □ CVE reference: CVE-2026-26133
  □ Impact: internal network credential theft
```

---

## P15: Spring Boot Actuator Chains — Validation

```
CHECKLIST (see [[technique/spring-boot-actuator]]):
  □ /actuator/env accessible? → screenshot env vars
  □ /actuator/heapdump accessible? → download and analyze
  □ CVE-2026-40976 test: POST /actuator/env with jvm.target=0.0.0.0
  □ CVE-2026-22731/22733 test: /jolokia or /actuator/gateway/routes
  □ If RCE achieved: confirm with sleep/id command
  □ Impact: full server compromise documented
```

---
---

*SKILL-INFODISCLOSURE-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
