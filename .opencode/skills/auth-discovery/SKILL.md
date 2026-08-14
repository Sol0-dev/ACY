---
name: auth-discovery
description: IDOR, access control, auth/session, JWT, OAuth, API versioning. Phase start — surface detection, parameter identification, initial probes. Use when testing AUTH vulnerabilities.
---

# SKILL-AUTH-DISCOVERY — Authentication & Authorization Discovery — DISCOVERY
# Phase Coverage: 11-15, 34
# Vuln Classes: IDOR, Access Control, Auth/Session, JWT, OAuth, API Versioning,
#               Privilege Escalation, Environment Variable Bypass
# Purpose: Discovery patterns for identity, authorization, and session management vulnerabilities

---

## Phase 11: IDOR / Broken Object Level Authorization — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns IDOR, or JS signals /api/users/{id}, /api/orders/{id}.
SURFACE TYPES: any endpoint that fetches/modifies user-specific objects by ID.
```

### Three IDOR Flavors ⭐
**Source:** [[raw-refs/tanvir-idor-15500-payout]]

Always classify which IDOR flavor you're facing — each needs different discovery techniques:

| Flavor | Description | Discovery Focus |
|--------|-------------|-----------------|
| **Horizontal IDOR** | Access another user's data at the same privilege level | Two-account testing: User A creates → User B accesses via ID change |
| **Vertical IDOR** | Access data at a higher privilege level | Role matrix: regular user → admin endpoints, header bypass, path traversal |
| **Blind IDOR** | Action succeeds but no visible response | Side channels: check secondary effects (email sent, order status changed, account deleted) |

### Beginner's IDOR Hunting Blueprint (5 Steps) ⭐
**Source:** [[raw-refs/tanvir-idor-15500-payout]] — $15,500 payout methodology

```
STEP 1: PICK A TARGET (Discovery)
  → Start with mid-size SaaS on HackerOne/Bugcrowd/Intigriti
  → NOT Google/Apple — less competition, same vulnerabilities
  → Filter for programs with wide scope and no IDOR restrictions

STEP 2: SET UP ENVIRONMENT
  → Burp Suite Community Edition (free) — intercept web traffic
  → Create TWO test accounts — ESSENTIAL for IDOR testing
  → Save both tokens in TARGET.env as USER1_TOKEN, USER2_TOKEN

STEP 3: MAP THE APPLICATION (as Account A)
  → Use EVERY feature: create data, upload files, send messages
  → Watch every API call in Burp — catalog ALL endpoints with IDs:
      /user/14377/profile    /invoice/88291    /document/4521/download
      /api/messages/thread/9923    /api/v1/projects/{id}/documents
  → Note ID formats: sequential numeric, UUID, hash, email-based, composite

STEP 4: TEST WITH ACCOUNT B
  → Switch to Account B's session/token
  → Try accessing ALL IDs found under Account A
  → Try incrementing/decrementing numbers, changing UUIDs
  → Try accessing admin endpoints with user token
  → KEY QUESTION: "Did Account B get information that should only belong to Account A?"
  → If yes → potential IDOR found → move to HUNT phase

STEP 5: CONFIRM & MEASURE IMPACT
  → Is the data PII? (email, phone, address, SSN, financial)
  → How many users affected? (sequential IDs = mass enumeration possible)
  → Is it read-only or read-write? (GET vs PUT/PATCH/DELETE)
  → Can it chain with other findings? (CORS, XSS, batch endpoints)
```

### The Developer Assumption Mindset ⭐
**Source:** [[raw-refs/tanvir-idor-15500-payout]]

> "What does the developer assume I won't do?"

- Developers assume you'll use only the frontend → test API directly
- Developers assume IDs are non-guessable → always check for alternate ID formats
- Developers assume authorization is handled by middleware → test every endpoint individually
- This mindset — curiosity + systematic thinking — is worth more than any tool

JS Signals:
- URL patterns with dynamic segments: /api/users/{id}, /api/orders/{id}, /api/accounts/{id}
- Client-side loops rendering user data by index
- API calls using user-supplied IDs in path or query string
- Admin panels listing users with "View" or "Edit" links containing sequential IDs
- Dual ID formats in responses: one hash-based and one numeric sequential ID

Endpoint Discovery:
- CRUD endpoints: GET/PUT/DELETE /api/resource/{id}
- Batch/list endpoints: /api/users, /api/orders, /api/resources
- UUID/hash IDs AND sequential numeric IDs in the same response
- WebSocket messages containing ID references
- GraphQL node IDs that may decode to sequential integers

Parameter Indicators:
- id, user_id, account_id, order_id, document_id, profile_id, customer_id
- uid, uuid, guid (may be hash-based or sequential)
- Internal IDs in hidden fields, data attributes, or response metadata

---

## Phase 12: Broken Access Control — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns access-control, or JS signals isAdmin client-side gates.
SURFACE TYPES: admin endpoints, privileged features, role-gated content.
```

**Discovery Patterns:**

JS Signals:
- Client-side admin checks: isAdmin, role === 'admin', user.role !== 'admin'
- Hidden admin UI elements toggled by role flags
- Conditional rendering based on user.role or user.isAdmin
- Frontend route guards that can be bypassed by direct navigation
- Admin paths in JS bundles: /admin, /dashboard, /console

Endpoint Discovery:
- Common admin paths: /admin, /administrator, /manager, /console
- Actuator endpoints: /actuator/env, /actuator/heapdump
- Config exposure: /.env, /.git/config, /config.json
- API admin endpoints: /api/admin, /api/internal, /api/management

Parameter Indicators:
- role, isAdmin, userType, access_level, permission, group
- X-Original-URL, X-Rewrite-URL, X-Forwarded-For headers
- HTTP method override headers: X-HTTP-Method-Override

---

## Phase 13: Authentication & Session Management — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns auth/session, or login/logout/session endpoints present.
SURFACE TYPES: login, logout, session handling, token lifecycle.
```

**Discovery Patterns:**

JS Signals:
- Token storage: localStorage.getItem('token'), sessionStorage
- Cookie read/write: document.cookie
- JWT decode: jwt.decode(), JSON.parse(atob(token.split('.')[1]))
- Login/logout API calls in network activity
- Password reset flow: /forgot-password, /reset-password
- Remember-me token handling

Endpoint Discovery:
- /login, /signin, /logout, /register, /signup
- /forgot-password, /reset-password, /change-password
- /api/auth, /api/login, /api/register, /api/session
- /api/token/refresh, /api/token/verify

Cookie Parameter Indicators:
- Set-Cookie flags: HttpOnly, Secure, SameSite, Domain, Path
- Session token format: length, randomness, prefix
- Remember-me tokens, auto-login parameters
- JS-readable vs HttpOnly cookies

---

## Phase 13A: Email Enumeration — CIA: C:I

```
TRIGGER: Public endpoints that accept email/username as parameter.
SURFACE TYPES: login, register, forgot-password, address-info endpoints.
```

### Discovery Pattern — Response Discrepancy

```
PRINCIPLE: Server returns different responses for valid vs invalid emails.
  → Valid email: useSimplePwd=true, status=0, specific error message
  → Invalid email: useSimplePwd=false, status=0, generic error message
  → The BOOLEAN DIFFERENCE reveals registration status.

COMMON VULNERABLE ENDPOINTS:
  GET  /api/public/user-auth/address-info?address=<email>
  POST /api/auth/check-email
  POST /api/auth/forgot-password
  POST /api/auth/login
  GET  /api/public/user/{email}/exists
```

### Discovery Steps

```
STEP 1: IDENTIFY PUBLIC ENDPOINTS
  → Scan JS bundles for /public/ endpoints
  → Map all endpoints that accept email/username as parameter
  → Test without authentication (no auth headers)

STEP 2: TEST RESPONSE DISCREPANCY
  → Send valid email (known registered account)
  → Send invalid email (random non-existent address)
  → Compare: status, error message, response fields, response length

STEP 3: CONFIRM ENUMERATION
  → If response differs: email enumeration confirmed
  → Document the exact field that leaks registration status
  → Measure: can attacker enumerate 1000+ emails?
```

### Tooling

```bash
# curl — email enumeration test
for email in "admin@target.com" "valid_user@test.com" "fake_999@nothing.io"; do
  curl -s "https://target.com/api/public/user-auth/address-info?address=$email" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{email}: {d[\"data\"]}')"
done

# nuclei template
nuclei -u https://target.com -t http/vulnerabilities/email-enumeration.yaml
```

### MCP Usage

```
kali-mcp: curl for API calls, nuclei for scanning
playwright: navigate to login page, observe response differences
firefox-devtools: intercept network requests during login flow
```

---

## Phase 13B: Public MFA Endpoint — CIA: C:H

```
TRIGGER: MFA/multi-factor endpoints accessible without authentication.
SURFACE TYPES: /public/security/verify-mfa, /public/mfa/verify, /public/2fa/check.
```

### Discovery Pattern — Public Access to Authenticated Function

```
PRINCIPLE: MFA verification should require authentication, but some apps
  expose it as a public endpoint for pre-authentication flows.
  → Attacker can attempt MFA codes without login
  → No rate limiting = brute force possible
  → No account lockout = unlimited attempts

COMMON VULNERABLE ENDPOINTS:
  POST /api/public/security/verify-mfa
  POST /api/public/mfa/verify
  POST /api/public/2fa/check
  POST /api/auth/mfa/verify
```

### Discovery Steps

```
STEP 1: MAP MFA ENDPOINTS
  → Search JS for: verify-mfa, mfa, 2fa, authType, security
  → Check both /public/ and /private/ versions
  → Document: which require auth, which don't

STEP 2: TEST PUBLIC ACCESS
  → Send POST to /public/security/verify-mfa WITHOUT auth headers
  → If returns 413/400 (not 401): endpoint is publicly accessible
  → Document: authType parameter, code parameter, requestId parameter

STEP 3: TEST AUTHTYPE BEHAVIOR
  → authType=0 → check for 500 (server crash)
  → authType=1-9 → check for specific error messages
  → authType=string → check for validation errors
  → Document: which values cause crashes vs errors

STEP 4: TEST RATE LIMITING
  → Send 20 rapid requests to /public/security/verify-mfa
  → If all return 400 (not 429): no rate limiting confirmed
  → If no lockout after failed attempts: no account lockout
```

### Tooling

```bash
# curl — public MFA test (no auth)
curl -s -X POST "https://target.com/api/public/security/verify-mfa" \
  -H "Content-Type: application/json" \
  -d '{"authType":"ga","code":"123456"}'

# authType=0 crash test
curl -s -X POST "https://target.com/api/public/security/verify-mfa" \
  -H "Content-Type: application/json" \
  -d '{"authType":0,"code":"123456"}'

# rate limit test
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}" -X POST \
    "https://target.com/api/public/security/verify-mfa" \
    -H "Content-Type: application/json" \
    -d "{\"authType\":\"ga\",\"code\":\"$i\"}"
done
```

### MCP Usage

```
kali-mcp: curl for API calls, rate limit testing
playwright: navigate to MFA setup page, observe flow
firefox-devtools: intercept MFA verification requests
oc-engines/payload_mutate: generate TOTP codes for testing
```

### Validation Checklist

```
□ Endpoint accessible WITHOUT authentication (no 401)
□ authType=0 triggers 500 (server crash) — document exact error
□ No rate limiting (20 rapid requests all processed)
□ No account lockout (unlimited failed attempts)
□ Combined with GA secret exposure = full MFA bypass chain
□ Response fields documented (status, error, data, params)
□ Cloudflare WAF behavior noted (blocks SQLi, allows JSON)
```

---

## Phase 12A: Forced Browsing / Hidden Admin Endpoints — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns access-control, or JS signals hidden admin routes.
SURFACE TYPES: admin panels, management interfaces, debug endpoints.
SOURCE: raw/Privilege Escalation Bug Bounty Arsenal (2026)
```

### Discovery — Direct Path Access

```
PRINCIPLE: Frontend route guards are client-side only. Directly accessing admin
           paths bypasses all frontend controls. If the backend doesn't enforce
           auth, the attacker gets full admin access.

COMMON ADMIN PATHS:
  /admin, /admin/dashboard, /admin/users, /admin/settings
  /administrator, /manager, /console, /panel
  /api/admin, /api/internal, /api/management
  /actuator, /actuator/env, /actuator/heapdump, /actuator/loggers
  /swagger-ui.html, /api-docs, /openapi.json
  /debug, /debug/pprof, /debug/vars
  /.env, /.git/config, /config.json
```

### Discovery Steps

```
STEP 1: MAP HIDDEN PATHS FROM JS
  → Grep JS bundles for: /admin, /internal, /debug, /api/v1/admin
  → Check source maps for unlisted routes
  → Look for route definitions with role checks

STEP 2: DIRECT ACCESS TEST
  → Log in as normal user
  → Directly visit each admin path: /admin, /api/admin/users, /dashboard/admin
  → If page loads or API returns data without 403/401 → broken BFLA

STEP 3: HEADER BYPASS
  → Test admin paths with X-Original-URL, X-Rewrite-URL headers
  → Test with X-Forwarded-For: 127.0.0.1
  → Test with X-HTTP-Method-Override for blocked methods
```

### Validation Checklist

```
□ Admin path accessible without admin role (200 OK with data)
□ Admin API endpoints return user data without admin auth
□ Actuator endpoints accessible without authentication
□ Swagger/OpenAPI docs reveal hidden admin operations
□ Debug endpoints expose system state (env vars, heap dumps)
```

---

## Phase 13C: Session / Local Storage Poisoning — CIA: I:H

```
TRIGGER: Phase 2 assigns session-poisoning, or JS signals session/local storage with role data.
SURFACE TYPES: any app that stores role/permission data in client-side storage.
SOURCE: raw/Privilege Escalation Bug Bounty Arsenal (2026) — Technique C
```

### Discovery — Client-Side Role Flags

```
PRINCIPLE: Some apps store user role/permission data in session storage or
           local storage. If the frontend uses these values to control UI
           rendering AND makes API calls based on them, injecting admin
           values can escalate privileges.

REAL-WORLD CASE: Researcher found `UserAdminRoles` in Session Storage was
  blank for an Employee. For an Admin, it was `IsAdmin`. By setting
  `UserAdminRoles = IsSuperAdmin,IsAdmin,IsManager` in the Employee's
  session storage and refreshing, they instantly gained SuperAdmin privileges.
```

### Discovery Steps

```
STEP 1: AUDIT CLIENT-SIDE STORAGE
  → Open DevTools → Application → Session Storage / Local Storage
  → Look for keys: role, UserAdminRoles, permissions, isAdmin, auth_level
  → Compare values between low-priv and high-priv accounts

STEP 2: CHECK API USAGE
  → Monitor network requests when storage values change
  → Does the app send these values in API requests?
  → Does the app render different UI based on storage values?

STEP 3: TEST INJECTION
  → As low-priv user, set: sessionStorage.setItem("role", "admin")
  → Set: localStorage.setItem("isAdmin", "true")
  → Refresh the page — does admin UI appear?
  → Test API calls — do admin endpoints now return data?
```

### Validation Checklist

```
□ Client-side storage contains role/permission data
□ Modifying storage values changes UI rendering
□ Modified values are sent in API requests
□ Admin endpoints accept the injected role
□ Privilege escalation confirmed: user → admin via storage manipulation
```

---

## Phase 14: JWT Vulnerabilities — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns JWT, or JS signals jwt.decode(), localStorage token.
SURFACE TYPES: JWT-authenticated APIs.
```

**Discovery Patterns:**

JS Signals:
- jwt.decode(), jwt.verify(), jsonwebtoken library usage
- Token parsing: JSON.parse(atob(token.split('.')[1]))
- Authorization: Bearer header in API calls
- Token refresh logic in client code
- JWKS endpoint: /.well-known/jwks.json
- Token in localStorage (XSS-exploitable)
- Token NOT rotated after password change

Endpoint Discovery:
- /api/auth/token, /api/token/refresh, /api/token/verify
- /.well-known/jwks.json, /.well-known/openid-configuration
- Any endpoint using Authorization: Bearer header

Parameter Indicators:
- Token format: header.payload.signature (three dot-separated base64 segments)
- Algorithm in header: alg (HS256, RS256, none, None, NONE)
- Key ID in header: kid (potential SQLi/path traversal injection)
- Claims: sub, role, iat, exp, jti
- Sensitive claims: isAdmin, role, permissions, scope

### Critical JWT Checks (2026)

```
□ alg: none accepted? (none/None/NONE variants)
□ alg: HS256 with RS256 public key as HMAC secret?
□ Weak HMAC secret (crackable with rockyou.txt)?
□ kid parameter vulnerable to SQLi or path traversal (/../../dev/null)?
□ Token not rotated after password change (session fixation)?
□ Role claims in token (role, isAdmin) modifiable?
□ JWKS endpoint uses HTTP (key injection via SSRF)?
□ Token in localStorage (XSS-exploitable)?
□ Token in URL (Referer leak)?
```

---

## Phase 15: OAuth2 / OpenID Connect Flaws — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns OAuth, or JS signals window.location = authUrl.
SURFACE TYPES: social login, SSO, any OAuth authorization flow.
```

**Discovery Patterns:**

JS Signals:
- OAuth library: oauth, oidc-client, passport, msal
- Authorization URL construction with redirect_uri parameter
- Social login buttons triggering window.location redirects
- Implicit flow token extraction from URL fragments (#access_token=)

Endpoint Discovery:
- /oauth/authorize, /oauth/token, /oauth/callback
- /auth/{provider}, /login/{provider}, /connect/{provider}
- /.well-known/openid-configuration
- /.well-known/oauth-authorization-server

Parameter Indicators:
- response_type (code, token, id_token)
- client_id, redirect_uri, scope, state
- grant_type (authorization_code, implicit, client_credentials)
- code, access_token, id_token, refresh_token

---

## Phase 34: API Security Flaws — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns api-versioning, or JS signals /api/v* paths.
SURFACE TYPES: all API endpoints, especially versioned (/v1/, /v2/) and undocumented ones.
```

**Discovery Patterns:**

JS Signals:
- API base URL patterns: /api/v1/, /api/v2/, /api/beta/
- Deprecated endpoint comments in JS source
- Version negotiation in headers or URL paths
- Old JS bundles referencing removed API versions

Endpoint Discovery:
- /swagger.json, /openapi.json, /api-docs, /swagger-ui.html
- /v2/api-docs, /v3/api-docs
- /api/v{1,2,3}/, /api/beta/, /api/dev/, /api/old/, /api/legacy

Parameter Indicators:
- Version prefixes in URL: v1, v2, beta, dev, old, legacy
- Content-Type versioning: application/vnd.api.v1+json
- Accept-Version header, X-Api-Version header
- Response fields exposing internal data: password_hash, ssn, internal_notes, api_key

---

*SKILL-AUTH-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
