---
name: auth-token-mgmt
description: API token lifecycle abuse, token management gaps, token creation/deletion without rate limit, token exposure via API responses. After DISCOVERY finds candidates — active testing. Use when testing token management vulnerabilities.
---

# SKILL-AUTH-TOKEN-MGMT — API Token Lifecycle Abuse — HUNT
# Phase Coverage: 13-14, 34
# Vuln Classes: API Token Exposure, Token Lifecycle Abuse, Missing Rate Limits on Token Operations
# Purpose: Discovery and exploitation of API token management weaknesses
# Source: Codacy.com findings — Token management abuse (HIGH)

---

## Philosophy

```
API tokens are high-value credentials that grant programmatic access to user accounts.
Weaknesses in token lifecycle management (creation, listing, deletion, rotation) can
lead to:
  → Token theft (exposed in API responses)
  → Token abuse (no rate limit on creation = resource exhaustion)
  → Token persistence (no expiration = indefinite access)
  → Cross-user token access (IDOR on token endpoints)
  → Missing confirmation on destructive operations (delete without auth)
```

---

## Pattern Index

| Pattern | Source | CIA Impact | Discovery Time |
|---------|--------|-----------|----------------|
| P1: Token Exposure via API Response | Codacy C1 | C:H | 2 min (API call) |
| P2: Token Creation Without Rate Limit | Codacy C2 | I:M | 5 min (bulk test) |
| P3: Token Deletion Without Confirmation | Codacy C3 | I:H | 2 min (API call) |
| P4: Token Auth Without IP Binding | Codacy C4 | C:H | 3 min (curl test) |
| P5: Cross-User Token IDOR | Codacy C5 | C:H | 5 min (2 accounts) |

---

## P1: Token Exposure via API Response

```
CIA: C:H — API tokens returned in full in API responses, enabling theft
TIME: 2 minutes
```

### Discovery

```bash
# Check if token listing endpoint returns full token values
curl -sk "$TARGET/api/v3/user/tokens" \
  -H "Authorization: Bearer $USER1_TOKEN" \
  -H "Accept: application/json" | jq .

# Check if token creation response includes full token
curl -sk -X POST "$TARGET/api/v3/user/tokens" \
  -H "Authorization: Bearer $USER1_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-token-poc","scopes":["read","write"]}' | jq .

# Check if token value is visible in account settings page
curl -sk "$TARGET/settings/tokens" \
  -H "Authorization: Bearer $USER1_TOKEN" | grep -oP 'token["\s:=]+["\'][a-zA-Z0-9]{20,}["\']'
```

### Validation Checklist
```
□ Token listing endpoint returns full token values (not just IDs/names)
□ Token creation response includes the plaintext token
□ Token visible in HTML/JS on settings page without masking
□ Token accessible to any authenticated user (not just owner)
```

---

## P2: Token Creation Without Rate Limit

```
CIA: I:M — Attacker can create unlimited tokens, causing resource exhaustion
TIME: 5 minutes
```

### Discovery

```bash
# Create 20 tokens rapidly without rate limiting
echo "[*] Testing token creation rate limit..."
for i in $(seq 1 20); do
  RESP=$(curl -sk -X POST "$TARGET/api/v3/user/tokens" \
    -H "Authorization: Bearer $USER1_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"ratelimit-test-$i\",\"scopes\":[\"read\"]}" \
    -w "\nHTTP:%{http_code}")
  CODE=$(echo "$RESP" | tail -1)
  echo "Token $i: $CODE"
done

# Check: if all 20 succeed (200/201) with no 429 → no rate limit confirmed
```

### Validation Checklist
```
□ All rapid token creation requests succeed (no 429 Too Many Requests)
□ No CAPTCHA or additional auth required for token creation
□ No cooldown period between token creation requests
□ Resource exhaustion possible (disk/memory/CPU from token storage)
```

---

## P3: Token Deletion Without Confirmation

```
CIA: I:H — Attacker can delete other users' tokens without confirmation
TIME: 2 minutes
```

### Discovery

```bash
# Test if token deletion requires confirmation or re-authentication
curl -sk -X DELETE "$TARGET/api/v3/user/tokens/TOKEN_ID" \
  -H "Authorization: Bearer $USER1_TOKEN" \
  -w "\nHTTP:%{http_code}"

# Check: 200/204 without requiring password re-entry or confirmation token
# → Token deleted without confirmation = vulnerability
```

### Validation Checklist
```
□ Token deletion succeeds without re-authentication
□ No confirmation dialog or token required
□ No rate limiting on deletion requests
□ Audit log not consulted before deletion
□ Cascading effects not checked (API access, integrations)
```

---

## P4: Token Auth Without IP Binding

```
CIA: C:H — Tokens work from any IP, enabling stolen token reuse
TIME: 3 minutes
```

### Discovery

```bash
# Test token from browser session (original IP)
curl -sk "$TARGET/api/v3/user" \
  -H "Authorization: Bearer $TOKEN" \
  -w " Browser IP: %{http_code}"

# Test token from external curl (different IP)
# If IP-bound: should fail with 401
# If NOT IP-bound: works from any IP = stolen token usable
curl -sk "$TARGET/api/v3/user" \
  -H "Authorization: Bearer $TOKEN" \
  --interface eth1 \
  -w " External IP: %{http_code}"

# Check token auth methods: Basic, Bearer, custom header
for header in "Authorization: Bearer $TOKEN" \
              "Authorization: Basic $(echo -n $TOKEN | base64)" \
              "X-Codacy-Token: $TOKEN" \
              "X-API-Key: $TOKEN"; do
  S=$(curl -sk -w "%{http_code}" -o /dev/null "$TARGET/api/v3/user" \
    -H "$header")
  echo "Header: $(echo $header | cut -d: -f1) → HTTP $S"
done
```

### Validation Checklist
```
□ Token works from different IP addresses (no IP binding)
□ Multiple auth methods accepted (Basic, Bearer, custom header)
□ Token does not expire (no expiration date enforced)
□ Token not rotated after suspicious activity
```

---

## P5: Cross-User Token IDOR

```
CIA: C:H — Attacker can access/manage other users' tokens
TIME: 5 minutes (requires 2 accounts)
```

### Discovery

```bash
# As User A, create a token and note the token ID
TOKEN_A=$(curl -sk -X POST "$TARGET/api/v3/user/tokens" \
  -H "Authorization: Bearer $USER1_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"user-a-token","scopes":["read"]}' | jq -r '.id')

# As User B, try to access User A's token
curl -sk "$TARGET/api/v3/user/tokens/$TOKEN_A" \
  -H "Authorization: Bearer $USER2_TOKEN" \
  -w " HTTP:%{http_code}"
# If 200 with token data → IDOR confirmed

# Try to delete User A's token as User B
curl -sk -X DELETE "$TARGET/api/v3/user/tokens/$TOKEN_A" \
  -H "Authorization: Bearer $USER2_TOKEN" \
  -w " HTTP:%{http_code}"
# If 200/204 → cross-user token deletion confirmed
```

### Validation Checklist
```
□ Token listing shows other users' tokens
□ Token detail endpoint accessible with other users' token IDs
□ Token deletion succeeds on other users' tokens
□ Token update/modification works cross-user
```

---

## Remediation

```
IMMEDIATE:
  1. Mask token values in API responses (show only last 4 chars)
  2. Implement rate limiting on token creation (max 5 per hour)
  3. Require re-authentication for token deletion
  4. Add IP binding or IP allowlisting for tokens
  5. Add expiration dates to all API tokens

LONG-TERM:
  6. Implement token rotation with automatic expiry
  7. Add anomaly detection for token usage patterns
  8. Audit token access logs for cross-user attempts
  9. Implement OAuth 2.0 with short-lived access tokens + refresh tokens
  10. Add audit trail for all token lifecycle operations
```

---

*SKILL-AUTH-TOKEN-MGMT — Part of the acy Agentic Security Research System v3.0*
