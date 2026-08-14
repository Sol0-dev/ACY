---
name: infodisclosure-discovery
description: Info disclosure, config leak, secret exposure, external data leaks. Phase start — surface detection, parameter identification, initial probes. Use when testing INFODISCLOSURE vulnerabilities.
---

# SKILL-INFODISCLOSURE-DISCOVERY — Information Disclosure Discovery — DISCOVERY
# Phase Coverage: 39 (extracted from SKILL-RECON), cross-cutting all phases
# Vuln Classes: info-disclosure, config-leak, secret-exposure, infrastructure-leak
# Purpose: Systematic discovery of sensitive information exposed via client-side code,
#          API responses, debug endpoints, cloud storage, and infrastructure patterns

---

## Philosophy

Information disclosure is the MOST common vulnerability class across bug bounty programs.
It's also the most POWERFUL chaining primitive — secrets, internal paths, identifiers,
and configuration enable escalation to higher-severity impacts. Every finding hunt
MUST run these patterns before moving to exploitation phases.

---

## Pattern Index

| Pattern | Source | CIA Impact | Discovery Time |
|---------|--------|-----------|----------------|
| P1: localStorage/IndexedDB Secrets | Coinhako C1 | C:H | 2 min (browser console) |
| P2: HTML Source Config Exposure | Agoda F1, Coinhako M6 | C:L-M | 30 sec (view-source) |
| P3: API Response Data Over-Exposure | Coinhako H2 | C:H | 1 min per endpoint |
| P4: K8s Pod Name / Infrastructure Leak | Agoda F1 | C:L | 15 sec (grep source) |
| P5: SDK / 3rd-Party Config Secrets | Coinhako C2 | C:H | 5 min (grep JS bundles) |
| P6: Cloud Storage Credentials | Coinhako M5 | C:H | 3 min (grep source + JS) |
| P7: .NET / Stack Trace Type Leak | Agoda | C:L | Instant (API response) |
| P8: Sequential ID Enumeration | Coinhako H2 | C:M | 5 min (compare 2 accounts) |
| P9: Security Header Audit | All targets | C:L | 2 min (curl -I) |
| P10: Debug / Default Endpoint Sweep | All targets | C:H (if open) | 5 min (wordlist + ffuf) |
| P11: AI Chatbot Unauthenticated Data Exposure | Priceline Penny | C:H | 2 min (browser console) |
| P12: Email Enumeration via Response Discrepancy | Coins.ph | C:I | 2 min (curl test) |

---

## Phase 39: Information Disclosure — Discovery

```
TRIGGER: After recon, after JS intel, and on every new surface.
         Run P1-P10 on EVERY target — these are fast, high-signal checks.

PHASE ORCHESTRATION:
  39.1 DISCOVERY → P1 (localStorage), P2 (source config), P3 (API responses)
  39.2 HUNT      → P4 (K8s), P5 (SDK secrets), P6 (cloud creds), P7 (stack traces)
  39.3 REPRODUCE → P8 (ID enum), P9 (headers), P10 (debug endpoints)
```

---

## P1: localStorage / IndexedDB / SessionStorage Secret Scanning

```
SOURCE: Coinhako C1 — ECDSA Private Key + API Key in localStorage plaintext
CIA: C:H — Any XSS on same origin → full account takeover
TIME: 2 minutes
```

### Discovery

**Via Firefox MCP (PREFERRED — runs in authenticated browser context):**
```javascript
// mcp__firefox-devtools__evaluate_script
() => {
  const dump = { localStorage: {}, sessionStorage: {} };
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    let val = localStorage.getItem(key);
    try { val = JSON.parse(val); } catch(e) {}
    dump.localStorage[key] = typeof val === 'object' ? JSON.stringify(val).substring(0, 200) : String(val).substring(0, 200);
  }
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    let val = sessionStorage.getItem(key);
    dump.sessionStorage[key] = String(val).substring(0, 200);
  }
  return dump;
}
```

---

## P2: HTML Source Configuration Exposure

```
SOURCE: Agoda F1 — agoda.pageConfig exposes K8s pod names, sessionId, loginLvl
        Coinhako M6 — Talos trading platform exposes __ENV_CONFIG__
CIA: C:L-M — Internal infrastructure, session identifiers, feature flags
TIME: 30 seconds
```

### Discovery
```bash
# Check for embedded config objects in HTML source
curl -sk "$TARGET" | grep -oP '(window\.\w+Config|window\.__\w+__|pageConfig|__ENV__)\s*=\s*\{[^}]+\}' | head -5
curl -sk "$TARGET" | grep -oP 'window\.\w+\s*=\s*"[^"]{50,}"' | head -5
```

---

## P3: API Response Data Over-Exposure

```
SOURCE: Coinhako H2 — user_id, controls.id, legal_entity_id in every API response
CIA: C:H — Sequential IDs + excessive fields enable mass enumeration
TIME: 1 minute per endpoint
```

### Discovery
```bash
# Call API endpoint and inspect all returned fields
curl -sk "$TARGET/api/user/me" \
  -H "Authorization: Bearer $USER1_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool 2>/dev/null

# Flag suspicious fields
curl -sk "$TARGET/api/user/me" \
  -H "Authorization: Bearer $USER1_TOKEN" | jq 'keys[]' 2>/dev/null | grep -iE 'id|internal|role|hash|secret|token|key'
```

---

## P4: Kubernetes Pod Name / Infrastructure Pattern Detection

```
SOURCE: Agoda F1 — hk-pc-2g-universal-login-main-749d9d867d-sbk8g in HTML source
CIA: C:L — Internal deployment architecture, datacenter locations, service names
TIME: 15 seconds
```

### Discovery
```bash
# K8s pod name patterns
curl -sk "$TARGET" | grep -oP '[a-z]{2,3}-(pc|prod|stg|dev)[a-z0-9-]+-\w{8,10}-\w{5}'

# Docker container ID patterns
curl -sk "$TARGET" | grep -oP '[a-f0-9]{12,64}'

# Internal hostname patterns
curl -sk "$TARGET" | grep -oP '(internal|staging|dev|qa|uat)[a-z0-9-]*\.[a-z]+\.[a-z]+'
```

---

## P5: SDK / Third-Party Configuration Secrets

```
SOURCE: Coinhako C2 — Zoho SDK secrets publicly exposed via JSONP config endpoint
CIA: C:H — 3rd-party service secrets enable lateral movement
TIME: 5 minutes
```

### Discovery
```bash
# Search JS bundles for 3rd-party config patterns
for f in ~/agents/finetune/fullrecon/${SLUG}/js/*.js; do
  grep -oP '(sdkKey|appId|clientSecret|apiSecret|tenantId|orgId|workspaceId)["\s:=]+["\'][a-zA-Z0-9_-]{16,}["\']' "$f"
done

# Check for JSONP endpoints exposing config
curl -sk "$TARGET/js/config.js" | head -20
curl -sk "$TARGET/api/config" | head -20
```

---

## P6: Cloud Storage Credential Exposure

```
SOURCE: Coinhako M5 — Pre-signed S3 URL in localStorage with AWS STS credentials
CIA: C:H — Cloud storage access can lead to data breach or infrastructure compromise
TIME: 3 minutes
```

### Discovery
```bash
# Search for S3/GCS/Azure URLs
grep -rhoP '(s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net)[^"'\''\s]{0,200}' \
  ~/agents/finetune/fullrecon/${SLUG}/js/*.js ~/agents/finetune/fullrecon/${SLUG}/katana_endpoints.txt 2>/dev/null | sort -u

# Search for cloud credentials
grep -rhoP '(AKIA|ASIA)[A-Z0-9]{16}' \
  ~/agents/finetune/fullrecon/${SLUG}/js/*.js 2>/dev/null | sort -u
grep -rhoP 'X-Amz-Credential[=:][^&\s]{20,}' \
  ~/agents/finetune/fullrecon/${SLUG}/js/*.js 2>/dev/null | sort -u
```

---

## P7: Internal Type / Stack Trace Leak Detection

```
SOURCE: Agoda — System.Linq.Enumerable+ListSelectIterator`2 in API response
CIA: C:L — Internal type names, framework version, code structure
TIME: Instant (API response inspection)
```

### Discovery
```bash
# Check API responses for stack traces or internal types
curl -sk "$TARGET/api/endpoint" | grep -iE 'System\.|\.Exception|\.Runtime\.|\.Internal\.|\.Infrastructure\.|at |line \d+'

# Check for generic error messages revealing framework
curl -sk "$TARGET/nonexistent" | grep -iE '\.NET|ASP\.NET|Django|Laravel|Spring|Rails|Node\.js|Express'
```

---

## P8: Sequential ID Enumeration

```
SOURCE: Coinhako H2 — user_id, controls.id, kyc_document_id all sequential integers
CIA: C:M — Enables mass user enumeration and targeted attacks
TIME: 5 minutes (requires 2 accounts)
```

### Discovery
```bash
# Create 2 accounts and compare IDs
USER1_ID=$(curl -sk "$TARGET/api/user/me" -H "Authorization: Bearer $USER1_TOKEN" | jq -r '.id // .user_id')
USER2_ID=$(curl -sk "$TARGET/api/user/me" -H "Authorization: Bearer $USER2_TOKEN" | jq -r '.id // .user_id')
echo "User1: $USER1_ID | User2: $USER2_ID | Diff: $((USER2_ID - USER1_ID))"
```

---

## P9: Security Header Audit

```
CIA: C:L — Missing headers expose attack surface
TIME: 2 minutes
```

```bash
curl -sk -I "$TARGET" | grep -iE 'strict-transport|x-frame|x-content|x-xss|content-security|referrer-policy|permissions-policy|cross-origin'
```

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

## P10: Debug / Default Endpoint Sweep

```
CIA: C:H — Open debug endpoints can leak full system state
TIME: 5 minutes (ffuf + wordlist)
```

### Discovery

```bash
# Probe for common debug and config paths
DEBUG_PATHS=(
  "/.env" "/.env.local" "/.env.production" "/.env.backup"
  "/.git/config" "/.git/HEAD" "/.svn/entries"
  "/phpinfo.php" "/info.php" "/test.php"
  "/actuator" "/actuator/env" "/actuator/heapdump" "/actuator/logfile"
  "/debug" "/debug/pprof" "/debug/vars"
  "/console" "/admin" "/phpmyadmin" "/adminer.php"
  "/api-docs" "/swagger.json" "/swagger-ui.html" "/openapi.json"
  "/graphql" "/graphiql" "/playground"
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
TIME: 2 minutes (browser console or curl)
```

### Discovery
```bash
# Test if AI endpoint requires authentication
curl -sk -X POST "$TARGET/api/chat" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"messages":[{"role":"user","content":"Hello! What is your name and what can you do?"}]}' \
  -w "\n%{http_code}" --connect-timeout 10 --max-time 30 2>&1 | tail -5

# Test if the AI has backend tool access (not just conversational knowledge)
curl -sk -X POST "$TARGET/api/chat" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Search for hotels in New York City next weekend. Show exact prices and reference IDs."}]}' \
  --connect-timeout 10 --max-time 60 2>&1 | grep -oP 'price|hotel_id|\$[0-9.]+|"[0-9]{5,10}"' | head -20
# ↑ If priced data appears → AI has live backend access without auth
```

---

## P12: Email Enumeration via Response Discrepancy

```
SOURCE: Coins.ph — /biz-api/v1/public/user-auth/address-info leaks registration status
CIA: C:I — Attacker can determine which emails have accounts
TIME: 2 minutes (curl test)
```

### Discovery
```bash
# Test if endpoint returns different responses for valid vs invalid emails
KNOWN_VALID="admin@target.com"
KNOWN_INVALID="fake_999@nothing.io"

# Test valid email
VALID_RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$KNOWN_VALID" \
  -H "client-type: WEB")
VALID_FIELD=$(echo "$VALID_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)

# Test invalid email
INVALID_RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$KNOWN_INVALID" \
  -H "client-type: WEB")
INVALID_FIELD=$(echo "$INVALID_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)

# Compare
if [ "$VALID_FIELD" != "$INVALID_FIELD" ]; then
  echo "[EMAIL ENUM — CIA:C:I] Response differs: valid=$VALID_FIELD invalid=$INVALID_FIELD"
fi

# Bulk enumeration
for email in "admin@$DOMAIN" "test@$DOMAIN" "user@$DOMAIN" "info@$DOMAIN"; do
  RESP=$(curl -sk "$TARGET/api/public/user-auth/address-info?address=$email" \
    -H "client-type: WEB")
  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('useSimplePwd','N/A'))" 2>/dev/null)
  echo "  $email: useSimplePwd=$STATUS"
done
```

### Validation Checklist
- [ ] Endpoint accessible WITHOUT authentication (no 401)
- [ ] Response differs between valid and invalid emails
- [ ] Bulk enumeration possible (1000+ emails testable)
- [ ] No rate limiting on endpoint
- [ ] Response fields documented (status, error, data, useSimplePwd)

---

## P13: Exposed Config & Environment Files

```
SOURCE: poorman3exp 2026 — .env, .git/config, phpinfo() on forgotten paths
CIA: C:H — Database credentials, API keys, cloud tokens
TIME: 3 minutes
```

### Discovery
```bash
# Google dorks
# site:target.com inurl:.env
# site:target.com inurl:phpinfo.php
# site:target.com inurl:.git/config

# Quick path check
for path in "/.env" "/.env.local" "/.env.production" "/.env.backup" "/.env.staging" "/config.env"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/env_test.txt "$TARGET$path")
  [[ "$S" == "200" ]] && echo "[ENV FILE] $TARGET$path → HTTP $S" && head -5 /tmp/env_test.txt
done
```

---

## P12: Source Map Disclosure (SPA/JS Bundles)

```
SOURCE: poorman3exp 2026 — .js.map reconstructs unminified frontend codebase
CIA: C:H — Full source code → hardcoded secrets, internal endpoints, business logic
TIME: 10 minutes
```

### Discovery
```bash
# Check for sourceMappingURL in page source
curl -sk "$TARGET" | grep -oP 'sourceMappingURL=\K[^"'\''\s]+'

# URL fuzz for .map files on common paths
ffuf -u "$TARGET/static/FUZZ.js.map" -w ~/wordlists/js-files.txt -mc 200 -s
ffuf -u "$TARGET/assets/FUZZ.js.map" -w ~/wordlists/js-files.txt -mc 200 -s
```

---

## P13: GitHub/GitLab Dorking for Secrets

```
SOURCE: poorman3exp 2026 — API keys, tokens, internal docs in public repos
CIA: C:H — Active API keys → direct financial/cloud access
TIME: 15 minutes
```

### Discovery
```bash
# GitHub dorks
# "target.com" api_key
# "target.com" password
# "target.com" aws_access_key_id
# org:target-org filename:.env

# TruffleHog scan
trufflehog github --org=target-org --json > github_secrets.json 2>/dev/null
```

---

## P14: API Documentation & Swagger UI Exposure

```
SOURCE: poorman3exp 2026 — /swagger.json reveals entire API surface + hidden admin endpoints
CIA: M-H — Full API surface → broken access control chains
TIME: 5 minutes
```

### Discovery
```bash
for path in "/swagger.json" "/swagger-ui.html" "/api-docs" "/openapi.json" "/docs" "/redoc" "/api/docs"; do
  S=$(curl -sk -w "%{http_code}" -o /dev/null "$TARGET$path")
  [[ "$S" == "200" ]] && echo "[API DOCS] $TARGET$path → HTTP $S"
done
```

---

## P15: NTLM Response Leakage (Microsoft Ecosystem)

```
SOURCE: poorman3exp 2026 — Office URI handlers leak NTLM hashes
CVE: CVE-2026-26133
CIA: C:H — NTLM hash capture → offline cracking / relay attacks
TIME: 15 minutes
```

### Discovery
```bash
# Look for library-ms files or Office document features triggering SMB
# Monitor for outbound SMB connections
# Capture with Responder
sudo responder -I eth0
```

---

## Run Order

```
ALWAYS RUN FIRST (before any exploitation phase):
  1. P1 — localStorage scan (2 min, browser)
  2. P2 — HTML source config (30 sec, curl)
  3. P9 — Security headers (2 min, curl)

RUN AFTER JS INTEL (Phase 0):
  4. P5 — SDK secrets (5 min, grep JS bundles)
  5. P6 — Cloud creds (3 min, grep JS + source)
  6. P12 — Source maps (10 min, ffuf + DevTools)

RUN WITH 2 ACCOUNTS:
  7. P3 — API over-exposure (1 min/endpoint)
  8. P8 — ID enumeration (5 min)

RUN ON ALL SUBDOMAINS:
  9. P4 — K8s patterns (15 sec/host)
  10. P7 — Stack traces (per endpoint)
  11. P10 — Debug sweep (5 min, curl + wordlist)
  12. P13 — Env files (3 min, curl + common paths)

RECON PHASE (Phase 0):
  13. P13 — GitHub dorking (15 min, trufflehog + dorks)
  14. P14 — API docs discovery (5 min, path list + curl)

POST-RECON:
  15. P15 — NTLM leakage (15 min, if Microsoft ecosystem detected)

HIGH-VALUE PATTERNS (from raw files):
  16. P16 — Exposed databases (Redis, MongoDB, Elasticsearch) (10 min)
  17. P17 — Progressive error analysis (schema enumeration) (10 min)
```

---

## P16: Exposed Databases (NoSQL, Redis, Elasticsearch)

```
SOURCE: raw/Security Misconfiguration Bug Bounty Playbook — Section 3.14
CIA: C:H — Complete data breach, credential theft, session compromise
TIME: 10 minutes
SEVERITY: CRITICAL
```

### Discovery
```bash
# MongoDB — look for default HTTP interface
curl -sk "$TARGET:27017/"  # "It looks like you are trying to access MongoDB over HTTP"

# Redis — test for no-auth access
redis-cli -h $TARGET -p 6379 INFO 2>/dev/null | head -5

# Elasticsearch — check cluster health
curl -sk "$TARGET:9200/_cluster/health" | jq .status 2>/dev/null
curl -sk "$TARGET:9200/_cat/indices?v" | head -10

# ClickHouse
curl -sk "$TARGET:8123/?query=SHOW%20DATABASES" 2>/dev/null

# CouchDB
curl -sk "$TARGET:5984/_all_dbs" 2>/dev/null

# CouchDB
curl -sk "$TARGET:5984/_all_dbs" 2>/dev/null
```

### Reproduction
```bash
# MongoDB: List databases and dump collections
mongo $TARGET:27017 --eval "db.adminCommand('listDatabases')"
mongodump --host $TARGET --port 27017 --out ./mongo-dump

# Redis: Extract all keys and sensitive data
redis-cli -h $TARGET KEYS '*'
redis-cli -h $TARGET GET session:admin
redis-cli -h $TARGET GET config:database_url

# Elasticsearch: Search all indices
curl -sk "$TARGET:9200/_search?size=1000&q=*" | jq '.hits.hits[0]'
```

### Validation Checklist
```
□ Database accepts connections without authentication
□ Sensitive data readable (user records, PII, credentials, session tokens)
□ Ability to write/modify data (if permissions allow)
□ Database version exposed and potentially vulnerable to known CVEs
□ Multiple databases/collections accessible
```

---

## P17: Progressive Error Analysis & API Schema Enumeration

```
SOURCE: codacy_com findings — admin schema leak via progressive error messages
CIA: C:M — Reveals complete API schema BEFORE auth check
TIME: 10 minutes
SEVERITY: MEDIUM
```

### Discovery — Schema Enumeration via Error Messages

```
PRINCIPLE: Some APIs return increasingly specific error messages based on
           what field is missing or malformed. By systematically sending
           requests with different fields, you can reconstruct the ENTIRE
           API schema without authentication.

REAL-WORLD CASE: Codacy admin license endpoint revealed:
  1. {} → "email is required"
  2. {"email":"x"} → "expirationDate is required"
  3. {"email":"x","expirationDate":1} → "numberOfSeats is required"
  → Complete schema reconstructed before auth check
```

### Discovery Steps

```bash
# Step 1: Send empty POST body to admin endpoints
curl -sk -X POST "$TARGET/api/admin/license" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION" \
  -d '{}' | jq .

# Step 2: Add fields one by one based on error messages
curl -sk -X POST "$TARGET/api/admin/license" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION" \
  -d '{"email":"test@test.com"}' | jq .

# Step 3: Continue until no more "required" errors
# Each error reveals a new field name and expected type

# Step 4: Test type validation
curl -sk -X POST "$TARGET/api/admin/license" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION" \
  -d '{"email":"test@test.com","expirationDate":"not-a-date","numberOfSeats":"not-an-int"}' | jq .
# Error messages reveal expected types (Long, Int, String, etc.)
```

### Validation Checklist
```
□ Error messages reveal field names progressively
□ Field types exposed (Long, Int, String, Boolean)
□ Complete schema reconstructed without authentication
□ Schema reveals admin-only operations
□ No rate limiting on error-triggering requests
```

---

*SKILL-INFODISCLOSURE-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
