# SKILL-RECON — Reconnaissance & Discovery
# Phase Coverage: 0, 36-37, 39, 43
# Vuln Classes: Reconnaissance, Subdomain Takeover, Dependency Confusion, Info Disclosure
# Purpose: Systematic target discovery, enumeration, and initial surface mapping

---

## Sub-Phases

### Phase 0: Target Initialization + Reconnaissance

```
TRIGGER: New target, new session start, or JS not yet analyzed for this target.
RUNS: Once per app version / once per session if JS changed.

STEPS:
  □ Write TARGET.env with all known info
  □ Create ~/agents/acy/ directory tree for this SLUG
  □ Initialize STATE_{SLUG}.md with session timestamp
  □ Run RECON PIPELINE (full_recon.sh) — subfinder, katana, waybackurls, gau
  □ Run JS Intelligence System (phases JS-1 through JS-8) on discovered JS files
  □ Write js_intelligence.md with all queues populated
  □ Write app_intelligence.md with tech stack, auth type, features mapped

OUTPUT → Phase 1 + Wiki:
  → Discovered subdomains list
  → All surface endpoints
  → JS-discovered hidden endpoints (HIGH priority)
  → JS-discovered secrets → test immediately
  → JS-detected vuln candidates per surface
  → Write wiki target page with frontmatter, tech stack, and links to recon notes
  → Write wiki recon intelligence page linking to all recon files
  → Update wiki index with new pages
```

### Phase 36: Subdomain Takeover

```
TRIGGER: Phase 2 assigns subdomain-takeover, or CNAME dangling detected.
SURFACE TYPES: all subdomains with dangling CNAMEs pointing to external services.

SUB-PHASE 36.1: DISCOVERY
  → Passive: Run recon pipeline for subdomains
  → Active: CNAME resolution check

SUB-PHASE 36.2: HUNT
  → Enumeration:
    subfinder -d $ROOT_DOMAIN -silent | tee ~/agents/acy/fullrecon/${SLUG}/subs.txt
    crt.sh enumeration for wildcard certs
    dnsx -l subs.txt -a -cname -resp -silent
  → Takeover services check:
    TAKEOVER_SERVICES=(".github.io" ".s3.amazonaws.com" ".azurewebsites.net"
      ".netlify.app" ".surge.sh" ".herokuapp.com" ".statuspage.io"
      ".zendesk.com" ".cloudfront.net" ".fastly.net" ".myshopify.com")
    subzy run --targets subs_resolved.txt --hide-fails

SUB-PHASE 36.3: REPRODUCE
  → Confirm: CNAME points to abandoned service, claimable by attacker
  → PoC: scripts/{SLUG}/subdomain-takeover.sh
  → Save: findings/{SLUG}/{severity}/subdomain-takeover/{title}/

CHAIN OUTPUT:
  → Subdomain takeover (high) + .target.com cookie scope = steal main auth cookies (critical)
  → Subdomain takeover + XSS on claimed subdomain = ATO on main app (critical)
  → Subdomain takeover + CORS trust = read main app API data (critical)
```

### Phase 37: Dependency Confusion

```
TRIGGER: Phase 2 assigns dependency-confusion, or package.json/requirements.txt exposed.

SUB-PHASE 37.1: DISCOVERY
  → Passive: Check for exposed package.json, requirements.txt
  → Active: Extract internal package names

SUB-PHASE 37.2: HUNT
  → Find internal package names from exposed files
  → Public registry check: npm, PyPI, RubyGems, Maven, NuGet
  → If package name returns 404 on public registry = candidate

SUB-PHASE 37.3: REPRODUCE
  → Confirm: internal package name not owned on public registry
  → PoC: scripts/{SLUG}/dependency-confusion.sh
  → Save: findings/{SLUG}/{severity}/dependency-confusion/{title}/

CHAIN OUTPUT:
  → Dependency confusion (critical) → malicious package executes on build (critical)
```

### Phase 39: Security Misconfiguration / Info Disclosure

```
TRIGGER: Phase 2 assigns info-disclosure, or default/debug endpoints detected.

SUB-PHASE 39.1: DISCOVERY
  → Passive: Response header analysis, tech stack fingerprinting
  → Active: Path enumeration for common misconfigs

SUB-PHASE 39.2: HUNT
  → Misc paths sweep:
    /robots.txt /sitemap.xml /.env /.env.local /.env.production
    /.git/config /.git/HEAD /.svn/entries /phpinfo.php
    /actuator /actuator/env /actuator/heapdump /actuator/logfile
    /debug /console /admin /phpmyadmin /adminer.php
    /api-docs /swagger.json /openapi.json /graphiql
    /server-status /server-info /metrics /health
    /encryptionkeys/ /backup/ /.DS_Store /package.json
  → Security headers audit
  → Default credentials test
  → Cloud storage exposure (S3, GCS, Azure Blob)

SUB-PHASE 39.3: REPRODUCE
  → Confirm: .env readable, actuator open, default creds work, or S3 public
  → Save: findings/{SLUG}/{severity}/info-disclosure/{title}/

CHAIN OUTPUT:
  → .env exposed (critical) → credentials → full backend access (critical)
  → .git/config exposed (high) → source code → additional vulns (critical)
  → Actuator /heapdump (critical) → memory dump → credentials in heap (critical)
```

---

## Recon Pipeline Script

```bash
#!/bin/bash
# ~/agents/acy/scripts/{SLUG}/full_recon.sh
DOMAIN=$1
SLUG=$(echo "$DOMAIN" | sed 's|[.:-]|_|g')
OUT=~/agents/acy/fullrecon/${SLUG}
mkdir -p "$OUT" "$OUT/js"

echo "[+] Subdomain enumeration"
subfinder -d "$DOMAIN" -silent | anew "$OUT/subs.txt"
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew "$OUT/subs.txt"
dnsx -l "$OUT/subs.txt" -o "$OUT/subs_resolved.txt" -silent

echo "[+] Live host detection"
httpx -l "$OUT/subs_resolved.txt" -title -tech-detect -status-code \
      -o "$OUT/httpx_live.txt" -silent

echo "[+] Endpoint crawling"
katana -l "$OUT/httpx_live.txt" -d 5 -jc -o "$OUT/katana_endpoints.txt" -silent
waybackurls "$DOMAIN" | anew "$OUT/urls_passive.txt"
gau "$DOMAIN" | anew "$OUT/urls_passive.txt"

echo "[+] Parameter discovery"
cat "$OUT/urls_passive.txt" "$OUT/katana_endpoints.txt" \
  | unfurl --unique keys | anew "$OUT/all_params.txt"

echo "[+] JS file extraction"
cat "$OUT/katana_endpoints.txt" | grep -E "\.js(\?|$)" | sort -u > "$OUT/js_urls.txt"
while read -r url; do
  fname=$(echo "$url" | md5sum | cut -c1-8)
  curl -sk "$url" -o "$OUT/js/${fname}.js"
done < "$OUT/js_urls.txt"

echo "[+] Secret scanning"
for f in "$OUT/js"/*.js; do
  jsluice urls -u "https://$DOMAIN" < "$f" 2>/dev/null >> "$OUT/jsluice_endpoints.txt"
  jsluice secrets < "$f" 2>/dev/null >> "$OUT/jsluice_secrets.txt"
done

echo "[+] Nuclei scan"
nuclei -l "$OUT/httpx_live.txt" -severity critical,high \
       -o "$OUT/nuclei_critical.txt" -silent

echo "[+] Subdomain takeover"
subzy run --targets "$OUT/subs_resolved.txt" --hide-fails | tee "$OUT/takeovers.txt"

echo "[+] Swagger/OpenAPI discovery"
while read -r host; do
  for p in /swagger.json /swagger/v1/swagger.json /api-docs /openapi.json /api/swagger; do
    S=$(curl -sk -o /dev/null -w "%{http_code}" "$host$p")
    [[ "$S" == "200" ]] && echo "$host$p" | tee -a "$OUT/swagger_found.txt"
  done
done < "$OUT/httpx_live.txt"

echo "[+] Recon complete → $OUT"
```

---

## Tool Reference

| Tool | Purpose | When to Use |
|------|---------|-------------|
| subfinder | Subdomain enumeration | Phase 0, 36 |
| crt.sh | Certificate transparency | Phase 0, 36 |
| dnsx | DNS resolution | Phase 0, 36 |
| httpx | Live host detection | Phase 0 |
| katana | Web crawler | Phase 0 |
| waybackurls | Passive URL discovery | Phase 0 |
| gau | URL enumeration | Phase 0 |
| unfurl | Parameter extraction | Phase 0 |
| jsluice | JS endpoint/secret extraction | Phase 0, JS Intel |
| nuclei | Vulnerability scanner | Phase 0, 39 |
| subzy | Subdomain takeover checker | Phase 36 |
| ffuf/wfuzz | Directory fuzzing | Phase 0, 39 |
| gobuster | Directory brute force | Phase 0, 39 |

---

*SKILL-RECON — Reconnaissance & Discovery Module*
*Part of the acy Agentic Security Research System*
