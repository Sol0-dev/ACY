---
name: recon-discovery
description: Reconnaissance, subdomain discovery, dependency confusion, open directory enumeration. Phase start — surface detection, parameter identification, initial probes. Use when testing RECON vulnerabilities.
---

# SKILL-RECON-DISCOVERY — Reconnaissance Discovery — DISCOVERY
# Phase Coverage: 0, 36-37, 39
# Vuln Classes: Reconnaissance, Subdomain Takeover, Dependency Confusion, Info Disclosure
# Purpose: Systematic target discovery, enumeration, and initial surface mapping — discovery phase

---

## Phase 0: Target Initialization + Reconnaissance

```
TRIGGER: New target, new session start, or JS not yet analyzed for this target.
RUNS: Once per app version / once per session if JS changed.

STEPS:
  □ Write TARGET.env with all known info
  □ Create ~/agents/finetune/ directory tree for this SLUG
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

## Phase 36: Subdomain Takeover — DISCOVERY

```
TRIGGER: Phase 2 assigns subdomain-takeover, or CNAME dangling detected.
SURFACE TYPES: all subdomains with dangling CNAMEs pointing to external services.

SUB-PHASE 36.1: DISCOVERY
  → Passive: Run recon pipeline for subdomains
  → Active: CNAME resolution check
```

## Phase 37: Dependency Confusion — DISCOVERY

```
TRIGGER: Phase 2 assigns dependency-confusion, or package.json/requirements.txt exposed.

SUB-PHASE 37.1: DISCOVERY
  → Passive: Check for exposed package.json, requirements.txt
  → Active: Extract internal package names
```

## Phase 39: Security Misconfiguration / Info Disclosure — DISCOVERY

```
TRIGGER: Phase 2 assigns info-disclosure, or default/debug endpoints detected.
PRIMARY SKILL: SKILL-INFODISCLOSURE.md — dedicated info-disclosure patterns
               with 10 patterns (P1-P10) from confirmed Coinhako/Agoda/BookBeat findings.

NOTE: Phase 39 now LOADS SKILL-INFODISCLOSURE.md for comprehensive info-disclosure
      hunting. The patterns below are the QUICK SWEEP; SKILL-INFODISCLOSURE.md
      contains the full step-by-step discovery, hunt, and reproduce workflows.

SUB-PHASE 39.1: DISCOVERY (QUICK SWEEP)
  → Run P1 (localStorage scan via MCP evaluate_script)
  → Run P2 (HTML source config extraction via curl | grep)
  → Run P9 (security header audit via curl -I)
  → Response header analysis, tech stack fingerprinting
```

---

## Recon Pipeline Script

```bash
#!/bin/bash
# ~/agents/finetune/scripts/{SLUG}/full_recon.sh
DOMAIN=$1
SLUG=$(echo "$DOMAIN" | sed 's|[.:-]|_|g')
OUT=~/agents/finetune/fullrecon/${SLUG}
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
| waymore | Advanced Wayback scraper | Phase 0, legacy API discovery |
| LinkFinder | JS endpoint extraction | Phase 0, JS Intel |

---

## Wayback Machine CDX API Recon (Phase 0 Enhancement)

```
SOURCE: poorman3exp 2026 — Wayback Machine & Legacy API Attack Surface
CIA: C:H — Forgotten endpoints still live with weaker auth
TIME: 10 minutes
```

### CDX API Queries
```bash
# All archived URLs
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original,statuscode,timestamp,mimetype&collapse=urlkey&limit=5000" | \
  jq -r '.[] | .[0]' | sort -u > wayback_all_urls.txt

# API endpoints only
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original,statuscode,mimetype&filter=mimetype:application/json&collapse=urlkey&limit=5000" | \
  jq -r '.[] | .[0]' | sort -u > wayback_api_endpoints.txt

# High-value paths (admin, debug, config, env, staging)
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original&collapse=urlkey&limit=10000" | \
  jq -r '.[] | .[0]' | grep -iE "admin|debug|backup|config|\.env|internal|staging|test|api/v[0-9]|/rest/|/graphql" | sort -u > wayback_high_value.txt
```

### What to Hunt For
- Old API versions (`/api/v1/`) — deprecated but often still active with weaker auth
- Debug endpoints (`/debug/`, `/test/`) — stack traces, env vars, auth bypass
- Admin panels (`/admin/`, `/panel/`) — removed from UI but backend still serves
- Config files (`.env`, `config.json`) — hardcoded secrets, DB credentials
- Backup files (`.bak`, `.sql`) — source code or DB dumps
- Robots.txt history — `Disallow` paths = hidden endpoints

---

*SKILL-RECON-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
