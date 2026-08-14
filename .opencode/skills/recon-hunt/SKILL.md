---
name: recon-hunt
description: Reconnaissance, subdomain discovery, dependency confusion, open directory enumeration. After DISCOVERY finds candidates — active testing, payload firing, CVE verification. Use when testing RECON vulnerabilities.
---

# SKILL-RECON-HUNT — Reconnaissance Hunt — HUNT
# Phase Coverage: 36-37, 39, 43
# Vuln Classes: Subdomain Takeover, Dependency Confusion, Info Disclosure, Subdomain Expansion
# Purpose: Active hunting for subdomain takeover, dependency confusion, and expanded recon

---

## Phase 36: Subdomain Takeover — HUNT

```
SUB-PHASE 36.2: HUNT

  Enumeration:
    subfinder -d $ROOT_DOMAIN -silent | tee ~/agents/finetune/fullrecon/${SLUG}/subs.txt
    crt.sh enumeration for wildcard certs
    dnsx -l subs.txt -a -cname -resp -silent

  Takeover services check:
    TAKEOVER_SERVICES=(".github.io" ".s3.amazonaws.com" ".azurewebsites.net"
      ".netlify.app" ".surge.sh" ".herokuapp.com" ".statuspage.io"
      ".zendesk.com" ".cloudfront.net" ".fastly.net" ".myshopify.com")
    subzy run --targets subs_resolved.txt --hide-fails
```

## Phase 37: Dependency Confusion — HUNT

```
SUB-PHASE 37.2: HUNT
  → Find internal package names from exposed files
  → Public registry check: npm, PyPI, RubyGems, Maven, NuGet
  → If package name returns 404 on public registry = candidate
```

## Phase 39: Security Misconfiguration / Info Disclosure — HUNT

```
SUB-PHASE 39.2: HUNT (FULL PATTERNS)
  → Load SKILL-INFODISCLOSURE.md for full P1-P10 workflows
  → P3: API response data over-exposure (requires 2 accounts)
  → P4: K8s pod name / infrastructure pattern detection
  → P5: SDK / 3rd-party config secret extraction from JS bundles
  → P6: Cloud storage credential exposure (S3, GCS, Azure)
  → P7: Internal type / stack trace leak detection
  → P8: Sequential ID enumeration (requires 2 accounts)
  → P10: Debug/default endpoint sweep (curl + wordlist)
  → Cloud storage exposure (S3, GCS, Azure Blob)
```

## Phase 43: Subdomain Expansion

```
TRIGGER: Main application surfaces exhausted, or subdomain intelligence accumulated.
RUNS: After Phase 42 (Chain Engine) completes on main app surfaces.

STEPS:
  1. Read subdomains from fullrecon/{SLUG}/subs.txt
  2. Apply same Phase 0-42 workflow to each subdomain:
     - JS intelligence on each subdomain
     - Surface classification per subdomain
     - Vulnerability hunting per subdomain
     - Chain evaluation across all subdomains + main app
  3. Cross-domain intelligence gathering:
     - Check CORS policies between subdomains and main app
     - Analyze cookie scope (.target.com vs sub.target.com)
     - Check for trust relationships (CSP, postMessage origins)
     - Identify subdomain-specific features (dev, staging, admin)
  4. New subdomains discovered during Phase 43 → add to queue and repeat

OUTPUT:
  → Per-subdomain surface maps added to wiki
  → Cross-domain chain candidates identified
  → Expanded attack surface for Phase 0-42 loop
```

---

## Playwright MCP Integration

Recon benefits from browser-based crawling that discovers JS-rendered endpoints invisible to curl/katana.

| Recon Task | Playwright Tool | Playbook |
|------------|----------------|----------|
| **JS-rendered endpoint discovery** | `browser_navigate` to SPA, `browser_network_requests` | Capture all API calls made by the SPA after hydration |
| **Swagger/OpenAPI detection** | `browser_navigate` to `/swagger.json`, `/api-docs` | Browser renders Swagger UI, confirms it's active |
| **Debug endpoint verification** | `browser_snapshot` after navigating to `/actuator` | See rendered debug output (curl gets raw JSON, browser confirms usability) |
| **Subdomain live check** | `browser_navigate` to each subdomain, capture title/screenshot | Confirm subdomain is active AND renders, not just HTTP 200 |
| **WAF detection** | `browser_navigate` → check for challenge pages | Distinguish Cloudflare JS challenges from real 403 blocks |
| **Tech stack fingerprinting** | `browser_evaluate` → `window.*` globals | Detect React, Angular, Vue from global namespace (more reliable than headers) |

### SPA Endpoint Discovery (Playwright beats curl)
```
1. browser_navigate(url="https://target.com") → wait for SPA to hydrate
2. browser_network_requests → filter for XHR/fetch calls
   → Discovers API endpoints that only appear after JS execution
   → These endpoints are INVISIBLE to curl, katana, and waybackurls
3. browser_evaluate → extract route definitions from framework globals:
   - Angular: window.ng?.getInjector()?.get(/* Router */)
   - React: __REACT_DEVTOOLS_GLOBAL_HOOK__
   - Vue: document.querySelector('#app').__vue__.$router.options.routes
```

---

*SKILL-RECON-HUNT — Part of the acy Agentic Security Research System v3.0*
