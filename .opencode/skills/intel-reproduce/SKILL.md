---
name: intel-reproduce
description: JS intelligence, technology fingerprinting, version extraction, asset attribution. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing INTEL vulnerabilities.
---

# SKILL-INTEL-REPRODUCE — JS Intelligence & App Understanding — REPRODUCE
# Phase Coverage: 1
# Purpose: Apply JS intelligence discoveries to produce actionable surface maps,
#          vulnerability classifications, and testing strategies for reproduction.

---

## Phase 1: Application Understanding + Surface Map

```
TRIGGER: After recon for each domain/subdomain.

STEPS:
  □ Browse the application — let Burp capture all traffic
  □ Map every feature: what it does, what it takes, what it returns
  □ Mine Burp history for tokens, CSRF tokens, hidden params
  □ Use mcp_firefox-devtools_list_network_requests() on each feature
  □ Write workflow.md for each major feature
  □ Use SURFACE-TO-VULN MAPPING TABLE to classify each surface
  □ Enrich classifications with JS Intelligence findings

OUTPUT → Phase 2 + Wiki:
  → Prioritized surface queue (JS-discovered first, then recon-discovered)
  → Per-surface applicable vuln class list
  → USER1_TOKEN, USER2_TOKEN, CSRF_TOKEN set in TARGET.env
  → LOOP_STATE_{SLUG}.md initialized with surface queue
  → For each surface, write wiki surface page with surface type, trust boundaries
  → Update target wiki page with surface links
```

---

## Surface-to-Vulnerability Mapping Table

```
CRITICAL PRINCIPLE: Not every vulnerability class applies to every feature.
Skilled bug hunters match the ATTACK TYPE to the SURFACE TYPE based on what the
backend likely does with the input. This table drives Phase 2 classification.
Applying irrelevant vuln classes wastes time; missing applicable ones = missed bugs.

The JS Intelligence System (Phase 0) will CONFIRM or OVERRIDE these mappings
based on what the source code actually reveals.

──────────────────────────────────────────────────────────────────────────────
SURFACE TYPE                    PRIORITY VULN CLASSES
──────────────────────────────────────────────────────────────────────────────
LOGIN / AUTH ENDPOINT           sqli nosqli auth-bypass jwt timing-attack
                                session-mgmt type-confusion ldap xpath
                                → WHY: Backend queries user store with input
                                → LOGIC: Check for timing diff on valid vs invalid user

REGISTRATION / SIGNUP           mass-assignment business-logic sqli nosqli
                                idor (if returns user ID) type-confusion
                                → WHY: Writes to DB, often trusts user-supplied fields
                                → LOGIC: Inject role/admin fields in body

PASSWORD RESET FLOW             auth-bypass 2fa-bypass timing-attack idor
                                host-header session-mgmt info-disclosure
                                → WHY: Token-based flow, often trusts Host header for link
                                → LOGIC: Test if token in response, host header poisoning

USER PROFILE / SETTINGS         idor mass-assignment xss csrf
                                access-control info-disclosure
                                → WHY: Reads/writes user-specific data
                                → LOGIC: Can user2 read/write user1's profile?

FILE UPLOAD ENDPOINT            file-upload xss xxe lfi rfi ssrf
                                → WHY: Accepts external content, often processes it
                                → LOGIC: SVG → XSS, DOCX/XML → XXE, ZIP → path traversal

SEARCH / FILTER / QUERY         xss sqli nosqli ssti redos
                                → WHY: User input reflected or used in DB query
                                → LOGIC: Reflection = XSS candidate; DB query = SQLi

URL / LINK PREVIEW / IMPORT     ssrf open-redirect rfi xxe lfi
                                → WHY: Server fetches a user-supplied URL
                                → LOGIC: Try http://127.0.0.1 for SSRF first

ADMIN PANEL / DASHBOARD         access-control idor auth-bypass mass-assignment
                                xss sqli info-disclosure
                                → WHY: Should be restricted; test with low-priv token
                                → LOGIC: Header-based bypass, path normalization

PAYMENT / CHECKOUT / CART       business-logic race-condition idor mass-assignment
                                → WHY: Numeric values + multi-step flow
                                → LOGIC: Negative qty, zero price, race on coupon

API VERSIONING ENDPOINT         api-versioning access-control auth-bypass idor
                                mass-assignment info-disclosure
                                → WHY: Old versions may lack newer security controls
                                → LOGIC: /v1/ may allow what /v3/ blocks

GRAPHQL ENDPOINT                graphql idor mass-assignment sqli
                                access-control info-disclosure
                                → WHY: Introspection reveals schema; nested auth bypass
                                → LOGIC: Try alias batching, nested field auth bypass

WEBSOCKET ENDPOINT              websocket csrf auth-bypass idor xss
                                → WHY: Often separate auth logic from REST
                                → LOGIC: Test Origin header, test message injection

JWT / TOKEN ENDPOINT            jwt auth-bypass info-disclosure
                                → WHY: Token validation is complex; alg:none, weak secret
                                → LOGIC: Decode → check alg, test none, crack if HS256

OAUTH / SSO FLOW                oauth open-redirect auth-bypass csrf
                                → WHY: Multi-party flow with redirect; easy to misvalidate
                                → LOGIC: Test redirect_uri bypass, missing state param

EMAIL / NOTIFICATION            xss ssrf open-redirect host-header
                                → WHY: Often renders HTML, may fetch URLs server-side
                                → LOGIC: HTML injection in email template = stored XSS

IMPORT / EXPORT FEATURE         xxe lfi ssrf sqli deserialization
                                → WHY: Processes external file formats (XML, CSV, JSON)
                                → LOGIC: Upload malicious XML → XXE first

REDIRECT ENDPOINT               open-redirect cors cache-poisoning
                                → WHY: Takes URL as param, redirects user
                                → LOGIC: Try // attacker.com variants

COMMENT / BIO / USER CONTENT    xss ssti second-order cmdi (if rendered in shell)
                                → WHY: User-controlled content displayed to others
                                → LOGIC: Stored XSS — test with victim account

TEMPLATE / REPORT GENERATOR     ssti lfi rfi
                                → WHY: Uses template engines that may eval user input
                                → LOGIC: {{7*7}} → 49 = Jinja2/Twig confirmed

SUBDOMAIN / DOMAIN FEATURE      subdomain-takeover cors host-header
                                → WHY: DNS delegation = takeover; cross-origin trust
                                → LOGIC: CNAME check first, then claim if abandoned

DOM / CLIENT-SIDE RENDERING     xss prototype-pollution postmessage
                                dom-clobbering service-worker
                                → WHY: React/Angular/Vue: user input into DOM sinks
                                → LOGIC: Read JS first (Phase JS-5, JS-6, JS-7)

HTTP HEADERS / CACHING          cache-poisoning cache-deception crlf
                                host-header smuggling
                                → WHY: Caches trust headers; injection can persist
                                → LOGIC: Test unkeyed headers first

INTERNAL / DEBUG ENDPOINTS      info-disclosure rce cmdi access-control
                                → WHY: Often left open in prod; no auth expected
                                → LOGIC: /actuator/env, /debug, /.git/config

THIRD-PARTY INTEGRATIONS        ssrf cors oauth open-redirect
                                dependency-confusion
                                → WHY: Trust boundaries between providers
                                → LOGIC: Redirect flows, CORS trust chains

ASYNC / BACKGROUND JOBS         race-condition second-order cmdi
                                → WHY: Executed later, different context/user
                                → LOGIC: Inject into job param, trigger race

SESSION MANAGEMENT              session-mgmt auth-bypass timing-attack
                                → WHY: Token invalidation, fixation, prediction
                                → LOGIC: Reuse old token after password change

AI / LLM / AGENT ENDPOINTS       prompt-injection model-output-handling
                                mcp-tool-abuse agent-hijacking system-prompt-extract
                                rag-injection training-data-poison
                                → WHY: LLMs process untrusted input; agent tool calls
                                → LOGIC: "Ignore previous instructions", tool injection

WEBASSEMBLY / WASM MODULES        type-confusion memory-corruption sandbox-escape
                                → WHY: WASM has its own memory model; bugs in bridge
                                → LOGIC: Fuzz WASM imports/exports, shared memory

SUPPLY CHAIN / PACKAGE REGISTRY   dependency-confusion typosquatting build-poisoning
                                → WHY: CI pulls from public registries before private
                                → LOGIC: Check package.json, requirements.txt for internal names

BROWSER EXTENSION / POSTMESSAGE   postmessage service-worker dom-clobbering
                                → WHY: Extensions inject into pages; postMessage trust
                                → LOGIC: Check window.postMessage listeners for origin

──────────────────────────────────────────────────────────────────────────────

HOW TO USE THIS TABLE:
  1. In Phase 1 (App Understanding), identify each surface's type from left column
  2. In Phase 2 (Surface Classification), load the priority vuln classes for that type
  3. Test those classes FIRST in Phases 3-41 before sweeping other classes
  4. Cross-reference with JS Intelligence — if JS reveals server-side template rendering
     on a "comment" surface, escalate SSTI to top priority for that surface
  5. After finding a bug, reference this table for chain candidates
```

---

## Playwright MCP Integration

Playwright provides a real Chromium browser that handles SPAs, Cloudflare, and JS-rendered pages better than curl or headless Firefox.

| Task | Playwright Tool | Notes |
|------|----------------|-------|
| Navigate with auth | `browser_navigate(url)` + `browser_evaluate` to set cookies first | Set `document.cookie` before navigating to auth-required pages |
| localStorage dump (JS-3b) | `browser_evaluate` → `() => JSON.stringify(localStorage)` | Better than Firefox MCP — works on all origins including CSP-restricted |
| sessionStorage dump | `browser_evaluate` → `() => JSON.stringify(sessionStorage)` | Same as above |
| DOM XSS sink detection (JS-5) | `browser_evaluate` → grep innerHTML sinks in live DOM | Run after page fully loads; `document.querySelectorAll('[id]')` for targets |
| postMessage listeners (JS-6) | `browser_evaluate` → monkey-patch `window.postMessage` | Intercept all postMessage calls and log origin checks |
| HTML source extraction (JS-3c) | `browser_snapshot` + `browser_evaluate` for `document.documentElement.outerHTML` | Full rendered DOM, not just raw source |
| Service Worker detection (JS-8) | `browser_evaluate` → `navigator.serviceWorker.getRegistrations()` | See all registered SWs |
| Console message capture | `browser_console_messages` | Capture JS errors, XSS markers, and app debug output |
| Network request inspection | `browser_network_requests` | See all API calls, token headers, and auth flow |
| Screenshot evidence | `browser_take_screenshot` | Capture DOM state for findings reports |

### Playwright vs Firefox MCP — When to Use Which

| Scenario | Use | Why |
|----------|-----|-----|
| Cloudflare-protected sites | **Playwright** | Full Chromium browser passes CF challenges automatically |
| SPA login flows | **Playwright** | Chromium renders React/Angular fully before DOM access |
| Cookie-heavy auth | **Playwright** | Set cookies before navigation, `browser_evaluate` to persist |
| CSP-restricted pages | **Playwright** | `browser_evaluate` bypasses CSP (runs in page context) |
| Firefox-specific testing | Firefox MCP | Use when testing Firefox-only behaviors or extensions |
| Burp integration needed | Firefox MCP | Firefox routes through Burp proxy (if configured) |

### Playwright Quick Reference

```
COOKIE SETUP (before navigating to auth pages):
  mcp__playwright__browser_evaluate:
    function: () => { document.cookie = "session=TOKEN; domain=.target.com; path=/; secure"; }
    
AUTHENTICATED NAVIGATION:
  mcp__playwright__browser_navigate(url="https://target.com/dashboard")
  
EXTRACT RENDERED DATA:
  mcp__playwright__browser_evaluate:
    function: () => { return { localStorage: {...localStorage}, title: document.title, configObjects: Object.keys(window).filter(k => k.includes('Config') || k.includes('ENV')) }; }
    
CAPTURE NETWORK:
  mcp__playwright__browser_network_requests → filter for API endpoints, auth headers
  
TAKE EVIDENCE:
  mcp__playwright__browser_take_screenshot → saves PNG for finding reports
```

---

*SKILL-INTEL-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
