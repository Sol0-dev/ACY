# SKILL-INTEL — JavaScript Intelligence & Application Understanding
# Phase Coverage: 0-1
# Purpose: Deep analysis of JavaScript files to reveal hidden endpoints, auth logic,
#          business rules, and client-side vulnerabilities before testing begins.

---

## Philosophy

JavaScript files are the blueprint of the application.
Read them BEFORE testing. They reveal: hidden endpoints, auth logic, business rules,
client-side validation (bypass targets), token handling, and developer mistakes.
JS analysis OVERRIDES and ENRICHES the Surface-to-Vuln Mapping for every surface.

---

## Phase JS-1: Discover and Download All JS Files

```bash
SLUG=$(echo "$TARGET" | sed 's|https\?://||;s|[/:.]|_|g' | tr '[:upper:]' '[:lower:]')
JSDIR=~/agents/acy/fullrecon/${SLUG}/js
mkdir -p "$JSDIR"

# From Burp proxy history
mcp_burp_get_proxy_http_history_regex(regex="\.js(\?|$)")
# → extract all JS URLs from results → download each

# From crawler
cat ~/agents/acy/fullrecon/${SLUG}/katana_endpoints.txt 2>/dev/null \
  | grep -E "\.js(\?.*)?$" | sort -u > "$JSDIR/js_urls.txt"

# Download and beautify each JS file
while read -r url; do
  fname=$(echo "$url" | md5sum | cut -c1-8).js
  curl -sk "$url" -o "$JSDIR/${fname}_raw.js"
  python3 -m jsbeautifier "$JSDIR/${fname}_raw.js" > "$JSDIR/${fname}.js" 2>/dev/null \
    || cp "$JSDIR/${fname}_raw.js" "$JSDIR/${fname}.js"
  echo "$url → $JSDIR/${fname}.js"
done < "$JSDIR/js_urls.txt"

# Source maps (.js.map) — often contain original unminified source
while read -r url; do
  curl -sk "${url}.map" -o "$JSDIR/$(basename $url).map" 2>/dev/null
done < "$JSDIR/js_urls.txt"
```

## Phase JS-2: Extract Hidden Endpoints and Parameters

```bash
cd "$JSDIR"

# jsluice — endpoint and secret extraction
for f in *.js; do
  jsluice urls -u "$TARGET" < "$f" 2>/dev/null >> ../jsluice_endpoints.txt
  jsluice secrets < "$f" 2>/dev/null >> ../jsluice_secrets.txt
done

# linkfinder
python3 /opt/LinkFinder/linkfinder.py -i "$TARGET" -d -o cli 2>/dev/null \
  | tee ../linkfinder_endpoints.txt

# Manual grep patterns
grep -rhoP '"(/[a-zA-Z0-9_/\-\.]+)"' *.js 2>/dev/null | sort -u | tee ../js_paths.txt
grep -rhoP "'(/[a-zA-Z0-9_/\-\.]+)'" *.js 2>/dev/null | sort -u >> ../js_paths.txt
grep -rhioP "(api|endpoint|url|path|route|baseurl)['\"\s:=]+['\"]?https?://[^\s'\"\\]+" *.js \
  | sort -u | tee ../js_api_urls.txt

# Parameter names from JS
grep -rhoP '"([a-zA-Z_][a-zA-Z0-9_]+)"\s*:' *.js 2>/dev/null \
  | sed 's|[":{ ]||g' | sort | uniq -c | sort -rn | head -100 \
  | tee ../js_param_names.txt

# Hidden debug / admin routes
grep -rhi "admin\|debug\|internal\|dev\|staging\|test\|backup\|secret\|private\|config" *.js \
  | grep -iP "route|path|url|endpoint" | tee ../js_hidden_routes.txt
```

## Phase JS-3: Secrets and Credentials

```bash
# Pattern-based secret scan
grep -rhioP "(api[_-]?key|apikey|secret|token|password|passwd|auth|bearer|access_key)['\"\s:=]+['\"][a-zA-Z0-9+/=_\-]{8,}" \
  *.js | sort -u | tee ../js_secrets.txt

# AWS key patterns
grep -rhoP "AKIA[0-9A-Z]{16}" *.js | tee -a ../js_secrets.txt

# Generic high-entropy strings
python3 - << 'EOF'
import re, math, glob

def entropy(s):
    if not s: return 0
    counts = {}
    for c in s: counts[c] = counts.get(c, 0) + 1
    return -sum((v/len(s)) * math.log2(v/len(s)) for v in counts.values())

high_ent = []
for f in glob.glob("*.js"):
    for m in re.finditer(r'["\x27]([A-Za-z0-9+/=_\-]{20,})["\x27]',
                         open(f,'r',errors='ignore').read()):
        s = m.group(1)
        if entropy(s) > 4.2:
            high_ent.append(f"{f}: {s[:80]}")

for h in set(high_ent):
    print(h)
EOF
```

## Phase JS-4: Auth Flow and Token Handling Analysis

```bash
# How does the app handle auth tokens?
grep -rhi "localStorage\|sessionStorage\|cookie\|token\|jwt\|bearer\|authorization" *.js \
  | grep -iP "set|get|store|save|load|retrieve" | tee ../js_token_handling.txt

# Where are tokens sent?
grep -rhi "Authorization\|X-Auth\|X-Token\|Bearer\|apiKey" *.js \
  | grep -iP "header|fetch|axios|xhr|request" | tee ../js_auth_headers.txt

# Token decode/verify logic (client-side = bypass target)
grep -rhi "jwt.verify\|jwt.decode\|atob\|base64decode\|parseJwt\|decode_token" *.js \
  | tee ../js_jwt_logic.txt

# Client-side role/permission checks (bypass targets)
grep -rhi "isAdmin\|role\|permission\|privilege\|canAccess\|isAuthorized\|hasRole" *.js \
  | tee ../js_access_control.txt

# JS-to-Vuln Mapping from Token Analysis:
#   localStorage.setItem('token') → jwt, auth-bypass (token in localStorage = XSS exfil)
#   if (user.role === 'admin') → access-control bypass (client-side gate)
#   jwt.decode() client-side → jwt (no server verify)
#   cookie HttpOnly missing → xss (token stealable)
```

## Phase JS-5: DOM XSS Sink/Source Mapping

```bash
SINKS=(
  "innerHTML" "outerHTML" "document.write" "document.writeln"
  "eval(" "setTimeout(" "setInterval(" "Function(" "execScript"
  ".src=" ".href=" ".action=" "location.href" "location.replace"
  "insertAdjacentHTML" "insertAdjacentElement" "createContextualFragment"
)
for sink in "${SINKS[@]}"; do
  grep -rnH "$sink" *.js 2>/dev/null | grep -v "^Binary" | head -5 \
    | tee -a ../dom_sinks.txt
done

grep -rhi "location.search\|location.hash\|document.URL\|document.referrer\
           \|URLSearchParams\|window.name\|postMessage" *.js | tee ../dom_sources.txt

# Source → Sink path detection
python3 - << 'EOF'
import re, glob
sources = ["location.search", "location.hash", "document.URL", "URLSearchParams",
           "window.name", "document.referrer", "postMessage"]
sinks   = ["innerHTML", "outerHTML", "document.write", "eval(", "setTimeout(", ".src=",
           ".href=", "location.href", "insertAdjacentHTML", "Function("]
for f in glob.glob("*.js"):
    content = open(f,'r',errors='ignore').read()
    for src in sources:
        if src in content:
            for sink in sinks:
                if sink in content:
                    print(f"[POTENTIAL DOM XSS] {f}: source={src} → sink={sink}")
                    break
EOF
# → Each hit adds to XSS test queue with specific payload target
```

## Phase JS-6: PostMessage and Cross-Origin Attacks

```bash
grep -rhi "addEventListener.*message\|onmessage\|postMessage" *.js \
  | tee ../postmessage_handlers.txt

python3 - << 'EOF'
import re, glob
for f in glob.glob("*.js"):
    content = open(f,'r',errors='ignore').read()
    for m in re.finditer(r"addEventListener\(['\"]message['\"].*?}\s*[,;)]", content, re.DOTALL):
        block = m.group(0)
        has_origin_check = bool(re.search(r'event\.origin|message\.origin|origin\s*[=!]==', block))
        print(f"[{'ORIGIN CHECK OK' if has_origin_check else 'NO ORIGIN CHECK — VULNERABLE'}] {f}")
        if not has_origin_check:
            print(f"  SINK: {block[:200].strip()}")
            print(f"  → Add to postmessage test queue — chain with XSS")
EOF
```

## Phase JS-7: Prototype Pollution Sources

```bash
grep -rhi "Object.assign\|merge(\|deepMerge\|extend(\|_.merge\|jQuery.extend\
           \|__proto__\|constructor.prototype" *.js | tee ../pp_candidates.txt

grep -rhi "location.search\|queryString\|qs.parse\|query\." *.js \
  | grep -v "^Binary" | head -20 | tee -a ../pp_candidates.txt

# PP → Logic Flaw connection:
# If PP via merge → pollutes isAdmin → access-control bypass
# If PP via query → pollutes template vars → XSS or SSTI
# Add all merge points to prototype-pollution test queue
```

## Phase JS-8: Service Worker and Cache Attack Surface

```bash
grep -rhi "serviceWorker\|registerServiceWorker\|sw.js\|service-worker.js" *.js \
  | tee ../serviceworker_refs.txt

grep -rhi "cache.put\|cache.add\|caches.open\|CacheStorage" *.js | tee ../cache_patterns.txt

for swpath in "/sw.js" "/service-worker.js" "/serviceworker.js" "/sw/sw.js" "/js/sw.js"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/sw_test.js "$TARGET$swpath")
  [[ "$S" == "200" ]] && grep -q "importScripts\|self.addEventListener\|FetchEvent" /tmp/sw_test.js \
    && echo "[SERVICE WORKER] Found: $TARGET$swpath" | tee -a ../serviceworker_refs.txt
done
```

---

## JS Intelligence → Action Decision Matrix

After ALL JS phases, write ~/agents/acy/notes/{SLUG}/js_intelligence.md:

| JS Finding | Attack Queue Entry |
|------------|-------------------|
| Hidden endpoint | add to surface queue (HIGH PRIORITY) |
| Client-side role check | auth-bypass + IDOR test queue |
| localStorage token | xss test queue (token stealable via XSS) |
| DOM source/sink pair | xss test queue with specific payload target |
| postMessage no origin | postmessage test queue + chain with XSS |
| Found secret/API key | test validity immediately |
| Hardcoded token | auth-bypass test immediately |
| Merge/deepMerge | prototype-pollution test queue |
| Service worker found | service-worker test queue |
| Admin/debug routes | access-control test queue (HIGH PRIORITY) |
| client price=qty*price | business-logic test (server recalculates?) |
| if(step >= 3) check | business-logic step bypass test |
| if(maxQty < 10) | business-logic API limit test |
| if(email.endsWith()) | auth-bypass email validation bypass |
| setTimeout(logout,...) | session-mgmt (client-only timeout) |
| jwt.decode() client | jwt test queue (is there server verify?) |

JS-discovered surface = HIGHER CONFIDENCE TARGET than generic enumeration.
JS-discovered logic flaw = DIRECTLY TEST with Logic Flaw Engine.

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

## App Understanding Checklist

```
□ What type of application is this? (e-commerce, banking, social, API-only, CMS...)
□ What tech stack? (Node/Express, Django, Rails, Laravel, Spring, ASP.NET...)
□ What auth system? (JWT, session cookie, OAuth, API key, basic auth, 2FA...)
□ What database? (MySQL, Postgres, MongoDB, SQLite, Redis as primary...)
□ What does each feature DO? Map inputs → backend logic → outputs
□ Where does money/value flow? (checkout, discount, credit, transfer, reward)
□ Where are privileges enforced? (middleware, per-route, per-object, none?)
□ Where is user-controlled data reflected? (stored vs reflected vs DOM)
□ What business rules exist? (one per user, time-limited, role-gated, quantity limits)
□ What integrations exist? (payment processors, email services, SSO providers, S3...)
□ What APIs are exposed? (REST, GraphQL, WebSocket, gRPC, SOAP...)
□ What does the JS tell us? (see JS Intelligence System — always run first)
```

---

## Workflow Map Format

For each feature, write in ~/agents/acy/notes/{SLUG}/{feature}.workflow.md:

```markdown
# {Feature} Workflow

## INPUT
[what the user provides]

## PROCESS
[what the backend likely does]

## OUTPUT
[what comes back]

## STATE
[what changes in the system]

## TRUST
[what assumptions the backend makes about input validity]

## LOGIC
[what business rules apply]

## FLAW
[what could go wrong given the above]

## VULNS
[applicable classes from SURFACE-TO-VULN MAPPING TABLE]
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

*SKILL-INTEL — JavaScript Intelligence & Application Understanding Module*
*Part of the acy Agentic Security Research System*
