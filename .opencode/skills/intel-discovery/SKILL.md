---
name: intel-discovery
description: JS intelligence, technology fingerprinting, version extraction, asset attribution. Phase start — surface detection, parameter identification, initial probes. Use when testing INTEL vulnerabilities.
---

# SKILL-INTEL-DISCOVERY — JS Intelligence & App Understanding — DISCOVERY
# Phase Coverage: JS-1, JS-2, JS-3, JS-4, JS-5
# Purpose: Discover and collect JavaScript files, extract hidden endpoints, parameters, and
#          build an application understanding checklist before testing begins.
#          Also: aggregate JS from EVERY source (subdomains, wayback, gau, CDN, open dirs),
#          dedup by content hash, deep-read every file end-to-end, map the entire application,
#          and turn every discovered leak into a validated finding with saved evidence.

ORDER: Aggregate ALL JS sources (subdomains, waybackurls, gau, CDN fallback, open-dir
      package files, source maps) → Dedup by content hash → Extract endpoints/params/secrets
      (grep layer, fast) → Deep-Read every unique file end-to-end (comprehension layer)
      → Build notes/{SLUG}/app-map.md + business-logic inventory → Leak triage → live
      validation → impact confirmation → evidence capture.

---

## Philosophy

JavaScript files are the blueprint of the application.
Read them BEFORE testing. They reveal: hidden endpoints, auth logic, business rules,
client-side validation (bypass targets), token handling, and developer mistakes.
JS analysis OVERRIDES and ENRICHES the Surface-to-Vuln Mapping for every surface.

This skill runs on TWO mandatory layers:
  EXTRACTION  — jsluice, linkfinder, grep patterns. Fast, produces an endpoint/secret
                checklist. This layer alone is NOT enough - it finds strings, not logic.
  COMPREHENSION — OPEN every unique JS file and READ it start to finish. This is where
                business logic, auth flows, trust boundaries, and real impact live.
Both layers run. Extraction output is a checklist aid, NEVER a substitute for reading.

A secret is NOT a finding until it is validated live with saved evidence.
A leak that unlocks nothing further is LOW/info, not a headline.
Every claim in a later finding must cite the evidence files saved here.

---

## Phase JS-1: Discover and Download All JS Files

```bash
SLUG=$(echo "$TARGET" | sed 's|https\?://||;s|[/:.]|_|g' | tr '[:upper:]' '[:lower:]')
JSDIR=~/agents/finetune/fullrecon/${SLUG}/js
mkdir -p "$JSDIR"

# From Burp proxy history
mcp_burp_get_proxy_http_history_regex(regex="\.js(\?|$)")
# → extract all JS URLs from results → download each

# From crawler
cat ~/agents/finetune/fullrecon/${SLUG}/katana_endpoints.txt 2>/dev/null \
  | grep -E "\.js(\?.*)?$" | sort -u > "$JSDIR/js_urls.txt"

# Download and beautify each JS file
while read -r url; do
  fname=$(echo "$url" | md5sum | cut -c1-8).js
  curl -sk "$url" -o "$JSDIR/${fname}_raw.js"
  jsbeautifier "$JSDIR/${fname}_raw.js" > "$JSDIR/${fname}.js" 2>/dev/null \
    || python3 -m jsbeautifier "$JSDIR/${fname}_raw.js" > "$JSDIR/${fname}.js" 2>/dev/null \
    || cp "$JSDIR/${fname}_raw.js" "$JSDIR/${fname}.js"
  echo "$url → $JSDIR/${fname}.js"
done < "$JSDIR/js_urls.txt"

# Source maps (.js.map) — often contain original unminified source
while read -r url; do
  curl -sk "${url}.map" -o "$JSDIR/$(basename $url).map" 2>/dev/null
done < "$JSDIR/js_urls.txt"
```

### JS-1.1 Subdomain + Host Sweep - collect JS from every live subdomain

```bash
DOMAIN=$(echo "$TARGET" | sed 's|https\?://||;s|www\.||;s|/.*||')

# Enumerate subdomains (skip if Phase 0 already produced them)
subfinder -d "$DOMAIN" -silent 2>/dev/null | sort -u > "$JSDIR/subdomains.txt"

# Fallback: crt.sh certificate transparency
curl -sk --max-time 30 "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]" \
  2>/dev/null | tr -d '*' | sort -u >> "$JSDIR/subdomains.txt"

# Resolve live hosts
cat "$JSDIR/subdomains.txt" | httpx -silent -mc 200,301,302,307,401,403 \
  > "$JSDIR/live_hosts.txt"

# Parse <script src> off every live host homepage (relative → absolute resolution)
while read -r host; do
  curl -sk --max-time 20 "$host" 2>/dev/null > "$JSDIR/tmp_home.html"
  python3 - "$JSDIR/tmp_home.html" "$host" <<'PYEOF' >> "$JSDIR/js_urls.txt"
import sys, re
html = open(sys.argv[1], encoding='utf-8', errors='ignore').read()
host = sys.argv[2].rstrip('/')
for src in re.findall(r'<script[^>]+src=[\'"]?([^\'">\s]+)', html):
    if src.startswith('http'):
        print(src)
    elif src.startswith('//'):
        print('https:' + src)
    elif src.startswith('/'):
        print(host + src)
    else:
        print(host + '/' + src)
PYEOF
done < "$JSDIR/live_hosts.txt"

# Every unique JS URL found so far, plus a per-host mapping for origin tracking
sort -u "$JSDIR/js_urls.txt" -o "$JSDIR/js_urls.txt"
```

### JS-1.2 Historical + Third-Party Sources (waybackurls, gau, CDN fallback)

```bash
# Wayback Machine + gau for every live host — catches JS no longer on the live site
while read -r host; do
  echo "$host" | waybackurls 2>/dev/null | grep -E "\.js(\?.*)?$" >> "$JSDIR/js_urls.txt"
  echo "$host" | gau --threads 3 2>/dev/null | grep -E "\.js(\?.*)?$" >> "$JSDIR/js_urls.txt"
done < "$JSDIR/live_hosts.txt"

# CDN fallback — if a bundle 404s on origin, retry via known CDN mirrors
# (cdnjs / jsdelivr / unpkg) using the library name + version parsed from the URL.
while read -r url; do
  grep -q "$url" "$JSDIR/downloaded.log" 2>/dev/null && continue
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 "$url")
  if [ "$code" != "200" ]; then
    lib=$(echo "$url" | grep -oP '(cdnjs|jsdelivr|unpkg)[^\s]*' || true)
    [ -n "$lib" ] && curl -sk --max-time 15 "https://cdn.jsdelivr.net/$lib" >> /dev/null 2>&1 \
      && echo "$url (cdn fallback attempted)" >> "$JSDIR/downloaded.log"
  fi
  echo "$url" >> "$JSDIR/downloaded.log"
done < "$JSDIR/js_urls.txt"

sort -u "$JSDIR/js_urls.txt" -o "$JSDIR/js_urls.txt"
```

### JS-1.3 Open-Dir Package Files (richer than page bundles)

```bash
# Dependency + version metadata often lives ONLY in these files
for path in /package.json /package-lock.json /composer.lock /yarn.lock \
            /bower.json /requirements.txt /Pipfile.lock /go.mod /Gemfile.lock; do
  while read -r host; do
    curl -sk --max-time 10 -o "$JSDIR/$(echo "$host$path" | md5sum | cut -c1-8)_pkg.json" \
      "$host$path" 2>/dev/null
  done < "$JSDIR/live_hosts.txt"
done

# Keep only files that are NOT the default 404/error body (must contain JSON/dependency keys)
for f in "$JSDIR"/*_pkg.json; do
  [ -f "$f" ] || continue
  grep -qiE '"(name|version|dependencies|require|deps)"' "$f" || rm -f "$f"
done
# These feed version → CVE mapping (Phase 48) and the app map (JS-4).
```

### JS-1.4 Source Map Recovery (expanded)

```bash
# Existing pass: "${url}.map" — keep. Additionally try all common map name variants:
while read -r url; do
  base=$(echo "$url" | sed 's/\.min\.js$/.js/;s/\.js$//')
  curl -sk --max-time 10 "${base}.js.map"  -o "$JSDIR/$(basename "$url").map"  2>/dev/null
  curl -sk --max-time 10 "${base}.min.js.map" -o "$JSDIR/$(basename "$url").map2" 2>/dev/null
  curl -sk --max-time 10 "$url.map"            -o "$JSDIR/$(basename "$url").map3" 2>/dev/null
done < "$JSDIR/js_urls.txt"

# Read the //# sourceMappingURL= comment out of every downloaded file and fetch the map
cd "$JSDIR"
for f in *.js; do
  [ -f "$f" ] || continue
  murl=$(grep -oP 'sourceMappingURL=\K\S+' "$f" | tail -1)
  if [ -n "$murl" ]; then
    case "$murl" in
      http*) curl -sk --max-time 10 "$murl" -o "$JSDIR/$(basename "$murl")" 2>/dev/null ;;
      /*)    curl -sk --max-time 10 "$TARGET$murl" -o "$JSDIR/$(basename "$murl")" 2>/dev/null ;;
    esac
  fi
done

# Expand each .map "sources" array — original unminified files
for m in *.map *.map2 *.map3; do
  [ -f "$m" ] || continue
  python3 - "$m" <<'PYEOF'
import json, sys, os, urllib.request
p = sys.argv[1]
try:
    d = json.load(open(p))
except Exception:
    continue
base = os.path.dirname(os.path.abspath(p))
for s in d.get('sources', []):
    if s.startswith('http'):
        try:
            fn = os.path.join(base, os.path.basename(s.split('?')[0]))
            urllib.request.urlretrieve(s, fn)
            print('  fetched source: %s -> %s' % (s, fn))
        except Exception as e:
            print('  skip %s: %s' % (s, e))
PYEOF
done
```

### JS-1.5 Dedup Pass - collapse byte-identical files (keep a registry)

```bash
# Identical vendor bundles (jQuery, React, shared utils) collapse to ONE file.
# Nothing is deleted: exact duplicates move to js/dup/, origin URLs stay in js_urls.txt.
mkdir -p "$JSDIR/dup"
cd "$JSDIR"
find . -maxdepth 1 -name "*.js" -type f -exec md5sum {} + | sort > "$JSDIR/../js_hashes.txt"
awk '{ if (seen[$1]++) print $2 }' "$JSDIR/../js_hashes.txt" | xargs -r -I{} mv {} "$JSDIR/dup/"
awk '{ if (!seen[$1]++) print $1" "$2 }' "$JSDIR/../js_hashes.txt" > "$JSDIR/../js_unique_registry.txt"

# js_unique_registry.txt = hash → kept unique file (this is the read list for JS-3).
# js/dup/ holds the exact copies that were collapsed (for provenance, never deleted).
# Map each kept file back to its origin URL via js_urls.txt for evidence attribution.
```

## Phase JS-2: Extract Hidden Endpoints and Parameters

```bash
cd "$JSDIR"

# jsluice — endpoint and secret extraction
for f in *.js; do
  jsluice urls -u "$TARGET" -j < "$f" 2>/dev/null >> ../jsluice_endpoints.txt
  jsluice secrets -j < "$f" 2>/dev/null >> ../jsluice_secrets.txt
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

---

## Phase JS-3: Deep-Read & Comprehension - READ EVERY FILE COMPLETELY

```
MANDATORY AND NON-SKIPPABLE. This is the layer grep cannot reach.

RULE: No grep. No filtering. No skimming. For EVERY file in the unique set
(js_unique_registry.txt), OPEN it and READ it start to finish.
The JS-2 extraction output is a checklist aid - NEVER a substitute for reading.
A file read 100% is worth more than 10,000 grep matches.

PER-FILE PROCEDURE:
  1. Open the file with the Read tool and read the ENTIRE file — every line,
     every function, every string, every comment.
  2. Write notes/{SLUG}/js/{fname}.read.md using the template below.
  3. Record what the file is, what it calls, what it trusts, what it leaks.
  4. Cross-reference the file against js_urls.txt to record its origin URL.

PER-FILE READ TEMPLATE (write for every unique file):

  # {fname}.js — source: {origin_url}

  PURPOSE: one-line description of what this module does
  DEPENDENCIES: modules/functions it imports or calls into
  API CALLS:  method | path/url built | params | auth header used | line ref
  AUTH LOGIC: token storage (localStorage/sessionStorage/cookie), refresh flow,
              expiry checks, role/admin gates, client-side only checks
  STATE:      store keys, storage keys, session/cookie names, reset logic
  BUSINESS LOGIC: money/quantity/role/privilege/validation rules found in code
  TRUST ASSUMPTIONS: what this client-side code assumes the backend enforces
  SECRETS:    keys/tokens/internal URLs/IPs/endpoints (feed to JS-5 triage)
  CALL GRAPH: entry points → functions → outbound calls (trace the flow)
  VULN HINTS: sinks (innerHTML, eval, postMessage, location=, fetch/XHR with
              user input), auth-bypass candidates, debug/admin flags

READ ORDER: start with files that bootstrap the app (index/main/app bundles),
then feature modules, then vendor code. Business logic usually sits in the
feature modules and the API client wrapper.
```

## Phase JS-4: App Map - Map the Entire Application

```
Deliverable: notes/{SLUG}/app-map.md — the single source of truth that
the HUNT phases (3-41) work from. Synthesize it AFTER all files are read.

SECTIONS:
  1. ENDPOINT TABLE
     method | path | params | auth | feature | data flow | source file:line
  2. FEATURE MAP — every feature → inputs → backend process → outputs → state
  3. BUSINESS LOGIC INVENTORY — money, auth, admin, privilege, quota, rate logic;
     each entry carries a code reference (file:line) and a trust-boundary note
     (is this enforced client-side, backend, or not at all?)
  4. TRUST BOUNDARIES — what is client-side only vs backend-enforced (bypass targets)
  5. HIDDEN / DEBUG SURFACES — admin, staging, debug, internal endpoints found
  6. SECRETS TRIAGE SUMMARY — every secret + classification + validation status (JS-5)
  7. INTEGRATIONS — payment, SSO, email, S3, cloud, third-party APIs
  8. TECH STACK + VERSIONS — from bundles + package files → CVE queue (Phase 48)

Every entry MUST link to the js read note and file that revealed it, e.g.
`notes/{SLUG}/js/abc12345.js.read.md`. No unlinked claims in the app map.
```

### JS-4 CVE WEAPONIZATION HANDOFF - Phase 48 gate fires here

```
TRIGGER: the app map (section 8 - TECH STACK + VERSIONS) confirms ANY tech + exact
         version (jQuery 1.12.4, React 16.8.6, AngularJS 1.4.0, Node 12, Struts 2.3.32...).
RULE:   DO NOT continue to Phase 2 surface classification / generic vuln-class hunting
        until Phase 48 (CVE Weaponization Pipeline) is invoked.
        CVE-first: an exploitable known CVE on a confirmed version beats new-bug hunting.

PROCEDURE:
  1. Write every confirmed tech + version to essentials/TECH_FINGERPRINT.json and
     essentials/CVE_QUEUE.json.
  2. Run Phase 48 (see AGENTS.md "CVE Weaponization Pipeline") for each confirmed version:
     NVD/OSV/GitHub Advisory → search PoC → pull patch diff → adapt → test (minimal
     viable payload first).
  3. Weaponize highest impact first (RCE > SSRF > SQLi > XSS).
  4. After the gate clears, resume Phase 2 surface classification with the app map.

## Phase JS-5: Leak Triage, Live Validation, Impact & Evidence
```

## Phase JS-5: Leak Triage, Live Validation, Impact & Evidence

```
Purpose: turn every discovered secret from "potential leak" into "confirmed
leak" with evidence — or honestly discard it. Do this for every entry in
jsluice_secrets.txt plus every SECRETS line from JS-3 read notes.

STEP 1 — CLASSIFY (secret type + provider + expected format)
  AWS        AKIA|ASIA + 40-char secret, arn:aws:s3::: bucket names, pre-signed URLs
  JWT        eyJ... three dot-delimited base64 segments (decode header/payload)
  Stripe     sk_live_|sk_test_|pk_live_|rk_live_
  GitHub     ghp_|gho_|github_pat_
  Slack      xox[baprs]- / xapp-
  SendGrid   SG.
  Twilio     SK... / AC...
  Google     AIza (API key), OAuth client secrets
  Firebase   https://*.firebaseio.com + apiKey
  Private    BEGIN RSA PRIVATE KEY / BEGIN OPENSSH PRIVATE KEY / EC PRIVATE KEY
  Internal   http://10./172.16./192.168./*.local/internal hostnames, DB strings

STEP 2 — VALIDATE LIVE (read-only, non-destructive ONLY)
  AWS key        → aws sts get-caller-identity (read-only identity check)
  JWT            → decode header/payload (alg, exp, iss, role claims); if a signing
                   secret is in the bundle, forge a test token OFFLINE only
  S3 bucket      → anonymous HEAD/GET on a known key or LIST (public-bucket check)
  Firebase DB    → GET a harmless known path (public rules check)
  GitHub token   → GET https://api.github.com/user
  Stripe         → verify key format + account id via test mode; NEVER charge
  Google API key → call a cheap read-only endpoint with a test string
  Private key    → NEVER upload; match fingerprint to a known host only

  RULE: leaked credentials are proven with READ-ONLY calls only. Never write,
  delete, charge, or spawn resources with a leaked credential.

STEP 3 — IMPACT CONFIRMATION (what does this unlock?)
  For each LIVE secret, trace the access chain to a concrete impact:
    live AWS key      → list buckets → read PII/backups/config → severity
    JWT signing secret → forge role=admin token → impersonation/ATO → severity
    Firebase public    → read user data → severity
    Stripe live key    → read customer/payment data → severity
  If a secret validates but unlocks NOTHING further: record as LOW/info.
  If validation fails: mark dead and discard from findings. No overclaiming.

STEP 4 — EVIDENCE CAPTURE (MANDATORY)
  Save under fullrecon/{SLUG}/js/evidence/:
    - {secret_type}_{hash}.request.txt   (full curl or raw HTTP used to validate)
    - {secret_type}_{hash}.response.txt  (status + headers + body PROVING it is live)
    - secrets_impact.md                  (leak → validated → access chain → data at risk)
  Redact full secret VALUES in saved evidence (show prefix only).
  Every later finding that references a leak MUST link these evidence files.
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
□ What AI/LLM features exist? (chat, agent, RAG, embeddings, completions, MCP tools...)
□ What CI/CD pipelines are visible? (GitHub Actions, GitLab CI, Jenkins, exposed .github/...)
□ What cloud infrastructure is detectable? (AWS, GCP, Azure — IMDS reachable, bucket names...)
□ What does the JS tell us? (see JS Intelligence System — always run first)
□ Deep-read coverage: every unique JS file read start-to-finish (js_unique_registry.txt)
□ App map built: notes/{SLUG}/app-map.md exists and links every endpoint to source
□ Leaks triaged: every secret classified, validated live, or honestly marked dead
□ Evidence saved: validation request + response under fullrecon/{SLUG}/js/evidence/
```

---

## Workflow Map Format

For each feature, write in ~/agents/finetune/notes/{SLUG}/{feature}.workflow.md:

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

*SKILL-INTEL-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
*v4.2 additions: multi-source JS aggregation (JS-1.1-1.5), deep-read comprehension (JS-3), full application map (JS-4), leak triage/live validation/evidence capture (JS-5)*
*v4.3 addition: JS-4 CVE WEAPONIZATION HANDOFF — confirmed tech+version triggers Phase 48 gate immediately, before Phase 2 surface classification*
