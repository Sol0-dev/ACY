---
name: dataset-discovery
description: Capture every agent action (tool calls, reasoning, findings, commands) into structured raw data for offensive security model fine-tuning. Cross-cutting — runs alongside ALL 48 phases. Intercepts every REACT loop iteration, every tool call, every finding, and every decision.
---

# SKILL-DATASET-DISCOVERY — Training Dataset Capture — DISCOVERY
# Phase Coverage: ALL 48 phases (cross-cutting)
# Purpose: Intercept and log every agent action into structured raw captures for fine-tuning.
# Config: dataset/capture-config.json (machine-readable phase→action→type mapping)
# Engine: mcp/dataset_capture.py (capture, format, validate, dedup, export)

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    REACT LOOP + DATASET CAPTURE (parallel)                   │
│                                                                             │
│   REASON ──→ capture reasoning decision ──→ reasoning-planning              │
│     ↓                                                                       │
│   ACT ────→ capture tool call + args ────→ varies by tool/type              │
│     ↓                                                                       │
│   OBSERVE → capture response + analysis ─→ varies by dataset type           │
│     ↓                                                                       │
│   ADAPT ──→ capture adaptation + why ────→ reasoning-planning              │
│                                                                             │
│   The capture layer is PASSIVE. It logs, never interferes.                  │
│   Every capture is auto-classified, auto-tagged, auto-timestamped.          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 0 — Recon + JS Intel + External Leak + Open Dir

```
CAPTURE POINTS (15 actions):

  1. WHOIS LOOKUP
     Tool: whois / websearch
     Dataset: osint-recon
     Capture: target domain, registrant org, name servers, registration dates
     Instruction: "Perform WHOIS enumeration on {target} and extract registrant details."

  2. SSL/TLS CERTIFICATE ANALYSIS
     Tool: curl / openssl / censys
     Dataset: osint-recon
     Capture: cert org, SANs, hidden subdomains, issuer details
     Instruction: "Analyze the SSL certificate on {target} to extract org details and hidden subdomains."

  3. CERTIFICATE TRANSPARENCY LOG SEARCH
     Tool: websearch / webfetch (crt.sh)
     Dataset: osint-recon
     Capture: all subdomains from CT logs
     Instruction: "Search CT logs for {target} to discover all SSL-issued subdomains."

  4. SUBDOMAIN ENUMERATION (subfinder)
     Tool: kali-mcp_execute_command (subfinder)
     Dataset: osint-recon
     Capture: command, output, subdomain list, categories
     Instruction: "Run subfinder to enumerate subdomains of {target}."

  5. DNS RESOLUTION (dnsx)
     Tool: kali-mcp_execute_command (dnsx)
     Dataset: osint-recon
     Capture: subdomain→IP mapping, CDN/hosting identification
     Instruction: "Resolve subdomains with dnsx to map IPs and CDN providers."

  6. HTTP PROBING (httpx)
     Tool: kali-mcp_execute_command (httpx)
     Dataset: network-webapp
     Capture: live hosts, status codes, server headers, technologies
     Instruction: "Probe resolved subdomains with httpx to identify live HTTP services."

  7. SALIENCY FILTERING
     Tool: mcp/saliency_filter.py
     Dataset: reasoning-planning
     Capture: raw input URLs, tier assignments (DROP/PASS/ELEVATE), reasoning
     Instruction: "Apply saliency filtering to classify recon URLs by priority."

  8. JAVASCRIPT BUNDLE EXTRACTION
     Tool: curl / firefox-devtools / playwright
     Dataset: osint-recon
     Capture: all JS files found, bundle sizes, entry points
     Instruction: "Extract all JavaScript bundles from {target} for endpoint discovery."

  9. JAVASCRIPT ENDPOINT ENUMERATION & EXERCISE
     Tool: curl / firefox-devtools / playwright
     Dataset: network-webapp
     Capture: each endpoint URL, HTTP method, auth requirement, request/response
     Instruction: "Enumerate every API endpoint in JS source and exercise each with real requests."

  10. WAYBACK MACHINE HISTORICAL ENDPOINTS
      Tool: websearch / webfetch
      Dataset: osint-recon
      Capture: historical URLs, forgotten endpoints, debug pages
      Instruction: "Search Wayback Machine for historical URLs of {target}."

  11. PASTE SITE & GITHUB LEAK SEARCH
      Tool: websearch / webfetch / gh CLI
      Dataset: osint-recon
      Capture: leaked credentials, API keys, internal URLs, database dumps
      Instruction: "Search paste sites, GitHub, and Shodan for exposed {target} data."

  12. OPEN DIRECTORY BRUTE-FORCE (gobuster / ffuf / dirb)
      Tool: kali-mcp_gobuster_scan / kali-mcp_dirb_scan / kali-mcp_execute_command
      Dataset: network-webapp
      Capture: discovered directories, files, directory listings
      Instruction: "Brute-force common paths (/assets/, /backup/, /.git/) on all hosts."

  13. DIRECTORY LISTING PARSING & VERSION EXTRACTION
      Tool: curl / python script
      Dataset: vulnerability-exploit
      Capture: filenames with versions (jquery-1.12.4.min.js), sizes, dates
      Instruction: "Parse directory listings to extract versioned artifacts for CVE mapping."

  14. OPEN DIRECTORY FILE IDENTIFICATION
      Tool: curl / python script
      Dataset: osint-recon
      Capture: backup archives, config files, .git/ dirs, database dumps
      Instruction: "Identify sensitive files: backups, configs, dumps, .git directories."

  15. ASSET ATTRIBUTION
      Tool: firefox-devtools / playwright / websearch
      Dataset: reasoning-planning
      Capture: target owner, org, parent company, tech partners
      Instruction: "Identify target owner, organization, and technology partners."
```

---

## Phase 1 — Tech Fingerprinting + Version→CVE Mapping

```
CAPTURE POINTS (11 actions):

  1. HTTP HEADERS → TECHNOLOGY
     Tool: curl / httpx
     Dataset: osint-recon
     Capture: Server, X-Powered-By, X-Generator, X-AspNet-Version, Set-Cookie patterns

  2. HTML META TAGS → TECHNOLOGY
     Tool: curl / firefox-devtools
     Dataset: osint-recon
     Capture: generator meta, HTML comments, framework signatures

  3. JAVASCRIPT FILES → TECHNOLOGY
     Tool: curl / firefox-devtools
     Dataset: osint-recon
     Capture: frontend frameworks, library versions, vendor chunks

  4. ERROR MESSAGES → TECHNOLOGY + VERSION
     Tool: curl / firefox-devtools
     Dataset: vulnerability-exploit
     Capture: stack traces, PHP errors, ASP.NET detailed errors, Java exceptions

  5. OPEN DIRECTORY FILENAMES → VERSION
     Tool: curl
     Dataset: vulnerability-exploit
     Capture: jquery-1.12.4 → jQuery 1.12.4, struts2-core-2.3.32 → Struts 2.3.32

  6. PACKAGE LOCK FILES → VERSIONS
     Tool: curl
     Dataset: vulnerability-exploit
     Capture: package-lock.json, composer.lock, requirements.txt contents

  7. VERSION → CVE (NVD API)
     Tool: curl / websearch
     Dataset: vulnerability-exploit
     Capture: CVE IDs, CVSS scores, exploitability, affected versions

  8. VERSION → CVE (OSV.dev)
     Tool: curl / webfetch
     Dataset: vulnerability-exploit
     Capture: open-source CVEs, affected packages

  9. VERSION → CVE (GitHub Advisory)
     Tool: gh CLI / websearch
     Dataset: vulnerability-exploit
     Capture: reviewed CVEs, severity, patch availability

  10. VERSION → CVE (searchsploit)
      Tool: kali-mcp_execute_command (searchsploit)
      Dataset: vulnerability-exploit
      Capture: exploit-db entries, EDB-IDs, module paths

  11. TECHNOLOGY BOUNDARY IDENTIFICATION
      Tool: reasoning
      Dataset: reasoning-planning
      Capture: framework handoff points, tech→vuln class matrix per surface
```

---

## Phase 2 — Surface Classification + Priority

```
CAPTURE POINTS (2 actions):

  1. SURFACE CLASSIFICATION BY FUNCTION
     Dataset: reasoning-planning
     Capture: each endpoint classified (auth/admin/api/upload/profile), priority ranking

  2. CVE-WEIGHTED VULN PRIORITY
     Dataset: reasoning-planning
     Capture: priority assignment per surface (known CVE > generic test), rationale
```

---

## Phases 3-41 — Per-Vulnerability Discovery→Hunt→Reproduce

```
EACH PHASE FOLLOWS SUB-PHASE PATTERN:

  {PHASE}.1 DISCOVERY:
    Capture: passive analysis, parameter identification, initial probes
    Dataset: network-webapp (for req/res), vulnerability-exploit (for CVE probes)
    Tools: burp proxy history, curl probes, parameter enumeration
    Instruction: "Analyze {endpoint} for {vuln_class} indicators via passive/active discovery."

  {PHASE}.2 HUNT:
    Capture: payload generation, delivery, response, evasion, OAST callbacks, DOM analysis
    Dataset: varies (network-webapp for req/res, vulnerability-exploit for CVEs, evasion-opsec for WAF)
    Tools: payload_mutator, curl, sqlmap, burp, firefox-devtools, oast_manager, dom_analyzer
    Instruction: "Test {endpoint} for {vuln_class} using {technique} with {payload_type}."

  {PHASE}.3 REPRODUCE:
    Capture: confirmation evidence, PoC script, finding report, CVE citation
    Dataset: vulnerability-exploit (evidence), shell-commands (PoC script), reporting (report)
    Tools: curl (reproduction), write (PoC + report)
    Instruction: "Confirm {vuln_class} on {endpoint}: write PoC script + finding report."

PHASE-TO-VULN-CLASS MAPPING (capture type varies):

  Phase 3  SQLi          → INJECTION: sqli payloads, union/blind/error techniques
  Phase 4  NoSQLi        → INJECTION: nosql operators, $gt/$ne/$regex injection
  Phase 5  XSS           → CLIENTSIDE: reflected/stored/DOM, script injection
  Phase 6  CSRF          → CLIENTSIDE: token forgery, cross-site request
  Phase 7  SSRF          → INJECTION: internal URL access, cloud metadata
  Phase 8  XXE           → INJECTION: XML external entity, file read
  Phase 9  SSTI          → INJECTION: template injection, RCE via Jinja/Twig/VTL
  Phase 10 CMDi          → INJECTION: command injection, pipe/backtick/dollar
  Phase 11 IDOR          → AUTH: ID enumeration, object reference manipulation
  Phase 12 Access Control → AUTH: vertical/horizontal privilege bypass
  Phase 13 Auth/Session  → AUTH: session fixation, cookie manipulation
  Phase 14 JWT           → AUTH: algorithm confusion, key cracking, token forgery
  Phase 15 OAuth         → AUTH: redirect URI manipulation, token leakage
  Phase 16 Deserialization→ INJECTION: PHP/Java/Python deserialization chains
  Phase 17 File Upload   → CLIENTSIDE: unrestricted upload, webshell, path traversal
  Phase 18 LFI           → INJECTION: path traversal, /proc/self/environ, null byte
  Phase 19 RFI           → INJECTION: remote file inclusion, wrapper abuse
  Phase 20 Open Redirect → CLIENTSIDE: parameter manipulation, filter bypass
  Phase 21 Clickjacking  → CLIENTSIDE: X-Frame-Options missing, frame bouncing
  Phase 22 Smuggling     → INJECTION: CL.TE, TE.CL, TE.TE header desync
  Phase 23 Cache Poison  → INJECTION: unkeyed headers, X-Forwarded-Host
  Phase 24 Cache Deception→ INJECTION: cacheable paths, content mismatch
  Phase 25 CORS          → CLIENTSIDE: wildcard origin, null origin, credential leak
  Phase 26 Business Logic→ LOGIC: workflow abuse, step skipping, price manipulation
  Phase 27 Race Conditions→ LOGIC: TOCTOU, concurrent requests, double-spend
  Phase 28 Mass Assignment→ LOGIC: parameter pollution, role escalation via hidden fields
  Phase 29 Prototype Pollution→ CLIENTSIDE: __proto__ injection, gadget chains
  Phase 30 DOM Clobbering→ CLIENTSIDE: named getters, prototype override
  Phase 31 HPP           → INJECTION: parameter pollution, split payloads
  Phase 32 GraphQL       → INJECTION: introspection, batching, alias-based DoS
  Phase 33 WebSocket     → CLIENTSIDE: ws:// upgrade, message injection
  Phase 34 API Security  → AUTH: rate limiting bypass, versioning abuse
  Phase 35 ReDoS         → LOGIC: catastrophic backtracking in regex
  Phase 36 Subdomain Takeover→ RECON: dangling CNAME, unclaimed S3/Heroku/Vercel
  Phase 37 Dependency Confusion→ RECON: typosquatting, namespace hijacking
  Phase 38 CRLF Injection→ INJECTION: header injection via \r\n
  Phase 39 Misconfiguration→ INFODISCLOSURE: default creds, directory listing, debug mode
  Phase 40 LDAP Injection→ INJECTION: LDAP filter manipulation
  Phase 41 XPath Injection→ INJECTION: XPath query manipulation
```

---

## Phase 42 — Attack Chain Execution

```
CAPTURE POINTS (4 actions):

  1. CHAIN CANDIDATE IDENTIFICATION
     Dataset: reasoning-planning
     Capture: existing findings, chain candidates, escalation paths
     Instruction: "Analyze findings and identify chains: low+medium → HIGH/CRITICAL."

  2. CHAIN ATTACK PLAN
     Dataset: reasoning-planning
     Capture: multi-step plan, each step's input/output, cumulative impact
     Instruction: "Design attack chain where vuln A output feeds vuln B input."

  3. CHAIN EXECUTION (end-to-end)
     Dataset: shell-commands
     Capture: full command sequence, each step's request/response, impact at each transition
     Instruction: "Execute chain from initial access to final impact with evidence at each step."

  4. CHAIN DOCUMENTATION
     Dataset: reporting
     Capture: cumulative impact, individual evidence, combined CIA rating
     Instruction: "Document chain as single finding with cumulative CIA impact."
```

---

## Phase 43 — Subdomain & Cross-Domain Expansion

```
CAPTURE POINTS (3 actions):

  1. NEW SUBDOMAIN DISCOVERY & PROBING
     Dataset: osint-recon
     Capture: new subdomains, technologies, live hosts

  2. CROSS-DOMAIN CORS/COOKIE/TRUST TESTING
     Dataset: network-webapp
     Capture: CORS headers, cookie scope, trust chain between subdomains

  3. CROSS-DOMAIN CVE SURFACE TESTING
     Dataset: vulnerability-exploit
     Capture: CVE exploits applied to new subdomains
```

---

## Phase 44 — Verification + Pre-Submit Hardening

```
CAPTURE POINTS (3 actions):

  1. REPRODUCIBILITY VERIFICATION
     Dataset: vulnerability-exploit
     Capture: fresh PoC run, same result, no prior state needed

  2. PRE-SUBMIT CHECKLIST
     Dataset: reporting
     Capture: each checklist item result (reproducible, impact, scope, PII, chain, wiki, CIA)

  3. EXPLOIT HARDENING
     Dataset: evasion-opsec
     Capture: WAF test, patch test, evasion adaptations if blocked
```

---

## Phase 45 — Loop & Self-Improvement

```
CAPTURE POINTS (3 actions):

  1. SELF-ASSESSMENT (every 20 surfaces)
     Dataset: reasoning-planning
     Capture: hit rate, dead ends, patterns, priorities, strategy adjustments

  2. DEAD END DETECTION & PIVOT
     Dataset: reasoning-planning
     Capture: what failed, why, new approach selected, rationale

  3. CVE DATABASE REFRESH
     Dataset: vulnerability-exploit
     Capture: newly published CVEs, updated fingerprints
```

---

## Phase 46 — CI/CD & Container Security

```
CAPTURE POINTS (3 actions):

  1. DOCKERFILE / K8S ANALYSIS
     Dataset: code-analysis
     Capture: Dockerfile misconfigs, K8S privilege escalation

  2. CI/CD WORKFLOW INJECTION
     Dataset: code-analysis
     Capture: GitHub Actions/GitLab CI injection points, secret exposure

  3. CONTAINER ESCAPE TESTING
     Dataset: shell-commands
     Capture: privilege escalation, kernel exploit, breakout technique
```

---

## Phase 47 — AI/LLM Security

```
CAPTURE POINTS (4 actions):

  1. DEFENSE ARCHITECTURE FINGERPRINTING
     Dataset: evasion-opsec
     Capture: regex filters, ML classifiers, dual-model, HITL detection

  2. PROMPT INJECTION DELIVERY
     Dataset: network-webapp
     Capture: injection payload, system response, instruction leakage

  3. ML CLASSIFIER EVASION
     Dataset: evasion-opsec
     Capture: evasion technique, classifier bypass, success indicator

  4. RAG INJECTION
     Dataset: network-webapp
     Capture: knowledge base poisoning payload, model output influence
```

---

## Phase 48 — CVE Weaponization Pipeline

```
CAPTURE POINTS (9 actions):

  1. VERSION DISCOVERY
     Dataset: vulnerability-exploit
     Capture: technology, exact version, source, discovery context

  2. CVE SEARCH (NVD/OSV/GitHub/exploit-db)
     Dataset: vulnerability-exploit
     Capture: CVE IDs, CVSS, exploitability, affected ranges

  3. PoC & PATCH RETRIEVAL
     Dataset: vulnerability-exploit
     Capture: GitHub repo URL, commit hash, patch diff link

  4. PATCH DIFF ANALYSIS
     Dataset: code-analysis
     Capture: vulnerable function, parameter, trigger condition

  5. PoC ADAPTATION
     Dataset: vulnerability-exploit
     Capture: original PoC → adapted PoC, changes made, why

  6. CUSTOM EXPLOIT WRITING (no public PoC)
     Dataset: vulnerability-exploit
     Capture: full exploit code, CVE description → code mapping

  7. EXPLOIT TESTING (minimal viable payload)
     Dataset: vulnerability-exploit
     Capture: minimal payload, version confirmation, impact proof

  8. WAF BYPASS
     Dataset: evasion-opsec
     Capture: original blocked payload → bypassed payload, technique used

  9. WEAPONIZATION DOCUMENTATION
     Dataset: reporting
     Capture: CVE reference, PoC source, adaptations, clean exploit script
```

---

## Cross-Cutting Capture Points (All Phases)

```
ACTIONS THAT HAPPEN IN EVERY PHASE:

  1. REACT REASONING DECISION
     Dataset: reasoning-planning
     Capture: current state, decision, rationale, alternatives rejected, confidence
     Trigger: every reasoning step

  2. TOOL CALL EXECUTION
     Dataset: varies by tool type (see kali_mcp_tools mapping in capture-config.json)
     Capture: tool name, full args, response summary, duration, phase context
     Trigger: every tool call

  3. FAILURE & RECOVERY
     Dataset: reasoning-planning
     Capture: original attempt, failure reason, recovery action, outcome
     Trigger: any tool failure, blocked payload, timeout

  4. SCOPE BOUNDARY DECISION
     Dataset: reasoning-planning
     Capture: target, in/out scope, reasoning, RoE rule reference
     Trigger: when encountering new targets or scope questions

  5. HALLUCINATION CHECK
     Dataset: reasoning-planning
     Capture: claim, evidence source, confidence score (1-5)
     Trigger: before any finding save

  6. STATE SAVE
     Dataset: reasoning-planning
     Capture: phase, surfaces tested, findings count, next action
     Trigger: every 5 tool calls

  7. CVE QUEUE UPDATE
     Dataset: vulnerability-exploit
     Capture: technology, version, new CVEs added to queue
     Trigger: every version discovery

  8. WIKI NOTE CREATION
     Dataset: reasoning-planning
     Capture: technique, tags, confidence, linked notes
     Trigger: every technique discovery or pattern refinement

  9. FINDING LOG UPDATE
     Dataset: reporting
     Capture: finding title, CWE, CVSS, severity, vuln class
     Trigger: every confirmed finding

  10. EXPERIMENT LOG (AutoResearch)
      Dataset: reasoning-planning
      Capture: hypothesis, vuln_score breakdown, status, outcome
      Trigger: every experiment cycle
```

---

## Capture Command Quick Reference

```
CAPTURE ANY ACTION:
  python3 mcp/dataset_capture.py --action capture \
    --type {dataset_type} \
    --tool {tool_name} \
    --session-id {session} \
    --target {slug} \
    --phase "{phase}" \
    --capture-point {point_name} \
    --instruction "{instruction}" \
    --input-text "{request/input}" \
    --output-text "{response/output}" \
    --decision "{decision}" \
    --rationale "{rationale}" \
    --cwe {CWE-ID} \
    --cvss {score} \
    --mitre {T####} \
    --tags "{tag1,tag2}"

AUTO-CLASSIFY FROM TOOL NAME:
  mcp_burp_*        → network-webapp
  kali-mcp_nmap_*    → network-webapp
  kali-mcp_sqlmap_*  → network-webapp
  kali-mcp_hydra_*   → credential-auth
  kali-mcp_john_*    → credential-auth
  kali-mcp_metasploit_* → vulnerability-exploit
  kali-mcp_wpscan_*  → vulnerability-exploit
  kali-mcp_execute_command → shell-commands
  firefox-devtools_* → network-webapp (or osint-recon for recon)
  playwright_*       → network-webapp (or osint-recon for recon)
  websearch/webfetch → osint-recon (or vulnerability-exploit for CVE search)
  mcp/dom_analyzer   → reasoning-planning
  mcp/oast_manager   → reasoning-planning
  mcp/saliency_filter → reasoning-planning
  mcp/payload_mutator → vulnerability-exploit
```

---

## Integration With AutoResearch Loop

```
AutoResearch Step 1 (RECON):
  → Capture all recon outputs: osint-recon, network-webapp
  → Capture saliency filtering: reasoning-planning
  → Capture tech fingerprinting: osint-recon, vulnerability-exploit
  → Capture CVE mapping: vulnerability-exploit
  → Capture external leak search: osint-recon
  → Capture open directory enumeration: network-webapp

AutoResearch Step 2 (HYPOTHESIZE):
  → Capture hypothesis statement: reasoning-planning
  → Capture evidence cited from recon: reasoning-planning
  → Capture alternative hypotheses rejected: reasoning-planning

AutoResearch Step 3 (EDIT):
  → Capture all script/skill edits: reasoning-planning
  → Capture payload mutations: vulnerability-exploit
  → Capture strategy adjustments: reasoning-planning

AutoResearch Step 4 (TEST):
  → Capture all tool calls + args + responses: varies by tool
  → Capture OAST callbacks: reasoning-planning
  → Capture DOM analysis results: reasoning-planning
  → Capture WAF detections + evasion: evasion-opsec
  → Capture command execution: shell-commands

AutoResearch Step 5 (SCORE):
  → Capture VULN_SCORE breakdown: reasoning-planning
  → Capture impact/reproducibility/exploitability/novelty ratings

AutoResearch Step 6 (KEEP/REVERT):
  → Capture keep/revert decision + rationale: reasoning-planning
  → If KEEP: capture finding save, PoC save, skill update, git commit
  → If REVERT: capture revert reason, what was discarded

AutoResearch Step 7 (TRIAGE):
  → Capture triage evaluation: reporting
  → Capture finding report generation: reporting
  → Capture CVE citation + attribution: reporting
```

---

## Automation Hooks Integration

```
OAST ROUTINE:
  → Capture oast_generate call + callback URL + token: reasoning-planning
  → Capture payload embedding callback URL: varies by vuln class
  → Capture oast_poll results + interaction confirmation: reasoning-planning

OBSERVATION GATE (DOM Analyzer):
  → Capture control response baseline: network-webapp
  → Capture true-condition response (with payload): network-webapp
  → Capture false-condition response (inert): network-webapp
  → Capture dom_analyzer result: reasoning-planning
  → Capture structural_divergence_detected boolean: reasoning-planning

SALIENCY CHECK:
  → Capture raw recon output: osint-recon / network-webapp
  → Capture saliency tier assignments: reasoning-planning
  → Capture elevated URLs for deep analysis: network-webapp

PAYLOAD MUTATION:
  → Capture seed payload: vulnerability-exploit
  → Capture mutation strategy selected: vulnerability-exploit
  → Capture all generated variations: vulnerability-exploit
  → Capture which variation succeeded (if any): vulnerability-exploit
```

---

## Activation & Integration

```
PREREQUISITES:
  → essentials/DATASET_STATE.json exists (created by first activation)
  → dataset/ directory structure exists (created by ensure_dirs())
  → mcp/dataset_capture.py is executable

ACTIVATION (operator says "collect data" / "start dataset" / "training mode"):
  STEP 1: Read essentials/DATASET_STATE.json
  STEP 2: Set mode=on, generate session_id = "{date}_{random4}"
  STEP 3: Write updated state to DATASET_STATE.json
  STEP 4: Print: "DATASET MODE ON — session {session_id}"
  STEP 5: Every subsequent REACT ACT phase triggers capture hook

CAPTURE HOOK (fires silently after every tool call when mode=on):
  → Read DATASET_STATE.json → confirm mode=on
  → Run: python3 mcp/dataset_capture.py --action auto \
       --tool "{tool_name}" \
       --session-id "{session_id}" \
       --target "{target_slug}" \
       --phase "{current_phase}" \
       --capture-point "{capture_point}" \
       --decision "{decision}" \
       --rationale "{rationale}"
  → Append "Dataset: captured {N}" to STATE_{SLUG}.md
  → Every 50 captures: auto-run format + export

EXPORT (operator says "export dataset" / "build training data"):
  STEP 1: python3 mcp/dataset_capture.py --action format \
       --input dataset/raw-captures/ --output dataset/formatted/
  STEP 2: python3 mcp/dataset_capture.py --action validate \
       --input dataset/formatted/
  STEP 3: python3 mcp/dataset_capture.py --action dedup \
       --input dataset/formatted/ --threshold 0.85
  STEP 4: python3 mcp/dataset_capture.py --action export \
       --input dataset/formatted/ --output dataset/exported/ --split 80,10,10
  STEP 5: python3 mcp/dataset_capture.py --action stats \
       --input dataset/exported/
  → Print: manifest.json contents + file sizes + entry counts

DEACTIVATION (operator says "stop dataset" / "stop capturing"):
  → Set mode=off in DATASET_STATE.json
  → Print: "DATASET OFF — captured {N} entries this session"
```
