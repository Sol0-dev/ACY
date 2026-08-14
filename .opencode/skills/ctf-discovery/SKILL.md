---
name: ctf-discovery
description: CTF challenge intake, wiki-first recon, skill reuse from bug bounty workflow. Phase start — load when beginning a TryHackMe or HackTheBox challenge.
---

# SKILL-CTF-DISCOVERY — CTF Challenge Discovery
# Phase Coverage: CTF-0 (Goal) → CTF-1 (Discovery) → CTF-2 (Context)
# Philosophy: Same bug bounty workflow, different end goal (flag instead of report)
# Knowledge Chain: Wiki → Skills → Web Fetch Writeup Fallback

---

## CTF Directory Structure — FILE PLACEMENT RULES

```
ALL CTF FILES GO IN PER-TARGET DIRECTORIES — NEVER IN ROOT.

SLUG = hostname with dots/slashes/colons → underscores
  Example: 10.48.176.42 → tryhackme_bypassdisablefunctions
  Example: box.htb → htb_box

DIRECTORY MAP (same as bug bounty):
  ~/agents/finetune/
  ├── scripts/{target-slug}/          ← ALL exploit scripts, droppers, shells
  ├── fullrecon/{target-slug}/        ← nmap output, gobuster results, recon
  ├── notes/{target-slug}/            ← attack chain logs, analysis notes
  ├── images/{target-slug}/           ← screenshots, visual evidence
  ├── findings/{target-slug}/         ← confirmed findings
  │   └── {severity}/{vuln-class}/{title}/
  │       ├── {title}.md              ← writeup / finding report
  │       └── {title}.sh              ← clean PoC script
  └── essentials/                     ← shared state files
      ├── STATE_{slug}.md             ← per-target session state
      ├── LOOP_STATE_{slug}.md        ← per-target loop position
      ├── MEMORY.md                   ← global growing memory
      ├── findings_log.jsonl          ← confirmed findings log
      ├── poc_registry.jsonl          ← PoC lifecycle tracker
      ├── session_log.jsonl           ← session metadata
      └── LEADERBOARD.json            ← CTF stats

FILE PLACEMENT RULES:
  ✗ NEVER create CTF_{PLATFORM}_{CHALLENGE}/ at root — use per-target dirs
  ✗ NEVER save scripts to root ~/agents/finetune/ — always scripts/{slug}/
  ✗ NEVER save recon to root — always fullrecon/{slug}/
  ✗ NEVER save notes to root — always notes/{slug}/
  ✗ NEVER save screenshots to root — always images/{slug}/
  ✓ Exploit scripts → scripts/{target-slug}/
  ✓ Recon output → fullrecon/{target-slug}/
  ✓ Attack chain notes → notes/{target-slug}/attack_chain.md
  ✓ Screenshots → images/{target-slug}/
  ✓ Writeups → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.md
  ✓ Clean PoCs → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.sh
  ✓ State files → essentials/STATE_{slug}.md, essentials/LOOP_STATE_{slug}.md
```

---

## CTF Mode = Bug Bounty Mode + Flag Capture

```
THE ONLY DIFFERENCE BETWEEN BUG BOUNTY AND CTF:
  Bug Bounty: Recon → Hypothesize → Exploit → Document Finding → Report
  CTF:        Recon → Hypothesize → Exploit → Capture Flag → Writeup

SKILLS ARE IDENTICAL:
  SQLi?    → SKILL-INJECTION-{DISCOVERY|HUNT|REPRODUCE}
  XSS?     → SKILL-CLIENTSIDE-{DISCOVERY|HUNT|REPRODUCE}
  IDOR?    → SKILL-AUTH-{DISCOVERY|HUNT|REPRODUCE}
  LFI?     → SKILL-INJECTION-{DISCOVERY|HUNT|REPRODUCE}
  CMDi?    → SKILL-INJECTION-{DISCOVERY|HUNT|REPRODUCE}
  SSTI?    → SKILL-INJECTION-{DISCOVERY|HUNT|REPRODUCE}
  SSRF?    → SKILL-INJECTION-{DISCOVERY|HUNT|REPRODUCE}
  XXE?     → SKILL-INJECTION-{DISCOVERY|HUNT|REPRODUCE}
  File Upload? → SKILL-CLIENTSIDE-{DISCOVERY|HUNT|REPRODUCE}
  disable_functions? → SKILL-INJECTION-{DISCOVERY|HUNT|REPRODUCE} (Phase 10.1)
  Privesc? → SKILL-INJECTION-{DISCOVERY|HUNT|REPRODUCE} (CMDi/LFI chain)
  Crypto?  → SKILL-INJECTION-{DISCOVERY|HUNT|REPRODUCE} (if web-based)

CTF-ONLY ADDITIONS:
  → Flag format validation (HTB{...}, THM{...})
  → User flag + root flag extraction
  → Writeup generation (not bug report)
  → Writeup lookup when stuck (web fetch)

MCP TOOLS FOR CTF:
  → Nmap: kali-mcp_nmap_scan (port/service enumeration)
  → Gobuster: kali-mcp_gobuster_scan (directory brute-force)
  → Browser: playwright_browser_* (web interaction, file upload, form submission)
  → OAST: oc-engines_oast_generate (blind injection callbacks)
  → DOM Analyzer: oc-engines_dom_analyze (injection confirmation)
  → Payload Mutator: oc-engines_payload_mutate (WAF bypass variations)
  → Saliency Filter: oc-engines_saliency_filter (recon output optimization)

STATE FILES (create/update per challenge):
  → essentials/STATE_{SLUG}.md — session state, findings, timestamps
  → essentials/LOOP_STATE_{SLUG}.md — phase progress, hypothesis tracking
  → essentials/MEMORY.md — global growing memory (append after each challenge)
  → essentials/findings_log.jsonl — confirmed findings log
  → essentials/poc_registry.jsonl — PoC lifecycle tracker
  → essentials/session_log.jsonl — session metadata
  → essentials/LEADERBOARD.json — CTF stats (rooms, points, streak)
```

---

## Knowledge Chain — Wiki First, Then Skills, Then Web

```
WHEN SOLVING A CTF CHALLENGE, FOLLOW THIS KNOWLEDGE CHAIN:

STEP 1: CHECK WIKI
  → Read wiki/index.md for matching technique notes
  → Read wiki/techniques/{vuln_class}.md for exploitation patterns
  → Read wiki/targets/{similar_challenge}.md for past solutions
  → If wiki has the answer → APPLY IT DIRECTLY

STEP 2: LOAD CORRESPONDING BUG BOUNTY SKILL
  → If wiki doesn't cover it → load the matching skill file
  → SQLi? → SKILL-INJECTION-DISCOVERY.md → SKILL-INJECTION-HUNT.md
  → XSS? → SKILL-CLIENTSIDE-DISCOVERY.md → SKILL-CLIENTSIDE-HUNT.md
  → Auth bypass? → SKILL-AUTH-DISCOVERY.md → SKILL-AUTH-HUNT.md
  → The skill has the payloads, techniques, and methodology

STEP 3: WEB FETCH WRITEUP LOOKUP (when stuck)
  → If neither wiki nor skills cover the specific challenge:
    1. WebSearch: "{challenge_name} {platform} writeup"
    2. WebFetch: retrieve the writeup content
    3. EXTRACT: what technique was used, what payloads worked
    4. APPLY: adapt the writeup's approach to the current challenge
    5. SAVE: update wiki with what was learned for future reference
  → NEVER stay stuck — always escalate to web fetch

STEP 4: SAVE WHAT YOU LEARNED
  → After solving: update wiki/targets/{PLATFORM}_{CHALLENGE}.md
  → Add any new technique to wiki/techniques/{vuln_class}.md
  → Future challenges will benefit from this knowledge
```

---

## Phase CTF-0: GOAL — Intake & Objective Definition

```
PURPOSE: Establish mission, scope, success criteria BEFORE any action.

ACTIONS:
  1. Parse challenge description → extract:
     → Target IP/hostname + port scope
     → Challenge category (Web/Pwn/Crypto/Forensics/OSINT/AD/Misc)
     → Flag format (HTB{...}, THM{...}, flag{...}, custom)
     → Provided files (binaries, PCAPs, source code, credentials)
     → Explicit restrictions or hints

  2. Define primary objective:
     → "Capture user flag" / "Capture root flag" / "Extract hidden message"
     → List all flag locations expected (user.txt, root.txt, /flag.txt)

  3. Initialize engagement state files:
     → essentials/STATE_{SLUG}.md — create with target info, status=STARTED
     → essentials/LOOP_STATE_{SLUG}.md — create with phase progress table
     → essentials/session_log.jsonl — append new session entry
     → Timestamp, target, category, objective

  4. Wiki check:
     → Has this challenge been solved before? Read wiki/targets/
     → Are there similar challenges? Search wiki/index.md
     → Load any relevant technique notes

  5. MCP recon tools ready:
     → kali-mcp_nmap_scan — port/service enumeration
     → kali-mcp_gobuster_scan — directory brute-force
     → playwright_browser_* — web interaction, file upload
     → oc-engines_saliency_filter — recon output optimization

CONSTRAINTS:
  ✗ NEVER proceed to Discovery without confirming scope
  ✗ NEVER attack outside explicit challenge scope
  ✓ If ambiguous, ASK for clarification
  ✓ If multiple targets, prioritize by attack surface (public-facing first)
```

### Goal Intake Template

```markdown
# CTF Challenge: {NAME}
- Platform: {HTB|THM|Other}
- IP: {TARGET_IP}
- Slug: {target_slug} (dots→underscores: 10.48.176.42 → tryhackme_bypassdisablefunctions)
- Category: {Web|Pwn|Crypto|Forensics|OSINT|AD|Misc}
- Difficulty: {Easy|Medium|Hard|Insane}
- Flag Format: {HTB{...}|THM{...}|flag{...}}
- Objective: {user.txt + root.txt | custom}
- Scope: {what's in bounds}
- Restrictions: {what's out of bounds}
- Files Provided: {list}

## Directory Plan
- Recon output → fullrecon/{target_slug}/
- Exploit scripts → scripts/{target_slug}/
- Attack chain → notes/{target_slug}/attack_chain.md
- Writeup → findings/{target_slug}/{severity}/{vuln-class}/{title}/
- State → essentials/STATE_{target_slug}.md
```

---

## Phase CTF-1: DISCOVERY — Reconnaissance & Enumeration

```
PURPOSE: Map attack surface systematically. Same tools as bug bounty recon.

MCP TOOLS (use these):
  → kali-mcp_nmap_scan(target="{TARGET_IP}", scan_type="-sC -sV -p-") — port/service enum
  → kali-mcp_gobuster_scan(url="http://{TARGET_IP}", mode="dir") — directory brute-force
  → playwright_browser_navigate(url="http://{TARGET_IP}") — web inspection
  → playwright_browser_snapshot() — DOM analysis
  → playwright_browser_network_requests() — HTTP request analysis

LOCAL TOOLS:
  → curl: HTTP header inspection, source code review
  → whatweb/Wappalyzer: technology fingerprinting
  → enum4linux-ng: SMB enumeration

CTF-SPECIFIC RECON:
  → If binary provided: file, strings, checksec, binwalk
  → If PCAP provided: tshark, Wireshark stream following
  → If disk image: fls, icat, autopsy
  → If memory dump: volatility3

SALIENCY CHECK:
  → After recon, pipe output through oc-engines_saliency_filter
  → Filters low-signal noise, elevates high-signal surfaces
  → Saves context for REACT reasoning loop

STATE UPDATE:
  → Update essentials/STATE_{SLUG}.md with recon findings
  → Update essentials/LOOP_STATE_{SLUG}.md phase progress

DOCUMENTATION:
  → Log every command with exact syntax, timestamp, full output
  → Save to fullrecon/{target-slug}/ (nmap, gobuster, whatweb output)
  → Save attack chain log to notes/{target-slug}/attack_chain.md
  → If scan returns nothing, note it (prevents redundant re-scanning)
```

### Web Recon (Same as Bug Bounty)

```bash
# Port scan
nmap -sC -sV -p- --min-rate 1000 {TARGET_IP} -oN recon/nmap_full.txt

# Directory brute-force
gobuster dir -u http://{TARGET_IP} -w /usr/share/wordlists/dirb/common.txt -o recon/gobuster.txt

# Technology fingerprint
whatweb http://{TARGET_IP}

# Source code review
curl -s http://{TARGET_IP} | grep -i "password\|secret\|key\|token"

# Hidden endpoints
curl -s http://{TARGET_IP}/robots.txt
```

### Binary Recon

```bash
file {binary}
strings {binary} | grep -i "flag\|password\|key\|htb\|thm"
checksec --file={binary}
```

### Documentation Rule

```
EVERY command → log in CTF_{SLUG}/notes/attack_chain.md:
  [TIMESTAMP] Action: {exact command}
  [TIMESTAMP] Result: {output or summary}
  [TIMESTAMP] Finding: {what was discovered}
  [TIMESTAMP] Next: {what to try based on this}
```

---

## Phase CTF-2: CONTEXT — Analysis & Hypothesis Generation

```
PURPOSE: Transform raw recon into actionable intelligence. Same as bug bounty.

HYPOTHESIS RANKING (3+ per challenge):
  1. MOST LIKELY: lowest complexity, highest evidence
  2. ALTERNATIVE: secondary path if primary fails
  3. LONG SHOT: complex chain requiring multiple steps

SERVICE → VULN MAPPING (from wiki + knowledge base):
  → Check wiki/techniques/ for matching patterns
  → Check KNOWLEDGE_BASE.md for similar past challenges
  → Map discovered services to known CVEs

SKILL LOADING (match vuln class to skill):
  → SQLi? → SKILL-INJECTION-DISCOVERY.md → SKILL-INJECTION-HUNT.md
  → XSS? → SKILL-CLIENTSIDE-DISCOVERY.md → SKILL-CLIENTSIDE-HUNT.md
  → Auth bypass? → SKILL-AUTH-DISCOVERY.md → SKILL-AUTH-HUNT.md
  → File Upload? → SKILL-CLIENTSIDE-DISCOVERY.md (Phase 17)
  → disable_functions? → SKILL-INJECTION-DISCOVERY.md (Phase 10.1)
  → CMDi? → SKILL-INJECTION-DISCOVERY.md (Phase 10)
  → LFI? → SKILL-INJECTION-DISCOVERY.md (Phase 18)
  → SSRF? → SKILL-INJECTION-DISCOVERY.md (Phase 7)
  → XXE? → SKILL-INJECTION-DISCOVERY.md (Phase 8)
  → SSTI? → SKILL-INJECTION-DISCOVERY.md (Phase 9)
  → Binary exploit? → SKILL-CTF-HUNT.md (pwn section)

STATE UPDATE:
  → Update essentials/STATE_{SLUG}.md with hypotheses
  → Update essentials/LOOP_STATE_{SLUG}.md with next phase

MCP TOOLS:
  → oc-engines_saliency_filter — filter recon output for high-signal surfaces
  → playwright_browser_* — browser-based analysis if needed
```

### Hypothesis Template

```markdown
## Hypothesis 1: {MOST LIKELY}
- Evidence: {why this is probable}
- Wiki/Skill Reference: {which skill note supports this}
- Test: {specific command to validate}
- Expected: {what success looks like}
- Falsification: {what proves this wrong}

## Hypothesis 2: {ALTERNATIVE}
- Evidence: {secondary signal}
- Wiki/Skill Reference: {which skill note supports this}
- Test: {validation command}
- Expected: {success indicator}
- Falsification: {failure indicator}

## Hypothesis 3: {LONG SHOT}
- Evidence: {weak but possible signal}
- Test: {validation command}
- Expected: {success indicator}
- Falsification: {failure indicator}

## Writeup Lookup (if stuck)
- WebSearch: "{challenge_name} writeup {platform}"
- Extract: technique, payload, approach
- Apply: adapt to current challenge
```

---

*SKILL-CTF-DISCOVERY — Part of the acy Agentic CTF Solver v1.0*
*Wiki-first knowledge → Bug bounty skill reuse → Web fetch fallback*
