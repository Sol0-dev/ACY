# acy - Agentic Security Research Orchestrator

**Version**: v4.3 | **Platform**: [opencode](https://opencode.ai) | **License**: MIT

A complete, modular framework for autonomous security research - reconnaissance, vulnerability discovery, PoC development, exploit writing, CVE weaponization, and bug bounty reporting. Built on the REACT (Reason → Act → Observe → Adapt) agent loop.

---

## What's Included

```
acy/
├── AGENTS.md                    ← Master orchestrator (51 phases, 70+ vuln classes)
├── opencode.jsonc               ← MCP server configuration
├── .opencode/skills/            ← 43+ modular skill files (3-file pattern per vuln class)
│   ├── {name}-discovery/SKILL.md    ← Surface detection, param identification
│   ├── {name}-hunt/SKILL.md         ← Active testing, payload firing
│   ├── {name}-reproduce/SKILL.md    ← Confirmation, PoC, exploit adaptation
│   ├── goal/SKILL.md                ← Autonomous completion loop (/goal)
│   ├── loop/SKILL.md                ← Recurring scheduled prompt (/loop)
│   ├── attack-vectors/SKILL.md      ← Phase 4 attack vector mapping
│   └── crown-jewels/SKILL.md        ← Phase 5 crown jewel goal definition
├── mcp/                         ← 4 automation engines (Python)
│   ├── mcp_server.py            ← MCP server wrapper (exposes engines as tools)
│   ├── oast_manager.py          ← Blind vuln callback polling (OAST)
│   ├── dom_analyzer.py          ← Structural DOM differential (false positive eliminator)
│   ├── saliency_filter.py       ← Recon output filtering (context optimization)
│   ├── payload_mutator.py       ← Deterministic exploit evolution (11 strategies)
│   ├── dataset_capture.py       ← Training data capture pipeline
│   ├── runner.sh                ← Unified CLI for all engines
│   └── __init__.py              ← Package init
├── templates/                   ← Reusable templates
│   ├── finding.md               ← Finding report template
│   ├── report.md                ← Full assessment report template
│   ├── session.md               ← Session state template
│   └── target-moc.md            ← Target map of content template
├── wiki/                        ← Knowledge base (markdown wiki)
│   ├── index.md                 ← Table of contents
│   ├── log.md                   ← Append-only operation record
│   ├── techniques/              ← Technique notes
│   └── targets/                 ← Per-target MOCs
├── essentials/                  ← State files & configuration
│   ├── TARGET.env               ← Active target config
│   ├── STATE_TEMPLATE.md        ← Per-target session state scaffold
│   ├── LOOP_STATE_TEMPLATE.md   ← Per-target loop position scaffold
│   ├── KNOWLEDGE_BASE.md        ← Accumulated attack patterns
│   ├── MEMORY.md                ← Cross-session persistent memory
│   ├── skill_registry.json      ← Registered skill index
│   ├── CVE_QUEUE.json           ← CVE weaponization queue
│   ├── TECH_FINGERPRINT.json    ← Technology version cache
│   ├── oast_registry.json       ← OAST callback token state
│   ├── DATASET_STATE.json       ← Dataset capture mode config
│   ├── LEADERBOARD.json         ← Finding tracker
│   ├── findings_log.jsonl       ← Confirmed findings log
│   ├── poc_registry.jsonl       ← PoC lifecycle tracker
│   └── session_log.jsonl        ← Session metadata
├── fullrecon/{target-slug}/     ← Recon output per target
├── images/{target-slug}/        ← Screenshots & visual evidence
├── notes/{target-slug}/         ← Workflow maps & intelligence
├── scripts/{target-slug}/       ← Test scripts & exploit scripts
├── findings/{target-slug}/      ← Confirmed findings
│   └── {critical|high|medium|low}/{vuln-class}/{title}/
├── attack_vectors/{target-slug}/← Phase 4 attack vector map (av.md)
├── crown_jewels/{target-slug}/  ← Phase 5 crown jewels (cj.md)
├── raw/                         ← Source documents (CVEs, writeups, PoC repos)
├── poc/                         ← Proof of concept artifacts
└── dataset/                     ← Training data pipeline
    ├── raw-captures/
    ├── formatted/
    └── exported/
```

---

## Quick Start

> **Full walkthrough with security-tool install commands: see [SETUP.md](SETUP.md).**

### 1. Prerequisites

- **opencode** - [Install opencode](https://opencode.ai)
- **Python 3.10+** - for MCP automation engines
- **Node.js 18+** - for MCP server dependencies
- **Kali Linux** (recommended) - for security tools (nmap, sqlmap, gobuster, etc.)

### 2. Clone & Configure

```bash
git clone https://github.com/YOUR_USERNAME/acy.git
cd acy

# Edit opencode.jsonc to match your environment
# - Set Kali MCP server address
# - Set Firefox/Playwright paths
# - Enable/disable Burp Suite integration
# - Configure oc-engines MCP server
```

### 3. Set Your Target

Edit `essentials/TARGET.env`:

```bash
# Target: example.com
# IP: 203.0.113.1
# Slug: example_com
# Scope: *.example.com
# Program URL: https://bugbounty.example.com
```

### 4. Start Hunting

```bash
# Open in opencode
opencode

# Then in the agent:
> let's hunt                           # Resume from last state
> fingerprint https://example.com      # Extract tech + versions
> scan for CVEs                        # Map versions to CVEs
> auto research                        # Start autonomous loop
> /goal all endpoints tested or stop after 30 turns
```

---

## Architecture

### REACT Framework

Every action follows: **REASON → ACT → OBSERVE → ADAPT**

```
REASON   - Understand target, plan attack, map CVEs
ACT      - Execute payloads, run tools, deploy exploits
OBSERVE  - Analyze responses, check OAST callbacks, structural DOM analysis
ADAPT    - Refine strategy based on observations
```

### 3-File Skill Pattern

Each vulnerability class has 3 skill files:

| File | Purpose | When Loaded |
|------|---------|-------------|
| `{name}-discovery/SKILL.md` | Surface detection, param identification | Phase start |
| `{name}-hunt/SKILL.md` | Active testing, payload firing | After candidates found |
| `{name}-reproduce/SKILL.md` | Confirmation, PoC, exploit adaptation | After exploitable found |

### 4 Automation Engines

| Engine | Purpose | CLI |
|--------|---------|-----|
| **OAST Manager** | Blind vuln callback polling | `python3 mcp/oast_manager.py --action generate` |
| **DOM Analyzer** | Structural DOM differential (false positive elimination) | `python3 mcp/dom_analyzer.py` |
| **Saliency Filter** | Recon output filtering (context optimization) | `python3 mcp/saliency_filter.py` |
| **Payload Mutator** | Deterministic exploit evolution (11 strategies) | `python3 mcp/payload_mutator.py` |

Or use the unified runner:
```bash
./mcp/runner.sh oast generate --correlation-id "sqli_blind_1"
./mcp/runner.sh dom --control ctrl.html --true true.html --false false.html
./mcp/runner.sh saliency --input recon.txt --elevate-only
./mcp/runner.sh mutate --seed "<script>alert(1)</script>" --strategy bypass_waf
```

### 51 Phases

| Phase | Name | Purpose |
|-------|------|---------|
| 0 | Recon | Target init, JS intel, external leaks, open dir enum |
| 1 | App Understanding | Tech fingerprinting, version→CVE mapping |
| 2 | Surface Classification | Prioritize by CVE exploitability |
| 3 | CVE Weaponization | Version→CVE→PoC→adapt→exploit (PRIMARY WINDOW after Phase 1) |
| 4 | Attack Vectors | Bug-bounty mindset map → attack_vectors/{slug}/av.md |
| 5 | Crown Jewels | Malicious mindset goals → crown_jewels/{slug}/cj.md |
| 6-44 | Per-Vuln Testing | DISCOVERY → HUNT → REPRODUCE per vuln class |
| 45 | Chain Engine | Multi-class escalation |
| 46 | Subdomain Expansion | Cross-domain CVE surfaces |
| 47 | Verification | Pre-submit hardening |
| 48 | Loop & Self-Improvement | Restart with fresh recon |
| 49 | CI/CD Security | DevOps & container security |
| 50 | AI/LLM Security | Prompt injection, MCP abuse |

---

## Skills (43+ files)

| Skill Base | Vuln Classes | Phases |
|------------|-------------|--------|
| RECON | Reconnaissance, Subdomain Takeover, Dependency Confusion | 0, 39-40, 42, 46 |
| INTEL | JS Intelligence, Tech Fingerprinting, App Understanding | 0-1, 3 |
| INJECTION | SQLi, NoSQLi, SSRF, XXE, SSTI, CMDi, LFI, RFI, Deserialization, Smuggling, Cache, CRLF, HPP, GraphQL, LDAP, XPath | 6-7, 10-13, 19-22, 25-27, 34-35, 41, 43-44 |
| AUTH | IDOR, Access Control, Auth/Session, JWT, OAuth, API Security | 14-18, 37 |
| CLIENTSIDE | XSS, CSRF, File Upload, Open Redirect, Clickjacking, CORS, Prototype Pollution, DOM Clobbering, WebSocket | 8-9, 20, 23-24, 28, 32-33, 36 |
| LOGIC | Business Logic, Race Conditions, Mass Assignment, ReDoS | 29-31, 38 |
| INFODISCLOSURE | Info Disclosure, Config Leak, Secret Exposure | 42, cross-cutting |
| DEVOPS | CI/CD Injection, Container Escape, Workflow Injection | 49 |
| CHAIN | Attack Chain Execution, Multi-Class Escalation | 45 |
| REPORT | PoC Development, Report Writing, Triage | 47 |
| AI | Prompt Injection, MCP Abuse, RAG Injection, Agent Hijacking | 50 |
| DATASET | Training Data Capture, Format, Validate, Export | cross-cutting |
| CTF | CTF Challenge Solver (TryHackMe, HackTheBox) | 51 |

**+ 4 utility skills**: `/goal` (autonomous completion), `/loop` (recurring scheduled prompt), `/attack-vectors` (Phase 4), `/crown-jewels` (Phase 5)

---

## Natural Language Commands

```
"let's hunt"              → Load state, resume hunting
"hunt for [vuln]"         → Prioritize that vuln class
"fingerprint [URL]"       → Extract tech + versions, map to CVEs
"scan for CVEs"           → Run Phase 3 CVE weaponization on fingerprinted tech
"look for leaks"          → Search paste sites, GitHub, Shodan
"let's look at [URL]"     → Analyze that surface
"test [endpoint]"         → Full playbook on that endpoint
"exploit [CVE-ID]"        → Find PoC, adapt, test
"what did we find?"       → Print findings summary
"resume" / "continue"     → Session continuity engine
"night" / "afk"           → Away mode (full autonomy)
"auto research"           → Start autonomous loop
"collect data"            → Enable dataset capture mode
```

---

## MCP Server Configuration

Edit `opencode.jsonc` to configure MCP servers for your environment:

```jsonc
{
  "mcp": {
    "kali-mcp": {
      "command": ["mcp-server", "--server", "http://127.0.0.1:9999/"],
      "enabled": true
    },
    "firefox-devtools": {
      "command": ["npx", "firefox-devtools-mcp", "--connectExisting", "--marionettePort", "2828"],
      "enabled": true
    },
    "playwright": {
      "command": ["npx", "@playwright/mcp@latest", "--browser", "chromium", "--no-sandbox"],
      "enabled": true
    },
    "oc-engines": {
      "command": ["python3", "mcp/mcp_server.py"],
      "enabled": true
    }
  }
}
```

See `opencode.jsonc` for full configuration options including Burp Suite integration.

---

## Knowledge Ingest Workflow — Raw → Wiki → Skills

This is how acy gets smarter over time. When you learn something new (a writeup, a CVE, a technique you discovered), you feed it in through three steps. Each step builds on the last, and nothing you already have is ever thrown away.

### The Flow (3 steps)

```
1. SAVE   → drop the source document in raw/          (your reference, never edited)
2. LEARN  → distill it into a wiki technique note     (what you learned, in your own words)
3. SHARE  → weave it into the matching skill file     (so the agent uses it next time)
```

That's it. The wiki holds *what you know*. The skills hold *what the agent does*. raw/ holds *where it came from*.

### Step-by-step

| Step | Action | Example prompt |
|------|--------|----------------|
| 1 | **Save** the source doc | `"save this writeup to raw/ssrf.md"` |
| 2 | **Learn** — turn it into a wiki note | `"create a wiki technique note from raw/ssrf.md"` |
| 3 | **Share** — add it to the skill, WITHOUT deleting anything | `"add the SSRF technique from the wiki to the injection skills, keep all existing content"` |
| 4 | **Check** — make sure nothing was lost | `"show git diff to confirm no content was removed from the skill"` |
| 5 | **Lint** — make sure everything is clean | `"lint the wiki and skills"` |

### Ready-to-paste Prompts

```
# One-liner: do the whole flow in one shot
"ingest raw/ssrf.md → wiki technique note → weave into injection skills additively → lint"

# Just the wiki step
"ingest raw/ssrf.md into the wiki"

# Just the skill step (the important one)
"update the injection skills with the new SSRF pattern from the wiki,
 but DO NOT remove or rewrite any existing content — append and merge only"

# Verify nothing was lost
"git diff the skill files — confirm only added lines, no removed content"

# Add a CVE while keeping the skill intact
"add CVE-2026-XXXX to CVE_QUEUE.json and the matching hunt block in the skill,
 keep all existing content"

# Lint everything
"lint the wiki and skills: check frontmatter, code fences, wiki links,
 and skill registry counts"
```

### The Golden Rule: Additive, Never Destructive

When the agent updates a skill, it **must** follow this rule:

- **Keep everything** that's already in the file. Old content is the floor, not disposable.
- **Weave in the new** knowledge alongside the old — same section, new payloads, updated `ORDER` line.
- **Never delete** existing lines, blocks, payloads, or references. Headings can be re-titled; body content cannot be removed.
- **Verify** with `git diff` that the update only *added* lines before finishing.
- **Lint** after every skill update.

If a prompt ever asks the agent to "rewrite" or "replace" a skill, that's wrong — always ask it to **add** and **merge** instead.

---

## Directory Conventions

| Content | Location | Rule |
|---------|----------|------|
| Recon output | `fullrecon/{slug}/` | Per-target |
| Scripts | `scripts/{slug}/` | Per-target, timestamp prefix |
| Findings | `findings/{slug}/{severity}/{vuln-class}/{title}/` | Only confirmed bugs |
| Screenshots | `images/{slug}/` | Always under target slug |
| Notes | `notes/{slug}/` | Workflow maps, intelligence |
| Wiki | `wiki/` | Knowledge base, technique notes |
| State | `essentials/` | Target config, memory, leaderboards |

**Slug format**: hostname with dots/slashes → underscores (`api.target.com:3000` → `api_target_com_3000`)

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add/modify skill files in `.opencode/skills/`
4. Update `essentials/skill_registry.json` if adding new skills
5. Submit a pull request

### Adding New Skills

1. Create 3 files: `{name}-discovery/SKILL.md`, `{name}-hunt/SKILL.md`, `{name}-reproduce/SKILL.md`
2. Register in `essentials/skill_registry.json`
3. Add phase mapping in `AGENTS.md`
4. Document in `wiki/log.md`

---

## License

MIT - use freely, modify as needed, credit appreciated.

---

*acy v4.3 - Agentic Security Research Orchestrator*
*REACT Framework | 3-File Skill Architecture | 4 Automation Engines | 51 Phases | 70+ Vulnerability Classes*

bug bounty · penetration testing · offensive security · ethical hacking · web application security · vulnerability scanner · vulnerability discovery · AI security agent · autonomous agent · security automation · red teaming · recon automation · subdomain enumeration · OSINT · CVE hunting · CVE exploit · exploit development · zero-day research · OWASP · XSS · SQL injection · SSRF · IDOR · API security · MCP server · opencode · Kali Linux · CTF solver · security research
