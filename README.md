# acy-1.0 -- Agentic Cyber Yield

> An autonomous, self-evolving security research agent for bug bounty hunting, web penetration testing, and vulnerability disclosure.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What is acy?

**acy** (Agentic Cyber Yield) is a production-ready AI agent framework that automates the entire vulnerability research workflow:

1. **Reconnaissance** -- subdomain enumeration, endpoint discovery, JS intelligence
2. **Application Understanding** -- deep analysis of JavaScript, API mapping, surface classification
3. **Vulnerability Discovery** -- systematic testing across 40+ vulnerability classes
4. **Attack Chaining** -- combining findings into critical-impact reports
5. **Auto-Skill Evolution** -- the agent proposes new skills when wiki knowledge grows beyond current coverage

### Key Differentiators

| Feature | Why It Matters |
|---------|---------------|
| **Auto-Skill Evolution** | When the wiki documents techniques not in skills, the agent proposes new SKILL-*.md files. User validates -> skill created -> phases updated. The agent gets smarter over time. |
| **45-Phase Engine** | Every vulnerability class gets Discovery -> Hunt -> Reproduce sub-phases. No random spraying. |
| **Chain Engine** | Automatically combines medium/low findings into critical reports (e.g., IDOR + CORS = mass PII exfiltration). |
| **Away Mode** | Full autonomous loop while you sleep. Returns with a full debrief. |
| **Session Continuity** | Resume from exact position. Never restart. Never lose progress. |
| **Hallucination Reduction** | Every claim must cite evidence. Confidence scores (1-5). Wiki-grounded citations. |
| **DeepSeek Optimized** | Configured for deepseek-v4-pro with max effort level. |

---

## Architecture

```
acy-1.0/
|-- CLAUDE.md              # Orchestrator -- master workflow engine
|-- README.md              # This file
|-- setup.sh               # One-command setup
|-- skills/                # 9 modular skill files (expandable)
|-- wiki/                  # Persistent knowledge base (markdown + YAML)
|-- templates/             # Reusable templates (findings, reports, sessions)
|-- essentials/            # State files, tokens, leaderboard
|-- fullrecon/             # Recon output per target
|-- notes/                 # Workflow maps per target
|-- scripts/               # Test scripts per target
|-- findings/              # Confirmed bugs per target
```

### Tri-Layer Architecture

```
Layer 3: Wiki (Persistent Knowledge)
  --> Markdown notes with YAML frontmatter
  --> Bi-directional links between findings, techniques, targets
  --> Auto-skill evolution triggers when knowledge exceeds skill coverage

Layer 2: Reasoning Core
  --> Attack chain synthesis, threat modeling, logic flaw analysis
  --> Skill gap analysis -- proposes new skills from wiki data

Layer 1: Tool Execution
  --> Burp Suite, Firefox DevTools, Kali, curl, custom scripts
  --> SKILL-TOOLS.md guides which tool for which task
```

---

## Quick Start

### 1. Clone / Extract

```bash
cd ~/agents
git clone https://github.com/yourusername/acy-1.0.git
# OR unzip acy-1.0.zip -d ~/agents/acy-1.0
cd acy-1.0
```

### 2. Run Setup

```bash
chmod +x setup.sh
./setup.sh
```

This creates:
- Runtime directories (`fullrecon/`, `notes/`, `scripts/`, `findings/`)
- State files (`TARGET.env`, `STATE_*.md`, `LOOP_STATE_*.md`)
- Skill registry and evolution log

### 3. Configure Target

Edit `essentials/TARGET.env`:

```bash
TARGET="https://api.target.com"
SLUG="api_target_com"
USER1_TOKEN="eyJhbGciOiJIUzI1NiIs..."  # normal user token
USER2_TOKEN="eyJhbGciOiJIUzI1NiIs..."  # second user token
CSRF_TOKEN="abc123..."
ROOT_DOMAIN="target.com"
PROGRAM_TYPE="bug_bounty"
```

### 4. Configure DeepSeek (if using)

```bash
# Add to ~/.bashrc or ~/.zshrc
export ANTHROPIC_AUTH_TOKEN="sk-yourapikey"
export ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic"
export ANTHROPIC_MODEL="deepseek-v4-pro"
export ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-v4-pro"
export ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-v4-pro"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-v4-flash"
export CLAUDE_CODE_SUBAGENT_MODEL="deepseek-v4-flash"
export CLAUDE_CODE_EFFORT_LEVEL="max"

# Claude Code setup
cat > ~/.claude.json << 'EOF'
{"hasCompletedOnboarding": true}
EOF
rm -f ~/.claude/settings.json
rm -rf ~/.claude/backups/
```

### 5. Start Hunting

```bash
cd ~/agents/acy-1.0
claude
```

Then say: **"let's hunt"**

The agent will:
1. Load `TARGET.env`
2. Check `STATE_*.md` for last position
3. Resume or start Phase 0 (Reconnaissance)
4. Run the full workflow autonomously

---

## Natural Language Commands

| You Say | Agent Does |
|---------|-----------|
| "let's hunt" | Resume from last position, start hunting |
| "hunt for sql injection" | Prioritize SQLi on current surfaces |
| "test /api/users endpoint" | Apply full playbook to that endpoint |
| "what did we find?" | Print findings summary |
| "I'm going to bed" | Activate Away Mode -- full autonomy |
| "I'm back" | Print debrief of everything done |
| "evolve skills" | Run skill gap analysis, propose new skills |
| "new skill for http/2" | Propose skill for specific topic |
| "resume" / "continue" | Resume exact position, never restart |

---

## Skill System

### Current Skills (9)

| Skill | Phases | Coverage |
|-------|--------|----------|
| SKILL-RECON.md | 0, 36-37, 39, 43 | Subdomain enum, takeover, info disclosure |
| SKILL-INTEL.md | 0-1 | JS analysis (8 phases), app mapping |
| SKILL-INJECTION.md | 3-4, 7-10, 18-19, 22-24, 31-32, 38, 40-41 | SQLi, NoSQLi, SSRF, XXE, SSTI, CMDi, LFI, RFI, GraphQL, LDAP, XPath |
| SKILL-AUTH.md | 11-15, 34 | IDOR, JWT, OAuth, access control |
| SKILL-CLIENTSIDE.md | 5-6, 17, 20-21, 25, 29-30, 33 | XSS, CSRF, CORS, prototype pollution, WebSocket |
| SKILL-LOGIC.md | 26-28, 35 | Business logic, race conditions, mass assignment |
| SKILL-CHAIN.md | 42 | Attack chain execution |
| SKILL-REPORT.md | 44 | PoC development, report writing |
| SKILL-TOOLS.md | ALL | Tool selection, MCP usage, installation |

### Auto-Skill Evolution

When the wiki documents techniques not covered by existing skills:

1. **Scan**: Compare wiki technique pages vs. skill registry
2. **Analyze**: Extract discovery methods, payloads, reproduction steps
3. **Propose**: Generate SKILL-{NAME}.md draft with full playbook
4. **Validate**: User reviews and approves/modifies
5. **Update**: Register skill, update phase table, log evolution
6. **Activate**: New skill available immediately

Example: Wiki documents "HTTP/2 Rapid Reset" -> Agent proposes SKILL-HTTP2.md -> User approves -> Phase 46 created -> Next session loads automatically.

---

## The 45-Phase Engine

```
Phase 0   : Reconnaissance + JS Intelligence
Phase 1   : Application Understanding + Surface Mapping
Phase 2   : Surface Classification + Vulnerability Priority Assignment
Phases 3-41: Per-Vulnerability Discovery / Hunt / Reproduce
Phase 42  : Attack Chain Execution
Phase 43  : Subdomain Expansion
Phase 44  : Verification + Pre-Submit Hardening
Phase 45  : Loop & Self-Improvement (never ends)
Phases 46+: Auto-generated from skill evolution
```

---

## Wiki System

Every finding, technique, target, and session gets a markdown note with YAML frontmatter:

```yaml
---
id: uuid-here
date: 2026-06-25T20:00:00Z
type: finding
status: confirmed
confidence: 5
severity: critical
cia: C:H I:H
target: api_target_com
vuln_class: sqli
links:
  - [[wiki/target/api_target_com]]
  - [[wiki/technique/sqli]]
---
```

Bi-directional links (`[[wiki/page-name]]`) create a knowledge graph that compounds over time.

---

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for:
- How to propose new skills
- Wiki formatting standards
- Tool integration guidelines
- Chain recipe contributions

---

## License

MIT License -- see [LICENSE](LICENSE)

---

*acy-1.0 -- Agentic Cyber Yield*
*Built for white-hat security researchers who never stop hunting.*
