# Setup Guide — acy Agentic Security Research Orchestrator

A complete, modular framework for autonomous security research built on opencode
(REACT loop, 50 phases, 70+ vuln classes, CVE weaponization gate, 4 automation engines).

This guide walks you through a fresh install in about 15 minutes.

---

## 1. Prerequisites

| Tool | Why | Install |
|------|-----|---------|
| **opencode** | The agent runtime (required) | [opencode.ai](https://opencode.ai) |
| **Python 3.10+** | MCP automation engines | `apt install python3 python3-pip` |
| **Node.js 18+** | Playwright / Firefox MCP servers | `apt install nodejs npm` |
| **Kali Linux** (recommended) | Security toolchain (nmap, sqlmap, gobuster...) | [kali.org](https://www.kali.org) |

## 2. Security tools used by the skills

These tools are called by the SKILL files (recon, intel, injection, etc.). Install the ones you need:

```bash
# Go-based recon/JS tools (install with Go 1.21+)
export GOBIN=/usr/local/bin
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/anew@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# Python tools
pip3 install --break-system-packages jsbeautifier
git clone https://github.com/GerbenJavado/LinkFinder /opt/LinkFinder
pip3 install --break-system-packages -r /opt/LinkFinder/requirements.txt

# Kali toolchain (optional but recommended)
apt install -y nmap ffuf gobuster sqlmap nuclei curl jq
```

If a tool is missing at runtime the skill will still run — the missing pieces just
get skipped (`2>/dev/null`), so a partial setup does not break the flow.

## 3. Clone

```bash
git clone https://github.com/Sol0-dev/ACY.git
cd ACY
```

> Note: `AGENTS.md` assumes the repo lives at `~/agents/finetune/`. If you clone
> elsewhere, either adjust the `ROOT` references in `AGENTS.md` or symlink it:
> `ln -s "$(pwd)" ~/agents/finetune`

## 4. Configure opencode.jsonc

Edit `opencode.jsonc` to match your environment:

- **caido** — set the binary path to your `caido-mcp-server` install and make sure
  Caido runs on `http://127.0.0.1:8080`
- **kali-mcp** — needs the kali MCP server on `http://127.0.0.1:9999`
- **firefox-devtools** — needs Firefox with remote debugging on port 2828
- **playwright** — config path is already relative to this repo (`mcp/playwright_mcp_config.json`)
- **oc-engines** — pure Python, runs from repo root, no config needed
- Disable any MCP server you do not use (`"enabled": false`)

## 5. Install the graphify plugin dependency

```bash
cd .opencode
npm install
cd ..
```

## 6. Launch

```bash
opencode
```

The agent should list ~20 MCP tools (caido, firefox-devtools, playwright, oc-engines, kali-mcp)
and expose all skills in `.opencode/skills/`.

## 7. Set your first target

```bash
cp essentials/TARGET.env.example essentials/TARGET.env
# edit essentials/TARGET.env — target, slug, scope, program URL, tokens
```

Then in the agent:

```
> let's hunt
> fingerprint https://example.com
> scan for CVEs
> auto research
```

## 8. Directory map

```
AGENTS.md                    ← master orchestrator (phases, rules, REACT loop)
opencode.jsonc               ← MCP server configuration
SETUP.md                     ← this guide
.opencode/skills/            ← 43 skill files (DISCOVERY/HUNT/REPRODUCE per vuln class)
mcp/                         ← automation engines (Python, no deps beyond stdlib)
  mcp_server.py              ← MCP wrapper exposing the engines as tools
  oast_manager.py            ← OAST blind-callback polling
  dom_analyzer.py            ← structural DOM differential (false-positive eliminator)
  saliency_filter.py         ← recon output filtering
  payload_mutator.py         ← deterministic payload mutation (11 strategies)
  dataset_capture.py         ← training-data capture pipeline
templates/                   ← finding / report / session / target-moc templates
essentials/                  ← state + config (TARGET.env, skill_registry.json)
  TARGET.env.example         ← copy to TARGET.env for your engagement
  STATE_TEMPLATE.md          ← per-target session state scaffold
  LOOP_STATE_TEMPLATE.md     ← per-target loop position scaffold
wiki/                        ← knowledge base (index, log, techniques/, targets/)
findings/ fullrecon/ images/ notes/ scripts/ raw/ poc/ dataset/   ← created at runtime
```

## 9. Legal

Only use against targets you are explicitly authorized to test (in-scope bug bounty
programs, your own infrastructure, or signed pentest engagements). Follow the Rules
of Engagement in `AGENTS.md`.
