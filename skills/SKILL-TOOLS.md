# SKILL-TOOLS -- Tool Intelligence & MCP Usage Guide
# Phase Coverage: ALL phases (loaded with every skill)
# Purpose: Maintain best tools, MCP invocation patterns, installation guides,
#          and tool selection logic for every vulnerability class.
# Auto-updates: When new tools are discovered or MCP patterns change,
#               update this skill and log in wiki.

---

## Tool Selection Matrix

| Vuln Class | Primary Tools | MCP Tools | Fallback |
|------------|--------------|-----------|----------|
| Recon | subfinder, httpx, katana, gau | - | curl, wget |
| JS Intel | jsluice, linkfinder | mcp_firefox-devtools | grep, sed |
| SQLi | sqlmap (careful), custom scripts | mcp_burp | curl |
| XSS | - | mcp_firefox-devtools, mcp_burp | curl |
| SSRF | curl, custom probes | mcp_burp_generate_collaborator_payload | - |
| IDOR | curl, custom scripts | mcp_burp | - |
| JWT | jwt_tool, custom scripts | - | python3 + PyJWT |
| OAuth | curl, custom scripts | mcp_burp | - |
| File Upload | - | mcp_firefox-devtools | curl -F |
| GraphQL | graphqlmap, custom scripts | - | curl |
| Race Conditions | python3 + httpx/asyncio | - | curl + parallel |
| Business Logic | curl, custom scripts | mcp_burp | - |
| Chain Testing | custom scripts | mcp_firefox-devtools, mcp_burp | curl |

---

## MCP Tool Invocation Patterns

### mcp_burp Suite
```
mcp_burp_get_proxy_http_history_regex(regex="pattern")
  --> Returns proxy history entries matching regex
  --> Use for: finding JS files, auth tokens, error patterns

mcp_burp_send_http1_request(host, port, use_https, request)
  --> Send raw HTTP/1.1 request
  --> Use for: smuggling, header injection, protocol attacks

mcp_burp_generate_collaborator_payload()
  --> Returns Collaborator payload for OOB testing
  --> Use for: SSRF, XXE, SQLi DNS exfil (BUG_BOUNTY/PENTEST only)

mcp_burp_get_collaborator_interactions(payload_id)
  --> Check for OOB callbacks
```

### mcp_firefox-devtools Suite
```
mcp_firefox-devtools_navigate_page(url)
  --> Load URL in headless Firefox
  --> ALWAYS use for XSS/DOM testing, never curl alone

mcp_firefox-devtools_list_console_messages()
  --> Read console output
  --> Use for: XSS confirmation (console.log, not alert)

mcp_firefox-devtools_clear_console_messages()
  --> Clear console before test

mcp_firefox-devtools_screenshot_page()
  --> Capture visual state

mcp_firefox-devtools_take_snapshot()
  --> Capture DOM snapshot
  --> Returns UID for further analysis

mcp_firefox-devtools_evaluate_script(uid, script)
  --> Execute JS in page context
  --> Use for: DOM clobbering tests, prototype pollution confirmation

mcp_firefox-devtools_list_network_requests()
  --> View network traffic
  --> Use for: API mapping, auth flow analysis
```

### mcp_kali-mcp Suite
```
mcp_kali-mcp_execute_command(command)
  --> Execute shell command in Kali environment
  --> Use for: tool execution, script running
```

---

## Tool Installation Commands

```bash
# Go tools
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  "github.com/projectdiscovery/httpx/cmd/httpx"
  "github.com/projectdiscovery/katana/cmd/katana"
  "github.com/projectdiscovery/dnsx/cmd/dnsx"
  "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
  "github.com/LukaSikic/subzy"
  "github.com/tomnomnom/waybackurls"
  "github.com/lc/gau/v2/cmd/gau"
  "github.com/BishopFox/jsluice/cmd/jsluice"
)
for tool in "${GO_TOOLS[@]}"; do
  go install "${tool}@latest"
done

# Python tools
pip install jsbeautifier httpx aiohttp

# Burp Suite (download from PortSwigger)
# Firefox with DevTools (standard installation)
```

---

## Tool Failure Logging

When a tool fails or produces unexpected results:
1. Log failure in wiki/technique/tool-failures.md
2. Try fallback tool from matrix
3. If all tools fail, use curl + manual analysis
4. Update this skill with new failure pattern

---

*SKILL-TOOLS -- Tool Intelligence Module*
*Part of the acy-1.0 Agentic Security Research System*
