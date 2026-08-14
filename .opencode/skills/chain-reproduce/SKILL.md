---
name: chain-reproduce
description: Attack chain execution, multi-class escalation, CVE chain recipes. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing CHAIN vulnerabilities.
---

# SKILL-CHAIN-REPRODUCE — Attack Chain Reproduce — REPRODUCE
# Phase Coverage: 42
# Purpose: Chain documentation template and Playwright-driven chain execution and evidence capture

---

## Chain Template

For each chain, write ~/agents/finetune/notes/{SLUG}/chains/{chain_name}.md:

```markdown
# Chain: {Name}

## FINDING A
[link to finding A note]

## FINDING B
[link to finding B note]

## CHAIN STEPS
1. [step 1: use A to achieve X]
2. [step 2: use X to achieve Y via B]
3. [step 3: demonstrate impact]

## IMPACT
CIA: [C/I/A rating]
Severity: [LOW/MEDIUM/HIGH/CRITICAL]

## PoC SCRIPT
[link to chain PoC script]

## STATUS
[CONFIRMED / ATTEMPTED / FAILED]
```

---

## Playwright MCP Integration

Attack chains span multiple surfaces — Playwright orchestrates the full chain in one browser session.

| Chain Task | Playwright Tool | Playbook |
|------------|----------------|----------|
| **End-to-end chain execution** | Sequence: `browser_navigate` → `browser_evaluate` → `browser_take_screenshot` | Execute every step in single browser session, maintaining state |
| **Cross-origin chain verification** | `browser_tabs(action="new")` for attacker origin, `browser_tabs(action="select")` for victim | Tab 1: attacker page with exploit. Tab 2: victim on target. Verify exfil. |
| **Chain evidence capture** | `browser_take_screenshot` at each step | Screenshot every chain link: CORS read → token extract → ATO |
| **Automated chain PoC** | `browser_run_code_unsafe` with playwright script | Full chain script: login → exploit → exfil → verify impact |

### Full Chain Execution Example (CORS → XSS → ATO)
```
// Tab 1 — Attacker page
1. browser_navigate(url="file:///tmp/poc_cors_exfil.html")
2. browser_click → "Fetch Departments" → verify CORS read works
3. browser_network_requests → confirm Access-Control-Allow-Origin reflected

// Tab 2 — Victim simulation (open in new tab, then switch back)
4. browser_tabs(action="new", url="https://target.com")
5. browser_evaluate → check if attack payload reached victim

// Evidence
6. browser_take_screenshot → full chain execution documented
7. browser_console_messages → capture all exfiltration logs
```

### Chain PoC Automation
```
// Single Playwright script drives the full chain:
1. Set cookies for authenticated session
2. Fetch victim data via IDOR (from browser = valid origin)
3. Submit cross-origin CORS POST
4. Trigger XSS payload on victim page
5. Read exfiltrated data from webhook.site
6. Take screenshots at each step for report
```
---

*SKILL-CHAIN-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
