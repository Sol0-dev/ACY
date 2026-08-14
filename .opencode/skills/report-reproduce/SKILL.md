---
name: report-reproduce
description: PoC development, finding reports, triage, verification, pre-submit hardening. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing REPORT vulnerabilities.
---

# SKILL-REPORT-REPRODUCE — PoC Development & Report Writing Reproduce — REPRODUCE
# Phase Coverage: 44
# Purpose: Playwright-driven evidence collection for report appendices

---

## Playwright MCP Integration

Playwright captures browser-based evidence for finding reports that curl alone cannot provide.

| Report Task | Playwright Tool | Purpose |
|-------------|----------------|---------|
| **Screenshot evidence** | `browser_take_screenshot` | Capture DOM state, XSS alerts, spoofed UI, auth bypass results |
| **Console log capture** | `browser_console_messages(level="info")` | Prove JS execution (XSS markers, exfiltrated data in console) |
| **Network request logs** | `browser_network_requests` | Show exact API calls, auth headers, CORS headers as evidence |
| **Full rendered DOM** | `browser_snapshot` | Capture accessible DOM tree for report appendices |
| **Video of attack flow** | `browser_run_code_unsafe` with `page.video()` | Record full attack chain execution for triager review (use sparingly) |
| **Multi-step PoC recording** | Sequence: navigate → fill → click → screenshot → console | Build step-by-step visual evidence trail |

### Evidence Collection Workflow for Reports
```
1. browser_console_messages → clear first
2. browser_navigate(url="TARGET_WITH_PAYLOAD")
3. browser_console_messages(level="info") → grep for XSS_MARKER / exfil tokens
4. browser_take_screenshot(fullPage=true) → save as evidence PNG
5. browser_network_requests → filter for relevant API calls, export as evidence
```
→ Save screenshots with: `browser_take_screenshot(filename="findings/{SLUG}/{severity}/{class}/{title}/poc_evidence.png")`

---

## Strict Triage Validation Checklist

```
SOURCE: poorman3exp 2026 — Bug Bounty Triage Methodology
```

### 6-Step Validation Pipeline
```
1. Intake → Metadata enrichment (auto-complete asset/endpoint/auth context)
2. Compliance → Scope & policy check (hard reject if out-of-scope)
3. Duplicate → AI pre-scores similarity, cross-reference full program history
4. Reproduction → Full PoC verification in real environment
5. Severity → CVSS metric-by-metric with evidence
6. Decision → Final status + reward alignment with bounty grid
```

### CVSS Metric-by-Metric Scoring
```
□ AV: Remote over network? (public URL, no VPN needed)
□ AC: Special conditions beyond attacker's control?
□ PR: Account level needed? (publicly registrable = "None")
□ UI: Separate user action required? (wormable stored XSS = None)
□ S: Affects resources outside auth scope? (different authorization boundary)
□ C: What data can attacker access? (list exact data types)
□ I: What can attacker modify? (show actual modified state)
□ A: Can attacker disrupt service? (demonstrate degradation/crash)
```

### Golden Rule
> **Severity = maximum impact DEMONSTRATED in PoC, not theoretical impact.**

### Report Quality Gates (all must pass)
```
□ Clarity: One-line summary + step-by-step reproduction
□ Evidence: Exact HTTP requests/responses or screenshots
□ Impact: Business impact tied to real-world consequence
□ Scope: Confirmed in-scope asset at submission
□ No Destruction: PoC must be non-destructive
```

### Edge Case Rules
- Same vuln, different impact → valid ONLY if demonstrates additional impact (delta-only reward)
- Same vuln, different hosts → assess individually only if original wouldn't lead to discovery
- Same vuln class, all endpoints → one root cause = one report, first valid wins
- Privacy without security impact → closed as "Informative"
- Privacy with security impact → assessed at maximum impact (IDOR + PII = Critical)
---

*SKILL-REPORT-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
