# SKILL-REPORT - PoC Development & Report Writing
# Phase Coverage: 44
# Purpose: Clean reproducible PoC creation, impact assessment, and professional reporting

---

## Phase 44: Verification + Pre-Submit Hardening

```
TRIGGER: After all surfaces tested, before any submission.
RUNS: Once per confirmed finding before it leaves the agent.

PRE-SUBMIT CHECKLIST (every finding MUST pass):
  [ ] Reproducible: Can the PoC script run from a fresh terminal and produce the same result?
  [ ] Impact demonstrated: Does the PoC show actual data modification, unauthorized access, or value manipulation?
  [ ] No false positive: Is the result definitely a bug, not a WAF anomaly or normal behavior?
  [ ] Scope verified: Is the target in scope for the current engagement?
  [ ] No PII storage: Is any PII in the PoC output redacted or minimal?
  [ ] Clean PoC: Is the PoC script free of unnecessary noise, comments explain each step?
  [ ] Chain evaluated: Has Phase 42 (Chain Engine) been run on this finding?
  [ ] Wiki linked: Does the finding note link to the target MOC and technique wiki pages?
  [ ] CIA rated: Is Confidentiality/Integrity/Availability impact explicitly rated?

HONEST TRIAGE:
  If a finding does NOT pass all checks -> do NOT report. Log as near-miss in wiki.
  If impact is self-only and no escalation path -> do NOT report. Log in wiki.
  If finding is informational only (missing header, version disclosure) -> do NOT report.
  If finding requires unlikely user action (self-XSS with no delivery mechanism) -> do NOT report.
```

---

## PoC Script Standards

### Naming Convention
```
scripts/{SLUG}/Test#N_{vuln-class}_{surface}.sh   <- working test scripts
findings/{SLUG}/{severity}/{vuln-class}/{title}/{title}.sh  <- final clean PoC
```

### PoC Script Template
```bash
#!/bin/bash
# PoC: {Title}
# Target: {TARGET}
# Vuln Class: {class}
# Severity: {severity}
# CIA Impact: C:{C} I:{I} A:{A}
# Date: {date}
# Reporter: acy Agent

TARGET="{TARGET}"
TOKEN="{USER1_TOKEN}"

# Step 1: [what this step does]
# Expected: [what should happen]
RESP=$(curl -sk -X {METHOD} "$TARGET{ENDPOINT}" \
       -H "Authorization: Bearer $TOKEN" \
       -H "Content-Type: application/json" \
       -d '{PAYLOAD}')

echo "$RESP" | jq .

# Step 2: [verification step]
# Expected: [impact demonstration]
```

### Finding Note Template (YAML frontmatter)
```markdown
---
id: {uuid}
date: {ISO8601}
type: finding
status: confirmed
confidence: 5
severity: {critical|high|medium|low}
cia: {C:H/I:H/A:H etc}
target: {target-slug}
vuln_class: {class}
surface: {endpoint}
links:
  - [[wiki/target/{slug}]]
  - [[wiki/technique/{class}]]
  - [[wiki/session/{session_id}]]
---

# {Impact-First Title}

## Summary
[One paragraph: what the bug is and why it matters]

## Impact
- Confidentiality: [C rating and explanation]
- Integrity: [I rating and explanation]
- Availability: [A rating and explanation]

## Steps to Reproduce
1. [step with exact request/response]
2. [step]
3. [step]

## Evidence
```
[request/response showing the bug]
```

## PoC Script
[link to {title}.sh]

## Chain Potential
[What other findings could this chain with?]

## Recommendations
[How to fix]
```

---

## Report Writing Standards

### Title Format
```
[Impact-First]: [Specific Action] on [Specific Target] via [Vulnerability]

GOOD:  "Account Takeover via JWT alg:none on api.target.com"
GOOD:  "Mass PII Exfiltration via IDOR + CORS Misconfiguration"
BAD:   "SQL Injection Found"
BAD:   "XSS in Search"
```

### Severity Calibration
```
CRITICAL: Immediate, widespread, no user interaction required
  - Mass ATO, RCE, full DB dump, cloud credential theft

HIGH: Significant impact, may require some conditions
  - Single ATO, admin access, PII of multiple users, financial manipulation

MEDIUM: Real impact but limited scope or requires user action
  - Single-user data exposure, CSRF with action, reflected XSS on auth page

LOW: Minor impact, hard to exploit, or self-only
  - Info disclosure (non-sensitive), open redirect, missing headers
```

### Report Structure
```markdown
# Executive Summary
[2-3 sentences: what was found, how bad it is, what could happen]

# Technical Details
## Vulnerability
[What class, where, why it exists]

## Proof of Concept
[Step-by-step with exact requests/responses]

## Impact Assessment
[CIA triad breakdown with specific data types affected]

## Affected Assets
[URLs, endpoints, versions]

## Recommendations
[Specific, actionable fix for each finding]

# Appendix
[PoC scripts, additional evidence, chain diagrams]
```

---

*SKILL-REPORT - PoC Development & Report Writing Module*
*Part of the acy Agentic Security Research System*
