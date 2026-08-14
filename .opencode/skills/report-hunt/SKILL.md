---
name: report-hunt
description: PoC development, finding reports, triage, verification, pre-submit hardening. After DISCOVERY finds candidates — active testing, payload firing, CVE verification. Use when testing REPORT vulnerabilities.
---

# SKILL-REPORT-HUNT — PoC Development & Report Writing Hunt — HUNT
# Phase Coverage: 44
# Purpose: PoC script standards, finding note templates, and report writing standards

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

### The Payout Multiplier ⭐
**Source:** [[raw-refs/tanvir-idor-15500-payout]] — $15,500 confirmed payout

> "A well-written report is the difference between $500 and $5,000."

Report quality directly determines payout. The same vulnerability reported two ways can yield a 10x difference. Triagers and program managers make rapid decisions — your report must make impact OBVIOUS in the first 30 seconds.

**What separates a $5,000 report from a $500 report:**

| Factor | $500 Report | $5,000 Report |
|--------|------------|----------------|
| **Title** | "IDOR in API" | "IDOR on /api/v1/projects/{id}/documents allows any authenticated user to access private financial data of all 47M users" |
| **Repro Steps** | Vague paragraph, missing exact URLs | Numbered steps, exact curl commands, copy-paste reproducible in 2 minutes |
| **Impact** | "Users could see other users' data" | "47M users' private invoices, transactions, and business records exposed. C:H (full financial PII read), I:H (modify/delete other users' documents via PUT/DELETE)" |
| **PoC** | One screenshot | Screenshots + HTTP request/response pairs + executable PoC script + video (if complex flow) |
| **Remediation** | "Fix IDOR" | "Implement object-level authorization check at the data access layer: verify request.user.id == document.owner_id before any read/write. Use per-object ACLs, not just per-endpoint middleware." |

**Report Quality Checklist (every report, every time):**
```
□ Title: Impact-first, endpoint-specific, impact-specific
□ Severity: Honest CVSS 4.0 scoring with vector string
□ Steps: Numbered, exact curl/browser commands, reproducible in <2 minutes
□ Impact: CIA triad rated, user count, data types named, business consequence stated
□ PoC: Screenshot + HTTP request/response + clean executable script at findings/{SLUG}/{severity}/{class}/{title}/ 
□ Remediation: Specific code-level fix, not vague "add authorization"
□ Scope: Verified in-scope for the program/engagement
□ Evidence freshness: All evidence from within last 48 hours
□ No PII in report: Redact PII from screenshots, only show what proves impact
```

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

*SKILL-REPORT-HUNT — Part of the acy Agentic Security Research System v3.0*
