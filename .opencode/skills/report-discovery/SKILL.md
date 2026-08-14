---
name: report-discovery
description: PoC development, finding reports, triage, verification, pre-submit hardening. Phase start — surface detection, parameter identification, initial probes. Use when testing REPORT vulnerabilities.
---

# SKILL-REPORT-DISCOVERY — PoC Development & Report Writing Discovery — DISCOVERY
# Phase Coverage: 44
# Purpose: Verification checklist and honest triage rules for pre-submit hardening

---

## Phase 44: Verification + Pre-Submit Hardening

```
TRIGGER: After all surfaces tested, before any submission.
RUNS: Once per confirmed finding before it leaves the agent.
```

### Pre-Submit Checklist

```
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
```

### Honest Triage

```
HONEST TRIAGE:
  If a finding does NOT pass all checks -> do NOT report. Log as near-miss in wiki.
  If impact is self-only and no escalation path -> do NOT report. Log in wiki.
  If finding is informational only (missing header, version disclosure) -> do NOT report.
  If finding requires unlikely user action (self-XSS with no delivery mechanism) -> do NOT report.
```

---

## GDPR Severity Multiplier

```
SOURCE: raw/Privilege Escalation Bug Bounty Arsenal — Key Mindset Rules (2026)
RULE: Accessing another user's PII on an EU target is a GDPR violation by definition.
      Always mention this to raise severity.

WHEN TO APPLY:
  → Target serves EU users (check privacy policy, geo-blocking, language)
  → Finding exposes PII (email, name, address, payment, health data)
  → Finding enables mass data access (IDOR, SQLi, API over-exposure)

SEVERITY UPGRADE:
  MEDIUM PII exposure → HIGH (GDPR violation)
  HIGH PII exposure → CRITICAL (GDPR + mass impact)
```

### GDPR Language Template

```
GDPR IMPACT:
This vulnerability exposes personal data (PII) of EU residents without authorization,
constituting a potential violation of GDPR Article 5 (principles relating to processing
of personal data) and Article 32 (security of processing). The exposed data includes:
  - [list specific PII types: email, name, address, payment method, etc.]

Under GDPR, this represents unauthorized access to personal data, potentially triggering
notification obligations under Articles 33-34 (breach notification to supervisory authority
and data subjects).
```

---

## Chaining Report Template

```
SOURCE: raw/Privilege Escalation Bug Bounty Arsenal — Section 3
PATTERN: Highest payouts come from chaining small issues into critical exploits.

CHAIN REPORT FORMAT:
  Title: [Critical] Chain: {Low Finding A} + {Medium Finding B} → {Critical Impact}
  
  Summary: This report demonstrates a vulnerability chain combining {Finding A}
  ({description}) with {Finding B} ({description}), resulting in {critical impact}.
  
  Individual Findings:
    1. {Finding A} — {severity} — {one-line description}
    2. {Finding B} — {severity} — {one-line description}
  
  Chain Exploitation Steps:
    Step 1: {How to exploit Finding A}
    Step 2: {How to leverage Finding A's output into Finding B}
    Step 3: {Final impact demonstration}
  
  Impact: The chain enables {critical impact} that neither vulnerability achieves alone.
  
  Remediation: Fix both issues. The chain is only exploitable when both are present.
```

### Common Chain Patterns

```
| Chain | Components | Potential Impact |
|-------|-----------|-----------------|
| Hidden admin endpoint + Mass assignment | No auth on admin path + role injection | Full admin takeover |
| Shadow /v2 endpoint + BOLA | Old API + broken access | Mass PII leak |
| Debug param + verbose errors + SSRF | Info leak → internal endpoint → metadata | Cloud credential theft |
| JWT weak secret + admin API | Forge admin token + access admin endpoints | Full system compromise |
| IDOR + CORS misconfiguration | Read other user's data + exfiltrate cross-origin | Session hijacking |
| Open redirect + OAuth flaw | Steal auth code + account takeover | Mass ATO |
| Missing header + XSS | No CSP + reflected XSS | Cookie theft, session hijacking |
| SQLi + auth bypass | Database access + credential extraction | Full database compromise |
```

---

## CVE Weaponization Report Template

```
SOURCE: AGENTS.md — CVE Weaponization Pipeline (Phase 48)
PATTERN: When technology versions are discovered, immediately map to known CVEs.

REPORT FORMAT:
  Title: [Critical] {CVE-ID}: {Vulnerability Name} in {Technology} {Version}
  
  Summary: The target uses {Technology} version {exact version}, which is vulnerable
  to {CVE-ID} ({vulnerability name}). This CVE enables {impact description}.
  
  Affected Component:
    Technology: {technology name}
    Version: {exact version confirmed from {source}}
    CVE: {CVE-ID} (NVD: https://nvd.nist.gov/vuln/detail/{CVE-ID})
    CVSS: {score} ({severity})
  
  Exploitation:
    Method: {adapted PoC / custom exploit}
    Source: {GitHub PoC URL / exploit-db URL / original researcher credit}
    Adaptation: {what was changed for this target}
  
  Steps to Reproduce:
    Step 1: {confirm version}
    Step 2: {run adapted exploit}
    Step 3: {demonstrate impact}
  
  Impact: {demonstrated impact — data access, RCE, privilege escalation}
  
  Remediation: Upgrade to {fixed version} or apply patch from {advisory URL}
```

---

*SKILL-REPORT-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
