---
title: "{TITLE}"
date: "{DATE}"
severity: "{SEVERITY}"
vuln_class: "{VULN_CLASS}"
cwe: "{CWE_ID}"
cvss: "{CVSS_SCORE}"
cvss_vector: "{CVSS_VECTOR}"
target: "{TARGET}"
endpoint: "{ENDPOINT}"
status: confirmed
confidence: 5
tags: []
links: []
---

# {TITLE}

## Summary

{One paragraph: what the vulnerability is, where it was found, and why it matters.}

## Vulnerability Details

{Technical description of the vulnerability. What is broken? Why is it exploitable?}

## Steps to Reproduce

1. {First step}
2. {Second step}
3. {Third step}

## Proof of Concept

### Request

```http
{Actual HTTP request used}
```

### Response

```http
{Actual HTTP response received}
```

### PoC Script

```bash
{Clean, executable script that reproduces the finding}
```

## Impact

**Confidentiality**: {None/Low/Medium/High} — {Explanation}
**Integrity**: {None/Low/Medium/High} — {Explanation}
**Availability**: {None/Low/Medium/High} — {Explanation}

{Plain-English explanation of what an attacker can achieve}

## Remediation

{Specific fix recommendations with code examples where applicable}

## References

- CWE: {CWE_URL}
- CVE: {CVE_URL}
- OWASP: {OWASP_URL}

---
*Finding saved: {TIMESTAMP}*
*Agent: acy v3.3*
