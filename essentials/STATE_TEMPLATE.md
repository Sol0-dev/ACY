# STATE_TEMPLATE.md — Per-Target Session State Scaffold
# Copy to STATE_{SLUG}.md per target and update.
# SLUG = hostname with dots/slashes/colons → underscores (api.target.com:3000 → api_target_com_3000)

# STATE_{SLUG}.md — Session State

Updated: {DATE}

## Confirmed findings
1. **{SEVERITY} — {TITLE}** (CWE-XXX, CVSS X.X)
   - {what was found, endpoint, proof}
   - Path: findings/{slug}/{severity}/{vuln-class}/{title}/

## Completed tests (negative / positive-control)
- {test} → {result}
- {test} → {result}

## In progress
- {current surface / sub-phase}

## Next actions
- {A: ...}
- {B: ...}