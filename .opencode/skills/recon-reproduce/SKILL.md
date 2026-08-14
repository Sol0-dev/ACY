---
name: recon-reproduce
description: Reconnaissance, subdomain discovery, dependency confusion, open directory enumeration. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing RECON vulnerabilities.
---

# SKILL-RECON-REPRODUCE — Reconnaissance Reproduce — REPRODUCE
# Phase Coverage: 36-37, 39
# Vuln Classes: Subdomain Takeover, Dependency Confusion, Info Disclosure
# Purpose: Confirmation, PoC creation, and chain output for recon-derived findings

---

## Phase 36: Subdomain Takeover — REPRODUCE

```
SUB-PHASE 36.3: REPRODUCE
  → Confirm: CNAME points to abandoned service, claimable by attacker
  → PoC: scripts/{SLUG}/subdomain-takeover.sh
  → Save: findings/{SLUG}/{severity}/subdomain-takeover/{title}/

CHAIN OUTPUT:
  → Subdomain takeover (high) + .target.com cookie scope = steal main auth cookies (critical)
  → Subdomain takeover + XSS on claimed subdomain = ATO on main app (critical)
  → Subdomain takeover + CORS trust = read main app API data (critical)
```

## Phase 37: Dependency Confusion — REPRODUCE

```
SUB-PHASE 37.3: REPRODUCE
  → Confirm: internal package name not owned on public registry
  → PoC: scripts/{SLUG}/dependency-confusion.sh
  → Save: findings/{SLUG}/{severity}/dependency-confusion/{title}/

CHAIN OUTPUT:
  → Dependency confusion (critical) → malicious package executes on build (critical)
```

## Phase 39: Security Misconfiguration / Info Disclosure — REPRODUCE

```
SUB-PHASE 39.3: REPRODUCE
  → Confirm: localStorage secret usable, config reveals internal infra, debug open
  → Save: findings/{SLUG}/{severity}/info-disclosure/{title}/
  → Each pattern has its own validation checklist in SKILL-INFODISCLOSURE.md

CHAIN OUTPUT:
  → localStorage secret (medium) + XSS = full ATO (critical) — Coinhako C1
  → HTML config (low) + CORS with creds = cross-origin steal (high) — Agoda F1
  → SDK secret (high) + 3rd-party access = lateral movement (high) — Coinhako C2
  → Cloud creds (high) + bucket listing = data breach (critical) — Coinhako M5
  → .env exposed (critical) → credentials → full backend access (critical)
  → .git/config exposed (high) → source code → additional vulns (critical)
```

---

*SKILL-RECON-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
