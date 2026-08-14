---
name: chain-discovery
description: Attack chain execution, multi-class escalation, CVE chain recipes. Phase start — surface detection, parameter identification, initial probes. Use when testing CHAIN vulnerabilities.
---

# SKILL-CHAIN-DISCOVERY — Attack Chain Discovery — DISCOVERY
# Phase Coverage: 42
# Purpose: Chain Engine philosophy, priority rules, and queue management for multi-class escalation

---

## Chain Engine Philosophy

```
A single vulnerability class is rarely the final impact.
The real impact comes from CHAINING: combining two or more vulnerabilities
so that the output of one feeds directly into the input of another.
```

## Chain Priority Rules

```
CHAIN PRIORITY RULES:
  1. ALWAYS chain after every confirmed finding (Phase 42)
  2. NEVER leave a medium/low finding unchained in CHAIN_QUEUE
  3. The chain must be REPRODUCIBLE end-to-end with a single script
  4. Chain impact is the SUM of individual impacts, not the max
  5. A chain that reaches C:H or I:H on the main app = HIGH or CRITICAL
```

## Chain Queue Management

```
CHAIN QUEUE MANAGEMENT:
  - After confirming any finding, add it to CHAIN_QUEUE
  - For each finding in CHAIN_QUEUE, evaluate chain candidates from wiki
  - Attempt top 3 chain candidates per finding
  - Log chain attempts (success/failure) in wiki chain notes
  - Remove from queue only after all candidates exhausted or chain confirmed
```

---

*SKILL-CHAIN-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
