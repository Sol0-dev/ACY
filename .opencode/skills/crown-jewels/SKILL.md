---
name: crown-jewels
description: Crown Jewels definition (Phase 5) — malicious attacker mindset. Define the worst-case goal in crown_jewels/{slug}/cj.md (e.g. delete every user profile, bypass auth/rate limits, abuse weird functionality), work backward to primitives from av.md, and find bugs while using the application. Use when entering Phase 5 or when setting a target goal before exploitation.
---

# SKILL-CROWN-JEWELS — Phase 5 — Malicious Attacker Mindset

# Phase Coverage: Phase 5 (after Attack Vectors, before per-vuln phases)
# Output: crown_jewels/{target-slug}/cj.md
# Vuln Classes: Goal Definition, Backward Primitive Mapping, Application Dogfooding, Bug Discovery
# Mindset: Think like a malicious attacker — not a scanner. Ask "what is the worst thing I could do to this application and its users?" Then work backward from that goal.

---

## Philosophy

```
No goal = no direction. Define the crown jewel, then let the application itself
show you the bugs as you use it to get there.

The goal is not the only prize — the bugs you meet on the way to it are.
Every bug found while chasing the goal is captured in av.md (Phase 4) and, if it
demonstrates impact, promoted to a finding via REPRODUCE.
```

---

## Pattern Index

| Pattern | Source | Focus |
|---------|--------|-------|
| P1: Define Worst-Case Goal | app feature surface | impact |
| P2: Decompose Into Conditions | goal requirements | conditions |
| P3: Map To Primitives | av.md (Phase 4) | primitives |
| P4: Hunt The Gap | missing primitives | bug birth |
| P5: Dogfood The Application | real user flows | opportunistic bugs |

---

## P1: Define Worst-Case Goal

```
Ask "what is the worst thing I could do to this application and its users?"
Write the goal in cj.md as a concrete, impact-stating sentence. Examples:

  → Delete every user profile — find the endpoint that allows deletion, then
    find the access-control / IDOR / mass-assignment flaw that lets one request
    (or a loop) wipe accounts you do not own.
  → Bypass something — auth, rate limits, payment, approval workflows, quotas.
  → Abuse weird functionality — export, import, invite, share, bulk actions,
    password reset, account merge, admin tooling, "hidden" debug features.
  → Mass data exfiltration, privilege escalation, full account takeover,
    financial manipulation, business-logic abuse.
```

## P2: Decompose Into Required Conditions

```
Decompose the goal into required conditions:
  → auth, ID ownership, CSRF token, role, feature flag, timing, sequence
Each condition is a gate the attacker must pass. Missing one = the gap to hunt.
```

## P3: Map To Primitives

```
Map each condition to an available primitive from Phase 4 attack_vectors/av.md:
  → endpoint, parameter, leak, behavior
If a condition maps cleanly, the chain path exists. If not, you found the gap.
```

## P4: Hunt The Gap

```
Identify the gap: what is missing to complete the chain?
Hunt the gap — this is where real bugs are born.

  → If the delete endpoint exists but requires ownership: test IDOR on the ID param
  → If the admin flag exists in the profile object: test mass assignment
  → If auth is enforced on some endpoints but not others: test the gap endpoints
```

## P5: Dogfood The Application

```
Use the application like a real user (register, buy, invite, delete, share).
While USING the app to reach the goal, bugs surface naturally:
  → broken workflows, missing checks, race windows, logic flaws
  → IDOR on the very endpoints the goal depends on

Capture everything in av.md (Phase 4). Promote impact-proving bugs to findings.
```

---

## Output Checklist (cj.md)

```
□ Worst-case goal written as a concrete, impact-stating sentence
□ Goal decomposed into required conditions
□ Each condition mapped to an av.md primitive (or marked as a gap)
□ Gap identified and queued for hunting
□ Application dogfooded — every flow toward the goal exercised
□ Bugs found while dogfooding recorded in av.md
```

---

## Transition To Phases 6-44

```
With the goal and primitive map in place, enter the per-vulnerability phases:
  → Fire the relevant SKILL-{VULN_CLASS}-{DISCOVERY|HUNT|REPRODUCE} on the gaps
  → Every finding along the way is weighed against the crown-jewel goal
```