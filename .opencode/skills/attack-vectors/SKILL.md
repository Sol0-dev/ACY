---
name: attack-vectors
description: Attack Vector mapping (Phase 4) — bug bounty hunter mindset. Catalog endpoints, parameters, weird behaviors, and info leaks into attack_vectors/{slug}/av.md. Medium-severity bugs and every oddity are first-class; each vector is chain-tagged toward the crown jewel. Use when entering Phase 4 or when building the attack-surface map for a target.
---

# SKILL-ATTACK-VECTORS — Phase 4 — Bug Bounty Hunter Mindset

# Phase Coverage: Phase 4 (after CVE Weaponization, before Crown Jewels)
# Output: attack_vectors/{target-slug}/av.md (append-only per session)
# Vuln Classes: Attack Vector Mapping, Weirdness Catalog, Info Leak Enumeration, Chain Primitive Tagging
# Mindset: Not every finding needs to be critical. The medium bug you almost dismissed is often the pivot that unlocks the critical chain.

---

## Philosophy

```
This phase is the bridge between raw recon (Phase 0-2) and goal-driven exploitation (Phase 5).
Think like a bug bounty hunter — every weird behavior, leaked string, oddly named parameter,
unexpected error, and stale endpoint is a potential stepping stone toward the crown jewel.

RULE: Every weird thing and every piece of information can help us reach the CJ.
      Do not discard "just a medium" or "just an info leak" — write it down, score it,
      tag its chain potential. av.md is append-only per session.
```

---

## Pattern Index

| Pattern | Source | Severity | Chain Potential |
|---------|--------|----------|-----------------|
| P1: Endpoint & Parameter Enumeration | JS bundles, sitemaps, source maps | N/A | high |
| P2: Weird Behavior Catalog | differential testing, error probing | MEDIUM+ | very high |
| P3: Info Leak Harvest | headers, error msgs, version strings | LOW | high |
| P4: Chain Tagging | cross-vector correlation | N/A | critical |

---

## P1: Endpoint & Parameter Enumeration

```
EXERCISE, DO NOT JUST CATALOG:
  → Send real requests to every discovered route, method, and query/body parameter
  → Map API version variants (/v1, /v2, /beta, /internal, /legacy)
  → Enumerate GraphQL operations, WebSocket channels, SSE streams
  → Mine hidden/undocumented endpoints from JS bundles, source maps, sitemaps
  → Capture FULL request+response for each endpoint (headers, body, cookies)

RECORD IN av.md:
  → Every route + method + parameter combination
  → Auth state per endpoint (which require auth, which don't — flag inconsistencies)
  → Response differences (verbose vs terse, reflection points, differential behavior)
```

## P2: Weird Behavior Catalog

```
RECORD ALL — NO FILTERING:
  → Unusual error messages, stack traces, debug output
  → Inconsistent auth behavior (some endpoints enforce, others don't)
  → Parameter names hinting at functionality (debug=, admin=, test=)
  → Reflection points, verbose responses, differential behaviors
  → Rate-limit quirks, CORS oddities, cookie scope surprises
  → Leftover dev/test/staging artifacts reachable in production

For each weird thing, record:
  → What you sent, what the server did, what makes it weird
  → Severity estimate: LOW / MEDIUM / HIGH / CRITICAL (medium is fully valid)
  → Exploitability: trivial / needs chaining / needs privileged context
```

## P3: Info Leak Harvest

```
  → Version strings, internal hostnames, cloud bucket names, IDs
  → Emails, usernames, org structure, business relationships
  → Anything that maps the target's internals or trust relationships
  → Feed discovered versions into Phase 3 (CVE Weaponization) immediately
```

## P4: Chain Tagging

```
CLASSIFY EACH VECTOR:
  → Severity estimate: LOW / MEDIUM / HIGH / CRITICAL
  → Exploitability: trivial / needs chaining / needs privileged context
  → Chain potential: which vectors combine? (link to Phase 45 Chain Engine)
  → Crown-jewel relevance: does this help reach a Phase 5 goal? Mark it.

  Tag format in av.md:
    [SEV:MEDIUM] [EXP:needs-chaining] [CHAIN:idor+upload] [CJ:ato] /api/v2/profile/{id}
```

---

## Output Checklist (av.md)

```
□ Every discovered endpoint + param recorded with request/response evidence
□ Every weird thing recorded with severity + exploitability + chain tag
□ Every info leak recorded and version strings fed to Phase 3
□ Chain potential tagged on each vector
□ Crown-jewel relevance marked on each vector
□ File saved to attack_vectors/{target-slug}/av.md (append-only)
```

---

## Transition To Phase 5

```
Once av.md is built, load SKILL-CROWN-JEWELS (Phase 5):
  → Pick the worst-case goal and work backward, mapping each required condition
    to a primitive already tagged in av.md.
  → The medium bugs recorded here become the pivots that unlock the critical chain.
```