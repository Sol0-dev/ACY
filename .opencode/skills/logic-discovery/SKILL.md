---
name: logic-discovery
description: Business logic, race conditions, mass assignment, ReDoS. Phase start — surface detection, parameter identification, initial probes. Use when testing LOGIC vulnerabilities.
---

# SKILL-LOGIC-DISCOVERY — Business Logic & State Manipulation Discovery — DISCOVERY
# Phase Coverage: 26-28, 35
# Vuln Classes: Business Logic Flaws, Race Conditions, Mass Assignment, ReDoS
# Purpose: Discovery patterns for logic flaws, state machine abuse, and timing-based attacks

---

## Logic Flaw Recognition Triggers

Always check these for every surface:
  - Multi-step workflows (registration, checkout, password reset, verification)
  - Numeric values that affect value (price, quantity, discount, credit, points)
  - One-time actions (coupon use, email verification, 2FA confirm, vote)
  - Role or permission state that can be changed (upgrade, admin flag, trust level)
  - Time-based constraints (cooldowns, expiry, scheduling windows)
  - Cross-account operations (share, transfer, reference, view)
  - Business rules enforced only client-side (found via JS analysis)
  - Batch operations that bypass individual limits
  - State that can be set without completing prerequisite steps

CIA MANDATE:
  C: accessing another user's data
  I: modifying state without authorization (price, role, balance, count)
  A: disrupting service (note only - never actively exploit for DoS)

---

## Phase 26: Business Logic Flaws — CIA: I:H

**Discovery Patterns:**

JS Signals:
- Client-side price/discount calculations (not validated server-side)
- Form validation logic that can be bypassed by direct API calls
- Multi-step wizards with client-side state tracking
- Hidden input fields containing prices, roles, or step indicators
- Base64-encoded JSON blobs in URLs, hidden fields, or cookies

Endpoint Discovery:
- /api/BasketItems, /api/Orders, /api/checkout, /api/coupon
- /api/account/activate, /api/user/upgrade, /api/payment
- Multi-step flow endpoints: step1, step2, confirm, complete
- State machine endpoints: PATCH with status field

Parameter Indicators:
- quantity, price, total, discount, credit, balance
- status, step, stage, phase (state machine fields)
- coupon, promo, discount_code
- role, accountType, plan, tier, isAdmin

### Type 5: Unsigned Client-Side State Manipulation

```
SOURCE: wiki/1password/findings/1password_com-f1-registration-state-manipulation.md
PATTERN: Multi-step flows (registration, checkout, password reset) that pass
         state through the client via base64-encoded JSON in URLs, cookies,
         or hidden form fields — WITHOUT cryptographic integrity (HMAC/JWT).

THREAT: Any attacker can decode, modify, and re-encode the state blob to:
         - Substitute their email/token for a victim's
         - Change account type, role, or pricing tier
         - Inject arbitrary text rendered in the DOM (UI spoofing/phishing)
         - Skip verification steps by setting verified=true
         - Modify quantities, prices, or discounts in checkout

DETECTION SIGNATURES:
  - URL contains base64 strings in path: /verify/eyJlbWFpbCI6...
  - URL contains base64 in query: ?state=eyJ...
  - Hidden form fields with base64 values
  - Cookies containing JSON state (not just session ID)
  - Base64 decodes to JSON with recognizable fields (email, token, step, type)
```

**Discovery — Base64 Detection in URLs:**
```bash
# Step 1: Collect all base64-looking strings from proxy history
mcp_burp_get_proxy_http_history_regex(regex="[A-Za-z0-9+/]{20,}={0,2}")

# Step 2: For each base64 string, decode and check if it's JSON
python3 - << 'PYEOF'
import base64, json, re, sys

candidates = [
    # Paste base64 strings here from Burp output
    "eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJ0b2tlbiI6ImFiYzEyMyJ9",
]

for b64 in candidates:
    try:
        # Try standard base64
        decoded = base64.b64decode(b64 + '=' * (4 - len(b64) % 4))
        try:
            data = json.loads(decoded)
            print(f"[UNSIGNED STATE] Fields: {list(data.keys())}")
            print(f"  Preview: {json.dumps(data)[:200]}")
            # Flag sensitive fields
            for key in data:
                if any(w in key.lower() for w in ['email','token','role','price','type','id','step','verified']):
                    print(f"  [MODIFIABLE] {key}: {data[key]}")
        except:
            print(f"[BASE64 NON-JSON] {decoded[:80]}")
    except Exception as e:
        print(f"[DECODE FAIL] {e}")
PYEOF

# Step 3: Check browser URL bar and sources for state blobs
# mcp__firefox-devtools__evaluate_script:
# () => {
#   const findings = [];
#   // Check URL for base64 segments
#   const urlParts = window.location.href.split('/');
#   for (const part of urlParts) {
#     if (/^[A-Za-z0-9+/]{20,}=*$/.test(part)) findings.push({source:'url', value:part});
#   }
#   // Check for hidden inputs with base64 values
#   document.querySelectorAll('input[type="hidden"]').forEach(el => {
#     if (/^[A-Za-z0-9+/]{20,}=*$/.test(el.value)) findings.push({source:'hidden_input', name:el.name, value:el.value});
#   });
#   return findings;
# }
```

---

## Phase 27: Race Conditions (TOCTOU) — CIA: I:H

```
TRIGGER: Phase 27 assigned, or endpoints with one-time actions, limits, or state transitions detected.
SURFACE TYPES: coupon redemption, balance withdrawals, limited-use actions (vote/like/claim),
               password reset tokens, API key generation, role/privilege changes.
CVSS RANGE: High (7.5-8.1) for business logic bypass, Critical (9.0+) for financial/ATO.
KEY INSIGHT: Microservices/serverless/distributed DBs are MORE vulnerable than monoliths.
```

**Discovery Patterns:**

JS Signals:
- Concurrent API calls in client code (Promise.all, parallel fetch)
- One-time actions sent asynchronously
- No client-side debouncing on submit buttons
- "Click once" UI enforced only via JavaScript, no server-side lock

Endpoint Discovery:
- Coupon redemption: POST /api/coupon/redeem
- Balance withdrawals: POST /api/wallet/withdraw
- Limited-use actions: /api/vote, /api/like, /api/claim
- Sequential state transitions that should be atomic
- Password reset: POST /reset-password (token collision)
- API key generation: POST /api/keys (limit overrun)
- Role changes: PATCH /api/users/{id}/role (privilege escalation)

Red Flags (Architecture):
- Read-Committed DB isolation (no locking during reads)
- Non-atomic check-then-act patterns
- Session-based state for multi-step flows
- Client-side price/role/currency parameters
- No idempotency keys on critical operations
- Microservice boundaries with eventual consistency

---

## Phase 28: Mass Assignment — CIA: I:H

**Discovery Patterns:**

JS Signals:
- User registration forms with hidden fields for role/permissions
- Profile update endpoints accepting arbitrary JSON
- API responses returning role, isAdmin, credits alongside user data
- Spread operator usage: {...userData, role: 'admin'}

Endpoint Discovery:
- POST /api/register, POST /api/signup, POST /api/users
- PUT /api/account/profile, PATCH /api/users/me
- POST /api/account/create

Parameter Indicators:
- role, isAdmin, isVerified, privilege, access_level
- credits, balance, subscription, plan, tier
- verified, emailVerified, kycVerified

---

## Phase 35: ReDoS — Regular Expression DoS — CIA: A:M

**Discovery Patterns:**

JS Signals:
- Client-side regex validation patterns (often mirrored server-side)
- Complex regex patterns with nested quantifiers
- Email/username/password validation regex transformations

Endpoint Discovery:
- POST /api/validate (email, username, password fields)
- POST /api/register, POST /api/signup
- Any endpoint accepting user input strings with server-side regex validation

Vulnerable Pattern Indicators:
- Nested quantifiers: (a+)+, ([a-zA-Z]+)*
- Alternation with repetition: (a|aa)+
- Overlapping patterns: (.*a){n}

---

*SKILL-LOGIC-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
