---
name: logic-reproduce
description: Business logic, race conditions, mass assignment, ReDoS. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing LOGIC vulnerabilities.
---

# SKILL-LOGIC-REPRODUCE — Business Logic & State Manipulation Reproduction — REPRODUCE
# Phase Coverage: 26-28, 35
# Vuln Classes: Business Logic Flaws, Race Conditions, Mass Assignment, ReDoS
# Purpose: Confirmation criteria, PoC standards, and Playwright-based reproduction

---

## Confirmation Criteria

A finding in any logic vulnerability phase is valid ONLY when the following are confirmed:

### Phase 26: Business Logic Flaws
- [ ] Negative or extreme price/quantity values produce order total below expected value
- [ ] Payment step can be bypassed entirely (order fulfilled without payment)
- [ ] Coupon code can be reused multiple times (single-use bypassed)
- [ ] Prerequisite steps in a multi-step workflow can be skipped
- [ ] Numeric boundaries overflow/underflow to unexpected values
- [ ] Order/account status can be changed to disallowed states
- [ ] Business rules (max items, discount limits) enforced client-side only — API bypass works
- [ ] Unauthorized state transitions succeed (e.g., "pending" to "delivered")

### Phase 27: Race Conditions
- [ ] More than one concurrent request succeeds for a single-use action (coupon, withdrawal, vote)
- [ ] Parallel requests produce different outcome than sequential requests
- [ ] TOCTOU window confirmed between validation and operation
- [ ] Success rate >30% with parallelism (reliably exploitable)
- [ ] Increasing parallelism increases success rate
- [ ] Connection warming improves reliability

**Validation Checklist (Full):**
```
□ Confirm: >3 reproductions, parallel-only, scaling with parallelism
□ Measure: request count (20-50), success rate (>30%), warming improvement
□ Prove: financial loss calculation, ATO demonstration, impact chain
□ Document: response differences, timing data, database state before/after
□ Wireshark: verify single-packet delivery (multiple HTTP/2 HEADERS in one TCP segment)
```

**Response Patterns (Report):**
  → 200 + 200 = limit overrun confirmed
  → 200 + 403 = partial race, increase parallelism
  → 200 + 500 = DB constraint violation, strong indicator
  → Same token = token collision, ATO potential
  → Different balances = double-spending, financial impact

**CVSS Template:**
  CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N = 7.5 (High)

**Root Cause (for report):**
  1. Non-atomic check-then-act pattern
  2. Read-Committed DB isolation (no locking during reads)
  3. No idempotency key or distributed lock
  4. Usage counter updated after operation completes

**Remediation (for report):**
  1. Atomic transactions: BEGIN → SELECT ... FOR UPDATE → UPDATE → COMMIT
  2. Idempotency keys for all financial operations
  3. Distributed locks (Redis, ZooKeeper) for critical operations
  4. Serializable DB isolation for coupon/withdrawal operations
  5. Application-level rate limiting per user per action

### Phase 28: Mass Assignment
- [ ] Registration with role=admin field in body creates admin account
- [ ] Profile update with isAdmin=true field elevates privileges
- [ ] Extra fields in request body modify sensitive account properties

### Phase 35: ReDoS
- [ ] Crafted input causes response time > 4 seconds
- [ ] Server CPU spikes confirm regex backtracking (note only — never repeatedly exploit)

---

## Type 5: Unsigned Client-Side State Manipulation — Analysis Checklist

```
□ Does the state blob decode to readable JSON?
□ Can you modify fields and the application accepts them?
□ Is there NO HMAC, JWT, or checksum protecting integrity?
□ Does the tampered state persist across the flow?
□ Can you substitute another user's identifier?
□ Can you inject text that renders in the DOM?
□ Can you skip verification steps?

FALSE POSITIVE CHECK:
  - State has HMAC/JWT signature that fails on tamper → PROTECTED
  - Server validates state against server-side session → PROTECTED
  - Tampered state returns 400/redirect to start → VALIDATED (but check bypasses)
  - State is only used for display (no security decisions) → lower severity
  - State is encrypted (not just encoded) → higher barrier but still test
```

### Type 5: Browser Confirmation (UI Spoofing)
```
mcp__firefox-devtools__navigate_page(url="CRAFTED_TAMPERED_URL")
mcp__firefox-devtools__take_snapshot()
→ Check if injected text renders on the legitimate domain
→ Check URL bar — still shows valid TLS on target domain
mcp__firefox-devtools__screenshot_page()
→ Capture evidence of spoofed content on legitimate domain
```

---

## PoC Standards

Every valid finding MUST include:

1. **Reproducible Proof Script**: A clean `.sh` or `.py` file in `scripts/{SLUG}/` that:
   - Sets TARGET and TOKEN variables at the top
   - Executes the exact request(s) that prove the vulnerability
   - Outputs the evidence (response body, status code, timing)
   - Requires no interactive input

2. **Finding Note**: Markdown file in `findings/{SLUG}/{severity}/{vuln-class}/{title}/` with:
   - Title describing the impact (e.g., "Race condition allows infinite coupon reuse")
   - CIA impact rating
   - Reproduction steps with exact payloads
   - Evidence: request/response pairs, timing data, screenshots
   - Chain candidates (how this can combine with other findings)

3. **Evidence Artifacts**:
   - For price manipulation: before/after totals showing negative price
   - For race conditions: multiple success responses from parallel requests
   - For mass assignment: user object showing elevated role
   - For Type 5: screenshot of spoofed content on legitimate domain with valid TLS
   - For ReDoS: timing diff between normal and crafted input

---

## Playwright MCP Integration

Logic flaws involve multi-step flows — Playwright drives complex UX workflows that curl can't.

| Logic Phase | Playwright Tool | Playbook |
|-------------|----------------|----------|
| **Workflow Bypass (Phase 26)** | Skip prerequisite pages, navigate directly to later steps | `browser_navigate` to step 3 URL, verify it works without steps 1-2 |
| **Race Conditions (Phase 27)** | `browser_evaluate` → `Promise.all(fetch()*25)` | Fire 25 concurrent requests from browser, count successes > 1 |
| **Mass Assignment (Phase 28)** | `browser_evaluate` → submit registration with `role=admin` | Inject privileged fields into fetch body |
| **Unsigned State (Type 5)** | Decode→modify→re-encode base64 state, navigate, screenshot | `browser_navigate` to tampered URL, `browser_snapshot` to verify UI spoofing |
| **Coupon Reuse / Checkout** | `browser_fill_form` + `browser_click` on checkout steps | Drive full e-commerce flow, apply coupon, observe total |
| **State Machine Attacks** | `browser_evaluate` → PATCH order status directly | Skip from "pending" to "delivered" via API from browser context |

### Race Condition — Parallel Fetch in Browser
```
mcp__playwright__browser_evaluate({
  function: `async () => {
    const results = await Promise.all(
      Array(25).fill().map(() =>
        fetch('/api/coupon/redeem', {
          method: 'POST', credentials: 'include',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({code: "SAVE50"})
        }).then(r => r.status)
      )
    );
    return { total: 25, successes: results.filter(s => s === 200).length };
  }`
})
// successes > 1 = race condition confirmed
```

### State Manipulation — Browser Verification
```
1. browser_navigate(url="tampered_base64_state_url")
2. browser_snapshot → verify injected text renders on legitimate domain
3. browser_take_screenshot → capture spoofed content with valid TLS URL bar
4. browser_evaluate → continue flow with tampered state, observe backend acceptance
```
---

*SKILL-LOGIC-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
