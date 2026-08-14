---
name: goal
description: Set a completion condition and work autonomously until it is met. Use when the user types /goal, /goal clear, /goal stop, /goal status, or any goal-related command. Also use when the user says "goal", "set a goal", "work until", "keep going until", or wants autonomous task execution with a verifiable end state.
---

# /goal — Autonomous Completion Loop

Set a completion condition. The agent keeps working across turns without user prompting until the condition is verifiably met. After each turn, the agent self-evaluates whether the condition holds, and continues or stops accordingly.

## Commands

| Command | Action |
|---------|--------|
| `/goal <condition>` | Set a new goal and begin working immediately |
| `/goal` | Show current goal status (condition, elapsed time, turns, last evaluation) |
| `/goal clear` | Stop the active goal. Aliases: `stop`, `off`, `reset`, `none`, `cancel` |

## Lifecycle

```
SET GOAL → WORK TURN → EVALUATE → (not met) → WORK TURN → EVALUATE → ... → (met) → REPORT & CLEAR
```

### Step 1: Parse User Input

When the user invokes `/goal`, parse the arguments:

- **No arguments**: Go to Step 6 (Status Report)
- **`clear` / `stop` / `off` / `reset` / `none` / `cancel`**: Go to Step 7 (Clear Goal)
- **Otherwise**: The entire argument string is the **completion condition**. Go to Step 2.

### Step 2: Initialize Goal State

Create or update `~/agents/finetune/essentials/GOAL_STATE.md` with:

```markdown
# Active Goal

**Condition**: {the user's condition text}
**Started**: {ISO 8601 timestamp}
**Turns**: 0
**Max Turns**: {extracted from condition if "stop after N turns" present, else 50}
**Last Evaluation**: pending
**Status**: active
```

### Step 3: Begin Work

Execute the condition as a directive. Start working toward it immediately using all available tools, skills, and the REACT loop. Do NOT ask for confirmation — the goal IS the instruction.

### Step 4: Work Turn

During each turn:
1. Take actions that move toward the completion condition
2. Use tools, run commands, edit files, search — whatever is needed
3. Log observable evidence of progress in the conversation
4. After completing the turn's work, proceed to Step 5

### Step 5: Self-Evaluate

After each work turn, evaluate the completion condition against what was accomplished:

**Evaluation Protocol:**
1. Re-read the exact condition text from GOAL_STATE.md
2. Examine ALL evidence produced during this turn (tool outputs, file contents, command results)
3. Apply these checks:
   - **Measurable end state**: Is the condition's measurable target achieved? (test exit code, file state, API response, queue empty, etc.)
   - **Proof visible**: Is the proof visible in the conversation? (did we run the check command and show its output?)
   - **Constraints satisfied**: Are all negative constraints still met? (no unwanted file changes, no scope creep)
4. Decide: **MET** or **NOT MET**

**If MET:**
- Update GOAL_STATE.md: `Status: achieved`, record final turn count and timestamp
- Print a completion summary to the user
- Clear the goal state
- STOP. Do not continue working.

**If NOT MET:**
- Update GOAL_STATE.md: increment `Turns`, update `Last Evaluation` with the reason
- Check if `Turns >= Max Turns`. If yes: print partial progress report, clear goal, STOP.
- Otherwise: proceed to next work turn (loop back to Step 4)

### Step 6: Status Report

When `/goal` is called with no arguments, read `GOAL_STATE.md` and display:

```
/goal {status}

Condition: {condition text}
Running: {duration since start}
Turns: {current}/{max}
Last Evaluation: {most recent evaluation reason}
Status: {active|achieved|cleared}
```

If no goal exists, report: "No active goal."

### Step 7: Clear Goal

When `/goal clear` is called:
1. If a goal is active, print what was accomplished so far
2. Update GOAL_STATE.md: `Status: cleared`
3. Delete or mark the goal as inactive
4. Confirm to user: "Goal cleared."

## Writing Effective Conditions

Conditions must be **verifiable from conversation evidence**. The agent can only judge what it has produced in the current session.

### Condition Template

```
{task description} until {finish line}, verified by {specific check}, while {constraints}, or stop after {turn limit}
```

### Good Conditions (verifiable)

```
/goal all tests in tests/ pass and `npm test` exits 0
/goal every endpoint in the API returns a response and status codes are documented
/goal the FINDINGS.md has curl proof for every finding listed
/goal technology fingerprint is complete: all versions extracted from headers, JS files, and open directories, and each version is mapped to CVEs in CVE_QUEUE.json
/goal all SQL injection test scripts return conclusive results (pass or fail with evidence)
```

### Bad Conditions (unverifiable)

```
/goal the code looks clean
/goal everything is secure
/goal do a good job
```

### Safety: Always Add Turn Limits

For any goal you walk away from, include a turn limit:

```
/goal all tests pass or stop after 20 turns
```

Without a limit, an unachievable condition loops indefinitely. Default max turns: 50.

## State Persistence

The goal state survives across messages within a session. On each turn:
- Read `GOAL_STATE.md` at the start of the turn
- Write updated state at the end of the turn
- The state file is the single source of truth

### GOAL_STATE.md Schema

```markdown
# Active Goal

**Condition**: <string, up to 4000 chars>
**Started**: <ISO 8601>
**Turns**: <integer>
**Max Turns**: <integer>
**Last Evaluation**: <"pending" | "not met: {reason}" | "met: {reason}">
**Status**: <"active" | "achieved" | "cleared">
**Achieved At**: <ISO 8601, only if achieved>
**Achieved Turn**: <integer, only if achieved>
```

## Integration with Away Mode

When combined with Away Mode ("night", "afk", etc.), the goal loop runs autonomously:

```
/goal all surfaces are tested and findings are saved with evidence
night
```

The agent continues working toward the goal across turns while the user is away. State is persisted to GOAL_STATE.md every turn so it survives interruptions.

## Integration with REACT Loop

Each work turn within a goal follows the REACT pattern:
- **Reason**: What actions will move toward the condition?
- **Act**: Execute those actions
- **Observe**: What did the actions produce?
- **Adapt**: Does the evaluation feedback suggest a different approach?

## Anti-Patterns

| Problem | Cause | Fix |
|---------|-------|-----|
| Goal never completes | Condition references state agent never surfaced | Include the proof command in the condition: "run X and its output shows Y" |
| Token spend runs away | No turn limit on unachievable condition | Always add "or stop after N turns" |
| premature completion | Condition too loose ("tests pass" = one test) | Tighten: "all 47 tests in tests/ pass with 0 failures" |
| Scope creep | No constraints stated | Add "without modifying package.json" or similar |

## Examples by Use Case

### Security Research
```
/goal all discovered endpoints are tested for SQL injection with at least 3 payloads each, or stop after 30 turns
```

```
/goal every finding in findings/ has a working PoC script and curl evidence, or stop after 20 turns
```

### Code Migration
```
/goal every import of 'old-module' is replaced with 'new-module', the project compiles, and tests pass. Do not modify package.json.
```

### Reconnaissance
```
/goal subdomain enumeration is complete, all live hosts identified, and technology fingerprint saved to TECH_FINGERPRINT.json, or stop after 25 turns
```

### Report Writing
```
/goal the report has sections for every finding with severity, impact, reproduction steps, and remediation. No placeholder text remains.
```
