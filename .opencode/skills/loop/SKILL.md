---
name: loop
description: Run a prompt or skill repeatedly on a fixed interval or self-paced schedule. Use when the user types /loop, /loop clear, /loop list, /loop stop, or any loop-related command. Also use when the user says "loop", "poll every", "check every", "monitor", "keep checking", "run repeatedly", or wants recurring scheduled task execution.
---

# /loop — Recurring Scheduled Prompt

Run a prompt or slash command repeatedly on an interval while the session stays open. Poll deployments, babysit PRs, monitor builds, run recurring checks — without manual prompting each time.

## Commands

| Command | Action |
|---------|--------|
| `/loop <interval> <prompt>` | Start a loop: run `<prompt>` every `<interval>` |
| `/loop <prompt>` | Start a loop: run `<prompt>` at a self-chosen interval |
| `/loop <interval>` | Start a loop: run the default maintenance prompt every `<interval>` |
| `/loop` | Start a loop: run the default maintenance prompt at a self-chosen interval |
| `/loop list` | List all active loops |
| `/loop stop` or `/loop clear` | Stop all active loops |
| `/loop stop <id>` | Stop a specific loop by ID |

## Interval Syntax

| Format | Example | Meaning |
|--------|---------|---------|
| `Ns` | `30s` | Every 30 seconds (rounded up to 1m) |
| `Nm` | `5m` | Every 5 minutes |
| `Nh` | `1h` | Every 1 hour |
| `Nd` | `1d` | Every 1 day |
| trailing `every Nm` | `check every 20m` | Every 20 minutes |

Supported units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days). Minimum granularity: 1 minute. Seconds round up.

## Lifecycle

```
USER: /loop 5m check deploy status
  → Parse interval (5m) + prompt
  → Generate loop ID
  → Execute prompt IMMEDIATELY (first run)
  → Save loop state to LOOP_TASKS.json
  → Start background scheduler (loop_runner.sh)
  → Confirm to user: cadence, ID, expiry

BACKGROUND (loop_runner.sh):
  → sleep interval
  → Check stop flag → if set, exit
  → Execute: opencode run "<prompt>" --continue
  → Log iteration result
  → Repeat

USER: /loop stop
  → Write stop flag for all loops
  → Background script exits on next check
  → Confirm stopped
```

## Step-by-Step Protocol

### Step 1: Parse Input

When the user invokes `/loop`, parse arguments in priority order:

1. **`list`**: Show all active loops from `LOOP_TASKS.json`. Go to Step 7.
2. **`stop` / `clear`**: Stop loops. Go to Step 8.
3. **`stop <id>` / `clear <id>`**: Stop specific loop. Go to Step 8.
4. **Otherwise**: Parse as `[interval] <prompt>`:

   a. **Leading token**: If the first whitespace-delimited token matches `^\d+[smhd]$` (e.g. `5m`, `2h`), that's the interval; the rest is the prompt.
   
   b. **Trailing "every" clause**: If the input ends with `every <N><unit>` or `every <N> <unit-word>` (e.g. `every 20m`, `every 5 minutes`), extract that as the interval and strip it from the prompt. Only match when what follows "every" is a time expression — `check every PR` has no interval.
   
   c. **Default**: Interval is `10m` and the entire input is the prompt.
   
   d. **Empty prompt after parsing**: If the resulting prompt is empty, check for `loop.md` default prompt. If neither exists, show usage and stop.

### Step 2: Validate & Register

1. Generate a unique loop ID: `loop_` + first 8 chars of random hex
2. Convert interval to seconds:
   - `30s` → 60 (round up to 1 minute)
   - `5m` → 300
   - `1h` → 3600
   - `1d` → 86400
3. Check total active loops < 50. If at limit, refuse and tell user.
4. Write to `~/agents/finetune/essentials/LOOP_TASKS.json`:

```json
{
  "loops": [
    {
      "id": "loop_a1b2c3d4",
      "prompt": "<the prompt>",
      "interval_seconds": 300,
      "interval_display": "5m",
      "created": "2026-07-13T10:00:00Z",
      "last_run": null,
      "run_count": 0,
      "status": "active",
      "mode": "fixed",
      "expires": "2026-07-20T10:00:00Z",
      "log_file": "scripts/loops/loop_a1b2c3d4.log"
    }
  ]
}
```

### Step 3: Execute First Run

Immediately execute the prompt. Do not wait for the interval:

- If the prompt is a slash command (starts with `/`), invoke it via the skill tool
- Otherwise, execute the prompt directly as a work turn
- Record the result

### Step 4: Start Background Scheduler

Launch the background runner:

```bash
bash ~/agents/finetune/scripts/loop_runner.sh <loop_id> <interval_seconds> '<prompt>'
```

The runner:
1. Enters a loop
2. Sleeps for the interval
3. Checks `~/agents/finetune/essentials/loops/<loop_id>.stop` — if file exists, exits
4. Runs `cd ~/agents/finetune && opencode run '<prompt>' --auto 2>>~/agents/finetune/scripts/loops/<loop_id>.log`
5. Updates `last_run` and `run_count` in `LOOP_TASKS.json`
6. Repeats from step 2

### Step 5: Confirm to User

```
Loop registered: <loop_id>
Cadence: every <interval> (<cron description>)
Prompt: <prompt>
Mode: fixed | self-paced
Expires: <7 days from now>
Stop with: /loop stop <id> or /loop clear
```

### Step 6: Self-Paced Mode

When the user omits the interval, use self-paced mode:

- After each iteration, choose a delay between 1 minute and 60 minutes
- Shorter waits when activity is high (build running, PR active)
- Longer waits when nothing is pending
- Print the chosen delay and reason after each iteration
- The agent may decide to stop the loop when the task is complete

### Step 7: List Active Loops

Read `LOOP_TASKS.json` and display:

```
Active loops:

ID              CADENCE    PROMPT                              RUNS   LAST RUN
loop_a1b2c3d4   5m         check deploy status                 12     2 min ago
loop_e5f6g7h8   self       check CI and fix review comments    5      8 min ago

Total: 2/50
```

### Step 8: Stop Loops

**Stop all loops:**
1. For each active loop in `LOOP_TASKS.json`, create `~/agents/finetune/essentials/loops/<loop_id>.stop`
2. Set all loop statuses to `stopped` in `LOOP_TASKS.json`
3. Confirm: "Stopped N loop(s)."

**Stop specific loop:**
1. Create `~/agents/finetune/essentials/loops/<loop_id>.stop`
2. Set status to `stopped` in `LOOP_TASKS.json`
3. Confirm: "Stopped loop <id>."

The background runner checks for the `.stop` file before each iteration and exits cleanly when found.

## Default Maintenance Prompt

When `/loop` is invoked without a prompt, use the default from `.opencode/loop.md` (project-level) or the built-in maintenance:

```
Continue any unfinished work from the conversation.
Check for pending test failures or build errors and fix them.
Review any uncommitted changes and ensure they are clean.
If nothing needs attention, report that briefly.
```

## State Files

| File | Purpose |
|------|---------|
| `~/agents/finetune/essentials/LOOP_TASKS.json` | All loop definitions, status, and metadata |
| `~/agents/finetune/essentials/loops/<id>.stop` | Stop flag file — creator's presence tells runner to exit |
| `~/agents/finetune/scripts/loops/<id>.log` | Per-loop execution log |
| `~/agents/finetune/.opencode/loop.md` | Custom default prompt (overrides built-in) |

## Writing Effective Loop Prompts

Good loop prompts:

- **State what to check**: "check if the deployment finished and report status"
- **Include boundaries**: "check for new review comments but do not push changes"
- **Are self-contained**: each iteration should be able to run independently
- **Have a natural stop**: "once all tests pass, report success and stop"

### Good Examples

```
/loop 5m check if the deployment finished and tell me what happened
/loop 15m run the test suite and report any new failures
/loop 30m check for new GitHub issues assigned to me and summarize each
/loop 1h scan for new subdomains and check if they are live
/loop 10m check the OAST registry for new callbacks and report findings
```

### Bad Examples (too vague, no verifiable output)

```
/loop make things better
/loop optimize the code
/loop do something useful
```

## Constraints

| Constraint | Value |
|------------|-------|
| Max loops per session | 50 |
| Minimum interval | 1 minute |
| Auto-expiry | 7 days (fixed), dynamic (self-paced) |
| Session-scoped | Dies when session ends |
| Restorable | On `--resume` within 7 days |
| First run | Always immediate (no waiting) |

## Integration with Away Mode

Combine `/loop` with Away Mode for autonomous monitoring:

```
/loop 10m check OAST registry for new callbacks and process findings
night
```

The background runner continues executing while you're away. Results accumulate in the log files.

## Integration with /goal

`/loop` and `/goal` serve different purposes:

| Aspect | `/loop` | `/goal` |
|--------|---------|---------|
| Trigger | Time interval | Completed turn |
| Stop condition | You cancel it, or 7-day expiry | Goal achieved or turn limit |
| Best for | Polling, monitoring, recurring checks | Tasks with a verifiable finish line |
| Context | Each iteration is independent | Each turn builds on previous |

Use `/loop` for "check every N minutes." Use `/goal` for "keep working until done."

They can compose: a `/goal` session can have a `/loop` monitoring its progress externally.

## Anti-Patterns

| Problem | Cause | Fix |
|---------|-------|-----|
| Token spend runaway | Too many loops or too-frequent interval | Use wider intervals (15m+), cancel when done |
| Loops pile up | Forgetting to stop old loops | `/loop list` periodically, stop stale ones |
| First run delayed | Waiting for interval before first execute | First run is ALWAYS immediate — check Step 3 |
| Loop does nothing | Prompt too vague for independent execution | Make each iteration self-contained with explicit checks |
| Background script dies | Session ended or machine restarted | Loops are session-scoped; use `/goal` + Away Mode for persistence |
