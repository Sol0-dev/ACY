---
name: ctf-reproduce
description: CTF flag validation, writeup generation, wiki updates. After HUNT captures flags — validate, document, save to wiki for future reference.
---

# SKILL-CTF-REPRODUCE — CTF Validation & Writeup
# Phase Coverage: CTF-5 (Validation) → CTF-6 (Report)
# Philosophy: Same as bug bounty REPRODUCE but write flag capture + generate writeup

---

## CTF Directory Structure — FILE PLACEMENT RULES

```
ALL CTF FILES GO IN PER-TARGET DIRECTORIES — NEVER IN ROOT.

SLUG = hostname with dots/slashes/colons → underscores
  Example: 10.48.176.42 → tryhackme_bypassdisablefunctions
  Example: box.htb → htb_box

DIRECTORY MAP:
  scripts/{target-slug}/          ← ALL exploit scripts, droppers, shells
  fullrecon/{target-slug}/        ← nmap output, gobuster results, recon
  notes/{target-slug}/            ← attack chain logs, analysis notes
  images/{target-slug}/           ← screenshots, visual evidence
  findings/{target-slug}/         ← confirmed findings
    {severity}/{vuln-class}/{title}/
      {title}.md                  ← writeup / finding report
      {title}.sh                  ← clean PoC script

FILE PLACEMENT RULES:
  ✗ NEVER create CTF_{PLATFORM}_{CHALLENGE}/ at root — use per-target dirs
  ✗ NEVER save scripts to root — always scripts/{slug}/
  ✗ NEVER save recon to root — always fullrecon/{slug}/
  ✓ Writeups → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.md
  ✓ Clean PoCs → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.sh
  ✓ State files → essentials/STATE_{slug}.md, essentials/LOOP_STATE_{slug}.md
```

---

## Phase CTF-5: VALIDATION — Flag Verification

```
PURPOSE: Confirm flags captured, verify format, document proof.

VALIDATION CHECKLIST:
  □ User flag captured and matches expected format
  □ Root flag captured and matches expected format
  □ All flags logged with exact command that revealed them
  □ Attack chain documented end-to-end
  □ No steps skipped in documentation

STATE FILES TO UPDATE:
  → essentials/STATE_{SLUG}.md — add flag values, locations, timestamps
  → essentials/LOOP_STATE_{SLUG}.md — mark CTF-5 as COMPLETED
  → essentials/findings_log.jsonl — append confirmed finding
  → essentials/poc_registry.jsonl — register PoC script
  → essentials/LEADERBOARD.json — update CTF stats (rooms, points, streak)
  → essentials/MEMORY.md — append session learnings
```

### Flag Format Reference

```
HackTheBox:  HTB{32_hex_chars}
TryHackMe:   THM{alphanumeric_string}
PicoCTF:     picoCTF{alphanumeric_string}
VulnHub:     flag{string} or custom
OverTheWire: varies by level
```

### Proof Documentation

```markdown
## Flag Captures

### User Flag
- **Location**: /home/{user}/user.txt
- **Command**: `cat /home/leonard/user.txt`
- **Flag**: THM{...}
- **Timestamp**: {TIME}

### Root Flag
- **Location**: /root/root.txt
- **Command**: `cat /root/root.txt`
- **Flag**: THM{...}
- **Timestamp**: {TIME}
```

---

## Phase CTF-6: REPORT — Writeup Generation & Wiki Update

```
PURPOSE: Generate writeup, update wiki for future challenges.

WORKFLOW:
  1. Generate writeup → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.md
  2. Save clean PoC → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.sh
  3. Move exploit scripts → scripts/{target-slug}/
  4. Update wiki/targets/{PLATFORM}_{CHALLENGE}.md
  5. Update wiki/techniques/{vuln_class}.md (if new pattern)
  6. Update wiki/index.md
  7. Update wiki/log.md
  8. Update essentials/KNOWLEDGE_BASE.md (if new technique)
  9. Update essentials/STATE_{SLUG}.md — mark status=COMPLETED
  10. Update essentials/LOOP_STATE_{SLUG}.md — mark all phases COMPLETED
  11. Update essentials/session_log.jsonl — mark session completed
  12. Update essentials/LEADERBOARD.json — CTF stats updated

FILE PLACEMENT:
  → Writeup → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.md
  → Clean PoC → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.sh
  → Exploit scripts → scripts/{target-slug}/
  → State files → essentials/STATE_{slug}.md, essentials/LOOP_STATE_{slug}.md
  → Global memory → essentials/MEMORY.md (append only)

ESSENTIAL FILES UPDATED:
  → essentials/STATE_{SLUG}.md — final state with all findings, flags, timestamps
  → essentials/LOOP_STATE_{SLUG}.md — all phases marked COMPLETED
  → essentials/MEMORY.md — append session learnings, patterns, tool preferences
  → essentials/KNOWLEDGE_BASE.md — add/update technique patterns
  → essentials/findings_log.jsonl — confirmed findings with evidence
  → essentials/poc_registry.jsonl — PoC lifecycle tracking
  → essentials/session_log.jsonl — session metadata
  → essentials/LEADERBOARD.json — CTF stats updated
  → essentials/skill_registry.json — update if new vuln classes added
```

### Writeup Structure

```markdown
# {CHALLENGE_NAME} — {PLATFORM} — {DIFFICULTY}

## Information
| Property | Value |
|----------|-------|
| Platform | {HTB|THM} |
| IP | {TARGET_IP} |
| Difficulty | {Easy/Medium/Hard/Insane} |
| Category | {Web|Pwn|Crypto|Forensics|AD|Misc} |
| Flags | user.txt + root.txt |

## Reconnaissance
{nmap output, directory enumeration, technology fingerprint}

## Vulnerability Identification
{what was found, CVE references if applicable}

## Exploitation
{step-by-step with commands and output}

## Privilege Escalation
{privesc vector and steps}

## Flag Capture
{exact commands that revealed flags, flag values}

## Attack Path Diagram
```
[Recon] → [Vuln Found] → [Exploit] → [Shell] → [Privesc] → [Flags]
```

## Failed Attempts
{what didn't work and why}

## Remediation
{specific fixes for each vulnerability}

## References
{CVE links, GTFOBins, HackTricks, tool docs}
```

### Wiki Target Update

```markdown
---
id: {PLATFORM}_{CHALLENGE}
date: {DATE}
type: ctf-target
platform: {htb|thm}
difficulty: {easy|medium|hard|insane}
status: solved
flags_captured: {count}
techniques_used: [{list}]
links: []
---

# {CHALLENGE_NAME}

## Summary
{one-paragraph overview}

## Attack Chain
{step-by-step with commands}

## Flags
- user.txt: {location, command, flag}
- root.txt: {location, command, flag}

## Techniques Used
{list of vuln classes exploited, with links to technique notes}

## Lessons Learned
{what worked, what didn't, what to try first next time}
```

### Wiki Technique Update (if new pattern discovered)

```markdown
---
id: {technique_name}
date: {DATE}
type: technique
status: active
confidence: {1-5}
tags: [{tags}]
links: []
---

# {Technique Name}

## Discovery
{how to find this vuln}

## Exploitation
{exact payloads and methods}

## Prerequisites
{what must be true}

## Remediation
{how to fix}

## CTF Examples
{challenges where this was used}
```

### Knowledge Base Update

```
AFTER EVERY CHALLENGE, update essentials/KNOWLEDGE_BASE.md:
  → Add pattern digest for any new technique
  → Update confidence score for existing patterns
  → Link to wiki/targets/ for the challenge

PATTERN DIGEST FORMAT:
  ## {Technique Name}
  - **Platform**: {HTB/THM/both}
  - **Category**: {Web/Pwn/Crypto/Forensics/AD}
  - **Discovery**: {how found}
  - **Exploitation**: {exact payload/method}
  - **CTF Adaptation**: {what changed from bug bounty}
  - **Prerequisites**: {what must be true}
  - **Remediation**: {fix}
  - **Confidence**: {1-5}
```

---

## Post-Challenge Checklist

```
FLAGS & FINDINGS:
  □ Flags validated and documented
  □ Writeup saved → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.md
  □ Clean PoC saved → findings/{target-slug}/{severity}/{vuln-class}/{title}/{title}.sh

SCRIPTS & ARTIFACTS:
  □ Exploit scripts saved → scripts/{target-slug}/
  □ Droppers saved → scripts/{target-slug}/droppers/
  □ Recon output in → fullrecon/{target-slug}/
  □ Attack chain log in → notes/{target-slug}/attack_chain.md
  □ No loose files in root ~/agents/finetune/

WIKI & KNOWLEDGE:
  □ wiki/targets/{PLATFORM}_{CHALLENGE}.md created
  □ wiki/techniques/{vuln_class}.md updated (if new)
  □ wiki/index.md updated
  □ wiki/log.md appended

ESSENTIAL FILES:
  □ essentials/STATE_{SLUG}.md — final state with all findings
  □ essentials/LOOP_STATE_{SLUG}.md — all phases marked COMPLETED
  □ essentials/MEMORY.md — session learnings appended
  □ essentials/KNOWLEDGE_BASE.md — technique patterns updated
  □ essentials/findings_log.jsonl — confirmed findings logged
  □ essentials/poc_registry.jsonl — PoC registered
  □ essentials/session_log.jsonl — session metadata logged
  □ essentials/LEADERBOARD.json — CTF stats updated
  □ essentials/skill_registry.json — updated if new vuln classes added
```

---

*SKILL-CTF-REPRODUCE — Part of the acy Agentic CTF Solver v1.0*
*Validate flags → Generate writeup → Update wiki → Grow knowledge base*
