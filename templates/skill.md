---
id: {uuid}
date: {ISO8601}
type: skill
status: draft
phase: {phase_number}
---

# SKILL-{NAME} -- {Vulnerability Class}
# Phase Coverage: {phase_number}
# Vuln Classes: {class_names}
# Purpose: {one_line_description}

---

## Sub-Phases

### Sub-Phase {N}.1: DISCOVERY

```bash
# Discovery commands here
```

### Sub-Phase {N}.2: HUNT

```bash
# Hunt payloads and scripts here
```

### Sub-Phase {N}.3: REPRODUCE

**Confirm:** {what confirms the bug}
**PoC Script:** save to scripts/{SLUG}/{vuln_class}_{surface}.sh
**Save finding:** findings/{SLUG}/{severity}/{vuln-class}/{title}/

### CHAIN OUTPUT:
  -> {finding} + {other_finding} = {impact}

---

*SKILL-{NAME} -- {Description} Module*
*Part of the acy-1.0 Agentic Security Research System*
