---
name: dataset-reproduce
description: Validate, deduplicate, and export the final fine-tuning dataset. After HUNT formats training pairs — validate accuracy, deduplicate, score quality, and export to JSONL for model training. Use when building training datasets.
---

# SKILL-DATASET-REPRODUCE — Validation, Dedup & Export — REPRODUCE
# Phase Coverage: Cross-cutting (final stage of dataset pipeline)
# Purpose: Validate formatted training data, deduplicate, compute final quality scores,
#          and export to JSONL ready for fine-tuning.

---

## Export Pipeline

```
FORMATTED DATA (from HUNT)
  → VALIDATE: verify all fields, CWE/CVSS/MITRE correctness
  → DEDUPLICATE: remove exact + near-duplicates
  → SCORE: compute final quality scores
  → BALANCE: ensure dataset type distribution meets targets
  → SPLIT: train (80%) / validation (10%) / test (10%)
  → EXPORT: write JSONL files to dataset/exported/
  → MANIFEST: generate dataset manifest with statistics

COMMAND:
  python3 mcp/dataset_capture.py --action export --input dataset/formatted/ --output dataset/exported/ --split 80/10/10
```

---

## Validation Rules

```
EVERY entry in dataset/formatted/ must pass ALL validation checks:

SCHEMA VALIDATION:
  [ ] capture_id is valid UUID
  [ ] timestamp is valid ISO-8601
  [ ] system, instruction, input, output are non-empty strings
  [ ] metadata contains dataset_type, tags[]
  [ ] quality_score is float between 0.0 and 1.0

TECHNICAL VALIDATION:
  [ ] CWE ID exists in MITRE CWE database (https://cwe.mitre.org/)
  [ ] CVSS score is between 0.0 and 10.0
  [ ] CVSS vector has 8 fields (AV/AC/PR/UI/S/C/I/A)
  [ ] MITRE ATT&CK technique ID format is T#### or T####.###
  [ ] CVE ID format is CVE-YYYY-NNNNN (if present)
  [ ] Code snippets have matching language tags
  [ ] HTTP requests have method + path
  [ ] Shell commands have valid syntax

CONTENT VALIDATION:
  [ ] Output directly addresses the instruction
  [ ] No PII or real credentials present (redaction scan)
  [ ] Technical claims are accurate (no hallucinated CVEs or versions)
  [ ] Reasoning chain is logical and complete
  [ ] Impact assessment is realistic (not oversold)

REDACTION SCAN:
  → Regex patterns to detect and redact:
    - Email: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
    - IP addresses: \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b (unless test IPs)
    - AWS keys: AKIA[0-9A-Z]{16}
    - Private keys: -----BEGIN (RSA |EC )?PRIVATE KEY-----
    - JWT tokens: eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+
    - Generic secrets: password\s*[:=]\s*["\'][^"\']+["\']
```

---

## Deduplication Algorithm

```
STEP 1: EXACT MATCH DEDUP
  → Hash each entry: SHA256(system + instruction + input + output)
  → Remove entries with identical hashes (keep first occurrence)

STEP 2: NEAR-DUPLICATE DETECTION
  → Compute Jaccard similarity on instruction + output token sets
  → Threshold: 0.85 (entries scoring >= 0.85 similarity are duplicates)
  → Keep entry with higher quality_score

STEP 3: SEMANTIC CLUSTERING
  → Group entries by (dataset_type, vuln_class)
  → Within each cluster, check for technique redundancy
  → If >5 entries teach the exact same technique: keep top 5 by quality_score
  → If entries teach variations of same technique: keep all (valuable diversity)

DEDUP STATISTICS:
  → Log: total_entries, exact_duplicates_removed, near_duplicates_removed,
          semantic_redundancies_removed, final_count
```

---

## Dataset Balancing

```
TARGET DISTRIBUTION (per dataset type):

  Type                        Min Entries   Target Entries   Weight
  ───────────────────────────────────────────────────────────────────
  vulnerability-exploit       50,000        75,000           0.20
  network-webapp              20,000        30,000           0.12
  shell-commands              30,000        45,000           0.15
  credential-auth             15,000        25,000           0.10
  code-analysis               100,000       150,000          0.25
  osint-recon                 10,000        15,000           0.06
  evasion-opsec               10,000        15,000           0.06
  reasoning-planning           5,000        10,000           0.04
  reporting                    5,000        10,000           0.02
  ───────────────────────────────────────────────────────────────────
  TOTAL                      245,000       375,000          1.00

IF a dataset type has fewer than min_entries:
  → Log warning: "UNDERSAMPLED: {type} has {count}/{min} entries"
  → Proceed with available data (never fabricate)
  → Flag for targeted capture in next session

IF a dataset type exceeds target_entries:
  → Apply quality threshold: keep entries with quality_score >= 0.7
  → If still over target: keep top target_entries by quality_score
```

---

## Train/Validation/Test Split

```
SPLIT RATIO: 80% train / 10% validation / 10% test

SPLIT RULES:
  → Stratified by dataset_type (proportional representation)
  → No data leakage: same technique never appears in train AND test
  → Cluster-aware: if multiple entries from same session, all go to same split
  → Random seed: 42 (reproducible splits)

SPLIT COMMAND:
  python3 mcp/dataset_capture.py --action split --input dataset/formatted/ --ratios 80,10,10 --seed 42

OUTPUT FILES:
  dataset/exported/train.jsonl
  dataset/exported/validation.jsonl
  dataset/exported/test.jsonl
```

---

## Export Format — JSONL

```jsonl
{"messages":[{"role":"system","content":"You are an authorized offensive security researcher operating under a signed Rules of Engagement."},{"role":"user","content":"<instruction>\n<input>"},{"role":"assistant","content":"<output>"}]}
```

Each line is a complete conversation turn suitable for chat-based fine-tuning (OpenAI, Anthropic, LLaMA-Factory, Axolotl, etc.).

---

## Dataset Manifest

```
After export, generate dataset/manifest.json:

{
  "version": "1.0",
  "created": "ISO-8601",
  "total_entries": 375000,
  "split": {"train": 300000, "validation": 37500, "test": 37500},
  "distribution": {
    "vulnerability-exploit": {"count": 75000, "pct": 20.0},
    "network-webapp": {"count": 30000, "pct": 8.0},
    "shell-commands": {"count": 45000, "pct": 12.0},
    "credential-auth": {"count": 25000, "pct": 6.7},
    "code-analysis": {"count": 150000, "pct": 40.0},
    "osint-recon": {"count": 15000, "pct": 4.0},
    "evasion-opsec": {"count": 15000, "pct": 4.0},
    "reasoning-planning": {"count": 10000, "pct": 2.7},
    "reporting": {"count": 10000, "pct": 2.6}
  },
  "quality_stats": {
    "mean": 0.0,
    "median": 0.0,
    "min": 0.0,
    "p95": 0.0
  },
  "cwe_coverage": [],
  "mitre_attack_coverage": [],
  "cve_coverage": [],
  "dedup_stats": {
    "total_before_dedup": 0,
    "exact_duplicates": 0,
    "near_duplicates": 0,
    "final_count": 0
  }
}
```

---

## Export Commands

```
FULL PIPELINE:
  python3 mcp/dataset_capture.py --action export \\
    --input dataset/formatted/ \\
    --output dataset/exported/ \\
    --split 80,10,10 \\
    --seed 42 \\
    --min-quality 0.6 \\
    --dedup-threshold 0.85

INDIVIDUAL STEPS:
  python3 mcp/dataset_capture.py --action validate --input dataset/formatted/
  python3 mcp/dataset_capture.py --action dedup --input dataset/formatted/ --threshold 0.85
  python3 mcp/dataset_capture.py --action score --input dataset/formatted/
  python3 mcp/dataset_capture.py --action balance --input dataset/formatted/ --targets dataset/targets.json
  python3 mcp/dataset_capture.py --action split --input dataset/formatted/ --ratios 80,10,10
  python3 mcp/dataset_capture.py --action export --input dataset/formatted/ --output dataset/exported/
  python3 mcp/dataset_capture.py --action stats --input dataset/exported/
```

---

## Integration with AutoResearch Loop

```
DATASET CAPTURE runs as a PASSIVE layer alongside the AutoResearch loop:

  AutoResearch Step 1 (Recon)     → Dataset DISCOVERY captures all recon outputs
  AutoResearch Step 2 (Hypothesize) → Dataset DISCOVERY captures hypothesis + rationale
  AutoResearch Step 3 (Edit)        → Dataset DISCOVERY captures all edits
  AutoResearch Step 4 (Test)        → Dataset DISCOVERY captures tool calls, req/res, commands
  AutoResearch Step 5 (Score)       → Dataset DISCOVERY captures scoring + reasoning
  AutoResearch Step 6 (Keep/Revert) → Dataset DISCOVERY captures decision + why
  AutoResearch Step 7 (Triage)      → Dataset HUNT formats findings into reporting type
                                     → Dataset REPRODUCE validates + exports periodically

PERIODIC EXPORT:
  → After every 100 new captures: run validation + dedup
  → After every 500 new captures: run full export pipeline
  → At session end: run final export + manifest generation
```
