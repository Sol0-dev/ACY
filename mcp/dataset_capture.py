#!/usr/bin/env python3
"""
dataset_capture.py — Offensive Security Training Dataset Pipeline Engine

Actions:
  capture   — Log a single agent action to raw-captures/
  format    — Transform raw captures into instruction-following training pairs
  validate  — Check all formatted entries for schema + content correctness
  dedup     — Remove exact and near-duplicates
  score     — Compute/override quality scores
  balance   — Check dataset type distribution against targets
  split     — Train/val/test split (stratified, cluster-aware)
  export    — Generate final JSONL files for fine-tuning
  stats     — Print dataset statistics and generate manifest.json

Usage:
  python3 mcp/dataset_capture.py --action capture --type vulnerability-exploit --tool curl ...
  python3 mcp/dataset_capture.py --action format --input dataset/raw-captures/ --output dataset/formatted/
  python3 mcp/dataset_capture.py --action validate --input dataset/formatted/
  python3 mcp/dataset_capture.py --action dedup --input dataset/formatted/ --threshold 0.85
  python3 mcp/dataset_capture.py --action export --input dataset/formatted/ --output dataset/exported/ --split 80,10,10
  python3 mcp/dataset_capture.py --action stats --input dataset/exported/

v4.0 — Dataset Pipeline for Offensive Security Model Fine-Tuning
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = ROOT / "dataset"
RAW_DIR = DATASET_DIR / "raw-captures"
FORMATTED_DIR = DATASET_DIR / "formatted"
EXPORTED_DIR = DATASET_DIR / "exported"

DATASET_TYPES = [
    "vulnerability-exploit",
    "network-webapp",
    "shell-commands",
    "credential-auth",
    "code-analysis",
    "osint-recon",
    "evasion-opsec",
    "reasoning-planning",
    "reporting",
]

TARGET_DISTRIBUTION = {
    "vulnerability-exploit": 75000,
    "network-webapp": 30000,
    "shell-commands": 45000,
    "credential-auth": 25000,
    "code-analysis": 150000,
    "osint-recon": 15000,
    "evasion-opsec": 15000,
    "reasoning-planning": 10000,
    "reporting": 10000,
}

REDACT_PATTERNS = [
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '[REDACTED_EMAIL]'),
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), '[REDACTED_AWS_KEY]'),
    (re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    (re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'), '[REDACTED_JWT]'),
    (re.compile(r'(?i)password\s*[:=]\s*["\'][^"\']+["\']'), '[REDACTED_PASSWORD]'),
    (re.compile(r'(?i)api[_-]?key\s*[:=]\s*["\'][^"\']+["\']'), '[REDACTED_API_KEY]'),
    (re.compile(r'(?i)secret\s*[:=]\s*["\'][^"\']+["\']'), '[REDACTED_SECRET]'),
    (re.compile(r'(?i)token\s*[:=]\s*["\'][^"\']+["\']'), '[REDACTED_TOKEN]'),
]

CWE_DB_URL = "https://cwe.mitre.org/data/definitions/"
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}')
CWE_PATTERN = re.compile(r'CWE-\d+')
MITRE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?')
CVSS_PATTERN = re.compile(r'CVSS:\d\.\d/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NSR]/S:[CU]/C:[NLH]/I:[NLH]/A:[NLH]')


def redact_text(text: str) -> str:
    for pattern, replacement in REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def generate_id() -> str:
    return str(secrets.uuid4()) if hasattr(secrets, 'uuid4') else hashlib.sha256(secrets.token_bytes(16)).hexdigest()[:36]


def compute_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def jaccard_similarity(set_a: set, set_b: set) -> float:
    if not set_a and not set_b:
        return 1.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union) if union else 0.0


def tokenize(text: str) -> set:
    return set(re.findall(r'\b\w+\b', text.lower()))


def load_jsonl(filepath: Path) -> list:
    entries = []
    if not filepath.exists():
        return entries
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  WARN: Skipping line {line_num}: {e}", file=sys.stderr)
    return entries


def write_jsonl(filepath: Path, entries: list):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def ensure_dirs():
    for dt in DATASET_TYPES:
        (RAW_DIR).mkdir(parents=True, exist_ok=True)
        (FORMATTED_DIR / dt).mkdir(parents=True, exist_ok=True)
    EXPORTED_DIR.mkdir(parents=True, exist_ok=True)


# ──────────────────────────────────────────────────────────────
# ACTION: capture
# ──────────────────────────────────────────────────────────────
def action_capture(args):
    """Log a single agent action to raw-captures/."""
    ensure_dirs()
    now = datetime.now(timezone.utc)
    session_dir = RAW_DIR / f"{now.strftime('%Y-%m-%d')}_{args.session_id or 'default'}"
    session_dir.mkdir(parents=True, exist_ok=True)

    input_data = {}
    if args.input_file:
        with open(args.input_file, 'r') as f:
            input_data = {"raw": f.read(), "redacted": redact_text(f.read())}
    elif args.input_text:
        input_data = {"raw": args.input_text, "redacted": redact_text(args.input_text)}
    else:
        input_data = {"raw": "", "redacted": ""}

    output_data = {}
    if args.output_file:
        with open(args.output_file, 'r') as f:
            content = f.read()
            output_data = {"raw": content[:10240], "summary": content[:500], "truncated": len(content) > 10240}
    elif args.output_text:
        content = args.output_text
        output_data = {"raw": content[:10240], "summary": content[:500], "truncated": len(content) > 10240}
    else:
        output_data = {"raw": "", "summary": "", "truncated": False}

    tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]

    capture = {
        "capture_id": generate_id(),
        "timestamp": now.isoformat(),
        "session_id": args.session_id or "default",
        "target": args.target or "unknown",
        "phase": args.phase or "0.0",
        "dataset_type": args.type or "reasoning-planning",
        "capture_point": args.capture_point or "general",
        "tool": args.tool or None,
        "input": input_data,
        "output": output_data,
        "reasoning": {
            "decision": args.decision or "",
            "rationale": args.rationale or "",
            "alternatives": [a.strip() for a in (args.alternatives or "").split(",") if a.strip()],
            "confidence": int(args.confidence or 3),
        },
        "classification": {
            "dataset_type": args.type or "reasoning-planning",
            "vuln_class": args.vuln_class or None,
            "cwe_id": args.cwe or None,
            "cvss_score": float(args.cvss or 0),
            "mitre_attack": args.mitre or None,
            "tags": tags,
        },
        "fine_tuning": {
            "system_prompt": args.system_prompt or "You are an authorized offensive security researcher operating under a signed Rules of Engagement.",
            "instruction": args.instruction or "",
            "input_text": input_data.get("redacted", ""),
            "output_text": output_data.get("summary", ""),
            "quality_score": 0.0,
        },
        "chain": {
            "parent_capture_id": args.parent_id or None,
            "child_capture_ids": [],
            "chain_position": args.chain_position or "start",
        },
    }

    filename = f"{args.capture_point or 'general'}_{now.strftime('%H%M%S')}_{args.type or 'reasoning'}.json"
    filepath = session_dir / filename
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(capture, f, indent=2, ensure_ascii=False)

    print(json.dumps({"status": "captured", "capture_id": capture["capture_id"], "file": str(filepath)}))


# ──────────────────────────────────────────────────────────────
# ACTION: format
# ──────────────────────────────────────────────────────────────
def action_format(args):
    """Transform raw captures into instruction-following training pairs."""
    input_dir = Path(args.input or RAW_DIR)
    output_dir = Path(args.output or FORMATTED_DIR)

    if not input_dir.exists():
        print(json.dumps({"error": f"Input directory not found: {input_dir}"}))
        sys.exit(1)

    formatted_count = Counter()
    skipped = 0

    for json_file in sorted(input_dir.rglob("*.json")):
        try:
            with open(json_file, 'r') as f:
                raw = json.load(f)
        except (json.JSONDecodeError, IOError):
            skipped += 1
            continue

        dataset_type = raw.get("dataset_type", "reasoning-planning")
        if dataset_type not in DATASET_TYPES:
            dataset_type = "reasoning-planning"

        ft = raw.get("fine_tuning", {})
        system = ft.get("system_prompt", "You are an authorized offensive security researcher operating under a signed Rules of Engagement.")
        instruction = ft.get("instruction") or raw.get("reasoning", {}).get("decision", "")
        input_text = ft.get("input_text") or raw.get("input", {}).get("redacted", "")
        output_text = ft.get("output_text") or raw.get("output", {}).get("summary", "")

        if not instruction and not output_text:
            skipped += 1
            continue

        classification = raw.get("classification", {})
        tags = classification.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        metadata = {
            "dataset_type": dataset_type,
            "vuln_class": classification.get("vuln_class"),
            "cwe_id": classification.get("cwe_id"),
            "cvss_score": classification.get("cvss_score", 0),
            "mitre_attack": classification.get("mitre_attack"),
            "tags": tags,
            "source_capture_id": raw.get("capture_id"),
            "source_file": str(json_file.name),
        }

        formatted = {
            "system": system,
            "instruction": instruction,
            "input": input_text,
            "output": output_text,
            "metadata": metadata,
            "quality_score": _compute_quality_score(raw, dataset_type),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        out_file = output_dir / dataset_type / f"{compute_hash(instruction + input_text)[:16]}.jsonl"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(formatted, ensure_ascii=False) + '\n')

        formatted_count[dataset_type] += 1

    result = {
        "status": "formatted",
        "formatted": dict(formatted_count),
        "total": sum(formatted_count.values()),
        "skipped": skipped,
    }
    print(json.dumps(result))


def _compute_quality_score(raw: dict, dataset_type: str) -> float:
    score = 0.3
    classification = raw.get("classification", {})
    if classification.get("cwe_id"):
        score += 0.1
    if classification.get("cvss_score", 0) > 0:
        score += 0.1
    if classification.get("mitre_attack"):
        score += 0.1
    output = raw.get("output", {})
    if output.get("raw") and len(output["raw"]) > 200:
        score += 0.1
    input_data = raw.get("input", {})
    if input_data.get("raw") and len(input_data["raw"]) > 100:
        score += 0.1
    reasoning = raw.get("reasoning", {})
    if reasoning.get("rationale") and len(reasoning["rationale"]) > 50:
        score += 0.1
    if dataset_type in ("vulnerability-exploit", "code-analysis", "reasoning-planning"):
        score += 0.1
    return min(score, 1.0)


# ──────────────────────────────────────────────────────────────
# ACTION: validate
# ──────────────────────────────────────────────────────────────
def action_validate(args):
    """Validate all formatted entries."""
    input_dir = Path(args.input)
    results = {"total": 0, "valid": 0, "invalid": 0, "errors": []}

    for jsonl_file in sorted(input_dir.rglob("*.jsonl")):
        entries = load_jsonl(jsonl_file)
        for i, entry in enumerate(entries):
            results["total"] += 1
            errors = _validate_entry(entry)
            if errors:
                results["invalid"] += 1
                results["errors"].append({"file": str(jsonl_file), "line": i, "errors": errors})
            else:
                results["valid"] += 1

    print(json.dumps(results, indent=2))


def _validate_entry(entry: dict) -> list:
    errors = []
    for field in ["system", "instruction", "input", "output"]:
        if not entry.get(field):
            errors.append(f"Missing or empty field: {field}")
    metadata = entry.get("metadata", {})
    if not metadata.get("dataset_type"):
        errors.append("Missing metadata.dataset_type")
    cwe = metadata.get("cwe_id")
    if cwe and not CWE_PATTERN.match(cwe):
        errors.append(f"Invalid CWE format: {cwe}")
    cvss = metadata.get("cvss_score", 0)
    if cvss and (cvss < 0 or cvss > 10):
        errors.append(f"Invalid CVSS score: {cvss}")
    text = entry.get("system", "") + entry.get("instruction", "") + entry.get("input", "") + entry.get("output", "")
    for pattern, _ in REDACT_PATTERNS:
        if pattern.search(text):
            errors.append("Potential PII/sensitive data detected (needs redaction)")
            break
    return errors


# ──────────────────────────────────────────────────────────────
# ACTION: dedup
# ──────────────────────────────────────────────────────────────
def action_dedup(args):
    """Remove exact and near-duplicates."""
    input_dir = Path(args.input)
    threshold = float(args.threshold or 0.85)
    stats = {"total_before": 0, "exact_duplicates": 0, "near_duplicates": 0, "final": 0}

    for dataset_type in DATASET_TYPES:
        type_dir = input_dir / dataset_type
        if not type_dir.exists():
            continue

        all_entries = []
        for jsonl_file in sorted(type_dir.glob("*.jsonl")):
            all_entries.extend(load_jsonl(jsonl_file))

        stats["total_before"] += len(all_entries)
        seen_hashes = {}
        unique_entries = []

        for entry in all_entries:
            key = compute_hash(entry.get("instruction", "") + entry.get("input", "") + entry.get("output", ""))
            if key in seen_hashes:
                stats["exact_duplicates"] += 1
                continue

            tokens = tokenize(entry.get("instruction", "") + " " + entry.get("output", ""))
            is_near_dup = False
            for existing_tokens, existing_idx in list(seen_hashes.values()):
                sim = jaccard_similarity(tokens, existing_tokens)
                if sim >= threshold:
                    stats["near_duplicates"] += 1
                    is_near_dup = True
                    break

            if not is_near_dup:
                seen_hashes[key] = (tokens, len(unique_entries))
                unique_entries.append(entry)

        stats["final"] += len(unique_entries)
        out_file = type_dir / "deduped.jsonl"
        write_jsonl(out_file, unique_entries)

    # Clean up original files (keep only deduped versions)
    for dataset_type in DATASET_TYPES:
        type_dir = input_dir / dataset_type
        if not type_dir.exists():
            continue
        for jsonl_file in type_dir.glob("*.jsonl"):
            if jsonl_file.name == "deduped.jsonl":
                continue
            jsonl_file.unlink()

    print(json.dumps(stats, indent=2))


# ──────────────────────────────────────────────────────────────
# ACTION: score
# ──────────────────────────────────────────────────────────────
def action_score(args):
    """Compute and update quality scores."""
    input_dir = Path(args.input)
    updated = 0

    for jsonl_file in sorted(input_dir.rglob("*.jsonl")):
        entries = load_jsonl(jsonl_file)
        modified = False
        for entry in entries:
            old_score = entry.get("quality_score", 0)
            new_score = _recompute_score(entry)
            if abs(new_score - old_score) > 0.01:
                entry["quality_score"] = new_score
                modified = True
                updated += 1
        if modified:
            write_jsonl(jsonl_file, entries)

    print(json.dumps({"status": "scored", "updated": updated}))


def _recompute_score(entry: dict) -> float:
    score = 0.2
    metadata = entry.get("metadata", {})
    if metadata.get("cwe_id"):
        score += 0.1
    if metadata.get("cvss_score", 0) > 0:
        score += 0.1
    if metadata.get("mitre_attack"):
        score += 0.1
    if metadata.get("tags") and len(metadata["tags"]) >= 3:
        score += 0.1
    output = entry.get("output", "")
    if len(output) > 500:
        score += 0.15
    elif len(output) > 200:
        score += 0.1
    instruction = entry.get("instruction", "")
    if len(instruction) > 50:
        score += 0.1
    system = entry.get("system", "")
    if "Rules of Engagement" in system:
        score += 0.05
    if "authorized" in system.lower():
        score += 0.05
    return min(round(score, 2), 1.0)


# ──────────────────────────────────────────────────────────────
# ACTION: balance
# ──────────────────────────────────────────────────────────────
def action_balance(args):
    """Check dataset type distribution against targets."""
    input_dir = Path(args.input)
    counts = {}
    for dataset_type in DATASET_TYPES:
        type_dir = input_dir / dataset_type
        if not type_dir.exists():
            counts[dataset_type] = 0
            continue
        total = 0
        for jsonl_file in type_dir.glob("*.jsonl"):
            total += len(load_jsonl(jsonl_file))
        counts[dataset_type] = total

    total_all = sum(counts.values())
    report = {"counts": counts, "total": total_all, "distribution": {}, "warnings": []}

    for dt, count in counts.items():
        target = TARGET_DISTRIBUTION.get(dt, 0)
        pct = (count / total_all * 100) if total_all > 0 else 0
        report["distribution"][dt] = {"count": count, "target": target, "pct": round(pct, 1), "ratio": round(count / target, 2) if target > 0 else 0}
        if count < target * 0.5:
            report["warnings"].append(f"UNDERSAMPLED: {dt} has {count}/{target} ({round(pct, 1)}%)")
        elif count > target * 2:
            report["warnings"].append(f"OVERSAMPLED: {dt} has {count}/{target} ({round(pct, 1)}%)")

    print(json.dumps(report, indent=2))


# ──────────────────────────────────────────────────────────────
# ACTION: split
# ──────────────────────────────────────────────────────────────
def action_split(args):
    """Stratified train/val/test split."""
    input_dir = Path(args.input)
    ratios = [int(x) for x in (args.ratios or "80,10,10").split(",")]
    seed = int(args.seed or 42)

    import random
    random.seed(seed)

    all_by_type = defaultdict(list)
    for dataset_type in DATASET_TYPES:
        type_dir = input_dir / dataset_type
        if not type_dir.exists():
            continue
        for jsonl_file in sorted(type_dir.glob("*.jsonl")):
            entries = load_jsonl(jsonl_file)
            for entry in entries:
                entry["_split_type"] = dataset_type
                all_by_type[dataset_type].append(entry)

    train, val, test = [], [], []
    for dtype, entries in all_by_type.items():
        shuffled = entries[:]
        random.shuffle(shuffled)
        n = len(shuffled)
        t = int(n * ratios[0] / 100)
        v = int(n * ratios[1] / 100)
        train.extend(shuffled[:t])
        val.extend(shuffled[t:t + v])
        test.extend(shuffled[t + v:])

    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)

    write_jsonl(EXPORTED_DIR / "train.jsonl", train)
    write_jsonl(EXPORTED_DIR / "validation.jsonl", val)
    write_jsonl(EXPORTED_DIR / "test.jsonl", test)

    print(json.dumps({
        "status": "split_complete",
        "train": len(train),
        "validation": len(val),
        "test": len(test),
        "total": len(train) + len(val) + len(test),
    }))


# ──────────────────────────────────────────────────────────────
# ACTION: export
# ──────────────────────────────────────────────────────────────
def action_export(args):
    """Full export pipeline: validate → dedup → score → balance → split → export."""
    input_dir = Path(args.input)
    output_dir = Path(args.output)

    class SubArgs:
        pass

    print("STEP 1: Validate...", file=sys.stderr)
    a = SubArgs()
    a.input = str(input_dir)
    action_validate(a)

    print("STEP 2: Dedup...", file=sys.stderr)
    a = SubArgs()
    a.input = str(input_dir)
    a.threshold = args.threshold or "0.85"
    action_dedup(a)

    print("STEP 3: Score...", file=sys.stderr)
    a = SubArgs()
    a.input = str(input_dir)
    action_score(a)

    print("STEP 4: Balance...", file=sys.stderr)
    a = SubArgs()
    a.input = str(input_dir)
    action_balance(a)

    print("STEP 5: Split + Export...", file=sys.stderr)
    a = SubArgs()
    a.input = str(input_dir)
    a.output = str(output_dir)
    a.ratios = args.ratios or "80,10,10"
    a.seed = args.seed or "42"
    action_split(a)

    print("STEP 6: Generate manifest...", file=sys.stderr)
    _generate_manifest(output_dir)

    print(json.dumps({"status": "export_complete", "output_dir": str(output_dir)}))


def _generate_manifest(output_dir: Path):
    stats = {"train": 0, "validation": 0, "test": 0}
    type_counts = Counter()
    all_cwes = set()
    all_mitre = set()
    all_cves = set()
    all_scores = []

    for split_name in ["train", "validation", "test"]:
        filepath = output_dir / f"{split_name}.jsonl"
        entries = load_jsonl(filepath)
        stats[split_name] = len(entries)
        for entry in entries:
            dtype = entry.get("metadata", {}).get("dataset_type", "unknown")
            type_counts[dtype] += 1
            all_scores.append(entry.get("quality_score", 0))
            cwe = entry.get("metadata", {}).get("cwe_id")
            if cwe:
                all_cwes.add(cwe)
            mitre = entry.get("metadata", {}).get("mitre_attack")
            if mitre:
                all_mitre.add(mitre)
            tags = entry.get("metadata", {}).get("tags", [])
            for tag in tags:
                if CVE_PATTERN.match(str(tag)):
                    all_cves.add(tag)

    total = sum(stats.values())
    manifest = {
        "version": "1.0",
        "created": datetime.now(timezone.utc).isoformat(),
        "total_entries": total,
        "split": stats,
        "distribution": {dt: {"count": cnt, "pct": round(cnt / total * 100, 1)} for dt, cnt in sorted(type_counts.items())},
        "quality_stats": {
            "mean": round(sum(all_scores) / len(all_scores), 3) if all_scores else 0,
            "min": round(min(all_scores), 3) if all_scores else 0,
            "max": round(max(all_scores), 3) if all_scores else 0,
        },
        "cwe_coverage": sorted(all_cwes),
        "mitre_attack_coverage": sorted(all_mitre),
        "cve_references": sorted(all_cves),
    }

    with open(output_dir / "manifest.json", 'w') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────────────────────
# ACTION: stats
# ──────────────────────────────────────────────────────────────
def action_stats(args):
    """Print dataset statistics."""
    input_dir = Path(args.input or EXPORTED_DIR)

    stats = {"splits": {}, "types": defaultdict(int), "total": 0, "quality": []}
    for split_name in ["train", "validation", "test"]:
        filepath = input_dir / f"{split_name}.jsonl"
        entries = load_jsonl(filepath)
        stats["splits"][split_name] = len(entries)
        stats["total"] += len(entries)
        for entry in entries:
            dtype = entry.get("metadata", {}).get("dataset_type", "unknown")
            stats["types"][dtype] += 1
            stats["quality"].append(entry.get("quality_score", 0))

    if stats["quality"]:
        scores = stats["quality"]
        stats["quality_summary"] = {
            "mean": round(sum(scores) / len(scores), 3),
            "min": round(min(scores), 3),
            "max": round(max(scores), 3),
        }
    del stats["quality"]
    stats["types"] = dict(stats["types"])

    print(json.dumps(stats, indent=2))


# ──────────────────────────────────────────────────────────────
# ACTION: auto — Auto-classify and capture based on tool + phase
# ──────────────────────────────────────────────────────────────
TOOL_TYPE_MAP = {
    "mcp_burp": "network-webapp",
    "nmap_scan": "network-webapp",
    "sqlmap_scan": "network-webapp",
    "nikto_scan": "network-webapp",
    "gobuster_scan": "network-webapp",
    "dirb_scan": "network-webapp",
    "hydra_attack": "credential-auth",
    "john_crack": "credential-auth",
    "enum4linux_scan": "osint-recon",
    "metasploit_run": "vulnerability-exploit",
    "wpscan_analyze": "vulnerability-exploit",
    "execute_command": "shell-commands",
    "firefox-devtools": "network-webapp",
    "playwright": "network-webapp",
    "websearch": "osint-recon",
    "webfetch": "osint-recon",
    "dom_analyze": "reasoning-planning",
    "oast_generate": "reasoning-planning",
    "oast_poll": "reasoning-planning",
    "oast_cleanup": "reasoning-planning",
    "saliency_filter": "reasoning-planning",
    "payload_mutate": "vulnerability-exploit",
}

PHASE_VULN_MAP = {
    "3": "sqli", "4": "nosqli", "5": "xss", "6": "csrf", "7": "ssrf",
    "8": "xxe", "9": "ssti", "10": "cmdi", "11": "idor", "12": "access-control",
    "13": "auth-bypass", "14": "jwt", "15": "oauth", "16": "deserialization",
    "17": "file-upload", "18": "lfi", "19": "rfi", "20": "open-redirect",
    "21": "clickjacking", "22": "smuggling", "23": "cache-poisoning",
    "24": "cache-deception", "25": "cors", "26": "business-logic",
    "27": "race-condition", "28": "mass-assignment", "29": "prototype-pollution",
    "30": "dom-clobbering", "31": "hpp", "32": "graphql", "33": "websocket",
    "34": "api-security", "35": "redos", "36": "subdomain-takeover",
    "37": "dependency-confusion", "38": "crlf", "39": "misconfiguration",
    "40": "ldap", "41": "xpath",
}

REASONING_PHASES = {"0": "recon", "1": "fingerprinting", "2": "classification",
                    "42": "chain", "45": "self-assessment", "48": "cve-weaponization"}


def action_auto(args):
    """Auto-classify a tool call and capture it. Infers dataset_type and tags from tool name and phase."""
    tool = (args.tool or "").lower()
    phase = (args.phase or "0").split(".")[0]

    dataset_type = None
    for prefix, dtype in TOOL_TYPE_MAP.items():
        if prefix in tool:
            dataset_type = dtype
            break

    if not dataset_type:
        if phase in REASONING_PHASES:
            dataset_type = "reasoning-planning"
        elif phase in PHASE_VULN_MAP:
            dataset_type = "vulnerability-exploit" if "cve" in tool.lower() else "network-webapp"
        else:
            dataset_type = "reasoning-planning"

    vuln_class = PHASE_VULN_MAP.get(phase)
    tags = []
    if vuln_class:
        tags.append(vuln_class)
    if phase in REASONING_PHASES:
        tags.append(REASONING_PHASES[phase])

    auto_tags = ",".join(tags) if tags else (args.tags or "")

    class AutoArgs:
        pass
    a = AutoArgs()
    a.type = dataset_type
    a.tool = args.tool
    a.session_id = args.session_id
    a.target = args.target
    a.phase = args.phase
    a.capture_point = args.capture_point or f"auto_{tool}"
    a.input_file = args.input_file
    a.input_text = args.input_text
    a.output_file = args.output_file
    a.output_text = args.output_text
    a.decision = args.decision
    a.rationale = args.rationale
    a.alternatives = args.alternatives
    a.confidence = args.confidence
    a.vuln_class = vuln_class or args.vuln_class
    a.cwe = args.cwe
    a.cvss = args.cvss
    a.mitre = args.mitre
    a.tags = auto_tags
    a.system_prompt = args.system_prompt
    a.instruction = args.instruction
    a.parent_id = args.parent_id
    a.chain_position = args.chain_position

    action_capture(a)


# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Offensive Security Dataset Pipeline Engine")
    parser.add_argument("--action", required=True,
                        choices=["capture", "auto", "format", "validate", "dedup", "score", "balance", "split", "export", "stats"])
    parser.add_argument("--input", help="Input directory/file")
    parser.add_argument("--output", help="Output directory")
    parser.add_argument("--type", help="Dataset type", choices=DATASET_TYPES)
    parser.add_argument("--session-id", help="Session identifier")
    parser.add_argument("--target", help="Target slug")
    parser.add_argument("--phase", help="Phase number")
    parser.add_argument("--tool", help="Tool/function name")
    parser.add_argument("--capture-point", help="Capture point name")
    parser.add_argument("--input-file", help="Input file path for capture")
    parser.add_argument("--input-text", help="Input text for capture")
    parser.add_argument("--output-file", help="Output file path for capture")
    parser.add_argument("--output-text", help="Output text for capture")
    parser.add_argument("--decision", help="Decision made")
    parser.add_argument("--rationale", help="Rationale for decision")
    parser.add_argument("--alternatives", help="Alternatives considered (comma-separated)")
    parser.add_argument("--confidence", help="Confidence level 1-5")
    parser.add_argument("--vuln-class", help="Vulnerability class")
    parser.add_argument("--cwe", help="CWE ID")
    parser.add_argument("--cvss", help="CVSS score")
    parser.add_argument("--mitre", help="MITRE ATT&CK technique")
    parser.add_argument("--tags", help="Tags (comma-separated)")
    parser.add_argument("--system-prompt", help="System prompt for training pair")
    parser.add_argument("--instruction", help="Instruction for training pair")
    parser.add_argument("--parent-id", help="Parent capture ID for chaining")
    parser.add_argument("--chain-position", help="Chain position: start/middle/end")
    parser.add_argument("--threshold", help="Dedup similarity threshold")
    parser.add_argument("--ratios", help="Split ratios (e.g. 80,10,10)")
    parser.add_argument("--seed", help="Random seed for splitting")

    args = parser.parse_args()

    actions = {
        "capture": action_capture,
        "auto": action_auto,
        "format": action_format,
        "validate": action_validate,
        "dedup": action_dedup,
        "score": action_score,
        "balance": action_balance,
        "split": action_split,
        "export": action_export,
        "stats": action_stats,
    }

    actions[args.action](args)


if __name__ == "__main__":
    main()
