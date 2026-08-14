#!/usr/bin/env python3
"""
oc v3.3 — Structural DOM Differential Analyzer
===============================================
Eliminates false positives from dynamic data fluctuations (timestamps, nonces,
CSRF tokens, random IDs) by applying structural normalization and then
comparing the normalized DOM trees.

Theory of operation:
  1. Parse each HTML payload into a parse tree.
  2. Structural normalization: strip text content, remove transient attributes
     (csrf, nonce, timestamp patterns), collapse script/style bodies.
  3. Compute a structural fingerprint (tag → attribute → child-count skeleton).
  4. Compare normalized fingerprints pairwise:
       - control vs false_condition (no injection) — should be similar.
       - true_condition vs false_condition — divergence here = injection worked.
  5. Return a definitive boolean plus supporting metrics.

Path-resilient: resolves all paths relative to this script's location, so it
works regardless of the agent's current working directory.

Usage:
  python3 mcp/dom_analyzer.py --control <file|string> \\
                              --true-condition <file|string> \\
                              --false-condition <file|string>
  python3 mcp/dom_analyzer.py --stdin  # reads JSON from stdin
"""

import sys
import json
import os
import re
import argparse
import hashlib
from html.parser import HTMLParser
from typing import Optional
from collections import Counter


# ---------------------------------------------------------------------------
# Lightweight HTML → Structural Skeleton Parser
# ---------------------------------------------------------------------------

# Attributes whose values are stripped entirely (csrf, nonces, timestamps, etc.)
STRIP_ATTRIBUTE_PATTERNS = re.compile(
    r"^(csrf|nonce|timestamp|token|hash|checksum|signature|version|"
    r"data-timestamp|data-nonce|data-hash|data-version|"
    r"aria-.*|id$|name$|style$)",
    re.IGNORECASE,
)

# Attributes whose values are normalized to a placeholder
NORMALIZE_VALUE_PATTERNS = re.compile(
    r"^(src|href|action|data-url|data-src|data-href|url|link|poster)$",
    re.IGNORECASE,
)

# Transient text patterns: timestamps, hex IDs, base64 blobs
TRANSIENT_TEXT_PATTERNS = [
    re.compile(r"\b\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}\b"),  # ISO dates
    re.compile(r"\b\d{10,13}\b"),                                         # Unix timestamps
    re.compile(r"\b[0-9a-f]{32,64}\b", re.IGNORECASE),                  # MD5/SHA hashes
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE),  # UUID
    re.compile(r"\b[A-Za-z0-9+/=]{32,}\b"),                              # Base64-like
]


class DOMStructuralParser(HTMLParser):
    """
    Parses HTML and builds a structural skeleton:
    A list of (tag, frozenset_of_attr_keys, child_count) tuples.

    Text nodes and attribute *values* are stripped; only the existence
    and count of structural elements matters.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skeleton: list[tuple[str, frozenset, int]] = []
        self._stack: list[int] = []   # indices into skeleton for parent tracking
        self._child_counts: dict[int, int] = {}  # idx → child element count

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        normalized_attrs = self._normalize_attrs(attrs)
        idx = len(self.skeleton)
        self.skeleton.append((tag.lower(), frozenset(normalized_attrs), 0))
        self._child_counts[idx] = 0

        if self._stack:
            parent_idx = self._stack[-1]
            self._child_counts[parent_idx] = self._child_counts.get(parent_idx, 0) + 1

        # Self-closing tags don't push onto stack
        if tag.lower() not in {
            "area", "base", "br", "col", "embed", "hr", "img", "input",
            "link", "meta", "param", "source", "track", "wbr",
        }:
            self._stack.append(idx)

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        # Update child count on the matching skeleton entry
        for i in range(len(self._stack) - 1, -1, -1):
            idx = self._stack[i]
            if self.skeleton[idx][0] == tag_lower:
                entry = self.skeleton[idx]
                self.skeleton[idx] = (entry[0], entry[1], self._child_counts.get(idx, 0))
                self._stack = self._stack[:i]
                break

    def handle_data(self, data: str) -> None:
        # Text nodes don't go into the structural skeleton.
        # Their presence is already captured by child_count > 0
        # (text is a child of the parent element).
        # However, we DO check if the raw data looks like it could
        # carry transient dynamic content — for the uniform template
        # fingerprint we ignore text entirely.
        pass

    def _normalize_attrs(self, attrs: list[tuple[str, Optional[str]]]) -> set[str]:
        """Keep only structurally relevant attribute keys. Strip transient values."""
        keep: set[str] = set()
        for key, value in attrs:
            if STRIP_ATTRIBUTE_PATTERNS.match(key):
                continue
            if NORMALIZE_VALUE_PATTERNS.match(key):
                keep.add(key)  # keep key, ignore dynamic value
            else:
                keep.add(key)
        return keep

    def finalize(self) -> list[tuple[str, frozenset, int]]:
        """Pop any remaining stack entries and return the skeleton."""
        for idx in reversed(self._stack):
            entry = self.skeleton[idx]
            self.skeleton[idx] = (entry[0], entry[1], self._child_counts.get(idx, 0))
        self._stack.clear()
        return self.skeleton


# ---------------------------------------------------------------------------
# Structural normalization & fingerprinting
# ---------------------------------------------------------------------------

def strip_dynamic_text(html: str) -> str:
    """Remove text nodes that match transient/volatile patterns."""
    for pattern in TRANSIENT_TEXT_PATTERNS:
        html = pattern.sub("__DYNAMIC__", html)
    return html


def parse_structural_skeleton(html: str) -> list[tuple[str, frozenset, int]]:
    """Parse HTML into a normalized structural skeleton."""
    cleaned = strip_dynamic_text(html)
    parser = DOMStructuralParser()
    try:
        parser.feed(cleaned)
    except Exception:
        pass  # best-effort: malformed HTML yields partial skeleton
    try:
        parser.close()
    except Exception:
        pass
    return parser.finalize()


def skeleton_fingerprint(skeleton: list[tuple[str, frozenset, int]]) -> str:
    """Produce a stable hash of the structural skeleton for fast comparison."""
    canon = ";".join(
        f"{tag}:{','.join(sorted(attrs))}:{children}"
        for tag, attrs, children in skeleton
    )
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def skeleton_distance(a: list[tuple[str, frozenset, int]],
                      b: list[tuple[str, frozenset, int]]) -> float:
    """
    Compute a normalized structural distance between two skeletons.
    Uses element-type jaccard distance + edit-distance-like weighting.
    Returns 0.0 (identical) to 1.0 (completely different).
    """
    if not a and not b:
        return 0.0
    if not a or not b:
        return 1.0

    # Compare tag sequences
    a_tags = [entry[0] for entry in a]
    b_tags = [entry[0] for entry in b]

    # Simple Damerau-Levenshtein-like on tag sequences, normalized
    n, m = len(a_tags), len(b_tags)
    if n == 0 and m == 0:
        return 0.0

    # Longest common subsequence ratio
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if a_tags[i - 1] == b_tags[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    lcs_len = dp[n][m]
    max_len = max(n, m)
    tag_dist = 1.0 - (lcs_len / max_len) if max_len > 0 else 0.0

    # Attribute similarity bonus/penalty
    attr_matches = 0
    attr_total = max(len(a), len(b))
    for i in range(min(len(a), len(b))):
        a_attrs = a[i][1]
        b_attrs = b[i][1]
        if a_attrs == b_attrs:
            attr_matches += 1
    attr_sim = attr_matches / max(attr_total, 1)

    # Combined: 60% tag structure, 40% attribute structure
    return 0.6 * tag_dist + 0.4 * (1.0 - attr_sim)


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyze_divergence(control_html: str,
                       true_html: str,
                       false_html: str,
                       threshold: float = 0.15) -> dict:
    """
    Determine whether true_condition is structurally divergent from
    false_condition relative to the control baseline.

    Logic:
      1. Normalize all three inputs.
      2. Compute skeleton distance between control and false_condition
         (baseline noise).
      3. Compute skeleton distance between true_condition and false_condition
         (candidate signal).
      4. If candidate signal exceeds baseline noise by more than `threshold`,
         structural divergence is detected.

    Returns a dict suitable for JSON output.
    """
    control_skel = parse_structural_skeleton(control_html)
    true_skel = parse_structural_skeleton(true_html)
    false_skel = parse_structural_skeleton(false_html)

    control_fp = skeleton_fingerprint(control_skel)
    true_fp = skeleton_fingerprint(true_skel)
    false_fp = skeleton_fingerprint(false_skel)

    # Baseline: how much does a non-injected page differ from control?
    baseline_dist = skeleton_distance(control_skel, false_skel)

    # Candidate: how much does the injected page differ from non-injected?
    candidate_dist = skeleton_distance(true_skel, false_skel)

    # Also compare true vs control for additional signal
    true_vs_control_dist = skeleton_distance(true_skel, control_skel)

    # Divergence is detected when the candidate distance exceeds the baseline
    # by more than the threshold, OR when true and false have different
    # fingerprints while control and false are similar.
    structural_divergence = (
        candidate_dist > baseline_dist + threshold
        or (true_fp != false_fp and control_fp == false_fp)
        or (true_fp != control_fp and false_fp == control_fp and true_fp != false_fp)
    )

    # Additional metrics for agent reasoning
    lengths = {
        "control": len(control_html),
        "true_condition": len(true_html),
        "false_condition": len(false_html),
    }
    skeleton_lengths = {
        "control": len(control_skel),
        "true_condition": len(true_skel),
        "false_condition": len(false_skel),
    }

    return {
        "structural_divergence_detected": structural_divergence,
        "metrics": {
            "baseline_distance": round(baseline_dist, 4),
            "candidate_distance": round(candidate_dist, 4),
            "true_vs_control_distance": round(true_vs_control_dist, 4),
            "threshold": threshold,
            "html_lengths": lengths,
            "skeleton_lengths": skeleton_lengths,
            "fingerprints": {
                "control": control_fp[:16],
                "true_condition": true_fp[:16],
                "false_condition": false_fp[:16],
            },
        },
        "interpretation": (
            "Injection caused structural DOM change — investigate further."
            if structural_divergence
            else "No structural divergence detected — likely false positive or dynamic noise."
        ),
    }


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _resolve_input(value: str) -> str:
    """If the value is a readable file path, return its content; otherwise return as-is."""
    if os.path.isfile(value):
        with open(value, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    return value


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="oc v3.3 DOM Structural Differential Analyzer — false positive elimination"
    )
    parser.add_argument(
        "--control",
        help="Baseline HTML response (no injection) — string or file path"
    )
    parser.add_argument(
        "--true-condition",
        help="HTML response with injection payload delivered"
    )
    parser.add_argument(
        "--false-condition",
        help="HTML response with harmless/inert payload"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.15,
        help="Divergence threshold (0.0–1.0, default: 0.15)"
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read JSON from stdin: {\"control\": \"...\", \"true_condition\": \"...\", \"false_condition\": \"...\"}"
    )

    args = parser.parse_args()

    if args.stdin:
        raw = sys.stdin.read()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"Invalid JSON on stdin: {e}"}))
            sys.exit(1)

        control = payload.get("control", "")
        true_cond = payload.get("true_condition", "")
        false_cond = payload.get("false_condition", "")
        threshold = payload.get("threshold", 0.15)
    else:
        if not all([args.control, args.true_condition, args.false_condition]):
            parser.print_help()
            print("\n[ERROR] --control, --true-condition, and --false-condition are all required.", file=sys.stderr)
            sys.exit(1)
        control = _resolve_input(args.control)
        true_cond = _resolve_input(args.true_condition)
        false_cond = _resolve_input(args.false_condition)
        threshold = args.threshold

    result = analyze_divergence(control, true_cond, false_cond, threshold=threshold)
    print(json.dumps(result, indent=2))

    # Non-zero exit if divergence detected (for use in shell pipelines)
    if result["structural_divergence_detected"]:
        sys.exit(0)  # success = divergence found
    else:
        sys.exit(1)  # no divergence = nothing to see


if __name__ == "__main__":
    main()
