#!/usr/bin/env python3
"""
oc v3.3 — Recon Saliency Filter
=================================
Pre-processes asset discovery output before it enters the REACT reasoning loop
or is written into fullrecon/ directories. Eliminates low-value noise and
elevates high-signal routing vectors to prevent context saturation.

Classification tiers:
  DROP     — Static assets, duplicate pages, 404 boilerplate, empty responses.
  PASS     — Standard pages; neither filtered nor elevated.
  ELEVATE  — High-value surfaces: API routes, auth endpoints, .git exposure,
             parameterized inputs, graphql, config paths.

Usage:
  python3 mcp/saliency_filter.py --input <file|stdin> [--output <file>] [--format json|text]
  python3 mcp/saliency_filter.py --stdin < noisy_recon.txt

Input formats:
  - Plain text: one URL/path per line (httpx, gau, waybackurls output)
  - JSON Lines: {"url": "...", "status": 200, "content_type": "...", ...}
  - Raw HTML/JSON response body (auto-detected)
"""

import sys
import json
import os
import re
import argparse
from urllib.parse import urlparse, parse_qs
from typing import Optional
from collections import Counter


# ---------------------------------------------------------------------------
# Static rule sets
# ---------------------------------------------------------------------------

# Extensions to drop outright — static assets with zero attack surface
DROP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".css", ".scss", ".sass", ".less",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".webm", ".ogg", ".wav", ".flac",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}

# Content-Types that indicate static/no-attack-surface responses
DROP_CONTENT_TYPES = {
    "image/png", "image/jpeg", "image/gif", "image/svg+xml", "image/webp",
    "image/x-icon", "image/vnd.microsoft.icon",
    "font/woff", "font/woff2", "font/ttf", "application/font-woff",
    "video/mp4", "video/webm", "audio/mpeg", "audio/ogg",
    "application/pdf",
    "text/css",
}

# Status codes that are almost always noise
DROP_STATUS_CODES = {404, 405, 410, 501, 502, 503}

# 404 boilerplate patterns — if a page body matches these, drop it
BOILERPLATE_404_PATTERNS = [
    re.compile(r"<title>\s*404\s*(Not Found|Page Not Found|Error)\s*</title>", re.IGNORECASE),
    re.compile(r"<h1[^>]*>\s*404\s*(Not Found|Page Not Found|Error)\s*</h1>", re.IGNORECASE),
    re.compile(r"The requested (URL|page|resource) (was|could) not (be )?found", re.IGNORECASE),
    re.compile(r"nginx/\d+\.\d+", re.IGNORECASE),
    re.compile(r"Apache/\d+\.\d+.*(404|Not Found)", re.IGNORECASE),
]

# Empty or near-empty responses
EMPTY_PAGE_THRESHOLD = 150  # bytes — pages smaller than this are noise

# ---------------------------------------------------------------------------
# Elevation patterns — high-signal routing vectors
# ---------------------------------------------------------------------------

ELEVATE_PATH_PATTERNS = [
    # API routes
    re.compile(r"/api/v?\d*/", re.IGNORECASE),
    re.compile(r"/graphql", re.IGNORECASE),
    re.compile(r"/graphiql", re.IGNORECASE),
    re.compile(r"/swagger", re.IGNORECASE),
    re.compile(r"/openapi\.json", re.IGNORECASE),
    re.compile(r"/api-docs?", re.IGNORECASE),
    # Auth & identity
    re.compile(r"/oauth2?", re.IGNORECASE),
    re.compile(r"/oauth/", re.IGNORECASE),
    re.compile(r"/authorize", re.IGNORECASE),
    re.compile(r"/\.well-known/openid-configuration", re.IGNORECASE),
    re.compile(r"/saml", re.IGNORECASE),
    re.compile(r"/sso", re.IGNORECASE),
    re.compile(r"/login", re.IGNORECASE),
    re.compile(r"/signin", re.IGNORECASE),
    re.compile(r"/auth", re.IGNORECASE),
    re.compile(r"/token", re.IGNORECASE),
    # Developer / config exposure
    re.compile(r"/\.git/", re.IGNORECASE),
    re.compile(r"/\.env", re.IGNORECASE),
    re.compile(r"/\.svn/", re.IGNORECASE),
    re.compile(r"/\.hg/", re.IGNORECASE),
    re.compile(r"/\.DS_Store", re.IGNORECASE),
    re.compile(r"/wp-config", re.IGNORECASE),
    re.compile(r"/config\.(json|yml|yaml|xml|ini|toml)", re.IGNORECASE),
    re.compile(r"/phpinfo\.php", re.IGNORECASE),
    re.compile(r"/debug", re.IGNORECASE),
    re.compile(r"/phpmyadmin", re.IGNORECASE),
    re.compile(r"/actuator", re.IGNORECASE),
    re.compile(r"/healthcheck", re.IGNORECASE),
    re.compile(r"/metrics", re.IGNORECASE),
    # Parameterized / input surfaces
    re.compile(r"\?(id|page|q|search|query|file|path|url|redirect|callback|cmd|exec|action|view|user|token|key|api_key)=", re.IGNORECASE),
    re.compile(r"/upload", re.IGNORECASE),
    re.compile(r"/import", re.IGNORECASE),
    re.compile(r"/export", re.IGNORECASE),
    re.compile(r"/download", re.IGNORECASE),
    re.compile(r"/admin", re.IGNORECASE),
    re.compile(r"/backup", re.IGNORECASE),
    re.compile(r"/backup\.(zip|tar\.gz|sql|sql\.gz|7z)", re.IGNORECASE),
    # WebSocket / real-time
    re.compile(r"/ws", re.IGNORECASE),
    re.compile(r"/socket\.io", re.IGNORECASE),
    re.compile(r"/realtime", re.IGNORECASE),
    # Interesting file extensions
    re.compile(r"\.(php|asp|aspx|jsp|do|action|ashx|asmx|cfm|cgi|pl|py|rb|sh)\b", re.IGNORECASE),
]

# Paths that indicate reflection (parameter in response) — very high signal
REFLECTION_INDICATORS = re.compile(
    r"\?(q|search|query|s|keyword|term|find|lookup)=", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

def classify_url(url: str) -> tuple[str, str]:
    """
    Classify a URL into one of three tiers.

    Returns (tier, reason) where tier is "DROP", "PASS", or "ELEVATE".
    """
    parsed = urlparse(url)
    path = parsed.path.lower()

    # --- DROP checks ---

    # Extension-based
    _, ext = os.path.splitext(path)
    if ext in DROP_EXTENSIONS:
        return ("DROP", f"static_asset:{ext}")

    # Trivial paths
    if path in ("/", "/index.html", "/index.php", "/home", "/robots.txt", "/favicon.ico"):
        return ("DROP", "trivial_path")

    # --- ELEVATE checks ---

    reasons: list[str] = []
    for pattern in ELEVATE_PATH_PATTERNS:
        if pattern.search(url):
            reasons.append(pattern.pattern[:40])

    if reasons:
        return ("ELEVATE", ",".join(reasons[:3]))

    # Reflection indicators on the full URL
    if REFLECTION_INDICATORS.search(url):
        return ("ELEVATE", "reflection_indicator")

    # --- DEFAULT ---
    return ("PASS", "standard")


def classify_response(url: str, status: int, content_type: str,
                      body: str = "", content_length: int = 0) -> tuple[str, str]:
    """
    Enhanced classification using HTTP response metadata.

    Returns (tier, reason).
    """
    # Start with URL-based classification
    tier, reason = classify_url(url)

    # If already DROP or ELEVATE by URL, return unless contradicted by strong signal
    if tier == "ELEVATE":
        return (tier, reason)

    # Additional DROP checks based on response

    # Status code
    if status in DROP_STATUS_CODES:
        return ("DROP", f"http_{status}")

    # Content-Type
    ct_lower = content_type.lower().split(";")[0].strip()
    if ct_lower in DROP_CONTENT_TYPES:
        return ("DROP", f"content_type:{ct_lower}")

    # Empty / near-empty
    if content_length > 0 and content_length < EMPTY_PAGE_THRESHOLD:
        if not body or body.strip() in ("{}", "[]", "null", "ok", "true", "false"):
            return ("DROP", "empty_or_trivial_body")
    elif body:
        body_len = len(body.encode("utf-8"))
        if body_len < EMPTY_PAGE_THRESHOLD:
            stripped = body.strip()
            if not stripped or stripped in ("{}", "[]", "null", "ok", "true", "false"):
                return ("DROP", "empty_or_trivial_body")

    # 404 boilerplate
    if status == 404 or (200 <= status < 300 and body):
        for pattern in BOILERPLATE_404_PATTERNS:
            if pattern.search(body):
                return ("DROP", "boilerplate_404")

    return (tier, reason)


# ---------------------------------------------------------------------------
# Bulk processing
# ---------------------------------------------------------------------------

def process_lines(lines: list[str]) -> dict:
    """
    Process a list of input lines (URLs or JSON objects).
    Returns a dict with 'dropped', 'passed', 'elevated' lists.
    """
    dropped: list[dict] = []
    passed: list[dict] = []
    elevated: list[dict] = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Try JSON-Lines format
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = {"url": line}
        else:
            obj = {"url": line}

        url = obj.get("url", obj.get("input", obj.get("host", line)))
        status = obj.get("status", obj.get("status_code", 200))
        content_type = obj.get("content_type", obj.get("content-type", ""))
        body = obj.get("body", obj.get("response", obj.get("content", "")))
        content_length = obj.get("content_length", obj.get("length", len(body)))

        # Try to coerce status
        try:
            status = int(status)
        except (ValueError, TypeError):
            status = 200

        tier, reason = classify_response(
            url, status, str(content_type), str(body), int(content_length or 0)
        )

        entry = {
            "url": url,
            "status": status,
            "reason": reason,
        }
        if obj.get("content_type"):
            entry["content_type"] = content_type
        if obj.get("content_length"):
            entry["content_length"] = content_length

        if tier == "DROP":
            dropped.append(entry)
        elif tier == "ELEVATE":
            elevated.append(entry)
        else:
            passed.append(entry)

    return {
        "dropped": dropped,
        "passed": passed,
        "elevated": elevated,
        "summary": {
            "total_input": len(lines),
            "dropped_count": len(dropped),
            "passed_count": len(passed),
            "elevated_count": len(elevated),
            "retention_rate": round(
                (len(passed) + len(elevated)) / max(len(lines), 1) * 100, 1
            ),
        },
    }


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_text_output(results: dict) -> str:
    """Plain-text output optimized for piping into other tools."""
    out: list[str] = []

    # Summary header
    s = results["summary"]
    out.append(f"# Saliency Filter: {s['total_input']} inputs → "
               f"{s['passed_count'] + s['elevated_count']} retained "
               f"({s['retention_rate']}%)")

    if results["elevated"]:
        out.append(f"\n## ELEVATED ({s['elevated_count']}) — HIGH SIGNAL")
        out.append("#" * 60)
        for entry in results["elevated"]:
            out.append(f"[ELEVATED] {entry['url']}  ({entry['reason']})")

    if results["passed"]:
        out.append(f"\n## PASSED ({s['passed_count']})")
        for entry in results["passed"]:
            out.append(entry["url"])

    if results["dropped"]:
        out.append(f"\n# Dropped {s['dropped_count']} noise entries (use --verbose to list)")

    return "\n".join(out)


def format_text_verbose(results: dict) -> str:
    """Verbose plain-text output including dropped items."""
    out = [format_text_output(results)]
    if results["dropped"]:
        out.append(f"\n## DROPPED ({results['summary']['dropped_count']})")
        for entry in results["dropped"]:
            out.append(f"[DROPPED] {entry['url']}  ({entry['reason']})")
    return "\n".join(out)


def format_json_output(results: dict) -> str:
    """JSON output for programmatic consumption."""
    return json.dumps(results, indent=2)


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="oc v3.3 Recon Saliency Filter — context optimization for asset discovery"
    )
    parser.add_argument(
        "--input", "-i",
        help="Input file path (one URL per line, or JSON Lines). Reads stdin if omitted."
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (writes to stdout if omitted)."
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "text", "text-verbose"],
        default="text",
        help="Output format: json (structured), text (summary + retained only), text-verbose (everything)"
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Explicitly read from stdin (default behavior when --input not provided)"
    )
    parser.add_argument(
        "--elevate-only",
        action="store_true",
        help="Output only elevated URLs (line-by-line, for piping)"
    )
    parser.add_argument(
        "--retain-only",
        action="store_true",
        help="Output only retained (elevated + passed) URLs line-by-line"
    )

    args = parser.parse_args()

    # Resolve input
    if args.input:
        with open(args.input, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    else:
        raw = sys.stdin.read()

    lines = raw.splitlines()

    results = process_lines(lines)

    # Format output
    if args.elevate_only:
        output = "\n".join(e["url"] for e in results["elevated"])
    elif args.retain_only:
        output = "\n".join(
            e["url"] for e in results["elevated"] + results["passed"]
        )
    elif args.format == "json":
        output = format_json_output(results)
    elif args.format == "text-verbose":
        output = format_text_verbose(results)
    else:
        output = format_text_output(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
