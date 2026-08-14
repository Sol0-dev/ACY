#!/usr/bin/env python3
"""
oc v3.3 — MCP Server Wrapper for Automation Engines
=====================================================
Exposes all four v3.3 automation engines as MCP (Model Context Protocol) tools
via stdio JSON-RPC transport. This makes them first-class citizens in opencode,
discoverable via tools/list and invokable via tools/call.

Registered tools:
  oast_generate    — Provision an OAST callback token for blind vuln testing
  oast_poll        — Poll the OAST provider for interactions on active tokens
  oast_cleanup     — Remove stale OAST registrations
  dom_analyze      — Structural DOM differential analysis (false positive eliminator)
  saliency_filter  — Filter recon output for high-signal surfaces (context optimizer)
  payload_mutate   — Deterministic payload mutation from seed + strategy

Protocol: MCP JSON-RPC 2.0 over stdin/stdout (per opencode spec).
"""

import sys
import json
import os

# Ensure we can import sibling modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oast_manager import action_generate, action_poll, action_cleanup
from dom_analyzer import analyze_divergence
from saliency_filter import process_lines
from payload_mutator import STRATEGIES


# ---------------------------------------------------------------------------
# Tool definitions (exposed to opencode via tools/list)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "oast_generate",
        "description": "Provision a unique OAST (Out-of-Band Application Security Testing) callback token for blind vulnerability detection. Returns a callback URL and token to embed in payloads for Blind RCE, SSRF, Second-Order SQLi testing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "correlation_id": {
                    "type": "string",
                    "description": "Human-readable label linking this token to the test surface (e.g. 'sqli_blind_endpoint_12')",
                },
            },
            "required": ["correlation_id"],
        },
    },
    {
        "name": "oast_poll",
        "description": "Poll the OAST provider for any interactions on active callback tokens. Returns all received interactions (DNS/HTTP/SMTP callbacks) grouped by token. Use this after deploying OAST payloads to check if blind injection succeeded.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "oast_cleanup",
        "description": "Remove stale OAST registrations older than the TTL (default 48 hours).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ttl_hours": {
                    "type": "integer",
                    "description": "Remove tokens older than this many hours (default: 48)",
                },
            },
            "required": [],
        },
    },
    {
        "name": "dom_analyze",
        "description": "Structural DOM differential analyzer. Accepts three HTML responses (control/no-injection, true-condition/with-payload, false-condition/inert-payload) and performs structural normalization to determine whether an injection caused actual DOM divergence — eliminating false positives from dynamic data (timestamps, CSRF tokens, nonces). Returns a definitive boolean and supporting metrics. MUST be called before confirming any injection finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "control": {
                    "type": "string",
                    "description": "Baseline HTML response with NO injection payload",
                },
                "true_condition": {
                    "type": "string",
                    "description": "HTML response with the active injection payload delivered",
                },
                "false_condition": {
                    "type": "string",
                    "description": "HTML response with a harmless/inert payload (no injection)",
                },
                "threshold": {
                    "type": "number",
                    "description": "Divergence sensitivity 0.0–1.0 (default: 0.15)",
                },
            },
            "required": ["control", "true_condition", "false_condition"],
        },
    },
    {
        "name": "saliency_filter",
        "description": "Pre-process recon/discovery output to filter out low-value noise (static assets, 404 boilerplate, empty responses) and elevate high-signal surfaces (API routes, auth endpoints, .git exposure, parameterized inputs, graphql). Prevents context saturation during Phase 0/1. Accepts newline-separated URLs or JSON Lines input.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_lines": {
                    "type": "string",
                    "description": "Raw recon output — one URL/endpoint per line, or JSON Lines",
                },
                "elevate_only": {
                    "type": "boolean",
                    "description": "If true, return only elevated (high-signal) URLs",
                },
            },
            "required": ["input_lines"],
        },
    },
    {
        "name": "payload_mutate",
        "description": "Deterministic seed-mutation engine for exploit evolution. Applies a named mutation strategy to a base payload seed. Strategies: url_encode_all, url_encode_all_double, tag_break, bypass_waf, base64_wrap, unicode_escape, html_entity, html_entity_full, json_escape, sql_comment_wrap, case_variation. Never guess payloads manually — use this engine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "seed": {
                    "type": "string",
                    "description": "Base payload to mutate",
                },
                "strategy": {
                    "type": "string",
                    "description": "Mutation strategy name (use 'all' for every strategy)",
                    "enum": list(STRATEGIES.keys()) + ["all"],
                },
            },
            "required": ["seed", "strategy"],
        },
    },
]


# ---------------------------------------------------------------------------
# MCP JSON-RPC 2.0 dispatcher
# ---------------------------------------------------------------------------

def _ok(request_id, result):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})


def _err(request_id, code: int, message: str):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def _dispatch(method: str, params: dict, request_id) -> str:
    """Route an MCP method call to the appropriate handler."""
    if method == "tools/list":
        return _ok(request_id, {"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        try:
            if tool_name == "oast_generate":
                result = action_generate(arguments.get("correlation_id", "unknown"))
                return _ok(request_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})

            elif tool_name == "oast_poll":
                result = action_poll()
                return _ok(request_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})

            elif tool_name == "oast_cleanup":
                ttl = arguments.get("ttl_hours", 48)
                result = action_cleanup(ttl_hours=ttl)
                return _ok(request_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})

            elif tool_name == "dom_analyze":
                result = analyze_divergence(
                    arguments["control"],
                    arguments["true_condition"],
                    arguments["false_condition"],
                    threshold=arguments.get("threshold", 0.15),
                )
                return _ok(request_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})

            elif tool_name == "saliency_filter":
                input_text = arguments["input_lines"]
                lines = input_text.splitlines()
                result = process_lines(lines)
                if arguments.get("elevate_only"):
                    result = [e["url"] for e in result["elevated"]]
                return _ok(request_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})

            elif tool_name == "payload_mutate":
                seed = arguments["seed"]
                strategy = arguments["strategy"]
                if strategy == "all":
                    mutations = {}
                    for s_name, s_fn in STRATEGIES.items():
                        mutations[s_name] = {"payload": s_fn(seed), "length": len(s_fn(seed))}
                    result = {"seed": seed, "seed_length": len(seed), "mutations": mutations}
                elif strategy in STRATEGIES:
                    output = STRATEGIES[strategy](seed)
                    result = {"seed": seed, "seed_length": len(seed), "mutations": {strategy: {"payload": output, "length": len(output)}}}
                else:
                    return _err(request_id, -32602, f"Unknown strategy: {strategy}. Available: {sorted(STRATEGIES.keys())}")
                return _ok(request_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})

            else:
                return _err(request_id, -32601, f"Unknown tool: {tool_name}")

        except KeyError as e:
            return _err(request_id, -32602, f"Missing required parameter: {e}")
        except Exception as e:
            return _err(request_id, -32603, f"Tool execution error: {e}")

    elif method == "initialize":
        return _ok(request_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "oc-v3.3-engines", "version": "3.3.0"},
        })

    elif method == "notifications/initialized":
        return None  # No response for notifications

    else:
        return _err(request_id, -32601, f"Unknown method: {method}")


# ---------------------------------------------------------------------------
# Main stdio loop
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the MCP JSON-RPC loop on stdin/stdout. Log diagnostics to stderr."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"[oc-v3.3-mcp] JSON parse error: {exc}", file=sys.stderr)
            continue

        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        response = _dispatch(method, params, req_id)
        if response is not None:
            print(response, flush=True)


if __name__ == "__main__":
    main()
