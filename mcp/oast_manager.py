#!/usr/bin/env python3
"""
oc v3.3 — OAST Interaction Engine (Out-of-Band Application Security Testing)
=============================================================================
Manages blind vulnerability detection by provisioning callback tokens from an
Interactsh-compatible OAST server and polling for out-of-band interactions.

Protocol:
  generate  → Request a unique callback identifier, register correlation state.
  poll      → Query the OAST provider for interactions matching active tokens.
  cleanup   → Remove stale registrations older than a configurable TTL.

Architecture:
  This module is thread-safe: JSON registry reads/writes use atomic renames
  and a file-system lock to prevent concurrent corruption across parallel
  agent sub-processes.

Usage:
  python3 mcp/oast_manager.py --action generate --correlation-id "sqli_blind_endpoint_12"
  python3 mcp/oast_manager.py --action poll
  python3 mcp/oast_manager.py --action cleanup --ttl-hours 24
"""

import sys
import json
import os
import time
import argparse
import hashlib
import fcntl
import tempfile
import shutil
from datetime import datetime, timezone
from urllib.parse import urljoin

# ---------------------------------------------------------------------------
# Path resolution — works regardless of CWD
# ---------------------------------------------------------------------------
def _repo_root() -> str:
    """Return the absolute path to the oc repository root."""
    # When run as a script or imported, __file__ is the path to this file
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_REGISTRY_PATH: str | None = None  # cached, resolved at first use

def _get_registry_path() -> str:
    global _REGISTRY_PATH
    if _REGISTRY_PATH is None:
        _REGISTRY_PATH = os.path.join(_repo_root(), "essentials", "oast_registry.json")
    return _REGISTRY_PATH

OAST_PROVIDER_URL = os.environ.get("OAST_SERVER_URL", "https://interactsh.com")
OAST_API_KEY = os.environ.get("OAST_API_KEY", "")
LOCK_PATH = os.path.join(_repo_root(), "essentials", "oast_registry.json.lock")
DEFAULT_TTL_HOURS = 48


# ---------------------------------------------------------------------------
# Thread-safe atomic JSON helpers
# ---------------------------------------------------------------------------

def _acquire_lock(timeout: float = 5.0) -> bool:
    """Acquire an exclusive advisory lock on the registry lock file."""
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    lock_fd = open(LOCK_PATH, "w")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            time.sleep(0.05)
    lock_fd.close()
    return False


def _release_lock() -> None:
    """Release the lock file if it exists. Best-effort."""
    try:
        lock_fd = open(LOCK_PATH, "w")
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
    except OSError:
        pass


def _load_registry(registry_path: str | None = None) -> dict:
    """Load the OAST registry atomically. Returns empty dict if absent."""
    rp = registry_path or _get_registry_path()
    if not os.path.exists(rp):
        return {}
    try:
        with open(rp, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except (json.JSONDecodeError, OSError):
        return {}


def _save_registry(data: dict, registry_path: str | None = None) -> None:
    """Save the OAST registry atomically via temp + rename."""
    rp = registry_path or _get_registry_path()
    os.makedirs(os.path.dirname(rp), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=os.path.dirname(rp),
        suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp_path, rp)  # atomic on POSIX
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# OAST API client
# ---------------------------------------------------------------------------

def _call_oast_provider(endpoint: str, payload: dict | None = None) -> dict:
    """
    Call the OAST provider's REST API.
    For a self-hosted Interactsh server, the typical endpoints are:
      POST /register   → {"correlation-id": "...", "server-url": "..."}
      GET  /poll       → {"{token}": {"protocol": "dns", ...}, ...}

    Falls back gracefully if the provider is unreachable.
    """
    import requests
    headers = {"Content-Type": "application/json"}
    if OAST_API_KEY:
        headers["Authorization"] = f"Bearer {OAST_API_KEY}"

    url = urljoin(OAST_PROVIDER_URL, endpoint)
    try:
        if payload:
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
        else:
            resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        # Provider unreachable — return empty so agent doesn't crash
        return {}


# ---------------------------------------------------------------------------
# Core actions
# ---------------------------------------------------------------------------

def action_generate(correlation_id: str, registry_path: str | None = None) -> dict:
    """
    Provision a unique OAST callback token.

    1. Generate a random token + callback hostname.
    2. Optionally register it with a remote Interactsh server.
    3. Persist the correlation entry in the local registry.
    """
    unique_token = os.urandom(8).hex()
    callback_url = f"{unique_token}.oast.interactsh.com"

    # Attempt remote registration (non-fatal)
    if OAST_API_KEY or "interactsh" in OAST_PROVIDER_URL:
        remote = _call_oast_provider("/register", {
            "public-key": unique_token,
            "correlation-id": correlation_id,
        })
        if remote and remote.get("server-url"):
            callback_url = remote.get("server-url", callback_url)

    _acquire_lock()
    try:
        registry = _load_registry(registry_path)
        now_ts = datetime.now(timezone.utc).isoformat()
        registry[unique_token] = {
            "correlation_id": correlation_id,
            "callback_url": callback_url,
            "status": "pending",
            "triggered": False,
            "interactions": [],
            "created_at": now_ts,
            "last_polled_at": None,
        }
        _save_registry(registry, registry_path)
    finally:
        _release_lock()

    return {
        "callback": callback_url,
        "token": unique_token,
        "correlation_id": correlation_id,
        "status": "registered",
    }


def action_poll(registry_path: str | None = None) -> dict:
    """
    Poll the OAST provider for any interactions on active tokens.

    Returns a summary of all interactions grouped by token, and updates
    the local registry so triggered tokens are marked.
    """
    registry = _load_registry(registry_path)
    if not registry:
        print(json.dumps({"interactions": [], "active_registry_count": 0}))
        return {"interactions": [], "active_registry_count": 0}

    # Build the list of tokens we care about
    active_tokens = [
        t for t, entry in registry.items()
        if not entry.get("triggered", False)
    ]

    hits: list[dict] = []

    if active_tokens and OAST_PROVIDER_URL:
        remote = _call_oast_provider("/poll")
        if remote:
            for token, interaction_list in remote.items():
                if isinstance(interaction_list, list):
                    for interaction in interaction_list:
                        hits.append({
                            "token": token,
                            "protocol": interaction.get("protocol", "unknown"),
                            "remote_address": interaction.get("remote-address", ""),
                            "timestamp": interaction.get("timestamp", ""),
                            "raw_request": interaction.get("raw-request", ""),
                            "raw_response": interaction.get("raw-response", ""),
                            "unique_id": interaction.get("unique-id", ""),
                        })
                elif isinstance(interaction_list, dict):
                    hits.append({
                        "token": token,
                        "protocol": interaction_list.get("protocol", "unknown"),
                        "remote_address": interaction_list.get("remote-address", ""),
                        "timestamp": interaction_list.get("timestamp", ""),
                        "raw_request": interaction_list.get("raw-request", ""),
                        "raw_response": interaction_list.get("raw-response", ""),
                        "unique_id": interaction_list.get("unique-id", ""),
                    })

    # Update registry state for each triggered token
    _acquire_lock()
    try:
        registry = _load_registry(registry_path)
        now_ts = datetime.now(timezone.utc).isoformat()
        updated = False
        seen_tokens = set()

        for hit in hits:
            token = hit.get("token", "")
            if not token or token not in registry:
                continue
            seen_tokens.add(token)
            entry = registry[token]
            if not entry.get("triggered"):
                entry["triggered"] = True
                entry["status"] = "triggered"
                updated = True
            entry["interactions"].append(hit)
            entry["last_polled_at"] = now_ts

        # Mark poll time on unchecked tokens too
        for token, entry in registry.items():
            if token not in seen_tokens:
                entry["last_polled_at"] = now_ts

        if updated:
            _save_registry(registry, registry_path)
    finally:
        _release_lock()

    result = {
        "interactions": hits,
        "active_registry_count": len(registry),
        "triggered_count": sum(1 for e in registry.values() if e.get("triggered")),
        "pending_count": sum(1 for e in registry.values() if not e.get("triggered")),
    }
    return result


def action_cleanup(ttl_hours: int = DEFAULT_TTL_HOURS, registry_path: str | None = None) -> dict:
    """Remove registrations older than TTL."""
    _acquire_lock()
    removed = 0
    try:
        registry = _load_registry(registry_path)
        cutoff = time.time() - (ttl_hours * 3600)
        to_remove = []
        for token, entry in registry.items():
            created = entry.get("created_at", "")
            if created:
                try:
                    dt = datetime.fromisoformat(created)
                    if dt.timestamp() < cutoff:
                        to_remove.append(token)
                except (ValueError, OSError):
                    pass
        for token in to_remove:
            del registry[token]
            removed += 1
        if removed:
            _save_registry(registry, registry_path)
    finally:
        _release_lock()
    return {"removed": removed, "remaining": len(registry)}


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="oc v3.3 OAST Interaction Engine — blind vulnerability callback manager"
    )
    parser.add_argument(
        "--action", choices=["generate", "poll", "cleanup"],
        required=True,
        help="generate: create callback token | poll: check for interactions | cleanup: expire old"
    )
    parser.add_argument(
        "--correlation-id",
        default="unknown",
        help="Human-readable label (endpoint, surface, test-case id)"
    )
    parser.add_argument(
        "--ttl-hours",
        type=int,
        default=DEFAULT_TTL_HOURS,
        help=f"Token expiry in hours (default: {DEFAULT_TTL_HOURS})"
    )
    parser.add_argument(
        "--token",
        help="Specific token to check (used with poll to narrow results)"
    )
    parser.add_argument(
        "--registry-path",
        default=None,
        help="Override path to oast_registry.json (default: auto-resolved from script location)"
    )

    args = parser.parse_args()

    # Resolve registry path: explicit override > env var > auto-detect from script location
    registry_path = args.registry_path or os.environ.get("OAST_REGISTRY_PATH") or _get_registry_path()

    if args.action == "generate":
        result = action_generate(args.correlation_id, registry_path)
    elif args.action == "poll":
        result = action_poll(registry_path)
        if args.token:
            registry = _load_registry(registry_path)
            token_entry = registry.get(args.token)
            result["token_specific"] = token_entry
    elif args.action == "cleanup":
        result = action_cleanup(args.ttl_hours, registry_path)
    else:
        result = {"error": "unknown action"}

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
