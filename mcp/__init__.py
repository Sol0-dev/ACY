#!/usr/bin/env python3
"""
oc v3.3 — MCP Automation Engine Package
=========================================
Provides thread-safe, deterministic automation tools for the oc security
research agent. Each module is independently invokable both as a CLI script
and as an importable Python library.

Modules:
  oast_manager    — OAST blind vulnerability callback polling
  dom_analyzer    — Structural DOM differential analyzer
  saliency_filter — Recon output saliency pre-processor
  payload_mutator — Deterministic seed-mutation engine

All modules resolve paths relative to the repository root (~/agents/finetune/)
regardless of the current working directory.
"""

import os

# Repository root is two levels up from this file: mcp/__init__.py → ~/agents/finetune/
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def repo_path(*segments: str) -> str:
    """Resolve a path relative to the oc repository root."""
    return os.path.join(REPO_ROOT, *segments)


__all__ = ["REPO_ROOT", "repo_path"]
