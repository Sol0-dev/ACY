#!/usr/bin/env bash
# oc v3.3 — Unified Engine Runner
# ================================
# Single entry point for all v3.3 automation engines. Resolves the repository
# root automatically so calls work from any working directory.
#
# Usage:
#   ./mcp/runner.sh oast generate --correlation-id "sqli_blind_1"
#   ./mcp/runner.sh dom --control resp_baseline.html --true resp_inject.html --false resp_inert.html
#   ./mcp/runner.sh saliency --stdin < recon_output.txt
#   ./mcp/runner.sh mutate --seed "<script>alert(1)</script>" --strategy bypass_waf
#
# The runner auto-resolves the oc root directory based on its own location,
# making it safe to invoke from any CWD.

set -euo pipefail

# Resolve the repository root (2 levels up from this script: mcp/runner.sh → ~/agents/finetune/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Map engine name → Python module
declare -A ENGINES=(
    ["oast"]="${SCRIPT_DIR}/oast_manager.py"
    ["dom"]="${SCRIPT_DIR}/dom_analyzer.py"
    ["saliency"]="${SCRIPT_DIR}/saliency_filter.py"
    ["mutate"]="${SCRIPT_DIR}/payload_mutator.py"
)

usage() {
    cat << 'EOF'
oc v3.3 Engine Runner — unified CLI for all automation engines

USAGE:
  ./mcp/runner.sh <engine> [engine-args...]

ENGINES:
  oast      OAST blind vulnerability callback manager
  dom       Structural DOM differential analyzer
  saliency  Recon output saliency filter
  mutate    Seed-mutation engine for exploit evolution

EXAMPLES:
  ./mcp/runner.sh oast generate --correlation-id "sqli_blind_endpoint_1"
  ./mcp/runner.sh oast poll
  ./mcp/runner.sh dom --stdin
  ./mcp/runner.sh saliency --input fullrecon/target/subs.txt --elevate-only
  ./mcp/runner.sh mutate --seed "<script>alert(1)</script>" --strategy url_encode_all
  ./mcp/runner.sh mutate --list-strategies

Use --help after the engine name for engine-specific options.
EOF
    exit 0
}

main() {
    if [[ $# -eq 0 ]]; then
        usage
    fi

    local engine="$1"
    shift

    case "$engine" in
        oast)      exec python3 "${ENGINES[oast]}" "$@" ;;
        dom)       exec python3 "${ENGINES[dom]}" "$@" ;;
        saliency)  exec python3 "${ENGINES[saliency]}" "$@" ;;
        mutate)    exec python3 "${ENGINES[mutate]}" "$@" ;;
        -h|--help|help) usage ;;
        *)
            echo "[ERROR] Unknown engine: $engine"
            echo "Valid engines: oast, dom, saliency, mutate"
            exit 1
            ;;
    esac
}

main "$@"
