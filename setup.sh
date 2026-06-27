#!/bin/bash
# acy-1.0 Setup Script
# One-command setup for the Agentic Cyber Yield system

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "  acy-1.0 Setup"
echo "  Agentic Cyber Yield"
echo "=========================================="

# Create runtime directories
echo "[+] Creating runtime directories..."
mkdir -p fullrecon notes scripts essentials findings raw wiki techniques

# Create per-target example structure (user will customize)
mkdir -p fullrecon/example_com
mkdir -p notes/example_com
mkdir -p scripts/example_com
mkdir -p findings/example_com/{critical,high,medium,low}

# Create state files
echo "[+] Creating state files..."

cat > essentials/TARGET.env << 'EOF'
# acy-1.0 Target Configuration
# Replace with your actual target before hunting

TARGET="https://example.com"
SLUG="example_com"

# Auth tokens (fill these in after logging in)
USER1_TOKEN=""
USER2_TOKEN=""
CSRF_TOKEN=""

# Cookie string (if session-based auth)
COOKIE=""

# Root domain for subdomain recon
ROOT_DOMAIN="example.com"

# Program type: bug_bounty | pentest | vdp
PROGRAM_TYPE="bug_bounty"
EOF

cat > essentials/STATE_example_com.md << 'EOF'
# Session State: example_com
# Started: $(date -Iseconds)
# Status: initialized

## Current Phase
Phase 0: Reconnaissance + JS Intelligence (not started)

## Surfaces Tested
0

## Findings Confirmed
0

## Next Action
Set real TARGET in TARGET.env, then run recon
EOF

cat > essentials/LOOP_STATE_example_com.md << 'EOF'
# Loop State: example_com
# Position: Phase 0

## Surface Queue
[empty - pending recon]

## CHAIN_QUEUE
[empty]

## Completed Surfaces
[empty]

## Next_Action
Run recon pipeline after TARGET is set
EOF

cat > essentials/skill_registry.json << 'EOF'
{
  "skills": [
    {"name": "SKILL-RECON.md", "phases": [0, 36, 37, 39, 43], "status": "active", "last_updated": "2026-06-25"},
    {"name": "SKILL-INTEL.md", "phases": [0, 1], "status": "active", "last_updated": "2026-06-25"},
    {"name": "SKILL-INJECTION.md", "phases": [3, 4, 7, 8, 9, 10, 18, 19, 22, 23, 24, 31, 32, 38, 40, 41], "status": "active", "last_updated": "2026-06-25"},
    {"name": "SKILL-AUTH.md", "phases": [11, 12, 13, 14, 15, 34], "status": "active", "last_updated": "2026-06-25"},
    {"name": "SKILL-CLIENTSIDE.md", "phases": [5, 6, 17, 20, 21, 25, 29, 30, 33], "status": "active", "last_updated": "2026-06-25"},
    {"name": "SKILL-LOGIC.md", "phases": [26, 27, 28, 35], "status": "active", "last_updated": "2026-06-25"},
    {"name": "SKILL-CHAIN.md", "phases": [42], "status": "active", "last_updated": "2026-06-25"},
    {"name": "SKILL-REPORT.md", "phases": [44], "status": "active", "last_updated": "2026-06-25"},
    {"name": "SKILL-TOOLS.md", "phases": ["all"], "status": "active", "last_updated": "2026-06-25"}
  ],
  "next_phase": 46,
  "version": "1.0"
}
EOF

cat > essentials/skill_evolution_log.md << 'EOF'
# Skill Evolution Log
# Append-only record of skill creation and updates

| Date | Action | Skill | Phase | Trigger | Approved By |
|------|--------|-------|-------|---------|---------------|
| 2026-06-25 | Initial | All base skills | 0-45 | System initialization | system |

EOF

cat > essentials/MEMORY.md << 'EOF'
# Global Memory
# Persistent memory across all sessions

## Known Patterns
[Add patterns here as they are discovered]

## Tool Failures
[Log tool failures and workarounds]

## Target-Specific Notes
[Cross-target intelligence]
EOF

cat > essentials/KNOWLEDGE_BASE.md << 'EOF'
# Knowledge Base
# Global pattern library

## Vulnerability Patterns
[Add confirmed patterns here]

## False Positive Patterns
[Add false positive signatures here]

## Chain Patterns
[Add successful chain patterns here]
EOF

cat > essentials/LEADERBOARD.json << 'EOF'
{
  "findings": [],
  "total_critical": 0,
  "total_high": 0,
  "total_medium": 0,
  "total_low": 0,
  "total_payout": 0,
  "last_updated": "2026-06-25T00:00:00Z"
}
EOF

touch essentials/findings_log.jsonl
touch essentials/poc_registry.jsonl
touch essentials/session_log.jsonl

echo "[+] Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit essentials/TARGET.env with your target"
echo "  2. Set auth tokens after logging in"
echo "  3. Run: cd $(pwd) && claude"
echo "  4. Say: 'let's hunt'"
echo ""
echo "For DeepSeek integration, add to ~/.bashrc:"
echo '  export ANTHROPIC_AUTH_TOKEN="sk-yourapikey"'
echo '  export ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic"'
echo '  export ANTHROPIC_MODEL="deepseek-v4-pro"'
echo '  export CLAUDE_CODE_EFFORT_LEVEL="max"'
