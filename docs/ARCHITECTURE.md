# Architecture Deep Dive

## Tri-Layer Architecture

### Layer 3: LLM Wiki
- Markdown-based knowledge base with YAML frontmatter
- Bi-directional links between pages ([[wiki-links]])
- Auto-skill evolution triggers when knowledge exceeds skill coverage
- Compounds intelligence across sessions

### Layer 2: Reasoning Core
- Attack chain synthesis and threat modeling
- Skill gap analysis -- proposes new skills from wiki data
- Logic flaw detection and business flow analysis
- Long-context ingestion of JS intelligence + recon data

### Layer 1: Tool Execution
- MCP tools: Burp Suite, Firefox DevTools, Kali
- Custom scripts and curl-based automation
- Structured output generation (YAML, JSON)
- SKILL-TOOLS.md guides tool selection for every task

## Auto-Skill Evolution Flow
1. Wiki documents new technique during hunting
2. Gap analysis compares wiki pages vs skill_registry.json
3. Agent proposes new SKILL-*.md with full playbook (Discovery/Hunt/Reproduce)
4. User reviews and validates (approve/modify/reject)
5. Phase table in CLAUDE.md updated with new phase number
6. New skill activated for next session
