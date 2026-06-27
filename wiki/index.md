# acy-1.0 Wiki Index
# LLM Knowledge Base for Agentic Security Research

## How to Use This Wiki

This wiki is the persistent, compounding knowledge base for the acy-1.0 agent.
Every finding, technique, target, and session is documented here.

## Page Types

| Type | Purpose | Example |
|------|---------|---------|
| target | Per-target intelligence | [[target/api_target_com]] |
| technique | Per-vulnerability-class knowledge | [[technique/sqli]] |
| session | Per-session log | [[session/2026-06-25-session-001]] |
| chain | Attack chain documentation | [[chain/subdomain-to-ato]] |
| moc | Map of Content | [[moc/injection-vulns]] |

## YAML Frontmatter (required)

```yaml
---
id: {uuid}
date: {ISO8601}
type: {target|technique|session|chain|moc}
status: {draft|active|completed|archived}
confidence: {1-5}
tags: [tag1, tag2]
links:
  - [[wiki/page-name]]
---
```

## Registered Targets

| Target | Status | Findings |
|--------|--------|----------|
| [Add targets here] | | |

## Technique Pages

| Technique | Status | Findings |
|-----------|--------|----------|
| [[technique/sqli]] | | |
| [[technique/xss]] | | |
| [[technique/ssrf]] | | |
| [[technique/idor]] | | |
| [[technique/jwt]] | | |

## Auto-Skill Evolution Tracking

| Date | Technique | Proposed Skill | Status |
|------|-----------|----------------|--------|
| [Log skill proposals here] | | | |
