# wiki/ — LLM Wiki Knowledge Base

Markdown knowledge base that compounds across sessions.

```
wiki/
├── index.md               ← table of contents + search index (vuln→skill→phase map)
├── log.md                 ← append-only record of all operations
├── techniques/            ← technique notes (one per pattern)
│   └── {technique}.md     ← e.g. websocket-security.md, command-obfuscation.md
└── targets/               ← per-target Maps of Content (MOCs)
    └── {target-slug}.md
```

Every note uses YAML frontmatter: `id, date, type, status, confidence, tags, links`.

See `templates/target-moc.md` for the target MOC template.