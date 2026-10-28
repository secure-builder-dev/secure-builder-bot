# Workflow

This repository builds the bot with Addy Osmani's agent-skills (`.claude/skills/`, `.claude/commands/`)
and gates every change with the scan and gate scripts under `engine/`.

```
DEFINE   /spec, /plan                 write the spec, cut it into tasks
BUILD    /build, /test                one task at a time, red then green, commit per task
CHECK    make check                   before every push — code checks block, doc checks report
GATE     make gate-scan               seven scanners, receipts, one verdict line
         make gate-prompt             the handoff, derived from git; refuses until the scan is green on this commit
         make gate                    Sentinel on the range in a clean context: tests prove the code, then security
         make scan-verdict            the scan line the gate records
REVIEW   /review                      the five-axis review before the PR
CLOSE    a human merges               no agent merges
```

Findings from a gate become checks: mechanical → a target in `make check`; judgment → a line in
`engine/SENTINEL-CHECKLIST.md`. Governance files (`CLAUDE.md`, `.claude/agents/gate.md`, the
checklist, the standards indexes) change in their own commit, read by a human before merge.
