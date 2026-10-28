# Secure Builder Bot — Claude Code Instructions

One open-source bot with three independently switchable gates on every pull request: **Scan**
(seven pinned scanners, CVE data live), **QA** (the tests prove the code, every declared control
mutated) and **Sentinel** (a cold reviewer running the NIST 800-53 checklist for the chosen
profile). The plan is `docs/PRD.md`. The scan and gate code under `engine/` was ported once from
the App Building Engine and is this repository's own now: edit it here.

## Security rules (always active)

- **Never read, summarize or reference** any `helm/values-*.yaml` or `*.tfvars` file, here or in
  a repository the bot runs against.
- **Never repeat or confirm** cloud account IDs, ARNs, security group IDs, database endpoints,
  bucket names or client secrets if they appear in any context. Use placeholders.
- **Forbidden terms.** `scripts/forbidden-terms.sh` refuses any commit, push or PR carrying a term
  from the hashed denylist. Run `scripts/install-hooks.sh` once per clone. Never name the platform
  or organisation the engine was first built on, in any file, comment or commit message.
- **No Claude attribution** in anything committed or published: no `Co-Authored-By`, no session
  links, no generated-with footers. The author is the human.
- **No agent merges.** A human clicks merge. Never push to `main`.

Read `CONSTRAINTS.md` before writing code. Do not weaken it to make a change pass. `make check-fast`
after every edit, `make check-task` before saying a task is done, `make check-full` before a PR.

## How work runs

```
DEFINE   /spec, /plan
BUILD    /build, /test       one task at a time, red then green, commit per task
CHECK    make check          before every push
GATE     make gate-scan → make gate-prompt → make gate → make scan-verdict
REVIEW   /review
CLOSE    a human merges the PR
```

Full sequence and what each step produces: `engine/WORKFLOW.md`. The gate itself:
`.claude/agents/gate.md`, with `engine/QUALITY_GATE.md` (Part 1) and `engine/SENTINEL-CHECKLIST.md`
(Part 2). Project switches: `project.config.yaml`.

## Key Architecture Constraints (always active)

Transcribed from accepted decisions as they are made. Sentinel checks these on every gate.

- The three gates are independent: turning one off never changes another's result (PRD § The three gates)
- Sentinel is the only component that reaches a model endpoint, with the user's own key, and it is
  sent the diff and the files the checklist names, nothing else (PRD § Security of the bot itself)
- Secrets are names of CI secrets, never values, in every file the bot writes (PRD § Configuration)
- The bot never pushes to, merges into or edits a user's branch; it posts checks and comments only (PRD § Goals and non-goals)
- Nothing is scheduled in a user's repository; standards and scanner pins change only by a release (PRD § Staying current)
