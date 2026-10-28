# Governance — changing the rulebook, protecting main

## Changing the rulebook

**What counts.** `CLAUDE.md`, `.claude/agents/`, `.claude/skills/`, and anything under `engine/` that
decides what the gate checks. Sentinel reads its checklist from these files, so an edit that weakens
a control is reviewed by the weakened control. The AI gate cannot be the backstop for a change to its
own rules; the human reading the diff is.

**Rule 1 — its own commit, and the human reads the diff.** A rulebook change lands in a commit that
changes nothing else, so the diff a human reads is the whole of it. The human reads the actual `+` and
`-` lines before merging — not the gate's verdict about them. That review is the accountable control.

**Rule 2 — the always-on section has a budget.** `CLAUDE.md` § Key Architecture Constraints is loaded
into every session, so its length is a control, not a style preference: the one sentence that binds
should not sit in a paragraph of history. `make check-constraints-budget` fails above the ceiling, so
an addition has to retire something. A bullet states the rule and the ADR that grounds it; the story of
how it came to hold belongs in the ADR.

That is all of it. Until 2026-10-03 this file carried a seven-rule protocol — fill-in zones,
scribe-not-legislator, a declared edit surface, evaluation against the pre-edit rules, append-only
data, a changelog row per edit, and pruning routes. Thirty-one tickets in the project that wrote them
existed only to enforce those rules, and none of them could have reached a user (T-SLIM-05).
The changelog that recorded them was deleted with them; git history keeps it.

---


## Protecting `main` — the merge button is the approval

A human clicking merge on a pull request is the approval. Two things stop an agent doing it instead:
the push guard below, which every agent session should install, and — where the hosting plan offers it
— branch protection. `make protect-main` applies GitHub branch protection to `main` with `gh api`
(pull request required, CI required, direct pushes blocked, stale approvals dismissed). GitHub does not
offer branch protection on a private repository under the Free plan, and nothing in this engine
depends on it: the gate, the push guard and the human merge are the controls.

## Push guard for agent sessions (belt-and-suspenders)

`engine/scripts/guard-main.sh` is a Claude Code `PreToolUse` hook that refuses three commands from
an agent session: `git push` to `main`, `git merge` while on `main`, and `gh pr merge`. Nothing else
is blocked. Install it by adding to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [ { "type": "command", "command": "bash engine/scripts/guard-main.sh" } ] }
    ]
  }
}
```

The hook reads the tool input on stdin and exits 2 with a one-line reason to block. Test it with
`echo '{"tool_input":{"command":"git push origin main"}}' | bash engine/scripts/guard-main.sh; echo $?` → `2`.
