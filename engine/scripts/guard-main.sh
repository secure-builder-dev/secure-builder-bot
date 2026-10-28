#!/usr/bin/env bash
# guard-main.sh — Claude Code PreToolUse hook: an agent session never merges or pushes to main.
# Blocks exactly three things: `git push` targeting main, `git merge` while on main, `gh pr merge`.
# Everything else passes. Install snippet: engine/GOVERNANCE.md. EXIT 0 allow · 2 block

set -uo pipefail
input="$(cat)"
cmd="$(printf '%s' "$input" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("tool_input",{}).get("command",""))
except Exception: print("")' 2>/dev/null)"
[ -n "$cmd" ] || exit 0
block() { echo "guard-main: blocked — $1. A human merges via the PR; agents never push to main." >&2; exit 2; }
# A backslash-newline continues the line in a shell, so join those before matching; every match then
# sees each command whole. git and gh may be named by path and git may carry options before its
# subcommand (-C dir, -c key=val, --no-pager), so the patterns allow both.
cmd="$(sed -e ':a' -e '/\\$/{N;s/\\\n//;ba' -e '}' <<<"$cmd")"
START='(^|[;&|(`[:space:]])([^;&|[:space:]]*/)?'
GIT="${START}git([[:space:]]+-[^[:space:]]+([[:space:]]+[^-;&|[:space:]][^;&|[:space:]]*)?)*[[:space:]]+"
if grep -qE "${GIT}push\b" <<<"$cmd"; then
  # --all and --mirror send every branch, main included.
  grep -qE "${GIT}push[^;&|]*(\bmain\b|HEAD:main|:main\b|--all\b|--mirror\b)" <<<"$cmd" && block "git push to main"
  cur="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  [ "$cur" = "main" ] && ! grep -qE 'push[^;&|]*[[:space:]][A-Za-z0-9_./-]+[[:space:]]+[A-Za-z0-9_./:-]+' <<<"$cmd" && block "git push from main"
fi
if grep -qE "${GIT}merge\b" <<<"$cmd"; then
  [ "$(git rev-parse --abbrev-ref HEAD 2>/dev/null)" = "main" ] && block "git merge on main"
fi
grep -qE "${START}gh[[:space:]]+pr[[:space:]]+merge\b" <<<"$cmd" && block "gh pr merge"
exit 0
