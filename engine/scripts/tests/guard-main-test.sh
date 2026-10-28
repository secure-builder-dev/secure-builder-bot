#!/usr/bin/env bash
# guard-main-test.sh — the push guard blocks its three moves, every time, however long the command.
#
# The guard read the command through `printf '%s' "$cmd" | grep -q` under pipefail. grep exits at
# its first match, the still-writing printf dies of SIGPIPE, and the pipeline reads as no match:
# a push to main followed by a long heredoc commit message was allowed in 17 of 30 runs. Each
# blocking case below runs 20 times; one allow among them is a failure.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
GUARD="${GUARD:-$ROOT/engine/scripts/guard-main.sh}"   # GUARD= overrides, to prove the test red on an old guard
PASS=0; FAIL=0
_pass() { echo "  ok    $1"; PASS=$((PASS + 1)); }
_fail() { echo "  FAIL  $1 — $2"; FAIL=$((FAIL + 1)); }
echo "── guard-main: an agent session never pushes to or merges on main ──"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
( cd "$T" && git init -q -b main . && git config user.email t@t && git config user.name t \
  && git commit -q --allow-empty -m base && git checkout -q -b feature ) >/dev/null 2>&1

hook_input() {   # <command> → the PreToolUse JSON the hook reads on stdin
  python3 -c 'import json,sys; print(json.dumps({"tool_input": {"command": sys.argv[1]}}))' "$1"
}
tail_lines="$(for i in $(seq 1 3000); do printf 'line %s of a long heredoc commit message\n' "$i"; done)"

blocks() {   # <name> <command> [branch] — exit 2 on every one of 20 runs
  local name="$1" cmd="$2" branch="${3:-feature}" rc allowed=0
  ( cd "$T" && git checkout -q "$branch" ) >/dev/null 2>&1
  hook_input "$cmd" > "$T/in.json"
  for _ in $(seq 1 20); do
    ( cd "$T" && bash "$GUARD" < "$T/in.json" ) >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] || allowed=$((allowed + 1))
  done
  if [ "$allowed" -eq 0 ]; then _pass "$name"; else _fail "$name" "allowed in $allowed of 20 runs"; fi
}
allows() {   # <name> <command> [branch]
  local name="$1" cmd="$2" branch="${3:-feature}" rc
  ( cd "$T" && git checkout -q "$branch" ) >/dev/null 2>&1
  hook_input "$cmd" > "$T/in.json"
  ( cd "$T" && bash "$GUARD" < "$T/in.json" ) >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 0 ]; then _pass "$name"; else _fail "$name" "exit $rc"; fi
}

blocks "git push to main is blocked" "git push origin main"
blocks "git push to main followed by a long multi-line message is blocked, every run" "git push origin main
$tail_lines"
blocks "gh pr merge after a long multi-line preamble is blocked, every run" "echo start
$tail_lines
gh pr merge 12"
blocks "git merge on main is blocked" "git merge feature" main
blocks "a bare git push from main is blocked" "git push" main
# Bypasses the core and standards gates found (core run 4 N-05, standards run 3 N-02): a push split
# by a line continuation, git with options before the subcommand, git by path, and the pushes that
# send every branch.
blocks "a push to main split by a line continuation is blocked" "git push origin \\
main"
blocks "gh pr merge split by a line continuation is blocked" "gh pr \\
merge 12"
blocks "git -C . push to main is blocked" "git -C . push origin main"
blocks "git with -c options before push to main is blocked" "git -c core.x=y push origin HEAD:main"
blocks "git by an absolute path pushing to main is blocked" "/usr/bin/git push origin main"
blocks "git push --all is blocked (it sends main)" "git push --all origin"
blocks "git push --mirror is blocked (it sends main)" "git push --mirror origin"
blocks "gh by an absolute path merging a PR is blocked" "/usr/local/bin/gh pr merge 12"
allows "a push of a branch whose name merely contains main is allowed" "git push origin feature-mainline"
allows "git -C elsewhere pushing a feature branch is allowed" "git -C . push -u origin feature"
allows "git push of a feature branch is allowed" "git push -u origin feature"
allows "git merge on a feature branch is allowed" "git merge main"
allows "a long command that pushes nothing is allowed" "echo hello
$tail_lines"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
