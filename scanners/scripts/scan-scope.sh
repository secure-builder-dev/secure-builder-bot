#!/usr/bin/env bash
# scan-scope.sh — where the scanners look: the whole checkout, with one prune list for all of them.
#
# WHY THIS EXISTS
#   Every runner used to look in backend/ and frontend/ and nowhere else, which is the layout of
#   the one project the engine grew up on. A bot that gates any repository cannot know where a
#   Dockerfile, a chart, a package.json or a requirements.txt lives, so every runner now asks this
#   one helper and gets the same answer: every matching file anywhere under the checkout, except
#   under a directory nobody ships (node_modules, .git, dist, build, vendor, a virtualenv), except
#   the bot's own canned scan results (scanners/fixtures, test data, not dependencies), and except
#   what git ignores (a reference copy on one clone is not part of what ships — finding F-25). The
#   Python side of the gate (securebuilderbot_scanners.scope) applies the same list, so what the
#   runners examined and what the gate expects to have been examined are the same set.
#
# USAGE   . "$SCRIPT_DIR/scan-scope.sh"
#           scan_targets <root> <find tests…>       → matching files, repo-relative, sorted
#           scan_target_dirs <root> <find tests…>   → the directories holding them, unique, sorted
#           scan_scope_pruned                       → the prune list, for a message
#         e.g. scan_targets "$ROOT" -name Dockerfile -o -name 'Dockerfile.*'
SCAN_SCOPE_PRUNE_NAMES=(node_modules .git dist build vendor .venv venv)
SCAN_SCOPE_PRUNE_PATHS=(scanners/fixtures)
scan_scope_pruned() { printf '%s' "node_modules, .git, dist, build, vendor, virtualenvs, scanners/fixtures and anything git ignores"; }

scan_targets() {
  local root="$1" n p f; shift
  local -a prune=()
  for n in "${SCAN_SCOPE_PRUNE_NAMES[@]}"; do prune+=( -o -name "$n" ); done
  for p in "${SCAN_SCOPE_PRUNE_PATHS[@]}"; do prune+=( -o -path "./$p" ); done
  prune=( "${prune[@]:1}" )   # drop the leading -o
  ( cd "$root" && find . \( "${prune[@]}" \) -prune -o -type f \( "$@" \) -print 2>/dev/null ) \
    | sed 's#^\./##' | LC_ALL=C sort | while IFS= read -r f; do
        git -C "$root" check-ignore -q "$f" 2>/dev/null && continue
        printf '%s\n' "$f"
      done
}

scan_target_dirs() {
  scan_targets "$@" | while IFS= read -r f; do dirname "$f"; done | LC_ALL=C sort -u
}
