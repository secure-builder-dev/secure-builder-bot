#!/usr/bin/env bash
# check-boundaries.sh — the allowed edges between script groups, and nothing else.
#
# .boundaries lists one allowed edge per line as "<from-dir> -> <to-dir>". A script under a
# group that references a path in another group not listed as an allowed edge is a violation.
# Today's edges were recorded from the code as it stands; a new edge is a design decision, so
# it is added to .boundaries in its own commit with a reason, never silently.
# EXIT 0 clean · 1 an edge not in .boundaries · 2 no .boundaries file
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 2
[ -f .boundaries ] || { echo "check-boundaries: no .boundaries file"; exit 2; }
script_groups=(scanners engine/scripts/gate engine/scripts/docs scripts core standards qa sentinel)
allowed() { grep -qE "^$1 -> $2\b" .boundaries; }
fail=0
for from in "${script_groups[@]}"; do
  for to in "${script_groups[@]}"; do
    [ "$from" = "$to" ] && continue
    allowed "$from" "$to" && continue
    # A reference is the group's path in code, comments excluded. The path must stand on its own
    # (not a longer path's tail: scripts/ inside engine/scripts/ is not the bot's scripts/), or be
    # reached by a relative hop (../gate/).
    seg=$(basename "$to")
    hits=$(grep -rnE --include='*.sh' --include='*.py' --include='*.mjs' "(^|[^/A-Za-z0-9_.-])$to/|\.\./$seg/" "$from" 2>/dev/null | grep -vE '^[^:]+:[0-9]+:\s*#' || true)
    if [ -n "$hits" ]; then
      echo "BOUNDARY  $from -> $to is not an allowed edge:"; printf '%s\n' "$hits" | head -5 | sed 's/^/    /'; fail=1
    fi
  done
done
[ "$fail" -eq 0 ] && echo "check-boundaries: every cross-group reference is an allowed edge"
exit "$fail"
