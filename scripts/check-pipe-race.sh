#!/usr/bin/env bash
# check-pipe-race.sh — no tracked shell script that sets pipefail pipes into `grep -q`.
#
# `grep -q` exits at its first match. Whatever is still writing into the pipe then dies of
# SIGPIPE, and under pipefail the pipeline returns 141: a match reads as no match. Bash
# line-buffers its builtin printf, so `printf '%s' "$multi_line" | grep -q pattern` loses the race
# whenever the match is not on the last line. The push guard did: a multi-line command that
# pushed to main was let through in 17 of 30 runs.
#
# Write `grep -q pattern <<<"$var"` for a variable, or let grep drain the pipe with
# `producer | grep pattern >/dev/null`. Either keeps grep's exit status and has no race.
#
# USAGE   scripts/check-pipe-race.sh
# EXIT    0 none found · 1 one or more, each printed as file:line
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
found=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  grep -q 'pipefail' "$f" || continue
  while IFS= read -r hit; do
    printf '  %s:%s\n' "$f" "$hit"; found=$((found + 1))
  done < <(grep -nE '\|[[:space:]]*grep[[:space:]]+-[A-Za-z]*q' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | cut -d: -f1-2)
done < <(git ls-files '*.sh' '*.bash')
if [ "$found" -gt 0 ]; then
  echo "check-pipe-race: $found pipe(s) into grep -q under pipefail; a match can read as no match."
  echo "                 Use grep -q … <<<\"\$var\", or … | grep … >/dev/null."
  exit 1
fi
echo "check-pipe-race: no pipe into grep -q under pipefail"
