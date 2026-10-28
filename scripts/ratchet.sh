#!/usr/bin/env bash
# ratchet.sh — the "Measured, not yet enforced" numbers in CONSTRAINTS.md may not get worse.
#
# Each row is "| <metric> | <today> | must not grow|fall |". This recomputes every metric it
# knows, compares against the recorded value, and fails on the wrong-direction move. A better
# number is reported so CONSTRAINTS.md can be updated (--record rewrites the table in place).
# USAGE   scripts/ratchet.sh [--record]
# EXIT    0 held or improved · 1 a metric got worse · 2 could not measure
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 2
export PATH="$PATH:$HOME/.local/bin"
RECORD=0; [ "${1:-}" = "--record" ] && RECORD=1
F=CONSTRAINTS.md; [ -f "$F" ] || { echo "ratchet: no $F"; exit 2; }
for t in shellcheck ruff; do command -v "$t" >/dev/null 2>&1 || { echo "ratchet: $t is not installed"; exit 2; }; done

measure() {  # prints "<metric>=<value>" for every metric this script knows
  local -a sh_files
  mapfile -t sh_files < <(git ls-files '*.sh')
  local sc; sc=$(shellcheck -f gcc "${sh_files[@]}" 2>/dev/null || true)
  echo "shellcheck findings, all levels=$(printf '%s\n' "$sc" | grep -cE ':[0-9]+:[0-9]+: ' || true)"
  echo "shellcheck findings, error or warning=$(printf '%s\n' "$sc" | grep -cE ': (error|warning): ' || true)"
  local -a py_dirs=() d
  for d in engine scripts core scanners standards qa; do [ -d "$d" ] && py_dirs+=("$d"); done   # a missing dir is not a finding
  echo "ruff findings=$( [ "${#py_dirs[@]}" -gt 0 ] && ruff check --output-format concise "${py_dirs[@]}" 2>/dev/null | grep -cE '^[^ ]+:[0-9]+:' || echo 0)"
  local untested=0 f
  while IFS= read -r f; do
    grep -rqF "$(basename "$f")" engine/scripts/tests engine/scripts/gate/selftest.sh engine/scripts/gate/selftest-phase1.sh scanners/tests scripts standards/tests qa/tests 2>/dev/null || untested=$((untested + 1))
  done < <(git ls-files 'scanners/*.sh' 'scanners/scripts/*.sh' 'engine/scripts/gate/*.sh' 'engine/scripts/*.sh' 'scripts/*.sh' 'standards/scripts/*.sh' 'qa/scripts/*.sh' | grep -v -E '/tests?/|selftest|_lib')
  echo "shell scripts without a named test=$untested"
}

fail=0; now=$(measure); updates=()
while IFS= read -r line; do
  case "$line" in '| '*' | '*' | must not '*) : ;; *) continue ;; esac
  metric=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$2); print $2}')
  recorded=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$3); print $3}')
  dir=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$4); print $4}')
  val=$(printf '%s\n' "$now" | awk -F= -v m="$metric" '$1==m{print $2}')
  [ -n "$val" ] || { printf '  %-42s recorded %-6s (not measured by this script)\n' "$metric" "$recorded"; continue; }
  worse=0
  case "$dir" in
    "must not grow") [ "$val" -gt "$recorded" ] && worse=1 ;;
    "must not fall") [ "$val" -lt "$recorded" ] && worse=1 ;;
  esac
  if [ "$worse" -eq 1 ]; then printf '  %-42s recorded %-6s now %-6s WORSE\n' "$metric" "$recorded" "$val"; fail=1
  elif [ "$val" != "$recorded" ]; then printf '  %-42s recorded %-6s now %-6s better\n' "$metric" "$recorded" "$val"
    updates+=("s#^| $metric | $recorded | $dir |#| $metric | $val | $dir |#")
  else printf '  %-42s %-6s held\n' "$metric" "$val"; fi
done < <(cat "$F")
# Writes happen after the read is finished, never in the same pipeline as the read.
if [ "$RECORD" -eq 1 ] && [ "${#updates[@]}" -gt 0 ]; then
  for u in "${updates[@]}"; do sed -i "$u" "$F"; done
  echo "ratchet: recorded ${#updates[@]} improved number(s) in $F"
fi
[ "$fail" -eq 0 ] && echo "ratchet: nothing got worse" || echo "ratchet: a measured number got worse — fix it, or record the reason in CONSTRAINTS.md Exceptions" >&2
exit "$fail"
