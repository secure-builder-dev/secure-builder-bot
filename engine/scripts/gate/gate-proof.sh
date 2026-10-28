#!/usr/bin/env bash
# gate-proof.sh — replay the proof set: ranges where the gate caught a real bug must still be caught.
#
# WHY THIS EXISTS
#   Every change that makes the gate cheaper is also a chance to make it blind. The proof set
#   (docs/security/PROOF-SET.md) is the project's record of bugs a gate actually found. Before any
#   change to the gate lands, the mechanical half of each row is replayed here:
#     range   → core/run classify must say deep, or the review that found the bug would be skipped
#     derived → qa/scripts/derive-controls.sh must list the fix's guard as registered to its CM row (rows with
#               `—` in that column are exempt and say why)
#     CM      → qa/scripts/mutate-controls.sh --only <every CM in the set> must prove every row red
#   The judgement half — the cold review reporting the bug on the pre-fix range — cannot be a
#   fixture. It is witnessed once per change to the gate, in that gate run's gate-log row.
#
# USAGE   gate-proof.sh [--no-mutate]
#           --no-mutate   skip the mutation half (seconds instead of minutes; `make check` runs this)
# EXIT    0 every row replays · 1 a row did not · 0 with a note when the project has no proof set

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
QA="$(cd "$HERE/../../../qa/scripts" && pwd)"
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1
SET="docs/security/PROOF-SET.md"
MUTATE=1; [ "${1:-}" = "--no-mutate" ] && MUTATE=0

if [ ! -f "$SET" ]; then
  echo "gate-proof: no $SET — nothing to replay. Add a row the first time a gate catches a real bug."
  exit 0
fi

DERIVED="$(bash "$QA/derive-controls.sh" --list 2>/dev/null || true)"
fail=0; n=0; cms=""
while IFS= read -r line; do
  case "$line" in "| T-"*|"| "[A-Z]*-[0-9]*" |"*) : ;; *) continue ;; esac
  bug=$(  printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$2); print $2}')
  range=$(printf '%s' "$line" | awk -F'|' '{gsub(/[` ]/,"",$4); print $4}')
  guard=$(printf '%s' "$line" | awk -F'|' '{gsub(/[` ]/,"",$6); print $6}')
  der=$(  printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$7); print $7}')
  cm=$(   printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$8); print $8}')
  case "$range" in *..*) : ;; *) continue ;; esac
  n=$((n + 1)); cms="${cms:+$cms,}$cm"
  depth="$("$HERE/../../../core/run" classify "$range" 2>&1 | head -1)"
  if [ "$depth" = "deep" ]; then r1="deep"; else r1="✗ $depth"; fail=1; fi
  if [ "$der" = "yes" ]; then
    file="${guard%%:*}"; sym="${guard##*:}"
    if printf '%s\n' "$DERIVED" | grep -E "registered ${cm} " | grep -F "${file}:" | grep -E "[[:space:]]${sym}[[:space:]]" >/dev/null; then r2="listed"
    else r2="✗ not listed as registered ${cm}"; fail=1; fi
  else r2="exempt"; fi
  printf '  %-12s %-20s range %-8s derived %-10s %s\n' "$bug" "$range" "$r1" "$r2" "$cm"
done < "$SET"

[ "$n" -gt 0 ] || { echo "gate-proof: $SET has no rows"; exit 1; }

if [ "$MUTATE" -eq 1 ]; then
  echo "  mutation: make mutate-controls ARGS=\"--only $cms\""
  if bash "$QA/mutate-controls.sh" --only "$cms" > "${TMPDIR:-/tmp}/gate-proof-mutate.log" 2>&1; then
    echo "  mutation: every proof-set row red"
  else
    echo "  ✗ mutation: a proof-set row is not proven —"; grep -E 'NOT PROVEN|MANUAL|RED|GREEN' "${TMPDIR:-/tmp}/gate-proof-mutate.log" | sed 's/^/    /' | tail -12; fail=1
  fi
else
  echo "  mutation: skipped (--no-mutate); the gate runs it"
fi

if [ "$fail" -ne 0 ]; then
  echo "gate-proof: FAIL — the gate as it stands would miss a bug it has caught before"; exit 1
fi
echo "gate-proof: $n of $n proof-set rows replay"
exit 0
