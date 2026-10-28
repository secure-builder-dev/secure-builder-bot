#!/usr/bin/env bash
# verify-controls.sh — does every declared security control still reach production code?
#
# WHY THIS EXISTS
#   A gate can confirm a control is implemented and tested. It cannot, from a diff, confirm the
#   control is still WIRED — that running code calls it, and that the infrastructure artifact it
#   depends on still exists. Both fail silently and stay failed, because a diff-scoped gate never
#   looks outside the story in flight.
#
#   The manifest declares WHAT SHOULD BE TRUE. This script computes what IS true and compares.
#   Call sites are NEVER read from the manifest — they are recomputed from the tree every run, so
#   the manifest cannot go stale in the one direction that matters.
#
# MANIFEST
#   docs/security/CONTROL-MANIFEST.md — project-owned. Seeded once by `make sync-engine`
#   (SEED_IF_ABSENT); never overwritten after that.
#
# USAGE   qa/scripts/verify-controls.sh [--quiet]
# EXIT    0 = every populated row resolves (or no manifest yet)
#         1 = at least one row FAILs
#         2 = manifest exists but holds only template placeholders — nothing was verified

set -uo pipefail
GATE_LIB="$(cd "$(dirname "$0")" && pwd)/_lib.sh"
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1
# shellcheck source=/dev/null
. "$GATE_LIB"

MANIFEST="${CONTROL_MANIFEST:-docs/security/CONTROL-MANIFEST.md}"   # the QA gate points this at the list it pinned
QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1
say() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }

if [ ! -f "$MANIFEST" ]; then
  say "CONTROL MANIFEST: none at $MANIFEST"
  say "  It is seeded by make sync-engine; if missing, copy docs/security/CONTROL-MANIFEST.md from the engine repo."
  say "  Until then this check is inert — it cannot tell a project with no controls from one"
  say "  whose controls were never declared."
  exit 0
fi

USED_IDX="$(mktemp)"; trap 'rm -f "$USED_IDX"' EXIT
gate_use_control_roots   # project.config.yaml CONTROL_* keys, when the controls are not in the track's roots
gate_build_use_index "$USED_IDX"

count_call_sites() {   # $1 = symbol, $2 = defining file, $3 = definition line -> call sites anywhere but the definition line
  awk -F'\t' -v s="$1" -v f="$2" -v d="$3" '$1==s && !($2==f && $3==d) {n++} END{print n+0}' "$USED_IDX"
}
def_line() {           # $1 = symbol, $2 = file -> line number of the definition (first match)
  grep -nE "(function|const|let|var|val|fun|class|object|def)[[:space:]]+$1\b" "$2" 2>/dev/null | head -1 | cut -d: -f1
}

FAILED=0; ROWS=0; PLACEHOLDERS=0
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
say "CONTROL MANIFEST VERIFY                        (track: ${APP_TRACK})"
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

while IFS= read -r line; do
  case "$line" in "| CM-"*) : ;; *) continue ;; esac

  id=$(      printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$2); print $2}')
  name=$(    printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$3); print $3}')
  impl=$(    printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$4); gsub(/`/,"",$4); print $4}')
  artifact=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$5); gsub(/`/,"",$5); print $5}')
  test_g=$(  printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$6); gsub(/`/,"",$6); print $6}')

  # Skip the template's illustrative example rows — and count them, so a manifest that is
  # nothing but placeholders reports "unpopulated" rather than a green "0 FAIL".
  case "$impl" in ""|"-"|"—"|"<"*) PLACEHOLDERS=$((PLACEHOLDERS + 1)); continue ;; esac
  ROWS=$((ROWS + 1))

  file="${impl%%:*}"; sym="${impl##*:}"
  problems=""

  if [ ! -f "$file" ]; then
    problems="${problems}impl file missing; "
  elif ! grep -qE "(function|const|val|fun|class|object|def)[[:space:]]+${sym}\b" "$file" 2>/dev/null; then
    problems="${problems}symbol '${sym}' not defined in ${file}; "
  fi

  sites=0
  [ -f "$file" ] && sites=$(count_call_sites "$sym" "$file" "$(def_line "$sym" "$file")")
  [ "$sites" -eq 0 ] && problems="${problems}NO production call site; "

  case "$artifact" in ""|"-"|"—") : ;; *) [ -e "$artifact" ] || problems="${problems}artifact missing: ${artifact}; " ;; esac

  case "$test_g" in
    ""|"-"|"—") : ;;
    *) [ -z "$(gate_test_files "$test_g")" ] && problems="${problems}proving test missing: ${test_g}; " ;;
  esac

  if [ -n "$problems" ]; then
    FAILED=$((FAILED + 1))
    say "  FAIL  ${id}  ${name}"
    say "        ${problems%; }"
  else
    say "  ok    ${id}  ${name}  (${sites} call site$( [ "$sites" -eq 1 ] || echo s ))"
  fi
done < "$MANIFEST"

say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$ROWS" -eq 0 ]; then
  say "  UNPOPULATED — ${PLACEHOLDERS} template placeholder row(s), 0 controls declared."
  say "  Nothing was verified. Replace the <path>:<symbol> rows with your project's controls."
  say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 2
fi
say "  ${ROWS} controls · ${FAILED} FAIL$( [ "$PLACEHOLDERS" -eq 0 ] || echo " · ${PLACEHOLDERS} placeholder row(s) ignored" )"
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
