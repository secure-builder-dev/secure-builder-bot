#!/usr/bin/env bash
# check-gate-docs.sh — the gate's reference docs must not drift from the files the gate reads.
#
# WHY THIS EXISTS
#   Governance edits update CLAUDE.md and .claude/agents/*, which are reviewed line by line. The
#   engine/*.md reference docs beside them are not in that protocol, so they are updated by hand or
#   not at all. On 2026-09-19 a staleness sweep found both of them lagging GOV-007:
#
#     - engine/WORKFLOW.md still printed the pre-scan gate sequence
#     - engine/SENTINEL-CHECKLIST.md carried a verdict block six lines behind the agent's — no
#       Scan: line at all — while CLAUDE.md item 4 tells the security gate to end with the verdict
#       block FROM THAT FILE
#
#   The second one is not a documentation nit. The rulebook pointed the gate at a block that omitted
#   the scan the same rulebook requires, so a gate that followed the checklist would have reported a
#   verdict with no scan line and been correct to. Per CLAUDE.md item 7, a mechanical finding becomes
#   a mechanical check rather than a line of prose asking people to remember.
#
# EXIT  0 = the docs agree · 1 = drift, named

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 0

FAIL=0
fail() { echo "  DRIFT  $1"; FAIL=1; }

# verdict_block <file> — the fenced block containing "GATE VERDICT:", placeholders normalised.
# Normalising [n]/[count]/[PASS / FAIL] spacing keeps this from failing over a cosmetic edit; the
# point is that the FIELDS match, not the whitespace inside the brackets.
verdict_block() {
  awk '/^```/{inblock=!inblock; if(!inblock && hit){exit} if(inblock){buf=""; hit=0} next}
       inblock{buf=buf $0 "\n"; if($0 ~ /GATE VERDICT:/) hit=1}
       END{if(hit) printf "%s", buf}' "$1" \
  | sed -E 's/\[[^]]*\]/[_]/g; s/[[:space:]]+/ /g; s/^ //; s/ $//' | grep -v '^$'
}

A=".claude/agents/gate.md"
B="engine/SENTINEL-CHECKLIST.md"

if [ ! -f "$A" ] || [ ! -f "$B" ]; then
  echo "check-gate-docs: missing $A or $B"; exit 1
fi

a_block="$(verdict_block "$A")"
b_block="$(verdict_block "$B")"

if [ -z "$a_block" ]; then fail "$A has no fenced GATE VERDICT block"; fi
if [ -z "$b_block" ]; then fail "$B has no fenced GATE VERDICT block"; fi

if [ -n "$a_block" ] && [ -n "$b_block" ] && [ "$a_block" != "$b_block" ]; then
  fail "the verdict block in $B does not match $A"
  echo "         CLAUDE.md item 4 sends the gate to the checklist's block, so the checklist is what"
  echo "         a gate actually emits. Fields only in one side:"
  diff <(printf '%s\n' "$a_block") <(printf '%s\n' "$b_block") \
    | grep -E '^[<>]' | sed 's/^</         only in agent:     /; s/^>/         only in checklist: /'
fi

# Every `make <target>` the rulebook names in its GATE sequence must also appear in the workflow
# summary. This is what caught WORKFLOW.md printing a gate that no longer existed.
W="engine/WORKFLOW.md"
if [ -f CLAUDE.md ] && [ -f "$W" ]; then
  # Read CLAUDE.md AND anything it pulls in with an @ line. The GATE sequence does not have to live
  # in CLAUDE.md itself — under the rulebook split it moves to engine/RULEBOOK.md and CLAUDE.md
  # becomes a thin importer. Reading only CLAUDE.md would then find no GATE block, extract no
  # targets, and pass while checking nothing: a check that cannot fail, which is the defect class
  # this file exists to catch. One hop only, because one hop is all Claude Code resolves.
  rulebook_sources="CLAUDE.md"
  while IFS= read -r imp; do
    [ -n "$imp" ] && [ -f "$imp" ] && rulebook_sources="$rulebook_sources $imp"
  done <<< "$(grep -oE '^@[A-Za-z0-9_/.-]+' CLAUDE.md | sed 's/^@//')"

  # shellcheck disable=SC2086
  gate_targets="$(cat $rulebook_sources | sed -n '/^GATE/,/^CLOSE/p' | grep -oE 'make [a-z-]+' | sort -u)"

  if [ -z "$gate_targets" ]; then
    fail "no GATE sequence found in: $rulebook_sources — this check would pass without checking anything"
  fi

  while IFS= read -r t; do
    [ -n "$t" ] || continue
    grep -qF "$t" "$W" || fail "the GATE sequence names \`$t\`, $W never mentions it"
  done <<< "$gate_targets"
fi

if [ "$FAIL" -eq 0 ]; then
  echo "check-gate-docs: the gate's reference docs match the files the gate reads"
fi
exit "$FAIL"
