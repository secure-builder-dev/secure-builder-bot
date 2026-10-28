#!/usr/bin/env bash
# checkov-decide.sh — apply the justification list to checkov's results and decide.
#
# WHY THIS EXISTS
#   checkov's open-source build emits `severity: null` for every check unless a Prisma Cloud key is
#   configured. run-checkov.sh and generate-dispatch.sh selected `severity == "HIGH" or "CRITICAL"`,
#   so the count that decided the verdict could never be anything but 0: on 2026-09-23 main had 55
#   failed checks and the gate reported checkov PASS. A scanner that runs and cannot fail is not a
#   scanner. Policy now: EVERY failed check blocks unless it is justified.
#
#   A justification is an entry in docs/security/checkov-justifications.yaml — check_id, an optional
#   path glob, reason, owner, expires — the same shape as the npm-audit allowlist. Expired entries
#   justify nothing. Findings a template suppresses with checkov's own `checkov.io/skip` annotation
#   never reach this script; that is the right place for a per-resource false positive (the chart
#   uses it), and this file is for a real finding accepted for a bounded time.
#
#   Kept apart from run-checkov.sh so the policy is testable with a JSON fixture and no checkov.
#
# USAGE   checkov-decide.sh <checkov.json>            rewrites the file in place: unjustified
#                                                      findings stay in failed_checks, justified
#                                                      ones move to justified_checks
# ENV     CHECKOV_JUSTIFICATIONS   (default docs/security/checkov-justifications.yaml)
# EXIT    0 = nothing blocking · 1 = at least one unjustified failed check, or unreadable input
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"  # the repository scanned, as in the runners beside it
IN="${1:?usage: checkov-decide.sh <checkov.json>}"
JUST="${CHECKOV_JUSTIFICATIONS:-$PROJECT_ROOT/docs/security/checkov-justifications.yaml}"
TODAY="$(date -u +%Y-%m-%d)"

command -v jq >/dev/null 2>&1 || { echo "[checkov] FAIL — jq is required to decide."; exit 1; }
if ! jq -e '.results.failed_checks' "$IN" >/dev/null 2>&1; then
  echo "[checkov] FAIL — $IN has no .results.failed_checks; nothing to decide on. The scanner did not run."
  exit 1
fi

# Justification list → JSON. Line-based on purpose (no YAML parser in the toolchain); five scalar
# keys per entry. `expiry`, not `exp`: `exp` is awk's built-in and macOS awk rejects it as a name.
just_json='[]'
if [ -f "$JUST" ]; then
  just_json=$(awk '
    function clean(v) { sub(/^[^:]*:[[:space:]]*/, "", v); gsub(/["\047]/, "", v); sub(/[[:space:]]+#.*$/, "", v); sub(/[[:space:]]+$/, "", v); return v }
    function emit() { if (id != "") printf "%s\t%s\t%s\n", id, pth, expiry }
    /^[[:space:]]*-[[:space:]]*check_id:/ { emit(); id = clean($0); pth = ""; expiry = ""; next }
    /^[[:space:]]*path:/                  { pth = clean($0); next }
    /^[[:space:]]*expires:/               { expiry = clean($0); next }
    END { emit() }' "$JUST" \
    | jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {check_id: .[0], path: (.[1] // ""), expires: (.[2] // "")})')
fi

tmp=$(mktemp)
jq --argjson just "$just_json" --arg today "$TODAY" '
  # A date the script cannot read is not an expiry; lexical ordering only holds for real ISO dates.
  def iso: test("^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$");
  ($just | map(select((.expires | iso) and .expires >= $today))) as $live
  | def glob_re($g): "^" + ($g | gsub("\\."; "\\.") | gsub("\\*"; ".*")) + "$";   # dot literal, star wildcard
    def covered_by($e): .check_id == $e.check_id and ($e.path == "" or ((.file_path // "") | test(glob_re($e.path))));
    def justified: . as $c | any($live[]; . as $e | $c | covered_by($e));
    .results.justified_checks      = [ .results.failed_checks[] | select(justified) ]
  | .results.failed_checks         = [ .results.failed_checks[] | select(justified | not) ]
  | .results.expired_justifications = ($just | map(select(((.expires | iso) | not) or .expires < $today)))
  | .summary.failed    = (.results.failed_checks | length)
  | .summary.justified = (.results.justified_checks | length)' "$IN" > "$tmp" 2>"$tmp.err"
if ! jq -e '.results.failed_checks' "$tmp" >/dev/null 2>&1; then
  echo "[checkov] FAIL — could not apply the justification list to $IN: $(head -3 "$tmp.err")"; rm -f "$tmp" "$tmp.err"; exit 1
fi
rm -f "$tmp.err"
mv "$tmp" "$IN"

B=$(jq '.results.failed_checks | length' "$IN")
J=$(jq '.results.justified_checks | length' "$IN")
E=$(jq '.results.expired_justifications | length' "$IN")
echo "[checkov] Decision: $B blocking (failed, not justified) · $J justified · severities are unrated (checkov emits none without a Prisma key), so every failed check counts"
[ "$E" -gt 0 ] && echo "[checkov] $E justification entr$([ "$E" -eq 1 ] && echo y || echo ies) expired, or carrying no date this script can read — no longer justif$([ "$E" -eq 1 ] && echo ies || echo y) anything: $(jq -r '[.results.expired_justifications[].check_id] | join(", ")' "$IN")"
jq -r '.results.failed_checks[]    | "  BLOCKING  \(.check_id)  \(.file_path // "?")  \(.resource // "")  \(.check_name // .check_description // "")"' "$IN"
jq -r '.results.justified_checks[] | "  justified \(.check_id)  \(.file_path // "?")  (justification entry, unexpired)"' "$IN"

if [ "$B" -gt 0 ]; then
  echo "[checkov] FAIL — $B unjustified failed check$([ "$B" -eq 1 ] || echo s). Fix the resource, suppress a per-resource false positive with a checkov.io/skip annotation carrying the reason, or add a bounded entry to $JUST."
  exit 1
fi
echo "[checkov] PASS — no unjustified failed checks"
exit 0
