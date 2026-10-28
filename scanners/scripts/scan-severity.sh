#!/usr/bin/env bash
# scan-severity.sh — decide whether a scan run should fail the build.
#
# WHY THIS EXISTS
#   `make scan` / `scan-lite` fail when generate-dispatch writes a dispatch file, which tracks
#   "is there something an agent could auto-remediate" — NOT "is this dangerous." A project with
#   hundreds of low findings and one critical can therefore exit 0. That is the wrong signal for
#   a scheduled compliance scan. Finding F-14.
#
#   This reads the SAME result files and fails only on HIGH/CRITICAL, so a nightly that goes red
#   means something that actually matters. A nightly that is always red gets ignored within a week.
#
#   Severity expressions are the ones already used by generate-dispatch.sh — one definition.
#
# USAGE   scanners/scripts/scan-severity.sh [--quiet]
# EXIT    0 = no high/critical · 1 = at least one, or nothing was scanned (a missing scan is not a pass — T-024)

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 0
R="${SCAN_RESULTS_DIR:-gate-records/scan/latest}"
QUIET=0; [ "${1:-}" = "--quiet" ] && QUIET=1
say() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }

[ -d "$R" ] && [ -n "$(ls -A "$R" 2>/dev/null)" ] || { say "scan-severity: no results at $R — nothing was scanned; that is not a pass. Run make scan first"; exit 1; }
command -v jq >/dev/null 2>&1 || { say "scan-severity: jq not installed — cannot evaluate; not a pass"; exit 1; }

TOTAL=0
count() { grep -qE '^[0-9]+$' <<<"${1:-0}" && echo "${1:-0}" || echo 0; }

# hadolint — an "error"-level Dockerfile finding
HAD=0
[ -f "$R/hadolint.json" ] && HAD=$(count "$(jq '[.[] | select(.level == "error")] | length' "$R/hadolint.json" 2>/dev/null)")

# checkov — IaC misconfig at HIGH or CRITICAL
CHK=0
[ -f "$R/checkov.json" ] && CHK=$(count "$(jq '[.results.failed_checks[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' "$R/checkov.json" 2>/dev/null)")

# clamav — any infection is critical, full stop
CLAM=0
[ -f "$R/clamav.log" ] && CLAM=$(count "$(grep -oE 'Infected files: [0-9]+' "$R/clamav.log" 2>/dev/null | grep -oE '[0-9]+' | head -1)")

# grype — image CVEs at Critical/High (only present when image scans ran)
GRY=0
[ -f "$R/grype.json" ] && GRY=$(count "$(jq '[.matches[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")] | length' "$R/grype.json" 2>/dev/null)")

TOTAL=$((HAD + CHK + CLAM + GRY))

say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
say "SCAN SEVERITY GATE                       (high/critical only)"
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
say "  hadolint  error-level Dockerfile findings : ${HAD}"
say "  checkov   HIGH/CRITICAL IaC misconfig     : ${CHK}"
say "  clamav    infected files                  : ${CLAM}"
say "  grype     Critical/High image CVEs        : ${GRY}$([ -f "$R/grype.json" ] || echo '   (no image scan in this run)')"
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$TOTAL" -gt 0 ]; then
  say "  FAIL — ${TOTAL} high/critical finding(s). Details: ${R}/"
  say "  Triage per engine/agent-cve-poam-guidelines.md. Lower severities are reported, not gated."
  exit 1
fi
say "  PASS — no high or critical findings."
exit 0
