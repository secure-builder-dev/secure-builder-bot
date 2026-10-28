#!/usr/bin/env bash
# scan-receipt.sh — a scanner's own statement about what it examined.
#
# WHY THIS EXISTS
#   gate-line.sh decided "did this scanner run" by inspecting the file the scanner left behind:
#   present, non-empty, and (since T-029) parseable. That file is a byproduct, not a claim. Four of
#   the seven runners write a perfectly valid, EMPTY result when they find nothing to examine —
#   hadolint with no Dockerfiles (and it exits 0), checkov with a missing target directory, grype
#   and trivy with no image present — so "examined everything and found nothing" and "examined
#   nothing" produce identical files. A scan of nothing therefore read as
#   `Scan: PASS — 7/7 scanners ran · 0 fixable`, with real carried findings vanishing from the
#   verdict line along with the scan. Finding SEC-SC2-1; it survived two rounds of narrower fixes
#   (T-024 closed the pollution source, T-029 the unparseable file) because both asked what the file
#   looked like rather than what the scanner actually did.
#
#   A receipt inverts the direction. The runner asserts what happened; the verdict reads the
#   assertion. There are exactly two honest assertions:
#
#     scan_ran <name> <detail>    I examined something. Count me.
#     scan_none <name> <why>      I had nothing in scope, deliberately. Count me, and say so.
#
#   A runner that crashes, exits early, or finds nothing where it expected something makes NEITHER
#   assertion, and the verdict refuses to count it. That is the property the old file inspection
#   could not express, and it is why `scan_ran` is the LAST act of a successful run rather than
#   something set up front.
#
#   `scan_none` exists so this does not break project shapes where a scanner legitimately has no
#   work: an Android project has no Dockerfiles and no images, and its gate must not fail forever
#   because hadolint had nothing to lint. The distinction is the runner's to make, because only the
#   runner knows whether an empty scope is normal for it — grype treats "no images" as a failure and
#   asserts nothing, hadolint treats "no Dockerfiles" as a legitimate empty scope and says so. A
#   `none` receipt is named in the verdict line, so an empty scope is visible rather than silent.
#
# USAGE   . "$SCRIPT_DIR/scan-receipt.sh"        # after RESULTS_DIR is set
#           scan_begin <name>                    # first thing: drop any previous receipt
#           scan_ran   <name> <detail>           # last thing, success path only
#           scan_none  <name> <why>              # nothing in scope, and that is correct here
#           scan_receipt_kind <name>             # read side: prints "ran", "none", or nothing
#
# FILE    $RESULTS_DIR/scanners-ran — one line per scanner: "<name> <kind> <detail>".
#         Readers use scan_receipt_kind; the detail is for a human reading the results directory.
#
# ENV     SCAN_RECEIPT_DIR overrides where the file lives (the scan verdict reads it; it names its
#         results directory $R, not $RESULTS_DIR).

_scan_receipt_file() {
  printf '%s/scanners-ran' "${SCAN_RECEIPT_DIR:-${RESULTS_DIR:-${SCAN_RESULTS_DIR:-.}}}"
}

# Drop this scanner's previous receipt, leaving every other scanner's alone. Called at the start of
# a run so a crash cannot leave last run's receipt behind to be counted — the stale-file half of
# the same finding.
scan_begin() {
  local name="$1" f; f="$(_scan_receipt_file)"
  [ -f "$f" ] || return 0
  # grep exits 1 when it filters everything out, which is a valid outcome here, not an error.
  grep -v "^${name} " "$f" > "$f.tmp" 2>/dev/null || : > "$f.tmp"
  mv -f "$f.tmp" "$f" 2>/dev/null || true
  return 0
}

_scan_record() {
  local name="$1" kind="$2" detail="${3:-}" f; f="$(_scan_receipt_file)"
  mkdir -p "$(dirname "$f")" 2>/dev/null || true
  scan_begin "$name"
  printf '%s %s %s\n' "$name" "$kind" "$detail" >> "$f"
}

scan_ran()  { _scan_record "$1" ran  "${2:-}"; }
scan_none() { _scan_record "$1" none "${2:-}"; }

# Prints "ran", "none", or nothing at all. Never fails, so a caller under `set -e` is safe.
scan_receipt_kind() {
  local name="$1" f; f="$(_scan_receipt_file)"
  [ -f "$f" ] || return 0
  awk -v n="$name" '$1 == n { print $2; exit }' "$f" 2>/dev/null || true
  return 0
}
