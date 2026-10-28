#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The checkout the other runners scan: the Scan gate sets PROJECT_ROOT to it. Until gate run 1 (B-4)
# this line ignored the environment, so ClamAV scanned the bot's own install and never the checkout.
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
RESULTS_DIR="${SCAN_RESULTS_DIR:-$PROJECT_ROOT/gate-records/scan/latest}"

# shellcheck source=tool-runner.sh
. "$SCRIPT_DIR/tool-runner.sh"
# shellcheck source=scan-receipt.sh
. "$SCRIPT_DIR/scan-receipt.sh"

# FIRST, before any check that can exit: drop this run's receipt. A runner that bails out early —
# tool missing, Docker down, jq absent — must not leave the PREVIOUS run's receipt behind, or the
# verdict counts a scanner that did not run this time and reads last run's result file as current.
# Found while closing SEC-SC2-1: 0 exit path(s) in this script precede the checks below.
scan_begin clamav

# SCAN_DIR_OVERRIDE allows the test suite to point clamscan at a specific directory
# (e.g., a temp dir with an EICAR test file) without scanning the whole repo.
SCAN_TARGET="${SCAN_DIR_OVERRIDE:-$PROJECT_ROOT}"

if ! have_tool clamscan; then
  tool_missing clamav clamscan
  exit 1
fi

# ── Signature freshness ──────────────────────────────────────────────────────
# Scanning with stale signatures is worse than not scanning: it returns a clean result that is not
# clean, which is the same failure shape as the stale-image problem image-age-guard.sh covers.
#
# This guard used to be unsatisfiable, for two reasons that compounded.
#
#   ClamAV bakes its signature database into the image at build time, and clamav/clamav rebuilds
#   roughly weekly — on 2026-09-19 every published tag was last built on the 14th. So a freshly
#   pulled image already carried signatures five days old, and two days later every scan in the
#   repo would have tripped a 7-day threshold through no fault of anyone's.
#
#   Its remedy could not clear it either. `docker pull` fetches the newest image; when that image
#   IS the stale one, pulling changes nothing, and the guard fell through to "bump the tag in
#   tool-versions.env" — advice nobody can act on, because the tag is already the newest moving tag
#   published. A gate that fails with an instruction that cannot be followed is a gate people learn
#   to skip.
#
# freshclam is the remedy that actually reaches current signatures, independently of when the image
# was built. That is why the threshold stays at 7 days instead of being relaxed to whatever cadence
# the image publisher happens to manage: the control is unchanged, it is now reachable. The refresh
# runs only when the database is genuinely over the line, so the ordinary case costs nothing.
CLAMAV_MAX_AGE_DAYS="${CLAMAV_MAX_AGE_DAYS:-7}"

mkdir -p "$RESULTS_DIR"

# Two functions rather than one, because the caller needs the raw version string for diagnostics and
# a function that both computes the age and exports the string cannot do the second half: the age is
# read through $( ), which is a subshell, so any variable it set would be discarded.
clamav_version_line() {
  tool_clamscan "$SCAN_TARGET" --version 2>&1 | head -1 || true
}

# "ClamAV 1.4.3/27712/Wed Sep 17 09:23:11 2026" — the third field is the signature build date.
clamav_age_from() {
  local v epoch now
  v=$(printf '%s' "${1:-}" | awk -F'/' '{print $3}')
  [ -n "$v" ] || return 1
  epoch=$(date -d "$v" +%s 2>/dev/null || date -j -f "%a %b %d %T %Y" "$v" +%s 2>/dev/null || echo 0)
  [ "$epoch" != 0 ] || return 1
  now=$(date +%s)
  echo $(( (now - epoch) / 86400 ))
}

VERSION_LINE=$(clamav_version_line)
AGE_DAYS=$(clamav_age_from "$VERSION_LINE" || echo "")
SIG_STATE=ok

if [ -z "$AGE_DAYS" ] || [ "$AGE_DAYS" -gt "$CLAMAV_MAX_AGE_DAYS" ]; then
  if [ -n "$AGE_DAYS" ]; then
    echo "[clamav] Signatures are $AGE_DAYS days old (max $CLAMAV_MAX_AGE_DAYS) — refreshing..."
  else
    echo "[clamav] Could not read a signature date — refreshing before deciding anything..."
  fi

  FRESHCLAM_EXIT=0
  tool_freshclam > "$RESULTS_DIR/freshclam.log" 2>&1 || FRESHCLAM_EXIT=$?

  if [ "$FRESHCLAM_EXIT" -eq 0 ]; then
    VERSION_LINE=$(clamav_version_line)
    AGE_DAYS=$(clamav_age_from "$VERSION_LINE" || echo "")
    [ -n "$AGE_DAYS" ] && echo "[clamav] Signatures refreshed — now $AGE_DAYS day(s) old."
  else
    # Print it, do not merely point at it. The same reasoning as the scan-error path below: on a CI
    # runner this log dies with the workspace, so a pointer leaves the next person an exit code.
    echo "[clamav] FRESHCLAM FAILED (exit $FRESHCLAM_EXIT) — last 15 lines:"
    tail -n 15 "$RESULTS_DIR/freshclam.log" 2>/dev/null | sed 's/^/[clamav]   /'
  fi
fi

if [ -z "$AGE_DAYS" ]; then
  # This path used to print "could not determine signature age; proceeding" and scan anyway, under a
  # comment saying it had never been seen in practice. It was seen on 2026-09-19: the configured
  # image tag did not exist, every clamscan invocation failed, and the unparseable version string
  # sent the scan straight down this branch. Proceeding means a run that cannot detect anything is
  # free to print "no infections found", which is the exact false-clean this file guards against.
  if [ "${CLAMAV_ALLOW_UNVERIFIED_SIGNATURES:-0}" = 1 ]; then
    echo "[clamav] WARNING — signature age UNVERIFIED, proceeding on CLAMAV_ALLOW_UNVERIFIED_SIGNATURES=1."
    echo "[clamav]   The scan will run, but its result is not a clean bill of health."
    SIG_STATE=unverified
  else
    echo "[clamav] UNVERIFIED SIGNATURES — no signature date, and a refresh did not produce one."
    echo "[clamav]   clamscan --version said: ${VERSION_LINE:-(no output)}"
    echo "[clamav]   Refusing to report a scan as clean when the signature age is unknown."
    echo "[clamav]   If you accept that risk: CLAMAV_ALLOW_UNVERIFIED_SIGNATURES=1"
    exit 1
  fi
elif [ "$AGE_DAYS" -gt "$CLAMAV_MAX_AGE_DAYS" ]; then
  echo "[clamav] STALE SIGNATURES — $AGE_DAYS days old (max $CLAMAV_MAX_AGE_DAYS) after a refresh."
  if [ "$(scan_engine)" = container ]; then
    echo "[clamav]   freshclam could not reach the signature mirrors, or they are behind."
    echo "[clamav]   Check outbound access to database.clamav.net, then re-run."
    echo "[clamav]   Details: $RESULTS_DIR/freshclam.log"
  else
    echo "[clamav]   Run: freshclam   (it may need sudo to write /var/lib/clamav)"
  fi
  exit 1
else
  echo "[clamav] Signature database: $AGE_DAYS day(s) old"
fi

echo "[clamav] Scanning $SCAN_TARGET via $(scan_engine_for clamav) engine..."
tool_clamscan "$SCAN_TARGET" \
  --recursive \
  --infected \
  --exclude-dir='^.*/(\.git|node_modules|gate-records/scan)(/|$)' \
  > "$RESULTS_DIR/clamav.log" 2>&1 || CLAMAV_EXIT=$?

CLAMAV_EXIT="${CLAMAV_EXIT:-0}"
# ClamAV's summary line is its proof of completion. Without this guard a truncated or half-written
# log read as "Infected files: 0" via the `|| echo 0` below — a scan that died mid-run reporting
# clean, the same shape as SEC-SC-2. The log is kept for a human under a name nothing else reads.
if ! grep -q 'Infected files:' "$RESULTS_DIR/clamav.log"; then
  echo "[clamav] FAIL — clamav.log has no 'Infected files:' summary, so the scan did not complete."
  echo "[clamav]   log begins: $(head -c 160 "$RESULTS_DIR/clamav.log" | tr '\n' ' ')"
  mv -f "$RESULTS_DIR/clamav.log" "$RESULTS_DIR/clamav.log.incomplete" 2>/dev/null \
    && echo "[clamav]   moved aside to clamav.log.incomplete — the results directory now shows clamav as not run"
  exit 2
fi

INFECTED=$(grep -oE 'Infected files: [0-9]+' "$RESULTS_DIR/clamav.log" | grep -oE '[0-9]+' || echo "0")
SCANNED_FILES="$(grep -oE 'Scanned files: [0-9]+' "$RESULTS_DIR/clamav.log" | head -1 || echo 'files unknown')"

if [[ "$INFECTED" -gt 0 ]]; then
  # It ran, whatever it found: the receipt is written before the verdict on the findings, so a
  # scanner that found something is never reported as one that did not run (gate run 1, B-1).
  scan_ran clamav "$SCANNED_FILES"
  echo "[clamav] INFECTION DETECTED — DO NOT COMMIT. See $RESULTS_DIR/clamav.log."
  exit 1
fi

if [[ "$CLAMAV_EXIT" -ne 0 ]]; then
  echo "[clamav] SCAN ERROR (exit $CLAMAV_EXIT) — see $RESULTS_DIR/clamav.log"
  # Print the tail rather than only pointing at it. On a CI runner the log is thrown away with the
  # workspace, so "see the log" leaves whoever reads the failure with an exit code and nothing else
  # — which is how a missing image tag got misdiagnosed as an entrypoint problem for two rounds.
  echo "[clamav] ── last 20 lines of clamav.log ──"
  tail -n 20 "$RESULTS_DIR/clamav.log" | sed 's/^/[clamav]   /'
  echo "[clamav] ── end ──"
  exit "$CLAMAV_EXIT"
fi

scan_ran clamav "$SCANNED_FILES"
if [ "$SIG_STATE" = unverified ]; then
  # Never an unqualified clean line when the signatures could not be dated. Whoever reads this in a
  # gate verdict has to see that the result rests on an override.
  echo "[clamav] PASS — no infections found (signature age UNVERIFIED — override in effect)"
else
  echo "[clamav] PASS — no infections found"
fi
exit 0
