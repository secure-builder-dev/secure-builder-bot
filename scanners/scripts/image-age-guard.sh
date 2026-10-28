#!/usr/bin/env bash
# image-age-guard.sh — refuse to report a stale image as evidence.
#
# WHY THIS EXISTS (F-18, follow-on to F-17)
#   build-images.sh closed the common path: `make scan` now builds with --pull --no-cache, so a
#   normal run measures the current tree. Two of its own exits still leave the original hole open,
#   and both return 0, so the scan proceeds and prints a number as if it were current:
#
#     SCAN_NO_BUILD=1     "skipping. The scan will measure whatever image already exists."
#     docker unavailable  "skipping build; image scans will report NOTHING SCANNED."
#
#   The second is only true when NO tagged image exists. When a stale one does — which is the
#   normal state of a dev machine — run-grype.sh and run-trivy.sh find it via their
#   scan/local/latest tag search and grade it silently. That is exactly the 2026-09-18 failure:
#   a July image scored 335/148 and read as a current result.
#
#   A build failure is already covered: build-images.sh returns 1 and make halts.
#
# USAGE   sourced by run-grype.sh and run-trivy.sh, after $IMAGES is resolved:
#           source "$SCRIPT_DIR/image-age-guard.sh"
#           guard_image_age "${IMAGES[@]}" || exit 1
#         The `|| exit 1` form is required — both callers run under `set -euo pipefail`, where a
#         bare call returning 1 aborts the script before the explanation is printed.
#
#   SCAN_MAX_IMAGE_AGE_HOURS   default 24; 0 disables the check
#   SCAN_ALLOW_STALE=1         downgrade the hard failure to a loud warning

# Portable RFC3339 -> epoch. GNU date first, BSD/macOS second. Engine scripts run on both.
_ts_to_epoch() {
  local ts="${1%%.*}"; ts="${ts%Z}"; ts="${ts%+00:00}"
  date -u -d "$ts" +%s 2>/dev/null && return 0
  date -u -j -f "%Y-%m-%dT%H:%M:%S" "$ts" +%s 2>/dev/null && return 0
  echo ""
}

guard_image_age() {
  local max_hours="${SCAN_MAX_IMAGE_AGE_HOURS:-24}"
  [ "$max_hours" = "0" ] && return 0

  local now stale=0 img created epoch age_h
  now=$(date -u +%s)

  for img in "$@"; do
    docker image inspect "$img" >/dev/null 2>&1 || continue
    created=$(docker image inspect "$img" --format '{{.Created}}' 2>/dev/null)
    epoch=$(_ts_to_epoch "$created")
    # An unreadable timestamp must not pass the guard silently.
    if [ -z "$epoch" ]; then
      echo "[age] WARNING — cannot read build time for $img; its age is unverified."
      continue
    fi
    age_h=$(( (now - epoch) / 3600 ))
    if [ "$age_h" -gt "$max_hours" ]; then
      stale=$((stale + 1))
      echo "[age] STALE: $img was built ${age_h}h ago (limit ${max_hours}h)."
    fi
  done

  [ "$stale" -eq 0 ] && return 0

  echo ""
  echo "[age] $stale image(s) exceed ${max_hours}h. Findings from them describe an OLD BUILD, not"
  echo "[age] the current tree: CVEs already fixed upstream will still be listed, and packages"
  echo "[age] added since will be missing entirely. This is NOT evidence."
  echo "[age]   Rebuild:           bash scanners/scripts/build-images.sh"
  echo "[age]   Accept the risk:   SCAN_ALLOW_STALE=1 make scan"
  echo "[age]   Widen the window:  SCAN_MAX_IMAGE_AGE_HOURS=72 make scan"

  if [ "${SCAN_ALLOW_STALE:-0}" = "1" ]; then
    echo "[age] SCAN_ALLOW_STALE=1 — continuing. Do not file this run as a clean scan."
    return 0
  fi
  return 1
}
