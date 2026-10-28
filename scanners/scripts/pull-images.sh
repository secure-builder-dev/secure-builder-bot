#!/usr/bin/env bash
# pull-images.sh — pull every scanner image before any runner starts.
#
# WHY THIS EXISTS
#   On a cold host (a fresh GitHub runner, a new laptop) the first `docker run` of a scanner image
#   pulls it, and Docker writes the pull progress to the command's stderr. On 2026-09-23 the nightly
#   captured that text into hadolint.json, the JSON guard fired (correctly), `make scan` aborted at
#   the second scanner, `|| true` swallowed the exit, and the job was green with zero valid scanners.
#   Pulling up front means no runner's first invocation is a pull, and a registry problem is one
#   loud failure here instead of a garbled result file later.
#
# USAGE  scanners/scripts/pull-images.sh        (first line of make scan / scan-lite / gate-scan)
# ENV    SCAN_ENGINE — under native, there is nothing to pull and this exits 0
# EXIT   0 = every image present · 1 = a pull failed (the scanner that needs it cannot run)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tool-runner.sh
. "$SCRIPT_DIR/tool-runner.sh"

if [ "$(scan_engine)" != container ]; then
  echo "[pull] SCAN_ENGINE=$(scan_engine) — host binaries, nothing to pull"
  exit 0
fi

# A registry can refuse a fresh pull of an image that is already on disk — Docker Hub's rate limit
# answers 429 to the HEAD request a pull starts with, outages do the same. A pinned tag on disk is
# the scanner the pin names, so the scan continues on it and says so; the one moving tag, ClamAV,
# refreshes its signatures through freshclam at run time, not through this pull. An image that is
# neither pullable nor present is a scanner that cannot run, and that fails here, loudly.
pull_or_present() {   # pull_or_present <ref> [docker pull flags…]
  local ref="$1" err; shift; err=$(mktemp)
  if docker pull -q "$@" "$ref" >/dev/null 2>"$err"; then echo "[pull] $ref"; rm -f "$err"; return 0; fi
  if docker image inspect "$ref" >/dev/null 2>&1; then
    echo "[pull] $ref — present locally; the registry refused a fresh pull ($(tail -1 "$err" | head -c 120))"
    rm -f "$err"; return 0
  fi
  echo "[pull] FAIL — could not pull $ref ($(tail -1 "$err" | head -c 120))"; rm -f "$err"; return 1
}

failed=0
for ref in "$SCAN_IMAGE_HADOLINT" "$SCAN_IMAGE_CHECKOV" "$SCAN_IMAGE_GRYPE" "$SCAN_IMAGE_TRIVY"; do
  pull_or_present "$ref" || failed=1
done
# ClamAV publishes amd64 only; the same --platform the wrapper passes to `docker run`.
# shellcheck disable=SC2046
pull_or_present "$SCAN_IMAGE_CLAMAV" $(_tr_clamav_platform) || failed=1

[ "$failed" -eq 0 ] || { echo "[pull] FAIL — a scanner image is missing; the scan cannot be complete."; exit 1; }
echo "[pull] all scanner images present"
exit 0
