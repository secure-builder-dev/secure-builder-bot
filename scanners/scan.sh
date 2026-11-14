#!/usr/bin/env bash
# scanners/scan.sh — the Scan gate's work: the scanner runners, in order, into one results directory.
#
# The same sequence as `make gate-scan`, minus the verdict: pull the pinned images, build what the
# image plan names, run the eight scanners, sort findings into dispatch.md and poam-candidates.md.
# core reads the results and decides (core/run scan-verdict, or the scan gate in core/run run).
# scanners/tests/test_gate.py fails if this list and the Makefile recipe drift apart.
#
# It scans the checkout it is installed in: the scanner runners locate the project from their own
# path. Scanning another checkout is the scanners image (scanners/Dockerfile), which carries the bot.
#
# ENV   SCAN_RESULTS_DIR  where results go (default gate-records/scan/latest)
#       SCAN_SKIP         space-separated scanner names the config turned off
#       PROJECT_ROOT      the checkout to scan (default: the one this file is installed in); the
#                         scanners image sets it to the mounted checkout
# FILE  $SCAN_RESULTS_DIR/scanners-exit — "<name> <exit code>", one line per runner this run started
# EXIT  0 the scanners ran (whatever they found — the verdict decides)
#       2 the scan could not start: images could not be pulled, or the build failed
set -uo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scan="$root/scanners/scripts"
PROJECT_ROOT="${PROJECT_ROOT:-$root}"; export PROJECT_ROOT
cd "$PROJECT_ROOT" || exit 2
results="${SCAN_RESULTS_DIR:-$PROJECT_ROOT/gate-records/scan/latest}"
mkdir -p "$results" && : > "$results/scanners-exit"
skip=" ${SCAN_SKIP:-} "

bash "$scan/pull-images.sh" || exit 2
bash "$scan/build-images.sh" || exit 2
for pair in hadolint:run-hadolint.sh checkov:run-checkov.sh clamav:run-clamav.sh grype:run-grype.sh \
            trivy:run-trivy.sh npm-audit:run-npm-audit.sh eslint:run-eslint.sh pip-audit:run-pip-audit.sh \
            wolfi-freshness:run-wolfi-freshness.sh; do
  name="${pair%%:*}"
  case "$skip" in *" $name "*) echo "[$name] skipped — turned off by scan.skip in the config"; continue ;; esac
  bash "$scan/${pair#*:}"; rc=$?
  printf '%s %s\n' "$name" "$rc" >> "$results/scanners-exit"
done
bash "$scan/generate-dispatch.sh" || exit 2
exit 0
