#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
scan_begin hadolint

if ! have_tool hadolint; then
  tool_missing hadolint hadolint
  exit 1
fi

mkdir -p "$RESULTS_DIR"

# Every Dockerfile in the checkout (scan-scope.sh): any directory, pruned and gitignored ones
# excluded. `Dockerfile.*` also matches the reference copies an engine sync writes beside a
# project's own container files; those are gitignored, so the scope helper drops them, and an
# error-level finding in a copy the project does not ship cannot fail its scan. Finding F-25.
# shellcheck source=scan-scope.sh
. "$SCRIPT_DIR/scan-scope.sh"
cd "$PROJECT_ROOT" || exit 1
DOCKERFILES=()
while IFS= read -r f; do [ -n "$f" ] && DOCKERFILES+=("$f"); done < <(scan_targets "$PROJECT_ROOT" -name "Dockerfile" -o -name "Dockerfile.*")

if [[ ${#DOCKERFILES[@]} -eq 0 ]]; then
  echo "[hadolint] No Dockerfile anywhere in the checkout ($(scan_scope_pruned) excluded)"
  echo "[]" > "$RESULTS_DIR/hadolint.json"
  printf '' > "$RESULTS_DIR/hadolint.log"
  # An empty scope is legitimate for this scanner — a library ships no image — so it is asserted
  # rather than left to look like a clean scan of something. The verdict names it.
  scan_none hadolint "no Dockerfile in the checkout"
  exit 0
fi

# The bot's own hadolint config, always. A .hadolint.yaml in the checkout is never read: it used to be
# passed here, and hadolint finds one in the working directory by itself when no config is named, so
# the checkout could switch off any rule (gate run 1, N-11). Rules change in scanners/scan-config.
CONFIG=(); while IFS= read -r a; do CONFIG+=("$a"); done < <(own_config_args hadolint)

echo "[hadolint] Scanning ${#DOCKERFILES[@]} Dockerfile(s) via $(scan_engine_for hadolint) engine..."

# JSON output (tolerate non-zero — findings produce non-zero exit)
tool_hadolint --format json "${CONFIG[@]}" "${DOCKERFILES[@]}" \
  > "$RESULTS_DIR/hadolint.json" 2>"$RESULTS_DIR/hadolint.stderr" || true   # stderr apart: docker chatter in the JSON broke the nightly (T-024)

# TTY output
tool_hadolint --format tty "${CONFIG[@]}" "${DOCKERFILES[@]}" \
  > "$RESULTS_DIR/hadolint.log" 2>&1 || true

ERROR_COUNT=$(count_json "$RESULTS_DIR/hadolint.json" '[.[] | select(.level == "error")] | length' hadolint) || exit 2
WARN_COUNT=$(count_json "$RESULTS_DIR/hadolint.json" '[.[] | select(.level == "warning")] | length' hadolint) || exit 2

echo "[hadolint] Results: $ERROR_COUNT error(s), $WARN_COUNT warning(s)"
# It ran, whatever it found: the receipt is written before the verdict on the findings, so a
# scanner that found something is never reported as one that did not run (gate run 1, B-1).
scan_ran hadolint "${#DOCKERFILES[@]} Dockerfile(s)"

if [[ "$ERROR_COUNT" -gt 0 ]]; then
  echo "[hadolint] FAIL — $ERROR_COUNT error-level finding(s). See $RESULTS_DIR/hadolint.json"
  exit 1
fi

echo "[hadolint] PASS"
exit 0
