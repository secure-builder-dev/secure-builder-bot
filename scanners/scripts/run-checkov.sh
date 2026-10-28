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
scan_begin checkov

if ! have_tool checkov; then
  tool_missing checkov checkov
  exit 1
fi

mkdir -p "$RESULTS_DIR"

# Accumulate JSON results across frameworks into one combined output
combined_failed=0
frameworks_scanned=0
combined_json='{"results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[]},"summary":{"passed":0,"failed":0,"skipped":0,"parsing_error":0,"resource_count":0}}'

run_framework() {   # run_framework <framework> <label> <target flags…>
  local framework="$1" label="$2"; shift 2
  frameworks_scanned=$((frameworks_scanned + 1))

  echo "[checkov] Scanning $label ($framework) via $(scan_engine_for checkov) engine..."
  local tmp_json
  tmp_json=$(mktemp)

  ( cd "$CHECKOV_ROOT" && PROJECT_ROOT="$CHECKOV_ROOT" tool_checkov \
    --framework "$framework" \
    "$@" \
    --output json \
    --quiet \
    "${OWN[@]}" ) > "$tmp_json" 2>/dev/null || true

  # An empty file here is not "nothing found" — checkov always emits a JSON document when it
  # runs. Empty means it did not run, and skipping the block on that condition contributed 0 to
  # the total and reported PASS. Finding F-22.
  if [[ ! -s "$tmp_json" ]]; then
    echo "[checkov] FAIL — $label produced no output. The scanner did not run." >&2
    rm -f "$tmp_json"
    return 2
  fi

  # checkov emits a summary-only document — no .results key at all — when it ran but found no
  # resources to check. That is valid output, not a crash, so it must not fail the run. It is not
  # a pass either: a target yielding zero resources is a scan that did nothing, and under the old
  # `|| echo "0"` it was indistinguishable from a clean result. This is how helm/templates went
  # unscanned for months while reporting PASS. Say so, loudly. Findings F-22 and F-27.
  if ! jq -e 'has("results")' "$tmp_json" >/dev/null 2>&1; then
    local rc; rc=$(jq -r '.resource_count // "unknown"' "$tmp_json" 2>/dev/null || echo unknown)
    echo "[checkov] $label — NOTHING SCANNED: checkov parsed 0 resources (resource_count=$rc)."
    echo "[checkov]   This is not a pass. Check that the target is the right shape for the"
    echo "[checkov]   $framework framework — the helm framework wants a chart root with Chart.yaml,"
    echo "[checkov]   not a templates directory."
    printf '%s (%s): NOTHING SCANNED, 0 resources\n' "$label" "$framework" >> "$RESULTS_DIR/checkov.log"
    rm -f "$tmp_json"
    return 0
  fi

  local fail_count
  fail_count=$(count_json "$tmp_json" \
    '(.results.failed_checks // error("no .results.failed_checks — output shape changed")) | length' \
    checkov) || { rm -f "$tmp_json"; return 2; }
  combined_failed=$((combined_failed + fail_count))
  printf '%s (%s): %s failed check(s)\n' "$label" "$framework" "$fail_count" >> "$RESULTS_DIR/checkov.log"
  jq -r '.results.failed_checks[] | "  FAILED  \(.check_id)  \(.file_path // "?")  \(.resource // "")  \(.check_name // .check_description // "")"' "$tmp_json" >> "$RESULTS_DIR/checkov.log" 2>/dev/null || true
  # Merge into combined
  combined_json=$(jq -s '
    .[0].results.failed_checks += .[1].results.failed_checks |
    .[0].results.passed_checks += .[1].results.passed_checks |
    .[0].summary.failed += .[1].summary.failed |
    .[0].summary.passed += .[1].summary.passed |
    .[0]
  ' <(echo "$combined_json") "$tmp_json" 2>/dev/null || echo "$combined_json")
  rm -f "$tmp_json"
}

# ── What to scan: every chart, terraform tree and Kubernetes manifest in the checkout ─────────
# scan-scope.sh prunes node_modules, .git, dist, build, vendor, the bot's own fixtures and what
# git ignores. The helm framework renders a chart before checking it, so it needs the chart ROOT —
# the directory holding Chart.yaml. Pointed at helm/templates it got raw Go-template files, parsed
# 0 resources, and contributed 0 findings to a scan that then reported PASS (finding F-27).
# A terraform tree is scanned once from its topmost directory: checkov recurses, so a module
# under it scanned again would be counted twice. A Kubernetes manifest is a yaml file carrying
# both apiVersion and kind outside any chart (a chart's templates are rendered by the helm run).
# shellcheck source=scan-scope.sh
. "$SCRIPT_DIR/scan-scope.sh"
cd "$PROJECT_ROOT" || exit 1
printf '' > "$RESULTS_DIR/checkov.log"
CHARTS=(); TF_DIRS=(); K8S_FILES=()
while IFS= read -r d; do [ -n "$d" ] && CHARTS+=("$d"); done < <(scan_target_dirs "$PROJECT_ROOT" -name Chart.yaml)
while IFS= read -r d; do
  [ -n "$d" ] || continue
  covered=0; for t in "${TF_DIRS[@]}"; do case "$d" in "$t"/*) covered=1 ;; esac; done
  [ "$covered" -eq 0 ] && TF_DIRS+=("$d")
done < <(scan_target_dirs "$PROJECT_ROOT" -name '*.tf')
while IFS= read -r f; do
  [ -n "$f" ] || continue
  in_chart=0; for c in "${CHARTS[@]}"; do case "$f" in "$c"/*) in_chart=1 ;; esac; done
  [ "$in_chart" -eq 1 ] && continue
  grep -qE '^apiVersion:' "$f" && grep -qE '^kind:' "$f" && K8S_FILES+=("$f")
done < <(scan_targets "$PROJECT_ROOT" -name '*.yaml' -o -name '*.yml')

# checkov reads .checkov.yaml (or .yml) from its working directory and from a directory it is given,
# and naming a --config-file does not displace either (checked on the pinned image). A checkout's file
# could skip any check, set a baseline that suppresses existing findings, or load external checks,
# which are Python (gate run 2, N-03). So checkov runs over a copy of the checkout holding none of
# them, with the bot's own config file. The paths inside the copy are the checkout's, so file_path in
# the results, and the justification globs that match it, are unchanged.
CHECKOV_ROOT=$(mktemp -d)
trap 'rm -rf "$CHECKOV_ROOT"' EXIT
if [ $(( ${#CHARTS[@]} + ${#TF_DIRS[@]} + ${#K8S_FILES[@]} )) -eq 0 ]; then
  :   # nothing to scan, so nothing to copy
elif ! tar -C "$PROJECT_ROOT" --exclude=.git --exclude=node_modules --exclude=.checkov.yaml --exclude=.checkov.yml -cf - . \
     | tar -C "$CHECKOV_ROOT" -xf -; then
  echo "[checkov] FAIL — could not stage a copy of the checkout to scan. The scanner did not run." >&2
  exit 2
fi
if [ -n "$(find "$CHECKOV_ROOT" -name '.checkov.y*ml' -print -quit)" ]; then
  echo "[checkov] FAIL — a .checkov.yaml survived staging, so the checkout's config would be read. The scanner did not run." >&2
  exit 2
fi
OWN=(); while IFS= read -r a; do OWN+=("$a"); done < <(own_config_args checkov)

for c in "${CHARTS[@]}"; do run_framework helm "helm chart $c" --directory "$c" || exit 2; done
for d in "${TF_DIRS[@]}"; do run_framework terraform "terraform $d" --directory "$d" || exit 2; done
if [ "${#K8S_FILES[@]}" -gt 0 ]; then
  files=(); for f in "${K8S_FILES[@]}"; do files+=(--file "$f"); done
  run_framework kubernetes "${#K8S_FILES[@]} Kubernetes manifest(s)" "${files[@]}" || exit 2
fi

echo "$combined_json" > "$RESULTS_DIR/checkov.json"

# Decide. checkov OSS rates nothing (severity null without a Prisma key), so the old HIGH/CRITICAL
# count here was always 0 and this runner could never fail: 55 failed checks on main reported PASS
# on 2026-09-23. Every failed check now blocks unless justified — the policy lives in
# checkov-decide.sh so it can be tested with a fixture and no checkov (T-023).
echo "[checkov] Results: $combined_failed total failed before justification"
# What the result file cannot say: whether anything was actually parsed. With no target at all the
# combined document is the empty template and looks exactly like a clean scan of a real chart
# (SEC-SC2-1). An empty scope is legitimate for a project with no IaC, so it is asserted rather
# than inferred, and the verdict names it.
if [ "$frameworks_scanned" -gt 0 ]; then
  scan_ran checkov "$frameworks_scanned target(s): ${#CHARTS[@]} chart(s), ${#TF_DIRS[@]} terraform tree(s), ${#K8S_FILES[@]} Kubernetes manifest(s)"
else
  echo "[checkov] No helm chart, terraform or Kubernetes manifest anywhere in the checkout ($(scan_scope_pruned) excluded)"
  scan_none checkov "no helm chart, terraform or Kubernetes manifest in the checkout"
fi
# It ran, whatever it found: the receipt above is written before the verdict on the findings, so a
# scanner that found something is never reported as one that did not run (gate run 1, B-1).
if ! bash "$SCRIPT_DIR/checkov-decide.sh" "$RESULTS_DIR/checkov.json"; then
  echo "[checkov] FAIL — see $RESULTS_DIR/checkov.json"
  exit 1
fi
