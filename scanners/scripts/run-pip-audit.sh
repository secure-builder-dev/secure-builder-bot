#!/usr/bin/env bash
# run-pip-audit.sh — PyPI advisories for every Python app in the checkout, as a gate scanner with
# the same contract as the runners beside it: a result file per run, a decision, a receipt, and
# "did not run" is never "clean".
#
# WHY THIS EXISTS
#   The PRD names the ecosystem's native audit as one of the scanners (npm audit, pip-audit, cargo
#   audit, govulncheck). The engine ran npm audit and nothing else, so a Python app — this bot's
#   own core/ first of all — had its dependencies read only by the filesystem scans of Grype and
#   Trivy. pip-audit asks PyPI's advisory feed directly and resolves the requirements the way pip
#   would, so a pinned requirements file is audited as the tree it installs, not as a text file.
#
# WHAT IT DECIDES
#   - Every requirements*.txt in the checkout is audited by file; a directory holding a
#     pyproject.toml and no requirements file is audited as a project (scan-scope.sh prunes
#     node_modules, .git, dist, build, vendor, virtualenvs, the bot's fixtures and what git
#     ignores). A manifest that was found is audited or the scan fails, named: nothing is stray.
#   - pip-audit emits no severity. A vulnerability WITH a fix available is BLOCKING (exit 1): it is
#     fixable work, routed to dispatch.md. One with no fix is reported, a POAM candidate. The
#     profile's severity policy is applied by the Scan gate (securebuilderbot_scanners.gate) over
#     the CVE aliases this file carries, cross-read with Grype's and Trivy's ratings.
#   - No parseable report is a scanner that DID NOT RUN: exit 1, no pip-audit.json, no receipt.
#     A report with findings is a scanner that ran: the receipt is written, then exit 1.
#   - The tool is the pinned one or nothing: SCAN_PIP_AUDIT_VERSION in tool-versions.env, installed
#     from scanners/requirements.txt; any other version is refused, so two runs of the same tree
#     are the same scan. It runs natively on every engine (`python3 -m pip_audit`): the scanners
#     image installs the same pin.
#
# INPUTS   requirements*.txt and pyproject.toml anywhere in the checkout
# OUTPUTS  $RESULTS_DIR/pip-audit-<app>.json   raw pip-audit JSON, one per manifest
#          $RESULTS_DIR/pip-audit.json         normalised: apps, blocking (fix available), reported (no fix)
#          $RESULTS_DIR/pip-audit.log          human summary
# ENV      SCAN_RESULTS_DIR · PROJECT_ROOT (default: the checkout this file is installed in)
#          PIP_AUDIT_CMD (default "python3 -m pip_audit"; tests substitute a fake)
# EXIT     0 = nothing blocking · 1 = a fixable vulnerability, or the scanner did not run
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
RESULTS_DIR="${SCAN_RESULTS_DIR:-$PROJECT_ROOT/gate-records/scan/latest}"
PIP_AUDIT_CMD="${PIP_AUDIT_CMD:-python3 -m pip_audit}"
TODAY="$(date -u +%Y-%m-%d)"
LOG="$RESULTS_DIR/pip-audit.log"

# shellcheck source=tool-versions.env
. "$SCRIPT_DIR/tool-versions.env"
# shellcheck source=scan-receipt.sh
. "$SCRIPT_DIR/scan-receipt.sh"
# shellcheck source=scan-scope.sh
. "$SCRIPT_DIR/scan-scope.sh"

# FIRST, before any check that can exit: drop this run's receipt, so a run that bails out early
# cannot be counted on the strength of the previous run's receipt and result file (SEC-SC2-1).
scan_begin pip-audit

say() { printf '%s\n' "$*" | tee -a "$LOG"; }

if ! command -v jq >/dev/null 2>&1; then
  echo "[pip-audit] FAIL — jq is required. The scanner did not run."; exit 1
fi
cd "$PROJECT_ROOT" || exit 1
mkdir -p "$RESULTS_DIR"

# ── Every Python manifest in the checkout ─────────────────────────────────────
MANIFESTS=()
while IFS= read -r f; do [ -n "$f" ] && MANIFESTS+=("$f"); done < <(scan_targets "$PROJECT_ROOT" -name 'requirements*.txt')
while IFS= read -r f; do
  [ -n "$f" ] || continue
  d=$(dirname "$f"); has_req=0
  for m in "${MANIFESTS[@]}"; do [ "$(dirname "$m")" = "$d" ] && has_req=1; done
  [ "$has_req" -eq 0 ] && MANIFESTS+=("$f")   # a pyproject beside a requirements file is covered by it
done < <(scan_targets "$PROJECT_ROOT" -name pyproject.toml)

if [ "${#MANIFESTS[@]}" -eq 0 ]; then
  : > "$LOG"
  jq -n --arg today "$TODAY" --arg pruned "$(scan_scope_pruned)" '{ scanner: "pip-audit", generated: $today,
    policy: ("nothing in scope — no requirements*.txt or pyproject.toml anywhere in the checkout (" + $pruned + " excluded)"),
    apps: [], blocking: [], reported: [] }' > "$RESULTS_DIR/pip-audit.json"
  say "[pip-audit] NOTHING IN SCOPE — no requirements*.txt or pyproject.toml anywhere in the checkout ($(scan_scope_pruned) excluded). No Python dependency tree to audit."
  scan_none pip-audit "no Python app (no requirements*.txt or pyproject.toml in the checkout)"
  exit 0
fi

# ── The pinned tool, or nothing ───────────────────────────────────────────────
read -r -a PA <<< "$PIP_AUDIT_CMD"
if ! command -v "${PA[0]}" >/dev/null 2>&1; then
  echo "[pip-audit] FAIL — '${PA[0]}' not found on PATH. The scanner did not run."; exit 1
fi
version=$("${PA[@]}" --version 2>/dev/null | sed -nE 's/^pip-audit ([0-9][^ ]*).*/\1/p' | head -1)
if [ "$version" != "$SCAN_PIP_AUDIT_VERSION" ]; then
  echo "[pip-audit] FAIL — pip-audit ${version:-is not installed}; the pin is $SCAN_PIP_AUDIT_VERSION (scanners/scripts/tool-versions.env)."
  echo "[pip-audit]   Install the pinned tool: pip install -r scanners/requirements.txt. The scanner did not run."
  exit 1
fi

rm -f "$RESULTS_DIR/pip-audit.json" "$RESULTS_DIR"/pip-audit-*.json
: > "$LOG"

# ── One audit per manifest ────────────────────────────────────────────────────
ran=0; failed=0; apps_json='[]'
for m in "${MANIFESTS[@]}"; do
  app=$(dirname "$m"); slug="${app//\//-}"; [ "$app" = "." ] && slug="root"
  raw="$RESULTS_DIR/pip-audit-$slug-$(basename "$m" | tr -c 'A-Za-z0-9.\n' '-').json"
  case "$(basename "$m")" in
    pyproject.toml) target=("$app") ;;
    *)              target=(-r "$m") ;;
  esac
  say "[pip-audit] $m: ${PA[*]} ${target[*]} (format json)"
  # pip-audit exits 1 when it found a vulnerability, which the report already says; stderr goes to
  # the log so a feed or resolution failure is readable, not swallowed.
  "${PA[@]}" "${target[@]}" --format json --progress-spinner off --desc off > "$raw" 2>>"$LOG"
  rc=$?
  if [ "$rc" -gt 1 ] || ! jq -e '.dependencies | type == "array"' "$raw" >/dev/null 2>&1; then
    say "[pip-audit] FAIL — $m: pip-audit exited $rc without a report (see $LOG). The scanner did not run."
    failed=1; continue
  fi
  ran=$((ran + 1))
  apps_json=$(jq -n --arg app "$app" --arg file "$m" --slurpfile raw "$raw" --argjson apps "$apps_json" '
    $apps + [{
      app: $app, file: $file,
      dependencies: ($raw[0].dependencies | length),
      vulns: [ $raw[0].dependencies[] | .name as $pkg | .version as $ver | (.vulns // [])[]
               | { app: $app, file: $file, id: .id, aliases: (.aliases // []), package: $pkg, version: $ver,
                   fix_versions: (.fix_versions // []),
                   fix: (if ((.fix_versions // []) | length) > 0 then .fix_versions[0] else "none" end) } ] }]')
done

[ "$failed" -eq 0 ] || exit 1
if [ "$ran" -eq 0 ]; then
  say "[pip-audit] FAIL — no manifest could be audited. The scanner did not run."; exit 1
fi

# ── Decide ────────────────────────────────────────────────────────────────────
jq -n --argjson apps "$apps_json" --arg today "$TODAY" '
  ($apps | map(.vulns[])) as $all
  | { scanner: "pip-audit", generated: $today,
      policy: "pip-audit rates nothing; a vulnerability with a fix available is blocking (fixable work), one without is reported as a POAM candidate; the profile severity policy is applied by the Scan gate over the CVE aliases",
      apps: ($apps | map({app, file, dependencies, vulns: (.vulns | length)})),
      blocking: [ $all[] | select(.fix != "none") ],
      reported: [ $all[] | select(.fix == "none") ] }' > "$RESULTS_DIR/pip-audit.json" 2>>"$LOG"

if ! jq -e '.blocking' "$RESULTS_DIR/pip-audit.json" >/dev/null 2>&1; then
  rm -f "$RESULTS_DIR/pip-audit.json"
  say "[pip-audit] FAIL — could not write the decision file (see $LOG). The scanner did not run."
  exit 1
fi

# It ran, whatever it found: the receipt is written before the verdict on the findings, so a
# scanner that found something is never reported as one that did not run (gate run 1, B-1).
scan_ran pip-audit "$ran manifest(s)"
B=$(jq '.blocking | length' "$RESULTS_DIR/pip-audit.json")
R=$(jq '.reported | length' "$RESULTS_DIR/pip-audit.json")
say "[pip-audit] Results: $ran manifest(s) audited · $B blocking (fix available) · $R reported (no fix, POAM candidates)"
jq -r '.blocking[] | "  BLOCKING  \(.file)  \(.id)  \(.aliases | join(","))  \(.package)@\(.version)  fix: \(.fix)"' "$RESULTS_DIR/pip-audit.json" | tee -a "$LOG"
jq -r '.reported[] | "  reported  \(.file)  \(.id)  \(.aliases | join(","))  \(.package)@\(.version)  fix: none"' "$RESULTS_DIR/pip-audit.json" | tee -a "$LOG"

if [ "$B" -gt 0 ]; then
  say "[pip-audit] FAIL — $B fixable vulnerabilit$([ "$B" -eq 1 ] && echo y || echo ies). Bump the pinned version in the manifest named above and run the suite."
  exit 1
fi
say "[pip-audit] PASS — nothing fixable"
exit 0
