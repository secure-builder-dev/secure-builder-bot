#!/usr/bin/env bash
# run-eslint.sh — ESLint over every app dir as a gate scanner, with the same contract as the
# runners beside it: a result file per run, a decision, and "did not run" is never "clean".
#
# WHY THIS EXISTS
#   `make lint` runs eslint in `make check`, so CI sees it. The gate does not: Sentinel transcribes
#   the scan verdict (`core/run scan-verdict`)'s verdict into the record, and a check that lives only in CI is invisible there.
#   Until 2026-09-23 the frontend was never linted anywhere at all; this makes lint findings part of
#   the scan the gate reads, using each app's own eslint config and its own `lint` script's target.
#
# WHAT IT DECIDES
#   - Every message is blocking. Both apps lint with `--max-warnings 0` (T-018), so a warning is a
#     failure by policy; the scanner does not soften that.
#   - An app dir with a `lint` script but no node_modules is a scanner that DID NOT RUN (exit 1,
#     no eslint.json): on a gate host that is a setup error, and a skip would read as clean.
#   - A package.json with no `lint` script is an app this scanner has no ruleset for: it is listed
#     as `unlinted` in eslint.json and the log, never silently dropped. A checkout whose apps all
#     lack one is a declared empty scope, named in the verdict.
#   - eslint exiting 2 (config error, crash) or printing something that is not its JSON report is
#     likewise "did not run".
#
# INPUTS   every <app>/package.json in the checkout (scan-scope.sh) with a `lint` script that starts
#          with `eslint`, and <app>/node_modules
# OUTPUTS  $RESULTS_DIR/eslint-<app>.json  raw eslint --format json, one per app
#          $RESULTS_DIR/eslint.json        normalised: apps, blocking (every message)
#          $RESULTS_DIR/eslint.log         human summary
# ENV      SCAN_RESULTS_DIR · ESLINT_ROOT (default: repo root; tests use a fixture)
#          ESLINT_APPS (default: every package.json directory) · ESLINT_NPX (default npx; tests substitute a fake)
# EXIT     0 = no messages · 1 = at least one message, or the scanner did not run
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
ROOT="${ESLINT_ROOT:-$PROJECT_ROOT}"
RESULTS_DIR="${SCAN_RESULTS_DIR:-$PROJECT_ROOT/gate-records/scan/latest}"
NPX="${ESLINT_NPX:-npx}"
LOG="$RESULTS_DIR/eslint.log"

# shellcheck source=scan-receipt.sh
. "$SCRIPT_DIR/scan-receipt.sh"

# FIRST, before any check that can exit: drop this run's receipt. A runner that bails out early —
# tool missing, Docker down, jq absent — must not leave the PREVIOUS run's receipt behind, or the
# verdict counts a scanner that did not run this time and reads last run's result file as current.
# Found while closing SEC-SC2-1: 1 exit path(s) in this script precede the checks below.
scan_begin eslint

say() { printf '%s\n' "$*" | tee -a "$LOG"; }

if ! command -v jq >/dev/null 2>&1; then
  echo "[eslint] FAIL — jq is required. The scanner did not run."; exit 1
fi
# ── Android track: no npm app dir exists, by design ──────────────────────────
# Same shape as run-npm-audit.sh: an empty, valid decision file and a "none" receipt, so the
# verdict counts this scanner as having run and names the empty scope. Kotlin lint is
# `make lint` (ktlint + detekt) on this track; it is not a gate scanner yet.
# shellcheck source=scan-track.sh
. "$SCRIPT_DIR/scan-track.sh"
if [ "$(scan_track "$ROOT")" = android ]; then
  mkdir -p "$RESULTS_DIR"
  jq -n '{ scanner: "eslint", policy: "not applicable on the android track — no npm app dir; Kotlin lint runs as make lint (ktlint, detekt)",
           apps: [], blocking: [] }' > "$RESULTS_DIR/eslint.json"
  say "[eslint] NOT APPLICABLE on the android track — no npm app dir here. Kotlin lint is make lint (ktlint, detekt)."
  scan_none eslint "not applicable on the android track (no npm app dir)"
  exit 0
fi

# ── Every npm app in the checkout ─────────────────────────────────────────────
# Same shape as run-npm-audit.sh: every directory holding a package.json, anywhere (scan-scope.sh).
# None is an empty, valid decision file and a "none" receipt, named in the verdict.
# shellcheck source=scan-scope.sh
. "$SCRIPT_DIR/scan-scope.sh"
APPS="${ESLINT_APPS:-$(scan_target_dirs "$ROOT" -name package.json | tr '\n' ' ')}"
APPS="${APPS% }"
empty_scope() {   # empty_scope <why> <unlinted json array>
  mkdir -p "$RESULTS_DIR"
  jq -n --arg why "$1" --argjson unlinted "$2" '{ scanner: "eslint", policy: ("nothing in scope — " + $why),
           apps: [], blocking: [], unlinted: $unlinted }' > "$RESULTS_DIR/eslint.json"
  say "[eslint] NOTHING IN SCOPE — $1. No JavaScript app to lint."
  scan_none eslint "$1"
  exit 0
}
if [ -z "$APPS" ]; then
  empty_scope "no package.json anywhere in the checkout ($(scan_scope_pruned) excluded)" '[]'
fi
if ! command -v "$NPX" >/dev/null 2>&1; then
  echo "[eslint] FAIL — '$NPX' not found on PATH. The scanner did not run."; exit 1
fi

mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR/eslint.json" "$RESULTS_DIR"/eslint-*.json
: > "$LOG"

ran=0; failed=0; apps_json='[]'; unlinted_json='[]'
for app in $APPS; do
  dir="$ROOT/$app"
  [ -f "$dir/package.json" ] || { say "[eslint] $app: no package.json — not an app dir here, skipped"; continue; }
  lint_script=$(jq -r '.scripts.lint // ""' "$dir/package.json")
  case "$lint_script" in
    eslint\ *|eslint) ;;
    "") say "[eslint] $app: package.json has no lint script — not linted (listed as unlinted)"
        unlinted_json=$(jq -n --arg app "$app" --argjson u "$unlinted_json" '$u + [$app]'); continue ;;
    *)  say "[eslint] FAIL — $app: lint script does not start with eslint (\"$lint_script\"). The scanner did not run."; failed=1; continue ;;
  esac
  if [ ! -d "$dir/node_modules" ]; then
    say "[eslint] FAIL — $app: no node_modules; install before scanning (cd $app && npm ci). The scanner did not run."
    failed=1; continue
  fi
  # The app's own target and flags, minus the leading `eslint`; the format and the warning policy
  # are ours and come last so they win over anything in the script.
  # shellcheck disable=SC2206
  args=( ${lint_script#eslint} )
  raw="$RESULTS_DIR/eslint-${app//\//-}.json"
  say "[eslint] $app: eslint ${args[*]} --max-warnings 0 (format json)"
  (cd "$dir" && "$NPX" --no-install eslint "${args[@]}" --format json --max-warnings 0 > "$raw" 2>>"$LOG")
  rc=$?
  if [ "$rc" -ge 2 ] || ! jq -e 'type == "array"' "$raw" >/dev/null 2>&1; then
    say "[eslint] FAIL — $app: eslint exited $rc without a report (see $LOG). The scanner did not run."
    failed=1; continue
  fi
  ran=$((ran + 1))
  apps_json=$(jq -n --arg app "$app" --arg dir "$dir/" --slurpfile raw "$raw" --argjson apps "$apps_json" '
    $apps + [{
      app: $app,
      files: ($raw[0] | length),
      errors: ($raw[0] | map(.errorCount // 0) | add // 0),
      warnings: ($raw[0] | map(.warningCount // 0) | add // 0),
      messages: [ $raw[0][] | .filePath as $f | .messages[]
                  | { app: $app,
                      file: ($f | ltrimstr($dir)),
                      line: (.line // 0), column: (.column // 0),
                      rule: (.ruleId // "parse"),
                      severity: (if .severity == 2 then "error" else "warning" end),
                      message: (.message // "") } ] }]')
done

[ "$failed" -eq 0 ] || exit 1
if [ "$ran" -eq 0 ]; then
  # Every app found lacks an eslint lint script: nothing this scanner can lint, said by name.
  empty_scope "no package.json with an eslint lint script ($(jq -r 'join(", ")' <<< "$unlinted_json") unlinted)" "$unlinted_json"
fi

jq -n --argjson apps "$apps_json" --argjson unlinted "$unlinted_json" '
  { scanner: "eslint",
    policy: "every message blocks: each app lints with --max-warnings 0 (T-018); an app with no lint script is listed as unlinted",
    apps: $apps,
    unlinted: $unlinted,
    blocking: [ $apps[].messages[] ] }' > "$RESULTS_DIR/eslint.json" 2>>"$LOG"

if ! jq -e '.blocking' "$RESULTS_DIR/eslint.json" >/dev/null 2>&1; then
  rm -f "$RESULTS_DIR/eslint.json"
  say "[eslint] FAIL — could not write the decision file (see $LOG). The scanner did not run."
  exit 1
fi

# It ran, whatever it found: the receipt is written before the verdict on the findings, so a
# scanner that found something is never reported as one that did not run (gate run 1, B-1).
scan_ran eslint "$ran app(s)$( [ "$unlinted_json" = "[]" ] || printf ', %s without a lint script (unlinted)' "$(jq 'length' <<< "$unlinted_json")" )"
B=$(jq '.blocking | length' "$RESULTS_DIR/eslint.json")
say "[eslint] Results: $ran app(s) linted · $B message(s) ($(jq -r '[.apps[] | "\(.app): \(.errors) error(s) \(.warnings) warning(s) in \(.files) file(s)"] | join("; ")' "$RESULTS_DIR/eslint.json"))"
jq -r '.blocking[] | "  BLOCKING  \(.app)  \(.file):\(.line):\(.column)  \(.severity)  \(.rule)  \(.message)"' "$RESULTS_DIR/eslint.json" | tee -a "$LOG"

if [ "$B" -gt 0 ]; then
  say "[eslint] FAIL — $B message(s). Fix them; both apps run eslint with --max-warnings 0, so a warning is a failure by policy."
  exit 1
fi
say "[eslint] PASS — no messages"
exit 0
