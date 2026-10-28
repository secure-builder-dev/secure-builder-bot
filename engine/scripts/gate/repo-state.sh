#!/usr/bin/env bash
# repo-state.sh — mechanical snapshot of HEAD, independent of any epic's diff.
#
# WHY THIS EXISTS
#   Every gate in this engine is diff-scoped. It can prove "this change is correct" and
#   structurally cannot prove "the system is still correct." Controls that decayed after their
#   epic closed, artifacts deleted by a commit outside the engine, and accumulating suite rot are
#   all invisible to a diff-scoped gate — not because anyone was careless, but because nothing in
#   the lifecycle ever looked at HEAD.
#
#   This reads HEAD, reports a fixed set of numbers, and diffs them against the previous gate.
#   It NEVER remediates and NEVER blocks: blocking is a human decision made on the delta.
#
#   It must stay fast. A gate probe that costs minutes gets skipped inside a month. It therefore
#   does not run the test suite — the gate already does, and passes the result in via --suites.
#
# BASELINE SEMANTICS
#   Snapshots are kept per commit under gate-records/state/history/<sha>.json. The delta is
#   always computed against the most recent snapshot taken at a DIFFERENT commit, so re-running at
#   the same HEAD is idempotent — it refreshes that commit's snapshot and reports the same delta
#   again rather than erasing it. Consequences:
#     • A run on main (after a merge) sees drift from outside the engine.
#     • A run on epic/<name> at gate time sees what the epic itself changed.
#   Only the first kind is a register finding; the second is reviewed inside the gate run.
#
# USAGE   engine/scripts/gate/repo-state.sh [--suites TOTAL/PASS/FAIL] [--json]
# EXIT    Always 0. This is a reporter.

set -uo pipefail
GATE_LIB="$(cd "$(dirname "$0")/../../../qa/scripts" && pwd)/_lib.sh"
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 0
# shellcheck source=/dev/null
. "$GATE_LIB"

STATE_DIR="gate-records/state"; HIST="$STATE_DIR/history"; mkdir -p "$HIST"
SUITES_ARG=""; JSON_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --suites) SUITES_ARG="${2:-}"; shift 2 ;;
    --json)   JSON_ONLY=1; shift ;;
    *) shift ;;
  esac
done
SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

# Baseline = newest snapshot whose sha differs from HEAD (see BASELINE SEMANTICS above).
PREV=""
for f in $(ls -t "$HIST"/*.json 2>/dev/null); do
  case "$(basename "$f" .json)" in "$SHA") continue ;; *) PREV="$f"; break ;; esac
done
# history/ is per-clone and untracked. latest.json is the snapshot a GATE commits (SEC-GS-7, at the
# bottom of this file) and is the one baseline a fresh worktree has — and until 2026-10-12 this read
# only history/, so every gate run in a fresh clone reported `baseline: none` and silently suppressed
# every delta flag, the `ci runs tests/lint` probe Table A marks PC-03 ACTIVE among them. Nine gate
# runs in the engine's first project ran blind that way and none of them knew (T-ENGINE-17). The tracked file is
# a candidate like any snapshot: it is skipped when it describes HEAD itself (idempotence, as above),
# and between it and the newest per-clone snapshot the later `recorded` stamp wins.
_rec() { grep -oE '"recorded": *"[^"]*"' "$1" 2>/dev/null | head -1 | sed 's/.*: *"//; s/"$//'; }
if [ -f "$STATE_DIR/latest.json" ]; then
  _lsha="$(grep -oE '"sha": *"[^"]*"' "$STATE_DIR/latest.json" 2>/dev/null | head -1 | sed 's/.*: *"//; s/"$//')"
  if [ -n "$_lsha" ] && [ "$_lsha" != "$SHA" ]; then
    if [ -z "$PREV" ] || [ "$(_rec "$STATE_DIR/latest.json")" \> "$(_rec "$PREV")" ]; then PREV="$STATE_DIR/latest.json"; fi
  fi
fi

# ── CI surface ────────────────────────────────────────────────────────────────
# Frozen platform surface in most deployments: the engine may not WRITE it. It must REPORT it.
# Freezing writes never freezes observation — silence here is how a pipeline can lose every
# test-running job and have no gate notice for weeks.
CI_FILE=".gitlab-ci.yml"; CI_LINES=0; CI_JOBS=0; CI_TEST_JOB="NO"
if [ -f "$CI_FILE" ]; then
  CI_LINES=$(wc -l < "$CI_FILE" | tr -d ' ')
  # grep -c prints 0 itself on no match (and exits 1) — no `|| echo 0`, which would print a second 0.
  all_keys=$(grep -cE '^[a-zA-Z_][a-zA-Z0-9_.-]*:' "$CI_FILE" 2>/dev/null)
  directives=$(grep -cE '^(variables|stages|include|default|workflow|image|before_script|after_script|services|cache):' "$CI_FILE" 2>/dev/null)
  CI_JOBS=$(( ${all_keys:-0} - ${directives:-0} )); [ "$CI_JOBS" -lt 0 ] && CI_JOBS=0
  if grep -qE '(npm|yarn|npx|pnpm) +(run +)?(test|lint|typecheck|tsc)|gradlew.*(test|ktlintCheck|detekt)' "$CI_FILE" 2>/dev/null; then
    CI_TEST_JOB="YES"
  fi
fi

# ── Deploy surface (web track only; tactical/android has no Kubernetes) ───────
HELM_TEMPLATES="n/a"
[ -d helm/templates ] && HELM_TEMPLATES=$(find helm/templates -maxdepth 1 \( -name '*.yaml' -o -name '*.yml' -o -name '*.tpl' \) | wc -l | tr -d ' ')

# ── Test surface ──────────────────────────────────────────────────────────────
# T-ENGINE-06 / GOV-029: count every suite the project runs, not just the one GATE_TEST_GLOB dir.
# A missing directory contributes 0 rather than failing: a project with no frontend is normal.
SUITE_FILES=0
for _pair in ${GATE_TEST_GLOBS:-"$GATE_TEST_GLOB:$GATE_TEST_EXT"}; do
  _d="${_pair%%:*}"; _e="${_pair##*:}"
  [ -d "$_d" ] || continue
  _n=$(find "$_d" -name "$_e" 2>/dev/null | wc -l | tr -d ' ')
  SUITE_FILES=$((SUITE_FILES + _n))
done

# Test files doing file I/O at MODULE scope. These throw at collection and take every sibling
# test in the file down with them — the suite reports one red file, not fifteen skipped controls.
COLLECT_RISK=0
for _pair in ${GATE_TEST_GLOBS:-"$GATE_TEST_GLOB:$GATE_TEST_EXT"}; do
  _d="${_pair%%:*}"; _e="${_pair##*:}"
  [ -d "$_d" ] || continue
  _n=$(find "$_d" -name "$_e" -exec grep -lE '^[[:space:]]*(const|let|var|val)[^=]*=[^=]*(readFileSync|existsSync|File\()' {} + 2>/dev/null | wc -l | tr -d ' ')
  COLLECT_RISK=$((COLLECT_RISK + _n))
done

# ── Orphaned exports (advisory trend) ─────────────────────────────────────────
# ADVISORY, and deliberately not itemised: a helper exported purely so tests can reach it lands
# here too, so the list is noisy. What matters is the TREND. The authoritative dead-control check
# is verify-controls.sh, which only asks this of symbols declared to BE controls.
USED_IDX="$(mktemp)"; DEFS_IDX="$(mktemp)"; trap 'rm -f "$USED_IDX" "$DEFS_IDX"' EXIT
gate_build_use_index "$USED_IDX"
: > "$DEFS_IDX"
if [ -d "$GATE_CONTROL_ROOT" ]; then
  # TS: `export function`, `export async function`, `export const NAME =` (arrow fns are the common
  # middleware shape). Kotlin: any non-private `fun`, indented or not, with any modifier prefix.
  gate_find_src "$GATE_CONTROL_ROOT" | grep -v "/${GATE_TEST_GLOB##*/}/" | while IFS= read -r f; do
    grep -noE '^export (async )?function [A-Za-z0-9_]+|^export const [A-Za-z0-9_]+|^[[:space:]]*((public|internal|protected|override|suspend|open|inline|operator|infix) +)*fun [A-Za-z0-9_]+' "$f" 2>/dev/null \
      | awk -v f="$f" -F: '{n=split($2,w," "); print w[n] "\t" f "\t" $1}'
  done | sort -u > "$DEFS_IDX"
fi
# Index uses by token once; O(uses + defs), not O(uses × defs).
DEAD_EXPORTS=$(awk -F'\t' '
  NR==FNR { files[$1] = files[$1] SUBSEP $2 ":" $3 SUBSEP; next }
  { if (!($1 in files)) { n++; next }
    # used somewhere other than its own definition line?
    m = split(files[$1], a, SUBSEP); found = 0
    for (i = 1; i <= m; i++) if (a[i] != "" && a[i] != $2 ":" $3) { found = 1; break }
    if (!found) n++ }
  END { print n+0 }' "$USED_IDX" "$DEFS_IDX")

# ── Control manifest ──────────────────────────────────────────────────────────
MANIFEST_RESULT="no-manifest"
if [ -f docs/security/CONTROL-MANIFEST.md ]; then
  if [ -f "$(dirname "$GATE_LIB")/verify-controls.sh" ]; then
    bash "$(dirname "$GATE_LIB")/verify-controls.sh" --quiet
    case $? in 0) MANIFEST_RESULT="PASS" ;; 2) MANIFEST_RESULT="unpopulated" ;; *) MANIFEST_RESULT="FAIL" ;; esac
  else
    MANIFEST_RESULT="no-verifier"
  fi
fi

S_TOTAL="-"; S_PASS="-"; S_FAIL="-"; S_NOTE=""
if [ -n "$SUITES_ARG" ]; then
  S_TOTAL="${SUITES_ARG%%/*}"; rest="${SUITES_ARG#*/}"; S_PASS="${rest%%/*}"; S_FAIL="${rest#*/}"
elif [ -f "$STATE_DIR/latest.json" ]; then
  # latest.json is committed with each gate row. A probe run without --suites (a security-gate
  # re-read, a curious developer) must not overwrite the gate's recorded counts with "-/-/-":
  # carry the last recorded values forward and say so.
  _lv() { grep -oE "\"$1\": *\"?[^,\"}]*\"?" "$STATE_DIR/latest.json" 2>/dev/null | head -1 | sed 's/.*: *"\{0,1\}//; s/"$//'; }
  _t="$(_lv suites_total)"; _p="$(_lv suites_pass)"; _f="$(_lv suites_fail)"
  if [ -n "$_t" ] && [ "$_t" != "-" ]; then S_TOTAL="$_t"; S_PASS="$_p"; S_FAIL="$_f"; S_NOTE="   (carried from $(_lv sha); no --suites this run)"; fi
fi

prev_val() { [ -n "$PREV" ] && grep -oE "\"$1\": *\"?[^,\"}]*\"?" "$PREV" 2>/dev/null | head -1 | sed 's/.*: *"\{0,1\}//; s/"$//' || echo ""; }
delta() { local now="$1" was="$2"
  { [ -z "$was" ] || [ "$was" = "$now" ]; } && { echo ""; return; }
  case "$now$was" in *[!0-9]*) echo "   (was $was)"; return ;; esac
  if [ "$now" -gt "$was" ]; then echo "   (was $was) ▲$((now-was))"; else echo "   (was $was) ▼$((was-now))"; fi; }
flag() { [ -n "$(prev_val "$2")" ] && [ "$(prev_val "$2")" != "$1" ] && echo "   (was $(prev_val "$2"))"; }
# Framework provenance. The citation checker proves an ID is real; nothing proves the CATALOGUE is
# current. This prints the age of the vendored index so drift is visible next to the suite counts
# rather than discovered by someone reading carefully. Reports only — a stale record leaves no other
# check verifying nothing (ADR-036), so it is a finding a human acts on, not a gate stop.
NIST_IDX="standards/data/controls/nist-800-53r5-index.json"
NIST_AGE="no index"
if [ -f "$NIST_IDX" ]; then
  _ret=$(sed -n 's/.*"_retrieved": *"\([0-9-]*\)".*/\1/p' "$NIST_IDX" | head -1)
  _ver=$(sed -n 's/.*"_catalog_version": *"\([^"]*\)".*/\1/p' "$NIST_IDX" | head -1)
  if [ -n "$_ret" ]; then
    _then=$(date -d "$_ret" +%s 2>/dev/null || date -j -f %Y-%m-%d "$_ret" +%s 2>/dev/null || echo "")
    if [ -n "$_then" ]; then
      NIST_AGE="r${_ver:-?} · $(( ( $(date +%s) - _then ) / 86400 ))d since $_ret"
    else
      NIST_AGE="r${_ver:-?} · retrieved $_ret"
    fi
  fi
fi

PREV_SHA="$(prev_val sha)"; BASELINE="${PREV_SHA:-none (first run — every number below is baseline)}"

if [ "$JSON_ONLY" -eq 0 ]; then
cat <<REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPO STATE @ ${SHA}   track:${APP_TRACK}   (reads HEAD · never remediates · never blocks)
  baseline: ${BASELINE}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  test suite files      : ${SUITE_FILES}$(delta "$SUITE_FILES" "$(prev_val suite_files)")
  suite run   T/P/F     : ${S_TOTAL}/${S_PASS}/${S_FAIL}$(delta "$S_FAIL" "$(prev_val suites_fail)")${S_NOTE}
  collection-risk files : ${COLLECT_RISK}$(delta "$COLLECT_RISK" "$(prev_val collect_risk)")
  .gitlab-ci.yml lines  : ${CI_LINES}$(delta "$CI_LINES" "$(prev_val ci_lines)")
  ci jobs               : ${CI_JOBS}$(delta "$CI_JOBS" "$(prev_val ci_jobs)")
  ci runs tests/lint    : ${CI_TEST_JOB}$(flag "$CI_TEST_JOB" ci_test_job)
  helm/templates files  : ${HELM_TEMPLATES}$(delta "$HELM_TEMPLATES" "$(prev_val helm_templates)")
  control manifest      : ${MANIFEST_RESULT}$(flag "$MANIFEST_RESULT" manifest)
  800-53 index age      : ${NIST_AGE}$(flag "$NIST_AGE" nist_age)
  orphaned exports (adv): ${DEAD_EXPORTS}$(delta "$DEAD_EXPORTS" "$(prev_val dead_exports)")
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Any ▲/▼ or a changed YES/NO is a delta against ${PREV_SHA:-no baseline}.
  • Caused by commits outside the engine → row in gate-records/gate-permanent-checks.md
    and a retro ticket — never a fix folded into the epic under gate.
  • Caused by the epic under gate        → reviewed inside this gate run.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORT
fi

SNAP="$HIST/$SHA.json"
cat > "$SNAP" <<JSON
{
  "sha": "${SHA}", "track": "${APP_TRACK}",
  "recorded": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "baseline": "${PREV_SHA}",
  "suite_files": "${SUITE_FILES}", "suites_total": "${S_TOTAL}",
  "suites_pass": "${S_PASS}", "suites_fail": "${S_FAIL}",
  "collect_risk": "${COLLECT_RISK}", "ci_lines": "${CI_LINES}",
  "ci_jobs": "${CI_JOBS}", "ci_test_job": "${CI_TEST_JOB}",
  "helm_templates": "${HELM_TEMPLATES}", "manifest": "${MANIFEST_RESULT}",
  "nist_age": "${NIST_AGE}",
  "dead_exports": "${DEAD_EXPORTS}"
}
JSON
# latest.json is the committed baseline the next gate reads. Only a gate run — one that passes
# --suites — may move it; a bare probe (a reviewer re-reading, a developer curious) writes its
# per-clone history snapshot and leaves the tracked file alone (SEC-GS-7).
[ -n "$SUITES_ARG" ] && cp "$SNAP" "$STATE_DIR/latest.json"
[ "$JSON_ONLY" -eq 1 ] && cat "$SNAP"
exit 0
