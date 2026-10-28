#!/usr/bin/env bash
# gate-prompt.sh — the handoff for the one gate (`make gate-prompt` prints it; `make gate` launches it).
#
# WHY THIS EXISTS
#   The gate runs in a clean context that must never see the build conversation — a subagent
#   started with nothing but this text (`make gate`, or an interactive session handing it to the
#   `gate` subagent). A subagent starting empty is all "fresh window" ever meant; nobody has to paste.
#   Everything the reviewer needs is derivable from git and project.config.yaml — the commit
#   range, the ticket IDs in it, the tier/track/provider, the mandatory reads — so this prints
#   exactly that. There is deliberately no free-text field: if build rationalization cannot be
#   typed in, it cannot cross the wall.
#
# PRECONDITION
#   `make gate-scan` must have run green on this exact commit — see core/securebuilderbot_core/precondition.py for
#   why that is a precondition rather than a step inside the gate.
#
# USAGE   engine/scripts/gate-prompt.sh [--checkpoint] [--regate] [--base <ref>]
#           --checkpoint   label the run a mid-epic checkpoint (findings only, no merge)
#           --base <ref>   the branch this epic was cut from, when it is not main: a stacked epic
#                          (epic/b cut from epic/a while epic/a's PR is still open) is gated on
#                          epic/a..HEAD, so the earlier epic's commits, which have their own
#                          gate-log rows, are not reviewed twice. The ref must exist; the block
#                          names it, so a reviewer sees the range is not main..HEAD.
#           --regate       range starts at the HEAD of this epic's last gate-log row, not at main.
#                          A re-gate reviews what changed since the last verdict; the full
#                          main..HEAD gate is the epic's first row and is not repeated — a green
#                          re-gate on the fixes is what the merge waits for. Refused when no prior
#                          row exists for this epic or its head is not an ancestor of HEAD.
#
# WHAT CHANGED (every prompt)
#   The prompt ends with a mechanical classification of the files in the range — production code,
#   tests, test harness, controls touched, dependencies, platform surface, governance, records —
#   and the gate steps that classification requires. The agents skip what it says to skip. It is
#   derived from git and the control manifest only, so it carries no build rationalization; the
#   reviewer can re-derive every line with `git diff --name-only`.
#
# EXIT    0 ok · 1 on main, main..HEAD is empty (nothing to gate), or --regate has no valid base

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1

CHECKPOINT=0; REGATE=0; BASE_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --checkpoint) CHECKPOINT=1 ;;
    --regate) REGATE=1 ;;
    --base) BASE_ARG="${2:-}"; [ -n "$BASE_ARG" ] || { echo "gate-prompt: --base needs a ref" >&2; exit 1; }; shift ;;
    --base=*) BASE_ARG="${1#--base=}" ;;
    *) echo "gate-prompt: unknown flag $1" >&2; exit 1 ;;
  esac
  shift
done

BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
case "$BRANCH" in
  main|master) echo "gate-prompt: you are on '$BRANCH'. The gate reviews an epic branch against main — check out epic/<slug> first." >&2; exit 1 ;;
esac
# Prefer origin/main over local main — the same ordering F-19 gave next.sh, for the same reason:
# you branch from the remote and a human merges the PR there, so local main is whatever it was when
# somebody last checked it out. Getting this wrong is worse here than in next.sh: the range lands in
# a prompt handed to a cold reviewer in a fresh window, who has no way to tell it is wrong and will
# review whatever they are given. On one project local main was an orphaned pre-rewrite history and
# this produced a 309-commit, 770-file "epic" range. Finding F-21.
BASE=""; for b in origin/main main origin/master master; do git rev-parse --verify -q "$b" >/dev/null 2>&1 && { BASE="$b"; break; }; done
[ -n "$BASE" ] || { echo "gate-prompt: no 'main' or 'origin/main' ref to compare against." >&2; exit 1; }
if [ -n "$BASE_ARG" ]; then
  git rev-parse --verify -q "${BASE_ARG}^{commit}" >/dev/null 2>&1 || { echo "gate-prompt: --base '$BASE_ARG' is not a ref in this repository." >&2; exit 1; }
  [ "$(git rev-parse "$BASE_ARG")" != "$(git rev-parse HEAD)" ] || { echo "gate-prompt: --base '$BASE_ARG' is HEAD itself; nothing to gate." >&2; exit 1; }
  BASE="$BASE_ARG"
fi

# Say so when local main is behind, so a stale checkout is visible rather than inferred later.
if [ "$BASE" = "origin/main" ] && git rev-parse --verify -q main >/dev/null 2>&1; then
  _behind="$(git rev-list --count main..origin/main 2>/dev/null || echo 0)"
  [ "${_behind:-0}" -gt 0 ] && echo "gate-prompt: note — local main is ${_behind} behind origin/main; gating against origin/main." >&2
fi

COUNT="$(git rev-list --count "$BASE..HEAD" 2>/dev/null || echo 0)"
[ "${COUNT:-0}" -gt 0 ] || { echo "gate-prompt: $BASE..HEAD is empty — nothing to gate." >&2; exit 1; }

# From the engine's first project (2026-10-03, GOV-034). MAX RE-GATE CAP.
#
# This runs BEFORE the scan precondition on purpose, and the order is the whole point. Every gate
# run needs a scan that is green on its exact commit, so a cap checked after that precondition
# would tell the operator to go and scan and only then refuse the handoff — having charged them the
# scan this rule exists to avoid. The refusal has to come first to save anything.
#
# A long chain of re-gates rescans the same tree for progressively smaller deltas; field-manual-ui
# reached run #12. Past a few rounds the full `main..HEAD` gate is both cheaper and more honest: it
# is the run that authorises the merge in any case, and one coherent range catches what a sequence
# of narrow deltas lets through — run #12 found four commits no quality gate had ever covered,
# which is precisely the shape a chain of re-gates produces.
#
# Counted as (Sentinel rows for this epic) - 1, because the first row is the full gate, not a
# re-gate. The cap applies ONLY to --regate, so it can never block a merge, only redirect it to the
# complete range. GATE_MAX_REGATES=off disables it.
EPIC=""; case "$BRANCH" in epic/*) EPIC="${BRANCH#epic/}" ;; esac
REGATE_SLUG_RE="$(printf '%s' "${EPIC:-$BRANCH}" | sed -E 's/[][\.|$(){}?+*^]/\\&/g')"
# The epic column is a bare slug on an epic/ branch; off one the gates write "<epic> (branch `<name>`)",
# so a bare-slug regex found none of seed-fix's three Sentinel rows and --regate refused (T-ENGINE-16).
REGATE_COL_RE="(${REGATE_SLUG_RE}|[^|]*\(branch \`${REGATE_SLUG_RE}\`\)[^|]*)"
# ── The gate log never stops a gate (2026-10-05) ─────────────────────
# It is a tracker. It used to refuse here: the re-gate cap counted Sentinel rows for this epic and
# exited 1 at three. A record that can refuse the thing it records is a record that has to be
# correct before work can proceed, and that is not what it is for.
#
# The cap's reasoning still holds — each re-gate rescans the whole tree for a smaller delta, and one
# coherent range catches what a chain of narrow deltas lets through — so it is still *said*, loudly,
# once. It just does not exit.
if [ "$REGATE" -eq 1 ] && [ "${GATE_MAX_REGATES:-3}" != "off" ]; then
  REGATE_CAP="${GATE_MAX_REGATES:-3}"
  _rows="$(grep -cE "^\| [0-9]{4}-[0-9]{2}-[0-9]{2} \| ${REGATE_COL_RE} \| .*\| Sentinel (PASS|FAIL)" gate-records/gate-log.md 2>/dev/null | head -1)"
  _rows="${_rows:-0}"
  _done=$(( _rows > 0 ? _rows - 1 : 0 ))
  if [ "$_done" -ge "$REGATE_CAP" ]; then
    echo "gate-prompt: NOTE — '${EPIC:-$BRANCH}' has already had $_done re-gate(s), past the advisory cap of $REGATE_CAP." >&2
    echo "             Proceeding anyway: the gate log is a tracker and never refuses a gate." >&2
    echo "             Worth considering: a full \`make gate\` on main..HEAD is the run that authorises" >&2
    echo "             the merge, and one coherent range catches what a chain of narrow deltas lets through." >&2
  fi
fi

# The tree must be scanned green before a reviewer is handed it. A CVE fix is a dependency bump,
# and a bump after the quality gate has run invalidates the coverage it just blessed. Scanning
# after the gate does not avoid that — only scanning before it does.
"$(dirname "${BASH_SOURCE[0]}")/../../core/run" scan-precondition || exit 1
# The override's warning goes to the terminal; the block is what the reviewer reads, so it says so
# there too, with the stamp it overrode (gate finding N-09).
SCAN_LINE="green on this commit (precondition held)"
if [ "${SKIP_SCAN_CHECK:-}" = "1" ]; then
  _stamp="${SCAN_RESULTS_DIR:-gate-records/scan/latest}/.scan-stamp"
  _s="$(awk '{ print substr($1, 1, 7) " " $2 }' "$_stamp" 2>/dev/null)"
  SCAN_LINE="PRECONDITION SKIPPED by SKIP_SCAN_CHECK=1 — last stamp: ${_s:-none}. Record it in the gate-log row."
fi

BASE_SHA="$(git rev-parse "$BASE")"; HEAD_SHA="$(git rev-parse HEAD)"
# No common ancestor means $BASE and HEAD are unrelated histories. Falling back to BASE_SHA here
# silently diffs two unrelated trees and reports every file as changed — the failure mode that made
# F-21 produce a whole-repository range. A range the reviewer cannot trust is worse than no range.
if ! MERGE_BASE="$(git merge-base "$BASE" HEAD 2>/dev/null)"; then
  echo "gate-prompt: '$BASE' and HEAD share no common ancestor — unrelated histories." >&2
  echo "             Nothing here can produce a meaningful range. Check that '$BASE' is the branch" >&2
  echo "             this work was cut from (git fetch; git log --oneline $BASE -1)." >&2
  exit 1
fi
cfg() {   # $1 = key in project.config.yaml
  [ -f project.config.yaml ] || return 0
  sed -nE "s/^[[:space:]]*$1:[[:space:]]*\"?([^\"#]*)\"?[[:space:]]*(#.*)?$/\1/p" project.config.yaml | head -1 | sed -E 's/[[:space:]]+$//'
}
TRACK="$(cfg APP_TRACK)"; TIER="$(cfg SECURITY_TIER)"; PROVIDER="$(cfg PROVIDER)"; APP_TYPE="$(cfg APP_TYPE)"
# EPIC and REGATE_SLUG_RE are computed above, before the scan precondition, because the re-gate cap
# needs them there (GOV-034).

# ── Re-gate: start where the last verdict stopped ────────────────────────────
# The last gate-log row for this epic names the head it reviewed. Everything before that head has
# a verdict already; a re-gate reviews only what landed after it. Without this, a one-ticket fix
# re-gates the whole epic (33 commits, 640 files, 17 mutations on a range where no control changed).
DIFF_FROM="$MERGE_BASE"; RANGE_LABEL="${BASE}..HEAD"; LAST_GATE=""; LAST_RUN=""
if [ "$REGATE" -eq 1 ]; then
  LOG="gate-records/gate-log.md"
  if [ -f "$LOG" ]; then
    # The base is the last SENTINEL row for this epic (or, off an epic/ branch, for this branch
    # name — the gates write the branch slug in the epic column). A quality-only row is half a gate
    # and a row for another epic is somebody else's verdict; neither is a head to re-gate from.
    slug_re="$REGATE_COL_RE"
    row="$(grep -E "^\| [0-9]{4}-[0-9]{2}-[0-9]{2} \| ${slug_re} \| " "$LOG" | grep -E '\| Sentinel (PASS|FAIL)' | tail -1)"
    # The head is the right side of the first `<rev>..<rev>` in the range column. A stacked row
    # carries a suffix (`b64709e..d41003f (stacked on epic/core, --base)`), so taking everything
    # after the last ".." read the suffix as part of the head and never resolved.
    LAST_GATE="$(printf '%s' "$row" | awk -F'|' '{print $4}' | grep -oE '[[:alnum:]/._~^-]+\.\.[0-9a-fA-F]{7,40}' | head -1 | sed -E 's/^.*\.\.//')"
    LAST_RUN="$(printf '%s' "$row" | awk -F'|' '{gsub(/ /,"",$5); print $5}')"
  fi
  # No usable prior row is not an error — the gate log never refuses (2026-10-05). The row
  # is an optimisation: it lets a re-gate review only what landed after the last verdict. Without
  # one, fall back to the full range, which is always a correct thing to review.
  # Each fallback below switches the re-gate off and leaves DIFF_FROM at the merge base with the
  # base (main, or the --base branch), so the full range is what gets reviewed. They are one chain:
  # a later test on an empty LAST_GATE would misreport why it fell back.
  if [ -z "$LAST_GATE" ] || ! git rev-parse --verify -q "${LAST_GATE}^{commit}" >/dev/null 2>&1; then
    echo "gate-prompt: no prior Sentinel row for '${EPIC:-$BRANCH}' resolves — reviewing the full range instead of a delta." >&2
    REGATE=0
  elif ! git merge-base --is-ancestor "$LAST_GATE" HEAD 2>/dev/null; then
    echo "gate-prompt: last gated head $LAST_GATE is not an ancestor of HEAD — history was rewritten." >&2
    echo "             Reviewing the full range instead of a delta; the gate log never refuses a gate." >&2
    REGATE=0
  elif [ "$(git rev-parse "$LAST_GATE")" = "$HEAD_SHA" ]; then
    # HEAD already carries a verdict, so the delta is empty. That is worth saying and is not an
    # error: fall back to the full range, which is always a correct thing to review.
    echo "gate-prompt: HEAD already carries run #${LAST_RUN:-?}'s verdict, so the delta is empty." >&2
    echo "             Reviewing the full range instead; the gate log never refuses a gate." >&2
    REGATE=0
  fi
  if [ "$REGATE" -eq 1 ]; then
    DIFF_FROM="$(git rev-parse "$LAST_GATE")"; RANGE_LABEL="${LAST_GATE}..HEAD"
  else
    LAST_GATE=""; LAST_RUN=""
  fi
fi

FILES="$(git diff --name-only "$DIFF_FROM" HEAD 2>/dev/null | wc -l | tr -d ' ')"
COUNT="$(git rev-list --count "$DIFF_FROM..HEAD" 2>/dev/null || echo 0)"
# From the engine's first project (2026-10-03, GOV-024). The pattern was `T-[0-9]{3,}` — three or more digits
# after `T-`. GOV-018 made ticket ids epic-scoped (`T-ONEROW-01`, `T-ENGINE-07`), which that pattern cannot
# match, so the gate prompt listed NONE of an epic's own tickets and instead listed whatever old `T-nnn` ids
# happened to be quoted in the commit prose. Measured on epic/one-row-model: nine historical ids, none of
# the seven the epic built. A reviewer reading the wrong tickets reviews against the wrong intent.
# Both forms are accepted, because the legacy flat ids are still live and still cited.
TICKETS="$(git log --format='%s%n%b' "$DIFF_FROM..HEAD" 2>/dev/null | grep -oE '\bT-([A-Z][A-Z0-9]*-[0-9]{2,}|[0-9]{3,})\b' | sort -u | tr '\n' ' ' | sed -E 's/ $//')"

# ── What changed, mechanically ───────────────────────────────────────────────
CHANGED="$(git diff --name-only "$DIFF_FROM" HEAD 2>/dev/null)"
cls() { printf '%s\n' "$CHANGED" | grep -cE "$1" 2>/dev/null; }
# Harness definition is shared with qa/scripts/mutate-controls.sh (harness_re) — keep the two identical.
N_HARNESS=$(cls '^(backend/src/test/|backend/jest\.config|backend/package\.json$|backend/package-lock\.json$|backend/src/__mocks__/|android/(app/)?build\.gradle(\.kts)?$)')
# Gate tooling: the scripts and Makefile that decide what the gate checks. A range that changes only
# these would otherwise land in no class and read as "nothing to do" — the one change that must
# never escape review is a change to the reviewer.
N_TOOLING=$(cls '^(engine/scripts/|qa/scripts/|standards/(data/controls|scripts)/|Makefile(\.project)?$|(.*/)?\.gitignore$|\.githooks/|\.doc-paths-ignore$|\.hadolint\.yaml$|renovate\.json$|project\.config\.yaml$|(.*/)?\.dockerignore$|backend/(\.eslintrc|eslint\.config|tsconfig)|frontend/(vite|vitest|tsconfig|eslint|postcss|tailwind))')
CTRL_HARNESS_RE="$(cfg CONTROL_HARNESS_RE)"
if [ -n "$CTRL_HARNESS_RE" ]; then N_HARNESS=$((N_HARNESS + $(cls "$CTRL_HARNESS_RE"))); fi
N_MUTATOR=$(cls '^qa/scripts/(mutate-controls\.sh|verify-controls\.sh|_lib\.sh)$')
# A project whose code is not a web or android app names its control roots and test directory in
# project.config.yaml (CONTROL_SRC_ROOTS, CONTROL_TEST_DIR); they are production code and tests here
# too, or the handoff tells the reviewer coverage is "no" on a range that is all code (F-03, N-02).
cfg_re() { cfg "$1" | tr ' ' '\n' | grep . | sed -E 's/[.]/\\./g; s#/*$#/#; s#^#^#' | paste -sd'|' -; }
CTRL_SRC_RE="$(cfg_re CONTROL_SRC_ROOTS)"; CTRL_TEST_RE="$(cfg_re CONTROL_TEST_DIR)"
N_TESTS=$(cls "^(backend/src/__tests__/|frontend/src/.*\.(test|spec)\.|android/app/src/test/)${CTRL_TEST_RE:+|$CTRL_TEST_RE}")
N_PROD=$(printf '%s\n' "$CHANGED" | grep -E "^(backend/src/|frontend/src/|frontend/index\.html$|android/app/src/main/)${CTRL_SRC_RE:+|$CTRL_SRC_RE}" | grep -vE '^(backend/src/test/|backend/src/__tests__/|backend/src/__mocks__/|frontend/src/.*\.(test|spec)\.)' | grep -c . 2>/dev/null)
N_ROUTES=$(printf '%s\n' "$CHANGED" | grep -cE '^backend/src/(routes|controllers)/' 2>/dev/null)
N_DEPS=$(cls '(^|/)(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|build\.gradle(\.kts)?|gradle\.lockfile|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|Pipfile(\.lock)?|uv\.lock)$')
N_PLATFORM=$(cls '^(helm/|terraform/|\.gitlab-ci\.yml$|\.github/workflows/|docker-compose[^/]*\.yml$|\.env|project\.config\.yaml$|docker/|(.*/)?Dockerfile|(.*/)?nginx[^/]*\.conf|(.*/)?docker-entrypoint\.sh$)')
N_GOV=$(cls '^(CLAUDE\.md$|\.claude/|engine/[A-Z_-]+\.md$|engine/skills/)')
N_RECORDS=$(cls '^(gate-records/|planning/|docs/)')
# Controls touched: a manifest row counts when its implementation file or its proving test changed.
CONTROLS=""; MANIFEST="docs/security/CONTROL-MANIFEST.md"
if [ -f "$MANIFEST" ] && [ -n "$CHANGED" ]; then
  tglob="backend/src/__tests__"; [ "$TRACK" = "android" ] && tglob="android/app/src/test"
  BASE_M="$(git show "$DIFF_FROM:$MANIFEST" 2>/dev/null || true)"   # rows added or edited since count as touched (T-SLIM-14/15)
  while IFS= read -r line; do
    case "$line" in "| CM-"*) : ;; *) continue ;; esac
    id=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$2); print $2}')
    impl=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$4); gsub(/`/,"",$4); print $4}')
    tst=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$6); gsub(/`/,"",$6); print $6}')
    case "$impl" in ""|"-"|"—"|"<"*) continue ;; esac
    f="${impl%%:*}"; hit=0
    [ "$(printf '%s\n' "$BASE_M" | grep -m1 -E "^\| *$id \|" || true)" = "$line" ] || hit=1
    grep -qxF "$f" <<<"$CHANGED" && hit=1
    if [ "$hit" -eq 0 ] && [ -n "$tst" ] && [ "$tst" != "-" ] && [ "$tst" != "—" ]; then
      pat="$(printf '%s' "$tst" | sed -E 's/[.]/\\./g; s/\*/.*/g')"
      grep -qE "^${tglob}/${pat}$" <<<"$CHANGED" && hit=1
    fi
    [ "$hit" -eq 1 ] && CONTROLS="${CONTROLS:+$CONTROLS,}$id"
  done < "$MANIFEST"
fi
# Mutation at the gate is scoped to what the range touched (2026-10-03). `--since` the range's
# base (the last gated head on a re-gate) mutates the rows whose implementation or proving test
# changed, and widens to every row by itself when the test harness changed. There is no nightly
# (2026-10-12): an unchanged row is cited to the gate-log row that last ran it on this code, or it
# is run. Measured before --since: 43 backend rows, 38 min.
SINCE_REV="${DIFF_FROM:0:7}"; [ "$REGATE" -eq 1 ] && SINCE_REV="$LAST_GATE"
if [ "$N_HARNESS" -gt 0 ]; then MUTATE_STEP="make mutate-controls ARGS=\"--since ${SINCE_REV}\" — the test harness changed, so --since widens to every row by itself"
elif [ "$N_MUTATOR" -gt 0 ]; then MUTATE_STEP="make mutate-controls ARGS=\"--since ${SINCE_REV}\" — the mutation tool itself changed: touched rows here (${CONTROLS:-none}); untouched rows cite the gate-log row that last ran them, or run"
elif [ -n "$CONTROLS" ]; then MUTATE_STEP="make mutate-controls ARGS=\"--since ${SINCE_REV}\" (touched: ${CONTROLS})"
elif [ "$REGATE" -eq 1 ]; then MUTATE_STEP="none — no control implementation or proving test changed since ${LAST_GATE}; cite run #${LAST_RUN:-?}"
else MUTATE_STEP="none — no control implementation or proving test in the range; unchanged rows cite the gate-log row that last ran them on this code, or get run"; fi
N_FE=$(cls '^frontend/src/')
if [ "$N_FE" -gt 0 ]; then FE_STEP="make mutate-frontend ARGS=\"--since ${SINCE_REV}\" (${N_FE} frontend/src file(s); a test change widens to every row)"
else FE_STEP="none — frontend/src unchanged"; fi
if [ "$N_HARNESS" -gt 0 ]; then SUITE_STEP="3 consecutive runs (test harness changed: flake check applies)"; else SUITE_STEP="1 run (harness unchanged; 3 only if it fails)"; fi
[ "$N_PROD" -gt 0 ] && COVERAGE_STEP="yes — ${N_PROD} production file(s) changed" || COVERAGE_STEP="no — no production code in range"
[ "$N_PROD" -gt 0 ] && VERIFY_STEP="yes" || VERIFY_STEP="no — no production code in range; cite the last PASS"
[ "$N_ROUTES" -gt 0 ] && NEG_STEP="yes — ${N_ROUTES} route/controller file(s) changed" || NEG_STEP="nothing to enumerate — no route files changed (say so, do not pass in silence)"
[ "$N_DEPS" -gt 0 ] && DP_STEP="yes" || DP_STEP="N/A — no dependency files changed"
[ "$N_PLATFORM" -gt 0 ] && PLAT_STEP="yes — ${N_PLATFORM} file(s); names only, never values" || PLAT_STEP="report 'no platform files changed in range'"
[ "$N_GOV" -gt 0 ] && GOV_STEP="yes — ${N_GOV} rulebook/agent/skill file(s): each change in a commit of its own, for the human to read (engine/GOVERNANCE.md)" || GOV_STEP="N/A — no governance files changed"
# Review depth (slim, T-SLIM-03): deep or light by path, never by the reviewer's judgement. The expensive
# half of the review — CC, AR, EH — runs only on a deep range. See core/securebuilderbot_core/classify.py for the rules.
DEPTH="$("$(dirname "${BASH_SOURCE[0]}")/../../core/run" classify "${DIFF_FROM}..${HEAD_SHA}" --why)"
DEPTH_WORD="$(printf '%s\n' "$DEPTH" | head -1)"
DEPTH_WHY="$(printf '%s\n' "$DEPTH" | sed -n '2,4p' | sed -E 's/^ +//' | paste -sd ';' - | sed 's/;/; /g')"
if [ "$DEPTH_WORD" = "deep" ]; then
  REVIEW_STEP="deep — Control Completeness Review, adversarial review (AR) and edge-case hunt (EH) required (${DEPTH_WHY})"
else
  REVIEW_STEP="light — CC, AR and EH skipped: ${DEPTH_WHY}. Checklist, CM, negative tests and scan still run"
fi
[ "$N_TOOLING" -gt 0 ] && TOOL_STEP="yes — ${N_TOOLING} gate-tooling file(s): run make gate-selftest, engine/scripts/tests/*.sh, qa/tests/*-test.sh, make check-gate-docs; read every hunk" || TOOL_STEP="N/A — no gate tooling changed"


KIND="EPIC GATE"; [ "$CHECKPOINT" -eq 1 ] && KIND="MID-EPIC CHECKPOINT (findings only — no merge)"
[ "$REGATE" -eq 1 ] && KIND="RE-GATE — delta since run #${LAST_RUN:-?} (${LAST_GATE}); the full ${BASE}..HEAD gate is run #1's row and is not repeated"

cat <<PROMPT
────────────────────────────── gate handoff ──────────────────────────────
# ${KIND} — ${BRANCH}

Range:   ${RANGE_LABEL}$( [ -n "$BASE_ARG" ] && printf ' — stacked on %s (--base): that branch has its own gate-log rows and is not reviewed here' "$BASE_ARG" )
  ${BASE} @ ${BASE_SHA}$( [ "$REGATE" -eq 1 ] && printf '\n  last gated head @ %s (run #%s) — diff from here' "$DIFF_FROM" "${LAST_RUN:-?}" )
  HEAD @ ${HEAD_SHA}$( [ "$REGATE" -eq 0 ] && [ "$MERGE_BASE" != "$BASE_SHA" ] && printf '\n  merge-base %s (diff the branch against this)' "$MERGE_BASE" )
  ${COUNT} commit(s) · ${FILES} file(s) changed
Epic:    ${EPIC:-none (branch is not epic/<slug>)}
Tickets: ${TICKETS:-none found in commit messages}
Project: APP_TRACK=${TRACK:-UNSET} · SECURITY_TIER=${TIER:-UNSET} · PROVIDER=${PROVIDER:-UNSET} · APP_TYPE=${APP_TYPE:-n/a}
Scan:    ${SCAN_LINE}

Gate definition: .claude/agents/gate.md — follow it exactly.
Read before anything else:
- CLAUDE.md
- engine/SENTINEL-CHECKLIST.md
- engine/QUALITY_GATE.md
- docs/security/CONTROL-MANIFEST.md
- docs/architecture/DEPENDENCY_POLICY.md (only when dependencies changed)
PROMPT
for t in $TICKETS; do
  # From the engine's first project (2026-10-02, GOV-021): per-epic folders, archive included — a gate
  # may cite a ticket that has since been archived.
  for f in planning/tickets/"$t"-*.md planning/tickets/*/"$t"-*.md planning/tickets/_archive/*/"$t"-*.md; do [ -f "$f" ] && echo "- $f"; done
done
cat <<PROMPT

What changed (from \`git diff --name-only ${DIFF_FROM:0:7}..HEAD\`; re-derive it, do not trust it):
  production code : ${N_PROD}   tests: ${N_TESTS}   test harness: ${N_HARNESS}   routes/controllers: ${N_ROUTES}
  dependencies    : ${N_DEPS}   platform surface: ${N_PLATFORM}   governance: ${N_GOV}   gate tooling: ${N_TOOLING}   records/docs: ${N_RECORDS}
  controls touched: ${CONTROLS:-none}

Steps this range requires (skip what is not required; say what was skipped and why in the record):
  review depth     : ${REVIEW_STEP}
  suite            : ${SUITE_STEP}
  coverage on range: ${COVERAGE_STEP}
  negative tests   : ${NEG_STEP}
  mutation check   : ${MUTATE_STEP}
  frontend mutation: ${FE_STEP}
  verify-controls  : ${VERIFY_STEP}
  dependencies (DP): ${DP_STEP}
  platform surface : ${PLAT_STEP}
  governance       : ${GOV_STEP}
  gate tooling     : ${TOOL_STEP}
  gate-state       : always (it is fast now); pass --suites from the run above

Run the gate (.claude/agents/gate.md) on this range: Part 1, then Part 2 at the depth above. Print the
verdict block last — it goes into the PR description — and write one gate-log row. Do not read this
branch's conversation history.
────────────────────────────── end of handoff ────────────────────────────────
PROMPT
exit 0
