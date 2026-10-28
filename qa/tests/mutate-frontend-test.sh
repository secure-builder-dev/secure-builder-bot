#!/usr/bin/env bash
# Fixture tests for qa/scripts/mutate-frontend.py.
#
# WHY THIS FILE EXISTS. `make mutate-frontend` is a gate input: GOV-010 made a NOT PROVEN row
# blocking, so the harness deciding what "proven" means is itself load-bearing — and it had no test
# of any kind. T-074, T-078 and T-080 are all defects in it that shipped because nothing exercised
# it. The specific shape these cases guard is a FALSE PASS: an exit 0 that proves nothing.
#
# WHERE. The harness and this fixture are the qa module's (qa/scripts, qa/tests) since 2026-10-23;
# they moved together, so the fixture stays on the same side of the line as the thing it tests.
#
# HOW IT WORKS. Every case builds a throwaway git repo under a temp directory — the harness calls
# `git rev-parse --show-toplevel` and chdirs there, so nothing runs against the project tree — holding
# a small FRONTEND-MUTATIONS.md and a stub frontend/ file. The suite is a canned command supplied
# through MUTATE_FRONTEND_TEST_CMD / MUTATE_FRONTEND_ROW_TEST_CMD, the same fake-suite approach the
# engine's own selftest uses for mutate-controls, so a case takes milliseconds and never runs vitest.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HARNESS="$PROJECT_ROOT/qa/scripts/mutate-frontend.py"

PASS=0; FAIL=0
_pass() { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
_fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n       %s\n' "$1" "$2"; }

# A git repo with one mutation row and a stub source file whose `from` text occurs exactly once.
make_repo() {
  local dir; dir="$(mktemp -d)"
  mkdir -p "$dir/frontend/src" "$dir/docs/security" "$dir/gate-records"
  cat > "$dir/docs/security/FRONTEND-MUTATIONS.md" <<'EOF'
| id | file | from | to | proves |
|---|---|---|---|---|
| FM-01 | src/stub.ts | `const guard = true;` | `const guard = false;` | a stub row for the fixture |
EOF
  printf 'const guard = true;\nexport default guard;\n' > "$dir/frontend/src/stub.ts"
  printf 'placeholder\n' > "$dir/gate-records/notes.md"
  git -C "$dir" init -q
  git -C "$dir" config user.email fixture@example.test
  git -C "$dir" config user.name Fixture
  git -C "$dir" add -A >/dev/null
  git -C "$dir" commit -qm 'base'
  printf '%s' "$dir"
}

# Output goes to a file and the exit status is this function's own. A variable set inside `$( )`
# is set in a subshell and is invisible to the caller — which is exactly how the first cut of this
# fixture reported rc=0 for a harness that had correctly exited 2.
OUT_FILE="$(mktemp)"
trap 'rm -f "$OUT_FILE"' EXIT
run_harness() {   # run_harness <repo> <args...>  -> output in $OUT_FILE, status is the return value
  local repo="$1"; shift
  ( cd "$repo" && MUTATE_FRONTEND_TEST_CMD="${TEST_CMD:-true}" \
    MUTATE_FRONTEND_ROW_TEST_CMD="${ROW_CMD:-false}" \
    python3 "$HARNESS" "$@" ) > "$OUT_FILE" 2>&1
}

echo "mutate-frontend fixture tests"

# ── T-080: --since with a revision the harness cannot resolve ────────────────
# The failure being guarded: an unresolvable revision used to yield an EMPTY change list, so every
# row landed in since_skip and the harness exited 0 having mutated nothing. A re-gate would read
# that as "all rows proven".
repo="$(make_repo)"
run_harness "$repo" --since 0000000deadbeef --only FM-01; rc=$?; out="$(cat "$OUT_FILE")"
if [ "$rc" -eq 2 ] && grep -q 'not a commit' <<<"$out"; then
  _pass "--since with an unresolvable revision exits 2 and says 'not a commit'"
else
  _fail "--since with an unresolvable revision exits 2 and says 'not a commit'" "rc=$rc out=${out:0:200}"
fi

# ── T-080: --since with a commit that is not an ancestor (the force-push case) ─
# rev-parse alone does not catch this: after a rebase the old head usually still resolves from the
# object store, so the scope silently becomes empty.
repo="$(make_repo)"
git -C "$repo" checkout -q -b diverged
printf 'const other = 1;\n' > "$repo/frontend/src/other.ts"
git -C "$repo" add -A >/dev/null && git -C "$repo" commit -qm 'diverged'
side="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q - 2>/dev/null || git -C "$repo" checkout -q master 2>/dev/null || git -C "$repo" checkout -q main
run_harness "$repo" --since "$side" --only FM-01; rc=$?; out="$(cat "$OUT_FILE")"
if [ "$rc" -eq 2 ] && grep -q 'not an ancestor' <<<"$out"; then
  _pass "--since with a non-ancestor commit exits 2 and says 'not an ancestor'"
else
  _fail "--since with a non-ancestor commit exits 2 and says 'not an ancestor'" "rc=$rc out=${out:0:200}"
fi

# ── T-080: a harness-file change widens to every row ─────────────────────────
# src/test/setup.ts is loaded before every test file, so it can change whether ANY row goes red while
# being no row's `file`. Narrowing past it would run a subset and call the range proven.
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
mkdir -p "$repo/frontend/src/test"
printf 'export const x = 1;\n' > "$repo/frontend/src/test/setup.ts"
git -C "$repo" add -A >/dev/null && git -C "$repo" commit -qm 'touch harness'
TEST_CMD=true ROW_CMD=false run_harness "$repo" --since "$base" --dry-run; rc=$?; out="$(cat "$OUT_FILE")"
if grep -qi 'every row' <<<"$out"; then
  _pass "a change to frontend/src/test/ widens the scope to every row"
else
  _fail "a change to frontend/src/test/ widens the scope to every row" "rc=$rc out=${out:0:300}"
fi

# ── T-080: a records-only change narrows to zero rows and still exits 0 ──────
# The predicate is "the scope could not be computed", never "zero rows ran". Zero rows is the
# legitimate records-only case; failing on it would make every docs commit red.
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
printf 'a note\n' >> "$repo/gate-records/notes.md"
git -C "$repo" add -A >/dev/null && git -C "$repo" commit -qm 'records only'
TEST_CMD=true ROW_CMD=false run_harness "$repo" --since "$base"; rc=$?; out="$(cat "$OUT_FILE")"
if [ "$rc" -eq 0 ]; then
  _pass "a records-only change narrows to zero rows and exits 0"
else
  _fail "a records-only change narrows to zero rows and exits 0" "rc=$rc out=${out:0:300}"
fi

# ── T-077: a red baseline prints what it captured ───────────────────────────
# The harness ran the suite, held the whole output in memory, printed two sentences and threw the
# evidence away — so the first move after a red baseline was always to re-run the suite by hand.
# `--only NOPE` matches no row, so the baseline runs and the row loop does not; `--dry-run` would
# skip the baseline entirely and prove nothing here.
repo="$(make_repo)"
TEST_CMD='printf "SENTINEL-BASELINE-LINE\nTests  1 failed (1)\n"; exit 1' \
  ROW_CMD=false run_harness "$repo" --only NOPE; rc=$?; out="$(cat "$OUT_FILE")"
if [ "$rc" -eq 1 ] && grep -q 'SENTINEL-BASELINE-LINE' <<<"$out"; then
  _pass "a red baseline exits 1 and prints the output it captured"
else
  _fail "a red baseline exits 1 and prints the output it captured" "rc=$rc out=${out:0:300}"
fi

# ── T-077: a green baseline stays quiet ─────────────────────────────────────
repo="$(make_repo)"
TEST_CMD=true ROW_CMD=false run_harness "$repo" --only NOPE; rc=$?; out="$(cat "$OUT_FILE")"
if grep -q 'green' <<<"$out" && ! grep -q 'captured baseline output' <<<"$out"; then
  _pass "a green baseline prints no captured-output banner"
else
  _fail "a green baseline prints no captured-output banner" "rc=$rc out=${out:0:300}"
fi

printf '\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
