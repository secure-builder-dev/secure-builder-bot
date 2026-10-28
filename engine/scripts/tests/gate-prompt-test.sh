#!/usr/bin/env bash
# gate-prompt tests — the range handed to a cold reviewer must be the right one.
#
# WHY   The gate prompt is consumed in a fresh window by a reviewer with no context. If the base ref
#       is wrong the range is wrong, and nothing downstream can detect it: the reviewer reviews what
#       they are given. F-21 was exactly this — local main was an orphaned pre-rewrite history, so
#       `main..HEAD` reported 309 commits and 770 files for a 15-commit epic.
#
#       Every case below that expects exit 1 is a negative fixture. A base-resolution check that has
#       never been observed rejecting a bad base is indistinguishable from one that always passes.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GP="$SCRIPT_DIR/../gate-prompt.sh"

PASS=0; FAIL=0
_pass() { echo "  ok    $1"; PASS=$((PASS + 1)); }
_fail() { echo "  FAIL  $1 — $2"; FAIL=$((FAIL + 1)); }

echo "── gate-prompt: base resolution ──"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# mkrepo <dir> — a repo with a REMOTE main and a LOCAL main that disagree.
# origin/main carries the real history; local main is left on an unrelated orphan branch, which is
# the F-21 shape. HEAD is an epic branch cut from origin/main.
mkrepo() {
  local d="$1"
  mkdir -p "$d/remote" "$d/work"
  ( cd "$d/remote" && git init -q --bare . )
  ( cd "$d/work" && git init -q . && git config user.email t@t && git config user.name t \
      && git remote add origin "$d/remote" \
      && printf 'APP_TRACK: web\n' > project.config.yaml \
      && git add -A && git commit -qm "base" \
      && echo one > a.txt && git add -A && git commit -qm "real history 1" \
      && git push -q origin main 2>/dev/null || git push -q origin master:main 2>/dev/null
  )
}

# ── Case 1: local main is an orphan; origin/main is correct ──────────────────
d="$TMP/c1"; mkrepo "$d"
(
  cd "$d/work"
  git checkout -q --orphan stale-main
  git rm -rqf . 2>/dev/null || true
  printf 'APP_TRACK: web\n' > project.config.yaml
  echo junk > junk.txt; git add -A; git commit -qm "orphaned history"
  git branch -qM main 2>/dev/null || git branch -qf main HEAD
  git checkout -q -b epic/thing origin/main
  echo two > b.txt; git add -A; git commit -qm "epic work"
) >/dev/null 2>&1

out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" 2>&1 )"; rc=$?
if [ "$rc" -eq 0 ] && grep -q 'origin/main\.\.HEAD\|Range:[[:space:]]*origin/main' <<<"$out"; then
  _pass "prefers origin/main when local main is an unrelated orphan"
else
  _pass_note="$(printf '%s' "$out" | grep -i 'Range:' | head -1)"
  if grep -q '^Range:[[:space:]]*main\.\.HEAD' <<<"$out"; then
    _fail "prefers origin/main when local main is an unrelated orphan" "resolved to local main: $_pass_note"
  else
    _fail "prefers origin/main when local main is an unrelated orphan" "rc=$rc ${_pass_note:-no Range line}"
  fi
fi

# The range must be the epic's, not the whole repository. This is the symptom F-21 actually showed.
commits="$(printf '%s' "$out" | grep -oE '^[[:space:]]*[0-9]+ commit\(s\)' | grep -oE '[0-9]+' | head -1)"
if [ "${commits:-0}" -le 2 ] && [ "${commits:-0}" -ge 1 ]; then
  _pass "range is the epic's commits, not the whole history (${commits})"
else
  _fail "range is the epic's commits, not the whole history" "counted ${commits:-none}"
fi

# ── Case 2: unrelated histories must be refused, not silently diffed ─────────
d="$TMP/c2"; mkdir -p "$d"
(
  cd "$d" && git init -q . && git config user.email t@t && git config user.name t
  printf 'APP_TRACK: web\n' > project.config.yaml
  echo a > a.txt; git add -A; git commit -qm "main history"
  git branch -qM main 2>/dev/null || true
  git checkout -q --orphan epic/unrelated
  git rm -rqf . 2>/dev/null || true
  printf 'APP_TRACK: web\n' > project.config.yaml
  echo b > b.txt; git add -A; git commit -qm "unrelated work"
) >/dev/null 2>&1

out="$( cd "$d" && SKIP_SCAN_CHECK=1 bash "$GP" 2>&1 )"; rc=$?
if [ "$rc" -ne 0 ] && grep -qi 'no common ancestor\|unrelated histories' <<<"$out"; then
  _pass "refuses a base that shares no ancestor with HEAD"
else
  _fail "refuses a base that shares no ancestor with HEAD" "rc=$rc, said: $(printf '%s' "$out" | head -1)"
fi

# ── Case 3: --regate starts at the last gate-log row's head, not at main ─────
d="$TMP/c3"; mkrepo "$d"
(
  cd "$d/work" && git checkout -q -b epic/thing origin/main
  echo two > b.txt; git add -A; git commit -qm "epic work 1 T-001"
  first="$(git rev-parse --short HEAD)"
  mkdir -p gate-records
  printf '| date | epic | range | run # | findings | retro | verdict | reviewer |\n|---|---|---|---|---|---|---|---|\n' > gate-records/gate-log.md
  printf '| 2026-01-01 | thing | `origin/main..%s` | 1 | 0 | — | Sentinel PASS | t@t |\n' "$first" >> gate-records/gate-log.md
  git add -A; git commit -qm "gate row"
  echo three > c.txt; git add -A; git commit -qm "fix T-002"
) >/dev/null 2>&1

out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" --regate 2>&1 )"; rc=$?
commits="$(printf '%s' "$out" | grep -oE '^[[:space:]]*[0-9]+ commit\(s\)' | grep -oE '[0-9]+' | head -1)"
if [ "$rc" -eq 0 ] && grep -q '^# RE-GATE' <<<"$out" && [ "${commits:-0}" -eq 2 ]; then
  _pass "--regate ranges from the last gated head (2 commits after it, not the epic's 3)"
else
  _fail "--regate ranges from the last gated head" "rc=$rc commits=${commits:-none}: $(printf '%s' "$out" | head -2 | tr '\n' ' ')"
fi
if grep -q 'Tickets: T-002' <<<"$out" && ! grep -q 'T-001' <<<"$out"; then
  _pass "--regate lists only tickets in the delta"
else
  _fail "--regate lists only tickets in the delta" "$(printf '%s' "$out" | grep Tickets)"
fi
if grep -q 'mutation check   : none' <<<"$out" && grep -q 'coverage on range: no' <<<"$out"; then
  _pass "records-only delta requires no mutation or coverage"
else
  _fail "records-only delta requires no mutation or coverage" "$(printf '%s' "$out" | grep -E 'mutation|coverage')"
fi

# ── Case 4: --regate with no prior row falls back; it does not refuse ────────
# Changed 2026-10-05: the gate log is a tracker and never stops a gate. It used to refuse
# here. The row is an optimisation — it lets a re-gate review only what landed after the last
# verdict — so without one the correct behaviour is to review the full range, which is always a
# valid thing to review. Asserting the fallback, not the refusal.
d="$TMP/c4"; mkrepo "$d"
( cd "$d/work" && git checkout -q -b epic/other origin/main && echo x > x.txt && git add -A && git commit -qm "w" ) >/dev/null 2>&1
out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" --regate 2>&1 )"; rc=$?
if [ "$rc" -eq 0 ] && grep -q 'reviewing the full range' <<<"$out" && grep -q '1 commit(s) · 1 file(s) changed' <<<"$out"; then
  _pass "--regate without a prior gate row falls back to the full range"
else
  _fail "--regate without a prior gate row falls back to the full range" "rc=$rc: $(printf '%s' "$out" | head -2 | tr '\n' ' ')"
fi

# ── Case 5: the gate log cannot refuse a gate, whatever it contains ─────────
# The cap used to count Sentinel rows and exit 1 at three. It is advisory now.
d="$TMP/c5"; mkrepo "$d"
( cd "$d/work" && git checkout -q -b epic/capped origin/main && echo y > y.txt && git add -A && git commit -qm "w" \
  && mkdir -p gate-records \
  && { for n in 1 2 3 4 5; do printf '| 2026-10-05 | capped | `aaaaaaa..bbbbbbb` | %s | none | none | Sentinel PASS (deep) | x@y.mil |\n' "$n"; done; } >> gate-records/gate-log.md \
  && git add -A && git commit -qm "rows" ) >/dev/null 2>&1
out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" --regate 2>&1 )"; rc=$?
if [ "$rc" -eq 0 ]; then
  _pass "a gate log past the re-gate cap does not refuse"
else
  _fail "a gate log past the re-gate cap does not refuse" "rc=$rc: $(printf '%s' "$out" | head -2 | tr '\n' ' ')"
fi

# ── Case 6: a project's own control roots are production code (gate finding N-02) ──
d="$TMP/c6"; mkrepo "$d"
( cd "$d/work" && git checkout -q -b epic/py origin/main \
  && printf 'APP_TRACK: web\nCONTROL_SRC_ROOTS: core/pkg\nCONTROL_TEST_DIR: core/tests\nCONTROL_HARNESS_RE: ^pytest\\.ini$\n' > project.config.yaml \
  && mkdir -p core/pkg core/tests && echo 'x = 1' > core/pkg/a.py && echo 'y = 1' > core/tests/test_a.py \
  && echo 'PyYAML==6.0.2' > core/requirements.txt && printf '[pytest]\n' > pytest.ini \
  && git add -A && git commit -qm "python" ) >/dev/null 2>&1
out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" 2>&1 )"
if grep -q 'production code : 1   tests: 1   test harness: 1' <<<"$out" \
   && grep -q 'dependencies    : 1 ' <<<"$out" && grep -q 'coverage on range: yes' <<<"$out"; then
  _pass "CONTROL_* roots count as production code, tests and harness; requirements.txt is a dependency"
else
  _fail "CONTROL_* roots count as production code, tests and harness; requirements.txt is a dependency" "$(printf '%s' "$out" | grep -E 'production code|dependencies ' | tr '\n' ' ')"
fi

# ── Case 7: an override of the scan precondition is marked inside the block (gate finding N-09) ──
d="$TMP/c7"; mkrepo "$d"
( cd "$d/work" && git checkout -q -b epic/skip origin/main && echo z > z.txt && git add -A && git commit -qm "w" \
  && mkdir -p gate-records/scan/latest && printf 'abcdef0123456789 FAIL 2026-10-15T00:00:00Z\n' > gate-records/scan/latest/.scan-stamp ) >/dev/null 2>&1
out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" 2>/dev/null )"
block="$(printf '%s' "$out" | sed -n '/gate handoff/,/end of handoff/p')"
if grep -q '^Scan:    PRECONDITION SKIPPED by SKIP_SCAN_CHECK=1 — last stamp: abcdef0 FAIL' <<<"$block"; then
  _pass "a skipped scan precondition is named inside the handoff block, with the stamp it overrode"
else
  _fail "a skipped scan precondition is named inside the handoff block" "$(printf '%s' "$block" | grep -E '^Scan:' || echo 'no Scan: line')"
fi

# ── Case 8: a stacked epic is gated against the branch it was cut from (--base) ──
d="$TMP/c8"; mkrepo "$d"
( cd "$d/work" && git checkout -q -b epic/first origin/main && echo f > f.txt && git add -A && git commit -qm "first epic" \
  && git checkout -q -b epic/second && echo s > s.txt && git add -A && git commit -qm "second epic" ) >/dev/null 2>&1
out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" --base epic/first 2>/dev/null )"
if grep -q '^Range:   epic/first\.\.HEAD — stacked on epic/first' <<<"$out" && grep -q '1 commit(s) · 1 file(s) changed' <<<"$out"; then
  _pass "--base gates only the commits after the branch the epic was cut from, and says so"
else
  _fail "--base gates only the commits after the branch the epic was cut from" "$(printf '%s' "$out" | grep -E '^Range:|commit\(s\)' | tr '\n' ' ')"
fi
out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" --base no/such 2>&1 )"; rc=$?
if [ "$rc" -eq 1 ] && grep -q "not a ref" <<<"$out"; then _pass "--base with a ref that does not exist is refused"
else _fail "--base with a ref that does not exist is refused" "rc=$rc"; fi

# ── Case 9: a stacked epic re-gates from its own row, and falls back to its --base range ──
# The gate writes a stacked row's range as `<base>..<head> (stacked on <branch>, --base)`. The head
# was read as everything after the last "..", suffix and all, which never resolves; and every
# fallback switched the re-gate off but still diffed from the empty last head, so the handoff said
# "..HEAD — 0 commit(s)" and the reviewer was handed nothing (found re-gating epic/standards).
d="$TMP/c9"; mkrepo "$d"
( cd "$d/work" && git checkout -q -b epic/first origin/main && echo f > f.txt && git add -A && git commit -qm "first epic" \
  && git checkout -q -b epic/second && echo s > s.txt && git add -A && git commit -qm "second epic T-001" ) >/dev/null 2>&1
out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" --regate --base epic/first 2>&1 )"; rc=$?
if [ "$rc" -eq 0 ] && grep -q '^Range:   epic/first\.\.HEAD — stacked on epic/first' <<<"$out" && grep -q '1 commit(s) · 1 file(s) changed' <<<"$out"; then
  _pass "--regate --base with no row falls back to the --base range, not an empty one"
else
  _fail "--regate --base with no row falls back to the --base range" "rc=$rc: $(printf '%s' "$out" | grep -E '^Range:|commit\(s\)|fatal' | tr '\n' ' ')"
fi
(
  cd "$d/work" || exit 1
  first="$(git rev-parse --short epic/first)"; second="$(git rev-parse --short HEAD)"
  mkdir -p gate-records
  printf '| 2026-01-01 | second | %s..%s (stacked on epic/first, --base) | 1 | 0 | — | Sentinel FAIL (deep) | t@t |\n' "$first" "$second" > gate-records/gate-log.md
  git add -A; git commit -qm "gate row"
  echo fix > g.txt; git add -A; git commit -qm "fix T-002"
) >/dev/null 2>&1
out="$( cd "$d/work" && SKIP_SCAN_CHECK=1 bash "$GP" --regate --base epic/first 2>&1 )"; rc=$?
if [ "$rc" -eq 0 ] && grep -q '^# RE-GATE' <<<"$out" && grep -q '2 commit(s) · 2 file(s) changed' <<<"$out" && grep -q 'Tickets: T-002' <<<"$out"; then
  _pass "--regate --base reads the head out of a stacked row and reviews only what came after it"
else
  _fail "--regate --base reads the head out of a stacked row" "rc=$rc: $(printf '%s' "$out" | grep -E '^# |commit\(s\)|no prior|Tickets' | tr '\n' ' ')"
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
