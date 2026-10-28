#!/usr/bin/env bash
# constraints-test.sh — the constraint checks must refuse what they exist to refuse.
#
# Each check gets a throwaway git repo with the scripts copied in, a committed baseline on main,
# and one planted violation in the working tree. A guard that cannot fail is the defect class
# CONSTRAINTS.md exists to prevent, so every script is driven to red here, then to green.
# Covers: lint-changed.sh, floor-guard.mjs, check-boundaries.sh, ratchet.sh, forbidden-terms.sh,
# coverage-changed.py, install-hooks.sh, check-pipe-race.sh.
set -uo pipefail
export PATH="$PATH:$HOME/.local/bin"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pass=0; fail=0
_pass() { echo "  ok    $1"; pass=$((pass + 1)); }
_fail() { echo "  FAIL  $1 — $2"; fail=$((fail + 1)); }
expect_exit() {  # <want> <name> <cmd...>
  local want="$1" name="$2"; shift 2; local out rc
  out=$("$@" 2>&1); rc=$?
  if [ "$rc" -eq "$want" ]; then _pass "$name"; else _fail "$name" "exit $rc, wanted $want: $(printf '%s' "$out" | tail -2 | tr '\n' ' ')"; fi
}
for t in shellcheck ruff node gitleaks; do
  command -v "$t" >/dev/null 2>&1 || { echo "constraints-test: $t not installed — skipping (CONSTRAINTS.md names the install)"; exit 0; }
done

fixture() {  # a repo with the scripts, a baseline commit on main, cwd inside it
  T=$(mktemp -d); cd "$T" || exit 2
  git init -q -b main . && git config user.email t@example.invalid && git config user.name t
  mkdir -p scripts engine/scripts/scan engine/scripts/gate engine/scripts/docs
  cp "$ROOT"/scripts/*.sh "$ROOT"/scripts/*.mjs "$ROOT"/scripts/forbidden-terms.sha256 scripts/
  mkdir -p qa && cp -r "$ROOT"/qa/securebuilderbot_qa qa/   # coverage-changed.py imports the qa module
  cp "$ROOT"/.boundaries "$ROOT"/.shellcheckrc "$ROOT"/ruff.toml "$ROOT"/.constraintsignore .
  printf '#!/usr/bin/env bash\necho ok\n' > engine/scripts/scan/a.sh
  printf '# Constraints\n\n## Measured, not yet enforced\n\n| Metric | Today | Direction |\n|---|---|---|\n| shellcheck findings, all levels | 0 | must not grow |\n| ruff findings | 0 | must not grow |\n\n## Exceptions\n\n| ID | Rule | Path | Reason | Owner | Expires |\n|---|---|---|---|---|---|\n' > CONSTRAINTS.md
  git add -A && git -c commit.gpgsign=false commit -q -m baseline
}
teardown() { cd "$ROOT" && rm -rf "$T"; }

echo "── lint-changed: zero findings on added lines ──"
fixture
expect_exit 0 "a clean change passes" bash scripts/lint-changed.sh --base main
printf '#!/usr/bin/env bash\nx="a b"\necho \044x\n' > engine/scripts/scan/planted.sh
expect_exit 1 "an unquoted expansion on an added line is refused" bash scripts/lint-changed.sh --base main
rm engine/scripts/scan/planted.sh
printf 'import os, sys\n' > engine/scripts/gate/planted.py
expect_exit 1 "a ruff finding on an added Python line is refused" bash scripts/lint-changed.sh --base main
rm engine/scripts/gate/planted.py
# A file moved with git mv is not a file this change wrote: its old findings stay the ratchet's.
printf '#!/usr/bin/env bash\nx="a b"\necho \044x\n' > engine/scripts/scan/old.sh && git add -A && git -c commit.gpgsign=false commit -q -m "a finding on main"
git checkout -q -b move && mkdir -p moved && git mv engine/scripts/scan/old.sh moved/old.sh
expect_exit 0 "a moved file's untouched lines are not added lines" bash scripts/lint-changed.sh --base main
printf 'echo \044y\n' >> moved/old.sh
expect_exit 1 "…but a line added to the moved file still is" bash scripts/lint-changed.sh --base main
teardown

echo "── floor-guard: the five moves that lower the bar ──"
fixture
expect_exit 0 "no change is clean" node scripts/floor-guard.mjs --base main
# A diff past Node's 1 MB default buffer is still read whole, not refused as "could not diff".
python3 -c 'print("\n".join(f"line {i} " + "x" * 60 for i in range(20000)))' > big-data.txt
expect_exit 0 "a diff over 1 MB is read, not refused" node scripts/floor-guard.mjs --base main
rm big-data.txt
printf '# shellcheck disable=SC2086\n' >> engine/scripts/scan/a.sh
expect_exit 1 "a new suppression comment is refused" node scripts/floor-guard.mjs --base main
git checkout -q engine/scripts/scan/a.sh
printf 'TODO: finish\n' >> engine/scripts/scan/a.sh
expect_exit 1 "unfinished work is refused" node scripts/floor-guard.mjs --base main
git checkout -q engine/scripts/scan/a.sh
mkdir -p engine/scripts/tests && printf '_skip "later"\n' > engine/scripts/tests/x-test.sh
expect_exit 1 "a skipped test is refused" node scripts/floor-guard.mjs --base main
rm -r engine/scripts/tests
mkdir -p web && printf "it.skip('later', () => {})\n" > web/a.test.js
expect_exit 1 "a JavaScript it.skip( call is refused" node scripts/floor-guard.mjs --base main
rm -r web
mkdir -p web && printf "it.skip.each([1])('later', () => {})\n" > web/a.test.js
expect_exit 1 "a JavaScript it.skip.each( call is refused" node scripts/floor-guard.mjs --base main
cat > web/a.test.js <<'JS'
describe.skip.each`a`('later', () => {})
JS
expect_exit 1 "a tagged-template describe.skip.each is refused" node scripts/floor-guard.mjs --base main
printf "it.only('just this', () => {})\n" > web/a.test.js
expect_exit 1 "an it.only( that silences its siblings is refused" node scripts/floor-guard.mjs --base main
printf "fit('just this', () => {})\n" > web/a.test.js
expect_exit 1 "a focused fit( is refused" node scripts/floor-guard.mjs --base main
mkdir -p engine/scripts/scan/tests && printf '@pytest.mark.xfail\ndef test_x(): pass\n' > engine/scripts/scan/tests/test_x.py
expect_exit 1 "a pytest xfail is refused" node scripts/floor-guard.mjs --base main
rm -r engine/scripts/scan/tests
rm -r web
printf 'skip = config.scan.skip\n' > engine/scripts/scan/settings.py
expect_exit 0 "a property named skip is not a skipped test" node scripts/floor-guard.mjs --base main
rm engine/scripts/scan/settings.py
sed -i 's/^| ruff findings | 0 | must not grow |/| ruff findings | 5 | must not grow |/' CONSTRAINTS.md
expect_exit 1 "a loosened ratchet number is refused" node scripts/floor-guard.mjs --base main
git checkout -q CONSTRAINTS.md
printf '| W1 | x | y | z | me | 2099-01-01 |\n' >> CONSTRAINTS.md
expect_exit 1 "a new exception row is refused" node scripts/floor-guard.mjs --base main
git checkout -q CONSTRAINTS.md
teardown

echo "── floor-guard: a removed test needs its reason in the commit ──"
fixture
mkdir -p engine/scripts/tests && printf '_pass "x"\n' > engine/scripts/tests/old-test.sh && git add -A && git -c commit.gpgsign=false commit -q -m "add a test"
git checkout -q -b work
git rm -q engine/scripts/tests/old-test.sh
expect_exit 1 "an uncommitted test deletion is refused" node scripts/floor-guard.mjs --base main
git -c commit.gpgsign=false commit -q -m "drop it"
expect_exit 1 "a committed deletion with no reason is refused" node scripts/floor-guard.mjs --base main
git -c commit.gpgsign=false commit -q --amend -m "drop it" -m "Test-removed: engine/scripts/tests/old-test.sh"
expect_exit 1 "a Test-removed line with no reason is refused" node scripts/floor-guard.mjs --base main
git -c commit.gpgsign=false commit -q --amend -m "drop it" -m "Test-removed: engine/scripts/tests/old-test.sh — ported to pytest"
expect_exit 0 "a Test-removed line with a reason excuses that file" node scripts/floor-guard.mjs --base main
git -c commit.gpgsign=false commit -q --amend -m "drop it" -m "Test-removed: engine/scripts/tests/other-test.sh — wrong file"
expect_exit 1 "a reason naming another file excuses nothing" node scripts/floor-guard.mjs --base main
teardown

echo "── check-boundaries: only the listed edges ──"
fixture
expect_exit 0 "the recorded edges pass" bash scripts/check-boundaries.sh
mkdir -p scanners && printf '#!/usr/bin/env bash\nbash engine/scripts/gate/x.sh\n' > scanners/a.sh
expect_exit 1 "an edge not in .boundaries is refused" bash scripts/check-boundaries.sh
printf '#!/usr/bin/env bash\necho scanners/scripts/self.sh\n' > scanners/a.sh
expect_exit 0 "a group naming its own path is not an edge to scripts/" bash scripts/check-boundaries.sh
rm -r scanners
teardown

echo "── ratchet: measured numbers may not get worse ──"
fixture
expect_exit 0 "a held number passes" bash scripts/ratchet.sh
printf 'echo \044x\n' >> engine/scripts/scan/a.sh && git add -A && git -c commit.gpgsign=false commit -q -m worse
expect_exit 1 "a grown shellcheck count is refused" bash scripts/ratchet.sh
teardown

echo "── check-pipe-race: no pipe into grep -q under pipefail ──"
fixture
expect_exit 0 "a tree with no such pipe passes" bash scripts/check-pipe-race.sh
cat > engine/scripts/scan/safe.sh <<'SH'
#!/usr/bin/env bash
set -uo pipefail
x="$1"
grep -q a <<<"$x" && echo here-string
printf "%s" "$x" | grep a >/dev/null && echo drained
# printf "%s" "$x" | grep -q a  (a comment is nothing)
SH
git add -A
expect_exit 0 "a here-string, a drained pipe and a comment pass" bash scripts/check-pipe-race.sh
cat > engine/scripts/scan/racy.sh <<'SH'
#!/usr/bin/env bash
set -uo pipefail
printf "%s" "$1" | grep -QE a && echo racy
SH
sed -i 's/grep -Q/grep -q/' engine/scripts/scan/racy.sh   # written as -Q so this file never carries the shape itself
git add -A
expect_exit 1 "a pipe into grep -qE under pipefail is refused" bash scripts/check-pipe-race.sh
cat > engine/scripts/scan/racy.sh <<'SH'
#!/usr/bin/env bash
printf "%s" "$1" | grep -Q a
SH
sed -i 's/grep -Q/grep -q/' engine/scripts/scan/racy.sh
expect_exit 0 "the same pipe without pipefail is not this race" bash scripts/check-pipe-race.sh
teardown

echo "── forbidden-terms: the denylist refuses, the list never names the word ──"
fixture
expect_exit 0 "a clean tree passes" bash scripts/forbidden-terms.sh --all
word=$(printf 'ze%s' 'us')   # assembled so this test file never carries the term itself
printf 'mentions %s here\n' "$word" > planted.md
expect_exit 1 "a planted term is refused" bash scripts/forbidden-terms.sh --all
rm planted.md
if grep -qi "$word" scripts/forbidden-terms.sha256; then _fail "the list never names the word" "found it in the digest file"; else _pass "the list never names the word"; fi
teardown

echo "── coverage-changed: added core lines must be covered ──"
fixture
cp "$ROOT"/scripts/coverage-changed.py scripts/
mkdir -p core/pkg gate-records/state
printf 'def a():\n    return 1\n\n\ndef b():\n    return 2\n' > core/pkg/m.py
here=$(pwd)
lcov() { printf 'SF:%s/core/pkg/m.py\nDA:1,1\nDA:2,%s\nDA:5,1\nDA:6,%s\nend_of_record\n' "$here" "$1" "$2" > gate-records/state/core.lcov; }
lcov 1 1
expect_exit 0 "fully covered added lines pass" python3 scripts/coverage-changed.py --base main --min 80
lcov 0 0
expect_exit 1 "half-covered added lines fail at an 80% minimum" python3 scripts/coverage-changed.py --base main --min 80
rm gate-records/state/core.lcov
expect_exit 2 "a missing coverage file is never read as a pass" python3 scripts/coverage-changed.py --base main --min 80
rm -r core/pkg
expect_exit 0 "no added core Python is nothing to measure" python3 scripts/coverage-changed.py --base main --min 80
teardown

echo "── pre-commit: the tracked hook refuses a planted term, in a worktree too ──"
fixture
mkdir -p .githooks engine/scripts/gate
cp "$ROOT"/.githooks/pre-commit .githooks/ && chmod +x .githooks/pre-commit
printf '#!/usr/bin/env bash\nexit 0\n' > engine/scripts/gate/pre-commit-scan.sh   # the secret scan is not what this proves
git add -A && git -c commit.gpgsign=false commit -q -m hooks && git config core.hooksPath .githooks
word=$(printf 'ze%s' 'us')
printf 'mentions %s here\n' "$word" > planted.md && git add planted.md
expect_exit 1 "the hook refuses a staged planted term" git -c commit.gpgsign=false commit -q -m planted
git rm -q --cached planted.md && rm planted.md
git worktree add -q wt -b wt-branch
( cd wt && printf 'mentions %s here\n' "$word" > planted.md && git add planted.md )
# In a worktree git hands the hook GIT_DIR but no GIT_WORK_TREE; the staged list once came back empty
# there, so every commit in a worktree passed unchecked ("clean (0 files)").
expect_exit 1 "the hook refuses a staged planted term in a worktree" git -C wt -c commit.gpgsign=false commit -q -m planted
teardown

echo "── install-hooks: git runs the tracked hooks ──"
fixture
mkdir -p .githooks && printf '#!/usr/bin/env bash\nexit 0\n' > .githooks/pre-commit && chmod +x .githooks/pre-commit
expect_exit 0 "install-hooks sets core.hooksPath" bash scripts/install-hooks.sh
if [ "$(git config core.hooksPath)" = ".githooks" ]; then _pass "hooksPath points at .githooks"; else _fail "hooksPath points at .githooks" "got $(git config core.hooksPath)"; fi
teardown

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
