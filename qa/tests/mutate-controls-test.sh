#!/usr/bin/env bash
# mutate-controls and verify-controls on Python controls — a Python control is found, wired, broken
# on purpose, and restored, exactly as a TypeScript one is.
#
# WHY   Gate finding F-03 (2026-10-15): this repository's controls are Python under core/, and both
#       tools read only TypeScript and Kotlin, so a populated manifest would have proven nothing. The
#       tools now honour the CONTROL_* keys in project.config.yaml (qa/scripts/_lib.sh). The
#       cases below are the ways that can go wrong: a mention that is not a call site counted as one
#       (an import, a comment, a docstring), a mutation that does not parse read as a proof, a
#       control with no test reported as proven, and a file left mutated.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QA="$(cd "$SCRIPT_DIR/.." && pwd)"
MC="$QA/scripts/mutate-controls.sh"
VC="$QA/scripts/verify-controls.sh"
PASS=0; FAIL=0
_pass() { echo "  ok    $1"; PASS=$((PASS + 1)); }
_fail() { echo "  FAIL  $1 — got: $2"; FAIL=$((FAIL + 1)); }
has() { if grep -qF -- "$3" <<<"$2"; then _pass "$1"; else _fail "$1" "$(printf '%s' "$2" | tail -4)"; fi; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
( cd "$T" && git init -q . && git config user.email t@t && git config user.name t
  mkdir -p pkg/tests web docs/security
  cat > project.config.yaml <<'YML'
APP_TRACK: web
SECURITY_TIER: IL6
PROVIDER: aws
APP_TYPE: n/a
CONTROL_SRC_ROOTS: pkg web
CONTROL_SRC_EXT: py ts
CONTROL_TEST_DIR: pkg/tests
CONTROL_TEST_CMD: python3 -m pytest -q -p no:cacheprovider -o pythonpath=pkg pkg/tests
CONTROL_TARGET_CMD: python3 -m pytest -q -p no:cacheprovider -o pythonpath=pkg {tests}
YML
  cat > pkg/guard.py <<'PY'
import re


def is_allowed(user: str) -> bool:
    """Only an admin. is_allowed(x) in a docstring is not a call site."""
    return user == "admin"


def redact_text(
    text: str,
) -> str:
    return re.sub(r"sk-[a-z0-9]+", "[x]", text)


def no_teeth(n: int) -> int:
    return n + 1


def only_imported(x):
    return x


def only_in_comment(x):
    return x


def only_in_docstring(x):
    return x
PY
  cat > pkg/app.py <<'PY'
from guard import (
    only_imported,
    redact_text,
)
from guard import is_allowed, no_teeth

# only_in_comment(x) used to be called here


def other():
    """A docstring that quotes the other kind: \'\'\' is not its end.
    only_in_docstring(x) is mentioned here, and nowhere called.
    """
    return 1


def handle(user, text):
    if not is_allowed(user):
        return None
    return redact_text(text), no_teeth(1)
PY
  cat > pkg/tests/test_guard.py <<'PY'
from guard import is_allowed, redact_text


def test_only_admin():
    assert is_allowed("admin") and not is_allowed("user")


def test_redacts():
    assert redact_text("key sk-abc123") == "key [x]"
PY
  # A second root in a second language (2026-10-23, adapter-gitlab): a repository whose controls
  # are Python and TypeScript names both extensions, and each root is indexed with its own.
  cat > web/guard.ts <<'TS'
export function isSafe(body: string): boolean {
  return !body.includes("secret");
}
TS
  cat > web/app.ts <<'TS'
import { isSafe } from "./guard.js";
export function post(body: string): string {
  return isSafe(body) ? "posted" : "refused";
}
TS
  cat > docs/security/CONTROL-MANIFEST.md <<'MD'
| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-11 | typescript beside python | `web/guard.ts:isSafe` | - | - | mutate:decision |
| CM-01 | admin only | `pkg/guard.py:is_allowed` | - | `test_guard.py` | mutate:decision |
| CM-02 | redaction | `pkg/guard.py:redact_text` | - | `test_guard.py` | multi-line signature |
| CM-03 | untested | `pkg/guard.py:no_teeth` | - | - | mutate:stmt=return 0 |
| CM-04 | import only | `pkg/guard.py:only_imported` | - | - | must FAIL verify |
| CM-05 | comment only | `pkg/guard.py:only_in_comment` | - | - | must FAIL verify |
| CM-10 | docstring only | `pkg/guard.py:only_in_docstring` | - | - | must FAIL verify |
MD
  git add -A && git commit -qm base )

echo "── verify-controls: Python call sites ──"
out=$(cd "$T" && bash "$VC" 2>&1)
has "a Python def called from another module is ok"          "$out" "ok    CM-01"
has "a parenthesised multi-line import is not a call site, the call is" "$out" "ok    CM-02"
has "a name only in a from-import FAILs"                     "$out" "FAIL  CM-04"
has "a name only in a # comment FAILs"                       "$out" "FAIL  CM-05"
has "a docstring mention is not a call site (CM-01 counts one)" "$out" "ok    CM-01  admin only  (1 call site)"
has "a docstring quoting the other quote kind stays a docstring (run #2, N-06)" "$out" "FAIL  CM-10"
has "a TypeScript control under a second root, with its own extension, is found and wired" "$out" "ok    CM-11  typescript beside python  (1 call site)"
out=$(cd "$T" && bash "$MC" --dry-run --only CM-11 2>&1)
has "a TypeScript body under the second root is located for mutation" "$out" "if (true as boolean) return true;"

echo "── mutate-controls: Python bodies ──"
out=$(cd "$T" && bash "$MC" --only CM-01,CM-02,CM-03 2>&1); rc=$?
has "decision → return True, caught by its own test"          "$out" "| CM-01 | admin only | decision → \`return True\` @ pkg/guard.py:5 | RED (own test) | ✓ proven |"
has "redact → returns its first parameter past a multi-line signature" "$out" "| CM-02 | redaction | redact → \`return text\` @ pkg/guard.py:12 | RED (own test) | ✓ proven |"
has "a control no test notices is NOT PROVEN"                 "$out" "| CM-03 | untested | stmt → \`return 0\` @ pkg/guard.py:16 | GREEN | ✗ NOT PROVEN |"
if [ "$rc" -eq 1 ]; then _pass "a NOT PROVEN row exits 1"; else _fail "a NOT PROVEN row exits 1" "rc=$rc"; fi
if (cd "$T" && git diff --quiet); then _pass "every mutated file is restored"; else _fail "every mutated file is restored" "$(cd "$T" && git diff --stat)"; fi
if [ -z "$(cd "$T" && find pkg -name __pycache__)" ]; then _pass "no run leaves bytecode in the repository's __pycache__"
else _fail "no run leaves bytecode in the repository's __pycache__" "$(cd "$T" && find pkg -name __pycache__)"; fi
cat >> "$T/docs/security/CONTROL-MANIFEST.md" <<'MD'
| CM-09 | same size | `pkg/guard.py:is_allowed` | - | `test_guard.py` | mutate:replace=user == "admin" ~> user != "admin" |
MD
out=$(cd "$T" && bash "$MC" --only CM-09 2>&1)
has "a same-size replacement is caught" "$out" "| CM-09 | same size | replace"
if (cd "$T" && python3 -m pytest -q -p no:cacheprovider -o pythonpath=pkg pkg/tests >/dev/null 2>&1); then
  _pass "straight after a same-size mutation, the restored code runs as written"
else _fail "straight after a same-size mutation, the restored code runs as written" "the suite is red"; fi

out=$(cd "$T" && bash "$MC" --dry-run --only CM-01 2>&1)
has "the mutation goes in above the body at the body's indent" "$out" "+    5      if True: return True  # mutate-controls: decision"

cat >> "$T/docs/security/CONTROL-MANIFEST.md" <<'MD'
| CM-06 | bad stmt | `pkg/guard.py:no_teeth` | - | `test_guard.py` | mutate:stmt=return ( |
MD
out=$(cd "$T" && bash "$MC" --only CM-06 --no-baseline 2>&1)
has "a statement that loses its tail in the cell is refused, never run" "$out" "✗ manual: unbalanced brackets"
cat >> "$T/docs/security/CONTROL-MANIFEST.md" <<'MD'
| CM-07 | broken parse | `pkg/guard.py:no_teeth` | - | `test_guard.py` | mutate:stmt=return 1 +* 2 |
MD
out=$(cd "$T" && bash "$MC" --only CM-07 --no-baseline 2>&1)
has "a mutation that does not parse is NOT PROVEN, never a proof" "$out" "✗ NOT PROVEN — mutation broke the build"
cat >> "$T/docs/security/CONTROL-MANIFEST.md" <<'MD'
| CM-08 | wrong kind | `pkg/guard.py:no_teeth` | - | - | mutate:middleware |
MD
out=$(cd "$T" && bash "$MC" --only CM-08 --no-baseline 2>&1)
has "a JavaScript-only kind on Python is manual, not guessed" "$out" "does not apply to Python"

echo "── several test directories (CONTROL_TEST_DIR lists each, space-separated) ──"
# A repository with more than one Python package keeps each package's tests beside it, so one row's
# proving test may live under a second directory. Both tools must look in every listed one.
( cd "$T" && mkdir -p other/tests && git checkout -q -- docs/security/CONTROL-MANIFEST.md
  sed -i 's|^CONTROL_TEST_DIR: pkg/tests$|CONTROL_TEST_DIR: pkg/tests other/tests|' project.config.yaml
  printf 'from guard import no_teeth\n\n\ndef test_adds_one():\n    assert no_teeth(1) == 2\n' > other/tests/test_second.py
  printf "| CM-11 | second dir | \`pkg/guard.py:no_teeth\` | - | \`test_second.py\` | mutate:stmt=return 0 |\n" >> docs/security/CONTROL-MANIFEST.md
  git add -A && git commit -qm "second test dir" )
out=$(cd "$T" && bash "$VC" 2>&1)
has "verify-controls finds a proving test in the second directory" "$out" "ok    CM-11"
out=$(cd "$T" && bash "$MC" --only CM-11 2>&1)
has "mutate-controls runs the row's own test from the second directory" "$out" "| CM-11 | second dir | stmt → \`return 0\` @ pkg/guard.py:16 | RED (own test) | ✓ proven |"
base=$(cd "$T" && git rev-parse HEAD)
( cd "$T" && printf '\n\ndef test_adds_one_again():\n    assert no_teeth(2) == 3\n' >> other/tests/test_second.py && git commit -qam "touch the second test" )
out=$(cd "$T" && bash "$MC" --dry-run --since "$base" --only CM-11 2>&1)
has "--since sees a proving test changed in the second directory" "$out" "| CM-11 | second dir | stmt → \`return 0\` | — | dry-run |"
# The QA gate hands the list in as a file outside the checkout (CONTROL_MANIFEST); --since must still
# compare each row with the repository's own list at the base, or every row reads as new.
pinned="$(mktemp)"; cp "$T/docs/security/CONTROL-MANIFEST.md" "$pinned"
head_now=$(cd "$T" && git rev-parse HEAD)
out=$(cd "$T" && CONTROL_MANIFEST="$pinned" bash "$MC" --dry-run --since "$head_now" --only CM-11 2>&1)
has "--since with the list outside the checkout: an untouched row is unchanged, not new" "$out" "○ unchanged since $head_now"
rm -f "$pinned"

# ── a mutated full-suite run that never ends is that row timing out, never the whole run's budget ──
echo "── mutate-controls: a full suite that hangs under mutation ──"
H=$(mktemp -d); trap 'rm -rf "$T" "$H"' EXIT
( cd "$H" && git init -q . && git config user.email t@t && git config user.name t
  mkdir -p pkg docs/security
  printf 'APP_TRACK: web\nCONTROL_SRC_ROOTS: pkg\nCONTROL_SRC_EXT: py\nCONTROL_TEST_DIR: pkg\nCONTROL_TEST_CMD: bash suite.sh\n' > project.config.yaml
  printf 'def gate(user):\n    if user != "admin":\n        raise PermissionError(user)\n    return True\n' > pkg/guard.py
  # The suite: green as written, and it hangs (a child that never exits) once gate() is disabled.
  cat > suite.sh <<'SH'
if python3 -B -c 'import sys; sys.path.insert(0, "pkg"); import guard
try:
    guard.gate("eve")
except PermissionError:
    sys.exit(0)
sys.exit(1)'; then exit 0; fi
sleep 317 &
wait
SH
  printf "| id | control | implementation | required artifact | proving test | note |\n|---|---|---|---|---|---|\n| CM-01 | admin only | \`pkg/guard.py:gate\` | - | - | mutate:noop |\n" > docs/security/CONTROL-MANIFEST.md
  git add -A && git commit -qm hang )
t0=$SECONDS
out=$(cd "$H" && MUTATE_SUITE_TIMEOUT=3 bash "$MC" 2>&1); rc=$?
took=$((SECONDS - t0))
has "the hung row is named as timing out and not proven" "$out" "| TIMED OUT | ✗ NOT PROVEN — the suite ran past 3s with the control disabled |"
if [ "$rc" -eq 1 ] && [ "$took" -lt 60 ]; then _pass "the run ends at the cap, exit 1 (took ${took}s)"; else _fail "the run ends at the cap" "rc=$rc took=${took}s"; fi
if (cd "$H" && git diff --quiet); then _pass "the hung row's file is restored"; else _fail "the hung row's file is restored" "$(cd "$H" && git diff --stat)"; fi
if pgrep -xf "sleep 317" >/dev/null; then _fail "the hung suite's children are stopped too" "$(pgrep -axf "sleep 317")"; pkill -xf "sleep 317"; else _pass "the hung suite's children are stopped too"; fi

echo "── --infer-roots: the suite command the layout implies, and JavaScript bodies (2026-10-28) ──"
# The QA gate's drafted mode on a repository that names no roots. The suite is the one the layout
# implies, a red baseline under inference exits 3 (the gate reads it as yellow, never not_run), and a
# .js control is mutated as JavaScript: no TypeScript-only syntax goes into it.
J=$(mktemp -d); trap 'rm -rf "$T" "$H" "$J"' EXIT
( cd "$J" && git init -q py && cd py && git config user.email t@t && git config user.name t
  mkdir -p svc tests && : > svc/__init__.py && printf 'pytest\n' > requirements.txt
  printf '[pytest]\naddopts = -p no:cacheprovider\npythonpath = .\n' > pytest.ini
  printf 'def require_admin(user):\n    if user != "admin":\n        raise PermissionError("admins only")\n    return user\n' > svc/auth.py
  printf 'import pytest\nfrom svc.auth import require_admin\n\n\ndef test_refused():\n    with pytest.raises(PermissionError):\n        require_admin("bob")\n' > tests/test_auth.py
  printf "| CM-01 | admin only | \`svc/auth.py:require_admin\` | - | \`test_auth.py\` | mutate:noop |\n" > list.md
  git add -A && git commit -qm base )
out=$(cd "$J/py" && CONTROL_MANIFEST=list.md bash "$MC" --infer-roots 2>&1); rc=$?
has "--infer-roots runs the suite the layout implies" "$out" "suite: python3 -m pytest -q -x (inferred from the layout: no CONTROL_SRC_ROOTS, no default roots)"
has "--infer-roots: a Python control is proven under the inferred suite" "$out" "| CM-01 | admin only | noop → \`return None\` @ svc/auth.py:2 | RED | ✓ proven |"
if [ "$rc" -eq 0 ]; then _pass "--infer-roots: every row proven exits 0"; else _fail "--infer-roots: every row proven exits 0" "rc=$rc"; fi
out=$(cd "$J/py" && CONTROL_MANIFEST=list.md bash "$MC" 2>&1); rc=$?
if [ "$rc" -eq 1 ] && grep -qF "cd backend && npm test" <<<"$out"; then _pass "without --infer-roots the default suite runs, as before"
else _fail "without --infer-roots the default suite runs, as before" "rc=$rc $(printf '%s' "$out" | head -3)"; fi
( cd "$J/py" && printf '\n\ndef test_red():\n    assert False\n' >> tests/test_auth.py )
out=$(cd "$J/py" && CONTROL_MANIFEST=list.md bash "$MC" --infer-roots 2>&1); rc=$?
if [ "$rc" -eq 3 ]; then _pass "a red baseline under an inferred suite exits 3, never 1"; else _fail "a red baseline under an inferred suite exits 3" "rc=$rc"; fi
has "a red inferred baseline says which command and what to set" "$out" "INFERRED SUITE NOT GREEN: python3 -m pytest -q -x is red before any mutation, so nothing was sabotage-tested — set CONTROL_TEST_CMD"
( cd "$J/py" && git checkout -q -- tests && printf 'CONTROL_SRC_ROOTS: svc\nCONTROL_SRC_EXT: py\nCONTROL_TEST_CMD: python3 -m pytest -q\n' > project.config.yaml )
out=$(cd "$J/py" && CONTROL_MANIFEST=list.md bash "$MC" --infer-roots 2>&1)
has "a configured CONTROL_SRC_ROOTS: the config's suite, nothing inferred" "$out" "suite: python3 -m pytest -q"
if grep -qF "inferred from the layout" <<<"$out"; then _fail "a configured CONTROL_SRC_ROOTS: nothing is inferred" "$out"; else _pass "a configured CONTROL_SRC_ROOTS: nothing is inferred"; fi

( cd "$J" && git init -q js && cd js && git config user.email t@t && git config user.name t
  mkdir -p src test
  printf '{ "name": "api", "private": true, "scripts": { "test": "node --test" } }\n' > package.json
  printf 'function requireAdmin(req, res, next) {\n  if (req.user !== "admin") return res.status(403).end()\n  next()\n}\nmodule.exports = { requireAdmin }\n' > src/auth.js
  cat > test/auth.test.js <<'JS'
const test = require("node:test")
const assert = require("node:assert")
const { requireAdmin } = require("../src/auth")
test("a user is refused with 403", () => {
  let status = 0, passed = false
  requireAdmin({ user: "bob" }, { status: (s) => { status = s; return { end() {} } } }, () => { passed = true })
  assert.strictEqual(status, 403)
  assert.strictEqual(passed, false)
})
JS
  printf "| CM-01 | admin only | \`src/auth.js:requireAdmin\` | - | \`auth.test.js\` | |\n" > list.md
  git add -A && git commit -qm base )
out=$(cd "$J/js" && CONTROL_MANIFEST=list.md bash "$MC" --infer-roots --dry-run 2>&1)
has "a .js body gets a plain JavaScript mutation" "$out" "+    2    if (true) return next();"
suppress="@ts""-ignore"   # the TypeScript suppression comment, spelled so no file carries it
if grep -qF "$suppress" <<<"$out"; then _fail "a .js body gets no TypeScript-only line" "$out"; else _pass "a .js body gets no TypeScript-only line"; fi
out=$(cd "$J/js" && CONTROL_MANIFEST=list.md bash "$MC" --infer-roots 2>&1); rc=$?
has "--infer-roots: npm test runs when package.json names a test script" "$out" "suite: npm test --silent (inferred from the layout"
has "a JavaScript middleware is proven, not a syntax error" "$out" "| CM-01 | admin only | middleware → \`return next();\` @ src/auth.js:2 | RED | ✓ proven |"
if [ "$rc" -eq 0 ] && (cd "$J/js" && git diff --quiet); then _pass "the .js file is restored"; else _fail "the .js file is restored" "rc=$rc $(cd "$J/js" && git diff --stat)"; fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
