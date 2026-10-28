#!/usr/bin/env bash
# derive-controls tests — a guard site must be found however it is written, and satisfied only by a
# manifest row or a written reason.
#
# WHY   T-SLIM-13: the first version read one line at a time, so `throw new AppError(` with the
#       status on the next line — the shape a formatter gives any long message — was no guard at
#       all, and a function holding only such refusals needed no row. The scanner is the thing that
#       removes the author's choice; a shape it cannot see hands the choice back.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QA="$(cd "$SCRIPT_DIR/.." && pwd)"
DC="$QA/scripts/derive-controls.sh"
PASS=0; FAIL=0
_pass() { echo "  ok    $1"; PASS=$((PASS + 1)); }
_fail() { echo "  FAIL  $1 — got: $2"; FAIL=$((FAIL + 1)); }

echo "── derive-controls ──"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
( cd "$T" && git init -q . && git config user.email t@t && git config user.name t
  mkdir -p backend/src/services docs/security
  printf 'APP_TRACK: web\nSECURITY_TIER: IL4\nPROVIDER: aws\nAPP_TYPE: n/a\n' > project.config.yaml
  printf "| CM-01 | x | \`backend/src/services/ledger.ts:post\` | - | \`x.test.ts\` | n |\n" > docs/security/CONTROL-MANIFEST.md
  printf 'export function post() { return 1 }\n' > backend/src/services/ledger.ts
  git add -A && git commit -qm base )
case_() {   # $1 = label, $2 = expected rc, $3 = expected substring of output (or ""), $4 = file body
  printf '%b' "$4" > "$T/backend/src/services/probe.ts"
  local out rc; out=$(cd "$T" && bash "$DC" --list 2>&1); rc=$?
  if [ "$rc" -ne "$2" ]; then _fail "$1 (expected rc $2)" "rc=$rc"; return; fi
  if [ -n "$3" ] && ! grep -qF -- "$3" <<<"$out"; then _fail "$1 (expected '$3')" "$(printf '%s' "$out" | tail -3)"; return; fi
  _pass "$1"
}
case_ "a one-line 403 with no row is UNREGISTERED" 1 "probe.ts:1  gate  [403]" \
  'export function gate(u) { if (!u) throw new AppError(403, "F", "no") }\n'
case_ "a 403 written across two lines is UNREGISTERED (T-SLIM-13)" 1 "probe.ts:2  gate  [403]" \
  'export function gate(u) {\n  if (!u) throw new AppError(\n    403, "F", "a message long enough that a formatter broke the line")\n}\n'
case_ "a 404 across two lines reports kind 404, on the throw line" 1 "probe.ts:2  gate  [404]" \
  'export function gate(u) {\n  if (!u) throw new AppError(\n    404, "F", "no")\n}\n'
case_ "res.status(403) is a refusal too (T-SLIM-13)" 1 "probe.ts:1  deny  [403]" \
  'export function deny(req, res) { return res.status(403).json({}) }\n'
case_ "a written reason above a two-line refusal satisfies it" 0 "not-a-control" \
  'export function gate(u) {\n  // not-a-control: the probe fixture checks the reason is read across the split\n  if (!u) throw new AppError(\n    403, "F", "no")\n}\n'
case_ "a reason above the function exempts the whole function" 0 "not-a-control" \
  '// not-a-control: fixture — the whole function is exempt by the line above its definition\nexport function gate(u) {\n  if (!u) throw new AppError(\n    403, "F", "no")\n}\n'
case_ "a commented-out two-line refusal is nothing" 0 "0 unregistered" \
  'export function gate(u) {\n  // if (!u) throw new AppError(\n  //   403, "F", "no")\n  return u\n}\n'
# Registered: the manifest names probe.ts:gate.
printf "| CM-02 | y | \`backend/src/services/probe.ts:gate\` | - | \`y.test.ts\` | n |\n" >> "$T/docs/security/CONTROL-MANIFEST.md"
case_ "a manifest row satisfies a two-line refusal" 0 "registered CM-02" \
  'export function gate(u) {\n  if (!u) throw new AppError(\n    403, "F", "no")\n}\n'

echo "── derive-controls: Python guards (qa module, 2026-10-23) ──"
# A repository whose controls are Python names its roots with CONTROL_SRC_ROOTS / CONTROL_SRC_EXT;
# the guard shapes are the ones the common frameworks raise or return.
P=$(mktemp -d); trap 'rm -rf "$T" "$P"' EXIT
( cd "$P" && git init -q . && git config user.email t@t && git config user.name t
  mkdir -p pkg/tests docs/security
  printf 'APP_TRACK: web\nSECURITY_TIER: IL4\nPROVIDER: aws\nAPP_TYPE: n/a\nCONTROL_SRC_ROOTS: pkg\nCONTROL_SRC_EXT: py\nCONTROL_TEST_DIR: pkg/tests\n' > project.config.yaml
  printf '| id | control | implementation | required artifact | proving test | note |\n|---|---|---|---|---|---|\n' > docs/security/CONTROL-MANIFEST.md
  cat > pkg/auth.py <<'PYF'
from fastapi import HTTPException


def require_admin(user):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin only")


def require_login(user):
    if user is None:
        abort(401)


def require_owner(user, doc):
    if doc.owner != user.id:
        raise PermissionDenied("not yours")


def refuse(request):
    if not request.user:
        return Response(status=401)


# not-a-control: a documented fixture exemption, long enough to count as a reason
def exempt(user):
    raise PermissionDenied("but exempt")


def plain(x):
    # abort(403) in a comment is nothing
    return x


def wrapped(user):
    if not user.ok:
        raise HTTPException(
            status_code=403,
            detail="wrapped the way black wraps it",
        )


def by_constant(doc):
    if doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


def by_enum(user):
    if user is None:
        return JSONResponse(
            {"detail": "log in"}, status_code=HTTPStatus.UNAUTHORIZED
        )


def builds_a_dict(x):
    return dict(
        a=x,
    )
    status_code = 403
PYF
  printf 'from auth import require_admin\n\n\ndef test_admin():\n    assert require_admin\n' > pkg/tests/test_auth.py
  # Gate run 2, N-02: each status spelling, the 20-line join cap and comment stripping on a joined
  # line, pinned so a mutant that drops any one of them goes red. pins.py keeps auth.py's lines fixed.
  cat > pkg/pins.py <<'PYF'
def by_constant_403(user):
    if user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


def by_constant_401(user):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


def by_enum_404(doc):
    if doc is None:
        return JSONResponse({}, status_code=HTTPStatus.NOT_FOUND)


def by_enum_403(user):
    if user is None:
        return JSONResponse({}, status_code=HTTPStatus.FORBIDDEN)


def commented_continuation(x):
    return dict(
        a=x,  # status_code=403 is what a caller would see, in a comment
    )
PYF
  # A "(" inside a string never balances, so the join runs to its cap: the status on the 20th line
  # after the return is read (line 28 + 20 = 48), the one on the 21st is not (line 52 + 21 = 73).
  { printf '\n\ndef at_the_cap(user):\n    return refuse(user, "(",\n'
    for _ in $(seq 19); do printf '        filler,\n'; done
    printf '        status_code=403)\n\n\ndef past_the_cap(user):\n    return refuse(user, "(",\n'
    for _ in $(seq 20); do printf '        filler,\n'; done
    printf '        status_code=403)\n'; } >> pkg/pins.py
  # Gate run 2, N-03: a positional status to HTTPException, and Flask's `return body, status`, are refusals.
  cat >> pkg/pins.py <<'PYF'


def positional(user):
    if user is None:
        raise HTTPException(403, "no")


def positional_401(user):
    if user is None:
        raise HTTPException(401)


def flask_refusal(user):
    if user is None:
        return jsonify(error="no"), 403


def flask_with_headers(user):
    if user is None:
        return "log in", 401, {"WWW-Authenticate": "Bearer"}


def flask_wrapped(doc):
    if doc is None:
        return jsonify(
            error="gone",
        ), 404


def not_a_status(x):
    return pad(x, 403)
PYF
  git add -A && git commit -qm base )
out=$(cd "$P" && bash "$DC" --list 2>&1); rc=$?
if [ "$rc" -eq 1 ]; then _pass "Python guards with no row exit 1"; else _fail "Python guards with no row exit 1" "rc=$rc"; fi
# The last three are gate run 1's B-02: a call black wraps across lines, and the status constants
# FastAPI and the standard library name, were invisible, so a guard written either way went unregistered.
for want in "auth.py:6  require_admin  [403]" "auth.py:11  require_login  [401]" "auth.py:16  require_owner  [403]" "auth.py:21  refuse  [401]" \
            "auth.py:36  wrapped  [403]" "auth.py:44  by_constant  [404]" "auth.py:49  by_enum  [401]"; do
  if grep -qF -- "UNREGISTERED  pkg/$want" <<<"$out"; then _pass "finds $want"; else _fail "finds $want" "$(printf '%s' "$out" | tail -8)"; fi
done
for want in "pins.py:3  by_constant_403  [403]" "pins.py:8  by_constant_401  [401]" "pins.py:13  by_enum_404  [404]" "pins.py:18  by_enum_403  [403]" \
            "pins.py:28  at_the_cap  [403]" "pins.py:78  positional  [403]" "pins.py:83  positional_401  [401]" \
            "pins.py:88  flask_refusal  [403]" "pins.py:93  flask_with_headers  [401]" "pins.py:98  flask_wrapped  [404]"; do
  if grep -qF -- "UNREGISTERED  pkg/$want" <<<"$out"; then _pass "finds $want"; else _fail "finds $want" "$(printf '%s' "$out" | tail -8)"; fi
done
if grep -qF -- "past_the_cap" <<<"$out"; then _fail "a statement is joined to at most 20 lines after it" "$out"; else _pass "a statement is joined to at most 20 lines after it"; fi
if grep -qF -- "not_a_status" <<<"$out"; then _fail "a status-like argument inside a call is not a Flask refusal" "$out"; else _pass "a status-like argument inside a call is not a Flask refusal"; fi
if grep -qF -- "commented_continuation" <<<"$out"; then _fail "a comment on a joined line is not read as a status" "$out"; else _pass "a comment on a joined line is not read as a status"; fi
if grep -qF -- "builds_a_dict" <<<"$out"; then _fail "a balanced multi-line return is not joined to a later line" "$out"; else _pass "a balanced multi-line return is not joined to a later line"; fi
if grep -qF -- "not-a-control pkg/auth.py:26  exempt" <<<"$out"; then _pass "a reason above a Python def exempts it"; else _fail "a reason above a Python def exempts it" "$out"; fi
if grep -q 'plain' <<<"$out"; then _fail "a commented-out abort is nothing" "$out"; else _pass "a commented-out abort is nothing"; fi
printf "| CM-01 | admin | \`pkg/auth.py:require_admin\` | - | \`test_auth.py\` | n |\n" >> "$P/docs/security/CONTROL-MANIFEST.md"
out=$(cd "$P" && bash "$DC" --list 2>&1)
if grep -qF -- "registered CM-01 pkg/auth.py:6  require_admin" <<<"$out"; then _pass "a manifest row registers a Python guard"; else _fail "a manifest row registers a Python guard" "$out"; fi
out=$(cd "$P" && bash "$DC" --draft draft.md 2>&1); rc=$?
if [ "$rc" -eq 1 ] && [ -f "$P/draft.md" ]; then _pass "--draft writes the file and still exits 1 while guards are unregistered"; else _fail "--draft writes the file" "rc=$rc $(ls "$P")"; fi
draft=$(cat "$P/draft.md" 2>/dev/null)
if grep -qF -- "| CM-02 | require_login — 401 refusal | \`pkg/auth.py:require_login\` | - | - | drafted by derive-controls: no test names require_login · mutate:noop |" <<<"$draft"; then
  _pass "the draft numbers rows after the manifest's last id and says when no test names the guard"
else _fail "the draft numbers rows after the manifest's last id" "$draft"; fi
if grep -q 'require_admin' <<<"$draft"; then _fail "a registered guard is not drafted again" "$draft"; else _pass "a registered guard is not drafted again"; fi
printf 'from auth import require_owner\n\n\ndef test_owner():\n    assert require_owner\n' > "$P/pkg/tests/test_owner.py"
out=$(cd "$P" && bash "$DC" --draft - 2>&1)
if grep -qF -- "| \`pkg/auth.py:require_owner\` | - | \`test_owner.py\` | drafted by derive-controls · mutate:noop |" <<<"$out"; then _pass "the draft names the test file that mentions the guard"; else _fail "the draft names the test file that mentions the guard" "$out"; fi

# ── --draft suggests controls by name: what protects without refusing (never blocking) ──
echo "── derive-controls --draft: suggestions by name ──"
S=$(mktemp -d); trap 'rm -rf "$T" "$P" "$S"' EXIT
( cd "$S" && git init -q . && git config user.email t@t && git config user.name t
  mkdir -p backend/src/middleware backend/src/services docs/security backend/src/__tests__
  printf 'APP_TRACK: web\nSECURITY_TIER: IL4\nPROVIDER: aws\nAPP_TYPE: n/a\n' > project.config.yaml
  printf "| CM-01 | x | \`backend/src/services/notes.ts:redactRegistered\` | - | - | n |\n" > docs/security/CONTROL-MANIFEST.md
  cat > backend/src/services/notes.ts <<'TS'
export function redactNotesFor(row, caller) { return { ...row, notes: null } }
export function redactRegistered(row) { return row }
// not-a-control: a display helper that only trims whitespace for the UI
export function sanitizeLabel(s) { return s.trim() }
export function formatDate(d) { return d.toISOString() }
export function unmaskForDisplay(s) { return s }
export function bitmaskOf(flags) { return flags.reduce((a, b) => a | b, 0) }
export const authorizedRoles = ["admin", "csm"]
export function maskSsn(s) { return "***" }
export function sanitiseHtml(s) { return s.replace(/</g, "") }
export function unMaskField(s) { return s }
export const apiLimiter = rateLimit({ windowMs: 60000, max: 100 })
export const verifyToken = async (
  req, res, next
) => { next() }
export const canReadAll = (u) => u.admin
export function canonicalName(n) { return n }
export function gate(u) { if (!u) throw new AppError(403, "F", "no") }
export function requireOwner(u) { if (u.id !== 1) throw new AppError(403, "F", "no") }
TS
  cat > backend/src/middleware/http.ts <<'TS'
export function globalErrorHandler(err, req, res, next) { res.status(500).json({ code: "INTERNAL" }) }
export const onError = (err, req, res, next) => res.status(500).end()
export function createUnauthRateLimiter() { return (q, s, n) => n() }
export async function verifySession(cookie) { return cookie === "ok" }
export function assertNotTestRuntime() { return true }
export function requestLogger(req, res, next) { next() }
export const RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
TS
  printf 'import { verifySession } from "../src/middleware/http"\ntest("v", () => verifySession("ok"))\n' > backend/src/__tests__/http.test.ts
  git add -A && git commit -qm base )
keep="$S/not-the-scripts.txt"; echo keep > "$keep"
out=$(cd "$S" && DRAFT_TMP="$keep" DRAFT_COUNT="$keep" bash "$DC" --draft draft.md 2>&1); rc=$?
draft=$(cat "$S/draft.md" 2>/dev/null)
if [ "$(cat "$keep" 2>/dev/null)" = keep ]; then _pass "the draft's scratch files are its own, never a path the environment names"
else _fail "the draft's scratch files are its own" "$(cat "$keep" 2>&1)"; fi
if grep -qF -- "drafting from 2 *.ts file(s) under backend/src/middleware backend/src/services" <<<"$out"; then _pass "the draft says which directories it read"
else _fail "the draft says which directories it read" "$out"; fi
if [ "$rc" -eq 1 ]; then _pass "suggestions never change the exit: the two refusals still exit 1"; else _fail "suggestions never change the exit" "rc=$rc"; fi
for want in "redactNotesFor — suggested: hides data, check me" "globalErrorHandler — suggested: fails safely, check me" \
            "onError — suggested: fails safely, check me" "createUnauthRateLimiter — suggested: limits abuse, check me" \
            "verifySession — suggested: proves identity, check me" "assertNotTestRuntime — suggested: refuses or scopes access, check me" \
            "canReadAll — suggested: refuses or scopes access, check me" "requestLogger — suggested: records security events, check me" \
            "maskSsn — suggested: hides data, check me" "sanitiseHtml — suggested: hides data, check me" \
            "apiLimiter — suggested: limits abuse, check me" "verifyToken — suggested: proves identity, check me"; do
  if grep -qF -- "$want" <<<"$draft"; then _pass "suggests ${want%% —*}"; else _fail "suggests ${want%% —*}" "$draft"; fi
done
for not in formatDate canonicalName sanitizeLabel redactRegistered RATE_LIMIT_EXCEEDED unmaskForDisplay unMaskField bitmaskOf authorizedRoles; do
  if grep -qF -- ":$not\`" <<<"$draft"; then _fail "does not suggest $not" "$draft"; else _pass "does not suggest $not"; fi
done
if [ "$(grep -c ':requireOwner`' <<<"$draft")" = 1 ] && grep -qF -- "requireOwner — 403 refusal" <<<"$draft"; then
  _pass "a function that refuses is drafted once, as a refusal, never again as a suggestion"
else _fail "a refusal is drafted once" "$draft"; fi
if grep -qF -- "| \`backend/src/middleware/http.ts:verifySession\` | - | \`http.test.ts\` | suggested by name, not a refusal: delete the row if it is not a control |" <<<"$draft"; then
  _pass "a suggested row names the test that mentions it and says how to judge it"
else _fail "a suggested row names its test" "$draft"; fi
if grep -qF -- "12 function(s) suggested by name" <<<"$out"; then _pass "the summary counts the suggestions"; else _fail "the summary counts the suggestions" "$out"; fi
out=$(cd "$S" && bash "$DC" --list 2>&1)
if grep -q "suggested" <<<"$out"; then _fail "--list without --draft suggests nothing" "$out"; else _pass "--list without --draft suggests nothing"; fi
( cd "$P" && printf 'def redact_token(t):\n    return "[x]"\n\n\ndef verify_signature(b):\n    return True\n\n\ndef helper():\n    return 1\n' > pkg/hide.py && git add -A && git commit -qm py )
draft=$(cd "$P" && bash "$DC" --draft - 2>&1)
if grep -qF -- "| \`pkg/hide.py:redact_token\` | - | - | suggested by name, not a refusal: delete the row if it is not a control · mutate:redact |" <<<"$draft" && grep -qF -- "verify_signature — suggested: proves identity, check me" <<<"$draft" && ! grep -q ":helper\`" <<<"$draft"; then
  _pass "Python functions are suggested by the same names, and a redaction is broken by handing its input back"
else _fail "Python functions are suggested by the same names" "$draft"; fi

# ── --infer-roots: a repository that names no roots and has none of the default ones (2026-10-28) ──
# A Python service or a plain-JS Express app with no project.config.yaml drafted nothing: the script
# read backend/src/{middleware,services,controllers} only. --infer-roots reads the layout instead,
# and only when nothing is configured and the default roots are absent; --propose-config writes the
# config lines that would make the inference permanent.
echo "── derive-controls --infer-roots ──"
I=$(mktemp -d); trap 'rm -rf "$T" "$P" "$S" "$I"' EXIT
( cd "$I" && git init -q py && cd py && mkdir -p svc tests docs venv src build-tools
  printf 'fastapi\n' > requirements.txt
  : > svc/__init__.py; : > tests/__init__.py; : > docs/__init__.py; : > venv/__init__.py; : > venv/pyvenv.cfg
  printf 'def require_admin(user):\n    if user.role != "admin":\n        raise HTTPException(status_code=403)\n' > svc/auth.py
  printf 'def require_owner(user, doc):\n    if doc.owner != user:\n        raise PermissionDenied("no")\n' > src/owner.py
  printf 'def in_tests(u):\n    raise PermissionDenied("x")\n' > tests/helpers.py
  printf 'def in_docs(u):\n    raise PermissionDenied("x")\n' > docs/example.py
  printf 'def in_venv(u):\n    raise PermissionDenied("x")\n' > venv/site.py
  printf 'from svc.auth import require_admin\n\n\ndef test_admin():\n    assert require_admin\n' > tests/test_auth.py )
out=$(cd "$I/py" && bash "$DC" --draft - 2>&1)
if ! grep -q '^| CM-' <<<"$out"; then _pass "without --infer-roots a Python repository with no config drafts nothing, as before"
else _fail "without --infer-roots nothing changes" "$out"; fi
out=$(cd "$I/py" && bash "$DC" --infer-roots --draft - --propose-config "$I/py.cfg" 2>&1)
has_() { if grep -qF -- "$2" <<<"$3"; then _pass "$1"; else _fail "$1" "$(printf '%s' "$3" | tail -6)"; fi; }
hasnt_() { if grep -qF -- "$2" <<<"$3"; then _fail "$1" "$(printf '%s' "$3" | tail -6)"; else _pass "$1"; fi; }
has_ "Python: a package dir with __init__.py is a root" "| \`svc/auth.py:require_admin\` | - | \`test_auth.py\` | drafted by derive-controls · mutate:noop |" "$out"
has_ "Python: src/ is a root without an __init__.py" "\`src/owner.py:require_owner\`" "$out"
hasnt_ "Python: tests/ is never a root" "in_tests" "$out"
hasnt_ "Python: docs/ is never a root" "in_docs" "$out"
hasnt_ "Python: a virtualenv is never a root" "in_venv" "$out"
has_ "the draft says the roots were inferred, and from what" "inferred the control roots src svc (*.py) from the layout" "$out"
cfg=$(cat "$I/py.cfg" 2>/dev/null)
has_ "--propose-config: CONTROL_SRC_ROOTS" "CONTROL_SRC_ROOTS: src svc" "$cfg"
has_ "--propose-config: CONTROL_SRC_EXT" "CONTROL_SRC_EXT: py" "$cfg"
has_ "--propose-config: CONTROL_TEST_DIR" "CONTROL_TEST_DIR: tests" "$cfg"
has_ "--propose-config: CONTROL_TEST_CMD" "CONTROL_TEST_CMD: python3 -m pytest -q -x" "$cfg"

( cd "$I" && git init -q js && cd js && mkdir -p src/routes test
  printf '{ "name": "api", "scripts": { "test": "node --test" } }\n' > package.json
  printf 'requests\n' > requirements.txt   # a package.json makes it a JavaScript repository whatever else is there
  printf 'function requireAdmin(req, res, next) {\n  if (req.user.role !== "admin") return res.status(403).end()\n  next()\n}\nmodule.exports = { requireAdmin }\n' > src/auth.js
  printf 'export function requireOwner(u: { id: number }) { if (u.id !== 1) throw new AppError(404, "F", "no") }\n' > src/routes/owner.ts
  printf 'function inTest() { throw new AppError(403, "x") }\n' > src/auth.test.js
  printf 'const { requireAdmin } = require("../src/auth")\n' > test/auth.test.js )
out=$(cd "$I/js" && bash "$DC" --infer-roots --draft - --propose-config "$I/js.cfg" 2>&1)
has_ "JavaScript: a .js guard under src/ is drafted" "| \`src/auth.js:requireAdmin\` | - | \`auth.test.js\` | drafted by derive-controls |" "$out"
has_ "TypeScript: a .ts guard under src/ is drafted" "\`src/routes/owner.ts:requireOwner\`" "$out"
hasnt_ "a test file under a root is never read" "inTest" "$out"
cfg=$(cat "$I/js.cfg" 2>/dev/null)
has_ "--propose-config: the JavaScript roots" "CONTROL_SRC_ROOTS: src" "$cfg"
has_ "--propose-config: the extensions read" "CONTROL_SRC_EXT: ts tsx js jsx" "$cfg"
has_ "--propose-config: the test directory" "CONTROL_TEST_DIR: test" "$cfg"
has_ "--propose-config: npm test when package.json has a test script" "CONTROL_TEST_CMD: npm test --silent" "$cfg"

# What the repository says wins: CONTROL_SRC_ROOTS set, or the default layout present, and nothing is inferred.
( cd "$I/py" && printf 'CONTROL_SRC_ROOTS: svc\nCONTROL_SRC_EXT: py\n' > project.config.yaml )
rm -f "$I/py.cfg"
out=$(cd "$I/py" && bash "$DC" --infer-roots --draft - --propose-config "$I/py.cfg" 2>&1)
has_ "an explicit CONTROL_SRC_ROOTS wins over inference" "\`svc/auth.py:require_admin\`" "$out"
hasnt_ "an explicit CONTROL_SRC_ROOTS: the other roots are not read" "require_owner" "$out"
hasnt_ "an explicit CONTROL_SRC_ROOTS: nothing is said to be inferred" "inferred the control roots" "$out"
if [ -s "$I/py.cfg" ]; then _fail "an explicit config: no config is proposed" "$(cat "$I/py.cfg")"; else _pass "an explicit config: no config is proposed"; fi
out=$(cd "$I/py" && GATE_GUARD_ROOTS=src bash "$DC" --infer-roots --draft - 2>&1)
hasnt_ "GATE_GUARD_ROOTS wins over inference" "inferred the control roots" "$out"
( cd "$I/js" && mkdir -p backend/src/services && printf 'export function gate(u) { if (!u) throw new AppError(403, "F", "no") }\n' > backend/src/services/gate.ts )
rm -f "$I/js.cfg"
out=$(cd "$I/js" && bash "$DC" --infer-roots --draft - --propose-config "$I/js.cfg" 2>&1)
has_ "the default layout wins over inference" "\`backend/src/services/gate.ts:gate\`" "$out"
hasnt_ "the default layout: src/ is not read" "requireAdmin" "$out"
if [ -s "$I/js.cfg" ]; then _fail "the default layout: no config is proposed" "$(cat "$I/js.cfg")"; else _pass "the default layout: no config is proposed"; fi
echo; echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
