#!/usr/bin/env bash
# verify-controls tests — a manifest row resolves only when its symbol is defined AND wired.
#
# WHY   The section that lived in engine/scripts/gate/selftest.sh until the qa module took the
#       tool (2026-10-23). The fixture is the cases that have bitten this probe: middleware wired
#       by reference (app.use(fn)), an ORM hook by reference, an arrow export, a same-file call
#       site, and the two false positives — a mention in a comment, and a symbol never wired.
#       Python call sites are covered by mutate-controls-test.sh.
#
# USAGE   qa/tests/verify-controls-test.sh        (or: make gate-selftest)
# EXIT    0 = all assertions hold · 1 = at least one failed

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QA="$(cd "$SCRIPT_DIR/.." && pwd)"
VC="$QA/scripts/verify-controls.sh"
FX="$(mktemp -d)"; trap 'rm -rf "$FX"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$3] got [$2]"; fi; }
assert_has() { if grep -qF -- "$3" <<<"$2"; then ok "$1"; else bad "$1" "output lacks [$3]"; fi; }

# ── fixture ───────────────────────────────────────────────────────────────────
cd "$FX" && git init -q && git config user.email t@t && git config user.name t
mkdir -p backend/src/middleware backend/src/hooks backend/src/__tests__ docs/security helm/templates
cat > backend/src/middleware/auth.ts <<'TS'
export function requireAuth(req, res, next) { next() }
export const requireRole = (role) => (req, res, next) => next()
export function neverWired(x) { return x }
TS
cat > backend/src/middleware/errors.ts <<'TS'
export function errorHandler(err, req, res, next) {}
TS
cat > backend/src/hooks/scope.ts <<'TS'
export function scopeTenant(opts) {}
export function onlyInComment() {}
export function sameFileHelper(q) { return q }
export function listAll() { return sameFileHelper(1) }
TS
cat > backend/src/app.ts <<'TS'
import { requireAuth, requireRole } from "./middleware/auth";
import { errorHandler } from "./middleware/errors";
import { scopeTenant, onlyInComment } from "./hooks/scope";
app.use(requireAuth);
router.get("/x", requireRole("admin"), h);
const hooks = { beforeFind: scopeTenant };
// onlyInComment(req) was called here once — this line must NOT count as a call site
app.use(errorHandler);
TS
printf 'x\n' > backend/src/__tests__/auth.test.ts
printf 'kind: NetworkPolicy\n' > helm/templates/netpol.yml
cat > docs/security/CONTROL-MANIFEST.md <<'MD'
| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-01 | token gate | `backend/src/middleware/auth.ts:requireAuth` | - | `auth.test.ts` | by-reference app.use |
| CM-02 | role gate | `backend/src/middleware/auth.ts:requireRole` | - | - | export const arrow, called |
| CM-05 | tenant scope | `backend/src/hooks/scope.ts:scopeTenant` | `helm/templates/netpol.yml` | - | ORM hook by reference |
| CM-10 | error handler | `backend/src/middleware/errors.ts:errorHandler` | - | - | by-reference app.use |
| CM-11 | comment-only | `backend/src/hooks/scope.ts:onlyInComment` | - | - | must FAIL |
| CM-12 | never wired | `backend/src/middleware/auth.ts:neverWired` | - | - | must FAIL |
| CM-13 | same-file helper | `backend/src/hooks/scope.ts:sameFileHelper` | - | - | called only from its own module |
| CM-99 | placeholder | `<path>:<symbol>` | - | `<glob>` | ignored |
MD
git add -A && git commit -qm base

echo "── verify-controls ──"
out=$(bash "$VC"); rc=$?
assert_eq  "exit 1 when any populated row fails"            "$rc" 1
assert_has "CM-01 middleware wired via app.use(ref) is ok"  "$out" "ok    CM-01"
assert_has "CM-02 export const arrow, called, is ok"        "$out" "ok    CM-02"
assert_has "CM-05 ORM hook by reference is ok"              "$out" "ok    CM-05"
assert_has "CM-10 error handler via app.use(ref) is ok"     "$out" "ok    CM-10"
assert_has "CM-11 comment-only mention FAILs"               "$out" "FAIL  CM-11"
assert_has "CM-12 never-wired FAILs"                        "$out" "FAIL  CM-12"
assert_has "CM-13 same-file call site (not the def line) is ok" "$out" "ok    CM-13"
assert_has "placeholder rows excluded from count"           "$out" "7 controls · 2 FAIL · 1 placeholder"

cp docs/security/CONTROL-MANIFEST.md "$FX/.cm"; grep -E '^\| CM-99|^\| id|^\|---' "$FX/.cm" > docs/security/CONTROL-MANIFEST.md
bash "$VC" --quiet; rc=$?
assert_eq  "placeholder-only manifest exits 2 (unpopulated)" "$rc" 2
mv "$FX/.cm" docs/security/CONTROL-MANIFEST.md

printf '\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
