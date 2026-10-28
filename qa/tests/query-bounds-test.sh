#!/usr/bin/env bash
# query-bounds tests — the check must FAIL on an unbounded read and PASS on a bounded one.
#
# WHY   A scanner that has never gone red is indistinguishable from one that works. Every case
#       below that expects exit 1 is a negative fixture: it exists so the check can be observed
#       failing against input built to break it. The pass cases exist so it is not merely a
#       function that always returns 1.
#       Part of the qa module since 2026-10-23, beside qa/scripts/query-bounds.sh. Every case is an
#       if/else so a true branch can never fall through to the failure message (SC2015).

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QA="$(cd "$SCRIPT_DIR/.." && pwd)"
CHK="$QA/scripts/query-bounds.sh"

PASS=0; FAIL=0
_pass() { echo "  ok    $1"; PASS=$((PASS + 1)); }
_fail() { echo "  FAIL  $1 — $2"; FAIL=$((FAIL + 1)); }

echo "── query-bounds: unbounded reads must be caught ──"

# mkrepo <dir> [android]
mkrepo() {
  local d="$1"
  mkdir -p "$d"; ( cd "$d" && git init -q . && git config user.email t@t && git config user.name t )
  if [ "${2:-web}" = android ]; then
    mkdir -p "$d/android"; printf '#!/bin/sh\nexit 0\n' > "$d/android/gradlew"
    printf 'APP_TRACK: android\n' > "$d/project.config.yaml"
  else
    mkdir -p "$d/backend/src"
    printf 'APP_TRACK: web\n' > "$d/project.config.yaml"
  fi
}
commit() { ( cd "$1" && git add -A && git commit -qm t ); }
run() { OUT=$(cd "$1" && bash "$CHK" 2>&1); RC=$?; return 0; }

# The check is awk. gawk accepts `\y` word boundaries; mawk (Debian/Ubuntu's default awk) silently
# never matches them, which is how the EXISTS / SELECT 1 / count() exclusions were dead on every
# Debian box while passing on every Mac (F-D16). When mawk is installed, the exclusion cases below
# run under it too, through a PATH shim, so the regexes are proven POSIX rather than assumed.
AWK_SHIM=""
if command -v mawk >/dev/null 2>&1; then
  AWK_SHIM="$(mktemp -d)"; ln -s "$(command -v mawk)" "$AWK_SHIM/awk"
fi
run_mawk() { [ -n "$AWK_SHIM" ] || return 1; OUT=$(cd "$1" && PATH="$AWK_SHIM:$PATH" bash "$CHK" 2>&1); RC=$?; return 0; }

# ── negative fixtures: these MUST fail ───────────────────────────────────────
T=$(mktemp -d); mkrepo "$T"
cat > "$T/backend/src/users.ts" <<'TS'
export async function listUsers(tenantId) {
  return await User.findAll({
    where: { tenantId },
  });
}
TS
commit "$T"; run "$T"
if [ "$RC" -eq 1 ]; then _pass "multi-line findAll with no limit FAILS"; else _fail "multi-line findAll with no limit FAILS" "exit $RC: $OUT"; fi
if grep -q 'users.ts:2' <<<"$OUT"; then _pass "…and names the file and line"; else _fail "…and names the file and line" "got: $OUT"; fi
rm -rf "$T"

T=$(mktemp -d); mkrepo "$T"
printf "const rows = await db.query(\`SELECT id, name FROM orders WHERE tenant = %s\`);\n" "\${t}" > "$T/backend/src/orders.ts"
commit "$T"; run "$T"
if [ "$RC" -eq 1 ]; then _pass "raw SELECT with no LIMIT FAILS"; else _fail "raw SELECT with no LIMIT FAILS" "exit $RC: $OUT"; fi
rm -rf "$T"

T=$(mktemp -d); mkrepo "$T"
printf 'const all = await prisma.invoice.findMany({ where: { open: true } });\n' > "$T/backend/src/inv.ts"
commit "$T"; run "$T"
if [ "$RC" -eq 1 ]; then _pass "single-line findMany with no take FAILS"; else _fail "single-line findMany with no take FAILS" "exit $RC: $OUT"; fi
rm -rf "$T"

# ── bounded reads must pass ──────────────────────────────────────────────────
T=$(mktemp -d); mkrepo "$T"
cat > "$T/backend/src/users.ts" <<'TS'
export async function listUsers(tenantId, page) {
  return await User.findAll({
    where: { tenantId },
    limit: 50,
    offset: page * 50,
  });
}
TS
commit "$T"; run "$T"
if [ "$RC" -eq 0 ]; then _pass "findAll WITH limit passes"; else _fail "findAll WITH limit passes" "exit $RC: $OUT"; fi
rm -rf "$T"

T=$(mktemp -d); mkrepo "$T"
printf 'const rows = await db.query("SELECT id FROM orders LIMIT 100");\n' > "$T/backend/src/orders.ts"
commit "$T"; run "$T"
if [ "$RC" -eq 0 ]; then _pass "raw SELECT with LIMIT passes"; else _fail "raw SELECT with LIMIT passes" "exit $RC: $OUT"; fi
rm -rf "$T"

T=$(mktemp -d); mkrepo "$T"
printf 'const n = await db.query("SELECT COUNT(*) FROM orders");\n' > "$T/backend/src/count.ts"
commit "$T"; run "$T"
if [ "$RC" -eq 0 ]; then _pass "SELECT COUNT(*) is bounded, passes"; else _fail "SELECT COUNT(*) is bounded, passes" "exit $RC: $OUT"; fi
if run_mawk "$T"; then
  if [ "$RC" -eq 0 ]; then _pass "…and under mawk"; else _fail "…and under mawk" "exit $RC: $OUT"; fi
fi
rm -rf "$T"

# A correlated EXISTS subquery is a boolean probe, not a row set. Its inner `SELECT 1 FROM` must not
# be read as an unbounded SELECT. Under mawk this case failed before F-D16.
T=$(mktemp -d); mkrepo "$T"
cat > "$T/backend/src/exists.ts" <<'TS'
const ok = await db.query(
  `SELECT id FROM vehicles v WHERE EXISTS (SELECT 1 FROM assignments a WHERE a.vehicle_id = v.id) LIMIT 20`,
);
const any = await db.query(`SELECT EXISTS (SELECT 1 FROM assignments WHERE vehicle_id = $1)`, [id]);
TS
commit "$T"; run "$T"
if [ "$RC" -eq 0 ]; then _pass "correlated WHERE EXISTS (SELECT 1 FROM …) is not flagged"; else _fail "correlated WHERE EXISTS (SELECT 1 FROM …) is not flagged" "exit $RC: $OUT"; fi
if run_mawk "$T"; then
  if [ "$RC" -eq 0 ]; then _pass "…and under mawk"; else _fail "…and under mawk" "exit $RC: $OUT"; fi
else
  echo "  skip  mawk not installed — EXISTS exclusion proven under $(awk --version 2>&1 | head -1 || echo awk) only"
fi
rm -rf "$T"

# …while a bare `SELECT ... FROM` on the same line shape is still caught, so the exclusion is not a
# blanket pass for anything mentioning EXISTS or 1.
T=$(mktemp -d); mkrepo "$T"
printf "const rows = await db.query(\`SELECT id, exists_flag FROM orders WHERE qty > 1\`);\n" > "$T/backend/src/orders.ts"
commit "$T"; run "$T"
if [ "$RC" -eq 1 ]; then _pass "exists_flag column and a literal 1 do not trigger the exclusion — still FAILS"; else _fail "exists_flag column and a literal 1 do not trigger the exclusion — still FAILS" "exit $RC: $OUT"; fi
if run_mawk "$T"; then
  if [ "$RC" -eq 1 ]; then _pass "…and under mawk"; else _fail "…and under mawk" "exit $RC: $OUT"; fi
fi
rm -rf "$T"

T=$(mktemp -d); mkrepo "$T"
printf 'const t = await Tier.findAll({}); // query-bounds: allow — fixed 4-row lookup table\n' > "$T/backend/src/tiers.ts"
commit "$T"; run "$T"
if [ "$RC" -eq 0 ]; then _pass "the allow annotation suppresses a finding"; else _fail "the allow annotation suppresses a finding" "exit $RC: $OUT"; fi
rm -rf "$T"

T=$(mktemp -d); mkrepo "$T"; mkdir -p "$T/backend/src/__tests__"
printf 'const all = await User.findAll({});\n' > "$T/backend/src/__tests__/users.test.ts"
printf 'export const ok = 1;\n' > "$T/backend/src/app.ts"
commit "$T"; run "$T"
if [ "$RC" -eq 0 ]; then _pass "test files are not scanned"; else _fail "test files are not scanned" "exit $RC: $OUT"; fi
rm -rf "$T"

# ── the three not-clean states must each be distinguishable ──────────────────
T=$(mktemp -d); mkrepo "$T" android; commit "$T"; run "$T"
if [ "$RC" -eq 0 ]; then _pass "android track exits 0"; else _fail "android track exits 0" "exit $RC"; fi
if grep -qi 'not applicable' <<<"$OUT"; then _pass "android says NOT APPLICABLE"; else _fail "android says NOT APPLICABLE" "got: $OUT"; fi
if grep -qi 'skipped' <<<"$OUT"; then _fail "android does not say 'skipped'" "it does: $OUT"; else _pass "android does not say 'skipped'"; fi
if grep -qi 'room\|jdbc' <<<"$OUT"; then _pass "…and names the Kotlin gap it leaves"; else _fail "…and names the Kotlin gap it leaves" "got: $OUT"; fi
rm -rf "$T"

T=$(mktemp -d); mkrepo "$T"; rmdir "$T/backend/src" "$T/backend"; commit "$T" 2>/dev/null; run "$T"
if grep -qi 'nothing to scan yet' <<<"$OUT"; then _pass "no backend/src on web says 'nothing to scan yet'"; else _fail "no backend/src on web says 'nothing to scan yet'" "got: $OUT"; fi
if grep -qi 'not applicable' <<<"$OUT"; then _fail "…and does NOT claim not-applicable" "it does: $OUT"; else _pass "…and does NOT claim not-applicable"; fi
rm -rf "$T"

# The vacuous-pass case: the directory exists, the file set is empty, nothing was read.
T=$(mktemp -d); mkrepo "$T"; printf 'x\n' > "$T/README.md"; commit "$T"; run "$T"
if grep -qi 'nothing was read' <<<"$OUT"; then _pass "empty source set says nothing was read"; else _fail "empty source set says nothing was read" "got: $OUT"; fi
if grep -qi 'clean' <<<"$OUT"; then _fail "…and does NOT report clean" "it claims clean having read nothing: $OUT"; else _pass "…and does NOT report clean"; fi
rm -rf "$T"

# A clean pass must state how much it read, so "clean" can be told from "read nothing".
T=$(mktemp -d); mkrepo "$T"
printf 'const u = await User.findOne({ where: { id } });\n' > "$T/backend/src/one.ts"
commit "$T"; run "$T"
if [ "$RC" -eq 0 ]; then _pass "findOne is bounded, passes"; else _fail "findOne is bounded, passes" "exit $RC: $OUT"; fi
if grep -q '1 file(s) read' <<<"$OUT"; then _pass "…and the clean line reports the file count"; else _fail "…and the clean line reports the file count" "got: $OUT"; fi
rm -rf "$T"

[ -n "$AWK_SHIM" ] && rm -rf "$AWK_SHIM"
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
