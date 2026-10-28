#!/usr/bin/env bash
# Fixture tests for qa/scripts/check-frontend-mutations.sh.
#
# Five cases over temp copies of whatever manifest the project ships. The third is the one that matters: restoring the
# COUNT while leaving an id unaccounted for is exactly what a careless "fix" to a failing check looks
# like, and a bare row-count floor would wave it through.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CHECK="$ROOT/qa/scripts/check-frontend-mutations.sh"
REAL="$ROOT/docs/security/FRONTEND-MUTATIONS.md"

PASS=0; FAIL=0
_pass() { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
_fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n       %s\n' "$1" "$2"; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
ROWS="$(grep -c '^| FM-' "$REAL")"
# The ids come FROM the manifest, never hardcoded: every project rewrites this file, so a fixed id
# (FM-07, from the project these tests were written in) breaks the moment the rows change. TARGET is
# the second id, so removing it leaves a gap; FILLER is one past the highest.
TARGET="$(grep -oE '^\| FM-[0-9]+' "$REAL" | sed -n '2p' | grep -oE 'FM-[0-9]+')"
_maxnum="$(grep -oE '^\| FM-[0-9]+' "$REAL" | grep -oE '[0-9]+$' | sort -n | tail -1)"
FILLER="$(printf 'FM-%02d' "$((10#$_maxnum + 1))")"
[ -n "$TARGET" ] || { echo "  FAIL  fixture setup: no second FM- row in $REAL"; exit 1; }

run_check() {   # run_check <manifest> <floor>  -> output in $OUT, status returned
  OUT="$(FM_MANIFEST="$1" FM_FLOOR="$2" bash "$CHECK" 2>&1)"
}

echo "check-frontend-mutations fixture tests"

# 1. the intact manifest passes at its own floor
cp "$REAL" "$TMP/intact.md"
if run_check "$TMP/intact.md" "$ROWS"; then
  _pass "the intact manifest passes at its own row count"
else
  _fail "the intact manifest passes at its own row count" "$OUT"
fi

# 2. a deleted row fails and names it
grep -v "^| $TARGET " "$REAL" > "$TMP/deleted.md"
if run_check "$TMP/deleted.md" "$ROWS"; then
  _fail "a deleted row is refused" "exited 0"
elif grep -q 'a row was removed' <<<"$OUT"; then
  _pass "a deleted row is refused"
else
  _fail "a deleted row is refused" "$OUT"
fi

# 3. count restored, id still unaccounted for — the case a bare count misses
{ grep -v "^| $TARGET " "$REAL"; printf "| %s | src/x.ts | \`a\` | \`b\` | filler added to restore the count |\n" "$FILLER"; } > "$TMP/restored.md"
if run_check "$TMP/restored.md" "$ROWS"; then
  _fail "restoring the count without accounting for the id is refused" "exited 0"
elif grep -q "$TARGET" <<<"$OUT"; then
  _pass "restoring the count without accounting for the id is refused, naming it"
else
  _fail "restoring the count without accounting for the id is refused, naming it" "$OUT"
fi

# 4. a declared removal with the floor lowered passes
{ grep -v "^| $TARGET " "$REAL"; printf '\n## Removed rows\n\n**%s removed 2026-09-26 — superseded by a stronger row.**\n' "$TARGET"; } > "$TMP/declared.md"
if run_check "$TMP/declared.md" "$((ROWS - 1))"; then
  _pass "a declared removal with the floor lowered passes"
else
  _fail "a declared removal with the floor lowered passes" "$OUT"
fi

# 5. a duplicated id is refused
{ cat "$REAL"; grep -m1 "^| $TARGET " "$REAL"; } > "$TMP/dupe.md"
if run_check "$TMP/dupe.md" "$ROWS"; then
  _fail "a duplicated id is refused" "exited 0"
elif grep -q 'duplicate' <<<"$OUT"; then
  _pass "a duplicated id is refused"
else
  _fail "a duplicated id is refused" "$OUT"
fi

printf '\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
