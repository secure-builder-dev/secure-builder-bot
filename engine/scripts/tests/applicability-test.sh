#!/usr/bin/env bash
# Applicability tests — a check that cannot apply must say so, not say "skipped".
#
# WHY   Three mechanical checks are Express/nginx shaped and have nothing to run against on the
#       android track. That is correct. What was not correct was the wording: "skipped" reads the
#       same whether a check could have run and did not, or had nothing to run against at all. The
#       effect was that a pure ATAK plugin passed a thinner `make check` than a web app, and no line
#       in the log said so.
#
#       These pin the distinction, because it is the whole point of the change. A regression here is
#       silent by nature — the exit code stays 0 either way.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$SCRIPT_DIR/../gate"

PASS=0; FAIL=0
_pass() { echo "  ok    $1"; PASS=$((PASS + 1)); }
_fail() { echo "  FAIL  $1 — $2"; FAIL=$((FAIL + 1)); }

echo "── applicability: not-applicable vs skipped vs nothing-yet ──"

# mk <dir> [android|web|empty]
mk() {
  local d="$1" kind="$2"
  mkdir -p "$d"; ( cd "$d" && git init -q . && git config user.email t@t && git config user.name t )
  case "$kind" in
    android)
      mkdir -p "$d/android"; printf '#!/bin/sh\nexit 0\n' > "$d/android/gradlew"; chmod +x "$d/android/gradlew"
      printf 'APP_TRACK: android\n' > "$d/project.config.yaml" ;;
    web)
      mkdir -p "$d/backend/src" "$d/frontend"
      printf 'const x=1;\n' > "$d/backend/src/app.ts"
      printf 'server { listen 80; }\n' > "$d/frontend/nginx.conf.template"
      printf 'APP_TRACK: web\n' > "$d/project.config.yaml"
      ( cd "$d" && git add -A && git commit -qm init ) ;;
  esac
}
run() { OUT=$(cd "$1" && bash "$GATE/$2" 2>&1); RC=$?; return 0; }

# ── android: both checks must name the track, not say "skipped" ──────────────
T=$(mktemp -d); mk "$T" android
for chk in sql-scan.sh check-nginx-surface.sh; do
  run "$T" "$chk"
  [ "$RC" -eq 0 ] && _pass "$chk exits 0 on android" || _fail "$chk exits 0 on android" "exit $RC"
  grep -qi "not applicable" <<<"$OUT" \
    && _pass "$chk says NOT APPLICABLE on android" \
    || _fail "$chk says NOT APPLICABLE on android" "got: $OUT"
  grep -qi "skipped" <<<"$OUT" \
    && _fail "$chk no longer says 'skipped' on android" "it still says skipped: $OUT" \
    || _pass "$chk no longer says 'skipped' on android"
done
# The honest part: say that Kotlin persistence is covered by nothing, rather than implying coverage.
run "$T" sql-scan.sh
grep -qi "kotlin" <<<"$OUT" \
  && _pass "sql-scan admits Kotlin persistence is uncovered" \
  || _fail "sql-scan admits Kotlin persistence is uncovered" "no mention of the gap: $OUT"
rm -rf "$T"

# ── empty repo: nothing yet is NOT the same claim as not applicable ──────────
T=$(mktemp -d); mk "$T" empty
for chk in sql-scan.sh check-nginx-surface.sh; do
  run "$T" "$chk"
  [ "$RC" -eq 0 ] && _pass "$chk exits 0 on an empty repo" || _fail "$chk exits 0 on an empty repo" "exit $RC"
  grep -qi "not applicable" <<<"$OUT" \
    && _fail "$chk does not claim 'not applicable' on an empty repo" "an empty web repo may still grow a backend: $OUT" \
    || _pass "$chk does not claim 'not applicable' on an empty repo"
done
rm -rf "$T"

# ── web: the checks actually run, and say neither thing ──────────────────────
T=$(mktemp -d); mk "$T" web
run "$T" sql-scan.sh
[ "$RC" -eq 0 ] && _pass "sql-scan runs clean on a web repo" || _fail "sql-scan runs clean on a web repo" "exit $RC — $OUT"
grep -qiE "not applicable|nothing to scan" <<<"$OUT" \
  && _fail "sql-scan does not bail out on a web repo" "it bailed: $OUT" \
  || _pass "sql-scan does not bail out on a web repo"

run "$T" check-nginx-surface.sh
grep -qiE "not applicable|no nginx config tracked yet" <<<"$OUT" \
  && _fail "check-nginx-surface does not bail out on a web repo" "it bailed: $OUT" \
  || _pass "check-nginx-surface does not bail out on a web repo"
rm -rf "$T"

# ── the word itself must be gone from both sources ───────────────────────────
for chk in sql-scan.sh check-nginx-surface.sh; do
  if grep -q '— skipped' "$GATE/$chk"; then
    _fail "$chk source carries no '— skipped' message" "the old wording is back"
  else
    _pass "$chk source carries no '— skipped' message"
  fi
done

# ── the pathspec regression: a scanner must read files directly under backend/src ────
# 'backend/src/**/*.ts' matches only files at least one directory deep. Both scanners used it, so
# a query in backend/src/db.ts was invisible and the check reported clean. Found 2026-09-21 by the
# query-bounds negative fixtures. Pinned here because the failure is silent by nature.
T=$(mktemp -d); mkdir -p "$T/backend/src"
( cd "$T" && git init -q . && git config user.email t@t && git config user.name t )
printf 'APP_TRACK: web\n' > "$T/project.config.yaml"
printf 'const r = await db.query(`SELECT * FROM t WHERE id = ${id}`);\n' > "$T/backend/src/db.ts"
( cd "$T" && git add -A && git commit -qm t )
run "$T" sql-scan.sh
[ "$RC" -eq 1 ] \
  && _pass "sql-scan reads files directly under backend/src" \
  || _fail "sql-scan reads files directly under backend/src" "missed backend/src/db.ts, exit $RC: $OUT"
rm -rf "$T"

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
