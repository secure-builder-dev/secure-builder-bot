#!/usr/bin/env bash
# sql-scan.sh — parameterized queries only. Flags SQL built by string interpolation or
# concatenation in backend source. Runs in `make check`.
# USAGE engine/scripts/gate/sql-scan.sh     EXIT 0 clean · 1 findings (or nothing to scan → 0)

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1
cfg() {   # $1 = key in project.config.yaml
  [ -f project.config.yaml ] || return 0
  sed -nE "s/^[[:space:]]*$1:[[:space:]]*\"?([^\"#]*)\"?[[:space:]]*(#.*)?$/\1/p" project.config.yaml | head -1 | sed -E 's/[[:space:]]+$//'
}
is_android() { [ -f android/gradlew ] || [ "$(cfg APP_TRACK)" = android ]; }

# "Skipped" made two different things look the same: a check that could have run and did not, and a
# check that has nothing to run against. An android plugin has no backend/src and no TypeScript, so
# there is genuinely nothing here — but a track that quietly runs fewer checks than another is
# exactly what a gate should say out loud rather than leave to be inferred from a log.
if [ ! -d backend/src ]; then
  if is_android; then
    echo "sql-scan: NOT APPLICABLE on the android track — this check reads TypeScript and JavaScript"
    echo "sql-scan:   under backend/src. Kotlin persistence is covered by no check in this engine today."
  else
    echo "sql-scan: nothing to scan yet — no backend/src in this repo"
  fi
  exit 0
fi
TMP="$(mktemp)"
# NOT 'backend/src/**/*.ts' — that pathspec matches only files at least one directory deep, so
# everything directly under backend/src (app.ts, db.ts) was never scanned and the check said clean.
git ls-files backend/src | grep -E '\.(ts|js)$' | grep -v '/__tests__/\|\.test\.\|/test/' | while IFS= read -r f; do
  # .query(`... ${x} ...`)   .raw("..." + x)   knex.raw(`${...}`)  sql`...${...}` is allowed (tagged, parameterized)
  grep -nE '\.(query|raw|execute|unsafe)\([^)]*`[^`]*\$\{' "$f" 2>/dev/null | grep -v 'sql-scan: allow' | sed "s|^|  $f:|" | tee -a "$TMP"
  grep -nE '\.(query|raw|execute|unsafe)\([^)]*["'"'"'][^"'"'"']*["'"'"'][[:space:]]*\+[[:space:]]*[A-Za-z_]' "$f" 2>/dev/null | grep -v 'sql-scan: allow' | sed "s|^|  $f:|" | tee -a "$TMP"
done
if [ -s "$TMP" ]; then echo "sql-scan: $(wc -l < "$TMP" | tr -d ' ') string-built quer(y/ies) — use parameters"; rm -f "$TMP"; exit 1; fi
rm -f "$TMP"; echo "sql-scan: clean"
