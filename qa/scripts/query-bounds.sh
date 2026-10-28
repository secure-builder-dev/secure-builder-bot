#!/usr/bin/env bash
# query-bounds.sh — every read must be bounded. Flags queries that can return an arbitrary
# number of rows: raw SELECT with no LIMIT, and ORM find-all calls with no limit/take.
#
# WHY   A query with no bound is correct on day one and pages someone at 3am in year two, when a
#       table that held forty rows holds four million. It is the efficiency defect that actually
#       reaches production, it is mechanically detectable, and unlike a "performance scan" it is
#       grounded in a property of the code rather than a guess about cost.
#
# Deliberate unbounded reads (a migration, a fixed-size lookup table) carry `query-bounds: allow`.
#
# USAGE qa/scripts/query-bounds.sh
# EXIT  0 clean / not applicable / nothing to scan · 1 findings

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

cfg() {   # $1 = key in project.config.yaml
  [ -f project.config.yaml ] || return 0
  sed -nE "s/^[[:space:]]*$1:[[:space:]]*\"?([^\"#]*)\"?[[:space:]]*(#.*)?$/\1/p" project.config.yaml | head -1 | sed -E 's/[[:space:]]+$//'
}
is_android() { [ -f android/gradlew ] || [ "$(cfg APP_TRACK)" = android ]; }

# Four states, three of which are not "clean". Saying "skipped" for any of them would make a check
# that had nothing to read indistinguishable from one that read everything and found nothing.
if [ ! -d backend/src ]; then
  if is_android; then
    echo "query-bounds: NOT APPLICABLE on the android track — this check reads TypeScript and JavaScript"
    echo "query-bounds:   under backend/src. Room and JDBC query bounds are covered by no check in this engine today."
  else
    echo "query-bounds: nothing to scan yet — no backend/src in this repo"
  fi
  exit 0
fi

# NOT 'backend/src/**/*.ts' — that pathspec silently misses files directly under backend/src,
# because ** requires at least one intervening directory. A scanner that cannot see app.ts is a
# scanner that reports clean having never read the file most likely to hold the query.
FILES="$(git ls-files backend/src | grep -E '\.(ts|js)$' | grep -v '/__tests__/\|\.test\.\|\.spec\.\|/test/' || true)"

# The empty-set case is its own answer. A loop over nothing that prints "clean" is the exact
# vacuous pass this engine spent 2026-09-19 removing — it reports success having read no code.
if [ -z "$FILES" ]; then
  echo "query-bounds: backend/src exists but holds no tracked .ts/.js source — nothing was read"
  exit 0
fi

TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT

# From the engine's first project (2026-10-03, T-ENGINE-05 / GOV-028). The allow marker used to be
# matched against the accumulated buffer only, and the buffer is flushed as soon as paren depth
# returns to zero -- which, for a SELECT line whose parens already balance, is immediately. So a
# marker on any following line was never seen, and whether a deliberate exemption worked depended
# on whether the SQL happened to call a function on the same line:
#   SELECT TO_CHAR(x) FROM t WHERE id = ?   balances, flushes, marker on the next line ignored
#   SELECT TO_CHAR(x\n) FROM t              does not balance, keeps collecting, marker honoured
# Measured 2026-10-03: two legitimate exemptions took two attempts to mark, the first looking
# correct and silently doing nothing, and the marker ended up crammed onto a long SQL line.
#
# The file is now read twice -- once to index its lines, once to scan -- so the marker can be found
# in a window around the finding. The WINDOW applies to the MARKER ONLY, never to the limit/take
# detection, which still reads just the call it collected. Widening the bound detection would let an
# unrelated `limit` on a later line silently bound a query that has none; widening an explicit
# exemption cannot do that, because `query-bounds: allow` is never incidental.
printf '%s\n' "$FILES" | while IFS= read -r f; do
  [ -f "$f" ] || continue
  awk -v FNAME="$f" -v WINDOW=15 '
    function cnt(s, ch,   t) { t = s; return gsub(ch, "", t) }
    # Find the extent of the ENCLOSING call, not of the SELECT line. This is the distinction the
    # ticket turns on: `db.raw(` may open on one line and the SELECT sit on the next, already
    # balanced in itself, so tracking depth from the SELECT ends the extent immediately and a
    # marker two lines down -- still inside the same call -- is never seen.
    function marker_near(s,   i, d, b, e) {
      # 1. Walk back to the line that opens the call we are inside: the first line, reading
      #    upward, that leaves an unclosed open paren. A blank line ends the search, since a
      #    statement does not span one.
      b = s; d = 0
      for (i = s; i >= 1 && s - i <= WINDOW; i--) {
        d += cnt(L[i], "\\(") - cnt(L[i], "\\)")
        if (d > 0) { b = i; break }
        if (L[i] ~ /^[[:space:]]*$/) break
      }
      # 2. Walk forward from there to where that call closes.
      e = b; d = 0
      for (i = b; i <= NL && i - b <= WINDOW; i++) {
        d += cnt(L[i], "\\(") - cnt(L[i], "\\)")
        e = i
        if (d <= 0) break
      }
      if (e < s) e = s
      # 3. A marker anywhere inside the call exempts it, wherever the author put it.
      for (i = b; i <= e; i++) if (tolower(L[i]) ~ /query-bounds: allow/) return 1
      # 4. Plus an unbroken run of COMMENT lines immediately above the call -- where a human
      #    actually writes an exemption, and bleed-free: the run stops at the first non-comment
      #    line, so it can never reach past an earlier statement and exempt the wrong query.
      #
      #    There is deliberately NO forward comment run beyond the call. A comment attaches to
      #    what follows it, so a marker sitting between two flagged queries belongs to the
      #    second; crediting it to the first would be a false negative. A fixed 15-line forward
      #    window was tried first and exempted an unmarked query nine lines away, which is how
      #    both of these narrowings were found.
      for (i = b - 1; i >= 1; i--) {
        if (L[i] !~ /^[[:space:]]*(\/\/|\*|\/\*|#|--)/) break
        if (tolower(L[i]) ~ /query-bounds: allow/) return 1
      }
      return 0
    }
    NR == FNR { L[FNR] = $0; NL = FNR; next }
    function flush(   low) {
      if (buf == "") return
      low = tolower(buf)
      # A bound anywhere in the call makes it bounded. findOne/findFirst/count return one row.
      # POSIX ERE only: no \y or \b word boundaries. Those are gawk extensions; under mawk (the
      # default awk on Debian and Ubuntu) they never match, which silently disabled the EXISTS,
      # SELECT 1 and count() exclusions. (^|[^a-z_])word([^a-z_]|$) is the portable spelling.
      if (low !~ /limit|take[[:space:]]*:|[.]take\(|first[[:space:]]*:|findone|findfirst|(^|[^a-z_])count\(/ \
          && low !~ /query-bounds: allow/ \
          && !marker_near(start))
        printf "  %s:%d: %s\n", FNAME, start, kind
      buf = ""
    }
    {
      line = $0
      if (collecting) {
        buf = buf " " line; n++
        depth += cnt(line, "\\(") - cnt(line, "\\)")
        if (depth <= 0 || n > 15) { collecting = 0; flush() }
        next
      }
      # ORM: an all-rows read
      if (line ~ /\.(findAll|findMany|findAndCountAll)[[:space:]]*\(/) {
        kind = "unbounded ORM read (findAll/findMany) — no limit or take"
      }
      # Raw SQL: a SELECT that is not an aggregate
      else if (tolower(line) ~ /select[[:space:]]/ && tolower(line) ~ /[[:space:]]from[[:space:]]/ \
               && tolower(line) !~ /count[[:space:]]*\(|(^|[^a-z_])exists([^a-z_]|$)|select[[:space:]]+1([^0-9a-z_]|$)/) {
        kind = "raw SELECT with no LIMIT"
      }
      else next

      start = FNR; buf = line; n = 1
      depth = cnt(line, "\\(") - cnt(line, "\\)")
      if (depth > 0) { collecting = 1 } else { flush() }
    }
    END { if (collecting) flush() }
  ' "$f" "$f" >> "$TMP"
done

if [ -s "$TMP" ]; then
  cat "$TMP"
  echo "query-bounds: $(wc -l < "$TMP" | tr -d ' ') unbounded quer(y/ies) — add a limit, or mark it 'query-bounds: allow'"
  exit 1
fi
echo "query-bounds: clean — $(printf '%s\n' "$FILES" | wc -l | tr -d ' ') file(s) read, every query bounded"
