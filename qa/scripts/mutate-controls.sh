#!/usr/bin/env bash
# mutate-controls.sh — break each declared security control on purpose; the suite must go red.
#
# WHY THIS EXISTS
#   A passing test proves the code behaves. It does not prove the test would notice if the code
#   stopped behaving. verify-controls.sh proves each control is implemented and wired; this
#   proves the tests actually depend on it: for every row in CONTROL-MANIFEST.md the control's
#   body is short-circuited (middleware → `return next()`, decision → `return true`, scoping /
#   redaction → pass the input through untouched), the suite is run, and the suite MUST fail.
#   Green under mutation means the control has no test with teeth — a blocking finding at the
#   epic gate. This is the red-phase commit's real job, done mechanically.
#
# HOW A MUTATION IS CHOSEN
#   1. `mutate:<kind>` in the row's note column wins   (middleware|decision|scope|redact|noop|escalate),
#      or `mutate:stmt=<code>` for an explicit statement (rest of the cell),
#      or `mutate:replace=<exact source> ~> <replacement>` to swap one literal inside the body
#   escalate (slim, T-SLIM-04): the caller becomes admin — `user = { ...user, role: 'admin' }` as the
#      first statement. It removes every role branch at once without touching anything else, which is
#      the question a role-gated guard has to answer: does any test notice a `user` acting as `admin`?
#   replace (slim, T-SLIM-04): the first occurrence of the literal at or after the definition is
#      replaced; when there is none, the nearest occurrence BEFORE it (a module-scope constant the
#      function reads — 2026-10-12, T-ENGINE-17). Name a literal only this guard carries. For a guard
#      that is one comparison in the middle of a function — a battalion term is the usual case —
#      where an early return would crash the function rather than weaken the check.
#   2. else inferred: last param named next            → middleware  return next();
#                     boolean return type or name like  → decision    return true;
#                       can/is/has/allow/permit/authorize/check
#                     name like scope/tenant/owner/filter/where → scope   return <firstParam>;
#                                                        (`return;` when the param is options/opts)
#                     name like redact/sanitize/mask/strip     → redact  return <firstParam>;
#                     anything else (TS/JS)              → noop        return;
#      Kotlin: Boolean → return true; Unit → return; any other return type → manual.
#      Python (2026-10-15): decision → return True; scope/redact → return <first param, past self/cls>;
#      noop → return None; stmt and replace as for TS. middleware and escalate are not Python kinds.
#      The mutation goes in as `if True: <mutation>` above the body's first line, at its indent.
#      A project whose controls are Python names their roots and test commands with the CONTROL_*
#      keys in project.config.yaml (qa/scripts/_lib.sh:gate_use_control_roots).
#   The mutation is inserted as the FIRST statement of the innermost body (curried arrows and
#   `return (req,res,next) => {…}` factories are followed to the middleware body). TS type errors
#   the mutation would cause are suppressed with a preceding `// @ts-ignore` line.
#
# SAFETY
#   Each file is backed up to a temp dir before mutation and restored from that backup after the
#   run — on normal exit, on error, and on Ctrl-C (trap). One control is mutated at a time.
#
# TARGETED FIRST (2026-10-07). Each mutation runs the row's own proving test (manifest column 5)
# before anything else, the way mutation tools scope to the tests that cover the change. Red there
# proves the control in seconds. Only when the named test stays green does the full suite run, so a
# control caught by some other test is still proven — the verdict is the same as a full-suite run,
# and only the time changes. A row with no proving test named runs the full suite, as before.
#   Nothing is written anywhere else. The suite runs once unmutated first (baseline) so a suite
#   that is already red cannot make every control look proven.
#
# USAGE   qa/scripts/mutate-controls.sh [--dry-run] [--only CM-01,CM-05] [--no-baseline] [--infer-roots]
#           --dry-run   show the exact mutated line with 2 lines of context per control; run nothing
#           --only      comma-separated manifest ids to include
#           --infer-roots  when no CONTROL_SRC_ROOTS is configured and the default roots are absent, take
#                       the test directories and the suite command from the layout
#                       (qa/scripts/_lib.sh:gate_infer_control_roots); a CONTROL_TEST_CMD in the config
#                       still wins. The QA gate passes it in its drafted mode only.
#           MUTATE_TARGET_CMD  the command for one control's own tests; `{tests}` is replaced by the
#                             row's proving-test files (default web: the suite command with the files
#                             appended, paths relative to backend/; android: `--tests '*<Class>'` per file).
#                             Unset when MUTATE_TEST_CMD is overridden, so a custom suite keeps full runs.
#           MUTATE_TARGET_TIMEOUT  seconds one targeted run may take (default 180; 0 = no cap). A run that
#                             hits it is reported TIMED OUT and counts as not proven; the run moves on.
#           MUTATE_SUITE_TIMEOUT  seconds one mutated full-suite run may take (default three times the
#                             unmutated baseline plus a minute; 0 = no cap). A disabled control that makes the
#                             suite hang is that row TIMED OUT and not proven, never the whole run's time budget.
#           MUTATE_TEST_CMD   override the suite command (default web:
#                             `cd backend && npm test --silent -- --passWithNoTests=false --testTimeout=8000 --forceExit`; a mutated control that never responds must not wait out the project timeout,
#                             android: `cd android && ./gradlew test -q`)
# EXIT    0 = every control proven (or dry-run with every control locatable)
#         1 = at least one control NOT PROVEN, manual, or unlocatable (each is named); or the
#             unmutated baseline is already red
#         2 = manifest missing or holds only placeholder rows
#         3 = --infer-roots inferred the roots and the suite is red before any mutation, or no suite
#             command could be inferred: nothing was proven, and the cause is the inference, not the code
#
# JAVASCRIPT (2026-10-28). A .js / .jsx / .mjs / .cjs body is mutated as TypeScript is, without the
# TypeScript-only parts: no TypeScript suppression comment above it, `if (true)` for `if (true as boolean)`,
# no `as any`.

set -uo pipefail
GATE_LIB="$(cd "$(dirname "$0")" && pwd)/_lib.sh"
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 2
# shellcheck source=/dev/null
. "$GATE_LIB"
gate_use_control_roots
CONTROL_TEST_CMD="$(_gate_cfg CONTROL_TEST_CMD)"; CONTROL_TARGET_CMD="$(_gate_cfg CONTROL_TARGET_CMD)"
CONTROL_HARNESS_RE="$(_gate_cfg CONTROL_HARNESS_RE)"

# CONTROL_MANIFEST: the QA gate points this at a drafted list when the repository declares none, so the
# drafted controls are sabotage-tested before a person confirms them. Unset, the repository's own list.
MANIFEST="${CONTROL_MANIFEST:-docs/security/CONTROL-MANIFEST.md}"
DRY=0; ONLY=""; BASELINE=1; SINCE=""; INFER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --only) ONLY=",${2:-},"; shift 2 ;;
    --since) SINCE="${2:-}"; shift 2 ;;
    --no-baseline) BASELINE=0; shift ;;
    --infer-roots) INFER=1; shift ;;
    -h|--help) sed -n '2,68p' "$0"; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[ -f "$MANIFEST" ] || { printf 'CONTROL MANIFEST: none at %s — nothing to mutate\n' "$MANIFEST"; exit 2; }

# --infer-roots: the layout's test directories and suite command, when nothing is configured.
INFERRED=0; SUITE_NOTE=""
if [ "$INFER" -eq 1 ] && gate_infer_control_roots; then
  INFERRED=1; SUITE_NOTE=" (inferred from the layout: no CONTROL_SRC_ROOTS, no default roots)"
  if [ -z "$CONTROL_TEST_CMD" ] && [ -z "${MUTATE_TEST_CMD:-}" ]; then
    if [ -z "$GATE_INFERRED_TEST_CMD" ] && [ "$DRY" -eq 0 ]; then
      printf 'INFERRED SUITE NOT GREEN: no suite command could be inferred for %s, so nothing was sabotage-tested — set CONTROL_TEST_CMD in project.config.yaml\n' "$GATE_INFERRED_ROOTS"
      exit 3
    fi
    CONTROL_TEST_CMD="$GATE_INFERRED_TEST_CMD"
  else SUITE_NOTE=""; fi
fi

# ── --since: what changed, and does it widen the scope back to everything? ──
CHANGED=""; SINCE_NOTE=""; SINCE_ESCALATED=0
if [ -n "$SINCE" ]; then
  if ! git rev-parse --verify -q "${SINCE}^{commit}" >/dev/null 2>&1; then
    printf -- '--since %s: not a commit\n' "$SINCE" >&2; exit 2
  fi
  if ! git merge-base --is-ancestor "$SINCE" HEAD 2>/dev/null; then
    printf -- '--since %s: not an ancestor of HEAD — run the full mutation check\n' "$SINCE" >&2; exit 2
  fi
  CHANGED="$(git diff --name-only "$SINCE" HEAD 2>/dev/null)"
  # T-SLIM-14 / T-SLIM-15. A row that did not exist at $SINCE has never been proven by any gate, and
  # a row whose line changed since $SINCE (re-pointed symbol, re-pointed proving test, new mutation
  # kind) was proven as something else — whatever the named files did. Both are always re-proven; the
  # file-name test below decides only rows whose manifest line is byte-identical at the base.
  # The base's copy is the repository's own list at $SINCE, wherever CONTROL_MANIFEST points this run:
  # the QA gate hands the head commit's list in as a file outside the checkout, a path no commit holds.
  BASE_MANIFEST="$(git show "$SINCE:docs/security/CONTROL-MANIFEST.md" 2>/dev/null || true)"
  if [ -n "$CONTROL_HARNESS_RE" ]; then harness_re="$CONTROL_HARNESS_RE"
  elif [ "$APP_TRACK" = "android" ]; then harness_re='^android/(app/)?build\.gradle(\.kts)?$|^android/app/src/test/.*(Base|Fixture|Rule)'
  else harness_re='^backend/(src/test/|jest\.config|package\.json$|package-lock\.json$|src/__mocks__/)'; fi
  if grep -qE "$harness_re" <<<"$CHANGED"; then
    SINCE_ESCALATED=1
    SINCE_NOTE="test harness changed in ${SINCE}..HEAD — every control re-proven"
  else
    SINCE_NOTE="scope: rows whose implementation or proving test changed in ${SINCE}..HEAD, and rows added or edited in the manifest since"
  fi
fi
row_changed() {   # $1 = impl file, $2 = proving-test glob, $3 = row id, $4 = the row's line → 0 when the row must be re-proven
  [ -z "$SINCE" ] || [ "$SINCE_ESCALATED" -eq 1 ] && return 0
  local base_line; base_line="$(printf '%s\n' "$BASE_MANIFEST" | grep -m1 -E "^\| *$3 \|" || true)"
  [ -n "$base_line" ] || return 0            # new since $SINCE: never proven (T-SLIM-14)
  [ "$base_line" = "$4" ] || return 0        # row edited since $SINCE: proven as something else (T-SLIM-15)
  grep -qxF "$1" <<<"$CHANGED" && return 0
  case "$2" in ""|"-"|"—") return 1 ;; esac
  local pat d; pat="$(printf '%s' "$2" | sed -E 's/[.]/\\./g; s/\*/.*/g')"
  for d in "${GATE_TEST_DIRS[@]}"; do
    grep -qE "^${d}/${pat}$" <<<"$CHANGED" && return 0
  done
  return 1
}

if [ -n "${MUTATE_TEST_CMD:-}" ]; then TEST_CMD="$MUTATE_TEST_CMD"
elif [ -n "$CONTROL_TEST_CMD" ]; then TEST_CMD="$CONTROL_TEST_CMD"
elif [ "$APP_TRACK" = "android" ]; then
  if [ -x android/gradlew ]; then TEST_CMD="cd android && ./gradlew test -q"; else TEST_CMD="./gradlew test -q"; fi
else TEST_CMD="cd backend && npm test --silent -- --passWithNoTests=false --testTimeout=8000 --forceExit"; fi
# A target command that is given, not derived, takes repo-relative test paths.
TARGET_GIVEN=0
if [ -n "${MUTATE_TARGET_CMD:-}" ]; then TARGET_TMPL="$MUTATE_TARGET_CMD"; TARGET_GIVEN=1
elif [ -n "${MUTATE_TEST_CMD:-}" ]; then TARGET_TMPL=""
elif [ -n "$CONTROL_TARGET_CMD" ]; then TARGET_TMPL="$CONTROL_TARGET_CMD"; TARGET_GIVEN=1
elif [ -n "$CONTROL_TEST_CMD" ]; then TARGET_TMPL=""
else TARGET_TMPL="${TEST_CMD} {tests}"; fi
TARGET_TIMEOUT="${MUTATE_TARGET_TIMEOUT:-180}"
command -v timeout >/dev/null 2>&1 || TARGET_TIMEOUT=0

target_files() {   # $1 = proving-test glob from the manifest → repo-relative test files, one per line
  gate_test_files "$1"
}
target_cmd() {   # $1 = newline-separated test files → the targeted command, or nothing
  [ -n "$TARGET_TMPL" ] && [ -n "$1" ] || return 0
  local args="" f c
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ "$APP_TRACK" = "android" ] && [ "$TARGET_GIVEN" -eq 0 ]; then
      c="$(basename "$f")"; c="${c%.*}"; args="$args --tests '*${c}'"
    elif [ "$TARGET_GIVEN" -eq 0 ]; then args="$args ${f#backend/}"
    else args="$args $f"; fi
  done <<< "$1"
  [ -n "$args" ] || return 0
  printf '%s' "${TARGET_TMPL//\{tests\}/${args# }}"
}

TMP="$(mktemp -d)"
CUR_FILE=""; CUR_BAK=""
restore_current() { if [ -n "$CUR_FILE" ] && [ -f "$CUR_BAK" ]; then cp "$CUR_BAK" "$CUR_FILE"; CUR_FILE=""; fi; }
cleanup() { restore_current; rm -rf "$TMP"; }
trap cleanup EXIT
SUITE_PID=""
trap '[ -n "$SUITE_PID" ] && kill "$SUITE_PID" 2>/dev/null; restore_current; printf "\ninterrupted — file restored\n" >&2; exit 130' INT TERM
# Python keeps compiled bytecode keyed on a source file's mtime (whole seconds) and size. A same-size
# mutation restored within the same second then keeps running from the cache: after the run, the
# restored file still behaves mutated (2026-10-15, seen on CM-08's "fail" → "pass"), and a mutation
# can be skipped the same way. Every run compiles into its own throwaway cache, so no run reads
# bytecode another wrote and nothing is written into the repository's __pycache__.
RUN_SEQ=0
fresh_pycache() { RUN_SEQ=$((RUN_SEQ + 1)); printf '%s/pycache.%s' "$TMP" "$RUN_SEQ"; }
run_suite() {   # $1 = log → exit status of the suite; runs in the background so a signal can reach the trap
  PYTHONPYCACHEPREFIX="$(fresh_pycache)" bash -c "$TEST_CMD" > "$1" 2>&1 & SUITE_PID=$!
  wait "$SUITE_PID"; local rc=$?; SUITE_PID=""; return $rc
}
run_mutated_suite() {   # $1 = log → the suite's exit status under mutation; 124 when it hit SUITE_TIMEOUT
  # timeout signals the whole process group it starts, so a hung test runner's children stop with it.
  if [ "${SUITE_TIMEOUT:-0}" -gt 0 ] 2>/dev/null; then PYTHONPYCACHEPREFIX="$(fresh_pycache)" timeout -k 10 "$SUITE_TIMEOUT" bash -c "$TEST_CMD" > "$1" 2>&1 & SUITE_PID=$!
  else PYTHONPYCACHEPREFIX="$(fresh_pycache)" bash -c "$TEST_CMD" > "$1" 2>&1 & SUITE_PID=$!; fi
  wait "$SUITE_PID"; local rc=$?; SUITE_PID=""; return $rc
}
run_targeted() {   # $1 = command, $2 = log → its exit status; 124 when it hit MUTATE_TARGET_TIMEOUT
  local pyc; pyc="$(fresh_pycache)"
  if [ "$TARGET_TIMEOUT" -gt 0 ] 2>/dev/null; then PYTHONPYCACHEPREFIX="$pyc" timeout "$TARGET_TIMEOUT" bash -c "$1" > "$2" 2>&1 & SUITE_PID=$!
  else PYTHONPYCACHEPREFIX="$pyc" bash -c "$1" > "$2" 2>&1 & SUITE_PID=$!; fi
  wait "$SUITE_PID"; local rc=$?; SUITE_PID=""; return $rc
}
build_broke() {   # $1 = log → 0 when the run died compiling rather than failing a test
  # pytest: a mutation that does not import is a collection error, not a failing test.
  grep -qE 'Test suite failed to run|error TS[0-9]+|Compilation failed|e: .*\.kt|ERROR collecting|(Syntax|Indentation)Error' "$1" \
    && ! grep -qE '(Tests:.*)?[1-9][0-9]* failed' "$1"
}
TAB=$'\t'; BT=$'\x60'   # a backtick, for the markdown table

# ─────────────────────────────────────────────────────────────────────────────
# locate the definition line of a symbol
# ─────────────────────────────────────────────────────────────────────────────
find_def_line() {   # $1 = file, $2 = symbol → line number or empty
  local f="$1" s="$2" ln
  case "$f" in
    *.py)
      ln=$(grep -nE "^[[:space:]]*(async[[:space:]]+)?def[[:space:]]+${s}[[:space:]]*\(" "$f" | head -1 | cut -d: -f1) ;;
    *.kt|*.kts)
      ln=$(grep -nE "(^|[^A-Za-z0-9_])fun([[:space:]]*<[^>]*>)?[[:space:]]+([A-Za-z_][A-Za-z0-9_]*\.)?${s}[[:space:]]*\(" "$f" | head -1 | cut -d: -f1)
      [ -n "$ln" ] || ln=$(grep -nE "(^|[^A-Za-z0-9_])(val|var)[[:space:]]+${s}[[:space:]]*(:[^=]*)?=" "$f" | head -1 | cut -d: -f1) ;;
    *)
      ln=$(grep -nE "(^|[^A-Za-z0-9_\$])function[[:space:]]*\*?[[:space:]]+${s}[[:space:]]*[(<]" "$f" | head -1 | cut -d: -f1)
      [ -n "$ln" ] || ln=$(grep -nE "(^|[^A-Za-z0-9_\$])(const|let|var)[[:space:]]+${s}[[:space:]]*(:[^=]*)?=([^=]|$)" "$f" | head -1 | cut -d: -f1)
      [ -n "$ln" ] || ln=$(grep -nE "^[[:space:]]*${s}[[:space:]]*:[[:space:]]*(async[[:space:]]*)?(function[[:space:]]*\(|\(|[A-Za-z_\$][A-Za-z0-9_\$]*[[:space:]]*=>)" "$f" | head -1 | cut -d: -f1)
      [ -n "$ln" ] || ln=$(grep -nE "^[[:space:]]*((public|private|protected|static|async|override|readonly)[[:space:]]+)*${s}[[:space:]]*(<[^>]*>)?[[:space:]]*\([^;]*$" "$f" | grep -vE '^[0-9]+:[[:space:]]*(if|for|while|switch|return|await|new)\b' | head -1 | cut -d: -f1) ;;
  esac
  printf '%s' "$ln"
}

# ─────────────────────────────────────────────────────────────────────────────
# analyse from the definition line: where is the innermost body's `{`, what are its params?
# prints:  ok<TAB>line<TAB>col<TAB>params<TAB>mode<TAB>rettype   or   manual<TAB>reason
# ─────────────────────────────────────────────────────────────────────────────
analyse() {   # $1 = file, $2 = def line, $3 = symbol, $4 = lang (ts|kt)
  awk -v start="$2" -v sym="$3" -v lang="$4" '
    NR < start { next }
    NR > start + 150 { exit }
    { buf = buf $0 "\n" }
    function ch(i) { return substr(buf, i, 1) }
    function is_id(c) { return c ~ /[A-Za-z0-9_$]/ }
    function skip_ws(i) { while (i <= L && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function prev_nonws(i) { i--; while (i >= 1 && ch(i) ~ /[ \t\r\n]/) i--; return i }
    # index of the bracket matching the one at i (handles nesting and string literals)
    function match_br(i,   op, cl, d, c, q) {
      op = ch(i); cl = (op == "(" ? ")" : op == "{" ? "}" : op == "[" ? "]" : ">"); d = 0; q = ""
      for (; i <= L; i++) { c = ch(i)
        if (q != "") { if (c == q && ch(i-1) != "\\") q = ""; continue }
        if (c == "\"" || c == "\x27" || c == "`") { q = c; continue }
        if (c == op) d++; else if (c == cl) { d--; if (d == 0) return i } }
      return 0 }
    function line_of(i,   n, k) { n = 0; for (k = 1; k < i; k++) if (ch(k) == "\n") n++; return start + n }
    function col_of(i,   k) { for (k = i - 1; k >= 1; k--) if (ch(k) == "\n") break; return i - k }
    function fail(r) { printf "manual\t%s\n", r; exit }
    function done(i, params, mode, ret) { printf "ok\t%d\t%d\t%s\t%s\t%s\n", line_of(i), col_of(i), params, mode, ret; exit }
    # from just after a parameter list: find the body brace, skipping a `: Type` annotation whose
    # type may itself contain object-literal braces (`: { ok: boolean }`). Sets RET.
    function body_after_params(i,   j, p, c) {
      RET = ""; j = skip_ws(i)
      if (ch(j) != ":" ) { if (ch(j) == "{") return j; if (ch(j) == "=" && ch(j+1) != ">") return -1; return 0 }
      for (j = j + 1; j <= L; j++) { c = ch(j)
        if (c == "{") { p = ch(prev_nonws(j)); if (p ~ /[:|&,<(=]/) { j = match_br(j); if (j == 0) return 0; continue } RET = substr(buf, i, j - i); sub(/^[ \t\n]*:[ \t\n]*/, "", RET); sub(/[ \t\n]+$/, "", RET); return j }
        if (c == "<" || c == "(" || c == "[") { j = match_br(j); if (j == 0) return 0; continue }
        if (c == "=" && ch(j+1) != ">") return -1
        if (c == ";" || c == "\n" && lang == "kt" && substr(buf, j) !~ /^\n[ \t]*[{:]/) return 0 }
      return 0 }
    # function/method form starting at the `(` of the parameter list
    function from_params(i, mode,   cl, body) {
      cl = match_br(i); if (cl == 0) fail("unbalanced parameter list")
      body = body_after_params(cl + 1)
      if (body == -1) fail("expression-bodied " (lang == "kt" ? "fun" : "function") " — give it a block body")
      if (body == 0) fail("no body brace found after parameter list")
      descend(body, substr(buf, i + 1, cl - i - 1), mode, RET) }
    # arrow form: scan forward for `=>` followed by `{`; params are the group just before it
    function from_arrow(i,   j, n, p, q, depth, c, params, start_i) {
      start_i = i; depth = 0; q = ""
      for (j = i; j <= L; j++) { c = ch(j)
        if (q != "") { if (c == q && ch(j-1) != "\\") q = ""; continue }
        if (c == "\"" || c == "\x27" || c == "`") { q = c; continue }
        if (c == "(" || c == "[" || c == "{") depth++
        if (c == ")" || c == "]" || c == "}") { depth--; if (depth < 0) fail("expression-bodied arrow — give it a block body") }
        if (c == ";" && depth == 0) fail("expression-bodied arrow — give it a block body")
        if (c == "\n" && depth == 0 && j > start_i && ch(j+1) ~ /[^ \t\n]/) fail("expression-bodied arrow — give it a block body")
        if (c == "=" && ch(j+1) == ">") {
          n = skip_ws(j + 2)
          if (ch(n) == "{") {
            p = over_type(prev_nonws(j))
            if (ch(p) == ")") { q2 = p; d = 0; for (; q2 >= 1; q2--) { if (ch(q2) == ")") d++; if (ch(q2) == "(") { d--; if (d == 0) break } } params = substr(buf, q2 + 1, p - q2 - 1) }
            else { q2 = p; while (q2 >= 1 && is_id(ch(q2))) q2--; params = substr(buf, q2 + 1, p - q2) }
            descend(n, params, "arrow", "") }
          j = n - 1 } }
      fail("no arrow body found") }
    # `(req): boolean =>` — walk back over a return-type annotation to the `)` of the params
    function over_type(p,   q, c, d) {
      q = p
      while (q >= 1) { c = ch(q)
        if (c == ")" || c == ">" || c == "]" || c == "}") { d = 0; op2 = (c == ")" ? "(" : c == ">" ? "<" : c == "]" ? "[" : "{")
          for (; q >= 1; q--) { if (ch(q) == c) d++; else if (ch(q) == op2) { d--; if (d == 0) break } }
          if (q < 1) return p; q--; continue }
        if (is_id(c) || c ~ /[ \t\n.|&,?]/) { q--; continue }
        if (c == ":") { q = prev_nonws(q); return (ch(q) == ")") ? q : p }
        return p }
      return p }
    # body found: if it is a factory (`return (req,res,next) => {` / `return function (…) {`), go inside
    function descend(body, params, mode, ret,   k, rest) {
      k = skip_ws(body + 1); rest = substr(buf, k, 60)
      if (rest ~ /^return[ \t\n]+(async[ \t\n]+)?function[ \t\n]*\*?[ \t\n]*[A-Za-z0-9_$]*[ \t\n]*\(/) { k += index(rest, "("); from_params(k - 1, "function") }
      if (rest ~ /^return[ \t\n]+(async[ \t\n]*)?(\(|[A-Za-z_$][A-Za-z0-9_$]*[ \t\n]*=>)/) from_arrow(k + 6)
      done(body, params, mode, ret) }
    END {
      L = length(buf); if (L == 0) fail("definition line out of range")
      # position of the symbol on the first line
      first = substr(buf, 1, index(buf, "\n"))
      pos = 0; p = 1
      while ((i = index(substr(first, p), sym)) > 0) { a = p + i - 1; b = a + length(sym)
        if (!is_id(substr(first, a - 1, 1)) && !is_id(substr(first, b, 1))) { pos = a; break } ; p = b }
      if (pos == 0) fail("symbol not on definition line")
      after = skip_ws(pos + length(sym))
      if (lang == "kt") {
        if (ch(after) == "<") after = skip_ws(match_br(after) + 1)
        if (ch(after) == "(") from_params(after, "kotlin")
        fail("kotlin val/var — only fun bodies are mutated") }
      if (ch(after) == "<") after = skip_ws(match_br(after) + 1)
      if (ch(after) == "(") from_params(after, (first ~ /function/) ? "function" : "method")
      # const x = …  /  const x: T = …  /  prop: … => …
      if (ch(after) == ":" && first !~ /(const|let|var)[ \t]/) { rhs = skip_ws(after + 1) }
      else {
        eq = 0; for (j = after; j <= L; j++) { c = ch(j); if (c == "=" && ch(j+1) != ">" && ch(j+1) != "=") { eq = j; break } if (c == "\n" && ch(j+1) ~ /[^ \t]/ && j > after) break }
        if (eq == 0) fail("no initializer found"); rhs = skip_ws(eq + 1) }
      if (substr(buf, rhs, 5) == "async") rhs = skip_ws(rhs + 5)
      if (substr(buf, rhs, 8) == "function") { k = index(substr(buf, rhs), "("); from_params(rhs + k - 1, "function") }
      from_arrow(rhs)
    }' "$1"
}

# Python: from the `def` line, past the signature (parentheses balanced, line ends in `:`), to the
# body's first non-blank, non-comment line. Same record shape as analyse: col 0 (insert above),
# mode "function", rettype from `-> T`. A one-line `def f(): return x` has no body line → manual.
analyse_py() {   # $1 = file, $2 = def line
  awk -v start="$2" '
    NR < start { next }
    !sig_done {
      line = $0; sub(/[[:space:]]*#.*$/, "", line); sig = sig line "\n"
      d += gsub(/\(/, "(", line) - gsub(/\)/, ")", line)
      if (d == 0 && line ~ /:[[:space:]]*$/) { sig_done = 1; next }
      if (d == 0 && line ~ /:[[:space:]]*[^[:space:]]/ && line ~ /\)[^)]*:/) { print "manual\tone-line def — give it a block body"; exit }
      if (NR > start + 40) { print "manual\tno end of signature found"; exit }
      next }
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    { i = index(sig, "("); body = substr(sig, i + 1)
      ret = ""; if (match(body, /->[^:]*:[[:space:]\n]*$/)) { ret = substr(body, RSTART + 2, RLENGTH - 2); sub(/:[[:space:]\n]*$/, "", ret); gsub(/^[[:space:]]+|[[:space:]]+$/, "", ret) }
      sub(/\)[^)]*$/, "", body); gsub(/\n/, " ", body)
      printf "ok\t%d\t0\t%s\tfunction\t%s\n", NR, body, ret; exit }
    END { if (!sig_done) print "manual\tno end of signature found" }' "$1"
}

# ─────────────────────────────────────────────────────────────────────────────
# parameter helpers (bash 3.2 — no arrays of arrays, keep it flat)
# ─────────────────────────────────────────────────────────────────────────────
param_names() {   # $1 = raw param text → names, one per line (destructured → "{" / "[")
  printf '%s' "$1" | awk '
    { s = $0; d = 0; cur = ""; q = ""
      for (i = 1; i <= length(s); i++) { c = substr(s, i, 1)
        if (q != "") { cur = cur c; if (c == q) q = ""; continue }
        if (c == "\"" || c == "\x27" || c == "`") { q = c; cur = cur c; continue }
        if (c ~ /[(<\[{]/) d++; if (c ~ /[)>\]}]/) d--
        if (c == "," && d == 0) { emit(cur); cur = "" } else cur = cur c }
      emit(cur) }
    function emit(p) { gsub(/^[ \t\n]+|[ \t\n]+$/, "", p); if (p == "") return
      sub(/^(public|private|protected|readonly)[ \t]+/, "", p); sub(/^\.\.\./, "", p)
      if (p ~ /^[{\[]/) { print substr(p, 1, 1); return }
      sub(/[?:=].*$/, "", p); gsub(/[ \t]/, "", p); print p }'
}

infer_kind() {   # $1 = symbol, $2 = last param, $3 = rettype → kind
  local s="$1" last="$2" ret="$3" ls
  ls=$(printf '%s' "$s" | tr '[:upper:]' '[:lower:]')
  case "$last" in next|_next) echo middleware; return ;; esac
  case "$ret" in boolean|Boolean|*"<boolean>"*|*"<Boolean>"*) echo decision; return ;; esac
  case "$s" in can[A-Z]*|is[A-Z]*|has[A-Z]*|allow*|permit*|authoriz*|authoris*|check*) echo decision; return ;; esac
  case "$s" in *Can[A-Z]*|*Is[A-Z]*|*Has[A-Z]*|*Allow*|*Permit*|*Authoriz*|*Authoris*|*Check*) echo decision; return ;; esac
  case "$ls" in *scope*|*tenant*|*owner*|*filter*|*where*) echo scope; return ;; esac
  case "$ls" in *redact*|*sanitiz*|*sanitis*|*mask*|*strip*|*scrub*) echo redact; return ;; esac
  echo noop
}

# ─────────────────────────────────────────────────────────────────────────────
ROWS_TSV="$TMP/rows"; : > "$ROWS_TSV"
PLACEHOLDERS=0
while IFS= read -r line; do
  case "$line" in "| CM-"*) : ;; *) continue ;; esac
  id=$(  printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$2); print $2}')
  name=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$3); print $3}')
  impl=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$4); gsub(/`/,"",$4); print $4}')
  test_g=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$6); gsub(/`/,"",$6); print $6}')
  note=$(printf '%s' "$line" | awk -F'|' '{gsub(/^ +| +$/,"",$7); print $7}')
  case "$impl" in ""|"-"|"—"|"<"*) PLACEHOLDERS=$((PLACEHOLDERS + 1)); continue ;; esac
  [ -n "$ONLY" ] && case "$ONLY" in *",$id,"*) : ;; *) continue ;; esac
  if ! row_changed "${impl%%:*}" "$test_g" "$id" "$line"; then
    UNCHANGED="${UNCHANGED:-} $id"; UNCHANGED_ROWS="${UNCHANGED_ROWS:-}| $id | $name | — | — | ○ unchanged since ${SINCE} — not re-proven here; cite the last full run |
"; continue
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$impl" "$note" "$test_g" >> "$ROWS_TSV"
done < "$MANIFEST"
UNCHANGED="${UNCHANGED:-}"; UNCHANGED_ROWS="${UNCHANGED_ROWS:-}"

if [ ! -s "$ROWS_TSV" ] && [ -n "$SINCE" ] && [ -n "$UNCHANGED" ]; then
  printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
  printf 'MUTATE CONTROLS --since %s                 (track: %s)\n' "$SINCE" "$APP_TRACK"
  printf '%s\n' "$SINCE_NOTE"
  printf 'no control implementation or proving test changed — 0 mutated, %s unchanged:%s\n' "$(printf '%s' "$UNCHANGED" | wc -w | tr -d ' ')" "$UNCHANGED"
  printf 'nothing to re-prove; the last full run stands\n'
  printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
  exit 0
fi

if [ ! -s "$ROWS_TSV" ]; then
  if [ -n "$ONLY" ]; then printf 'no manifest rows match --only %s\n' "${ONLY//,/ }"; exit 1; fi
  printf 'CONTROL MANIFEST: %s placeholder row(s), 0 controls declared — nothing to mutate\n' "$PLACEHOLDERS"; exit 2
fi

printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf 'MUTATE CONTROLS %s                 (track: %s)\n' "$( [ "$DRY" -eq 1 ] && printf '(dry-run)' )" "$APP_TRACK"
printf 'suite: %s%s\n' "$TEST_CMD" "$SUITE_NOTE"
[ -n "$SINCE_NOTE" ] && printf -- '--since %s: %s\n' "$SINCE" "$SINCE_NOTE"
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'

T0=$SECONDS
if [ "$DRY" -eq 0 ] && [ "$BASELINE" -eq 1 ]; then
  printf 'baseline (unmutated) … '
  if run_suite "$TMP/baseline.log"; then printf 'GREEN (%ss)\n' "$((SECONDS - T0))"; BASELINE_SECS=$((SECONDS - T0))
  else printf 'RED\n  the suite is already red before any mutation — fix that first; nothing can be proven against a red suite\n'
       tail -20 "$TMP/baseline.log" | sed 's/^/  │ /'
       if [ "$INFERRED" -eq 1 ]; then
         printf 'INFERRED SUITE NOT GREEN: %s is red before any mutation, so nothing was sabotage-tested — set CONTROL_TEST_CMD in project.config.yaml to the command that runs this repository'"'"'s tests\n' "$TEST_CMD"
         exit 3
       fi
       exit 1; fi
fi

SUITE_TIMEOUT="${MUTATE_SUITE_TIMEOUT:-$([ -n "${BASELINE_SECS:-}" ] && echo $((BASELINE_SECS * 3 + 60)) || echo 0)}"
command -v timeout >/dev/null 2>&1 || SUITE_TIMEOUT=0
TABLE="$TMP/table"; : > "$TABLE"
NOT_PROVEN=""; MANUAL=""; TIMED_OUT=""; N=0; N_TARGETED=0; N_FALLBACK=0
while IFS="$TAB" read -r id name impl note test_g; do
  N=$((N + 1))
  file="${impl%%:*}"; sym="${impl##*:}"
  case "$file" in *.kt|*.kts) lang=kt ;; *.py) lang=py ;; *.js|*.jsx|*.mjs|*.cjs) lang=js ;; *) lang=ts ;; esac
  # `mutate:stmt=<code>` in the note is an explicit mutation statement (to the end of the cell, `;` added
  # if missing) — use it when the generic kinds would crash rather than weaken the control, e.g. a
  # query-builder scope: mutate:stmt=return getDb()('notes')
  kind=""; stmt=""; stmt_bad=""
  case "$note" in
    *mutate:stmt=*) stmt=$(printf '%s' "$note" | sed -E 's/.*mutate:stmt=//; s/[[:space:]]+$//'); case "$stmt" in *';') : ;; *) stmt="${stmt};" ;; esac; kind="stmt"
                    # A markdown cell cannot hold "|"; a statement that lost its tail shows up as unbalanced brackets.
                    o=$(printf '%s' "$stmt" | tr -cd '(' | wc -c); c=$(printf '%s' "$stmt" | tr -cd ')' | wc -c)
                    ob=$(printf '%s' "$stmt" | tr -cd '{' | wc -c); cb=$(printf '%s' "$stmt" | tr -cd '}' | wc -c)
                    if [ "$o" -ne "$c" ] || [ "$ob" -ne "$cb" ]; then stmt_bad="unbalanced brackets in mutate:stmt (a '|' in the cell truncates it — use ?? instead of ||)"; else stmt_bad=""; fi ;;
    *mutate:replace=*) kind="replace"; rep=$(printf '%s' "$note" | sed -E 's/.*mutate:replace=//; s/[[:space:]]+$//')
                    rep_from="${rep%% ~> *}"; rep_to="${rep#* ~> }"
                    if [ "$rep_from" = "$rep" ] || [ -z "$rep_from" ]; then stmt_bad="mutate:replace needs '<exact source> ~> <replacement>'"; fi ;;
    *mutate:*) kind=$(printf '%s' "$note" | sed -E 's/.*mutate:([a-z]+).*/\1/') ;;
  esac

  if [ ! -f "$file" ]; then
    printf '| %s | %s | — | — | ✗ unlocatable: file missing |\n' "$id" "$name" >> "$TABLE"; MANUAL="$MANUAL $id"; continue
  fi
  def=$(find_def_line "$file" "$sym")
  if [ -z "$def" ]; then
    printf '| %s | %s | — | — | ✗ unlocatable: %s not defined in %s |\n' "$id" "$name" "$sym" "$file" >> "$TABLE"; MANUAL="$MANUAL $id"; continue
  fi
  # analyse returns ONE tab-separated record. A multi-line signature (params spread over
  # several lines, as Express middleware usually is) puts literal newlines inside the params
  # field, which breaks the TSV contract: `cut -f2` then yields one value per line and $bline
  # becomes multi-line, crashing sed/awk downstream. Join the record back onto one line.
  if [ "$lang" = "py" ]; then res=$(analyse_py "$file" "$def")
  else res=$(analyse "$file" "$def" "$sym" "${lang/js/ts}" | awk '{ if (NR > 1) printf " "; printf "%s", $0 } END { print "" }'); fi
  status="${res%%"${TAB}"*}"
  if [ "$status" != "ok" ]; then
    printf '| %s | %s | %s:%s | — | ✗ manual: %s |\n' "$id" "$name" "$file" "$def" "${res#*"${TAB}"}" >> "$TABLE"; MANUAL="$MANUAL $id"; continue
  fi
  bline=$(printf '%s' "$res" | cut -f2); bcol=$(printf '%s' "$res" | cut -f3)
  params=$(printf '%s' "$res" | cut -f4); mode=$(printf '%s' "$res" | cut -f5); ret=$(printf '%s' "$res" | cut -f6)
  names=$(param_names "$params"); first=$(printf '%s\n' "$names" | head -1); last=$(printf '%s\n' "$names" | tail -1)
  [ -n "$kind" ] || kind=$(infer_kind "$sym" "$last" "$ret")

  mutation=""; reason=""
  if [ "$lang" = "py" ]; then
    pfirst=$(printf '%s\n' "$names" | grep -vxE 'self|cls' | head -1); pfirst="${pfirst#\*}"; pfirst="${pfirst#\*}"
    case "$kind" in
      stmt)    if [ -n "$stmt_bad" ]; then reason="$stmt_bad"; else mutation="${stmt%;}"; fi ;;
      decision) mutation="return True" ;;
      scope|redact) if [ -n "$pfirst" ]; then mutation="return ${pfirst}"; else reason="no parameter to pass through — name a mutate:stmt"; fi ;;
      noop)    mutation="return None" ;;
      replace) if [ -n "$stmt_bad" ]; then reason="$stmt_bad"; else mutation="${rep_from} ~> ${rep_to}"; fi ;;
      *)       reason="mutate kind '$kind' does not apply to Python (decision|scope|redact|noop|stmt|replace)" ;;
    esac
  elif [ "$lang" = "kt" ]; then
    case "$ret" in
      Boolean|"Boolean?") mutation="return true" ;;
      ""|Unit) mutation="return" ;;
      *) reason="Kotlin return type '$ret' — only Boolean/Unit bodies are mutated automatically" ;;
    esac
  else
    case "$kind" in
      stmt)       if [ -n "$stmt_bad" ]; then reason="$stmt_bad"; else mutation="$stmt"; fi ;;
      middleware) case "$last" in next|_next) mutation="return ${last}();" ;; *) mutation="return next();" ;; esac ;;
      decision)   mutation="return true;" ;;
      scope|redact)
        case "$first" in
          options|opts|_options) mutation="return;" ;;
          ""|"{"|"[") if [ "$mode" = "function" ] || [ "$mode" = "method" ]; then mutation="return arguments[0];"; else reason="first parameter is destructured/absent in an arrow — add mutate:noop or name the parameter"; fi ;;
          *) mutation="return ${first};" ;;
        esac ;;
      noop) mutation="return;" ;;
      escalate)
        upar=""; for n in $names; do case "$n" in user|caller|actor|currentUser) upar="$n"; break ;; esac; done
        if [ -n "$upar" ] && [ "$lang" = "js" ]; then mutation="${upar} = { ...${upar}, role: 'admin' };"
        elif [ -n "$upar" ]; then mutation="${upar} = { ...${upar}, role: 'admin' } as any;"
        else reason="escalate needs a parameter named user/caller/actor/currentUser"; fi ;;
      replace) if [ -n "$stmt_bad" ]; then reason="$stmt_bad"; else mutation="${rep_from} ~> ${rep_to}"; fi ;;
      *) reason="unknown mutate kind '$kind' (middleware|decision|scope|redact|noop|escalate|replace)" ;;
    esac
  fi
  if [ -n "$reason" ]; then
    printf '| %s | %s | %s:%s (%s) | — | ✗ manual: %s |\n' "$id" "$name" "$file" "$bline" "$kind" "$reason" >> "$TABLE"; MANUAL="$MANUAL $id"; continue
  fi

  # ── build the mutated file: split the body line at the brace, insert the mutation ──
  indent=$(sed -n "${bline}p" "$file" | sed -E 's/^([[:space:]]*).*/\1/')"  "
  MUT="$TMP/mut.$N"; BAK="$TMP/bak.$N"; cp "$file" "$BAK"
  if [ "$kind" = "replace" ]; then
    # Forward from the definition first — the guard is usually one comparison in the body — and,
    # failing that, the nearest line above it: a guard that is a module-scope constant the function
    # reads (an eligibility list, a role set) is defined ABOVE the symbol, and the 200-line forward
    # window this used to have made such a control unprovable: `✗ manual`, one such control in the engine's first project
    # (T-ENGINE-17). Neither direction is capped; the manifest names a literal only the guard carries.
    hit=$(REP_FROM="$rep_from" awk -v a="$def" 'NR>=a && index($0, ENVIRON["REP_FROM"]) { print NR; exit }' "$BAK")
    [ -n "$hit" ] || hit=$(REP_FROM="$rep_from" awk -v a="$def" 'NR<a && index($0, ENVIRON["REP_FROM"]) { h=NR } END { if (h) print h }' "$BAK")
    if [ -z "$hit" ]; then
      printf '| %s | %s | %s:%s (replace) | — | ✗ manual: replace text not found anywhere in %s (looked from %s forward, then above it) |\n' "$id" "$name" "$file" "$def" "$file" "$sym" >> "$TABLE"; MANUAL="$MANUAL $id"; continue
    fi
    REP_FROM="$rep_from" REP_TO="$rep_to" awk -v h="$hit" 'NR==h { i=index($0, ENVIRON["REP_FROM"]); $0=substr($0,1,i-1) ENVIRON["REP_TO"] substr($0,i+length(ENVIRON["REP_FROM"])) } { print }' "$BAK" > "$MUT"
    bline=$hit; ins1=""; ins2="$(sed -n "${hit}p" "$MUT")"; loc="${file}:${hit}"
  else
  # TS: an unconditional early return makes the rest of the body unreachable and TypeScript then
  # drops its narrowing on that dead code (spurious "possibly null" errors → a build failure, not a
  # proof). `if (true as boolean)` is always taken at runtime but keeps the body reachable for tsc.
  if [ "$lang" = "py" ]; then
    # Above the body's first line, at its own indent: the def line's indent plus one level is not
    # knowable from the def line alone (tabs, 2 or 4 spaces), the body line's is.
    indent=$(sed -n "${bline}p" "$file" | sed -E 's/^([[:space:]]*).*/\1/')
    ins1=""; ins2="${indent}if True: ${mutation}  # mutate-controls: ${kind}"
    awk -v ln="$bline" -v i2="$ins2" 'NR == ln { print i2 } { print }' "$BAK" > "$MUT"
    loc="${file}:${bline}"
  elif [ "$lang" = "kt" ]; then ins1=""; ins2="${indent}if (true) ${mutation} // mutate-controls: ${kind}"
  elif [ "$lang" = "js" ]; then ins1=""; ins2="${indent}if (true) ${mutation}"
  else ins1="${indent}// @ts-ignore -- mutate-controls: ${kind}"; ins2="${indent}if (true as boolean) ${mutation}"; fi
  [ "$lang" = "py" ] || awk -v ln="$bline" -v col="$bcol" -v i1="$ins1" -v i2="$ins2" '
    NR != ln { print; next }
    { head = substr($0, 1, col); tail = substr($0, col + 1)
      print head; if (i1 != "") print i1; print i2
      if (tail ~ /[^ \t\r]/) print tail }' "$BAK" > "$MUT"
  if [ "$lang" = "py" ]; then :; elif [ -n "$ins1" ]; then loc="${file}:$((bline + 2))"; else loc="${file}:$((bline + 1))"; fi
  fi

  if [ "$DRY" -eq 1 ]; then
    printf '\n%s  %s  →  %s   [%s, %s]\n' "$id" "$name" "$impl" "$kind" "$mode"
    from=$((bline - 2)); [ "$from" -lt 1 ] && from=1
    to=$((bline + 4))
    awk -v a="$from" -v b="$to" -v i1="$ins1" -v i2="$ins2" 'NR >= a && NR <= b { mark = ($0 == i2 || (i1 != "" && $0 == i1)) ? "+" : " "; printf "  %s %4d  %s\n", mark, NR, $0 }' "$MUT"
    printf '| %s | %s | %s → %s%s%s | — | dry-run |\n' "$id" "$name" "$kind" "$BT" "$mutation" "$BT" >> "$TABLE"
    continue
  fi

  CUR_FILE="$file"; CUR_BAK="$BAK"; cp "$MUT" "$file"
  t1=$SECONDS; printf '%s %s … ' "$id" "$sym"
  # Targeted first: the row's own proving test. Red there (and not a build error) settles it.
  tcmd="$(target_cmd "$(target_files "$test_g")")"; decided=""; tag=""
  if [ -n "$tcmd" ]; then
    N_TARGETED=$((N_TARGETED + 1))
    if run_targeted "$tcmd" "$TMP/run.$N.log"; then trc=0; else trc=$?; fi
    if [ "$trc" -eq 124 ] && [ "$TARGET_TIMEOUT" -gt 0 ]; then decided="timeout"
    elif [ "$trc" -ne 0 ] && ! build_broke "$TMP/run.$N.log"; then decided="red"; tag=" (own test)"
    fi
  fi
  # Otherwise the full suite, exactly as before: no proving test named, or the named one stayed green.
  if [ -z "$decided" ]; then
    [ -n "$tcmd" ] && N_FALLBACK=$((N_FALLBACK + 1)) && tag=" (full suite)"
    if run_mutated_suite "$TMP/run.$N.log"; then rc=0; else rc=$?; fi
    if [ "$rc" -eq 124 ] && [ "$SUITE_TIMEOUT" -gt 0 ]; then decided="suite-timeout"; fi
  fi
  restore_current
  el=$((SECONDS - t1))
  if [ "$decided" = "suite-timeout" ]; then
    suite="TIMED OUT"; verdict="✗ NOT PROVEN — the suite ran past ${SUITE_TIMEOUT}s with the control disabled"; TIMED_OUT="$TIMED_OUT $id"; NOT_PROVEN="$NOT_PROVEN $id"
  elif [ "$decided" = "timeout" ]; then
    suite="TIMED OUT"; verdict="✗ NOT PROVEN — own test ran past ${TARGET_TIMEOUT}s"; TIMED_OUT="$TIMED_OUT $id"; NOT_PROVEN="$NOT_PROVEN $id"
  elif [ "$decided" = "red" ]; then
    suite="RED${tag}"; verdict="✓ proven"
  elif [ "$rc" -eq 0 ]; then
    suite="GREEN"; verdict="✗ NOT PROVEN"; NOT_PROVEN="$NOT_PROVEN $id"
  elif build_broke "$TMP/run.$N.log"; then
    suite="RED (build error)"; verdict="✗ NOT PROVEN — mutation broke the build, no test failed"; NOT_PROVEN="$NOT_PROVEN $id"
  else
    suite="RED${tag}"
    if [ -n "$tcmd" ]; then verdict="✓ proven — by another test; the named proving test missed it"; else verdict="✓ proven"; fi
  fi
  printf '%s (%ss)\n' "$suite" "$el"
  printf '| %s | %s | %s → %s%s%s @ %s | %s | %s |\n' "$id" "$name" "$kind" "$BT" "$mutation" "$BT" "$loc" "$suite" "$verdict" >> "$TABLE"
done < "$ROWS_TSV"

printf '\n| id | control | mutation | suite | verdict |\n|---|---|---|---|---|\n'
cat "$TABLE"
[ -n "$UNCHANGED_ROWS" ] && printf '%s' "$UNCHANGED_ROWS"
printf '\n%s control(s) · elapsed %ss' "$N" "$((SECONDS - T0))"
[ -z "$UNCHANGED" ] || printf ' · %s unchanged since %s (not re-proven)' "$(printf '%s' "$UNCHANGED" | wc -w | tr -d ' ')" "$SINCE"
[ "$PLACEHOLDERS" -eq 0 ] || printf ' · %s placeholder row(s) ignored' "$PLACEHOLDERS"
[ "$N_TARGETED" -eq 0 ] || printf ' · %s run against their own test first (%s needed the full suite)' "$N_TARGETED" "$N_FALLBACK"
printf '\n'
rc=0
[ -z "$TIMED_OUT" ] || printf 'TIMED OUT:%s — ran past its cap under mutation (a row'"'"'s own test: %ss, MUTATE_TARGET_TIMEOUT; the full suite: %ss, MUTATE_SUITE_TIMEOUT)\n' "$TIMED_OUT" "$TARGET_TIMEOUT" "$SUITE_TIMEOUT"
if [ -n "$NOT_PROVEN" ]; then printf 'NOT PROVEN:%s — the suite stays green with the control disabled; these tests have no teeth\n' "$NOT_PROVEN"; rc=1; fi
if [ -n "$MANUAL" ]; then printf 'MANUAL / UNLOCATABLE:%s — mutate by hand or fix the manifest row (add mutate:<kind> to the note)\n' "$MANUAL"; rc=1; fi
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
cleanup   # the EXIT trap does this too; calling it here keeps every exit path explicit
exit $rc
