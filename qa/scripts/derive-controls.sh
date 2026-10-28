#!/usr/bin/env bash
# derive-controls.sh — the control list comes from the code, not from whoever wrote the guard.
#
# WHY THIS EXISTS
#   mutate-controls.sh proves every row in CONTROL-MANIFEST.md has a test with teeth. It cannot
#   prove anything about a guard that has no row — and the agent that writes a guard is the same
#   agent that decides whether to give it one. Three of the field-manual-ui findings were exactly
#   that: a guard written, no row, deletable with every test green (T-150, T-157, T-143). This
#   script removes the choice. It finds every guard site in the security code and fails unless the
#   function that holds it is either registered in the manifest or carries a written reason.
#
# WHAT A GUARD SITE IS   (web track; outside comments; a `(` at end of line reads the next line too)
#   AppError(403 …)        a refusal — also res.status(403)
#   AppError(404 …)        a refusal that hides existence — how out-of-scope reads answer here;
#                          also res.status(404)
#   role === '…' / !==     a role branch
#   is_1sg in a condition  the one capability flag that widens or narrows scope (a type field, a
#                          select list or an audit record naming it is not a branch)
#
# WHAT A PYTHON GUARD SITE IS   (2026-10-23, qa module; a line that raises, returns or aborts)
#   HTTPException(status_code=403 / HTTPException(403 / Response(status=403 / abort(403) /
#   Flask's `return body, 403` / PermissionDenied / Forbidden(
#                          a refusal; the same shapes with 401 (and Unauthorized, NotAuthenticated)
#                          are an authentication refusal, with 404 (and NotFound, Http404) a hidden one
#
# WHERE IT LOOKS
#   backend/src/{middleware,services,controllers}/**/*.ts, never db/, test/, __tests__/, __mocks__/.
#   Override with GATE_GUARD_ROOTS="dir1 dir2". A project whose controls are Python names them
#   with CONTROL_SRC_ROOTS and CONTROL_SRC_EXT: py in project.config.yaml; its *.py files are read,
#   never tests/, test_*.py, conftest.py or __pycache__. The android track reports N/A and exits 0
#   until someone writes its Kotlin patterns — said, never silent.
#   --infer-roots: when neither CONTROL_SRC_ROOTS nor GATE_GUARD_ROOTS is set and none of the default
#   roots exists, the roots come from the layout instead (qa/scripts/_lib.sh:gate_infer_control_roots):
#   a Python repository's packages, or src/ server/ lib/ app/ backend/src/ with *.js read beside *.ts.
#   Test files (*.test.*, *.spec.*, test/, tests/, __tests__/), *.d.ts, *.min.js and build output never.
#
# WHAT SATISFIES A SITE  (the site's enclosing top-level function is the unit)
#   1. the manifest names it: an implementation cell `<file>:<symbol>` in CONTROL-MANIFEST.md
#   2. `// not-a-control: <reason>` on the guard line, the line above it, or the line above the
#      function's definition (which exempts the whole function). The reason must be words — at
#      least 12 characters — so "x" or "n/a" does not count as having thought about it.
#
# USAGE   derive-controls.sh [--list] [--quiet] [--draft <file>|-] [--infer-roots [--propose-config <file>]]
#           --list   print every site with its status, then the summary (gate-proof reads this)
#           --quiet  print only failures and the summary
#           --draft  also write a manifest draft, one row per UNREGISTERED function in the
#                    manifest's own table shape, with the test file that names the function (or
#                    `-`), numbered after the manifest's last id; `-` writes it to stdout. The
#                    "drafted manifest" a user confirms row by row (PRD § The control manifest).
#           --infer-roots     read the roots the layout implies when none are configured (above)
#           --propose-config  when roots were inferred, write the project.config.yaml lines that name
#                    them (CONTROL_SRC_ROOTS, CONTROL_SRC_EXT, and CONTROL_TEST_DIR, CONTROL_TEST_CMD
#                    when known) to <file>; nothing is written when nothing was inferred
# EXIT    0 every site satisfied (or N/A) · 1 at least one UNREGISTERED site (each is named)

set -uo pipefail
GATE_LIB="$(cd "$(dirname "$0")" && pwd)/_lib.sh"
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1
# shellcheck source=/dev/null
. "$GATE_LIB"

LIST=0; QUIET=0; DRAFT=""; INFER=0; PROPOSE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --list) LIST=1; shift ;;
    --quiet) QUIET=1; shift ;;
    --draft) DRAFT="${2:-}"; [ -n "$DRAFT" ] || { echo "derive-controls: --draft needs a file (or -)" >&2; exit 1; }; shift 2 ;;
    --infer-roots) INFER=1; shift ;;
    --propose-config) PROPOSE="${2:-}"; [ -n "$PROPOSE" ] || { echo "derive-controls: --propose-config needs a file" >&2; exit 1; }; shift 2 ;;
    -h|--help) sed -n '2,53p' "$0"; exit 0 ;;
    *) echo "derive-controls: unknown option $1" >&2; exit 1 ;;
  esac
done

if [ "$APP_TRACK" = "android" ]; then
  echo "derive-controls: N/A on the android track — no Kotlin guard patterns yet (say so in the gate record)"
  exit 0
fi

MANIFEST="${CONTROL_MANIFEST:-docs/security/CONTROL-MANIFEST.md}"   # the QA gate points this at the list it pinned
gate_use_control_roots   # CONTROL_* keys in project.config.yaml, when the controls are not in the track's roots
LANG_EXT="$(_gate_cfg CONTROL_SRC_EXT)"; INFERRED=0
if [ "$INFER" -eq 1 ] && gate_infer_control_roots; then
  INFERRED=1; LANG_EXT="$GATE_INFERRED_EXT"; ROOTS="$GATE_INFERRED_ROOTS"
  echo "derive-controls: no CONTROL_SRC_ROOTS in project.config.yaml and no $GATE_DEFAULT_GUARD_ROOTS: inferred the control roots $ROOTS (*.${LANG_EXT// /, *.}) from the layout" >&2
  [ -z "$PROPOSE" ] || gate_inferred_config > "$PROPOSE"
elif [ "$LANG_EXT" = "py" ]; then ROOTS="${GATE_GUARD_ROOTS:-$GATE_SRC_ROOTS}"
else ROOTS="${GATE_GUARD_ROOTS:-$GATE_DEFAULT_GUARD_ROOTS}"; fi

# Registered symbols: "file:symbol" per line, from populated implementation cells only.
REG="$(mktemp)"; trap 'rm -f "$REG"' EXIT
if [ -f "$MANIFEST" ]; then
  awk -F'|' '/^\| CM-[0-9]+ /{ id=$2; impl=$4; gsub(/^ +| +$/,"",id); gsub(/[` ]/,"",impl);
             if (impl ~ /^</ || impl=="" || impl=="-") next; print impl "\t" id }' "$MANIFEST" > "$REG"
fi

FILES=""
for r in $ROOTS; do
  [ -d "$r" ] || continue
  if [ "$LANG_EXT" = "py" ]; then
    FILES="$FILES $(find "$r" \( -name tests -o -name test -o -name __pycache__ -o -name node_modules \) -prune -o -type f -name '*.py' ! -name 'test_*.py' ! -name '*_test.py' ! -name 'conftest.py' -print 2>/dev/null | sort)"
  elif [ "$INFERRED" -eq 1 ]; then   # the layout's roots: JavaScript beside TypeScript, and never a test or a build
    FILES="$FILES $(find "$r" \( -name __tests__ -o -name __mocks__ -o -name test -o -name tests -o -name db -o -name node_modules -o -name dist -o -name build -o -name coverage \) -prune -o -type f \( "${GATE_SRC_FIND[@]}" \) ! -name '*.test.*' ! -name '*.spec.*' ! -name '*.d.ts' ! -name '*.min.js' -print 2>/dev/null | sort)"
  else
    FILES="$FILES $(find "$r" \( -name __tests__ -o -name __mocks__ -o -name test -o -name db -o -name node_modules \) -prune -o -type f -name '*.ts' ! -name '*.test.ts' ! -name '*.d.ts' -print 2>/dev/null | sort)"
  fi
done

# Python: the enclosing `def` (any indent, so a method counts under its own name) is the unit; a
# guard is a statement that raises, returns or aborts one of the refusal shapes above. A statement
# black wraps across lines (`raise HTTPException(` with the status on the next line) is read whole,
# up to the line its parentheses balance on, and reported at its first line. The status may be a
# literal, a framework constant (`status.HTTP_403_FORBIDDEN`) or the standard library's `HTTPStatus`.
py_sites() {   # $1 = file → file<TAB>line<TAB>symbol<TAB>kind<TAB>exempt(0|1)
  awk -v F="$1" '
    function reason(s) { return (s ~ /not-a-control:[[:space:]]*[^[:space:]].{10,}/) }
    function code(s) { sub(/#.*$/, "", s); return s }
    function depth(s,   t, o, c) { t=s; o=gsub(/[(]/, "", t); t=s; c=gsub(/[)]/, "", t); return o-c }
    # A status passed by position, HTTPException(403, ...), or the Flask return body, 403[, headers]:
    # the status is the last item of the tuple, or the one before a headers item with no call in it.
    function positional(p, c) {
      return (p ~ ("HTTPException[[:space:]]*[(][[:space:]]*" c "([^0-9]|$)") ||
              p ~ ("^[[:space:]]*return[[:space:]].*,[[:space:]]*" c "[[:space:]]*(,[^()]*)?$")) }
    { line[NR]=$0 }
    END {
      for (i=1; i<=NR; i++) {
        s=line[i]
        if (s ~ /^[[:space:]]*(async[[:space:]]+)?def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
          n=s; sub(/^[[:space:]]*(async[[:space:]]+)?def[[:space:]]+/, "", n); sub(/[^A-Za-z0-9_].*$/, "", n)
          sym=n; fnexempt=(i>1 && reason(line[i-1])) }
        if (s ~ /^[[:space:]]*#/) continue
        probe=code(s)
        if (probe !~ /raise|return|abort[[:space:]]*\(/) continue
        d=depth(probe)
        for (j=i+1; d>0 && j<=NR && j<=i+20; j++) { more=code(line[j]); probe=probe " " more; d+=depth(more) }
        kind=""
        if (probe ~ /(status_code|status)[[:space:]]*=[[:space:]]*403|abort[[:space:]]*\([[:space:]]*403|PermissionDenied|Forbidden[[:space:]]*\(|HTTP_403_|HTTPStatus\.FORBIDDEN/ || positional(probe, 403)) kind="403"
        else if (probe ~ /(status_code|status)[[:space:]]*=[[:space:]]*401|abort[[:space:]]*\([[:space:]]*401|Unauthorized[[:space:]]*\(|NotAuthenticated|HTTP_401_|HTTPStatus\.UNAUTHORIZED/ || positional(probe, 401)) kind="401"
        else if (probe ~ /(status_code|status)[[:space:]]*=[[:space:]]*404|abort[[:space:]]*\([[:space:]]*404|NotFound[[:space:]]*\(|Http404|HTTP_404_|HTTPStatus\.NOT_FOUND/ || positional(probe, 404)) kind="404"
        if (kind=="") continue
        ex = fnexempt || reason(s) || (i>1 && reason(line[i-1]))
        printf "%s\t%d\t%s\t%s\t%d\n", F, i, (sym==""?"<module>":sym), kind, ex
      }
    }' "$1"
}

# One awk pass per file: track the enclosing top-level definition, emit one record per guard site.
#   file<TAB>line<TAB>symbol<TAB>kind<TAB>exempt(0|1)
SITES="$(for f in $FILES; do
  if [ "$LANG_EXT" = "py" ]; then py_sites "$f"; continue; fi
  awk -v F="$f" '
    function defname(s,   m) {
      if (match(s, /^export[[:space:]]+(default[[:space:]]+)?(async[[:space:]]+)?function\*?[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*/)) { m=substr(s,RSTART,RLENGTH); sub(/.*[[:space:]]/,"",m); return m }
      if (match(s, /^(async[[:space:]]+)?function\*?[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*/)) { m=substr(s,RSTART,RLENGTH); sub(/.*[[:space:]]/,"",m); return m }
      if (match(s, /^(export[[:space:]]+)?(const|let)[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*/)) { m=substr(s,RSTART,RLENGTH); sub(/.*[[:space:]]/,"",m); return m }
      return ""
    }
    function reason(s) { return (s ~ /not-a-control:[[:space:]]*[^[:space:]].{10,}/) }
    { line[NR]=$0 }
    /^(export|async|function|const|let)[[:space:]]/ { n=defname($0); if (n!="") { sym=n; symline=NR; fnexempt=(NR>1 && reason(line[NR-1])) } }
    /^[[:space:]]*(\/\/|\*|\/\*)/ { next }
    {
      # T-SLIM-13. A refusal written across two lines — `throw new AppError(` or `res.status(` with
      # the status on the next line, the shape a formatter gives a long message — is one guard site.
      # Pull the next line in so the status is seen; it is an argument line, never a definition.
      site=NR; probe=$0
      if ($0 ~ /(AppError|res\.status)\([[:space:]]*$/) { if ((getline nxt) > 0) { line[NR]=nxt; probe=probe " " nxt } }
      kind=""
      if (probe ~ /(AppError|res\.status)\([[:space:]]*403/) kind="403"
      else if (probe ~ /(AppError|res\.status)\([[:space:]]*404/) kind="404"
      else if ($0 ~ /role[[:space:]]*[!=]==[[:space:]]*["\047]/) kind="role"
      else if ($0 ~ /is_1sg/ && $0 ~ /(if[[:space:]]*\(|&&|\|\||[!=]==|\?[[:space:]])/) kind="is_1sg"
      if (kind=="") next
      ex = fnexempt || reason(probe) || (site>1 && reason(line[site-1]))
      printf "%s\t%d\t%s\t%s\t%d\n", F, site, (sym==""?"<module>":sym), kind, ex
    }' "$f"
done)"

total=0; bad=0; reg=0; exm=0
UNREG="$(mktemp)"; trap 'rm -f "$REG" "$UNREG"' EXIT   # file:symbol<TAB>kind, first site per function
while IFS=$'\t' read -r file ln sym kind ex; do
  [ -n "$file" ] || continue
  total=$((total + 1))
  id="$(awk -F'\t' -v k="$file:$sym" '$1==k{print $2; exit}' "$REG")"
  if [ -n "$id" ]; then status="registered $id"; reg=$((reg + 1))
  elif [ "$ex" = "1" ]; then status="not-a-control"; exm=$((exm + 1))
  else status="UNREGISTERED"; bad=$((bad + 1)); grep -qF "$file:$sym	" "$UNREG" || printf '%s:%s\t%s\n' "$file" "$sym" "$kind" >> "$UNREG"; fi
  if [ "$LIST" -eq 1 ] || { [ "$status" = "UNREGISTERED" ]; }; then
    [ "$QUIET" -eq 1 ] && [ "$status" != "UNREGISTERED" ] && continue
    printf '  %-13s %s:%s  %s  [%s]\n' "$status" "$file" "$ln" "$sym" "$kind"
  fi
done <<< "$SITES"

syms="$(printf '%s\n' "$SITES" | awk -F'\t' 'NF{print $1":"$3}' | sort -u | grep -c . || true)"

# ── --draft also suggests controls by name: code that protects without refusing ─────────────────
# A refusal is found by its shape; a function that hides data, limits abuse, proves identity, fails
# safely or records a security event usually refuses nothing, so its name is the only signal. These
# rows are suggestions for the human who confirms the draft, marked as such, and never block: a
# guard site is still the only thing that fails this script. Same roots and files as the sites.
suggestions() {   # → file<TAB>symbol<TAB>category, one per suggested function
  for f in $FILES; do
    awk -v F="$f" -v PY="$([ "$LANG_EXT" = "py" ] && echo 1 || echo 0)" '
      function reason(s) { return (s ~ /not-a-control:[[:space:]]*[^[:space:]].{10,}/) }
      function category(n, l,   low) {
        low = tolower(n)
        if (low ~ /redact|sanitiz|sanitis|scrub/ || (low ~ /mask/ && low !~ /unmask|bitmask/)) return "hides data"
        if (low ~ /ratelimit|rate_limit|limiter|throttl|lockout|bruteforce/) return "limits abuse"
        if (low ~ /errorhandler|error_handler/ || l ~ /[(][[:space:]]*(err|error)[[:space:]]*(:[^,]*)?,[[:space:]]*req[^,]*,[[:space:]]*res[^,]*,[[:space:]]*next/) return "fails safely"
        if (low ~ /^(verify|authenticate|authorise|authorize)/ || low ~ /^validate_?(token|session|jwt|signature)/) return "proves identity"
        if (n ~ /^(require|ensure|assert|guard|can|scope|permit|deny)([A-Z_]|$)/) return "refuses or scopes access"
        if (low ~ /logger$|logger_|^audit|audit$|_audit/) return "records security events"
        return ""
      }
      function tsname(s,   m) {
        if (match(s, /^export[[:space:]]+(default[[:space:]]+)?(async[[:space:]]+)?function\*?[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*/)) { m=substr(s,RSTART,RLENGTH); sub(/.*[[:space:]]/,"",m); return m }
        if (match(s, /^(async[[:space:]]+)?function\*?[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*/)) { m=substr(s,RSTART,RLENGTH); sub(/.*[[:space:]]/,"",m); return m }
        if (match(s, /^(export[[:space:]]+)?(const|let)[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*/)) { m=substr(s,RSTART,RLENGTH); sub(/.*[[:space:]]/,"",m); return m }
        return ""
      }
      { prev = cur; cur = $0; n = "" }
      PY == 1 && /^[[:space:]]*(async[[:space:]]+)?def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/ { n=$0; sub(/^[[:space:]]*(async[[:space:]]+)?def[[:space:]]+/, "", n); sub(/[^A-Za-z0-9_].*$/, "", n) }
      PY == 0 && /^(export|async|function|const|let)[[:space:]]/ { n = tsname($0) }
      PY == 0 && /^(export[[:space:]]+)?(const|let)[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*(:[^=]*)?=[[:space:]]*([\x27"`[{0-9-]|true|false|null|undefined|new[[:space:]])/ { n = "" }   # a literal value, not a function or a factory call
      n ~ /^[A-Z0-9_]+$/ { n = "" }   # an ALL_CAPS constant (an error code, a limit) is data, not a control
      n != "" && !reason(prev) && !seen[n]++ { c = category(n, $0); if (c != "") printf "%s\t%s\t%s\n", F, n, c }' "$f"
  done
}

# ── --draft: the rows a human confirms, one per unregistered function ──────────────────────────
# The test is a guess: the first file under the test directories that names the function. The
# human deletes the rows that are not controls; the ids continue the manifest's own numbering.
if [ -n "$DRAFT" ]; then
  # Scratch files are this run's own, never a path the environment names.
  DRAFT_TMP="$(mktemp)"; DRAFT_COUNT="$(mktemp)"; trap 'rm -f "$REG" "$UNREG" "$DRAFT_TMP" "$DRAFT_COUNT"' EXIT
  scanned=""; for r in $ROOTS; do [ -d "$r" ] && scanned="$scanned $r"; done
  nfiles=0; for f in $FILES; do nfiles=$((nfiles + 1)); done
  shown="${LANG_EXT:-ts}"; echo "derive-controls: drafting from $nfiles *.${shown// /, *.} file(s) under${scanned:- none of: $ROOTS} — controls kept elsewhere are named with CONTROL_SRC_ROOTS (and CONTROL_SRC_EXT: py) in project.config.yaml" >&2
  next_id=1; bt=$'\x60'
  if [ -f "$MANIFEST" ]; then
    last="$(grep -oE '^\| CM-[0-9]+' "$MANIFEST" | grep -oE '[0-9]+$' | sort -n | tail -1)"
    [ -z "$last" ] || next_id=$((10#$last + 1))
  fi
  {
    printf '<!-- drafted by qa/scripts/derive-controls.sh --draft on %s: one row per guard-shaped function with no\n' "$(date -u +%Y-%m-%d)"
    printf '     CONTROL-MANIFEST row. Delete the rows that are not controls, check each proving test, and move the rest\n'
    printf '     into docs/security/CONTROL-MANIFEST.md. Rows marked "suggested" refuse nothing; their names say they may\n'
    printf '     protect something (hide data, limit abuse, prove identity, fail safely, record events). Keep the real ones. -->\n'
    printf '| id | control | implementation | required artifact | proving test | note |\n|---|---|---|---|---|---|\n'
    while IFS=$'\t' read -r impl kind; do
      [ -n "$impl" ] || continue
      sym="${impl##*:}"; test_cell="-"; note="drafted by derive-controls"
      hit=""
      for d in "${GATE_TEST_DIRS[@]}"; do
        [ -d "$d" ] || continue
        hit="$(grep -rlIF --exclude-dir=__pycache__ --exclude-dir=node_modules -- "$sym" "$d" 2>/dev/null | sort | head -1)"
        if [ -n "$hit" ]; then test_cell="${bt}${hit#"$d"/}${bt}"; break; fi
      done
      [ -n "$hit" ] || note="$note: no test names $sym"
      [ "$LANG_EXT" = "py" ] && note="$note · mutate:noop"
      printf '| CM-%02d | %s — %s refusal | %s%s%s | - | %s | %s |\n' "$next_id" "$sym" "$kind" "$bt" "$impl" "$bt" "$test_cell" "$note"
      next_id=$((next_id + 1))
    done < "$UNREG"
    suggested=0
    while IFS=$'\t' read -r file sym category; do
      [ -n "$file" ] || continue
      grep -qF "$file:$sym	" "$REG" "$UNREG" && continue   # registered, or already drafted as a refusal
      test_cell="-"; note="suggested by name, not a refusal: delete the row if it is not a control"
      for d in "${GATE_TEST_DIRS[@]}"; do
        [ -d "$d" ] || continue
        hit="$(grep -rlIF --exclude-dir=__pycache__ --exclude-dir=node_modules -- "$sym" "$d" 2>/dev/null | sort | head -1)"
        if [ -n "$hit" ]; then test_cell="${bt}${hit#"$d"/}${bt}"; break; fi
      done
      # A function that hides data is broken realistically by handing its input back unredacted; the
      # rest by doing nothing (Python) or by the kind mutate-controls infers from the function (TypeScript).
      if [ "$category" = "hides data" ]; then note="$note · mutate:redact"
      elif [ "$LANG_EXT" = "py" ]; then note="$note · mutate:noop"; fi
      printf '| CM-%02d | %s — suggested: %s, check me | %s%s:%s%s | - | %s | %s |\n' "$next_id" "$sym" "$category" "$bt" "$file" "$sym" "$bt" "$test_cell" "$note"
      next_id=$((next_id + 1)); suggested=$((suggested + 1))
    done <<< "$(suggestions)"
    printf '%s\n' "$suggested" > "$DRAFT_COUNT"
  } > "$DRAFT_TMP"
  if [ "$DRAFT" = "-" ]; then cat "$DRAFT_TMP"; else cp "$DRAFT_TMP" "$DRAFT"; echo "derive-controls: draft written to $DRAFT ($(grep -c '^| CM-' "$DRAFT_TMP" || true) row(s), $(cat "$DRAFT_COUNT") function(s) suggested by name, never blocking)"; fi
  rm -f "$DRAFT_TMP" "$DRAFT_COUNT"
fi
if [ "$bad" -gt 0 ]; then
  echo "── derive-controls: $bad of $total guard site(s) belong to no manifest row and carry no reason"
  echo "   Each UNREGISTERED line is a guard nothing proves. Add a CONTROL-MANIFEST row for its function"
  echo "   (then make mutate-controls ARGS=\"--only CM-nn\" must go red), or write '// not-a-control: <why>'."
  exit 1
fi
echo "derive-controls: $total guard site(s) in $syms function(s) — $reg registered, $exm with a written reason, 0 unregistered"
exit 0
