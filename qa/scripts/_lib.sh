#!/usr/bin/env bash
# _lib.sh — shared track resolution for the gate state probes.
#
# The probes must work on both tracks the engine supports. APP_TRACK is read from
# project.config.yaml (the single source of truth per CLAUDE.md); if it is UNSET or the file
# is missing, the track is inferred from what is actually on disk so the probes still run in a
# half-initialised repo rather than erroring out.

_gate_cfg() {   # $1 = key -> value, or empty
  [ -f project.config.yaml ] || return 0
  sed -nE "s/^[[:space:]]*$1:[[:space:]]*\"?([^\"#]*)\"?[[:space:]]*(#.*)?$/\1/p" project.config.yaml \
    | head -1 | sed -E 's/[[:space:]]+$//'
}

APP_TRACK="$(_gate_cfg APP_TRACK)"
if [ -z "$APP_TRACK" ] || [ "$APP_TRACK" = "UNSET" ]; then
  # Infer from where the source actually is, not from which scaffold directory exists —
  # the engine template ships empty android/, backend/ and frontend/ trees.
  _kt=$(find android -name '*.kt' 2>/dev/null | head -5 | wc -l | tr -d ' ')
  _ts=$(find backend frontend -name '*.ts' -o -name '*.tsx' 2>/dev/null | head -5 | wc -l | tr -d ' ')
  if [ "${_kt:-0}" -gt "${_ts:-0}" ]; then APP_TRACK="android"; else APP_TRACK="web"; fi
fi

case "$APP_TRACK" in
  android)
    GATE_SRC_ROOTS="android"
    GATE_SRC_FIND=( -name '*.kt' -o -name '*.java' )
    GATE_CONTROL_ROOT="android"
    GATE_TEST_GLOB="android/app/src/test"
    GATE_TEST_EXT="*.kt"
    GATE_TEST_GLOBS="android/app/src/test:*.kt android/app/src/androidTest:*.kt"
    ;;
  *)
    GATE_SRC_ROOTS="backend frontend"
    GATE_SRC_FIND=( -name '*.ts' -o -name '*.tsx' )
    GATE_CONTROL_ROOT="backend"
    GATE_TEST_GLOB="backend/src/__tests__"
    GATE_TEST_EXT="*.test.ts"
    GATE_TEST_GLOBS="backend/src:*.test.ts frontend/src:*.test.ts frontend/src:*.test.tsx"
    ;;
esac
# Read by the scripts that source this file (repo-state, legacy-inventory), not by the lib itself.
export GATE_CONTROL_ROOT GATE_TEST_EXT GATE_TEST_GLOBS
# Every directory a proving test may live in (2026-10-23, qa module): one per package when a
# repository holds several. GATE_TEST_GLOB stays the first, for the callers that want one directory.
GATE_TEST_DIRS=("$GATE_TEST_GLOB")

# From the engine's first project (2026-10-03, T-ENGINE-06 / GOV-029). GATE_TEST_GLOB is ONE directory
# and one extension, and `make gate-state` counted its suite files from that alone — so on the web
# track the number described `backend/src/__tests__` and nothing else. Measured across several
# gates: it reported 33 against the ~101 the suites actually run, and `gate-permanent-checks.md`
# Table A carries PC-04 and PC-05 as ACTIVE on the strength of that number. A range that adds or
# deletes a frontend test file moved the real count and not the reported one, so neither row could
# detect a frontend suite being removed. Carried as a finding at four consecutive gates (T-054).
#
# GATE_TEST_GLOBS is a list of `dir:ext` pairs covering every suite the project actually runs.
# GATE_TEST_GLOB stays exactly as it was: `repo-state.sh` also uses its BASENAME to exclude test
# directories from the orphan-export index, which is a different question from how many suite
# files there are, and widening that exclusion would hide real orphans.

# Control roots (2026-10-15, gate finding F-03). The track's roots say where an app's controls live
# (backend/ on web). A repository whose controls live elsewhere, in another language, names them in
# project.config.yaml; this one's are Python under core/. Every key is optional:
#   CONTROL_SRC_ROOTS   directories holding control implementations (space-separated)
#   CONTROL_SRC_EXT     their file extensions, without the dot, space-separated (py, or py ts when
#                       the controls are in more than one language, as this repository's are)
#   CONTROL_TEST_DIR    where proving tests live; the manifest's test globs are relative to it.
#                       Several directories, space-separated, when each package keeps its own
#   CONTROL_TEST_CMD    the suite command mutate-controls runs (from the repo root)
#   CONTROL_TARGET_CMD  one row's own tests; {tests} becomes repo-relative test paths
#   CONTROL_HARNESS_RE  paths whose change re-proves every row under --since
# Only verify-controls and mutate-controls call this; every other probe keeps the track's roots,
# so a project that sets nothing sees no change.
gate_use_control_roots() {
  local roots ext tdir
  roots="$(_gate_cfg CONTROL_SRC_ROOTS)"; [ -n "$roots" ] || return 0
  ext="$(_gate_cfg CONTROL_SRC_EXT)"; tdir="$(_gate_cfg CONTROL_TEST_DIR)"
  GATE_SRC_ROOTS="$roots"
  if [ -n "$ext" ]; then
    GATE_SRC_FIND=()
    local e
    for e in $ext; do
      [ "${#GATE_SRC_FIND[@]}" -eq 0 ] || GATE_SRC_FIND+=( -o )
      GATE_SRC_FIND+=( -name "*.${e}" )
    done
  fi
  if [ -n "$tdir" ]; then read -r -a GATE_TEST_DIRS <<< "$tdir"; GATE_TEST_GLOB="${GATE_TEST_DIRS[0]}"; fi
}

# Control roots inferred from the layout (2026-10-28). A repository that names no roots, and has none
# of derive-controls' default ones, had nothing read: a Python service or a plain-JS Express app with
# no project.config.yaml drafted an empty list. Only a caller that asks (`--infer-roots`, which the
# QA gate passes in its drafted mode alone) gets this, and only when CONTROL_SRC_ROOTS and
# GATE_GUARD_ROOTS are unset and backend/src/{middleware,services,controllers} are all absent, so a
# repository that sets the config, or uses the default layout, sees no change.
#   Python  pyproject.toml, setup.py or requirements.txt, and no package.json: every top-level
#           directory holding __init__.py, plus src/ app/ server/ lib/; never tests, docs, a
#           virtualenv, build output, a hidden directory or a link. Tests in tests/ or test/,
#           run with `python3 -m pytest -q -x`.
#   else    TypeScript and JavaScript (*.ts *.tsx *.js *.jsx) under src/ server/ lib/ app/ backend/src/;
#           tests in test/ tests/ __tests__/; `npm test --silent` when package.json names a test
#           script (backend/package.json for backend/src alone).
# Sets GATE_INFERRED_ROOTS / _EXT / _TEST_DIR / _TEST_CMD (each may be empty but the roots), applies
# them to GATE_SRC_ROOTS, GATE_SRC_FIND and GATE_TEST_DIRS, and returns 0; returns 1 and changes
# nothing when inference does not apply or finds no root. A name that is not a plain directory name
# is never a root, so nothing inferred can carry a space, a colon or a newline into a config line.
GATE_DEFAULT_GUARD_ROOTS="backend/src/middleware backend/src/services backend/src/controllers"
_gate_plain_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [[ "$1" =~ ^[A-Za-z0-9_][A-Za-z0-9_./-]*$ ]]; }
_gate_npm_test() { [ -f "$1" ] && grep -qE '"test"[[:space:]]*:' "$1"; }
gate_infer_control_roots() {
  GATE_INFERRED_ROOTS=""; GATE_INFERRED_EXT=""; GATE_INFERRED_TEST_DIR=""; GATE_INFERRED_TEST_CMD=""
  [ "$APP_TRACK" != "android" ] || return 1
  if [ -n "$(_gate_cfg CONTROL_SRC_ROOTS)" ] || [ -n "${GATE_GUARD_ROOTS:-}" ]; then return 1; fi
  local d roots="" tests=""
  for d in $GATE_DEFAULT_GUARD_ROOTS; do [ ! -e "$d" ] || return 1; done
  if [ ! -e package.json ] && { [ -f pyproject.toml ] || [ -f setup.py ] || [ -f requirements.txt ]; }; then
    for d in *; do
      if ! _gate_plain_dir "$d" || ! [[ "$d" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then continue; fi   # an importable name: no hidden dir (.venv)
      case "$d" in tests|test|docs|doc|venv|env|virtualenv|site-packages|node_modules|build|dist|__pycache__) continue ;; esac
      [ ! -f "$d/pyvenv.cfg" ] || continue
      if [ -f "$d/__init__.py" ]; then roots="$roots $d"; continue; fi
      case "$d" in src|app|server|lib) roots="$roots $d" ;; esac
    done
    for d in tests test; do ! _gate_plain_dir "$d" || tests="$tests $d"; done
    GATE_INFERRED_EXT="py"; GATE_INFERRED_TEST_CMD="python3 -m pytest -q -x"
  else
    for d in src server lib app backend/src; do ! _gate_plain_dir "$d" || roots="$roots $d"; done
    for d in test tests __tests__; do ! _gate_plain_dir "$d" || tests="$tests $d"; done
    GATE_INFERRED_EXT="ts tsx js jsx"
    if _gate_npm_test package.json; then GATE_INFERRED_TEST_CMD="npm test --silent"
    elif [ "${roots# }" = "backend/src" ] && _gate_npm_test backend/package.json; then GATE_INFERRED_TEST_CMD="cd backend && npm test --silent"; fi
  fi
  GATE_INFERRED_ROOTS="${roots# }"; GATE_INFERRED_TEST_DIR="${tests# }"
  if [ -z "$GATE_INFERRED_ROOTS" ]; then GATE_INFERRED_EXT=""; GATE_INFERRED_TEST_CMD=""; return 1; fi
  GATE_SRC_ROOTS="$GATE_INFERRED_ROOTS"; GATE_SRC_FIND=()
  for d in $GATE_INFERRED_EXT; do
    [ "${#GATE_SRC_FIND[@]}" -eq 0 ] || GATE_SRC_FIND+=( -o )
    GATE_SRC_FIND+=( -name "*.${d}" )
  done
  if [ -n "$GATE_INFERRED_TEST_DIR" ]; then read -r -a GATE_TEST_DIRS <<< "$GATE_INFERRED_TEST_DIR"; GATE_TEST_GLOB="${GATE_TEST_DIRS[0]}"; fi
  return 0
}

# The project.config.yaml lines that make an inference permanent, one per inferred key.
gate_inferred_config() {
  printf 'CONTROL_SRC_ROOTS: %s\nCONTROL_SRC_EXT: %s\n' "$GATE_INFERRED_ROOTS" "$GATE_INFERRED_EXT"
  [ -z "$GATE_INFERRED_TEST_DIR" ] || printf 'CONTROL_TEST_DIR: %s\n' "$GATE_INFERRED_TEST_DIR"
  [ -z "$GATE_INFERRED_TEST_CMD" ] || printf 'CONTROL_TEST_CMD: %s\n' "$GATE_INFERRED_TEST_CMD"
}

# The files a manifest row's proving-test glob names, across every test directory: repo-relative,
# one per line, sorted. Nothing for an empty glob or a `-`.
gate_test_files() {   # $1 = glob from the manifest
  local d
  case "$1" in ""|"-"|"—") return 0 ;; esac
  for d in "${GATE_TEST_DIRS[@]}"; do
    [ -d "$d" ] || continue
    find "$d" -type f -path "${d}/$1" 2>/dev/null
  done | sort -u
}

# Directories never scanned — build output, vendored deps, coverage.
GATE_PRUNE=( -name node_modules -o -name dist -o -name build -o -name coverage -o -name .gradle )

# find wrapper that prunes rather than filtering after the fact (much faster on big trees)
gate_find_src() {   # $1 = root
  [ -d "$1" ] || return 0
  find "$1" \( "${GATE_PRUNE[@]}" \) -prune -o -type f \( "${GATE_SRC_FIND[@]}" \) -print 2>/dev/null
}

# Build a "token<TAB>file" index of every reference to a symbol in non-test source.
# One pass, two shapes per line:
#   call        — `sym(`                          e.g. verifyToken(req)
#   by-reference — `(sym` `,sym` `:sym` `[sym`    e.g. app.use(requireAuth)
#                                                     router.get('/x', requireAuth, h)
#                                                     hooks: { beforeFind: scopeTenant }
# The second shape is how Express middleware, ORM hooks and handler arrays are wired; an index of
# calls alone reports every such control as dead. Comment lines and import/export lines are
# dropped BEFORE matching — a symbol named only in a doc comment or an import is NOT a call site,
# which is the specific false positive that lets a dead control look wired.
gate_build_use_index() {   # $1 = output file  →  lines of: token<TAB>file<TAB>line
  # One awk pass over every source file. The previous shape forked grep/sed/awk per LINE — three
  # subprocesses × ~40k lines — and took 90 s on a 500-file backend, which made verify-controls
  # and gate-state the slowest steps of every gate (QG3-N1: 192 s against a 5 s target). Same
  # output, same filters: comment / import / re-export lines are dropped before matching, and
  # each line is scanned twice (call shape, then by-reference shape) exactly as before.
  : > "$1"
  local prog
  prog=$(cat <<'AWK'
    # Python (2026-10-15): `#` comments, `from m import a, b` (one line or parenthesised over
    # several) and docstring blocks are not call sites either. None of these shapes occurs in TS.
    # A docstring ends only at the quote kind that opened it, so a """ block may quote \047\047\047
    # (run #2, N-06): the first triple quote on a line decides, and the block is open until it recurs.
    FNR == 1 { indoc = ""; inimp = 0 }
    indoc != "" { if (index($0, indoc)) indoc = ""; next }
    {
      dq = index($0, "\"\"\""); sq = index($0, "\047\047\047"); q = ""
      if (dq && (!sq || dq < sq)) q = "\"\"\""; else if (sq) q = "\047\047\047"
      if (q != "") {
        starts = ($0 ~ /^[[:space:]]*[rbuRBU]?("""|\047\047\047)/)
        if (index(substr($0, index($0, q) + 3), q) == 0) indoc = q
        if (starts) next
      }
    }
    inimp { if ($0 ~ /\)/) inimp = 0; next }
    /^[[:space:]]*from[[:space:]]+[A-Za-z0-9_.]+[[:space:]]+import[[:space:]]*\(/ { if ($0 !~ /\)/) inimp = 1; next }
    /^[[:space:]]*from[[:space:]]+[A-Za-z0-9_.]+[[:space:]]+import[[:space:]]/ { next }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*(\/\/|\*|\/\*)/ { next }
    /^[[:space:]]*import[[:space:]]/ { next }
    /^[[:space:]]*export[[:space:]]+(type[[:space:]]+)?\{[^}]*\}[[:space:]]+from/ { next }
    {
      s = $0
      while (match(s, /[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(/)) {
        t = substr(s, RSTART, RLENGTH); sub(/[[:space:]]*\($/, "", t)
        print t "\t" FILENAME "\t" FNR; s = substr(s, RSTART + RLENGTH)
      }
      s = $0
      while (match(s, /[(,:[][[:space:]]*[A-Za-z_][A-Za-z0-9_]*/)) {
        t = substr(s, RSTART, RLENGTH); sub(/^[(,:[][[:space:]]*/, "", t)
        print t "\t" FILENAME "\t" FNR; s = substr(s, RSTART + RLENGTH)
      }
    }
AWK
)
  for root in $GATE_SRC_ROOTS; do
    [ -d "$root" ] || continue
    gate_find_src "$root" | grep -v "/${GATE_TEST_GLOB##*/}/"
  done | tr '\n' '\0' | xargs -0 -r awk "$prog" | sort -u > "$1"
}
