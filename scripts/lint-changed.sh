#!/usr/bin/env bash
# lint-changed.sh — shellcheck and ruff on the lines this change added. Zero findings allowed.
#
# The whole-repo totals are a ratchet (scripts/ratchet.sh): they may not grow. The lines a change
# ADDS are held to zero, which is the number an agent can actually move. A finding on a line the
# change did not touch is not this change's problem and is not reported here.
#
# USAGE   scripts/lint-changed.sh [--base <ref>] [--all]
#           --base   the ref to diff against; default: the first of origin/main and main that exists
#           --all    every tracked .sh and .py, every line — the ratchet's view, not the gate's
# EXIT    0 clean · 1 findings on added lines · 2 could not run (tool or merge base missing)
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 2
export PATH="$PATH:$HOME/.local/bin"
BASE=""; ALL=0
while [ $# -gt 0 ]; do case "$1" in --base) BASE="$2"; shift 2 ;; --all) ALL=1; shift ;; *) echo "unknown option: $1" >&2; exit 2 ;; esac; done
if [ -z "$BASE" ]; then for b in origin/main main; do git rev-parse --verify -q "$b" >/dev/null 2>&1 && { BASE="$b"; break; }; done; fi
[ -n "$BASE" ] || BASE="origin/main"
for t in shellcheck ruff; do command -v "$t" >/dev/null 2>&1 || { echo "lint-changed: $t is not installed (CONSTRAINTS.md names the install)"; exit 2; }; done

files=(); untracked=()
if [ "$ALL" -eq 1 ]; then
  mapfile -t files < <(git ls-files '*.sh' '*.py')
  ranges=""
else
  mb=$(git merge-base "$BASE" HEAD 2>/dev/null) || { echo "lint-changed: no merge base against $BASE"; exit 2; }
  mapfile -t untracked < <(git ls-files --others --exclude-standard -- '*.sh' '*.py')
  mapfile -t files < <( { git diff --name-only --diff-filter=ACMR "$mb" -- '*.sh' '*.py'; printf '%s\n' "${untracked[@]}"; } | grep -v '^$' | sort -u)
  # added line ranges per file: "file:start:count". The diff takes the same pathspec as the file
  # list, not the new paths alone: with only the destination named, git cannot pair a `git mv` with
  # its source, and a moved file reads as wholly added, so every finding it carried from before the
  # change is charged to the change. Those stay the ratchet's; only the lines the move edited are new.
  ranges=$( { [ "${#files[@]}" -gt 0 ] && git diff --unified=0 -M "$mb" -- '*.sh' '*.py' 2>/dev/null
              for f in "${untracked[@]}"; do [ -n "$f" ] && git diff --no-index --unified=0 /dev/null "$f" 2>/dev/null; done; } \
    | awk '/^\+\+\+ /{f=$2; sub(/^b\//,"",f)} /^@@/{split($3,a,/[+,]/); s=a[2]; c=(a[3]==""?1:a[3]); if (c>0) print f ":" s ":" c}')
fi
[ "${#files[@]}" -gt 0 ] || { echo "lint-changed: no shell or Python files in the change"; exit 0; }

sh_files=(); py_files=()
for f in "${files[@]}"; do case "$f" in *.sh) sh_files+=("$f") ;; *.py) py_files+=("$f") ;; esac; done
out=$(mktemp); trap 'rm -f "$out"' EXIT
[ "${#sh_files[@]}" -gt 0 ] && shellcheck -f gcc "${sh_files[@]}" >> "$out" 2>/dev/null
[ "${#py_files[@]}" -gt 0 ] && ruff check --output-format concise "${py_files[@]}" >> "$out" 2>/dev/null

if [ "$ALL" -eq 1 ]; then
  n=$(grep -cE '^[^ :]+:[0-9]+:' "$out" || true)
  echo "lint-changed --all: $n finding(s) across ${#files[@]} files"
  grep -E '^[^ :]+:[0-9]+:' "$out" | head -40
  exit 0
fi

# Keep only findings whose file:line is inside an added range. Python, not awk: the regex-with-
# capture form is a gawk extension and mawk (Debian's default) rejects it silently as "no hits".
hits=$(RANGES="$ranges" python3 -I - "$out" <<'PY'
import os, re, sys
ok = set()
for r in os.environ.get('RANGES', '').split():
    f, start, count = r.rsplit(':', 2)
    ok.update(f'{f}:{n}' for n in range(int(start), int(start) + int(count)))
for line in open(sys.argv[1], encoding='utf-8', errors='replace'):
    m = re.match(r'^([^ :]+):(\d+):', line)
    if m and f'{m.group(1)}:{m.group(2)}' in ok:
        sys.stdout.write(line)
PY
)
if [ -n "$hits" ]; then
  echo "lint-changed: findings on lines this change added:"; printf '%s\n' "$hits"; exit 1
fi
echo "lint-changed: clean on ${#files[@]} changed file(s)"
