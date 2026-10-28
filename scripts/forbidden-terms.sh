#!/usr/bin/env bash
# forbidden-terms.sh — refuse any commit, push or PR that carries a term from the denylist.
#
# WHY THIS EXISTS
#   This repository must never name the platform, program or organisation the engine it
#   descends from was built on. One slip and the repository is compromised, so the check is
#   mechanical, runs before every commit (git hook) and on every push and pull request (CI),
#   and exits non-zero on the first hit.
#
# HOW THE LIST STAYS CLEAN
#   The denylist holds SHA-256 digests of lowercase tokens, never the words. Every file is
#   split into tokens on anything that is not a letter or digit, each token is lowercased and
#   hashed, and a match against the digest list is a failure that names the file and line but
#   never prints the token. Adding a term:  scripts/forbidden-terms.sh add <term>
#   (prints the digest; paste it into scripts/forbidden-terms.sha256 — the word is never typed
#   into a tracked file).
#
# USAGE   scripts/forbidden-terms.sh [--staged | --all | <paths…>]
#           --staged   scan the files staged for commit (what the pre-commit hook runs)
#           --all      scan every tracked and untracked file (what CI runs)
#           add <term> print the digest for a new term, nothing else
# EXIT    0 clean · 1 a forbidden term was found · 2 usage or missing list
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LIST="$HERE/forbidden-terms.sha256"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || echo "$HERE/..")"
cd "$ROOT" || exit 2

digest() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sha256sum | cut -d' ' -f1; }

if [ "${1:-}" = "add" ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 add <term>" >&2; exit 2; }
  digest "$2"; exit 0
fi
[ -f "$LIST" ] || { echo "forbidden-terms: no $LIST" >&2; exit 2; }

mode="${1:---all}"
case "$mode" in
  --staged) files=$(git diff --cached --name-only --diff-filter=ACMR) ;;
  --all)    files=$(git ls-files --cached --others --exclude-standard) ;;
  *)        files="$*" ;;
esac
[ -n "$files" ] || exit 0

# The scan itself runs in Python: one process for the whole tree, hashing every token in
# memory. A shell loop forking sha256sum per token takes minutes on a vendored standards index.
LISTFILE=$(mktemp); printf '%s\n' "$files" > "$LISTFILE"; trap 'rm -f "$LISTFILE"' EXIT
python3 -I - "$LIST" "$LISTFILE" <<'PY'
import hashlib, re, subprocess, sys
bad = set()
for line in open(sys.argv[1], encoding='utf-8'):
    line = line.split('#', 1)[0].strip()
    if line: bad.add(line)
files = [f for f in open(sys.argv[2], encoding='utf-8').read().split('\n') if f]
tok = re.compile(r'[A-Za-z0-9]{2,}')
fail = 0; scanned = 0
for f in files:
    if f == 'scripts/forbidden-terms.sha256': continue
    try:
        data = open(f, 'rb').read()
    except (FileNotFoundError, IsADirectoryError):
        continue
    if b'\0' in data[:8192]: continue
    scanned += 1
    for n, text in enumerate(data.decode('utf-8', 'replace').split('\n'), 1):
        for t in tok.findall(text):
            h = hashlib.sha256(t.lower().encode()).hexdigest()
            if h in bad:
                print(f'FORBIDDEN TERM  {f}:{n}  (token hidden; digest {h[:12]}…)')
                fail = 1
                break
if fail:
    print('forbidden-terms: refused. Remove the term; never commit, push or merge with it present.', file=sys.stderr)
    sys.exit(1)
print(f'forbidden-terms: clean ({scanned} files)')
PY
exit $?
