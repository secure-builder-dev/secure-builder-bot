#!/usr/bin/env bash
# secrets-scan.sh — no credentials in tracked files. Runs in `make check` on every push.
#
# Patterns: AWS access keys, private key blocks, GitHub/Slack tokens, hardcoded password/secret
# assignments with a real-looking value. Placeholders (<LIKE_THIS>, example, changeme,
# TestPassword) and *.example files are skipped. Allow a specific line with `secrets-scan: allow`.
# USAGE engine/scripts/gate/secrets-scan.sh     EXIT 0 clean · 1 findings

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1
PAT='AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|(password|passwd|secret|api[_-]?key|client[_-]?secret|token)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9+/=_@#$%^&*!.-]{12,}["'"'"']'
# --staged: scan only what is about to be committed, reading content from the index rather than
# the worktree. Lets the pre-commit hook reuse THIS definition of "a secret" instead of keeping a
# parallel regex that drifts out of sync with CI. Finding F-13.
STAGED=0
[ "${1:-}" = "--staged" ] && STAGED=1
if [ "$STAGED" -eq 1 ]; then
  list_files() { git diff --cached --name-only --diff-filter=ACM; }
  grep_file()  { git grep --cached -nIE "$1" -- "$2" 2>/dev/null; }
else
  list_files() { git ls-files; }
  grep_file()  { git grep -nIE "$1" -- "$2" 2>/dev/null; }
fi

TMP="$(mktemp)"
while IFS= read -r f; do
  case "$f" in *.example|*.png|*.jpg|*.gif|*.pdf|*.ico|*.woff*|*.lock|package-lock.json|engine/scripts/gate/secrets-scan.sh) continue ;; esac
  grep_file "$PAT" "$f" \
  | grep -viE 'secrets-scan: allow|<[A-Z_]+>|example|changeme|placeholder|TestPassword|your[-_ ]|xxx|[$][{]|["'"'"'][$][A-Za-z_]|process[.]env|os[.]environ|getenv' \
  | while IFS= read -r hit; do echo "  $hit" | cut -c1-160; echo x >> "$TMP"; done
done < <(list_files)
if [ -s "$TMP" ]; then echo "secrets-scan: $(wc -l < "$TMP" | tr -d ' ') possible secret(s) — remove them or mark a false positive with 'secrets-scan: allow'"; rm -f "$TMP"; exit 1; fi
rm -f "$TMP"; [ "$STAGED" -eq 1 ] && echo "secrets-scan: clean (staged)" || echo "secrets-scan: clean"
