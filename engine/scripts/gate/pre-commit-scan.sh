#!/usr/bin/env bash
# pre-commit-scan.sh — block credentials at commit time; let infrastructure knobs through.
#
# WHY THIS EXISTS
#   CI catches a secret AFTER it is in git history, and history is the part you cannot fix by
#   deleting the line — the only real remediation is rotating the credential. A commit-time check
#   is the difference between "never happened" and "rotate everything."
#
#   The engine shipped such a hook until 2026-09-16, when it was removed because it blocked
#   legitimate DevOps work: it treated S3 bucket names, AWS account IDs, security group IDs, ARNs
#   and RDS endpoints the same as passwords. Those are identifiers, not credentials — knobs. This
#   version separates the two.
#
# TWO TIERS
#   Tier 1 — real credentials. Blocks anywhere. Delegated to gate/secrets-scan.sh --staged, which
#            is the SAME definition make check uses, so commit-time and CI cannot drift apart.
#            It keys off the VALUE: quoted, 12+ chars, and not ${VAR} / <PLACEHOLDER> / process.env.
#   Tier 2 — infrastructure identifiers. Blocks in application source, warns everywhere else.
#            A hardcoded bucket name in backend/src is a bug; in terraform/ it is usually config.
#
# ESCAPE HATCH   `secrets-scan: allow` on the line. Visible in the diff and greppable at audit
#                time — unlike --no-verify, which skips every check instead of one line.
#
# USAGE   installed as .git/hooks/pre-commit by `make install-hooks` (or `make init`)
# EXIT    0 = nothing blocking (warnings may have printed) · 1 = blocked

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 0
GATE_DIR="engine/scripts/gate"
RED=$'\033[0;31m'; YEL=$'\033[0;33m'; NC=$'\033[0m'
BLOCKED=0

STAGED="$(git diff --cached --name-only --diff-filter=ACM)"
[ -z "$STAGED" ] && exit 0

# ── tfvars never get committed (CLAUDE.md: agent never reads them; nobody should commit them) ──
if grep -qE '\.tfvars$' <<<"$STAGED"; then
  echo "${RED}[BLOCKED]${NC} *.tfvars is staged — these hold real infrastructure values and are never committed."
  BLOCKED=1
fi

# ── Tier 1 — real credentials, blocks anywhere ────────────────────────────────
if [ -x "$GATE_DIR/secrets-scan.sh" ] || [ -f "$GATE_DIR/secrets-scan.sh" ]; then
  if ! out=$(bash "$GATE_DIR/secrets-scan.sh" --staged 2>&1); then
    echo "${RED}[BLOCKED]${NC} credential-shaped value(s) in staged content:"
    printf '%s\n' "$out" | sed 's/^/  /'
    BLOCKED=1
  fi
fi

# ── Tier 2 — infrastructure identifiers ───────────────────────────────────────
# perl, not grep: PCRE behaves the same on macOS and Linux. A grep ERE would need \t-free,
# BSD/GNU-safe patterns — the trap that produced finding F-10.
SRC_PATHS='^(backend/src/|frontend/src/|android/app/src/)'
t2_check() {   # $1 = label, $2 = PCRE
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    hits=$(git show ":$f" 2>/dev/null \
      | P="$2" perl -ne 'print "$.: $_" if /$ENV{P}/i' 2>/dev/null \
      | grep -vE 'secrets-scan: allow|\$\{|<[A-Z_]+>|example|placeholder' | head -3)
    [ -n "$hits" ] || continue
    if grep -qE "$SRC_PATHS" <<<"$f"; then
      echo "${RED}[BLOCKED]${NC} $1 in application source — $f"
      printf '%s\n' "$hits" | sed 's/^/    /'
      BLOCKED=1
    else
      echo "${YEL}[warn]${NC}    $1 — $f"
      printf '%s\n' "$hits" | sed 's/^/    /'
    fi
  done <<< "$STAGED"
}

t2_check "AWS account ID"     '(account[_-]?id|aws[_-]?account)\s*[=:]\s*["\x27]?[0-9]{12}["\x27]?'
t2_check "AWS ARN"            'arn:aws[a-z\-]*:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:'
t2_check "RDS endpoint"       '[a-z0-9\-]+\.c[a-z0-9]+\.[a-z]{2}-[a-z]+-[0-9]\.rds\.amazonaws\.com'
t2_check "S3 bucket name"     '(s3[_-]?bucket|bucket[_-]?name)\s*[=:]\s*["\x27][a-z0-9][a-z0-9\-\.]{3,62}["\x27]'
t2_check "security group id"  '\bsg-[0-9a-f]{8,17}\b'

if [ "$BLOCKED" -ne 0 ]; then
  echo ""
  echo "${RED}Commit blocked.${NC} Use \${VAR} or <PLACEHOLDER> instead of the real value."
  echo "A genuine false positive: add  secrets-scan: allow  to that line. Never --no-verify."
  exit 1
fi
exit 0
