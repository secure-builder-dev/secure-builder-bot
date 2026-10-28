#!/usr/bin/env bash
# gate-proof tests — the replay must fail when the gate would miss a recorded bug.
#
# WHY   gate-proof is the argument that a cheaper gate is not a blinder one. A replay that has never
#       been seen failing proves nothing, so each negative case below breaks exactly one claim.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENG="$SCRIPT_DIR/../gate"
PASS=0; FAIL=0
_pass() { echo "  ok    $1"; PASS=$((PASS + 1)); }
_fail() { echo "  FAIL  $1 — $2"; FAIL=$((FAIL + 1)); }
echo "── gate-proof ──"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/engine/scripts" && cp -r "$ENG" "$T/engine/scripts/gate"
# derive-controls and mutate-controls live in the qa module; gate-proof calls them there.
mkdir -p "$T/qa" && cp -r "$ENG/../../../qa/scripts" "$T/qa/scripts"
# The range classifier lives in core/ (ported from classify-range.sh); gate-proof calls it there.
cp -r "$ENG/../../../core" "$T/core"
( cd "$T" && git init -q . && git config user.email t@t && git config user.name t
  mkdir -p backend/src/services docs/security
  printf 'APP_TRACK: web\n' > project.config.yaml
  printf 'export function shout() { return 1 }\n' > backend/src/services/text.ts
  git add -A && git commit -qm base
  git tag light0
  printf 'export function shout() { return 2 }\n' > backend/src/services/text.ts
  git commit -qam light && git tag light1
  printf 'export function guard(user) {\n  if (user.role !== "admin") throw new AppError(403, "F", "no")\n}\n' > backend/src/services/gatekeeper.ts
  git add -A && git commit -qm deep && git tag deep1 )
manifest() { printf '| CM-01 | g | `backend/src/services/gatekeeper.ts:guard` | - | `x.test.ts` | n |\n' > "$T/docs/security/CONTROL-MANIFEST.md"; }
proof() { printf '| bug | found | range | by | guard | derived | CM |\n|---|---|---|---|---|---|---|\n| T-001 | x | `%s` | run | `backend/src/services/gatekeeper.ts:guard` | %s | CM-01 |\n' "$1" "$2" > "$T/docs/security/PROOF-SET.md"; }
run() { OUT=$(cd "$T" && bash engine/scripts/gate/gate-proof.sh --no-mutate 2>&1); RC=$?; }

manifest; proof "light1..deep1" yes; run
[ "$RC" -eq 0 ] && _pass "a deep range with a registered guard replays" || _fail "a deep range with a registered guard replays" "$OUT"
proof "light0..light1" yes; run
if [ "$RC" -eq 1 ] && grep -q '✗ light' <<<"$OUT"; then _pass "a range the classifier calls light fails the replay"; else _fail "light range must fail" "$OUT"; fi
: > "$T/docs/security/CONTROL-MANIFEST.md"; proof "light1..deep1" yes; run
if [ "$RC" -eq 1 ] && grep -q 'not listed' <<<"$OUT"; then _pass "a guard that lost its manifest row fails the replay"; else _fail "unregistered guard must fail" "$OUT"; fi
proof "light1..deep1" "— not a guard shape"; run
[ "$RC" -eq 0 ] && _pass "an exempt row needs no derived listing" || _fail "exempt row" "$OUT"
rm -f "$T/docs/security/PROOF-SET.md"; run
if [ "$RC" -eq 0 ] && grep -q 'nothing to replay' <<<"$OUT"; then _pass "no proof set is a note, not a failure"; else _fail "no proof set" "$OUT"; fi
echo; echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
