#!/usr/bin/env bash
# selftest.sh — fixture-backed regression test for the gate probes.
#
# Builds a throwaway git repo shaped like the cases that have bitten these probes before and
# asserts each probe's answer. Run it after touching anything in engine/scripts/gate/.
#
# USAGE   engine/scripts/gate/selftest.sh        (or: make gate-selftest)
# EXIT    0 = all assertions hold · 1 = at least one failed

set -uo pipefail
GATE_DIR="$(cd "$(dirname "$0")" && pwd)"
FX="$(mktemp -d)"; trap 'rm -rf "$FX"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }
assert_eq() { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected [$3] got [$2]"; }
assert_has() { if grep -qF -- "$3" <<<"$2"; then ok "$1"; else bad "$1" "output lacks [$3]"; fi; }
assert_not() { if grep -qF -- "$3" <<<"$2"; then bad "$1" "output contains [$3]"; else ok "$1"; fi; }

# ── fixture ───────────────────────────────────────────────────────────────────
cd "$FX" && git init -q && git config user.email t@t && git config user.name t
mkdir -p backend/src/middleware backend/src/hooks backend/src/__tests__ docs/security helm/templates
cat > backend/src/middleware/auth.ts <<'TS'
export function requireAuth(req, res, next) { next() }
export const requireRole = (role) => (req, res, next) => next()
export function neverWired(x) { return x }
TS
cat > backend/src/middleware/errors.ts <<'TS'
export function errorHandler(err, req, res, next) {}
TS
cat > backend/src/hooks/scope.ts <<'TS'
export function scopeTenant(opts) {}
export function onlyInComment() {}
export function sameFileHelper(q) { return q }
export function listAll() { return sameFileHelper(1) }
TS
cat > backend/src/app.ts <<'TS'
import { requireAuth, requireRole } from "./middleware/auth";
import { errorHandler } from "./middleware/errors";
import { scopeTenant, onlyInComment } from "./hooks/scope";
app.use(requireAuth);
router.get("/x", requireRole("admin"), h);
const hooks = { beforeFind: scopeTenant };
// TODO: onlyInComment(req) was called here once — this line must NOT count as a call site
app.use(errorHandler);
TS
printf 'x\n' > backend/src/__tests__/auth.test.ts
printf 'kind: Deployment\n' > helm/templates/deploy.yaml
printf 'kind: NetworkPolicy\n' > helm/templates/netpol.yml
cat > .gitlab-ci.yml <<'YML'
build:
  script: [make]
lint:
  script: [npm run lint]
YML
cat > docs/security/CONTROL-MANIFEST.md <<'MD'
| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-01 | token gate | `backend/src/middleware/auth.ts:requireAuth` | - | `auth.test.ts` | by-reference app.use |
| CM-02 | role gate | `backend/src/middleware/auth.ts:requireRole` | - | - | export const arrow, called |
| CM-05 | tenant scope | `backend/src/hooks/scope.ts:scopeTenant` | `helm/templates/netpol.yml` | - | ORM hook by reference |
| CM-10 | error handler | `backend/src/middleware/errors.ts:errorHandler` | - | - | by-reference app.use |
| CM-11 | comment-only | `backend/src/hooks/scope.ts:onlyInComment` | - | - | must FAIL |
| CM-12 | never wired | `backend/src/middleware/auth.ts:neverWired` | - | - | must FAIL |
| CM-13 | same-file helper | `backend/src/hooks/scope.ts:sameFileHelper` | - | - | called only from its own module |
| CM-99 | placeholder | `<path>:<symbol>` | - | `<glob>` | ignored |
MD
git add -A && git commit -qm "[F-ATAK-002/impl] hyphenated story id" -- backend/src/app.ts
git commit -qm "[S-001/tests] plain story id" -- backend/src/__tests__/auth.test.ts
git commit -qm "outside the engine" -- . 

# The verify-controls assertions moved to qa/tests/verify-controls-test.sh with the qa module (2026-10-23);
# the fixture stays, because repo-state's "control manifest : FAIL" line below reads the same manifest.

echo "── repo-state ──"
out=$(bash "$GATE_DIR/repo-state.sh")
assert_has "ci jobs counted with zero directives (no grep -c double print)" "$out" "ci jobs               : 2"
assert_has "helm counts .yml as well as .yaml"                  "$out" "helm/templates files  : 2"
assert_has "manifest FAIL surfaced"                             "$out" "control manifest      : FAIL"
assert_has "orphaned exports = the 3 dead ones (listAll is never called)" "$out" "orphaned exports (adv): 3"
assert_has "first run reports baseline none"                    "$out" "baseline: none"
json=$(bash "$GATE_DIR/repo-state.sh" --json)
assert_has "--json prints JSON to stdout"                       "$json" '"ci_jobs": "2"'
out=$(bash "$GATE_DIR/repo-state.sh")
assert_has "re-run at same SHA is idempotent (still baseline none)" "$out" "baseline: none"
# advance HEAD, drop a helm file, delete the CI test job → deltas must appear against the old SHA
rm helm/templates/netpol.yml; printf 'build:\n  script: [make]\n' > .gitlab-ci.yml
git add -A && git commit -qm "outside the engine: drift" 
out=$(bash "$GATE_DIR/repo-state.sh")
assert_has "helm delta ▼1 against previous SHA"                 "$out" "helm/templates files  : 1   (was 2) ▼1"
assert_has "ci test job YES→NO flagged"                          "$out" "ci runs tests/lint    : NO   (was YES)"
out2=$(bash "$GATE_DIR/repo-state.sh")
assert_eq  "re-run at new SHA reports the same delta again"     "$out2" "$out"
# T-ENGINE-17: a fresh worktree has no per-clone history/, but latest.json is tracked — the gate
# commits it with every row. It must be the baseline there, or every delta flag is suppressed.
rm -rf gate-records/state/history
printf '{ "sha": "0000bad", "recorded": "2026-01-01T00:00:00Z", "ci_test_job": "YES", "helm_templates": "2" }\n' > gate-records/state/latest.json
out=$(bash "$GATE_DIR/repo-state.sh")
assert_has "fresh worktree: the tracked latest.json is the baseline" "$out" "baseline: 0000bad"
assert_has "…and its YES/NO flags are raised"                   "$out" "ci runs tests/lint    : NO   (was YES)"
assert_has "…and its numbers are deltas"                        "$out" "helm/templates files  : 1   (was 2) ▼1"
# a newer per-clone snapshot at another sha still wins over an older latest.json
printf '{ "sha": "1111new", "recorded": "2027-01-01T00:00:00Z", "helm_templates": "5" }\n' > gate-records/state/history/1111new.json
out=$(bash "$GATE_DIR/repo-state.sh")
assert_has "the later snapshot wins, wherever it lives"         "$out" "baseline: 1111new"
# latest.json that describes HEAD itself is not a baseline, for the same idempotence reason
rm -rf gate-records/state/history
printf '{ "sha": "%s", "recorded": "2026-01-01T00:00:00Z", "helm_templates": "2" }\n' "$(git rev-parse --short HEAD)" > gate-records/state/latest.json
out=$(bash "$GATE_DIR/repo-state.sh")
assert_has "latest.json at HEAD's own sha is not a baseline"    "$out" "baseline: none"
rm -f gate-records/state/latest.json

echo "── legacy-inventory ──"
out=$(bash "$GATE_DIR/legacy-inventory.sh")
# app.ts gated by [F-ATAK-002/impl]; auth.test.ts is a test (excluded); the other 3 src files never gated
assert_has "hyphenated story id counts as gated; substring match does not" "$out" "source files: 4 · engine-gated: 1 (25%) · never gated: 3"

echo "── legacy-inventory substring guard ──"
mkdir -p src && cp backend/src/app.ts src/app.ts && git add -A && git commit -qm "outside the engine: copy"
out=$(bash "$GATE_DIR/legacy-inventory.sh")
assert_has "src/app.ts not vouched for by backend/src/app.ts"   "$out" "engine-gated: 1 "

echo "── legacy-inventory: gate-logged merge counts as gated ──"
git checkout -q -b epic/widgets && mkdir -p backend/src/widgets && printf 'export function w(){}\n' > backend/src/widgets/w.ts \
  && git add -A && git commit -qm "add widgets (free-form message, no story prefix)" && git checkout -q - \
  && git merge -q --no-ff -m "Merge epic/widgets" epic/widgets
M=$(git rev-parse --short HEAD)
mkdir -p gate-records && printf '| date | epic | range | run | findings | retro | verdict | reviewer |\n|---|---|---|---|---|---|---|---|\n| 2026-09-16 | widgets | abc1234..%s | 1 | 0 | - | PASS | t |\n' "$M" > gate-records/gate-log.md
out=$(bash "$GATE_DIR/legacy-inventory.sh")
assert_has "merge with a gate-log row marks its files gated" "$out" "engine-gated: 2 "
rm gate-records/gate-log.md
out=$(bash "$GATE_DIR/legacy-inventory.sh")
assert_has "same merge without a gate-log row is NOT gated" "$out" "engine-gated: 1 "

# ── scan-precondition ─────────────────────────────────────────────────────────
# The defect this exists for: a CVE fix is a dependency bump, so a bump landing after the quality
# gate ran invalidates the coverage it just blessed. Scanning at the END of the gate does not avoid
# that — the finding still arrives too late. This refuses the handoff until the tree is scanned
# green on the commit being gated.
echo "── scan-precondition ──"
SP_DIR="$FX/_scanres"; mkdir -p "$SP_DIR"
SP_HEAD="$(git rev-parse HEAD)"
sp() { SCAN_RESULTS_DIR="$SP_DIR" "$GATE_DIR/../../../core/run" scan-precondition 2>&1; }
sp_rc() { SCAN_RESULTS_DIR="$SP_DIR" "$GATE_DIR/../../../core/run" scan-precondition >/dev/null 2>&1; echo $?; }

# Commit one file at $1, stamp the scan at the commit BEFORE it, and report the exit code. Used to
# prove the record-only exemption applies to records and to nothing else. Leaves no commit behind.
_sp_drift_rc() {
  local f="$1" base_sha rc
  base_sha="$(git rev-parse HEAD)"
  mkdir -p "$(dirname "$f")" 2>/dev/null || true
  printf 'probe\n' > "$f"
  git add -- "$f" >/dev/null 2>&1
  git -c user.email=selftest@x -c user.name=selftest commit -qm "selftest drift probe" >/dev/null 2>&1
  printf '%s PASS 2026-09-19T00:00:00Z\n' "$base_sha" > "$SP_DIR/.scan-stamp"
  SCAN_RESULTS_DIR="$SP_DIR" "$GATE_DIR/../../../core/run" scan-precondition >/dev/null 2>&1; rc=$?
  git reset -q --hard "$base_sha" >/dev/null 2>&1
  rm -f "$f" 2>/dev/null || true
  echo "$rc"
}

rm -f "$SP_DIR/.scan-stamp"
assert_eq  "no scan recorded refuses"                  "$(sp_rc)" "1"
assert_has "…and says which command to run"            "$(sp)"    "make gate-scan"

printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef PASS 2026-09-19T00:00:00Z\n' > "$SP_DIR/.scan-stamp"
assert_eq  "a scan naming a commit that does not exist refuses" "$(sp_rc)" "1"
assert_has "…and says the sha is not a commit"         "$(sp)"    "not a commit in this repository"

# Record-only drift does not invalidate a scan (2026-10-05). The gate writes its own
# gate-log row, which moved HEAD past the scanned commit and made the NEXT gate re-scan because of
# a row the PREVIOUS gate wrote — the log stopping a scan by proxy. A scan reads dependencies,
# images and source, so a range of pure records describes the same inputs. Anything that is not a
# record still refuses, which is the half that matters.
assert_eq  "a scan of HEAD~ with only a record changed passes" \
  "$(_sp_drift_rc 'gate-records/probe-only.md')" "0"
assert_eq  "…but a source file in the same range refuses" \
  "$(_sp_drift_rc 'src/probe-only.ts')" "1"

printf '%s FAIL 2026-09-19T00:00:00Z\n' "$SP_HEAD" > "$SP_DIR/.scan-stamp"
assert_eq  "a red scan on this commit refuses"         "$(sp_rc)" "1"
assert_has "…and says it was FAIL"                     "$(sp)"    "was FAIL"

printf '%s PASS 2026-09-19T00:00:00Z\n' "$SP_HEAD" > "$SP_DIR/.scan-stamp"
assert_eq  "green scan on this commit passes"          "$(sp_rc)" "0"

# The override exists for "Docker is unavailable", not for "the scan is red". It must be loud.
rm -f "$SP_DIR/.scan-stamp"
out=$(SKIP_SCAN_CHECK=1 SCAN_RESULTS_DIR="$SP_DIR" "$GATE_DIR/../../../core/run" scan-precondition 2>&1)
assert_eq  "SKIP_SCAN_CHECK=1 overrides" \
  "$(SKIP_SCAN_CHECK=1 SCAN_RESULTS_DIR="$SP_DIR" "$GATE_DIR/../../../core/run" scan-precondition >/dev/null 2>&1; echo $?)" "0"
assert_has "…and warns that CVE state is unknown"      "$out"     "CVE state is unknown"

# ── make lint / make test cover every app dir (T-018) ─────────────────────────
# On 2026-09-23 `make lint` and `make test` looked only at backend/, so a frontend with its own
# lint, typecheck and test scripts was never run by `make check` or CI. Drive the real Makefile
# from a fixture holding both app dirs and a fake npm that records every call it receives.
echo "── make lint / make test cover both apps ──"
MK_DIR="$FX/_make"; mkdir -p "$MK_DIR/bin" "$MK_DIR/backend/node_modules" "$MK_DIR/frontend/node_modules"
printf '{}\n' > "$MK_DIR/backend/package.json"; printf '{}\n' > "$MK_DIR/frontend/package.json"
cat > "$MK_DIR/bin/npm" <<'SH'
#!/usr/bin/env bash
echo "$(basename "$PWD") $*" >> "$NPM_CALLS"
SH
chmod +x "$MK_DIR/bin/npm"
MK_ROOT="$(cd "$GATE_DIR/../../.." && pwd)"
mk() { NPM_CALLS="$MK_DIR/calls" PATH="$MK_DIR/bin:$PATH" make -s -C "$MK_DIR" -f "$MK_ROOT/Makefile" "$@"; }
rm -f "$MK_DIR/calls"; mk lint >/dev/null 2>&1; CALLS="$(cat "$MK_DIR/calls" 2>/dev/null)"
assert_has "make lint lints the backend"        "$CALLS" "backend run lint"
assert_has "make lint typechecks the backend"   "$CALLS" "backend run typecheck"
assert_has "make lint lints the frontend"       "$CALLS" "frontend run lint"
assert_has "make lint typechecks the frontend"  "$CALLS" "frontend run typecheck"
rm -f "$MK_DIR/calls"; mk test >/dev/null 2>&1; CALLS="$(cat "$MK_DIR/calls" 2>/dev/null)"
assert_has "make test runs the backend suite"   "$CALLS" "backend test"
assert_has "make test runs the frontend suite"  "$CALLS" "frontend test"
# A lockfile with no node_modules under CI is an install error, not a greenfield project.
rm -rf "$MK_DIR/frontend/node_modules"; printf '{}\n' > "$MK_DIR/frontend/package-lock.json"
rc="$(CI=true mk lint >/dev/null 2>&1; echo $?)"
[ "$rc" != 0 ] && ok "CI: a frontend lockfile with no node_modules fails make lint" \
  || bad "CI: a frontend lockfile with no node_modules fails make lint" "exit was 0"
rc="$(CI=true mk test >/dev/null 2>&1; echo $?)"
[ "$rc" != 0 ] && ok "CI: a frontend lockfile with no node_modules fails make test" \
  || bad "CI: a frontend lockfile with no node_modules fails make test" "exit was 0"
# CI must be explicitly empty here: GitHub's runner exports CI=true, which is exactly what this
# case is the control for (found when the branch's first CI run failed on this assertion).
rc="$(CI= mk lint >/dev/null 2>&1; echo $?)"
[ "$rc" = 0 ] && ok "off CI the same tree only skips the frontend" \
  || bad "off CI the same tree only skips the frontend" "exit was $rc"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
