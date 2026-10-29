#!/usr/bin/env bash
# Scan-script test suite — bats not available on this machine; custom shell test runner.
# Asserts expected behavior for all scanner scripts and generate-dispatch.sh.
# RED phase: all tests fail (scripts do not exist yet).
# GREEN phase: all tests pass after implementation commit.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN_DIR="$MODULE_DIR/scripts"
PROJECT_ROOT="$(cd "$MODULE_DIR/.." && pwd)"
FIXTURE_DIR="$MODULE_DIR/fixtures"

# ── Nothing here may write to the live results directory ─────────────────────
# SEC-SC3-1: two cases invoked a REAL runner without SCAN_RESULTS_DIR, so grype and trivy wrote
# into gate-records/scan/latest — over the results and the receipt file a `make gate-scan` had just
# produced. `make gate-selftest` is a required step of the gate itself and runs before the verdict
# is read, so the gate's own procedure invalidated the evidence it then transcribed. The same defect
# was fixed for ClamAV under T-023 one case below; the grype/trivy call twenty lines above was not.
#
# Fixed at the root rather than per call site: every runner this file invokes inherits a scratch
# directory unless a case deliberately sets its own. A case added later cannot reintroduce it by
# forgetting, which is exactly how this one survived. The guard is asserted at the end of the run.
# `cksum` and not `md5`: md5 is a BSD binary, absent on Linux, and the first cut fell back to a
# placeholder on both sides so they compared equal and the check printed a pass having measured
# nothing — the epic's own defect, inside the guard against it (QG-SC4-1). cksum is POSIX and
# present on macOS and Linux alike; only same-machine comparison matters. Contents, not `ls -l`,
# because `ls -l` prints mtime to the minute and hides a same-length rewrite within one (QG-SC4-N1).
# Failure to measure returns non-zero and can never reach the passing branch below.
_LIVE_RESULTS="$PROJECT_ROOT/gate-records/scan/latest"
[ -d "$_LIVE_RESULTS" ] || _LIVE_RESULTS=""
_live_manifest() {
  [ -n "$_LIVE_RESULTS" ] || return 1
  local m; m="$(find "$_LIVE_RESULTS" -type f 2>/dev/null | LC_ALL=C sort | xargs cksum 2>/dev/null)"
  [ -n "$m" ] || return 1
  printf '%s' "$m"
}
_LIVE_BEFORE="$(_live_manifest)" || _LIVE_BEFORE=""
SCAN_RESULTS_DIR="$(mktemp -d)"; export SCAN_RESULTS_DIR
trap 'rm -rf "$SCAN_RESULTS_DIR"' EXIT

PASS=0
FAIL=0
SKIP=0

# The date the justification-list fixtures use for "unexpired". GNU date first, BSD second.
DATE_SOON=$(date -u -d '+10 days' +%Y-%m-%d 2>/dev/null || date -u -v+10d +%Y-%m-%d)

_pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
_fail() { echo "  FAIL: $1 — $2"; FAIL=$((FAIL + 1)); }
_skip() { echo "  SKIP: $1 — $2"; SKIP=$((SKIP + 1)); }

check_executable() {
  local name="$1" path="$2"
  if [[ -x "$path" ]]; then _pass "$name"; else _fail "$name" "not found or not executable: $path"; fi
}

check_makefile_target() {
  local target="$1"
  local mf="$PROJECT_ROOT/Makefile"
  if [[ -f "$mf" ]] && grep -qE "^$target[[:space:]]*(:|##)" "$mf"; then
    _pass "Makefile has target: $target"
  else
    _fail "Makefile has target: $target" "target not found in $mf"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 1: Script existence and permissions ==="
for script in run-hadolint.sh run-checkov.sh run-clamav.sh run-grype.sh run-trivy.sh run-npm-audit.sh run-eslint.sh pull-images.sh checkov-decide.sh generate-dispatch.sh; do
  check_executable "$script exists and is executable" "$SCAN_DIR/$script"
done

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 2: Makefile targets ==="
for target in scan scan-lite scan-images scan-dispatch audit audit-fix; do
  check_makefile_target "$target"
done

# The scan is read-only against the tree it stamps. `audit-fix` rewrites lockfiles, so no scan or
# check target may reach it, directly or through $(MAKE).
mf="$PROJECT_ROOT/Makefile"
if awk '/^(scan|scan-lite|scan-images|gate-scan|check|audit):/{p=1;next} /^[a-zA-Z_-]+:/{p=0} p' "$mf" | grep 'audit-fix' >/dev/null; then
  _fail "no scan/check target calls audit-fix" "a scan or check recipe references audit-fix"
else
  _pass "no scan/check target calls audit-fix"
fi
for t in scan scan-lite gate-scan; do
  if awk -v t="$t" '$0 ~ "^"t":"{p=1;next} /^[a-zA-Z_-]+:/{p=0} p' "$mf" | grep 'run-npm-audit.sh' >/dev/null; then
    _pass "$t runs run-npm-audit.sh"
  else
    _fail "$t runs run-npm-audit.sh" "recipe does not call the runner"
  fi
done
for t in scan scan-lite gate-scan; do
  if awk -v t="$t" '$0 ~ "^"t":"{p=1;next} /^[a-zA-Z_-]+:/{p=0} p' "$mf" | grep 'run-eslint.sh' >/dev/null; then
    _pass "$t runs run-eslint.sh"
  else
    _fail "$t runs run-eslint.sh" "recipe does not call the runner"
  fi
done
# From the engine's first project (2026-10-03, GOV-023). The assertion is unchanged in intent — `audit` must be
# wired into `check` — but its mechanism was "grep check's prerequisites", and `check` no longer has any.
# GOV-023 moved the list into CHECK_TARGETS so that one failing check stops hiding every check after it, which
# required `check` to have no prerequisites: make merges prerequisites across every definition of a target, so
# they run fail-fast ahead of the recipe. Either wiring satisfies this; neither alone is weaker.
if grep -qE '^(check:.*\baudit\b|CHECK_TARGETS[[:space:]]*[:+]?=.*\baudit\b)' "$mf"; then
  _pass "check depends on audit"
else
  _fail "check depends on audit" "audit is in neither check's prerequisites nor CHECK_TARGETS"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 3: Image scanners never silently skip ==="

# These used to assert "exits 0 and prints SKIPPED when credentials are absent" — a contract that
# came from a credentialed hardened registry being the primary base. ADR-034 superseded that:
# Chainguard is primary and any credentialed registry is a documented fallback. The credential plumbing was also in the wrong place. These
# scanners read images that are already built and present locally, so they need no registry auth
# whatever the base is; auth would matter only for `docker build --pull` in build-images.sh.
#
# What is worth asserting is the invariant underneath: an image scan must never report a skip.
# A skip reads as "nothing to worry about" and is indistinguishable from a clean result in a log,
# which is the same failure shape image-age-guard.sh exists to prevent.

no_silent_skip_test() {
  local script_name="$1"
  local path="$SCAN_DIR/$script_name"
  local output
  if [[ ! -x "$path" ]]; then
    _fail "$script_name never reports a skip" "script does not exist"
    return
  fi
  # Whatever the credential environment, the answer must be a scan or a stated failure — never
  # a skip. It may exit non-zero here for a missing tool or a missing image; that is honest.
  output=$(env -u REGISTRY_USERNAME -u REGISTRY_PASSWORD -u BASE_IMAGE "$path" 2>&1 || true)
  if grep -q "SKIPPED" <<<"$output"; then
    _fail "$script_name never reports a skip" "printed SKIPPED: $(echo "$output" | grep SKIPPED | head -1)"
  else
    _pass "$script_name never reports a skip"
  fi
}

# And the plumbing itself should stay gone: a scanner carrying registry credentials is a scanner
# that can skip for a reason unrelated to what it found.
no_registry_auth_test() {
  local script_name="$1"
  local path="$SCAN_DIR/$script_name"
  if grep -qiE "REGISTRY_(USERNAME|PASSWORD)|docker login" "$path"; then
    _fail "$script_name carries no registry credentials" "found registry auth in a local-image scanner"
  else
    _pass "$script_name carries no registry credentials"
  fi
}

for img_script in run-grype.sh run-trivy.sh; do
  no_silent_skip_test "$img_script"
  no_registry_auth_test "$img_script"
done

# The exclusion above must not have blunted the guard. Plant a real bare call in a scratch copy and
# assert it is still seen — the same canary discipline as the npm-audit-fix check (SEC-SC-5).
bare_canary=$(mktemp -d); cp "$SCAN_DIR/run-grype.sh" "$bare_canary/run-grype.sh"
printf 'grype --output json some-image:tag\n' >> "$bare_canary/run-grype.sh"
canary_hit=$(grep -nE '(^|[^_[:alnum:]])(hadolint|checkov|clamscan|grype|trivy)[[:space:]]+[^)=]' \
  "$bare_canary/run-grype.sh" | grep -vE 'tool_|command -v|^[0-9]+:[[:space:]]*#|echo|install|NOT INSTALLED|scan_(begin|ran|none)[[:space:]]' || true)
if [ -n "$canary_hit" ]; then
  _pass "the bare-scanner-call guard still catches a planted bare call"
else
  _fail "the bare-scanner-call guard still catches a planted bare call" "a planted 'grype --output json' was not seen"
fi
rm -rf "$bare_canary"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 4: Dispatch generator routing ==="

run_dispatch_test() {
  local label="$1"
  local fixture_set="$2"
  local expect_dispatch="$3"      # "yes" | "no"
  local expect_poam="$4"          # "yes" | "no"
  local dispatch_contains="${5:-}"

  local gen="$SCAN_DIR/generate-dispatch.sh"
  if [[ ! -x "$gen" ]]; then
    _fail "Dispatch [$label]: generate-dispatch.sh runs without error" "script does not exist"
    [[ "$expect_dispatch" == "yes" ]] && _fail "Dispatch [$label]: dispatch.md written" "script does not exist"
    [[ "$expect_dispatch" == "no" ]]  && _fail "Dispatch [$label]: dispatch.md NOT written" "script does not exist"
    [[ "$expect_poam" == "yes" ]]     && _fail "Dispatch [$label]: poam-candidates.md written" "script does not exist"
    return
  fi

  local src_dir out_dir
  src_dir=$(mktemp -d)
  out_dir=$(mktemp -d)
  cp "$FIXTURE_DIR/$fixture_set/"* "$src_dir/"

  # generate-dispatch.sh reads from SCAN_RESULTS_DIR and writes to OUTPUT_DIR
  local gd_exit=0
  SCAN_RESULTS_DIR="$src_dir" OUTPUT_DIR="$out_dir" "$gen" >/dev/null 2>&1 || gd_exit=$?
  _pass "Dispatch [$label]: generate-dispatch.sh ran (exit $gd_exit)"

  if [[ "$expect_dispatch" == "yes" ]]; then
    if [[ -f "$out_dir/dispatch.md" ]]; then
      _pass "Dispatch [$label]: dispatch.md written"
      if [[ -n "$dispatch_contains" ]]; then
        if grep -q "$dispatch_contains" "$out_dir/dispatch.md"; then
          _pass "Dispatch [$label]: dispatch.md contains '$dispatch_contains'"
        else
          _fail "Dispatch [$label]: dispatch.md contains '$dispatch_contains'" "not found in dispatch.md"
        fi
      fi
    else
      _fail "Dispatch [$label]: dispatch.md written" "file not created in $out_dir"
      [[ -n "$dispatch_contains" ]] && _fail "Dispatch [$label]: dispatch.md contains '$dispatch_contains'" "dispatch.md missing"
    fi
  else
    if [[ ! -f "$out_dir/dispatch.md" ]]; then
      _pass "Dispatch [$label]: dispatch.md NOT written"
    else
      _fail "Dispatch [$label]: dispatch.md NOT written" "dispatch.md was incorrectly created"
    fi
  fi

  if [[ "$expect_poam" == "yes" ]]; then
    if [[ -f "$out_dir/poam-candidates.md" ]]; then
      _pass "Dispatch [$label]: poam-candidates.md written"
    else
      _fail "Dispatch [$label]: poam-candidates.md written" "file not created"
    fi
  fi

  rm -rf "$src_dir" "$out_dir"
}

run_dispatch_test "amelia-findings"  "amelia-findings"  "yes" "no"  "Amelia"
run_dispatch_test "frank-findings"   "frank-findings"   "yes" "no"  "Frank"
run_dispatch_test "poam-only"        "poam-only"        "no"  "yes" ""
run_dispatch_test "clean"            "clean"            "no"  "no"  ""
run_dispatch_test "npm-audit-blocking" "npm-audit-blocking" "yes" "no" "GHSA-fixt-high-0001"
run_dispatch_test "eslint-findings"   "eslint-findings"   "yes" "no" "react-hooks/rules-of-hooks"
# checkov OSS emits no severity; an unrated failed check must still dispatch (it used to be filtered to nothing).
run_dispatch_test "checkov-null-severity" "checkov-null-severity" "yes" "no" "CKV_K8S_21"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 5: ClamAV EICAR detection ==="

# Gate on what run-clamav.sh itself can use, not on a host binary. Checking `command -v clamscan`
# skipped malware detection on every machine that has Docker but no local ClamAV — which, now that
# the scan runs from a container, is most of them. This is the only test that proves the scanner
# detects anything at all, so skipping it by default is the worst place to be lenient.
# shellcheck source=../scripts/tool-runner.sh
. "$SCAN_DIR/tool-runner.sh"

if ! have_tool clamscan; then
  _skip "run-clamav.sh exits 1 on EICAR detection" "no clamscan and no Docker ($(scan_engine) engine)"
  _skip "run-clamav.sh prints INFECTION DETECTED on EICAR" "no clamscan and no Docker ($(scan_engine) engine)"
elif [[ ! -x "$SCAN_DIR/run-clamav.sh" ]]; then
  _fail "run-clamav.sh exits 1 on EICAR detection" "script does not exist"
  _fail "run-clamav.sh prints INFECTION DETECTED on EICAR" "script does not exist"
else
  eicar_dir=$(mktemp -d)
  # EICAR standard test string — safe, not malware
  printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    > "$eicar_dir/eicar.com"
  # CLAMAV_MAX_AGE_DAYS is lifted for this test on purpose. What is under test here is whether the
  # scanner detects anything at all; the freshness policy is under test in Group 8, against fakes.
  # Left at the default, this test would trigger a full freshclam download on every `make check` as
  # soon as the image's baked signatures aged past a week — minutes of CI, on an ephemeral runner
  # that cannot keep the cache volume, to prove something EICAR has been detected by since 1991.
  # Results go to a scratch dir: without SCAN_RESULTS_DIR this test wrote an EICAR-positive
  # clamav.log into gate-records/scan/latest and the next verdict read MALWARE DETECTED (T-023).
  eicar_results=$(mktemp -d)
  eicar_out=$(SCAN_DIR_OVERRIDE="$eicar_dir" SCAN_RESULTS_DIR="$eicar_results" CLAMAV_MAX_AGE_DAYS=36500 \
    "$SCAN_DIR/run-clamav.sh" 2>&1) && eicar_exit=0 || eicar_exit=$?
  rm -rf "$eicar_results"
  # Any non-zero used to satisfy this, so a docker failure (exit 125, container never started)
  # passed it while the detection assertion below failed. Exit 1 is the infection path; anything
  # else is the scanner falling over, which is a different result and must not read as success.
  if [[ $eicar_exit -eq 1 ]]; then
    _pass "run-clamav.sh exits 1 on EICAR detection"
  elif [[ $eicar_exit -eq 0 ]]; then
    _fail "run-clamav.sh exits 1 on EICAR detection" "exit 0 — EICAR was not detected"
  else
    _fail "run-clamav.sh exits 1 on EICAR detection" \
      "exit $eicar_exit — the scanner failed to run, it did not scan and find nothing"
  fi
  if grep -qi "INFECTION DETECTED" <<<"$eicar_out"; then
    _pass "run-clamav.sh prints INFECTION DETECTED on EICAR"
  else
    _fail "run-clamav.sh prints INFECTION DETECTED on EICAR" "expected INFECTION DETECTED in: $eicar_out"
  fi
  rm -rf "$eicar_dir"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 6: Container tool runner ==="

RUNNER="$SCAN_DIR/tool-runner.sh"
check_executable "tool-runner.sh exists" "$RUNNER"
if [[ -f "$SCAN_DIR/tool-versions.env" ]]; then
  _pass "tool-versions.env exists"
else
  _fail "tool-versions.env exists" "not found"
fi

# Engine resolution honours the override in both directions. The assignment is exported rather
# than prefixed: in bash `VAR=x . file` does not survive the source, so a prefix here would test
# the default path twice and pass for the wrong reason.
engine_of() { ( export SCAN_ENGINE="$1"; . "$RUNNER" >/dev/null 2>&1; scan_engine ); }
for want in native container; do
  got=$(engine_of "$want" 2>/dev/null || echo ERROR)
  if [[ "$got" == "$want" ]]; then
    _pass "SCAN_ENGINE=$want resolves to $want"
  else
    _fail "SCAN_ENGINE=$want resolves to $want" "got '$got'"
  fi
done

# One tool may take the other engine: a host with trivy installed and the rest in containers (this
# bot's own sandbox) sets SCAN_ENGINE_TRIVY=native and the other wrappers are unchanged. The
# override is per tool and never leaks: scan_engine still answers for everything else.
# The wrapper is sourced in a fresh bash, never in this shell: the engine it resolves is cached.
read -r -d '' ENGINE_FOR_SCRIPT <<'EOS' || true
. "$0" >/dev/null 2>&1
out=""
for t in "$@"; do out="$out $(scan_engine_for "$t")"; done
printf '%s' "${out# }"
EOS
engine_for() {   # engine_for <VAR=value…> -- <tool…> → the engines resolved for those tools, space-separated
  local -a vars=()
  while [ "$1" != "--" ]; do vars+=("$1"); shift; done; shift
  env "${vars[@]}" bash -c "$ENGINE_FOR_SCRIPT" "$RUNNER" "$@" 2>/dev/null
}
got=$(engine_for SCAN_ENGINE=container SCAN_ENGINE_TRIVY=native -- grype trivy hadolint || echo ERROR)
if [[ "$got" == "container native container" ]]; then
  _pass "SCAN_ENGINE_TRIVY=native overrides trivy alone (grype and hadolint stay on the global engine)"
else
  _fail "SCAN_ENGINE_TRIVY=native overrides trivy alone" "got '$got'"
fi
got=$(engine_for SCAN_ENGINE=native SCAN_ENGINE_CLAMAV=bogus -- clamscan || echo ERROR)
if [[ "$got" == "native" ]]; then
  _pass "a per-tool override that is not container|native is ignored (clamscan asks as clamav)"
else
  _fail "a per-tool override that is not container|native is ignored" "got '$got'"
fi

# Every runner goes through the wrapper — no residual host-binary gate.
for script in run-hadolint.sh run-checkov.sh run-clamav.sh run-grype.sh run-trivy.sh; do
  if grep -q 'tool-runner.sh' "$SCAN_DIR/$script"; then
    _pass "$script sources tool-runner.sh"
  else
    _fail "$script sources tool-runner.sh" "no reference found"
  fi
  if grep -qE '^if ! command -v (hadolint|checkov|clamscan|grype|trivy) ' "$SCAN_DIR/$script"; then
    _fail "$script has no host-binary gate" "still gates on 'command -v' for its scanner"
  else
    _pass "$script has no host-binary gate"
  fi
  # A runner can drop the gate and still call the bare binary further down, which fails only on a
  # machine without the tool installed — i.e. everywhere the container engine exists to serve.
  # Checking the gate alone missed exactly that in run-trivy.sh.
  # `scan_begin grype` / `scan_ran grype "..."` name a scanner as an ARGUMENT to the receipt
  # helpers, not as a binary to run (SEC-SC2-1's fix). Excluded by those exact call shapes only, so
  # `grype --output json` on its own is still caught — proven by the canary below.
  bare=$(grep -nE '(^|[^_[:alnum:]])(hadolint|checkov|clamscan|grype|trivy)[[:space:]]+[^)=]' \
           "$SCAN_DIR/$script" | grep -vE 'tool_|command -v|^[0-9]+:[[:space:]]*#|echo|install|NOT INSTALLED|scan_(begin|ran|none)[[:space:]]' || true)
  if [[ -z "$bare" ]]; then
    _pass "$script invokes its scanner only through tool-runner"
  else
    _fail "$script invokes its scanner only through tool-runner" "bare call: $(echo "$bare" | head -1)"
  fi
done

# Every image named in tool-versions.env must carry an explicit version. A bare name resolves to
# :latest, which makes the scan unreproducible and silently changes what ran between two runs.
unpinned=0
while IFS= read -r ref; do
  [[ "$ref" == *:* || "$ref" == *@sha256:* ]] || unpinned=$((unpinned + 1))
done < <( ( . "$RUNNER" >/dev/null 2>&1
            printf '%s\n' "$SCAN_IMAGE_HADOLINT" "$SCAN_IMAGE_CHECKOV" \
                           "$SCAN_IMAGE_CLAMAV" "$SCAN_IMAGE_GRYPE" "$SCAN_IMAGE_TRIVY" ) )
if [[ "$unpinned" -eq 0 ]]; then
  _pass "all five scanner images carry an explicit tag or digest"
else
  _fail "all five scanner images carry an explicit tag or digest" "$unpinned unpinned"
fi

# ClamAV must never be digest-pinned: its signatures ship inside the image, so a digest freezes
# them permanently and the scan stops recognising anything published after that build.
clamav_ref=$( . "$RUNNER" >/dev/null 2>&1; printf '%s' "$SCAN_IMAGE_CLAMAV" )
if [[ "$clamav_ref" == *@sha256:* ]]; then
  _fail "ClamAV image is not digest-pinned" "digest pin freezes virus signatures: $clamav_ref"
else
  _pass "ClamAV image is not digest-pinned"
fi

# A patch tag fails for the same reason a digest does. clamav/clamav publishes x.y.z once and
# never rebuilds it, so x.y.z freezes the signatures exactly as a digest would; only the moving
# tags (stable, latest, x.y) are rebuilt with fresh ones. This also catches a tag that was never
# published at all — the repo sat on clamav/clamav:1.4.1, which does not exist, and every scan
# died at exit 125 before a container started.
clamav_tag="${clamav_ref##*:}"
if [[ "$clamav_tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+(_base)?$ ]]; then
  _fail "ClamAV image is on a moving tag" \
    "$clamav_ref is a patch tag — published once, never rebuilt, so its signatures never move"
else
  _pass "ClamAV image is on a moving tag"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
# ClamAV publishes no arm64 image, so on an arm64 host Docker writes a platform-mismatch WARNING
# into the command's own output, where the signature-freshness guard parses it instead of a version
# line and blocks the scan as UNVERIFIED. Grepping the call sites is not enough: the flag has to
# reach `docker run`, and the opt-out has to actually opt out.
platform_of() { ( export SCAN_PLATFORM_CLAMAV="$1"; . "$RUNNER" >/dev/null 2>&1; _tr_clamav_platform ); }

got=$(platform_of "linux/amd64" || true)
if [[ "$got" == "--platform linux/amd64" ]]; then
  _pass "ClamAV wrapper requests a platform when one is set"
else
  _fail "ClamAV wrapper requests a platform when one is set" "got '$got'"
fi

# The negative fixture. An empty override must emit nothing at all — not `--platform` with a blank
# argument, which docker rejects outright and would turn an opt-out into a hard failure.
got=$(platform_of "" || true)
if [[ -z "$got" ]]; then
  _pass "ClamAV wrapper emits nothing when the platform override is empty"
else
  _fail "ClamAV wrapper emits nothing when the platform override is empty" "got '$got'"
fi

# If tool-versions.env ever drops the default, every arm64 machine silently returns to the
# UNVERIFIED-signature failure this exists to stop — and CI, being amd64, would not notice.
got=$( ( . "$RUNNER" >/dev/null 2>&1; printf '%s' "${SCAN_PLATFORM_CLAMAV:-}" ) )
if [[ -n "$got" ]]; then
  _pass "tool-versions.env sets a default ClamAV platform ($got)"
else
  _fail "tool-versions.env sets a default ClamAV platform" "SCAN_PLATFORM_CLAMAV is empty by default"
fi

# Both call sites, not one. clamscan alone would still leave freshclam — the call whose output the
# guard actually parses — emitting the warning.
clam_calls=$(grep -c '[$](_tr_clamav_platform)' "$RUNNER" || true)
if [[ "$clam_calls" -eq 2 ]]; then
  _pass "both ClamAV docker calls request the platform"
else
  _fail "both ClamAV docker calls request the platform" "found $clam_calls of 2"
fi

echo "=== Group 7: Gate verdict line ==="

# The scan verdict was gate-line.sh; it is core/run scan-verdict now. Every assertion below is
# unchanged and runs against the Python port.
GL="$PROJECT_ROOT/core/run"
check_executable "core/run (scan-verdict) exists" "$GL"
check_makefile_target "gate-scan"

# gate_verdict <label> <fixture> <expect PASS|FAIL> [extra-grep]
gate_verdict() {
  local label="$1" fixture="$2" expect="$3" extra="${4:-}"
  local dir out code
  dir=$(mktemp -d)
  cp "$FIXTURE_DIR/$fixture/"* "$dir/" 2>/dev/null
  SCAN_RESULTS_DIR="$dir" OUTPUT_DIR="$dir" "$SCAN_DIR/generate-dispatch.sh" >/dev/null 2>&1 || true
  out=$(SCAN_RESULTS_DIR="$dir" "$GL" scan-verdict 2>&1) && code=0 || code=1

  if grep -q "Scan: $expect" <<<"$out"; then
    _pass "Gate verdict [$label] = $expect"
  else
    _fail "Gate verdict [$label] = $expect" "got: $out"
  fi
  if [[ "$expect" == "PASS" && $code -ne 0 ]] || [[ "$expect" == "FAIL" && $code -eq 0 ]]; then
    _fail "Gate verdict [$label] exit code matches verdict" "verdict $expect but exit $code"
  else
    _pass "Gate verdict [$label] exit code matches verdict"
  fi
  if [[ -n "$extra" ]]; then
    if grep -q "$extra" <<<"$out"; then
      _pass "Gate verdict [$label] reports '$extra'"
    else
      _fail "Gate verdict [$label] reports '$extra'" "got: $out"
    fi
  fi
  rm -rf "$dir"
}

gate_verdict "clean"     "clean"          "PASS"
gate_verdict "fixable"   "frank-findings" "FAIL"

# The distinction the gate exists to make. scan-severity.sh fails on any HIGH/CRITICAL, which is
# right for the nightly and wrong here: a CVE with no upstream fix would hold an epic hostage to
# someone else's release schedule. It must be recorded and carried, not blocking.
gate_verdict "poam only" "poam-only"      "PASS" "POAM candidate"

# A High from npm audit with no allowlist entry is fixable work, so the verdict is FAIL and the
# dispatch block counts as fixable. Moderate/Low in the same fixture change nothing.
gate_verdict "npm audit blocking" "npm-audit-blocking" "FAIL" "1 fixable"

# eslint messages are fixable work, one block per file: two messages in two files → 2 fixable.
gate_verdict "eslint findings" "eslint-findings" "FAIL" "2 fixable"
gate_verdict "checkov unrated" "checkov-null-severity" "FAIL" "1 fixable"
gate_verdict "clean counts seven" "clean" "PASS" "7/7 scanners"

es_missing_dir=$(mktemp -d)
cp "$FIXTURE_DIR/clean/"* "$es_missing_dir/" 2>/dev/null
rm -f "$es_missing_dir/eslint.json"
es_ms_out=$(SCAN_RESULTS_DIR="$es_missing_dir" "$GL" scan-verdict 2>&1) || true
if grep -q "Scan: FAIL" <<<"$es_ms_out" && grep -q "eslint" <<<"$es_ms_out"; then
  _pass "Gate verdict: a missing eslint result is FAIL and is named"
else
  _fail "Gate verdict: a missing eslint result is FAIL and is named" "got: $es_ms_out"
fi
rm -rf "$es_missing_dir"

# The sixth scanner is missing → FAIL, and the line names it.
na_missing_dir=$(mktemp -d)
cp "$FIXTURE_DIR/clean/"* "$na_missing_dir/" 2>/dev/null
rm -f "$na_missing_dir/audit.json"
na_ms_out=$(SCAN_RESULTS_DIR="$na_missing_dir" "$GL" scan-verdict 2>&1) || true
if grep -q "Scan: FAIL" <<<"$na_ms_out" && grep -q "npm-audit" <<<"$na_ms_out"; then
  _pass "Gate verdict: a missing npm audit result is FAIL and is named"
else
  _fail "Gate verdict: a missing npm audit result is FAIL and is named" "got: $na_ms_out"
fi
rm -rf "$na_missing_dir"

# A partial scan reporting no findings is indistinguishable from a clean one.
missing_scanner_dir=$(mktemp -d)
cp "$FIXTURE_DIR/clean/"* "$missing_scanner_dir/" 2>/dev/null
rm -f "$missing_scanner_dir/trivy.json"
ms_out=$(SCAN_RESULTS_DIR="$missing_scanner_dir" "$GL" scan-verdict 2>&1) || true
if grep -q "Scan: FAIL" <<<"$ms_out" && grep -q "trivy" <<<"$ms_out"; then
  _pass "Gate verdict: a scanner that did not run is FAIL and is named"
else
  _fail "Gate verdict: a scanner that did not run is FAIL and is named" "got: $ms_out"
fi
rm -rf "$missing_scanner_dir"

# ClamAV writes its block as '## ', not '### ', so counting only '### ' reported a malware-only run
# as zero findings. The verdict must not depend on that heading level.
eicar_dir=$(mktemp -d)
cp "$FIXTURE_DIR/clean/"* "$eicar_dir/" 2>/dev/null
printf '/src/nasty.bin: Eicar-Test-Signature FOUND\n\n----------- SCAN SUMMARY -----------\nInfected files: 1\n' \
  > "$eicar_dir/clamav.log"
SCAN_RESULTS_DIR="$eicar_dir" OUTPUT_DIR="$eicar_dir" "$SCAN_DIR/generate-dispatch.sh" >/dev/null 2>&1 || true
mw_out=$(SCAN_RESULTS_DIR="$eicar_dir" "$GL" scan-verdict 2>&1) || true
if grep -q "Scan: FAIL" <<<"$mw_out" && grep -q "MALWARE DETECTED" <<<"$mw_out"; then
  _pass "Gate verdict: a ClamAV hit is FAIL and says MALWARE DETECTED"
else
  _fail "Gate verdict: a ClamAV hit is FAIL and says MALWARE DETECTED" "got: $mw_out"
fi
rm -rf "$eicar_dir"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 9: npm audit runner (fake npm, real policy) ==="

# run-npm-audit.sh applies DEPENDENCY_POLICY rules 3 and 7 itself; these cases pin each branch of
# that decision with a fake `npm` that prints a canned report, so no registry and no lockfile is
# needed. The report shapes are npm 7+ `npm audit --json`.
NA="$SCAN_DIR/run-npm-audit.sh"
check_executable "run-npm-audit.sh exists and is executable" "$NA"

na_fixture() {   # na_fixture <canned stdout for npm>  → prints the fixture root
  local root; root=$(mktemp -d)
  mkdir -p "$root/bin" "$root/backend" "$root/frontend" "$root/results"
  printf '{}\n' > "$root/backend/package-lock.json"
  printf '{}\n' > "$root/frontend/package-lock.json"
  printf '%s' "$1" > "$root/canned"
  cat > "$root/bin/npm" <<'FAKE'
#!/usr/bin/env bash
cat "$FAKE_CANNED"
exit 1
FAKE
  chmod +x "$root/bin/npm"
  printf '%s' "$root"
}
na_run() {   # na_run <root> [allowlist file] → sets NA_RC (exit code) and NA_OUT (output).
             # Not a command substitution: that would run in a subshell and lose both.
  local root="$1" allow="${2:-$1/no-such-allowlist.yaml}"
  NA_RC=0
  NA_OUT=$(FAKE_CANNED="$root/canned" PATH="$root/bin:$PATH" NPM_AUDIT_ROOT="$root" \
           SCAN_RESULTS_DIR="$root/results" NPM_AUDIT_ALLOWLIST="$allow" bash "$NA" 2>&1) || NA_RC=$?
}
NA_HIGH='{"vulnerabilities":{"vite":{"name":"vite","severity":"high","isDirect":true,"via":[{"source":1,"name":"vite","dependency":"vite","title":"fixture high","url":"https://github.com/advisories/GHSA-fake-high-0001","severity":"high","range":"<=6.4.2"}],"effects":[],"range":"<=6.4.2","nodes":["node_modules/vite"],"fixAvailable":{"name":"vite","version":"8.3.0","isSemVerMajor":true}}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":1,"critical":0,"total":1}}}'
NA_MOD='{"vulnerabilities":{"esbuild":{"name":"esbuild","severity":"moderate","isDirect":false,"via":[{"source":2,"name":"esbuild","dependency":"esbuild","title":"fixture moderate","url":"https://github.com/advisories/GHSA-fake-mod-0002","severity":"moderate","range":"<=0.24.2"}],"effects":["vite"],"range":"<=0.24.2","nodes":["node_modules/esbuild"],"fixAvailable":true},"vite":{"name":"vite","severity":"moderate","isDirect":true,"via":["esbuild"],"effects":[],"range":"<=6.4.2","nodes":["node_modules/vite"],"fixAvailable":true}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":2,"high":0,"critical":0,"total":2}}}'
NA_CLEAN='{"vulnerabilities":{},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}'

# clean → PASS, audit.json written with an empty blocking list
root=$(na_fixture "$NA_CLEAN"); na_run "$root"; rc=$NA_RC
[[ "$rc" == 0 ]] && _pass "npm-audit: clean report exits 0" || _fail "npm-audit: clean report exits 0" "exit $rc: $NA_OUT"
[[ -s "$root/results/audit.json" && "$(jq '.blocking | length' "$root/results/audit.json")" == 0 ]] \
  && _pass "npm-audit: clean report writes audit.json with no blocking entries" \
  || _fail "npm-audit: clean report writes audit.json with no blocking entries" "missing or non-empty"
rm -rf "$root"

# high, no allowlist → FAIL, named, counted per app (the fake answers for both apps)
root=$(na_fixture "$NA_HIGH"); na_run "$root"; rc=$NA_RC
[[ "$rc" == 1 ]] && _pass "npm-audit: a High with no allowlist entry exits 1" || _fail "npm-audit: a High with no allowlist entry exits 1" "exit $rc"
if grep -q "BLOCKING.*GHSA-fake-high-0001" <<<"$NA_OUT"; then _pass "npm-audit: the blocking advisory is named"; else _fail "npm-audit: the blocking advisory is named" "got: $NA_OUT"; fi
[[ "$(jq '.blocking | length' "$root/results/audit.json")" == 2 ]] \
  && _pass "npm-audit: blocking is counted once per app" \
  || _fail "npm-audit: blocking is counted once per app" "got $(jq '.blocking | length' "$root/results/audit.json")"
# …and the same High allowlisted with a future expiry → PASS
printf 'entries:\n  - id: GHSA-fake-high-0001\n    package: vite\n    reason: fixture\n    owner: test\n    expires: %s\n' "$DATE_SOON" > "$root/allow.yaml"
na_run "$root" "$root/allow.yaml"; rc=$NA_RC
[[ "$rc" == 0 ]] && _pass "npm-audit: an unexpired allowlist entry lifts the block" || _fail "npm-audit: an unexpired allowlist entry lifts the block" "exit $rc: $NA_OUT"
[[ "$(jq '.allowlisted | length' "$root/results/audit.json")" == 2 ]] \
  && _pass "npm-audit: the allowlisted advisory is recorded as allowlisted" \
  || _fail "npm-audit: the allowlisted advisory is recorded as allowlisted" "got $(jq '.allowlisted | length' "$root/results/audit.json")"
# …and the same entry expired → FAIL again, and the runner says the entry no longer counts
sed -i.bak "s/$DATE_SOON/2000-01-01/" "$root/allow.yaml"
na_run "$root" "$root/allow.yaml"; rc=$NA_RC
[[ "$rc" == 1 ]] && _pass "npm-audit: an expired allowlist entry suppresses nothing" || _fail "npm-audit: an expired allowlist entry suppresses nothing" "exit $rc"
if grep -qi "expired" <<<"$NA_OUT"; then _pass "npm-audit: an expired entry is called out"; else _fail "npm-audit: an expired entry is called out" "got: $NA_OUT"; fi
rm -rf "$root"

# moderate only → PASS, reported, not blocking
root=$(na_fixture "$NA_MOD"); na_run "$root"; rc=$NA_RC
[[ "$rc" == 0 ]] && _pass "npm-audit: Moderate alone exits 0" || _fail "npm-audit: Moderate alone exits 0" "exit $rc: $NA_OUT"
if grep -q "reported.*GHSA-fake-mod-0002" <<<"$NA_OUT"; then _pass "npm-audit: Moderate is reported by id"; else _fail "npm-audit: Moderate is reported by id" "got: $NA_OUT"; fi
rm -rf "$root"

# npm prints something that is not a report → the scanner did not run: exit 1, no audit.json
root=$(na_fixture "npm ERR! network request to https://registry failed"); na_run "$root"; rc=$NA_RC
[[ "$rc" == 1 ]] && _pass "npm-audit: an unparseable report exits 1" || _fail "npm-audit: an unparseable report exits 1" "exit $rc"
if grep -q "did not run" <<<"$NA_OUT"; then _pass "npm-audit: …and says the scanner did not run"; else _fail "npm-audit: …and says the scanner did not run" "got: $NA_OUT"; fi
[[ ! -f "$root/results/audit.json" ]] && _pass "npm-audit: …and writes no audit.json" || _fail "npm-audit: …and writes no audit.json" "audit.json exists"
rm -rf "$root"

# a package.json with no lockfile anywhere → not a pass (an app with no lockfile is not an empty scope;
# no app dir at all is a declared empty scope, tested with the T7 cases)
root=$(na_fixture "$NA_CLEAN"); rm -f "$root/backend/package-lock.json" "$root/frontend/package-lock.json"; printf '{"name":"x"}\n' > "$root/backend/package.json"; na_run "$root"; rc=$NA_RC
[[ "$rc" == 1 ]] && _pass "npm-audit: no lockfile anywhere exits 1" || _fail "npm-audit: no lockfile anywhere exits 1" "exit $rc"
rm -rf "$root"

# The runner must never rewrite the tree it audits.
# Was `grep -q ... | grep -v '^#'`: `grep -q` writes nothing, so the second grep always exited 1 and
# the assertion always passed. Both gates caught it (SEC-SC-5 / QG-SC-N1). Strip comments FIRST,
# then search what is left — and prove the new form can fail, since a guard nobody has seen go red
# is the exact defect being fixed here.
na_calls_fix() { grep -vE '^[[:space:]]*#' "$1" | grep -E 'audit[[:space:]]+fix' >/dev/null; }
if na_calls_fix "$NA"; then
  _fail "npm-audit: runner never calls npm audit fix" "found an audit fix call outside a comment"
else
  _pass "npm-audit: runner never calls npm audit fix"
fi
na_canary=$(mktemp); { cat "$NA"; echo 'npm audit fix'; } > "$na_canary"
if na_calls_fix "$na_canary"; then
  _pass "npm-audit: …and that check detects one when it is there"
else
  _fail "npm-audit: …and that check detects one when it is there" "a planted 'npm audit fix' was not seen"
fi
rm -f "$na_canary"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 10: eslint runner (fake npx, real policy) ==="

ES="$SCAN_DIR/run-eslint.sh"
check_executable "run-eslint.sh exists and is executable" "$ES"

es_fixture() {   # es_fixture <canned stdout for npx> <npx exit code> → prints the fixture root
  local root; root=$(mktemp -d)
  mkdir -p "$root/bin" "$root/backend/node_modules" "$root/frontend/node_modules" "$root/results"
  printf '{"scripts":{"lint":"eslint src --ext .ts --max-warnings 0"}}\n' > "$root/backend/package.json"
  printf '{"scripts":{"lint":"eslint . --max-warnings 0"}}\n' > "$root/frontend/package.json"
  printf '%s' "$1" > "$root/canned"; printf '%s' "$2" > "$root/canned.rc"
  cat > "$root/bin/npx" <<'FAKE'
#!/usr/bin/env bash
cat "$FAKE_CANNED"
exit "$(cat "$FAKE_CANNED.rc")"
FAKE
  chmod +x "$root/bin/npx"
  printf '%s' "$root"
}
es_run() {   # es_run <root> → sets ES_RC and ES_OUT (no command substitution: a subshell would lose them)
  local root="$1"
  ES_RC=0
  ES_OUT=$(FAKE_CANNED="$root/canned" PATH="$root/bin:$PATH" ESLINT_ROOT="$root" \
           SCAN_RESULTS_DIR="$root/results" bash "$ES" 2>&1) || ES_RC=$?
}
ES_CLEAN='[{"filePath":"/x/src/a.ts","messages":[],"errorCount":0,"warningCount":0}]'
ES_ERR='[{"filePath":"/x/src/a.ts","messages":[{"ruleId":"no-undef","severity":2,"message":"fixture: foo is not defined","line":4,"column":3}],"errorCount":1,"warningCount":0}]'
ES_WARN='[{"filePath":"/x/src/a.ts","messages":[{"ruleId":"no-unused-vars","severity":1,"message":"fixture: x is defined but never used","line":9,"column":1}],"errorCount":0,"warningCount":1}]'

root=$(es_fixture "$ES_CLEAN" 0); es_run "$root"
[[ "$ES_RC" == 0 ]] && _pass "eslint: clean report exits 0" || _fail "eslint: clean report exits 0" "exit $ES_RC: $ES_OUT"
[[ -s "$root/results/eslint.json" && "$(jq '.blocking | length' "$root/results/eslint.json")" == 0 ]] \
  && _pass "eslint: clean report writes eslint.json with no blocking entries" \
  || _fail "eslint: clean report writes eslint.json with no blocking entries" "missing or non-empty"
rm -rf "$root"

root=$(es_fixture "$ES_ERR" 1); es_run "$root"
[[ "$ES_RC" == 1 ]] && _pass "eslint: an error exits 1" || _fail "eslint: an error exits 1" "exit $ES_RC"
if grep -q "BLOCKING.*no-undef" <<<"$ES_OUT"; then _pass "eslint: the message is named by rule"; else _fail "eslint: the message is named by rule" "got: $ES_OUT"; fi
rm -rf "$root"

# A warning is a failure: both apps lint with --max-warnings 0, and the runner must not soften that.
root=$(es_fixture "$ES_WARN" 1); es_run "$root"
[[ "$ES_RC" == 1 ]] && _pass "eslint: a warning alone exits 1 (max-warnings 0)" || _fail "eslint: a warning alone exits 1 (max-warnings 0)" "exit $ES_RC"
rm -rf "$root"

# eslint crashed (exit 2, no report) → did not run, no decision file.
root=$(es_fixture "Oops! Something went wrong! :(" 2); es_run "$root"
[[ "$ES_RC" == 1 ]] && _pass "eslint: a crash (exit 2) exits 1" || _fail "eslint: a crash (exit 2) exits 1" "exit $ES_RC"
if grep -q "did not run" <<<"$ES_OUT"; then _pass "eslint: …and says the scanner did not run"; else _fail "eslint: …and says the scanner did not run" "got: $ES_OUT"; fi
[[ ! -f "$root/results/eslint.json" ]] && _pass "eslint: …and writes no eslint.json" || _fail "eslint: …and writes no eslint.json" "eslint.json exists"
rm -rf "$root"

# No node_modules is a setup error on a gate host, never a skip.
root=$(es_fixture "$ES_CLEAN" 0); rm -rf "$root/frontend/node_modules"; es_run "$root"
[[ "$ES_RC" == 1 ]] && _pass "eslint: an app without node_modules fails rather than skips" || _fail "eslint: an app without node_modules fails rather than skips" "exit $ES_RC"
if grep -q "SKIPPED" <<<"$ES_OUT"; then _fail "eslint: never prints SKIPPED" "printed SKIPPED"; else _pass "eslint: never prints SKIPPED"; fi
rm -rf "$root"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 11: hadolint honours .hadolint.yaml ==="

# Until 2026-09-23 the config said `ignore:`; hadolint reads `ignored:` and silently applied
# nothing, so DL3018 (apk pins, ignored on purpose because Wolfi prunes old versions) showed up in
# every scan. Lint a fixture Dockerfile that trips DL3018 and DL3007 with the repo's config: both
# must be absent, and a rule the config does not mention must still be reported.
if ! have_tool hadolint; then
  _skip "hadolint config: ignored rules are absent" "no hadolint and no Docker ($(scan_engine) engine)"
else
  hl_dir=$(mktemp -d)
  printf 'FROM alpine:latest\nRUN apk add curl\nRUN apk add --no-cache git\nMAINTAINER nobody\n' > "$hl_dir/Dockerfile"
  hl_out=$(cd "$PROJECT_ROOT" && tool_hadolint --config .hadolint.yaml --format json "$(realpath --relative-to="$PROJECT_ROOT" "$hl_dir" 2>/dev/null || echo "$hl_dir")/Dockerfile" 2>/dev/null) || true
  # realpath --relative-to is GNU; when the fixture is outside the mounted tree (container engine)
  # fall back to a fixture inside the repo, removed right after.
  if ! printf '%s' "$hl_out" | jq -e 'type == "array"' >/dev/null 2>&1; then
    mkdir -p "$PROJECT_ROOT/.hadolint-selftest"
    cp "$hl_dir/Dockerfile" "$PROJECT_ROOT/.hadolint-selftest/Dockerfile"
    hl_out=$(cd "$PROJECT_ROOT" && tool_hadolint --config .hadolint.yaml --format json .hadolint-selftest/Dockerfile 2>/dev/null) || true
    rm -rf "$PROJECT_ROOT/.hadolint-selftest"
  fi
  hl_codes=$(printf '%s' "$hl_out" | jq -r '.[].code' 2>/dev/null | sort -u | tr '\n' ' ')
  case " $hl_codes " in
    *" DL3018 "*) _fail "hadolint config: DL3018 is ignored" "DL3018 reported — the ignore list is not being read (key must be 'ignored:')" ;;
    *)            _pass "hadolint config: DL3018 is ignored" ;;
  esac
  case " $hl_codes " in
    *" DL3007 "*) _fail "hadolint config: DL3007 is ignored" "DL3007 reported" ;;
    *)            _pass "hadolint config: DL3007 is ignored" ;;
  esac
  case " $hl_codes " in
    *" DL4000 "*) _pass "hadolint config: an unlisted rule (DL4000 MAINTAINER) is still reported" ;;
    *)            _fail "hadolint config: an unlisted rule (DL4000 MAINTAINER) is still reported" "codes seen: '$hl_codes' — did hadolint run at all?" ;;
  esac
  rm -rf "$hl_dir"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 12: nightly cannot be green without a scan (T-024) ==="

# pull-images.sh: one pull per scanner image, ClamAV with its platform, a failed pull fails the
# script. Driven by a fake docker on PATH that answers `info` and records every `pull`.
PI="$SCAN_DIR/pull-images.sh"
pi_root=$(mktemp -d); mkdir -p "$pi_root/bin"
cat > "$pi_root/bin/docker" <<'FAKE'
#!/usr/bin/env bash
case "$1" in
  info) exit 0 ;;
  pull) echo "$*" >> "$FAKE_PULLS"; [ "${FAKE_PULL_FAIL:-0}" = 1 ] && { echo "toomanyrequests: rate limited" >&2; exit 1; }; exit 0 ;;
  image) [ "${FAKE_PRESENT:-0}" = 1 ] && exit 0; exit 1 ;;
  *) exit 0 ;;
esac
FAKE
chmod +x "$pi_root/bin/docker"
pi_rc=0; pi_out=$(FAKE_PULLS="$pi_root/pulls" PATH="$pi_root/bin:$PATH" SCAN_ENGINE=container bash "$PI" 2>&1) || pi_rc=$?
[[ "$pi_rc" == 0 ]] && _pass "pull-images: exits 0 when every pull succeeds" || _fail "pull-images: exits 0 when every pull succeeds" "exit $pi_rc: $pi_out"
[[ "$(wc -l < "$pi_root/pulls" | tr -d ' ')" == 5 ]] && _pass "pull-images: pulls all five scanner images" || _fail "pull-images: pulls all five scanner images" "$(cat "$pi_root/pulls")"
grep -q -- '--platform linux/amd64.*clamav' "$pi_root/pulls" && _pass "pull-images: ClamAV is pulled for its platform" || _fail "pull-images: ClamAV is pulled for its platform" "$(grep clamav "$pi_root/pulls")"
rm -f "$pi_root/pulls"
pi_rc=0; pi_out=$(FAKE_PULLS="$pi_root/pulls" FAKE_PULL_FAIL=1 PATH="$pi_root/bin:$PATH" SCAN_ENGINE=container bash "$PI" 2>&1) || pi_rc=$?
[[ "$pi_rc" == 1 ]] && _pass "pull-images: a failed pull exits 1" || _fail "pull-images: a failed pull exits 1" "exit $pi_rc"
# A registry that refuses a fresh pull (a rate limit, an outage) of a pinned image already on disk
# is not a missing scanner: the scan continues on the local copy and says so, by name.
pi_rc=0; pi_out=$(FAKE_PULLS="$pi_root/pulls" FAKE_PULL_FAIL=1 FAKE_PRESENT=1 PATH="$pi_root/bin:$PATH" SCAN_ENGINE=container bash "$PI" 2>&1) || pi_rc=$?
if [[ "$pi_rc" == 0 ]] && grep -q 'present locally' <<<"$pi_out"; then
  _pass "pull-images: a refused pull of an image present locally continues and says so"
else
  _fail "pull-images: a refused pull of an image present locally continues and says so" "exit $pi_rc: $pi_out"
fi
pi_rc=0; pi_out=$(SCAN_ENGINE=native bash "$PI" 2>&1) || pi_rc=$?
[[ "$pi_rc" == 0 ]] && _pass "pull-images: native engine has nothing to pull and exits 0" || _fail "pull-images: native engine has nothing to pull and exits 0" "exit $pi_rc: $pi_out"
rm -rf "$pi_root"

# The Makefile pulls before it scans.
for t in scan scan-lite gate-scan; do
  if awk -v t="$t" '$0 ~ "^"t":"{p=1;next} /^[a-zA-Z_-]+:/{p=0} p' "$PROJECT_ROOT/Makefile" | grep 'pull-images.sh' >/dev/null; then
    _pass "$t pulls scanner images first"
  else
    _fail "$t pulls scanner images first" "recipe does not call pull-images.sh"
  fi
done

# scan-severity: no results is not a pass.
ss_dir=$(mktemp -d)
ss_rc=0; SCAN_RESULTS_DIR="$ss_dir" bash "$SCAN_DIR/scan-severity.sh" >/dev/null 2>&1 || ss_rc=$?
[[ "$ss_rc" == 1 ]] && _pass "scan-severity: an empty results dir exits 1" || _fail "scan-severity: an empty results dir exits 1" "exit $ss_rc"
rm -rf "$ss_dir"

# The nightly workflow runs the gate scan, unswallowed, after installing both apps for eslint.
#
# LOCAL CHANGE — T-ENGINE-18 (2026-10-10); `make sync-engine` will revert it until the
# engine carries it. A project may run no GitHub Actions at all: this one scans and gates in the
# harness and pushes on green (`make gate-prompt` already refuses a handoff unless `make gate-scan`
# is green on the commit), so the workflow is absent by decision, not by accident. The three
# assertions below are about the file's CONTENT and still run when it is present; its ABSENCE is a
# skip, because an engine self-test must not fail a project for declining a scheduled runner it
# has no account for. What this group's name promises — "nightly cannot be green without a scan" —
# is kept by the gate-scan precondition when there is no nightly.
NW="$PROJECT_ROOT/.github/workflows/nightly-scan.yml"
if [[ -f "$NW" ]]; then
  grep -qE '^\s+run: make gate-scan\s*$' "$NW" && _pass "nightly: runs make gate-scan" || _fail "nightly: runs make gate-scan" "no 'run: make gate-scan' line"
  # Only `run:` lines count — the file's own comment quotes the old `make scan || true` to explain it.
  if grep -E '^\s+run: make (scan|gate-scan)\b' "$NW" | grep '|| true' >/dev/null; then _fail "nightly: the scan exit is not swallowed" "found '|| true' on the scan run line"; else _pass "nightly: the scan exit is not swallowed"; fi
  grep -q 'cd frontend && npm ci' "$NW" && grep -q 'cd backend && npm ci' "$NW" && _pass "nightly: installs both apps for the eslint runner" || _fail "nightly: installs both apps for the eslint runner" "an npm ci step is missing"
else
  _skip "nightly: workflow file exists" "no GitHub Actions in this project (T-ENGINE-18); the scan runs before the gate in the harness"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 13: checkov decides on every failed check (T-023) ==="

CD="$SCAN_DIR/checkov-decide.sh"
check_executable "checkov-decide.sh exists and is executable" "$CD"
cd_fixture() { local d; d=$(mktemp -d); cp "$FIXTURE_DIR/checkov-null-severity/checkov.json" "$d/checkov.json"; printf '%s' "$d"; }
cd_run() {   # cd_run <dir> [justification file] → CD_RC, CD_OUT
  local d="$1" j="${2:-$1/no-such-file.yaml}"; CD_RC=0
  CD_OUT=$(CHECKOV_JUSTIFICATIONS="$j" bash "$CD" "$d/checkov.json" 2>&1) || CD_RC=$?
}
cd_just() {   # cd_just <dir> <path glob> <expires>
  printf 'entries:\n  - check_id: CKV_K8S_21\n    path: %s\n    reason: fixture\n    owner: test\n    expires: %s\n' "$2" "$3" > "$1/j.yaml"
}

d=$(cd_fixture); cd_run "$d"
[[ "$CD_RC" == 1 ]] && _pass "checkov-decide: an unrated failed check with no justification exits 1" || _fail "checkov-decide: an unrated failed check with no justification exits 1" "exit $CD_RC: $CD_OUT"
if grep -q "BLOCKING.*CKV_K8S_21" <<<"$CD_OUT"; then _pass "checkov-decide: the blocking check is named"; else _fail "checkov-decide: the blocking check is named" "got: $CD_OUT"; fi
rm -rf "$d"

d=$(cd_fixture); cd_just "$d" '/fixture/templates/*.yaml' "$DATE_SOON"; cd_run "$d" "$d/j.yaml"
[[ "$CD_RC" == 0 ]] && _pass "checkov-decide: a matching unexpired justification exits 0" || _fail "checkov-decide: a matching unexpired justification exits 0" "exit $CD_RC: $CD_OUT"
[[ "$(jq '.results.justified_checks | length' "$d/checkov.json")" == 1 && "$(jq '.results.failed_checks | length' "$d/checkov.json")" == 0 ]] \
  && _pass "checkov-decide: the justified check moves out of failed_checks" \
  || _fail "checkov-decide: the justified check moves out of failed_checks" "$(jq -c '.summary' "$d/checkov.json")"
rm -rf "$d"

d=$(cd_fixture); cd_just "$d" '/other/templates/*.yaml' "$DATE_SOON"; cd_run "$d" "$d/j.yaml"
[[ "$CD_RC" == 1 ]] && _pass "checkov-decide: a justification for another path does not apply" || _fail "checkov-decide: a justification for another path does not apply" "exit $CD_RC"
rm -rf "$d"

d=$(cd_fixture); cd_just "$d" '/fixture/templates/*.yaml' 2000-01-01; cd_run "$d" "$d/j.yaml"
[[ "$CD_RC" == 1 ]] && _pass "checkov-decide: an expired justification justifies nothing" || _fail "checkov-decide: an expired justification justifies nothing" "exit $CD_RC"
if grep -qi "expired" <<<"$CD_OUT"; then _pass "checkov-decide: the expired entry is called out"; else _fail "checkov-decide: the expired entry is called out" "got: $CD_OUT"; fi
rm -rf "$d"

# The justification list is the scanned repository's (PROJECT_ROOT), never the bot install's own.
d=$(cd_fixture); mkdir -p "$d/docs/security"; cd_just "$d" '/fixture/templates/*.yaml' "$DATE_SOON"; mv "$d/j.yaml" "$d/docs/security/checkov-justifications.yaml"
CD_RC=0; CD_OUT=$(env -u CHECKOV_JUSTIFICATIONS PROJECT_ROOT="$d" bash "$CD" "$d/checkov.json" 2>&1) || CD_RC=$?
if [[ "$CD_RC" == 0 ]]; then _pass "checkov-decide: reads the justification list of the repository PROJECT_ROOT names"
else _fail "checkov-decide: reads the justification list of the repository PROJECT_ROOT names" "exit $CD_RC: $CD_OUT"; fi
rm -rf "$d"

d=$(mktemp -d); printf 'not json' > "$d/checkov.json"; cd_run "$d"
[[ "$CD_RC" == 1 ]] && _pass "checkov-decide: unreadable results exit 1" || _fail "checkov-decide: unreadable results exit 1" "exit $CD_RC"
rm -rf "$d"

# The runner must call the decision and must no longer filter on a severity checkov does not emit.
grep -q 'checkov-decide.sh' "$SCAN_DIR/run-checkov.sh" && _pass "run-checkov.sh calls checkov-decide.sh" || _fail "run-checkov.sh calls checkov-decide.sh" "no call found"
grep -qE 'severity == "HIGH"' "$SCAN_DIR/run-checkov.sh" && _fail "run-checkov.sh no longer decides on severity" "HIGH/CRITICAL filter still present" || _pass "run-checkov.sh no longer decides on severity"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 14: an unreadable result is not a clean result (T-029 / SEC-SC-2) ==="

# The 2026-09-23 nightly was green with no working scanner because docker pull text landed in
# hadolint.json. T-024 closed that source; this closes the DETECTION: whatever puts garbage in a
# result file, the verdict must refuse to count that scanner. The existing "did not run" case
# covers an ABSENT file only — a present-but-unreadable one used to read as 7/7 PASS.
polluted_case() {   # polluted_case <label> <result file> <how to break it: prepend|truncate>
  local label="$1" file="$2" how="$3" dir out rc=0
  dir=$(mktemp -d); cp "$FIXTURE_DIR/clean/"* "$dir/" 2>/dev/null
  case "$how" in
    prepend) { printf 'Unable to find image locally\nlatest: Pulling from a/b\n9621f1afde84: Pulling fs layer\n'; cat "$FIXTURE_DIR/clean/$file"; } > "$dir/$file" ;;
    truncate) printf '\n----------- SCAN SUMMARY -----------\nKnown viruses: 3628071\n' > "$dir/$file" ;;
  esac
  out=$(SCAN_RESULTS_DIR="$dir" "$GL" scan-verdict 2>&1) || rc=$?
  if grep -q "Scan: FAIL" <<<"$out" && grep -q "$label" <<<"$out" && [ "$rc" -ne 0 ]; then
    _pass "unreadable $file → FAIL, $label named, rc $rc"
  else
    _fail "unreadable $file → FAIL, $label named" "rc $rc · got: $out"
  fi
  rm -rf "$dir"
}
# Every JSON result in the SCANNERS list, not just hadolint: any of them can be polluted the same way.
polluted_case hadolint  hadolint.json prepend
polluted_case checkov   checkov.json  prepend
polluted_case grype     grype.json    prepend
polluted_case trivy     trivy.json    prepend
polluted_case npm-audit audit.json    prepend
polluted_case eslint    eslint.json   prepend
# ClamAV's log is not JSON; its summary line is its proof of completion.
polluted_case clamav    clamav.log    truncate

# The other half: a runner's own guard must take its unreadable file out of the results directory,
# keeping it under a name nothing reads, so the verdict is not relying on gate-line alone.
cj_dir=$(mktemp -d); printf 'Pulling from a/b\n[]\n' > "$cj_dir/hadolint.json"
( . "$SCAN_DIR/tool-runner.sh" >/dev/null 2>&1; count_json "$cj_dir/hadolint.json" 'length' hadolint ) >/dev/null 2>&1
if [[ ! -f "$cj_dir/hadolint.json" && -f "$cj_dir/hadolint.json.unparseable" ]]; then
  _pass "count_json moves an unparseable result aside and keeps it"
else
  _fail "count_json moves an unparseable result aside and keeps it" "$(ls "$cj_dir")"
fi
rm -rf "$cj_dir"

# A read must not write. `make scan-verdict` re-stamped with whatever commit was checked out, so a
# commit nothing had scanned could satisfy scan-precondition (SEC-SC-3, observed live at a gate).
st_dir=$(mktemp -d); cp "$FIXTURE_DIR/clean/"* "$st_dir/" 2>/dev/null
printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef PASS 2026-01-01T00:00:00Z\n' > "$st_dir/.scan-stamp"
SCAN_RESULTS_DIR="$st_dir" "$GL" scan-verdict >/dev/null 2>&1 || true
if grep -q '^deadbeef' "$st_dir/.scan-stamp"; then
  _pass "gate-line leaves the stamp alone when it is only reading"
else
  _fail "gate-line leaves the stamp alone when it is only reading" "stamp now: $(cat "$st_dir/.scan-stamp")"
fi
GATE_LINE_STAMP=1 SCAN_RESULTS_DIR="$st_dir" "$GL" scan-verdict >/dev/null 2>&1 || true
if ! grep -q '^deadbeef' "$st_dir/.scan-stamp"; then
  _pass "…and writes it when the caller actually scanned"
else
  _fail "…and writes it when the caller actually scanned" "stamp unchanged: $(cat "$st_dir/.scan-stamp")"
fi
rm -rf "$st_dir"

# A failed image pull means no scan is possible, so gate-scan must not swallow it.
if awk '/^gate-scan:/{p=1;next} /^[a-zA-Z_-]+:/{p=0} p' "$PROJECT_ROOT/Makefile" | grep 'pull-images.sh.*|| true' >/dev/null; then
  _fail "gate-scan does not swallow a failed image pull" "pull-images.sh still runs under || true"
else
  _pass "gate-scan does not swallow a failed image pull"
fi
# …and only the scanning target stamps.
if awk '/^gate-scan:/{p=1;next} /^[a-zA-Z_-]+:/{p=0} p' "$PROJECT_ROOT/Makefile" | grep 'GATE_LINE_STAMP=1' >/dev/null; then
  _pass "gate-scan stamps the commit it scanned"
else
  _fail "gate-scan stamps the commit it scanned" "no GATE_LINE_STAMP=1 in the recipe"
fi
if awk '/^scan-verdict:/{p=1;next} /^[a-zA-Z_-]+:/{p=0} p' "$PROJECT_ROOT/Makefile" | grep 'GATE_LINE_STAMP' >/dev/null; then
  _fail "scan-verdict does not stamp" "GATE_LINE_STAMP set in a read-only target"
else
  _pass "scan-verdict does not stamp"
fi

# A date neither list can read must suppress nothing: until 2026-09-24 `expires: soon` compared
# lexically as later than today and lifted the block, so an unreadable date was a suppression.
root=$(na_fixture "$NA_HIGH")
for pair in "2999-13-45:not a real date" "soon:not a date at all"; do
  d="${pair%%:*}"; why="${pair#*:}"
  printf 'entries:\n  - id: GHSA-fake-high-0001\n    package: vite\n    reason: fixture\n    owner: test\n    expires: %s\n' "$d" > "$root/allow.yaml"
  na_run "$root" "$root/allow.yaml"; rc=$NA_RC
  [[ "$rc" == 1 ]] && _pass "npm-audit: an expiry $why suppresses nothing" || _fail "npm-audit: an expiry $why suppresses nothing" "exit $rc"
done
printf 'entries:\n  - id: GHSA-fake-high-0001\n    package: vite\n    reason: fixture\n    owner: test\n    expires: %s\n' "$DATE_SOON" > "$root/allow.yaml"
na_run "$root" "$root/allow.yaml"; rc=$NA_RC
[[ "$rc" == 0 ]] && _pass "npm-audit: a readable future date still lifts the block" || _fail "npm-audit: a readable future date still lifts the block" "exit $rc: $NA_OUT"
rm -rf "$root"

d=$(cd_fixture)
printf 'entries:\n  - check_id: CKV_K8S_21\n    path: /fixture/templates/*.yaml\n    reason: fixture\n    owner: test\n    expires: soon\n' > "$d/j.yaml"
cd_run "$d" "$d/j.yaml"
[[ "$CD_RC" == 1 ]] && _pass "checkov: an expiry it cannot read justifies nothing" || _fail "checkov: an expiry it cannot read justifies nothing" "exit $CD_RC"
printf 'entries:\n  - check_id: CKV_K8S_21\n    path: /fixture/templates/*.yaml\n    reason: fixture\n    owner: test\n    expires: %s\n' "$DATE_SOON" > "$d/j.yaml"
cd_run "$d" "$d/j.yaml"
[[ "$CD_RC" == 0 ]] && _pass "checkov: a readable future date still justifies" || _fail "checkov: a readable future date still justifies" "exit $CD_RC: $CD_OUT"
rm -rf "$d"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 15: a scanner that examined nothing is not a scanner that ran (SEC-SC2-1) ==="

# Four runners write a valid, EMPTY result when they find nothing to examine — hadolint with no
# Dockerfiles (exit 0), checkov with a missing target directory, grype and trivy with no image — so
# the file cannot distinguish "examined everything, found nothing" from "examined nothing". The
# verdict therefore reads each runner's own receipt. Absent receipt = not counted.
SR="$SCAN_DIR/scan-receipt.sh"
check_executable "scan-receipt.sh exists and is executable" "$SR"

receipt_case() {   # receipt_case <scanner name>
  local name="$1" dir out rc=0
  dir=$(mktemp -d); cp "$FIXTURE_DIR/clean/"* "$dir/" 2>/dev/null
  grep -v "^${name} " "$dir/scanners-ran" > "$dir/scanners-ran.tmp" 2>/dev/null || : > "$dir/scanners-ran.tmp"
  mv "$dir/scanners-ran.tmp" "$dir/scanners-ran"
  out=$(SCAN_RESULTS_DIR="$dir" "$GL" scan-verdict 2>&1) || rc=$?
  if grep -q "Scan: FAIL" <<<"$out" && grep -q "did not run:.*$name" <<<"$out" && [ "$rc" -ne 0 ]; then
    _pass "no receipt from $name → FAIL, named, rc $rc (its result file is present and valid)"
  else
    _fail "no receipt from $name → FAIL, named" "rc $rc · got: $out"
  fi
  rm -rf "$dir"
}
# Every scanner in the list, not just the two the finding named: the property has to hold for all.
for n in hadolint checkov clamav grype trivy npm-audit eslint; do receipt_case "$n"; done

# A deliberate empty scope still counts — an Android project has no Dockerfiles — but is named, so
# "nothing to examine" never reaches a verdict unremarked.
dir=$(mktemp -d); cp "$FIXTURE_DIR/clean/"* "$dir/" 2>/dev/null
sed 's/^hadolint ran .*/hadolint none no Dockerfiles under backend\/ or frontend\//' "$dir/scanners-ran" > "$dir/sr.tmp" && mv "$dir/sr.tmp" "$dir/scanners-ran"
out=$(SCAN_RESULTS_DIR="$dir" "$GL" scan-verdict 2>&1); rc=$?
if grep -q "Scan: PASS" <<<"$out" && grep -q "7/7" <<<"$out" && grep -q "nothing in scope: hadolint" <<<"$out" && [ "$rc" -eq 0 ]; then
  _pass "a declared empty scope counts as ran and is named in the verdict"
else
  _fail "a declared empty scope counts as ran and is named in the verdict" "rc $rc · got: $out"
fi
rm -rf "$dir"

# The receipt is per-run: a crash must not leave the last run's receipt to be counted.
dir=$(mktemp -d)
( export SCAN_RECEIPT_DIR="$dir"; . "$SR"
  scan_ran grype "2 image(s)"; scan_ran trivy "2 image(s)"
  scan_begin grype )   # a new run starts; it has not earned a receipt yet
if [ "$(SCAN_RECEIPT_DIR="$dir" bash -c ". $SR; scan_receipt_kind grype")" = "" ] \
   && [ "$(SCAN_RECEIPT_DIR="$dir" bash -c ". $SR; scan_receipt_kind trivy")" = "ran" ]; then
  _pass "scan_begin drops only this scanner's stale receipt"
else
  _fail "scan_begin drops only this scanner's stale receipt" "$(cat "$dir/scanners-ran" 2>/dev/null)"
fi
rm -rf "$dir"

# Every runner must claim its receipt only on a success path, and clear it on entry.
for pair in "run-hadolint.sh:hadolint" "run-checkov.sh:checkov" "run-clamav.sh:clamav" \
            "run-grype.sh:grype" "run-trivy.sh:trivy" "run-npm-audit.sh:npm-audit" "run-eslint.sh:eslint"; do
  f="$SCAN_DIR/${pair%%:*}"; n="${pair#*:}"
  if grep -q "scan_begin $n" "$f"; then _pass "${pair%%:*} clears its receipt on entry"
  else _fail "${pair%%:*} clears its receipt on entry" "no scan_begin"; fi
  if grep -qE "scan_(ran|none) $n" "$f"; then _pass "${pair%%:*} claims a receipt"
  else _fail "${pair%%:*} claims a receipt" "no scan_ran/scan_none"; fi
done

# A runner that bails out before it can scan — tool missing, Docker down, jq absent — must still
# have dropped this run's receipt, or the verdict counts it on the strength of the PREVIOUS run and
# reads that run's result file as current. Every exit path in all seven runners is behind scan_begin.
for pair in "run-eslint.sh:eslint:ESLINT_NPX:ESLINT_ROOT" "run-npm-audit.sh:npm-audit:NPM_AUDIT_NPM:NPM_AUDIT_ROOT"; do
  IFS=: read -r f n var root_var <<< "$pair"
  dir=$(mktemp -d)
  # An app to scan, so the runner reaches the tool check this case is about (no app is an empty scope).
  app_root=$(mktemp -d); mkdir -p "$app_root/backend"; printf '{"name":"x","scripts":{"lint":"eslint ."}}\n' > "$app_root/backend/package.json"; printf '{}\n' > "$app_root/backend/package-lock.json"
  printf '%s ran 2 app(s)\ngrype ran 2 image(s)\n' "$n" > "$dir/scanners-ran"
  # SCAN_TRACK=web: on an android project both runners declare an empty scope before any tool check,
  # which is the right behaviour there and not the bail-out under test (seen running inside an ATAK repo).
  env "$var=definitely-not-on-this-path" "$root_var=$app_root" SCAN_TRACK=web SCAN_RESULTS_DIR="$dir" bash "$SCAN_DIR/$f" >/dev/null 2>&1
  e_rc=$?
  e_self=$(SCAN_RECEIPT_DIR="$dir" bash -c ". $SR; scan_receipt_kind $n")
  e_other=$(SCAN_RECEIPT_DIR="$dir" bash -c ". $SR; scan_receipt_kind grype")
  if [ "$e_rc" -ne 0 ] && [ -z "$e_self" ] && [ "$e_other" = ran ]; then
    _pass "$f bailing out early drops its own stale receipt and leaves others alone"
  else
    _fail "$f bailing out early drops its own stale receipt and leaves others alone" \
      "rc $e_rc · own '$e_self' · other '$e_other'"
  fi
  rm -rf "$dir"
done

# Every runner clears its receipt before any line that can exit, not merely somewhere in the file.
for pair in "run-hadolint.sh:hadolint" "run-checkov.sh:checkov" "run-clamav.sh:clamav" \
            "run-grype.sh:grype" "run-trivy.sh:trivy" "run-npm-audit.sh:npm-audit" "run-eslint.sh:eslint"; do
  f="$SCAN_DIR/${pair%%:*}"
  b_line=$(grep -n '^scan_begin' "$f" | head -1 | cut -d: -f1)
  early=$(awk -v b="${b_line:-0}" 'NR<b && $0 !~ /^[[:space:]]*#/ && /exit[[:space:]]+[0-9]/ {c++} END{print c+0}' "$f")
  if [ -n "$b_line" ] && [ "$early" -eq 0 ]; then
    _pass "${pair%%:*} clears its receipt before any exit path"
  else
    _fail "${pair%%:*} clears its receipt before any exit path" "scan_begin at line ${b_line:-none}, $early exit(s) above it"
  fi
done

# End to end, the finding's own reproduction: point an image scanner at an image that does not
# exist. It must leave no receipt, and must not overwrite a real previous result with an empty one.
# SCAN_TRACK=web: this is the image path. Inside an android project the runner would otherwise read
# APP_TRACK from the real project.config.yaml, scan android/ as a filesystem, exit 0 and claim a
# receipt, and the case fails for the wrong reason (seen on the first Safe House CI run, 2026-10-08).
if ! have_tool grype || ! command -v docker >/dev/null 2>&1; then
  _skip "grype scanning nothing leaves no receipt and no empty result" "docker unavailable"
else
  dir=$(mktemp -d); cp "$FIXTURE_DIR/clean/"* "$dir/" 2>/dev/null
  printf '{"matches":[{"vulnerability":{"id":"CVE-FIXTURE-1","severity":"High"},"artifact":{"name":"x","version":"1","type":"apk"}}]}\n' > "$dir/grype.json"
  SCAN_TRACK=web SCAN_RESULTS_DIR="$dir" SCAN_IMAGES="does-not-exist-fixture:nope" bash "$SCAN_DIR/run-grype.sh" >/dev/null 2>&1
  g_rc=$?
  g_kind=$(SCAN_RECEIPT_DIR="$dir" bash -c ". $SR; scan_receipt_kind grype")
  g_matches=$(jq '.matches | length' "$dir/grype.json" 2>/dev/null || echo ERR)
  g_out=$(SCAN_RESULTS_DIR="$dir" "$GL" scan-verdict 2>&1) || true
  [ "$g_rc" -ne 0 ] && _pass "grype scanning nothing exits non-zero" || _fail "grype scanning nothing exits non-zero" "rc 0"
  [ -z "$g_kind" ] && _pass "…leaves no receipt" || _fail "…leaves no receipt" "receipt kind '$g_kind'"
  [ "$g_matches" = 1 ] && _pass "…and does not overwrite the previous result with an empty one" \
    || _fail "…and does not overwrite the previous result with an empty one" "matches now $g_matches"
  grep -q "Scan: FAIL" <<<"$g_out" && grep -q "did not run:.*grype" <<<"$g_out" \
    && _pass "…so the verdict is FAIL and names grype" \
    || _fail "…so the verdict is FAIL and names grype" "got: $g_out"
  rm -rf "$dir"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 8: ClamAV signature freshness guard ==="

# The guard decides whether a scan is allowed to call itself clean, so its logic needs tests that
# are not at the mercy of what a real image happens to carry today. These drive run-clamav.sh under
# SCAN_ENGINE=native against a fake clamscan and a fake freshclam, which lets every branch run
# anywhere — including a machine with no Docker daemon, where the real-container tests skip.
#
# The scenarios are the ones that were actually broken: a database too old to trust, a refresh that
# cannot fix it, and a version string that will not parse (which used to print a warning and scan
# anyway, so a scanner that could detect nothing was free to report no infections).

fresh_fixture() {   # fresh_fixture <version-line-for-clamscan>
  local state; state=$(mktemp -d)
  mkdir -p "$state/bin" "$state/results"
  printf '%s\n' "$1" > "$state/version"
  cat > "$state/bin/clamscan" <<'FAKE'
#!/usr/bin/env bash
for a in "$@"; do
  [ "$a" = --version ] && { cat "$FAKE_STATE/version"; exit 0; }
done
printf '\n----------- SCAN SUMMARY -----------\nInfected files: 0\n'
exit 0
FAKE
  cat > "$state/bin/freshclam" <<'FAKE'
#!/usr/bin/env bash
echo ran >> "$FAKE_STATE/freshclam.calls"
if [ "${FAKE_FRESHCLAM_FAIL:-0}" = 1 ]; then echo "ERROR: Can't download daily.cvd"; exit 1; fi
if [ "${FAKE_FRESHCLAM_NOOP:-0}" = 1 ]; then echo "up to date"; exit 0; fi
printf 'ClamAV 9.9.9/99999/%s\n' "$(date '+%a %b %d %T %Y')" > "$FAKE_STATE/version"
exit 0
FAKE
  chmod +x "$state/bin/clamscan" "$state/bin/freshclam"
  printf '%s' "$state"
}

# guard_case <label> <version-line> <expect-exit> <expect-grep> [env assignments...]
guard_case() {
  local label="$1" version="$2" want_exit="$3" want_grep="$4"; shift 4
  local state out code=0
  state=$(fresh_fixture "$version")
  out=$(cd "$PROJECT_ROOT" && env "$@" \
        FAKE_STATE="$state" PATH="$state/bin:$PATH" SCAN_ENGINE=native \
        SCAN_RESULTS_DIR="$state/results" SCAN_DIR_OVERRIDE="$state/results" \
        bash "$SCAN_DIR/run-clamav.sh" 2>&1) || code=$?

  if [[ $code -ne $want_exit ]]; then
    _fail "$label" "expected exit $want_exit, got $code — output: $out"
  elif ! grep -q "$want_grep" <<<"$out"; then
    _fail "$label" "expected '$want_grep' in: $out"
  else
    _pass "$label"
  fi
  GUARD_LAST_STATE="$state"
  GUARD_LAST_OUT="$out"
}

NOW_VERSION="ClamAV 1.4.3/27712/$(date '+%a %b %d %T %Y')"
OLD_VERSION="ClamAV 1.4.3/27000/$(date -d '30 days ago' '+%a %b %d %T %Y' 2>/dev/null \
              || date -v-30d '+%a %b %d %T %Y')"

# Current signatures: scan proceeds, and nothing is downloaded.
guard_case "guard: current signatures scan without a refresh" \
  "$NOW_VERSION" 0 "Signature database: 0 day(s) old"
if [[ -f "$GUARD_LAST_STATE/freshclam.calls" ]]; then
  _fail "guard: current signatures do not trigger freshclam" "freshclam ran anyway"
else
  _pass "guard: current signatures do not trigger freshclam"
fi
rm -rf "$GUARD_LAST_STATE"

# Stale signatures, refresh works: this is the case the old guard could never reach, because
# `docker pull` cannot make an image carry signatures newer than the day it was built.
guard_case "guard: stale signatures are refreshed and the scan proceeds" \
  "$OLD_VERSION" 0 "Signatures refreshed"
if [[ -f "$GUARD_LAST_STATE/freshclam.calls" ]]; then
  _pass "guard: stale signatures trigger freshclam"
else
  _fail "guard: stale signatures trigger freshclam" "freshclam was never called"
fi
rm -rf "$GUARD_LAST_STATE"

# Stale, and the refresh fails outright — must not scan and must not claim clean.
guard_case "guard: a failed refresh blocks the scan" \
  "$OLD_VERSION" 1 "STALE SIGNATURES" FAKE_FRESHCLAM_FAIL=1
grep -q "FRESHCLAM FAILED" <<<"$GUARD_LAST_OUT" \
  && _pass "guard: a failed refresh prints why, not just a pointer to a log" \
  || _fail "guard: a failed refresh prints why, not just a pointer to a log" "got: $GUARD_LAST_OUT"
rm -rf "$GUARD_LAST_STATE"

# Stale, refresh succeeds but changes nothing (mirror behind). Still stale, still blocked — and the
# advice must not be the old "bump the tag", which nobody can act on.
guard_case "guard: a refresh that does not help still blocks" \
  "$OLD_VERSION" 1 "STALE SIGNATURES" FAKE_FRESHCLAM_NOOP=1
if grep -qi "bump the tag" <<<"$GUARD_LAST_OUT"; then
  _fail "guard: stale advice is actionable" "still says 'bump the tag', which cannot clear this"
else
  _pass "guard: stale advice is actionable"
fi
rm -rf "$GUARD_LAST_STATE"

# An unparseable version string must not scan-and-report-clean. This is the exact path the
# nonexistent image tag took on 2026-09-19.
guard_case "guard: an unreadable signature date blocks the scan" \
  "garbage with no date" 1 "UNVERIFIED SIGNATURES" FAKE_FRESHCLAM_NOOP=1
if grep -q "no infections found" <<<"$GUARD_LAST_OUT"; then
  _fail "guard: an unreadable signature date never reports clean" "it reported no infections found"
else
  _pass "guard: an unreadable signature date never reports clean"
fi
rm -rf "$GUARD_LAST_STATE"

# The override exists, but it must taint the verdict rather than hand back a clean-looking line.
guard_case "guard: the unverified override runs the scan" \
  "garbage with no date" 0 "no infections found" \
  FAKE_FRESHCLAM_NOOP=1 CLAMAV_ALLOW_UNVERIFIED_SIGNATURES=1
# Grep the verdict line itself, not the whole transcript. The earlier "WARNING — signature age
# UNVERIFIED" line also contains the word, so a whole-output match passes even when the final line
# reads as an ordinary clean — an assertion satisfied by the wrong line is how the EICAR test came
# to accept exit 125 as a detection.
if printf '%s\n' "$GUARD_LAST_OUT" | grep '^\[clamav\] PASS' | grep "UNVERIFIED" >/dev/null; then
  _pass "guard: the overridden pass is marked UNVERIFIED"
else
  _fail "guard: the overridden pass is marked UNVERIFIED" \
    "the PASS line reads as an ordinary clean: $(printf '%s\n' "$GUARD_LAST_OUT" | grep '^\[clamav\] PASS')"
fi
rm -rf "$GUARD_LAST_STATE"

# tool-runner must expose the refresh at all, and share one database between the two calls: a
# freshclam in its own --rm container updates a filesystem that is deleted before clamscan runs.
if grep -q '^tool_freshclam()' "$SCAN_DIR/tool-runner.sh"; then
  _pass "tool-runner.sh provides tool_freshclam"
else
  _fail "tool-runner.sh provides tool_freshclam" "no freshclam wrapper — the guard has no remedy"
fi
if [[ $(grep -c 'CLAMAV_DB_VOLUME:/var/lib/clamav' "$SCAN_DIR/tool-runner.sh") -eq 2 ]]; then
  _pass "clamscan and freshclam share one signature volume"
else
  _fail "clamscan and freshclam share one signature volume" \
    "both must mount the db volume or the refresh is discarded by --rm"
fi

echo ""
echo "=== Group 9: A crashed scanner must not read as clean ==="

# Every runner used to read its count as `jq ... 2>/dev/null || echo "0"`, so a scanner that
# crashed reported 0 findings and the scan reported PASS. These are the negative fixtures for
# count_json: each feeds it input a failed scanner actually produces. Finding F-22.
cj() { ( . "$RUNNER" >/dev/null 2>&1; count_json "$1" "$2" probe ) 2>/dev/null; }

_tmp9="$(mktemp -d)"

# The exact shape run-hadolint.sh writes when the tool fails: its stderr, via 2>&1, lands in
# the file where findings belong.
printf 'Unable to find image "hadolint/hadolint:v2.12.0-alpine" locally\ndocker: Error response from daemon.\n' > "$_tmp9/blob.json"
if out=$(cj "$_tmp9/blob.json" '[.[] | select(.level == "error")] | length'); then
  _fail "an error blob is rejected, not counted as 0" "returned '$out' and succeeded"
else
  [[ -z "$out" ]] && _pass "an error blob is rejected, not counted as 0" \
                  || _fail "an error blob is rejected, not counted as 0" "printed '$out' while failing"
fi

: > "$_tmp9/empty.json"
if out=$(cj "$_tmp9/empty.json" '. | length'); then
  _fail "an empty results file is rejected" "returned '$out' and succeeded"
else
  _pass "an empty results file is rejected"
fi

if out=$(cj "$_tmp9/missing.json" '. | length'); then
  _fail "a missing results file is rejected" "returned '$out' and succeeded"
else
  _pass "a missing results file is rejected"
fi

# jq returns 0 for `null | length`, so a filter over a key that has vanished reports "no findings"
# while parsing cleanly — the same silent zero one layer up. The runners' filters therefore assert
# their own key with `// error(...)`. This feeds checkov's REAL filter a document missing it.
printf '{"results":{}}' > "$_tmp9/shape.json"
if out=$(cj "$_tmp9/shape.json" '(.results.failed_checks // error("missing")) | length'); then
  _fail "a vanished key is rejected, not counted as 0" "returned '$out'"
else
  _pass "a vanished key is rejected, not counted as 0"
fi

# and the un-asserted form is exactly what that guards against
printf '{"results":{}}' > "$_tmp9/shape.json"
out=$(cj "$_tmp9/shape.json" '.results.failed_checks | length')
if [[ "$out" == "0" ]]; then
  _pass "confirms why: the un-asserted filter yields a silent 0"
else
  _fail "confirms why: the un-asserted filter yields a silent 0" "got '$out'"
fi

# every runner's count filter must assert its key or use an explicit optional
if grep -nE "count_json" "$SCAN_DIR"/run-*.sh | grep -vE 'error\(|\[\]\?|\.\[\]|RESULTS_DIR|tmp_json|\\$' >/dev/null; then
  :  # informational only; the per-filter assertions above are the real check
fi

# And the positive case, so this is not a function that always fails.
printf '[{"level":"error"},{"level":"warning"},{"level":"error"}]' > "$_tmp9/real.json"
out=$(cj "$_tmp9/real.json" '[.[] | select(.level == "error")] | length')
if [[ "$out" == "2" ]]; then
  _pass "a real results file still counts correctly (2 errors)"
else
  _fail "a real results file still counts correctly" "got '$out', expected 2"
fi

# No runner may carry the old fallback again.
if grep -q 'jq.*|| echo "0"' "$SCAN_DIR"/run-*.sh 2>/dev/null; then
  _fail "no runner reads a count with a '|| echo 0' fallback" \
    "$(grep -l 'jq.*|| echo \"0\"' "$SCAN_DIR"/run-*.sh | tr '\n' ' ')"
else
  _pass "no runner reads a count with a '|| echo 0' fallback"
fi

# The results directory moved to gate-records/scan on 2026-09-21 (F-23) so scan output lives with
# the other gate records instead of a top-level _scan-results/. Nine scripts carried the old
# default independently; this catches any one of them regressing.
# --exclude-dir=tests: this file names the old path in the pattern and the message, and would
# otherwise match itself.
_old_path='_scan''-results'
if grep -rq --exclude-dir=tests "$_old_path" "$SCAN_DIR"/../ 2>/dev/null; then
  _fail "no engine script still writes the old results path" \
    "$(grep -rl --exclude-dir=tests "$_old_path" "$SCAN_DIR"/../ 2>/dev/null | head -3 | tr '\n' ' ')"
else
  _pass "no engine script still writes the old results path"
fi

# A gitignored Dockerfile is a reference copy, not something the project ships. Including it made
# the scan depend on whether sync-engine had been run on this clone. Finding F-25.
if grep -q 'scan-scope.sh' "$SCAN_DIR/run-hadolint.sh" && grep -q 'check-ignore' "$SCAN_DIR/scan-scope.sh"; then
  _pass "run-hadolint skips gitignored Dockerfiles"
else
  _fail "run-hadolint skips gitignored Dockerfiles" "no check-ignore filter in the discovery loop"
fi

# The helm framework renders the chart, so it needs the directory holding Chart.yaml. Aimed at
# helm/templates it parsed 0 resources and contributed 0 findings while the scan reported PASS —
# the helm chart went unscanned for months. Finding F-27.
if grep -q -- '-name Chart.yaml' "$SCAN_DIR/run-checkov.sh"; then
  _pass "checkov scans the helm chart root, not helm/templates"
else
  _fail "checkov scans the helm chart root, not helm/templates" \
    "$(grep -E 'run_framework "helm"' "$SCAN_DIR/run-checkov.sh" | head -1)"
fi

# A summary-only checkov document (no .results key) means it ran and parsed nothing. That is valid
# output, so it must not be treated as a crash — but it must not read as a pass either.
if grep -q 'NOTHING SCANNED' "$SCAN_DIR/run-checkov.sh"; then
  _pass "a checkov run that parses 0 resources says so instead of passing quietly"
else
  _fail "a checkov run that parses 0 resources says so instead of passing quietly" "no notice"
fi

rm -rf "$_tmp9"

# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 16: the android track scans a filesystem and declares its empty scopes (2026-10-07) ==="

# Until this change four of seven scanners exited 1 on a plugin repo — no image to scan, no npm app
# dir to audit — so gate-line reported "did not run" and the verdict could never pass. Grype and
# Trivy now scan android/ as a filesystem; npm audit and eslint declare an empty scope the way
# hadolint does with no Dockerfiles. Every case that expects an android path is a negative fixture
# for "the web path ran anyway".
ST="$SCAN_DIR/scan-track.sh"
check_executable "scan-track.sh exists and is executable" "$ST"
track_of() { ( cd "$1" && . "$ST" && scan_track . ); }
_t=$(mktemp -d); printf 'APP_TRACK: android\n' > "$_t/project.config.yaml"
[ "$(track_of "$_t")" = android ] && _pass "scan-track: APP_TRACK: android → android" || _fail "scan-track: APP_TRACK: android → android" "got $(track_of "$_t")"
printf 'APP_TRACK: web\n' > "$_t/project.config.yaml"; mkdir -p "$_t/android"; printf '#!/bin/sh\n' > "$_t/android/gradlew"; chmod +x "$_t/android/gradlew"
[ "$(track_of "$_t")" = web ] && _pass "scan-track: the config wins over a gradlew on disk" || _fail "scan-track: the config wins over a gradlew on disk" "got $(track_of "$_t")"
printf 'APP_TRACK: UNSET\n' > "$_t/project.config.yaml"
[ "$(track_of "$_t")" = android ] && _pass "scan-track: UNSET + android/gradlew → android" || _fail "scan-track: UNSET + android/gradlew → android" "got $(track_of "$_t")"
rm -f "$_t/android/gradlew"
[ "$(track_of "$_t")" = web ] && _pass "scan-track: an empty android/ tree (the engine template) is still web" || _fail "scan-track: an empty android/ tree is still web" "got $(track_of "$_t")"
[ "$(SCAN_TRACK=android track_of "$_t")" = android ] && _pass "scan-track: SCAN_TRACK overrides" || _fail "scan-track: SCAN_TRACK overrides" "got $(SCAN_TRACK=android track_of "$_t")"
rm -rf "$_t"

# npm audit and eslint on an android root: exit 0, a valid empty decision file, a "none" receipt.
for pair in "run-npm-audit.sh:npm-audit:audit.json:NPM_AUDIT_ROOT" "run-eslint.sh:eslint:eslint.json:ESLINT_ROOT"; do
  f="${pair%%:*}"; rest="${pair#*:}"; n="${rest%%:*}"; rest="${rest#*:}"; file="${rest%%:*}"; var="${rest#*:}"
  root=$(mktemp -d); mkdir -p "$root/results" "$root/android"; printf 'APP_TRACK: android\n' > "$root/project.config.yaml"
  out=$(env "$var=$root" SCAN_RESULTS_DIR="$root/results" bash "$SCAN_DIR/$f" 2>&1); rc=$?
  kind=$(SCAN_RECEIPT_DIR="$root/results" bash -c ". $SR; scan_receipt_kind $n")
  [ "$rc" -eq 0 ] && _pass "$f on the android track exits 0" || _fail "$f on the android track exits 0" "rc $rc: $out"
  if grep -q "NOT APPLICABLE on the android track" <<<"$out"; then _pass "…and says NOT APPLICABLE, not skipped"; else _fail "…and says NOT APPLICABLE" "got: $out"; fi
  [ "$kind" = none ] && _pass "…and leaves a 'none' receipt" || _fail "…and leaves a 'none' receipt" "kind '$kind'"
  [ "$(jq '.blocking | length' "$root/results/$file" 2>/dev/null)" = 0 ] && _pass "…and writes a valid empty decision file" || _fail "…and writes a valid empty decision file" "$(cat "$root/results/$file" 2>/dev/null | head -c 200)"
  rm -rf "$root"
done
# …and the same two on a web root still take the web path (the android branch did not swallow it).
root=$(mktemp -d); mkdir -p "$root/results" "$root/backend" "$root/frontend"; printf 'APP_TRACK: web\n' > "$root/project.config.yaml"; printf '{"name":"x","scripts":{"lint":"eslint ."}}\n' > "$root/backend/package.json"
out=$(ESLINT_ROOT="$root" ESLINT_NPX=definitely-not-on-this-path SCAN_RESULTS_DIR="$root/results" bash "$SCAN_DIR/run-eslint.sh" 2>&1); rc=$?
if [ "$rc" -ne 0 ] && ! grep -q "NOT APPLICABLE" <<<"$out"; then _pass "run-eslint.sh on a web root still takes the web path"; else _fail "run-eslint.sh on a web root still takes the web path" "rc $rc: $out"; fi
rm -rf "$root"

# Grype and Trivy on the android track: a filesystem scan of android/, through the wrapper, with a
# fake binary on PATH (SCAN_ENGINE=native) that records what it was asked to scan.
fs_case() {   # fs_case <script> <scanner> <expected arg> <canned json>
  local f="$1" n="$2" want="$3" canned="$4" root out rc kind args
  root=$(mktemp -d); mkdir -p "$root/bin" "$root/results"
  printf '%s' "$canned" > "$root/canned"
  cat > "$root/bin/$n" <<FAKE
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$root/args"
cat "$root/canned"
FAKE
  chmod +x "$root/bin/$n"
  out=$(SCAN_TRACK=android SCAN_ENGINE=native PATH="$root/bin:$PATH" SCAN_RESULTS_DIR="$root/results" bash "$SCAN_DIR/$f" 2>&1); rc=$?
  kind=$(SCAN_RECEIPT_DIR="$root/results" bash -c ". $SR; scan_receipt_kind $n")
  args=$(cat "$root/args" 2>/dev/null)
  [ "$rc" -eq 0 ] && _pass "$f on the android track exits 0" || _fail "$f on the android track exits 0" "rc $rc: $out"
  if grep -q -- "$want" <<<"$args"; then _pass "…and scans android/ as a filesystem ($want)"; else _fail "…and scans android/ as a filesystem ($want)" "args: $args"; fi
  [ "$kind" = ran ] && _pass "…and claims a 'ran' receipt naming the filesystem" || _fail "…and claims a 'ran' receipt" "kind '$kind'"
  if grep -q "NO gradle.lockfile" <<<"$out"; then _pass "…and says out loud when there is no gradle.lockfile"; else _fail "…and says out loud when there is no gradle.lockfile" "got: $out"; fi
  [ -s "$root/results/${n}.json" ] && _pass "…and writes ${n}.json" || _fail "…and writes ${n}.json" "missing"
  rm -rf "$root"
}
if [ -d "$PROJECT_ROOT/android" ]; then
  fs_case run-grype.sh grype "dir:android" '{"matches":[],"source":{"type":"directory","target":"android"},"descriptor":{"name":"grype","version":"fake"}}'
  fs_case run-trivy.sh trivy "fs" '{"SchemaVersion":2,"ArtifactName":"android","ArtifactType":"filesystem","Results":[]}'
else
  _skip "grype/trivy filesystem cases" "no android/ directory in this checkout"
fi
# A fake that prints garbage is a scanner that did not run — no receipt, exit 1.
root=$(mktemp -d); mkdir -p "$root/bin" "$root/results"
printf '#!/usr/bin/env bash\necho "panic: not json"\n' > "$root/bin/grype"; chmod +x "$root/bin/grype"
out=$(SCAN_TRACK=android SCAN_ENGINE=native PATH="$root/bin:$PATH" SCAN_RESULTS_DIR="$root/results" bash "$SCAN_DIR/run-grype.sh" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$root/results" bash -c ". $SR; scan_receipt_kind grype")
[ "$rc" -ne 0 ] && [ -z "$kind" ] && _pass "grype fs: an unparseable report is not a scan (exit $rc, no receipt)" || _fail "grype fs: an unparseable report is not a scan" "rc $rc · kind '$kind' · $out"
rm -rf "$root"

# Dispatch with no image-scanner result at all must finish (exit 0) so the verdict line still prints;
# the verdict, not dispatch, says those scanners did not run.
nd=$(mktemp -d); cp -r "$FIXTURE_DIR/clean/." "$nd/"; rm -f "$nd/grype.json" "$nd/trivy.json"
nd_rc=0; SCAN_RESULTS_DIR="$nd" bash "$SCAN_DIR/generate-dispatch.sh" >/dev/null 2>&1 || nd_rc=$?
if [ "$nd_rc" -eq 0 ]; then _pass "dispatch with no grype or trivy result exits 0, so the verdict still prints"
else _fail "dispatch with no grype or trivy result exits 0" "exit $nd_rc"; fi
rm -rf "$nd"

# ── A repository that builds no image and has no npm app (T7) ─────────────────
# Grype and trivy scan the repository's files when image-plan.sh finds nothing to build; npm-audit
# and eslint declare an empty scope when no app dir holds a package.json. The failing halves stay:
# a named image that is missing still fails, and a package.json without a lockfile still fails.
repo_fs_case() {   # $1 runner  $2 tool  $3 canned json  $4… args that must appear
  local f="$1" n="$2" canned="$3" root out rc kind args want; shift 3
  root=$(mktemp -d); mkdir -p "$root/bin" "$root/results"
  printf '%s' "$canned" > "$root/canned"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/args"\ncat "%s/canned"\n' "$root" "$root" > "$root/bin/$n"; chmod +x "$root/bin/$n"
  out=$(SCAN_TRACK=web SCAN_ENGINE=native PATH="$root/bin:$PATH" SCAN_RESULTS_DIR="$root/results" bash "$SCAN_DIR/$f" 2>&1); rc=$?
  kind=$(SCAN_RECEIPT_DIR="$root/results" bash -c ". $SR; scan_receipt_kind $n")
  args=$(cat "$root/args" 2>/dev/null)
  if [ "$rc" -eq 0 ] && [ "$kind" = ran ]; then _pass "$f with no image to build scans the repository filesystem (exit 0, 'ran')"
  else _fail "$f with no image to build scans the repository filesystem" "rc $rc · kind '$kind' · $out"; fi
  for want in "$@"; do
    if grep -q -- "$want" <<<"$args"; then _pass "…and passes $want"; else _fail "…and passes $want" "args: $args"; fi
  done
  if grep -q 'repository filesystem' "$root/results/scanners-ran"; then _pass "…and its receipt says what it examined"
  else _fail "…and its receipt says what it examined" "$(cat "$root/results/scanners-ran")"; fi
  rm -rf "$root"
}
# Run from a scratch repository with no Dockerfile: image-plan.sh reads the current directory's
# repository, so these cases exercise the filesystem path whatever this checkout builds.
no_image_repo=$(mktemp -d); git -C "$no_image_repo" init -q
pushd "$no_image_repo" >/dev/null || exit 1
repo_fs_case run-grype.sh grype '{"matches":[],"source":{"type":"directory","target":"."},"descriptor":{"name":"grype","version":"fake"}}' "dir:." "fixtures/\*\*" "node_modules/\*\*"
repo_fs_case run-trivy.sh trivy '{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[]}' "fs --scanners vuln" "--skip-dirs scanners/fixtures" "--skip-dirs \*\*/node_modules"
# A named image is not an empty scope: the image path runs, and a missing image still fails.
root=$(mktemp -d); mkdir -p "$root/bin" "$root/results"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/args"\necho "{}"\n' "$root" > "$root/bin/grype"; chmod +x "$root/bin/grype"
out=$(SCAN_IMAGES="no-such-image:tag" SCAN_TRACK=web SCAN_ENGINE=native PATH="$root/bin:$PATH" SCAN_RESULTS_DIR="$root/results" bash "$SCAN_DIR/run-grype.sh" 2>&1); rc=$?
if ! grep -q 'dir:' "$root/args" 2>/dev/null && [ "$rc" -ne 0 ]; then _pass "grype with a named image takes the image path, and a missing image still fails"
else _fail "grype with a named image takes the image path" "rc $rc · args $(cat "$root/args" 2>/dev/null) · $out"; fi
rm -rf "$root"
popd >/dev/null || exit 1
rm -rf "$no_image_repo"
for pair in "run-npm-audit.sh:npm-audit:audit.json:NPM_AUDIT_ROOT" "run-eslint.sh:eslint:eslint.json:ESLINT_ROOT"; do
  IFS=: read -r f n out_file root_var <<< "$pair"
  root=$(mktemp -d); mkdir -p "$root/results" "$root/backend" "$root/frontend"
  out=$(env "$root_var=$root" SCAN_TRACK=web SCAN_RESULTS_DIR="$root/results" bash "$SCAN_DIR/$f" 2>&1); rc=$?
  kind=$(SCAN_RECEIPT_DIR="$root/results" bash -c ". $SR; scan_receipt_kind $n")
  if [ "$rc" -eq 0 ] && [ "$kind" = none ] && jq -e '.blocking == []' "$root/results/$out_file" >/dev/null 2>&1; then
    _pass "$f with no package.json anywhere is a declared empty scope (exit 0, 'none', valid $out_file)"
  else _fail "$f with no package.json anywhere is a declared empty scope" "rc $rc · kind '$kind' · $out"; fi
  if grep -q 'NOTHING IN SCOPE' <<<"$out"; then _pass "…and says so out loud"; else _fail "…and says so out loud" "$out"; fi
  rm -rf "$root"
done
root=$(mktemp -d); mkdir -p "$root/results" "$root/backend"; printf '{"name":"x"}\n' > "$root/backend/package.json"
out=$(NPM_AUDIT_ROOT="$root" SCAN_TRACK=web SCAN_RESULTS_DIR="$root/results" bash "$SCAN_DIR/run-npm-audit.sh" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$root/results" bash -c ". $SR; scan_receipt_kind npm-audit")
if [ "$rc" -ne 0 ] && [ -z "$kind" ]; then _pass "npm-audit: a package.json without a lockfile still fails (no receipt)"
else _fail "npm-audit: a package.json without a lockfile still fails" "rc $rc · kind '$kind' · $out"; fi
rm -rf "$root"

# The verdict on an android run: 7/7 ran, PASS, and every empty scope named.
dir=$(mktemp -d); cp "$FIXTURE_DIR/android-clean/"* "$dir/"
out=$(SCAN_RESULTS_DIR="$dir" "$GL" scan-verdict 2>&1); rc=$?
if grep -q "Scan: PASS" <<<"$out" && grep -q "7/7" <<<"$out" && grep -q "nothing in scope:.*npm-audit.*eslint" <<<"$out" && [ "$rc" -eq 0 ]; then
  _pass "gate verdict on a clean android run: PASS 7/7 with the empty scopes named"
else
  _fail "gate verdict on a clean android run: PASS 7/7 with the empty scopes named" "rc $rc · got: $out"
fi
rm -rf "$dir"

# Dispatch routing for filesystem results: a Gradle CVE with a fix blocks on ONE scanner's word (Grype
# cannot read the lockfile), an unfixed jar CVE is a POAM candidate, a clean tree dispatches nothing.
run_dispatch_test "android-gradle-fixable" "android-gradle-fixable" "yes" "yes" "CVE-2024-12345"
run_dispatch_test "android-clean"          "android-clean"          "no"  "no"  ""
src_dir=$(mktemp -d); out_dir=$(mktemp -d); cp "$FIXTURE_DIR/android-gradle-fixable/"* "$src_dir/"
SCAN_RESULTS_DIR="$src_dir" OUTPUT_DIR="$out_dir" bash "$SCAN_DIR/generate-dispatch.sh" >/dev/null 2>&1 || true
grep -q 'gradlew dependencies --write-locks' "$out_dir/dispatch.md" 2>/dev/null && _pass "Dispatch [android]: the remedy is the Gradle one, not npm" || _fail "Dispatch [android]: the remedy is the Gradle one, not npm" "$(grep -n 'Action' "$out_dir/dispatch.md" 2>/dev/null | head -2)"
grep -q 'CVE-2023-99001' "$out_dir/poam-candidates.md" 2>/dev/null && _pass "Dispatch [android]: the unfixed jar CVE is a POAM candidate" || _fail "Dispatch [android]: the unfixed jar CVE is a POAM candidate" "missing"
! grep -q 'base image layer' "$out_dir/poam-candidates.md" 2>/dev/null && _pass "Dispatch [android]: no 'base image layer' wording on a filesystem scan" || _fail "Dispatch [android]: no 'base image layer' wording on a filesystem scan" "found it"
rm -rf "$src_dir" "$out_dir"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 17: the scope is the whole checkout (SPEC-scanners.md) ==="

# Every runner finds its targets anywhere in the checkout, pruning node_modules, .git, dist, build,
# vendor and the bot's own canned fixtures, and skipping what git ignores. backend/ and frontend/
# are two directories among many, not the scope.
scope_repo() {   # a scratch git repository; prints its path
  local r; r=$(mktemp -d); git -C "$r" init -q; printf 'ref/\n' > "$r/.gitignore"; printf '%s' "$r"
}
fake_tool() {   # fake_tool <root> <name> <stdout> [exit] — a binary on $root/bin that records its args
  mkdir -p "$1/bin"; printf '%s' "$3" > "$1/canned-$2"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/args-%s"\ncat "%s/canned-%s"\nexit %s\n' "$1" "$2" "$1" "$2" "${4:-0}" > "$1/bin/$2"
  chmod +x "$1/bin/$2"
}
expect() {   # expect <name> <detail on failure> <command…> — pass when the command succeeds
  local name="$1" why="$2"; shift 2
  if "$@"; then _pass "$name"; else _fail "$name" "$why"; fi
}
refuse() {   # refuse <name> <detail on failure> <command…> — pass when the command fails
  local name="$1" why="$2"; shift 2
  if "$@"; then _fail "$name" "$why"; else _pass "$name"; fi
}
has() { grep -q -- "$2" <<<"$1"; }   # has <text> <pattern>

# hadolint: a Dockerfile outside backend/ is linted; a gitignored one and one under node_modules are not.
r=$(scope_repo); mkdir -p "$r/svc/api" "$r/ref" "$r/web/node_modules/x" "$r/results"
printf 'FROM scratch\n' > "$r/svc/api/Dockerfile"; printf 'FROM scratch\n' > "$r/ref/Dockerfile"; printf 'FROM scratch\n' > "$r/web/node_modules/x/Dockerfile"
fake_tool "$r" hadolint '[]'
out=$(PROJECT_ROOT="$r" SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-hadolint.sh" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind hadolint"); args=$(cat "$r/args-hadolint" 2>/dev/null)
if [ "$rc" -eq 0 ] && [ "$kind" = ran ] && has "$args" 'svc/api/Dockerfile'; then
  _pass "hadolint: a Dockerfile outside backend/ is linted (svc/api/Dockerfile, receipt 'ran')"
else _fail "hadolint: a Dockerfile outside backend/ is linted" "rc $rc · kind '$kind' · args $args · $out"; fi
if ! has "$args" 'ref/Dockerfile' && ! has "$args" 'node_modules'; then
  _pass "hadolint: a gitignored Dockerfile and one under node_modules are not linted"
else _fail "hadolint: a gitignored Dockerfile and one under node_modules are not linted" "args: $args"; fi
expect "hadolint: the receipt counts the one Dockerfile in scope" "$(cat "$r/results/scanners-ran")" grep -q 'ran 1 Dockerfile' "$r/results/scanners-ran"
rm -rf "$r"

# image-plan: every Dockerfile in the checkout is an image to build, named by its directory, built from it.
r=$(scope_repo); mkdir -p "$r/svc/api" "$r/ref" "$r/backend"
printf 'FROM scratch\n' > "$r/svc/api/Dockerfile"; printf 'FROM scratch\n' > "$r/ref/Dockerfile"; printf 'FROM scratch\n' > "$r/backend/Dockerfile"; printf 'FROM scratch\n' > "$r/backend/Dockerfile.worker"
plan=$(cd "$r" && bash "$SCAN_DIR/image-plan.sh")
expect "image-plan: svc/api/Dockerfile → image svc-api built from ./svc/api" "plan: $plan" has "$plan" $'^svc-api\tsvc/api/Dockerfile\t\\./svc/api$'
expect "image-plan: backend/Dockerfile keeps its name and context" "plan: $plan" has "$plan" $'^backend\tbackend/Dockerfile\t\\./backend$'
expect "image-plan: Dockerfile.worker is a second image of that directory" "plan: $plan" has "$plan" $'^backend-worker\tbackend/Dockerfile\\.worker\t\\./backend$'
refuse "image-plan: a gitignored Dockerfile is not an image" "plan: $plan" has "$plan" 'ref/'
rm -rf "$r"
# …and the bot's own image is never built by the bot's own scan: its Dockerfile is linted, not planned.
if [ -f "$PROJECT_ROOT/scanners/Dockerfile" ]; then
  plan=$(cd "$PROJECT_ROOT" && bash "$SCAN_DIR/image-plan.sh")
  refuse "image-plan: the bot's own Dockerfile is not in its own plan" "plan: $plan" has "$plan" 'scanners/Dockerfile'
fi

# checkov: a helm chart root, a terraform directory and a Kubernetes manifest anywhere in the checkout.
r=$(scope_repo); mkdir -p "$r/infra/chart/templates" "$r/infra/tf/modules/net" "$r/deploy" "$r/results"
printf 'apiVersion: v2\nname: x\nversion: 0.1.0\n' > "$r/infra/chart/Chart.yaml"; printf 'kind: Deployment\n' > "$r/infra/chart/templates/d.yaml"
printf 'resource "null_resource" "x" {}\n' > "$r/infra/tf/main.tf"; printf 'resource "null_resource" "y" {}\n' > "$r/infra/tf/modules/net/main.tf"
printf 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n' > "$r/deploy/app.yaml"; printf 'name: not a manifest\n' > "$r/deploy/other.yaml"
fake_tool "$r" checkov '{"results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[]},"summary":{"passed":0,"failed":0,"skipped":0,"parsing_error":0,"resource_count":1}}'
out=$(PROJECT_ROOT="$r" SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-checkov.sh" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind checkov"); args=$(cat "$r/args-checkov" 2>/dev/null)
if [ "$rc" -eq 0 ] && [ "$kind" = ran ]; then _pass "checkov: a checkout with IaC anywhere exits 0 with a 'ran' receipt"
else _fail "checkov: a checkout with IaC anywhere exits 0 with a 'ran' receipt" "rc $rc · kind '$kind' · $out"; fi
expect "checkov: the chart root (the directory holding Chart.yaml) is scanned with the helm framework" "args: $args" has "$args" '--framework helm --directory infra/chart'
expect "checkov: the terraform directory is scanned" "args: $args" has "$args" '--framework terraform --directory infra/tf'
refuse "checkov: a nested terraform directory is covered by its parent, not scanned twice" "args: $args" has "$args" 'infra/tf/modules/net'
expect "checkov: a Kubernetes manifest is scanned by file" "args: $args" has "$args" '--framework kubernetes.*--file deploy/app.yaml'
refuse "checkov: a yaml with no apiVersion/kind is not a manifest" "args: $args" has "$args" 'deploy/other.yaml'
refuse "checkov: a chart's templates are rendered by the helm run, not scanned as manifests" "args: $args" has "$args" 'templates/d.yaml'
expect "checkov: the receipt counts three targets" "$(cat "$r/results/scanners-ran")" grep -q 'ran 3 target' "$r/results/scanners-ran"
rm -rf "$r"
r=$(scope_repo); mkdir -p "$r/results"; fake_tool "$r" checkov '{}'
out=$(PROJECT_ROOT="$r" SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-checkov.sh" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind checkov")
if [ "$rc" -eq 0 ] && [ "$kind" = none ] && [ ! -f "$r/args-checkov" ]; then _pass "checkov: a checkout with no IaC is a declared empty scope and runs nothing"
else _fail "checkov: a checkout with no IaC is a declared empty scope" "rc $rc · kind '$kind' · $out"; fi
rm -rf "$r"

# npm audit and eslint: a package.json under tools/site/ is an app like any other — audited, linted,
# named in the decision file. Nothing is "stray" and nothing outside backend/ is "nothing in scope".
r=$(scope_repo); mkdir -p "$r/tools/site/node_modules" "$r/results"
printf '{"name":"site","scripts":{"lint":"eslint ."}}\n' > "$r/tools/site/package.json"; printf '{}\n' > "$r/tools/site/package-lock.json"
fake_tool "$r" npm "$NA_CLEAN" 1; fake_tool "$r" npx "$ES_CLEAN" 0
out=$(PATH="$r/bin:$PATH" NPM_AUDIT_ROOT="$r" SCAN_TRACK=web SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-npm-audit.sh" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind npm-audit")
if [ "$rc" -eq 0 ] && [ "$kind" = ran ] && [ "$(jq -r '.apps[0].app' "$r/results/audit.json" 2>/dev/null)" = "tools/site" ]; then
  _pass "npm-audit: a package.json in tools/site/ is audited (receipt 'ran', named in audit.json)"
else _fail "npm-audit: a package.json in tools/site/ is audited" "rc $rc · kind '$kind' · $(jq -c '.apps' "$r/results/audit.json" 2>/dev/null) · $out"; fi
out=$(PATH="$r/bin:$PATH" ESLINT_ROOT="$r" SCAN_TRACK=web SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-eslint.sh" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind eslint")
if [ "$rc" -eq 0 ] && [ "$kind" = ran ] && [ "$(jq -r '.apps[0].app' "$r/results/eslint.json" 2>/dev/null)" = "tools/site" ]; then
  _pass "eslint: a package.json in tools/site/ is linted with its own lint script (receipt 'ran')"
else _fail "eslint: a package.json in tools/site/ is linted" "rc $rc · kind '$kind' · $out"; fi
# A second app without its lockfile is named and fails the run: a manifest that was not audited is never an empty scope.
mkdir -p "$r/svc/worker"; printf '{"name":"w"}\n' > "$r/svc/worker/package.json"
out=$(PATH="$r/bin:$PATH" NPM_AUDIT_ROOT="$r" SCAN_TRACK=web SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-npm-audit.sh" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind npm-audit")
if [ "$rc" -ne 0 ] && [ -z "$kind" ] && has "$out" 'svc/worker/package.json'; then _pass "npm-audit: an app without a lockfile fails, named, beside one that was audited"
else _fail "npm-audit: an app without a lockfile fails, named" "rc $rc · kind '$kind' · $out"; fi
# …while a package.json with no lint script is reported as unlinted, not a failure of the scanner.
out=$(PATH="$r/bin:$PATH" ESLINT_ROOT="$r" SCAN_TRACK=web SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-eslint.sh" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && [ "$(jq -r '.unlinted[0]' "$r/results/eslint.json" 2>/dev/null)" = "svc/worker" ]; then _pass "eslint: a package.json with no lint script is listed as unlinted in eslint.json"
else _fail "eslint: a package.json with no lint script is listed as unlinted" "rc $rc · $(head -c 300 "$r/results/eslint.json" 2>/dev/null) · $out"; fi
rm -rf "$r"
# A checkout whose only package.json has no lint script is a declared empty scope for eslint, named.
r=$(scope_repo); mkdir -p "$r/tools/x" "$r/results"; printf '{"name":"x"}\n' > "$r/tools/x/package.json"; fake_tool "$r" npx "$ES_CLEAN" 0
out=$(PATH="$r/bin:$PATH" ESLINT_ROOT="$r" SCAN_TRACK=web SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-eslint.sh" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind eslint")
if [ "$rc" -eq 0 ] && [ "$kind" = none ] && has "$out" 'tools/x'; then _pass "eslint: no app with an eslint lint script is an empty scope that names the apps"
else _fail "eslint: no app with an eslint lint script is an empty scope" "rc $rc · kind '$kind' · $out"; fi
rm -rf "$r"

# pip-audit: every requirements*.txt and pyproject.toml in the checkout, through a pinned pip-audit.
PA="$SCAN_DIR/run-pip-audit.sh"
check_executable "run-pip-audit.sh exists and is executable" "$PA"
PA_PIN=$(sed -nE 's/^SCAN_PIP_AUDIT_VERSION="\$\{SCAN_PIP_AUDIT_VERSION:-([^}]+)\}"$/\1/p' "$SCAN_DIR/tool-versions.env")
expect "tool-versions.env pins pip-audit ($PA_PIN)" "SCAN_PIP_AUDIT_VERSION is empty" test -n "$PA_PIN"
expect "scanners/requirements.txt carries the same pin" "$(cat "$PROJECT_ROOT/scanners/requirements.txt" 2>/dev/null)" grep -qxF "pip-audit==$PA_PIN" "$PROJECT_ROOT/scanners/requirements.txt"
pa_fixture() {   # pa_fixture <canned json> <exit> [version] → root with svc/requirements*.txt, lib/pyproject.toml, vendor/
  local r; r=$(mktemp -d); git -C "$r" init -q; mkdir -p "$r/bin" "$r/svc" "$r/lib" "$r/results" "$r/vendor/old"
  printf 'pyyaml==6.0.2\n' > "$r/svc/requirements.txt"; printf 'pyyaml==6.0.2\n' > "$r/svc/requirements-dev.txt"
  printf '[project]\nname = "lib"\nversion = "0.1"\n' > "$r/lib/pyproject.toml"; printf 'x==1\n' > "$r/vendor/old/requirements.txt"
  printf '%s' "$1" > "$r/canned"; printf '%s' "$2" > "$r/canned.rc"; printf '%s' "${3:-$PA_PIN}" > "$r/version"
  cat > "$r/bin/fake-pip-audit" <<FAKE
#!/usr/bin/env bash
case " \$* " in *" --version "*) printf 'pip-audit %s\n' "\$(cat "$r/version")"; exit 0 ;; esac
printf '%s\n' "\$*" >> "$r/args"
cat "$r/canned"; exit "\$(cat "$r/canned.rc")"
FAKE
  chmod +x "$r/bin/fake-pip-audit"; printf '%s' "$r"
}
pa_run() { PA_RC=0; PA_OUT=$(PROJECT_ROOT="$1" PIP_AUDIT_CMD="$1/bin/fake-pip-audit" SCAN_RESULTS_DIR="$1/results" bash "$PA" 2>&1) || PA_RC=$?; }
PA_CLEAN='{"dependencies":[{"name":"pyyaml","version":"6.0.2","vulns":[]}],"fixes":[]}'
PA_VULN='{"dependencies":[{"name":"pyyaml","version":"5.3","vulns":[{"id":"PYSEC-2021-142","fix_versions":["5.4"],"aliases":["CVE-2020-14343"],"description":"fixture"}]},{"name":"old","version":"1","vulns":[{"id":"PYSEC-0000-1","fix_versions":[],"aliases":[],"description":"no fix"}]}],"fixes":[]}'
r=$(pa_fixture "$PA_CLEAN" 0); pa_run "$r"
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind pip-audit"); args=$(cat "$r/args" 2>/dev/null)
if [ "$PA_RC" -eq 0 ] && [ "$kind" = ran ]; then _pass "pip-audit: a clean audit exits 0 with a 'ran' receipt"
else _fail "pip-audit: a clean audit exits 0 with a 'ran' receipt" "rc $PA_RC · kind '$kind' · $PA_OUT"; fi
if has "$args" -- '-r svc/requirements.txt' && has "$args" -- '-r svc/requirements-dev.txt'; then _pass "pip-audit: every requirements*.txt is audited by file"
else _fail "pip-audit: every requirements*.txt is audited by file" "args: $args"; fi
expect "pip-audit: a pyproject.toml with no requirements file is audited as a project" "args: $args" grep -qE '(^| )lib( |$)' <<<"$args"
refuse "pip-audit: vendor/ is pruned" "args: $args" has "$args" 'vendor'
expect "pip-audit: pip-audit.json names the three manifests" "$(jq -c '.apps' "$r/results/pip-audit.json")" test "$(jq '.apps | length' "$r/results/pip-audit.json")" = 3
expect "pip-audit: the receipt counts the manifests" "$(cat "$r/results/scanners-ran")" grep -q 'ran 3 manifest' "$r/results/scanners-ran"
rm -rf "$r"
r=$(pa_fixture "$PA_VULN" 1); pa_run "$r"
expect "pip-audit: a vulnerability with a fix exits 1" "rc $PA_RC · $PA_OUT" test "$PA_RC" -eq 1
expect "pip-audit: the fixable vulnerability is named as blocking" "$PA_OUT" has "$PA_OUT" 'BLOCKING.*PYSEC-2021-142'
expect "pip-audit: a vulnerability with no fix is reported, not blocking" "$(jq -c '.reported' "$r/results/pip-audit.json")" test "$(jq -r '.reported[0].id' "$r/results/pip-audit.json")" = "PYSEC-0000-1"
expect "pip-audit: the CVE alias travels with the finding" "$(jq -c '.blocking' "$r/results/pip-audit.json")" test "$(jq -r '.blocking[0].aliases[0]' "$r/results/pip-audit.json")" = "CVE-2020-14343"
rm -rf "$r"
r=$(pa_fixture "not json" 2); pa_run "$r"
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind pip-audit")
if [ "$PA_RC" -eq 1 ] && [ -z "$kind" ] && [ ! -f "$r/results/pip-audit.json" ] && has "$PA_OUT" 'did not run'; then _pass "pip-audit: an unparseable report is a scanner that did not run (no receipt, no decision file)"
else _fail "pip-audit: an unparseable report is a scanner that did not run" "rc $PA_RC · kind '$kind' · $PA_OUT"; fi
rm -rf "$r"
r=$(pa_fixture "$PA_CLEAN" 0 "0.0.1"); pa_run "$r"
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind pip-audit")
if [ "$PA_RC" -eq 1 ] && [ -z "$kind" ] && has "$PA_OUT" "$PA_PIN"; then _pass "pip-audit: a version other than the pin is refused, naming the pin"
else _fail "pip-audit: a version other than the pin is refused" "rc $PA_RC · kind '$kind' · $PA_OUT"; fi
rm -rf "$r"
r=$(mktemp -d); git -C "$r" init -q; mkdir -p "$r/results"
out=$(PROJECT_ROOT="$r" PIP_AUDIT_CMD=definitely-not-on-this-path SCAN_RESULTS_DIR="$r/results" bash "$PA" 2>&1); rc=$?
kind=$(SCAN_RECEIPT_DIR="$r/results" bash -c ". $SR; scan_receipt_kind pip-audit")
if [ "$rc" -eq 0 ] && [ "$kind" = none ] && jq -e '.blocking == []' "$r/results/pip-audit.json" >/dev/null 2>&1; then _pass "pip-audit: no Python manifest anywhere is a declared empty scope (before any tool check)"
else _fail "pip-audit: no Python manifest anywhere is a declared empty scope" "rc $rc · kind '$kind' · $out"; fi
rm -rf "$r"
for t in scan scan-lite gate-scan; do
  if awk -v t="$t" '$0 ~ "^"t":"{p=1;next} /^[a-zA-Z_-]+:/{p=0} p' "$PROJECT_ROOT/Makefile" | grep 'run-pip-audit.sh' >/dev/null; then _pass "$t runs run-pip-audit.sh"; else _fail "$t runs run-pip-audit.sh" "recipe does not call the runner"; fi
done
expect "scan.sh runs run-pip-audit.sh" "not in the list" grep -q 'run-pip-audit.sh' "$PROJECT_ROOT/scanners/scan.sh"
# dispatch routes a fixable Python CVE to the fixable list and an unfixable one to the POAM candidates
d=$(mktemp -d); o=$(mktemp -d); cp "$FIXTURE_DIR/clean/"* "$d/"
printf '{"scanner":"pip-audit","apps":[{"app":"svc","file":"svc/requirements.txt","dependencies":2}],"blocking":[{"app":"svc","file":"svc/requirements.txt","id":"PYSEC-2021-142","aliases":["CVE-2020-14343"],"package":"pyyaml","version":"5.3","fix":"5.4"}],"reported":[{"app":"svc","file":"svc/requirements.txt","id":"PYSEC-0000-1","aliases":[],"package":"old","version":"1","fix":"none"}]}\n' > "$d/pip-audit.json"
SCAN_RESULTS_DIR="$d" OUTPUT_DIR="$o" bash "$SCAN_DIR/generate-dispatch.sh" >/dev/null 2>&1 || true
expect "dispatch: a fixable pip-audit finding is a fixable block" "$(head -40 "$o/dispatch.md" 2>/dev/null)" grep -q '^### PYSEC-2021-142' "$o/dispatch.md"
expect "dispatch: an unfixable pip-audit finding is a POAM candidate" "$(cat "$o/poam-candidates.md" 2>/dev/null)" grep -q '^## PYSEC-0000-1' "$o/poam-candidates.md"
rm -rf "$d" "$o"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 18: a scanner that found something ran (gate run 1, B-1) ==="

# A runner exits 1 on a blocking finding. Until gate run 1 it did so BEFORE writing its receipt, so
# the verdict and the Scan gate reported a scanner that ran and found something as one that did not
# run — failing every profile, whatever an accepted risk said, and telling the assessor it never ran.
# Each runner here is given a fake tool that finds one thing; the receipt must say "ran", exit 1.
found_case() {   # found_case <label> <scanner> <rc> <results dir>
  local kind; kind=$(SCAN_RECEIPT_DIR="$4" bash -c ". $SR; scan_receipt_kind $2")
  if [ "$3" -eq 1 ] && [ "$kind" = ran ]; then _pass "$1: a finding exits 1 and the receipt still says ran"
  else _fail "$1: a finding exits 1 and the receipt still says ran" "rc $3 · kind '$kind'"; fi
}
r=$(scope_repo); mkdir -p "$r/results"; printf 'FROM scratch\n' > "$r/Dockerfile"
fake_tool "$r" hadolint '[{"level":"error","code":"DL3006","file":"Dockerfile","line":1,"message":"fixture"}]' 1
rc=0; PROJECT_ROOT="$r" SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-hadolint.sh" >/dev/null 2>&1 || rc=$?
found_case hadolint hadolint "$rc" "$r/results"; rm -rf "$r"
r=$(scope_repo); mkdir -p "$r/deploy" "$r/results"; printf 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n' > "$r/deploy/app.yaml"
fake_tool "$r" checkov '{"results":{"passed_checks":[],"failed_checks":[{"check_id":"CKV_K8S_21","file_path":"/deploy/app.yaml","resource":"Deployment.x","check_name":"fixture"}],"skipped_checks":[]},"summary":{"passed":0,"failed":1,"skipped":0,"parsing_error":0,"resource_count":1}}'
rc=0; PROJECT_ROOT="$r" CHECKOV_JUSTIFICATIONS=/nonexistent SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-checkov.sh" >/dev/null 2>&1 || rc=$?
found_case checkov checkov "$rc" "$r/results"; rm -rf "$r"
root=$(es_fixture "$ES_ERR" 1); es_run "$root"
found_case eslint eslint "$ES_RC" "$root/results"; rm -rf "$root"
state=$(fresh_fixture "$NOW_VERSION")
cat > "$state/bin/clamscan" <<'FAKE'
#!/usr/bin/env bash
for a in "$@"; do [ "$a" = --version ] && { cat "$FAKE_STATE/version"; exit 0; }; done
printf 'x: Eicar-Signature FOUND\n----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\n'; exit 1
FAKE
rc=0; (cd "$PROJECT_ROOT" && FAKE_STATE="$state" PATH="$state/bin:$PATH" SCAN_ENGINE=native SCAN_RESULTS_DIR="$state/results" \
  SCAN_DIR_OVERRIDE="$state/results" bash "$SCAN_DIR/run-clamav.sh" >/dev/null 2>&1) || rc=$?
found_case clamav clamav "$rc" "$state/results"; rm -rf "$state"
r=$(pa_fixture "$PA_VULN" 1); pa_run "$r"
found_case pip-audit pip-audit "$PA_RC" "$r/results"; rm -rf "$r"
root=$(na_fixture "$NA_HIGH"); na_run "$root"
found_case npm-audit npm-audit "$NA_RC" "$root/results"; rm -rf "$root"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 19: ClamAV scans the checkout it is given (gate run 1, B-4) ==="

# run-clamav.sh set PROJECT_ROOT from its own path and ignored the environment, so under the Scan
# gate (PROJECT_ROOT = the user's checkout) it scanned the bot's install and never the checkout.
state=$(fresh_fixture "$NOW_VERSION"); co=$(mktemp -d); printf 'x\n' > "$co/file.txt"
cat > "$state/bin/clamscan" <<'FAKE'
#!/usr/bin/env bash
for a in "$@"; do [ "$a" = --version ] && { cat "$FAKE_STATE/version"; exit 0; }; done
for a in "$@"; do last="$a"; done; printf '%s\n' "$last" >> "$FAKE_STATE/targets"
printf '%s\n' '----------- SCAN SUMMARY -----------' 'Scanned files: 1' 'Infected files: 0'
FAKE
rc=0; (cd "$state" && PROJECT_ROOT="$co" FAKE_STATE="$state" PATH="$state/bin:$PATH" SCAN_ENGINE=native \
  SCAN_RESULTS_DIR="$state/results" bash "$SCAN_DIR/run-clamav.sh" >/dev/null 2>&1) || rc=$?
targets=$(sort -u "$state/targets" 2>/dev/null)
if [ "$rc" -eq 0 ] && [ "$targets" = "$co" ]; then _pass "clamav: scans the PROJECT_ROOT it is given, not the bot's own install"
else _fail "clamav: scans the PROJECT_ROOT it is given, not the bot's own install" "rc $rc · targets '$targets' · want '$co'"; fi
rm -rf "$state" "$co"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 20: the scanners read the bot's config, never the checkout's (gate run 1, B-5, N-11) ==="

# Grype, Trivy and hadolint each look for their own config in the working directory, and the
# runners cd into the checkout. A .grype.yaml, .trivyignore, trivy.yaml, trivy-secret.yaml or
# .hadolint.yaml there dropped a CVE or a rule before the Scan gate saw it — no expiry (CM-22), no
# yellow (CM-25), nothing in the receipt. Every scan call must name the bot's own file instead.
CFG="$MODULE_DIR/scan-config"
every_call() {   # every_call <label> <args file> <pattern> — the pattern is on every recorded call
  local n m; n=$(grep -c . "$2" 2>/dev/null) || true; m=$(grep -cF -- "$3" "$2" 2>/dev/null) || true; n=${n:-0}; m=${m:-0}
  if [ "$n" -gt 0 ] && [ "$n" = "$m" ]; then _pass "$1"; else _fail "$1" "$m of $n call(s) carry '$3': $(head -3 "$2" 2>/dev/null)"; fi
}
hostile_checkout() {   # a scratch repository carrying every scanner config file a checkout could plant
  local r; r=$(scope_repo); mkdir -p "$r/results" "$r/.grype"
  printf 'ignore:\n  - vulnerability: CVE-2018-18074\n' > "$r/.grype.yaml"; cp "$r/.grype.yaml" "$r/.grype/config.yaml"
  printf 'CVE-2018-18074\n' > "$r/.trivyignore"; printf 'scan:\n  skip-dirs: [.]\n' > "$r/trivy.yaml"
  printf 'disable-rules: [github-pat]\n' > "$r/trivy-secret.yaml"; printf 'ignored: [DL3006]\n' > "$r/.hadolint.yaml"
  printf '%s' "$r"
}
for f in grype.yaml trivy.yaml trivy-secret.yaml trivyignore hadolint.yaml checkov.yaml; do
  expect "scan-config/$f is the bot's own file" "missing" test -f "$CFG/$f"
done
refuse "scan-config/grype.yaml ignores nothing" "$(cat "$CFG/grype.yaml" 2>/dev/null)" grep -q 'vulnerability' "$CFG/grype.yaml"
refuse "scan-config/trivyignore ignores nothing" "$(cat "$CFG/trivyignore" 2>/dev/null)" grep -qvE '^[[:space:]]*(#|$)' "$CFG/trivyignore"
# The repository-filesystem path (no image in the checkout).
r=$(hostile_checkout)
fake_tool "$r" grype '{"matches":[],"source":{"type":"directory","target":"."},"descriptor":{"name":"grype","version":"fake"}}'
fake_tool "$r" trivy '{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[]}'
(cd / && PROJECT_ROOT="$r" SCAN_TRACK=web SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-grype.sh" >/dev/null 2>&1)
(cd / && PROJECT_ROOT="$r" SCAN_TRACK=web SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-trivy.sh" >/dev/null 2>&1)
every_call "grype (filesystem): every call reads the bot's config" "$r/args-grype" "--config $CFG/grype.yaml"
grep -v '^version' "$r/args-trivy" > "$r/args-trivy-scan" 2>/dev/null
# Every call, `version` included (gate run 2, B-7): the database date is read through `version`.
expect "trivy (filesystem): the database date is read, so \`version\` is among the calls checked" "$(cat "$r/args-trivy" 2>/dev/null)" grep -q '^version' "$r/args-trivy"
every_call "trivy (filesystem): every call, version included, reads the bot's config" "$r/args-trivy" "--config $CFG/trivy.yaml"
every_call "trivy (filesystem): every call, version included, names the bot's cache" "$r/args-trivy" "--cache-dir "
every_call "trivy (filesystem): every scan reads the bot's ignore file" "$r/args-trivy-scan" "--ignorefile $CFG/trivyignore"
every_call "trivy (filesystem): every scan reads the bot's secret config" "$r/args-trivy-scan" "--secret-config $CFG/trivy-secret.yaml"
rm -rf "$r"
# The image path.
r=$(hostile_checkout)
printf '#!/usr/bin/env bash\ncase "$*" in *Created*) date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ ;; esac\nexit 0\n' > "$r/docker-fake"; mkdir -p "$r/bin"; mv "$r/docker-fake" "$r/bin/docker"; chmod +x "$r/bin/docker"
fake_tool "$r" grype '{"matches":[],"source":{"type":"image"},"descriptor":{"name":"grype","version":"fake","db":{"status":{"built":"2026-10-14T00:00:00Z"}}}}'
fake_tool "$r" trivy '{"SchemaVersion":2,"ArtifactName":"x","ArtifactType":"container_image","Results":[]}'
(cd / && PROJECT_ROOT="$r" SCAN_IMAGES="api:scan" SCAN_TRACK=web SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-grype.sh" >/dev/null 2>&1)
(cd / && PROJECT_ROOT="$r" SCAN_IMAGES="api:scan" SCAN_TRACK=web SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-trivy.sh" >/dev/null 2>&1)
every_call "grype (image): every call reads the bot's config" "$r/args-grype" "--config $CFG/grype.yaml"
grep -v '^version' "$r/args-trivy" > "$r/args-trivy-scan" 2>/dev/null
every_call "trivy (image): every scan reads the bot's ignore file" "$r/args-trivy-scan" "--ignorefile $CFG/trivyignore"
# Every call, `version` included (gate run 2, B-7): the database date is read through `version`.
expect "trivy (image): the database date is read, so \`version\` is among the calls checked" "$(cat "$r/args-trivy" 2>/dev/null)" grep -q '^version' "$r/args-trivy"
every_call "trivy (image): every call, version included, reads the bot's config" "$r/args-trivy" "--config $CFG/trivy.yaml"
every_call "trivy (image): every call, version included, names the bot's cache" "$r/args-trivy" "--cache-dir "
every_call "trivy (image): every scan reads the bot's secret config" "$r/args-trivy-scan" "--secret-config $CFG/trivy-secret.yaml"
rm -rf "$r"
# The reviewer's probe (gate run 2, B-7): a trivy.yaml in the checkout points the cache at a directory
# whose metadata.json says 2099. Read through `trivy version` without the bot's config, that is the
# date stale_databases judges, and CM-05 is defeated. The fake models trivy's own lookup: the file
# --config names, else ./trivy.yaml; --cache-dir, else that file's cache.dir, else the default.
r=$(hostile_checkout); mkdir -p "$r/fake/db" "$r/cache/db" "$r/bin"
printf 'cache:\n  dir: ./fake\n' > "$r/trivy.yaml"
printf '{"Version":2,"UpdatedAt":"2099-01-01T00:00:00Z"}' > "$r/fake/db/metadata.json"
printf '{"Version":2,"UpdatedAt":"2026-10-14T00:00:00Z"}' > "$r/cache/db/metadata.json"
cat > "$r/bin/trivy" <<FAKE
#!/usr/bin/env bash
cfg=trivy.yaml; cache=""; prev=""
for a in "\$@"; do [ "\$prev" = --config ] && cfg="\$a"; [ "\$prev" = --cache-dir ] && cache="\$a"; prev="\$a"; done
dir=\$(sed -nE 's/^[[:space:]]+dir:[[:space:]]*(.*)$/\1/p' "\$cfg" 2>/dev/null | head -1)
[ -n "\$cache" ] || cache="\${dir:-\${TRIVY_CACHE_DIR:-$r/cache}}"   # the flag, else the config file, else the default
case "\$1" in
  version) printf '{"Version":"0.58.2","VulnerabilityDB":%s}\n' "\$(cat "\$cache/db/metadata.json")" ;;
  *) echo '{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[]}' ;;
esac
FAKE
chmod +x "$r/bin/trivy"
(cd / && PROJECT_ROOT="$r" TRIVY_CACHE_DIR="$r/cache" SCAN_TRACK=web SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-trivy.sh" >/dev/null 2>&1)
d=$(jq -r '.VulnerabilityDB.UpdatedAt // "none"' "$r/results/trivy-version.json" 2>/dev/null)
if [ "$d" = "2026-10-14T00:00:00Z" ]; then _pass "trivy: a trivy.yaml in the checkout cannot fake the database date (the bot's cache is read)"
else _fail "trivy: a trivy.yaml in the checkout cannot fake the database date" "trivy-version.json says '$d'"; fi
rm -rf "$r"
# …and with the real trivy, where the host has one and its database: the runner's date is the cache's, never 2099.
if command -v trivy >/dev/null 2>&1 && trivy version --format json 2>/dev/null | jq -e '.VulnerabilityDB.UpdatedAt' >/dev/null 2>&1; then
  r=$(hostile_checkout); mkdir -p "$r/fake/db"; printf 'cache:\n  dir: ./fake\n' > "$r/trivy.yaml"
  printf '{"Version":2,"NextUpdate":"2099-01-01T00:00:00Z","UpdatedAt":"2099-01-01T00:00:00Z","DownloadedAt":"2099-01-01T00:00:00Z"}' > "$r/fake/db/metadata.json"
  (cd / && PROJECT_ROOT="$r" TRIVY_SKIP_DB_UPDATE=true TRIVY_OFFLINE_SCAN=true SCAN_TRACK=web SCAN_ENGINE=native SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-trivy.sh" >/dev/null 2>&1)
  d=$(jq -r '.VulnerabilityDB.UpdatedAt // "none"' "$r/results/trivy-version.json" 2>/dev/null)
  if [ -n "$d" ] && [ "$d" != none ] && ! has "$d" '^2099'; then _pass "real trivy: the reviewer's trivy.yaml cannot fake the database date ($d)"
  else _fail "real trivy: the reviewer's trivy.yaml cannot fake the database date" "trivy-version.json says '$d'"; fi
  rm -rf "$r"
else echo "  NOTE: real trivy with a database not on this host — the fake-tool case above is the test; this one adds evidence where it can"; fi
# hadolint: the checkout's .hadolint.yaml is never read; the bot's is.
r=$(hostile_checkout); printf 'FROM scratch\n' > "$r/Dockerfile"; fake_tool "$r" hadolint '[]'
(cd / && PROJECT_ROOT="$r" SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-hadolint.sh" >/dev/null 2>&1)
every_call "hadolint: every call reads the bot's config" "$r/args-hadolint" "--config $CFG/hadolint.yaml"
every_call "hadolint: every call disables the checkout's '# hadolint ignore=' pragmas (gate run 2, N-02)" "$r/args-hadolint" "--disable-ignore-pragma"
refuse "hadolint: the checkout's .hadolint.yaml is never named" "$(cat "$r/args-hadolint" 2>/dev/null)" grep -qE '(^| )(\./)?\.hadolint\.yaml' "$r/args-hadolint"
rm -rf "$r"
# …and with the real hadolint (the pinned image, or a host binary): the pragma no longer hides DL3008.
if have_tool hadolint; then
  r=$(scope_repo); mkdir -p "$r/results"
  printf 'FROM debian:12\n# hadolint ignore=DL3008\nRUN apt-get update && apt-get install -y curl\n' > "$r/Dockerfile"
  (cd / && PROJECT_ROOT="$r" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-hadolint.sh" >/dev/null 2>&1)
  codes=$(jq -r '[.[].code] | join(" ")' "$r/results/hadolint.json" 2>/dev/null)
  if has " $codes " ' DL3008 '; then _pass "real hadolint: a '# hadolint ignore=DL3008' line in the checkout hides nothing ($codes)"
  else _fail "real hadolint: the checkout's ignore pragma hides nothing" "codes: '$codes'"; fi
  rm -rf "$r"
else echo "  NOTE: no hadolint and no Docker on this host — the fake-tool case above is the test; this one adds evidence where it can"; fi
# checkov (gate run 2, N-03): it reads .checkov.yaml from its working directory and from a directory
# it is given, and --config-file does not displace either (checked on bridgecrew/checkov:3.2.334). A
# checkout's .checkov.yaml could skip any check, or load external checks, which are Python. So
# checkov runs over a copy of the checkout that holds no .checkov.y(a)ml, with the bot's own file.
r=$(scope_repo); mkdir -p "$r/results" "$r/deploy" "$r/infra/chart/templates" "$r/bin"
printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n' > "$r/deploy/app.yaml"
printf 'apiVersion: v2\nname: x\nversion: 0.1.0\n' > "$r/infra/chart/Chart.yaml"
printf 'skip-check:\n  - CKV_K8S_21\n' > "$r/.checkov.yaml"; cp "$r/.checkov.yaml" "$r/infra/chart/.checkov.yml"; cp "$r/.checkov.yaml" "$r/deploy/.checkov.yaml"
cat > "$r/bin/checkov" <<FAKE
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$r/args-checkov"
find . -name '.checkov.y*ml' >> "$r/seen-checkov-config"
pwd >> "$r/cwd-checkov"
echo '{"results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[]},"summary":{"passed":0,"failed":0,"skipped":0,"parsing_error":0,"resource_count":1}}'
FAKE
chmod +x "$r/bin/checkov"
(cd / && PROJECT_ROOT="$r" SCAN_ENGINE=native PATH="$r/bin:$PATH" SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-checkov.sh" >/dev/null 2>&1)
every_call "checkov: every call names the bot's config file" "$r/args-checkov" "--config-file $CFG/checkov.yaml"
expect "checkov: it ran twice (the chart and the manifest)" "$(cat "$r/args-checkov" 2>/dev/null)" test "$(grep -c . "$r/args-checkov" 2>/dev/null)" = 2
expect "checkov: no .checkov.yaml or .checkov.yml is where checkov runs" "seen: $(cat "$r/seen-checkov-config" 2>/dev/null)" test ! -s "$r/seen-checkov-config"
refuse "checkov: it does not run in the checkout itself" "cwd: $(cat "$r/cwd-checkov" 2>/dev/null)" grep -qxF "$r" "$r/cwd-checkov"
expect "checkov: the checkout's own files are left as they were" "missing" test -f "$r/.checkov.yaml" -a -f "$r/deploy/.checkov.yaml"
rm -rf "$r"
if have_tool checkov; then
  r=$(scope_repo); mkdir -p "$r/results" "$r/deploy"
  printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  containers:\n  - name: c\n    image: nginx\n' > "$r/deploy/app.yaml"
  printf 'skip-check:\n  - CKV_K8S_21\n' > "$r/.checkov.yaml"
  (cd / && PROJECT_ROOT="$r" CHECKOV_JUSTIFICATIONS=/nonexistent SCAN_RESULTS_DIR="$r/results" timeout 600 bash "$SCAN_DIR/run-checkov.sh" >/dev/null 2>&1)
  n=$(jq '[.results.failed_checks[] | select(.check_id == "CKV_K8S_21")] | length' "$r/results/checkov.json" 2>/dev/null)
  if [ "${n:-0}" -ge 1 ]; then _pass "real checkov: a .checkov.yaml in the checkout skips nothing (CKV_K8S_21 still fails)"
  else _fail "real checkov: a .checkov.yaml in the checkout skips nothing" "CKV_K8S_21 failures: '${n:-none}'"; fi
  rm -rf "$r"
else echo "  NOTE: no checkov and no Docker on this host — the fake-tool case above is the test; this one adds evidence where it can"; fi
# npm audit (gate run 3, N-01): it ran inside the PR's app directory, so a committed .npmrc
# (registry=, omit=, a proxy, a CA) chose the server the audit asked: one answering {} turned a
# FAIL into a PASS with a 'ran' receipt. The audit now runs on a copy of the app's manifests with
# no .npmrc, the registry and the dependency types named on the command line, the bot's own empty
# user and global config, and no npm_config_* variable in its environment.
r=$(scope_repo); mkdir -p "$r/web" "$r/results" "$r/bin"
printf '{"name":"w","version":"1.0.0"}\n' > "$r/web/package.json"; printf '{"lockfileVersion":3,"packages":{}}\n' > "$r/web/package-lock.json"
printf 'registry=http://127.0.0.1:9/\nomit=dev\naudit=false\n' > "$r/web/.npmrc"; cp "$r/web/.npmrc" "$r/.npmrc"
cat > "$r/bin/npm" <<FAKE
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$r/args-npm"; pwd >> "$r/cwd-npm"
[ -e .npmrc ] && echo present >> "$r/npmrc-seen"; env | grep -i '^npm_config_' >> "$r/env-npm"
echo '{"vulnerabilities":{},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}'
FAKE
chmod +x "$r/bin/npm"
(cd / && npm_config_registry=http://127.0.0.1:9/ NPM_CONFIG_USERCONFIG=/nonexistent PATH="$r/bin:$PATH" NPM_AUDIT_ROOT="$r" SCAN_TRACK=web SCAN_RESULTS_DIR="$r/results" bash "$SCAN_DIR/run-npm-audit.sh" >/dev/null 2>&1)
NCFG="$MODULE_DIR/scan-config"
every_call "npm-audit: every audit names the public registry on the command line" "$r/args-npm" "--registry=https://registry.npmjs.org/"
every_call "npm-audit: every audit reads the bot's empty user config" "$r/args-npm" "--userconfig=$NCFG/npm-userconfig"
every_call "npm-audit: every audit reads the bot's empty global config" "$r/args-npm" "--globalconfig=$NCFG/npm-globalconfig"
every_call "npm-audit: every audit includes optional and peer dependencies" "$r/args-npm" "--include=optional --include=peer"
expect "npm-audit: the full pass includes dev dependencies, the production pass omits them" "$(cat "$r/args-npm" 2>/dev/null)" \
  test "$(grep -c -- '--include=dev' "$r/args-npm" 2>/dev/null)" = 1 -a "$(grep -c -- '--omit=dev' "$r/args-npm" 2>/dev/null)" = 1
expect "npm-audit: no .npmrc is where npm audit runs" "seen" test ! -s "$r/npmrc-seen"
refuse "npm-audit: it does not run in the PR's app directory" "cwd: $(cat "$r/cwd-npm" 2>/dev/null)" grep -qxF "$r/web" "$r/cwd-npm"
expect "npm-audit: no npm_config_* variable reaches npm" "env: $(cat "$r/env-npm" 2>/dev/null)" test ! -s "$r/env-npm"
expect "npm-audit: the checkout's .npmrc is left as it was" "missing" test -f "$r/web/.npmrc"
rm -rf "$r"
# npm audit (adapter-gitlab gate run 4, B-01): the staged copy held only the app's root manifests, so
# an npm workspace member's or a `file:`-linked package's own package.json was missing. The full
# pass still saw their dependencies through the lockfile, but the --omit=dev pass did not, so a
# production High in a workspace member was graded dev-only and passed. Now every local package
# the lockfile names is staged at its own path, and one that cannot be staged (outside the app, a
# symlink, no manifest) makes the production pass unusable: every advisory grades as production.
ws_repo() {   # ws_repo <lockfile local path> — an app 'web' whose lockfile names one local package
  local r; r=$(scope_repo); mkdir -p "$r/web" "$r/results" "$r/bin"
  printf '{"name":"root","version":"1.0.0","private":true,"workspaces":["%s"]}\n' "$1" > "$r/web/package.json"
  printf '{"name":"root","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","workspaces":["%s"]},"%s":{"name":"a","version":"1.0.0","dependencies":{"lodash":"4.17.15"}},"node_modules/a":{"resolved":"%s","link":true},"node_modules/lodash":{"version":"4.17.15"}}}\n' "$1" "$1" "$1" > "$r/web/package-lock.json"
  # The full pass answers a High; the production pass answers clean unless the member's manifest
  # was staged — exactly what the real npm does when the workspace member is missing.
  cat > "$r/bin/npm" <<FAKE
#!/usr/bin/env bash
find . -name package.json | sort >> "$r/staged"
case " \$* " in
  *" --omit=dev "*) if [ -f ./$1/package.json ]; then printf '%s' '$NA_HIGH'; else printf '%s' '$NA_CLEAN'; fi ;;
  *) printf '%s' '$NA_HIGH' ;;
esac
FAKE
  chmod +x "$r/bin/npm"; printf '%s' "$r"
}
ws_graded() {   # ws_graded <repo> <true|false> — web's High blocks, and the production pass was graded as said
  [ "$(jq '[.blocking[] | select(.app == "web")] | length' "$1/results/audit.json" 2>/dev/null)" -ge 1 ] 2>/dev/null \
    && [ "$(jq '[.apps[] | select(.app == "web") | .prod_graded][0]' "$1/results/audit.json" 2>/dev/null)" = "$2" ]
}
ws_run() {   # ws_run <repo> → WS_RC
  WS_RC=0; (cd / && PATH="$1/bin:$PATH" NPM_AUDIT_ROOT="$1" NPM_AUDIT_ALLOWLIST=/nonexistent SCAN_TRACK=web SCAN_RESULTS_DIR="$1/results" bash "$SCAN_DIR/run-npm-audit.sh" >"$1/out" 2>&1) || WS_RC=$?
}
r=$(ws_repo packages/a); mkdir -p "$r/web/packages/a"
printf '{"name":"a","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}\n' > "$r/web/packages/a/package.json"
ws_run "$r"
expect "npm-audit: a workspace member's package.json is staged at its own path" "staged: $(cat "$r/staged" 2>/dev/null)" grep -qxF ./packages/a/package.json "$r/staged"
expect "npm-audit: a workspace member's production High blocks" "rc $WS_RC · $(cat "$r/out")" \
  ws_graded "$r" true
rm -rf "$r"
r=$(ws_repo ../shared); mkdir -p "$r/shared"; printf '{"name":"a","version":"1.0.0"}\n' > "$r/shared/package.json"
printf '{}\n' > "$r/shared/package-lock.json"   # its own app here; the case below has no lockfile
ws_run "$r"
expect "npm-audit: a local package outside the app grades every advisory as production (fail-safe)" "rc $WS_RC · $(cat "$r/out")" \
  ws_graded "$r" false
refuse "npm-audit: …and nothing outside the app is staged" "staged: $(cat "$r/staged" 2>/dev/null)" grep -q shared "$r/staged"
rm -rf "$r"
r=$(ws_repo packages/a); e=$(mktemp -d); mkdir -p "$r/web/packages/a"
printf '{"name":"a","version":"1.0.0"}\n' > "$e/package.json"; ln -s "$e/package.json" "$r/web/packages/a/package.json"
ws_run "$r"; rm -rf "$e"
expect "npm-audit: a symlinked member manifest is not followed, and grades fail-safe" "rc $WS_RC · $(cat "$r/out")" \
  ws_graded "$r" false
rm -rf "$r"
r=$(ws_repo packages/a); ws_run "$r"
expect "npm-audit: a member the lockfile names but the checkout lacks grades fail-safe" "rc $WS_RC · $(cat "$r/out")" \
  ws_graded "$r" false
rm -rf "$r"
# scanners run 5, B-1: a package outside the app is staged nowhere and npm writes none of its
# dependencies into the claiming lockfile, so it is never "audited through" that app: without a
# lockfile of its own it fails, as before b99b1ee (which skipped it, and its production High passed).
r=$(ws_repo ../shared); mkdir -p "$r/shared"; printf '{"name":"a","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}\n' > "$r/shared/package.json"
ws_run "$r"
expect "npm-audit: a local package outside the app, with no lockfile of its own, still fails the scan (run 5, B-1)" "rc $WS_RC · $(cat "$r/out")" \
  test "$WS_RC" = 1
expect "npm-audit: …naming it as an app with no lockfile" "$(cat "$r/out")" grep -q 'shared/package.json: no package-lock.json beside it' "$r/out"
rm -rf "$r"
# A lockfile key carrying a newline: read line by line, it would become two paths, the second
# (`../shared`) unchecked and copied outside the staging directory. The key is refused whole.
r=$(ws_repo packages/a); mkdir -p "$r/web/packages/a" "$r/shared"
printf '{"name":"a","version":"1.0.0"}\n' > "$r/web/packages/a/package.json"; printf '{"name":"s","version":"1.0.0"}\n' > "$r/shared/package.json"
printf '{}\n' > "$r/shared/package-lock.json"
jq '.packages["packages/a\n../shared"] = {"name":"x"}' "$r/web/package-lock.json" > "$r/l" && mv "$r/l" "$r/web/package-lock.json"
ws_run "$r"
expect "npm-audit: a lockfile key with a newline in it is refused whole, and grades fail-safe" "rc $WS_RC · $(cat "$r/out")" \
  ws_graded "$r" false
rm -rf "$r"
# A v1 lockfile names a file: dependency by version, with no path to stage: fail-safe.
r=$(ws_repo packages/a); mkdir -p "$r/web/packages/a"
printf '{"name":"a","version":"1.0.0"}\n' > "$r/web/packages/a/package.json"
printf '{"name":"root","lockfileVersion":1,"requires":true,"dependencies":{"a":{"version":"file:packages/a"},"lodash":{"version":"4.17.15"}}}\n' > "$r/web/package-lock.json"
ws_run "$r"
# The member is claimed by nobody (no path), so it also fails for its missing lockfile: closed twice.
expect "npm-audit: a v1 lockfile with a file: dependency grades fail-safe" "rc $WS_RC · $(cat "$r/out")" \
  test "$WS_RC" = 1 -a "$(grep -c '^\[npm-audit\] web: a local package its lockfile names' "$r/out")" = 1
rm -rf "$r"
# npm-shrinkwrap.json wins over package-lock.json, in npm and here: a harmless package-lock.json
# beside it must not decide what is staged.
r=$(ws_repo packages/a); mkdir -p "$r/web/packages/a"
printf '{"name":"a","version":"1.0.0"}\n' > "$r/web/packages/a/package.json"
jq '.packages["../outside"] = {"name":"o"}' "$r/web/package-lock.json" > "$r/web/npm-shrinkwrap.json"
ws_run "$r"
expect "npm-audit: npm-shrinkwrap.json, not package-lock.json, decides what is staged" "rc $WS_RC · $(cat "$r/out")" ws_graded "$r" false
rm -rf "$r"
# The reviewer's probe with the real npm, where it can reach the public registry: lodash 4.17.15 has
# advisories; a .npmrc pointing at a local server that answers {} must not make them disappear.
if command -v npm >/dev/null 2>&1 && timeout 20 npm view lodash@4.17.15 version --registry=https://registry.npmjs.org/ >/dev/null 2>&1; then
  r=$(scope_repo); mkdir -p "$r/web" "$r/results"
  printf '{"name":"probe","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}\n' > "$r/web/package.json"
  printf '{"name":"probe","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"probe","version":"1.0.0","dependencies":{"lodash":"4.17.15"}},"node_modules/lodash":{"version":"4.17.15","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz","integrity":"sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A=="}}}\n' > "$r/web/package-lock.json"
  cat > "$r/server.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def _r(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        open(sys.argv[2], "a").write(self.command + " " + self.path + "\n")
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(b"{}")
    do_GET = do_POST = _r
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), H); open(sys.argv[1], "w").write(str(s.server_port)); s.serve_forever()
PY
  python3 "$r/server.py" "$r/port" "$r/hits" & srv=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$r/port" ] && break; sleep 0.3; done
  printf 'registry=http://127.0.0.1:%s/\n' "$(cat "$r/port")" > "$r/web/.npmrc"
  rc=0; (cd / && NPM_AUDIT_ROOT="$r" NPM_AUDIT_ALLOWLIST=/nonexistent SCAN_TRACK=web SCAN_RESULTS_DIR="$r/results" timeout 300 bash "$SCAN_DIR/run-npm-audit.sh" >/dev/null 2>&1) || rc=$?
  kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null
  b=$(jq '.blocking | length' "$r/results/audit.json" 2>/dev/null)
  if [ "$rc" -eq 1 ] && [ "${b:-0}" -ge 1 ] && [ ! -s "$r/hits" ]; then _pass "real npm: a .npmrc pointing at a server that answers {} hides nothing (lodash 4.17.15 blocks, the server was never asked)"
  else _fail "real npm: the checkout's .npmrc cannot choose the audit server" "rc $rc · blocking '${b:-none}' · server hits: $(cat "$r/hits" 2>/dev/null)"; fi
  rm -rf "$r"
  # B-01 with the real npm: lodash 4.17.15 is a production dependency of workspace member
  # packages/a only. Before the member's manifest was staged it graded dev-only and passed.
  r=$(scope_repo); mkdir -p "$r/web/packages/a" "$r/results"
  printf '{"name":"root","version":"1.0.0","private":true,"workspaces":["packages/a"]}\n' > "$r/web/package.json"
  printf '{"name":"a","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}\n' > "$r/web/packages/a/package.json"
  printf '{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","version":"1.0.0","workspaces":["packages/a"]},"node_modules/a":{"resolved":"packages/a","link":true},"node_modules/lodash":{"version":"4.17.15","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz","integrity":"sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A=="},"packages/a":{"name":"a","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}}}\n' > "$r/web/package-lock.json"
  rc=0; (cd / && NPM_AUDIT_ROOT="$r" NPM_AUDIT_ALLOWLIST=/nonexistent SCAN_TRACK=web SCAN_RESULTS_DIR="$r/results" timeout 300 bash "$SCAN_DIR/run-npm-audit.sh" >/dev/null 2>&1) || rc=$?
  b=$(jq '[.blocking[] | select(.package == "lodash")] | length' "$r/results/audit.json" 2>/dev/null)
  if [ "$rc" -eq 1 ] && [ "${b:-0}" -ge 1 ]; then _pass "real npm: a workspace member's production lodash 4.17.15 blocks (B-01)"
  else _fail "real npm: a workspace member's production High blocks (B-01)" "rc $rc · lodash blocking '${b:-none}'"; fi
  rm -rf "$r"
else echo "  NOTE: no npm, or the public registry is unreachable here — the fake-npm case above is the test; this one adds evidence where it can"; fi
# With the real tools, where the host has them: the bot's flags really do displace the checkout's files.
# Grype's loaded configuration, and a Trivy secret scan (no vulnerability database, so no network).
if command -v grype >/dev/null 2>&1; then
  r=$(hostile_checkout)
  without=$(cd "$r" && timeout 120 grype config --load 2>/dev/null | grep -A1 '^ignore:')
  with=$(cd "$r" && timeout 120 grype --config "$CFG/grype.yaml" config --load 2>/dev/null | grep -A1 '^ignore:')
  if has "$without" 'CVE-2018-18074' && ! has "$with" 'CVE-2018-18074' && has "$with" 'ignore: \[\]'; then
    _pass "real grype: the checkout's .grype.yaml ignores a CVE, and under the bot's config it ignores nothing"
  else _fail "real grype: the bot's config displaces the checkout's" "without: $without · with: $with"; fi
  rm -rf "$r"
else echo "  NOTE: real grype not installed on this host — the fake-tool cases above are the test; this one adds evidence where it can"; fi
if command -v trivy >/dev/null 2>&1; then
  r=$(hostile_checkout); printf 'token = "ghp_%s"\n' "$(printf 'a%.0s' $(seq 1 36))" > "$r/app.txt"
  printf 'github-pat\n' >> "$r/.trivyignore"; printf 'scan:\n  skip-files: [app.txt]\n' > "$r/trivy.yaml"
  trivy_secrets() { (cd "$r" && timeout 300 trivy fs --scanners secret --skip-db-update --offline-scan --format json --quiet "$@" . 2>/dev/null | jq -c '[.Results[]?.Secrets[]?.RuleID]'); }
  without=$(trivy_secrets); with=$(trivy_secrets --config "$CFG/trivy.yaml" --ignorefile "$CFG/trivyignore" --secret-config "$CFG/trivy-secret.yaml")
  if [ "$without" = "[]" ] && [ "$with" = '["github-pat"]' ]; then
    _pass "real trivy: the checkout's ignore and config files hide a secret, and under the bot's files it is found"
  else _fail "real trivy: the bot's files displace the checkout's" "without: $without · with: $with"; fi
  rm -rf "$r"
else echo "  NOTE: real trivy not installed on this host — the fake-tool cases above are the test; this one adds evidence where it can"; fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Group 21: every planned image has its own docker-valid name (gate run 1, B-6, N-01) ==="

# image-plan.sh named an image after its directory with / turned into -, or after the checkout's own
# name at the root. svc/api and svc-api were both svc-api; a root Dockerfile and src/Dockerfile in a
# checkout mounted at /src were both src. build-images.sh tags each name:scan, so one build
# overwrote the other and that image was never scanned. Upper case was refused by docker as a tag.
DOCKER_NAME='^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$'
plan_names_ok() {   # plan_names_ok <label> <plan> <expected count>
  local names dup bad; names=$(cut -f1 <<<"$2")
  dup=$(sort <<<"$names" | uniq -d); bad=$(grep -vE "$DOCKER_NAME" <<<"$names")
  if [ "$(grep -c . <<<"$names")" = "$3" ] && [ -z "$dup" ] && [ -z "$bad" ]; then _pass "$1"
  else _fail "$1" "names: $(tr '\n' ' ' <<<"$names") · duplicated: '$dup' · not docker-valid: '$bad'"; fi
}
base=$(mktemp -d); r="$base/src"; mkdir -p "$r"; git -C "$r" init -q
mkdir -p "$r/svc/api" "$r/svc-api" "$r/src" "$r/Web/API" "$r/svc"
for d in svc/api svc-api src . Web/API; do printf 'FROM scratch\n' > "$r/$d/Dockerfile"; done
printf 'FROM scratch\n' > "$r/svc/Dockerfile.worker"; mkdir -p "$r/svc-worker"; printf 'FROM scratch\n' > "$r/svc-worker/Dockerfile"
plan=$(cd "$r" && bash "$SCAN_DIR/image-plan.sh")
plan_names_ok "image-plan: svc/api, svc-api, src/, the root of a checkout at /src, Web/API, svc/Dockerfile.worker and svc-worker/ get seven distinct docker-valid names" "$plan" 7
expect "image-plan: a name that collides with nothing stays readable (Web/API → web-api)" "plan: $plan" has "$plan" $'^web-api\tWeb/API/Dockerfile\t\\./Web/API$'
again=$(cd "$r" && bash "$SCAN_DIR/image-plan.sh")
expect "image-plan: the names are the same on every run" "first: $plan · then: $again" test "$plan" = "$again"
# …and build-images.sh tags each planned image once, so no build overwrites another.
mkdir -p "$base/bin"; printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/docker-args"\nexit 0\n' "$base" > "$base/bin/docker"; chmod +x "$base/bin/docker"
(cd "$r" && PATH="$base/bin:$PATH" bash "$SCAN_DIR/build-images.sh" >/dev/null 2>&1)
tags=$(grep -oE -- '-t [^ ]+' "$base/docker-args" 2>/dev/null | cut -d' ' -f2)
if [ "$(grep -c . <<<"$tags")" = 7 ] && [ -z "$(sort <<<"$tags" | uniq -d)" ]; then _pass "build-images: seven builds, seven distinct tags"
else _fail "build-images: seven builds, seven distinct tags" "tags: $(tr '\n' ' ' <<<"$tags")"; fi
rm -rf "$base"
# A plan that still names one image twice (a pipeline file can) is refused by build-images, named.
base=$(mktemp -d); mkdir -p "$base/bin"; printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/docker-args"\nexit 0\n' "$base" > "$base/bin/docker"; chmod +x "$base/bin/docker"
r="$base/co"; mkdir -p "$r/a" "$r/b"; git -C "$r" init -q; printf 'FROM scratch\n' > "$r/a/Dockerfile"; printf 'FROM scratch\n' > "$r/b/Dockerfile"
cat > "$r/.gitlab-ci.yml" <<'CI'
variables:
  MULTI_DOCKERFILE_PAYLOAD: |
      [{"image_name": "app", "docker_file": "a/Dockerfile", "docker_context": "a"},
       {"image_name": "app", "docker_file": "b/Dockerfile", "docker_context": "b"}]
CI
rc=0; out=$(cd "$r" && PATH="$base/bin:$PATH" bash "$SCAN_DIR/build-images.sh" 2>&1) || rc=$?
if [ "$rc" -ne 0 ] && has "$out" 'app' && ! grep -q -- '-t app:scan' "$base/docker-args" 2>/dev/null; then _pass "build-images: a plan naming one image twice is refused, named, and nothing is tagged over"
else _fail "build-images: a plan naming one image twice is refused" "rc $rc · $out · $(cat "$base/docker-args" 2>/dev/null)"; fi
rm -rf "$base"

# The guard for the guard: this whole run must not have touched the live results directory. Without
# it, a case added later that forgets SCAN_RESULTS_DIR silently corrupts a real scan again.
# Three outcomes, never two: measured and identical is the only pass. Unmeasurable says so out
# loud rather than going quiet or, worse, claiming a pass — the first cut did both on Linux.
if [ -z "$_LIVE_RESULTS" ] || [ -z "$_LIVE_BEFORE" ]; then
  _skip "the self-tests left gate-records/scan/latest untouched" \
    "no readable live results directory here — nothing to compare, so nothing is claimed"
elif _live_after="$(_live_manifest)" && [ "$_live_after" = "$_LIVE_BEFORE" ]; then
  _pass "the self-tests left gate-records/scan/latest untouched"
else
  _fail "the self-tests left gate-records/scan/latest untouched" \
    "a case wrote into the live results directory — it is missing SCAN_RESULTS_DIR (SEC-SC3-1)"
fi

echo ""
echo "════════════════════════════════════════"
TOTAL=$((PASS + FAIL + SKIP))
echo "Results: $PASS passed  $FAIL failed  $SKIP skipped  ($TOTAL total)"
echo "════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
