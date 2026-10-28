#!/usr/bin/env bash
# run-npm-audit.sh — npm registry advisories for every app dir, over ALL dependencies, as a gate
# scanner with the same contract as the container and IaC runners beside it.
#
# WHY THIS EXISTS
#   Until 2026-09-23 `npm audit` ran nowhere: not in `make check`, not in `make gate-scan`, and
#   docs/architecture/DEPENDENCY_POLICY.md §5.3 pointed at a CI stage that did not exist. The
#   policy itself is explicit — rule 3: no unresolved Critical or High; rule 7: devDependencies are
#   not exempt, they run in CI and on every developer machine. This runner is that policy, executed.
#
# WHAT IT DECIDES
#   - A High or Critical advisory REACHABLE IN THE PRODUCTION TREE, with no unexpired entry in the
#     allowlist, is BLOCKING (exit 1). Reachability comes from a second `npm audit --omit=dev` pass.
#   - A High or Critical that is dev or build-time only is reported under `dev_only`, never blocking
#     (T-ENGINE-03, 2026-10-03). It stays visible in the log, the decision file and the dispatch;
#     what changed is that it no longer needs an allowlist entry to unblock a gate. Suppressing a
#     dev advisory used to be the cheapest way past it, which hid it everywhere and expired.
#   - If the --omit=dev pass yields nothing parseable, the scanner CANNOT grade and treats every
#     advisory as production-reachable. A registry hiccup must not be why a High stops blocking.
#   - Moderate and Low are reported, in the log and in the dispatch summary, never blocking.
#   - No parseable report from `npm audit` is a scanner that DID NOT RUN, not a clean one: exit 1
#     and no audit.json, so the scan verdict (core/run scan-verdict) counts it as missing. Same rule as every other runner.
#   - It never runs `npm audit fix`. The scan describes the committed tree that the scan verdict (core/run scan-verdict) stamps;
#     `make audit-fix` is the developer command that changes the tree, and it is never called from
#     scan, gate-scan or check.
#
# INPUTS   <app>/package-lock.json for every directory in the checkout holding a package.json or a
#          package-lock.json (scan-scope.sh: node_modules, .git, dist, build, vendor, the bot's own
#          fixtures and gitignored trees excluded). `npm audit` reads the lockfile and asks the
#          registry; it needs the network, it does not need node_modules. A package.json with no
#          lockfile beside it is an app that CANNOT be audited, and fails the scan, named: nothing
#          outside backend/ is "stray", every manifest is a target.
# OUTPUTS  $RESULTS_DIR/audit-<app>.json       raw npm output, one per app (all dependencies)
#          $RESULTS_DIR/audit-<app>-prod.json  raw npm output, --omit=dev, one per app
#          $RESULTS_DIR/audit.json             normalised: apps, blocking, allowlisted, dev_only,
#                                              expired_allowlist, reported
#          $RESULTS_DIR/audit.log         human summary
# ENV      SCAN_RESULTS_DIR      results dir (default gate-records/scan/latest)
#          NPM_AUDIT_ROOT        directory holding the app dirs (default: repo root; tests use a fixture)
#          NPM_AUDIT_APPS        space-separated app dirs (default: every one the checkout holds)
#          NPM_AUDIT_ALLOWLIST   allowlist file (default docs/security/npm-audit-allowlist.yaml)
#          NPM_AUDIT_NPM         the npm to run (default npm; tests substitute a fake on PATH)
# EXIT     0 = nothing blocking · 1 = at least one blocking advisory, or the scanner did not run
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
ROOT="${NPM_AUDIT_ROOT:-$PROJECT_ROOT}"
RESULTS_DIR="${SCAN_RESULTS_DIR:-$PROJECT_ROOT/gate-records/scan/latest}"
ALLOWLIST="${NPM_AUDIT_ALLOWLIST:-$PROJECT_ROOT/docs/security/npm-audit-allowlist.yaml}"
NPM="${NPM_AUDIT_NPM:-npm}"
TODAY="$(date -u +%Y-%m-%d)"
LOG="$RESULTS_DIR/audit.log"

# shellcheck source=scan-receipt.sh
. "$SCRIPT_DIR/scan-receipt.sh"

# FIRST, before any check that can exit: drop this run's receipt. A runner that bails out early —
# tool missing, Docker down, jq absent — must not leave the PREVIOUS run's receipt behind, or the
# verdict counts a scanner that did not run this time and reads last run's result file as current.
# Found while closing SEC-SC2-1: 2 exit path(s) in this script precede the checks below.
scan_begin npm-audit

say() { printf '%s\n' "$*" | tee -a "$LOG"; }

if ! command -v jq >/dev/null 2>&1; then
  echo "[npm-audit] FAIL — jq is required. The scanner did not run."; exit 1
fi
# ── Android track: no npm app dir exists, by design ──────────────────────────
# A declared empty scope, the way run-hadolint.sh handles a repo with no Dockerfiles: the decision
# file is written (empty, valid) and the receipt says "none" so gate-line counts the scanner as
# having run and names the empty scope in the verdict. Not a skip: a skip reads as clean. Gradle
# dependencies are run-trivy.sh's and run-grype.sh's job on this track.
# shellcheck source=scan-track.sh
. "$SCRIPT_DIR/scan-track.sh"
if [ "$(scan_track "$ROOT")" = android ]; then
  mkdir -p "$RESULTS_DIR"; : > "$LOG"
  jq -n --arg today "$TODAY" '{ scanner: "npm-audit", generated: $today,
    policy: "not applicable on the android track — no npm app dir; Gradle dependencies are scanned by trivy fs and grype dir",
    apps: [], blocking: [], allowlisted: [], dev_only: [], expired_allowlist: [], reported: [] }' > "$RESULTS_DIR/audit.json"
  say "[npm-audit] NOT APPLICABLE on the android track — no npm app dir here. Gradle dependencies are scanned by trivy and grype."
  scan_none npm-audit "not applicable on the android track (no npm app dir)"
  exit 0
fi
# ── Every npm app in the checkout ─────────────────────────────────────────────
# A directory holding a package.json or a package-lock.json, anywhere (scan-scope.sh). None at
# all is a declared empty scope: a valid empty decision file and a "none" receipt, named in the
# verdict, never a skip. A package.json WITHOUT a lockfile fails below: that is an app this
# scanner cannot audit, not an empty scope. Python, Go and other manifests are pip-audit's,
# grype's and trivy's.
# shellcheck source=scan-scope.sh
. "$SCRIPT_DIR/scan-scope.sh"
APPS="${NPM_AUDIT_APPS:-$(scan_target_dirs "$ROOT" -name package.json -o -name package-lock.json | tr '\n' ' ')}"
APPS="${APPS% }"
if [ -z "$APPS" ]; then
  mkdir -p "$RESULTS_DIR"; : > "$LOG"
  jq -n --arg today "$TODAY" --arg pruned "$(scan_scope_pruned)" '{ scanner: "npm-audit", generated: $today,
    policy: ("nothing in scope — no package.json or package-lock.json anywhere in the checkout (" + $pruned + " excluded)"),
    apps: [], blocking: [], allowlisted: [], dev_only: [], expired_allowlist: [], reported: [] }' > "$RESULTS_DIR/audit.json"
  say "[npm-audit] NOTHING IN SCOPE — no package.json or package-lock.json anywhere in the checkout ($(scan_scope_pruned) excluded). No npm dependency tree to audit."
  scan_none npm-audit "no npm app (no package.json in the checkout)"
  exit 0
fi
if ! command -v "$NPM" >/dev/null 2>&1; then
  echo "[npm-audit] FAIL — '$NPM' not found on PATH. The scanner did not run."; exit 1
fi

mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR/audit.json" "$RESULTS_DIR"/audit-*.json
: > "$LOG"

# ── Allowlist → JSON [{id, package, expires}] ─────────────────────────────────
# Line-based on purpose: the toolchain has no YAML parser, and the format is four scalar keys per
# entry (id, package, reason, owner, expires). Anything fancier than that belongs in a script that
# validates the file, not in the scanner. An entry with no `expires:` never suppresses anything.
# (`expiry`, not `exp`: `exp` is awk's built-in function and macOS awk rejects it as a variable.)
allow_json='[]'
if [ -f "$ALLOWLIST" ]; then
  allow_json=$(awk '
    function clean(v) { sub(/^[^:]*:[[:space:]]*/, "", v); gsub(/["\047]/, "", v); sub(/[[:space:]]+#.*$/, "", v); sub(/[[:space:]]+$/, "", v); return v }
    function emit() { if (id != "") printf "%s\t%s\t%s\n", id, pkg, expiry }
    /^[[:space:]]*-[[:space:]]*id:/  { emit(); id = clean($0); pkg = ""; expiry = ""; next }
    /^[[:space:]]*package:/          { pkg = clean($0); next }
    /^[[:space:]]*expires:/          { expiry = clean($0); next }
    END { emit() }' "$ALLOWLIST" \
    | jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {id: .[0], package: .[1], expires: (.[2] // "")})')
fi

# ── The audit asks the registry the bot names, never one the checkout names ───
# Until gate run 3 (N-01) `npm audit` ran inside the PR's app directory, so a committed .npmrc chose
# the server it asked (registry=), what it graded (omit=), and how it got there (a proxy, a CA): a
# local server answering {} turned lodash 4.17.15's FAIL into a PASS with a 'ran' receipt. Now:
#   - the audit runs on a COPY of the app's package.json, package-lock.json and npm-shrinkwrap.json
#     (and the package.json of each workspace member or file: link its lockfile names, at its own
#     path — see stage_app), in a directory with no .npmrc, so no project config exists at all — npm has keys with no fixed
#     flag (per-scope and per-host ones) and its key list moves between versions, so naming flags
#     alone could never be shown complete;
#   - the registry and the dependency types the grading below expects are on the command line,
#     which beats every config file and variable;
#   - the user and global config are the bot's own empty files (scanners/scan-config);
#   - no npm_config_* variable, in any case, reaches npm.
# The trade-off: a project whose dependencies live on a private registry is audited against the
# public one, where its private packages have no advisories. That needs a bot-level setting, later.
NPM_REGISTRY="https://registry.npmjs.org/"
NPM_CFG="$(cd "$SCRIPT_DIR/../scan-config" && pwd)"
NPM_OWN=(--registry="$NPM_REGISTRY" --userconfig="$NPM_CFG/npm-userconfig" --globalconfig="$NPM_CFG/npm-globalconfig")
for v in $(compgen -e); do
  case "$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')" in npm_config_*) unset "$v" ;; esac
done
# The local packages an app's lockfile names — npm workspace members and `file:` links — one path
# per line, relative to the app (adapter-gitlab gate run 4, B-01). Exit 2 when it names one this
# scanner will not stage: a path with an empty, `.` or `..` segment (absolute, or leaving the app,
# or not a plain path), or with a control character (a newline would split one key into two paths
# read line by line here, the second unchecked), or a v1 lockfile with a `file:` or `link:`
# version, which names no path at all. npm-shrinkwrap.json wins over package-lock.json, as in npm.
lock_locals() {   # lock_locals <app dir>
  local lock="" f p bad=0
  for f in npm-shrinkwrap.json package-lock.json; do
    if [ -f "$1/$f" ]; then lock="$1/$f"; break; fi
  done
  [ -n "$lock" ] || return 0
  while IFS= read -r p; do
    if [ "$p" = BAD ]; then bad=1; else printf '%s\n' "$p"; fi
  done < <(jq -r '
    if .packages == null then (if (tostring | test("\"(file|link):")) then "BAD" else empty end)
    else .packages | keys[] | select(. != "" and (split("/") | any(. == "node_modules") | not))
         | if test("[[:cntrl:]]") or (split("/") | any(. == "" or . == "." or . == ".."))
           then "BAD" else . end
    end' "$lock" 2>/dev/null)
  [ "$bad" -eq 0 ] || return 2
}
# The checkout directories some app's lockfile claims as a local package, relative to $ROOT, one
# per line. A claimed directory with no lockfile of its own is audited through the app that claims
# it, not failed for lacking one — every npm workspace member is shaped like that. Only what
# lock_locals would stage is claimed: a path inside the app. A package outside it (`../shared`)
# is not staged, and npm writes none of its dependencies into the claiming lockfile, so it is
# audited nowhere unless it is its own app (scanners run 5, B-1): it fails for its missing
# lockfile, as before.
lock_claims() {   # lock_claims <app>…
  local app p
  for app in "$@"; do
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      if [ "$app" = . ]; then printf '%s\n' "$p"; else printf '%s\n' "$app/$p"; fi
    done < <(lock_locals "$ROOT/$app")
  done
}
stage_app() {   # stage_app <app dir> — prints a fresh directory holding only the app's manifests and
                # those of the local packages its lockfile names. Exit 2: staged, but one of those
                # could not be (see lock_locals; also a symlink anywhere on its path, or no
                # package.json there), so the production pass cannot be trusted. Exit 1: nothing staged.
  local s f p q seg partial=0 locals segs
  s=$(mktemp -d) || return 1
  for f in package.json package-lock.json npm-shrinkwrap.json; do
    if [ -f "$1/$f" ]; then cp "$1/$f" "$s/$f" || { rm -rf "$s"; return 1; }; fi
  done
  locals=$(lock_locals "$1") || partial=1
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    q="$1"; IFS=/ read -ra segs <<<"$p/package.json"
    for seg in "${segs[@]}"; do
      q="$q/$seg"
      if [ -L "$q" ]; then partial=1; continue 2; fi
    done
    if [ ! -f "$q" ]; then partial=1; continue; fi
    { mkdir -p "$s/$p" && cp "$q" "$s/$p/package.json"; } || { rm -rf "$s"; return 1; }
  done <<<"$locals"
  printf '%s' "$s"
  [ "$partial" -eq 0 ] || return 2
}

# ── One `npm audit --json` per app ───────────────────────────────────────────
ran=0; failed=0; apps_json='[]'
read -ra APP_LIST <<<"$APPS"
CLAIMED=$(lock_claims "${APP_LIST[@]}")
for app in $APPS; do
  dir="$ROOT/$app"
  if [ ! -f "$dir/package-lock.json" ] && grep -qxF -- "$app" <<<"$CLAIMED"; then
    say "[npm-audit] $app: a local package another app's lockfile names (a workspace member or a file: link) — audited through that app."
    continue
  fi
  if [ ! -f "$dir/package-lock.json" ]; then
    say "[npm-audit] FAIL — $app/package.json: no package-lock.json beside it, so its dependency tree cannot be audited. Commit the lockfile (npm install --package-lock-only). The scanner did not run."
    failed=1
    continue
  fi
  slug="${app//\//-}"   # tools/site → tools-site: one raw file per app, flat
  raw="$RESULTS_DIR/audit-$slug.json"
  # npm's exit code says "vulnerabilities exist", which the report already says; the JSON is what
  # matters. stderr goes to the log so a registry failure is readable, not swallowed.
  staged=0; stage=$(stage_app "$dir") || staged=$?
  if [ "$staged" -ne 0 ] && [ "$staged" -ne 2 ]; then
    say "[npm-audit] FAIL — $app: could not stage a copy of its manifests to audit. The scanner did not run."
    failed=1
    continue
  fi
  (cd "$stage" && "$NPM" audit --json "${NPM_OWN[@]}" --include=dev --include=optional --include=peer > "$raw" 2>>"$LOG")
  if ! jq -e '.metadata.vulnerabilities' "$raw" >/dev/null 2>&1; then
    say "[npm-audit] FAIL — $app: npm audit produced no parseable report (see $LOG). The scanner did not run."
    rm -rf "$stage"
    failed=1
    continue
  fi
  # T-ENGINE-03 / GOV-030: a SECOND pass over the production tree only. An advisory that appears
  # here is reachable in something that ships and blocks; one that appears only in the full report
  # is dev or build-time and is reported instead.
  #
  # FAIL-SAFE, and the direction matters: if this pass produces nothing parseable, the scanner
  # cannot tell dev from production, so `prod_graded` is false and EVERY advisory is treated as
  # production-reachable. A registry hiccup must never be the reason a High stops blocking.
  prodraw="$RESULTS_DIR/audit-$slug-prod.json"
  #
  # A local package that could not be staged has no manifest in the copy, so npm drops its
  # dependencies from the production tree: its production High would read as dev-only. The pass
  # is not run at all, and the same fail-safe applies.
  if [ "$staged" -eq 2 ]; then
    rm -rf "$stage"
    prod_graded=false
    say "[npm-audit] $app: a local package its lockfile names (a workspace member or a file: link) could not be staged — outside the app, a symlink, or no package.json — so grading every advisory as production-reachable (fail-safe)."
    prodraw=/dev/null
  else
    (cd "$stage" && "$NPM" audit --omit=dev --json "${NPM_OWN[@]}" --include=optional --include=peer > "$prodraw" 2>>"$LOG")
    rm -rf "$stage"
    if jq -e '.metadata.vulnerabilities' "$prodraw" >/dev/null 2>&1; then
      prod_graded=true
    else
      prod_graded=false
      say "[npm-audit] $app: the --omit=dev pass produced no parseable report — grading every advisory as production-reachable (fail-safe)."
      prodraw=/dev/null
    fi
  fi
  ran=$((ran + 1))
  # Advisories are the `via` objects: each carries its own id (the last path segment of the GitHub
  # advisory URL), severity and range. A `via` string is a dependency that merely depends on a
  # vulnerable package — reported by npm as a separate entry, but not an advisory of its own.
  apps_json=$(jq -n --arg app "$app" --slurpfile raw "$raw" --slurpfile prod "$prodraw" \
                    --argjson graded "$prod_graded" --argjson apps "$apps_json" '
    # Keys present in the PRODUCTION tree, as "<advisory id>|<package>" — the same identity the
    # full pass builds below, so the two are comparable.
    ([ ($prod[0].vulnerabilities // {}) | to_entries[] | .key as $pkg | .value as $v
       | ($v.via // [])[] | select(type == "object")
       | ((.url // "" | split("/") | last) + "|" + $pkg) ] | unique) as $prodkeys
    | $apps + [{
      app: $app,
      prod_graded: $graded,
      prod_counts: ($prod[0].metadata.vulnerabilities // null),
      counts: $raw[0].metadata.vulnerabilities,
      advisories: ([ $raw[0].vulnerabilities | to_entries[] | .key as $pkg | .value as $v
                     | ($v.via // [])[] | select(type == "object")
                     | { app: $app,
                         id: (.url // "" | split("/") | last),
                         url: (.url // ""),
                         severity: (.severity // "unknown"),
                         package: $pkg,
                         range: (.range // ""),
                         title: (.title // ""),
                         direct: ($v.isDirect // false),
                         fix: ($v.fixAvailable
                               | if type == "object" then "\(.name)@\(.version)" + (if .isSemVerMajor then " (major)" else "" end)
                                 elif . == true then "available" else "none" end),
                         prod: (if $graded
                                then (((.url // "" | split("/") | last) + "|" + $pkg) as $k
                                      | ($prodkeys | index($k)) != null)
                                else true end) } ]
                   | unique_by(.id + "|" + .package)) }]')
done

[ "$failed" -eq 0 ] || exit 1
if [ "$ran" -eq 0 ]; then
  say "[npm-audit] FAIL — no app with a package-lock.json under $ROOT (found: $APPS). The scanner did not run."
  exit 1
fi

# ── Decide ───────────────────────────────────────────────────────────────────
# High and Critical block unless allowlisted with an expiry that has not passed. The comparison is
# on ISO dates as strings, which orders correctly for YYYY-MM-DD.
jq -n --argjson apps "$apps_json" --argjson allow "$allow_json" --arg today "$TODAY" '
  def rank: {critical: 4, high: 3, moderate: 2, low: 1, info: 0}[.] // 0;
  # A date the scanner cannot read is not an expiry. Lexical >= only orders correctly for a real
  # ISO date, so the shape is checked before any comparison trusts it.
  def iso: test("^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$");
  ($apps | map(.advisories[])) as $all
  | ($allow | map(select((.expires | iso) and .expires >= $today))) as $live
  | ($allow | map(select(((.expires | iso) | not) or .expires < $today))) as $dead
  | def allowed: . as $c | any($live[]; .id == $c.id);
    # T-ENGINE-03 / GOV-030. The four buckets are mutually exclusive and every advisory lands in
    # exactly one. `prod` is set per advisory by the --omit=dev pass above and is true under the
    # fail-safe, so an advisory whose reachability could not be determined blocks as before.
    { scanner: "npm-audit",
      generated: $today,
      policy: "High and Critical block when reachable in the PRODUCTION dependency tree (DEPENDENCY_POLICY §1.1 rule 3); a High or Critical that is dev or build-time only is reported, not blocking (rule 7, amended 2026-10-03 by T-ENGINE-03); Moderate and Low are reported",
      apps: $apps,
      blocking:    [ $all[] | select((.severity | rank) >= 3) | select(.prod) | select(allowed | not) ],
      allowlisted: [ $all[] | select((.severity | rank) >= 3) | select(.prod) | select(allowed) ],
      dev_only:    [ $all[] | select((.severity | rank) >= 3) | select(.prod | not) ],
      expired_allowlist: $dead,
      reported:    [ $all[] | select((.severity | rank) < 3) ] }' > "$RESULTS_DIR/audit.json" 2>>"$LOG"

# The decision file is the scanner's output; if it did not get written, nothing downstream may
# read an absent file as "no findings".
if ! jq -e '.blocking' "$RESULTS_DIR/audit.json" >/dev/null 2>&1; then
  rm -f "$RESULTS_DIR/audit.json"
  say "[npm-audit] FAIL — could not write the decision file (see $LOG). The scanner did not run."
  exit 1
fi

# It ran, whatever it found: the receipt is written before the verdict on the findings, so a
# scanner that found something is never reported as one that did not run (gate run 1, B-1).
scan_ran npm-audit "$ran app(s)"
B=$(jq '.blocking | length' "$RESULTS_DIR/audit.json")
A=$(jq '.allowlisted | length' "$RESULTS_DIR/audit.json")
R=$(jq '.reported | length' "$RESULTS_DIR/audit.json")
E=$(jq '.expired_allowlist | length' "$RESULTS_DIR/audit.json")
D=$(jq '.dev_only | length' "$RESULTS_DIR/audit.json")
UNGRADED=$(jq -r '[.apps[] | select(.prod_graded | not) | .app] | join(", ")' "$RESULTS_DIR/audit.json")

say "[npm-audit] Results: $ran app(s) audited · $B blocking (High/Critical reachable in production, not allowlisted) · $A allowlisted · $D dev/build-only (High/Critical, reported) · $R reported (Moderate/Low, not blocking)"
[ -n "$UNGRADED" ] && say "[npm-audit] production grading UNAVAILABLE for: $UNGRADED — every advisory in those apps was treated as production-reachable (fail-safe)."
[ "$E" -gt 0 ] && say "[npm-audit] $E allowlist entr$([ "$E" -eq 1 ] && echo y || echo ies) expired, or carrying no date this scanner can read — no longer suppress anything: $(jq -r '[.expired_allowlist[].id] | join(", ")' "$RESULTS_DIR/audit.json")"
jq -r '.blocking[]    | "  BLOCKING  \(.app)  \(.id)  \(.severity)  \(.package) \(.range)  fix: \(.fix)"' "$RESULTS_DIR/audit.json" | tee -a "$LOG"
jq -r '.allowlisted[] | "  allowed   \(.app)  \(.id)  \(.severity)  \(.package) \(.range)  (allowlist entry, unexpired)"' "$RESULTS_DIR/audit.json" | tee -a "$LOG"
jq -r '.dev_only[]    | "  dev-only  \(.app)  \(.id)  \(.severity)  \(.package) \(.range)  fix: \(.fix)  (not in the production tree — reported, not blocking)"' "$RESULTS_DIR/audit.json" | tee -a "$LOG"
jq -r '.reported[]    | "  reported  \(.app)  \(.id)  \(.severity)  \(.package) \(.range)  fix: \(.fix)"' "$RESULTS_DIR/audit.json" | tee -a "$LOG"

if [ "$B" -gt 0 ]; then
  say "[npm-audit] FAIL — $B blocking advisor$([ "$B" -eq 1 ] && echo y || echo ies). Remedy: \`make audit-fix\` for a non-major fix, a manual bump for a major; one with no fix needs an allowlist entry with a reason, an owner and an expiry ($ALLOWLIST)."
  exit 1
fi
say "[npm-audit] PASS — nothing blocking"
exit 0
