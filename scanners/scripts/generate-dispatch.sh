#!/usr/bin/env bash
# Reads completed scan results and produces dispatch.md and poam-candidates.md.
# Does NOT re-run scanners.
#
# Environment variables:
#   SCAN_RESULTS_DIR  — where to read scan JSON/log files (default: gate-records/scan/latest)
#   OUTPUT_DIR        — where to write dispatch.md / poam-candidates.md (default: SCAN_RESULTS_DIR)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SCAN_RESULTS_DIR="${SCAN_RESULTS_DIR:-$PROJECT_ROOT/gate-records/scan/latest}"
OUTPUT_DIR="${OUTPUT_DIR:-$SCAN_RESULTS_DIR}"

GRYPE_JSON="$SCAN_RESULTS_DIR/grype.json"
TRIVY_JSON="$SCAN_RESULTS_DIR/trivy.json"
HADOLINT_JSON="$SCAN_RESULTS_DIR/hadolint.json"
CHECKOV_JSON="$SCAN_RESULTS_DIR/checkov.json"
CLAMAV_LOG="$SCAN_RESULTS_DIR/clamav.log"
AUDIT_JSON="$SCAN_RESULTS_DIR/audit.json"
ESLINT_JSON="$SCAN_RESULTS_DIR/eslint.json"
PIP_AUDIT_JSON="$SCAN_RESULTS_DIR/pip-audit.json"

DISPATCH_FILE="$OUTPUT_DIR/dispatch.md"
POAM_FILE="$OUTPUT_DIR/poam-candidates.md"
DISCREPANCY_LOG="$OUTPUT_DIR/discrepancy.log"

# From the engine's first project (2026-10-03, GOV-025 / T-ENGINE-07). This run's output describes THIS run.
#
# dispatch.md is written only when there is something actionable, and the scan verdict (`core/run scan-verdict`) uses its existence as
# the blocking condition. Without this, a file left by an earlier failing scan fails every later scan on the
# clone — including a scan of a genuinely clean tree — and the verdict reports the stale file's `###` count
# as "N fixable", naming findings that no longer exist. Measured twice on 2026-10-03: every scanner PASS,
# `Scan: FAIL — 2 fixable`, with the only tell being dispatch.md's mtime against the artefacts beside it.
#
# The remedy a reader reaches for is deleting a scan artefact by hand, which is indistinguishable from
# gaming the gate. `run-npm-audit.sh` already clears its own receipt on entry and has a selftest for it;
# this was the one producer that did not follow the pattern.
rm -f "$DISPATCH_FILE" "$POAM_FILE" "$DISCREPANCY_LOG"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")

if ! command -v jq >/dev/null 2>&1; then
  echo "[generate-dispatch] ERROR: jq is required. Install via brew install jq or apt install jq."
  exit 1
fi

# ─── Tracking state ───────────────────────────────────────────────────────────

amelia_blocks=""
frank_blocks=""
poam_blocks=""

has_amelia=false
has_frank=false
has_poam=false
has_clamav_infection=false

clamav_status="N/A"
hadolint_status="N/A"
checkov_status="N/A"
image_scan_status="SKIPPED"

hadolint_self_healing=0; hadolint_poam=0
checkov_self_healing=0; checkov_poam=0
image_self_healing=0;   image_poam=0
clamav_self_healing=0;  clamav_poam=0
npm_audit_status="N/A"; npm_audit_self_healing=0; npm_audit_poam=0; npm_audit_reported=0
eslint_status="N/A"; eslint_self_healing=0; eslint_poam=0
pip_audit_status="N/A"; pip_audit_self_healing=0; pip_audit_poam=0

clamav_critical_block=""

# ─── ClamAV ───────────────────────────────────────────────────────────────────

process_clamav() {
  [[ ! -f "$CLAMAV_LOG" ]] && return
  clamav_status="PASS"
  local infected_count
  infected_count=$(grep -oE 'Infected files: [0-9]+' "$CLAMAV_LOG" | grep -oE '[0-9]+' || echo "0")
  if [[ "$infected_count" -gt 0 ]]; then
    has_clamav_infection=true
    clamav_status="FAIL"
    clamav_self_healing=$infected_count
    local infected_files
    infected_files=$(grep " FOUND$" "$CLAMAV_LOG" 2>/dev/null || echo "(see clamav.log)")
    clamav_critical_block="## ClamAV — INFECTION DETECTED (CRITICAL)

\`\`\`
$infected_files
\`\`\`

**SEVERITY: CRITICAL — DO NOT COMMIT. Remove infected files before continuing.**
See \`$SCAN_RESULTS_DIR/clamav.log\` for full scan output.

"
  fi
}

# ─── Hadolint ─────────────────────────────────────────────────────────────────

process_hadolint() {
  [[ ! -f "$HADOLINT_JSON" ]] && return
  hadolint_status="PASS"
  local error_count
  error_count=$(jq '[.[] | select(.level == "error")] | length' "$HADOLINT_JSON" 2>/dev/null || echo "0")
  [[ "$error_count" -eq 0 ]] && return

  hadolint_status="FAIL"
  hadolint_self_healing=$error_count
  has_frank=true

  while IFS=$'\t' read -r file line code message; do
    [[ -z "$code" ]] && continue
    frank_blocks+="### $code — $message

- **File:** $file
- **Line:** $line
- **Severity:** error
- **Action:** Fix the hadolint violation in \`$file\` at line $line. See https://github.com/hadolint/hadolint/wiki/$code for details.

"
  done < <(jq -r '.[] | select(.level == "error") | [.file, (.line | tostring), .code, .message] | @tsv' \
    "$HADOLINT_JSON" 2>/dev/null || true)
}

# ─── Checkov ──────────────────────────────────────────────────────────────────

process_checkov() {
  [[ ! -f "$CHECKOV_JSON" ]] && return
  checkov_status="PASS"
  # Every remaining failed check is a finding: checkov-decide.sh already moved justified ones to
  # justified_checks, and checkov OSS emits no severity to filter on (T-023).
  local fail_count
  fail_count=$(jq '.results.failed_checks | length' "$CHECKOV_JSON" 2>/dev/null || echo "0")
  [[ "$fail_count" -eq 0 ]] && return

  checkov_status="FAIL"
  checkov_self_healing=$fail_count
  has_frank=true

  while IFS=$'\t' read -r check_id file line_s line_e severity description; do
    [[ -z "$check_id" ]] && continue
    frank_blocks+="### $check_id — $description

- **File:** $file
- **Line:** $line_s–$line_e
- **Severity:** $severity
- **Action:** Fix the resource; suppress a per-resource false positive with a \`checkov.io/skipN: "$check_id=reason"\` annotation; or add a bounded entry to \`docs/security/checkov-justifications.yaml\`. See https://www.checkov.io for the check.

"
  done < <(jq -r '.results.failed_checks[] |
    [
      .check_id,
      (.file_path // "?"),
      ((.file_line_range[0] // 0) | tostring),
      ((.file_line_range[1] // 0) | tostring),
      (.severity // "unrated (checkov OSS emits no severity)"),
      (.check_name // .check_description // .check_id)
    ] | @tsv' "$CHECKOV_JSON" 2>/dev/null || true)
}

# ─── npm audit (run-npm-audit.sh) ─────────────────────────────────────────────
# The runner already applied the policy: audit.json carries `blocking` (High/Critical with no
# unexpired allowlist entry), `allowlisted`, `expired_allowlist` and `reported` (Moderate/Low). This
# only turns each blocking advisory into a work block for Amelia. Absent file = scanner did not run;
# the scan verdict (core/run scan-verdict) counts that, not this.
process_npm_audit() {
  [[ ! -f "$AUDIT_JSON" ]] && return
  npm_audit_status="PASS"
  npm_audit_reported=$(jq '.reported | length' "$AUDIT_JSON" 2>/dev/null || echo "0")
  local n
  n=$(jq '.blocking | length' "$AUDIT_JSON" 2>/dev/null || echo "0")
  [[ "$n" -eq 0 ]] && return

  npm_audit_status="FAIL"
  npm_audit_self_healing=$n
  has_amelia=true

  while IFS=$'\t' read -r app id severity pkg range fix direct url title; do
    [[ -z "$id" ]] && continue
    local remedy="\`make audit-fix\`, then the app's build and suite; stage \`$app/package.json\` and \`$app/package-lock.json\` together"
    if [[ "$fix" == *"(major)"* ]]; then
      remedy="manual bump to \`$fix\` — \`npm audit fix\` does not cross a major; run the app's build and suite after"
    elif [[ "$fix" == "none" ]]; then
      remedy="no fixed version published — replace the package, or add an allowlist entry with reason, owner and expiry to \`docs/security/npm-audit-allowlist.yaml\`"
    fi
    local dep_label="transitive"
    [[ "$direct" == "true" ]] && dep_label="direct"
    amelia_blocks+="### $id — ${pkg} (${app}, ${severity})

- **Advisory:** ${title} — ${url}
- **Vulnerable range:** \`${range}\`
- **Fix available:** \`${fix}\`
- **Dependency type:** $dep_label
- **Found by:** npm audit over all dependencies, dev included (DEPENDENCY_POLICY §1.1 rules 3 and 7)
- **Action:** $remedy

"
  done < <(jq -r '.blocking[] | [.app, .id, .severity, .package, .range, .fix, (.direct | tostring), .url, .title] | @tsv' \
    "$AUDIT_JSON" 2>/dev/null || true)
}

# ─── pip-audit (run-pip-audit.sh) ─────────────────────────────────────────────
# The runner already decided: `blocking` is every vulnerability with a fix available (fixable
# work), `reported` every one without (a POAM candidate). pip-audit rates nothing, so no severity
# is shown; the Scan gate applies the profile's policy over the CVE aliases.
process_pip_audit() {
  [[ ! -f "$PIP_AUDIT_JSON" ]] && return
  pip_audit_status="PASS"
  local n
  n=$(jq '.blocking | length' "$PIP_AUDIT_JSON" 2>/dev/null || echo "0")
  if [[ "$n" -gt 0 ]]; then
    pip_audit_status="FAIL"
    pip_audit_self_healing=$n
    has_amelia=true
    while IFS=$'\t' read -r file id aliases pkg version fix; do
      [[ -z "$id" ]] && continue
      amelia_blocks+="### $id — ${pkg}@${version} (${file}, pip-audit)

- **Aliases:** ${aliases:-none}
- **Fix available:** \`${pkg}==${fix}\`
- **Found by:** pip-audit over the manifest's resolved tree (PyPI advisories, unrated)
- **Action:** pin \`${pkg}==${fix}\` in \`${file}\`, reinstall, run the suite

"
    done < <(jq -r '.blocking[] | [.file, .id, (.aliases | join(", ")), .package, .version, .fix] | @tsv' "$PIP_AUDIT_JSON" 2>/dev/null || true)
  fi
  while IFS=$'\t' read -r file id aliases pkg version; do
    [[ -z "$id" ]] && continue
    has_poam=true; pip_audit_status="FAIL"
    pip_audit_poam=$((pip_audit_poam + 1))
    poam_blocks+="## $id — $pkg

- **Aliases:** ${aliases:-none}
- **Affected component:** ${pkg}@${version} (${file}, pip-audit)
- **Fix availability:** No upstream fix available
- **Reason for POAM routing:** No fixed version released as of scan date.
- **Next step:** Follow \`engine/agent-cve-poam-guidelines.md\`.

"
  done < <(jq -r '.reported[] | [.file, .id, (.aliases | join(", ")), .package, .version] | @tsv' "$PIP_AUDIT_JSON" 2>/dev/null || true)
}

# ─── eslint (run-eslint.sh) ───────────────────────────────────────────────────
# Every message is blocking (both apps lint with --max-warnings 0). One block per file, so a file
# with forty messages is one piece of work, and the fixable count in the verdict line stays honest.
process_eslint() {
  [[ ! -f "$ESLINT_JSON" ]] && return
  eslint_status="PASS"
  local n
  n=$(jq '.blocking | length' "$ESLINT_JSON" 2>/dev/null || echo "0")
  [[ "$n" -eq 0 ]] && return

  eslint_status="FAIL"
  eslint_self_healing=$(jq '[.blocking[] | .app + "/" + .file] | unique | length' "$ESLINT_JSON" 2>/dev/null || echo "$n")
  has_amelia=true

  while IFS=$'\t' read -r app file count; do
    [[ -z "$file" ]] && continue
    local lines
    lines=$(jq -r --arg app "$app" --arg file "$file" '
      .blocking[] | select(.app == $app and .file == $file)
      | "- line \(.line):\(.column) — `\(.rule)` (\(.severity)): \(.message)"' "$ESLINT_JSON" 2>/dev/null)
    amelia_blocks+="### eslint — ${app}/${file} (${count} message$([[ "$count" -eq 1 ]] || echo s))

${lines}
- **Action:** fix every message above and re-run \`cd ${app} && npm run lint\`; both apps lint with \`--max-warnings 0\`, so warnings count.

"
  done < <(jq -r '.blocking | group_by(.app + "/" + .file)[] | [.[0].app, .[0].file, (length | tostring)] | @tsv' \
    "$ESLINT_JSON" 2>/dev/null || true)
}

# ─── Filesystem scans (android track: Grype dir + Trivy fs, union) ───────────
# On the android track run-grype.sh and run-trivy.sh scan android/ as a filesystem. The two
# catalog different things there — Trivy reads gradle.lockfile, Syft reads jars and poms — so the
# image rule "a CVE counts only when both scanners agree" would mean a Gradle CVE never counts.
# Here either scanner's word is enough. Routing is the same as for npm: a fix available blocks and
# names the Gradle remedy; no fix is a POAM candidate. A secret or a failed misconfiguration check
# Trivy finds in the tree blocks too — both are the project's own files.
process_filesystem_scans() {
  # What was scanned, for the wording: android/ on the android track, the whole repository when it
  # builds no container image (run-grype.sh and run-trivy.sh, filesystem mode).
  local fs_label
  fs_label=$( { jq -r '.source.target // empty' "$GRYPE_JSON" 2>/dev/null || true; jq -r '.ArtifactName // empty' "$TRIVY_JSON" 2>/dev/null || true; } | head -1)
  case "$fs_label" in ""|android|android/) fs_label="android/" ;; .|./) fs_label="the repository" ;; esac
  local grype_src="$GRYPE_JSON" trivy_src="$TRIVY_JSON"
  [[ -f "$grype_src" ]] || grype_src="/dev/null"
  [[ -f "$trivy_src" ]] || trivy_src="/dev/null"
  image_scan_status="PASS"

  # id \t pkg \t installed \t fixed \t severity \t type \t scanner — fixed, from either scanner
  local fixed unfixed
  fixed=$( { jq -r '.Results[]? | .Type as $t | .Vulnerabilities[]?
                     | select((.FixedVersion // "") != "")
                     | [.VulnerabilityID, .PkgName, .InstalledVersion, .FixedVersion, (.Severity // "UNKNOWN"), ($t // "fs"), "trivy"] | @tsv' \
             "$trivy_src" 2>/dev/null
           jq -r '.matches[]? | select(.vulnerability.fix.state == "fixed" and (.vulnerability.fix.versions | length) > 0)
                     | [.vulnerability.id, .artifact.name, .artifact.version, .vulnerability.fix.versions[0], (.vulnerability.severity // "Unknown"), (.artifact.type // "fs"), "grype"] | @tsv' \
             "$grype_src" 2>/dev/null; } | sort -t "$(printf '\t')" -k1,1 -u )
  unfixed=$( { jq -r '.Results[]? | .Type as $t | .Vulnerabilities[]?
                       | select((.FixedVersion // "") == "")
                       | [.VulnerabilityID, .PkgName, .InstalledVersion, (.Severity // "UNKNOWN"), ($t // "fs")] | @tsv' \
               "$trivy_src" 2>/dev/null
             jq -r '.matches[]? | select(.vulnerability.fix.state != "fixed" or (.vulnerability.fix.versions | length) == 0)
                       | [.vulnerability.id, .artifact.name, .artifact.version, (.vulnerability.severity // "Unknown"), (.artifact.type // "fs")] | @tsv' \
               "$grype_src" 2>/dev/null; } | sort -t "$(printf '\t')" -k1,1 -u )
  # An id fixed per one scanner and unfixed per the other is fixed: the scanner that knows the fix wins.
  if [[ -n "$fixed" && -n "$unfixed" ]]; then
    unfixed=$(comm -13 <(cut -f1 <<< "$fixed" | sort) <(sort -t "$(printf '\t')" -k1,1 <<< "$unfixed") 2>/dev/null \
              | awk -F'\t' 'NF >= 4' || true)
  fi

  local id pkg installed fixedv severity ptype scanner
  while IFS=$'\t' read -r id pkg installed fixedv severity ptype scanner; do
    [[ -z "$id" ]] && continue
    image_scan_status="FAIL"; has_amelia=true
    image_self_healing=$((image_self_healing + 1))
    local remedy="bump \`${pkg}\` to \`${fixedv}\` in the Gradle build file, then \`./gradlew dependencies --write-locks\` and commit \`gradle.lockfile\`; run \`./gradlew test\`"
    case "$ptype" in
      gradle|java-archive|jar|pom) ;;
      *) remedy="upgrade \`${pkg}\` to \`${fixedv}\` (${ptype}); commit the lock or manifest it lives in and run the suite" ;;
    esac
    amelia_blocks+="### $id — ${pkg}@${installed} (${severity})

- **Fix available:** \`${pkg}@${fixedv}\`
- **Found by:** ${scanner} (filesystem scan of ${fs_label}; type: ${ptype})
- **Action:** $remedy

"
  done <<< "$fixed"

  while IFS=$'\t' read -r id pkg installed severity ptype; do
    [[ -z "$id" ]] && continue
    has_poam=true; image_scan_status="FAIL"
    image_poam=$((image_poam + 1))
    poam_blocks+="## $id — $pkg

- **Severity:** $severity
- **Affected component:** ${pkg}@${installed} (type: $ptype, ${fs_label} filesystem scan)
- **Fix availability:** No upstream fix available
- **Reason for POAM routing:** No fixed version released as of scan date.
- **Next step:** Follow \`engine/agent-cve-poam-guidelines.md\`.

"
  done <<< "$unfixed"

  # Secrets and failed misconfiguration checks in the tree (Trivy fs) — the project's own files.
  local target rule title line
  while IFS=$'\t' read -r target rule title line; do
    [[ -z "$target" ]] && continue
    image_scan_status="FAIL"; has_amelia=true
    image_self_healing=$((image_self_healing + 1))
    amelia_blocks+="### SECRET — ${target}:${line} (${rule})

- **Finding:** ${title}
- **Found by:** trivy (secret scanner, android/)
- **Action:** remove the secret from the tree and its history, rotate it, and inject it at build or run time instead

"
  done < <(jq -r '.Results[]? | .Target as $t | .Secrets[]? | [$t, .RuleID, (.Title // .RuleID), ((.StartLine // 0) | tostring)] | @tsv' "$trivy_src" 2>/dev/null || true)
  while IFS=$'\t' read -r target rule title; do
    [[ -z "$target" ]] && continue
    image_scan_status="FAIL"; has_amelia=true
    image_self_healing=$((image_self_healing + 1))
    amelia_blocks+="### MISCONFIG — ${target} (${rule})

- **Finding:** ${title}
- **Found by:** trivy (misconfiguration scanner, android/)
- **Action:** fix the configuration in place; the check names what it expects

"
  done < <(jq -r '.Results[]? | .Target as $t | .Misconfigurations[]? | select(.Status == "FAIL") | [$t, .ID, (.Title // .ID)] | @tsv' "$trivy_src" 2>/dev/null || true)
}

# ─── Image scans (Grype + Trivy intersection) ─────────────────────────────────

process_image_scans() {
  local grype_present=false trivy_present=false
  [[ -f "$GRYPE_JSON" ]] && grype_present=true
  [[ -f "$TRIVY_JSON" ]] && trivy_present=true
  # Neither image scanner left a result: nothing to route here. `return 0`, not a bare `return`: a bare
  # one returns the false test before it, and under set -e that ended the whole script, so a scan whose
  # image scanners did not run never reached its verdict line.
  $grype_present || $trivy_present || return 0
  # A filesystem result (android track) is routed by its own rules above; an image result as before.
  if { $grype_present && [[ "$(jq -r '.source.type // ""' "$GRYPE_JSON" 2>/dev/null)" == "directory" ]]; } \
     || { $trivy_present && [[ "$(jq -r '.ArtifactType // ""' "$TRIVY_JSON" 2>/dev/null)" == "filesystem" ]]; }; then
    process_filesystem_scans; return
  fi
  image_scan_status="PASS"

  local grype_src="$GRYPE_JSON"
  local trivy_src="$TRIVY_JSON"
  $grype_present || grype_src="/dev/null"
  $trivy_present || trivy_src="/dev/null"

  # ── npm CVEs with fix available ───────────────────────────────────────────
  local grype_npm_fixed="" trivy_npm_fixed=""

  if $grype_present; then
    grype_npm_fixed=$(jq -r '
      .matches[]? |
      select(.artifact.type == "npm") |
      select(.vulnerability.fix.state == "fixed") |
      select((.vulnerability.fix.versions | length) > 0) |
      .vulnerability.id
    ' "$grype_src" 2>/dev/null | sort -u || true)
  fi

  if $trivy_present; then
    trivy_npm_fixed=$(jq -r '
      .Results[]? |
      select(.Type == "node-pkgs") |
      .Vulnerabilities[]? |
      select(.FixedVersion != null and .FixedVersion != "") |
      .VulnerabilityID
    ' "$trivy_src" 2>/dev/null | sort -u || true)
  fi

  local both_ids="" grype_only="" trivy_only=""
  if [[ -n "$grype_npm_fixed" && -n "$trivy_npm_fixed" ]]; then
    both_ids=$(comm -12  <(echo "$grype_npm_fixed") <(echo "$trivy_npm_fixed") 2>/dev/null || true)
    grype_only=$(comm -23 <(echo "$grype_npm_fixed") <(echo "$trivy_npm_fixed") 2>/dev/null || true)
    trivy_only=$(comm -13 <(echo "$grype_npm_fixed") <(echo "$trivy_npm_fixed") 2>/dev/null || true)
  elif [[ -n "$grype_npm_fixed" ]]; then
    grype_only="$grype_npm_fixed"
  elif [[ -n "$trivy_npm_fixed" ]]; then
    trivy_only="$trivy_npm_fixed"
  fi

  # Amelia blocks — CVEs confirmed in BOTH scanners
  while IFS= read -r cve_id; do
    [[ -z "$cve_id" ]] && continue
    image_scan_status="FAIL"
    has_amelia=true
    image_self_healing=$((image_self_healing + 1))

    local pkg="" installed="" fixed="" severity="" cvss="" dep_type=""
    local raw
    raw=$(jq -r --arg cve "$cve_id" '
      .matches[] |
      select(.vulnerability.id == $cve and .artifact.type == "npm") |
      [
        .artifact.name,
        .artifact.version,
        (.vulnerability.fix.versions[0] // "unknown"),
        .vulnerability.severity,
        ((.vulnerability.cvss[0].metrics.baseScore // "N/A") | tostring),
        (.matchDetails[0].type // "")
      ] | @tsv
    ' "$grype_src" 2>/dev/null | head -1 || true)

    if [[ -n "$raw" ]]; then
      IFS=$'\t' read -r pkg installed fixed severity cvss dep_type <<< "$raw"
    fi

    local dep_label="direct"
    if grep -qi "indirect\|transitive" <<<"$dep_type"; then
      dep_label="transitive"
    fi

    amelia_blocks+="### $cve_id — ${pkg}@${installed}

- **Fix available:** \`${pkg}@${fixed}\`
- **Severity:** $severity
- **CVSS:** $cvss
- **Found in:** Grype + Trivy (both)
- **Dependency type:** $dep_label
- **Action:** \`npm install ${pkg}@${fixed}\` — then run full test suite. Stage both \`package.json\` and \`package-lock.json\` in the remediation commit.

"
  done <<< "$both_ids"

  # Discrepancy log
  mkdir -p "$OUTPUT_DIR"
  {
    echo "# Discrepancy Log — $TIMESTAMP"
    echo ""
    echo "CVEs found by only one scanner. Excluded from dispatch.md — verify with both tools."
    echo ""
  } > "$DISCREPANCY_LOG"

  while IFS= read -r cve_id; do
    [[ -z "$cve_id" ]] && continue
    local pkg="" installed=""
    raw=$(jq -r --arg cve "$cve_id" '
      .matches[] | select(.vulnerability.id == $cve and .artifact.type == "npm") |
      [.artifact.name, .artifact.version] | @tsv
    ' "$grype_src" 2>/dev/null | head -1 || true)
    [[ -n "$raw" ]] && IFS=$'\t' read -r pkg installed <<< "$raw"
    echo "- $cve_id | ${pkg}@${installed} | found in: GRYPE only" >> "$DISCREPANCY_LOG"
  done <<< "$grype_only"

  while IFS= read -r cve_id; do
    [[ -z "$cve_id" ]] && continue
    local pkg="" installed=""
    raw=$(jq -r --arg cve "$cve_id" '
      .Results[]? | select(.Type == "node-pkgs") | .Vulnerabilities[]? |
      select(.VulnerabilityID == $cve) |
      [.PkgName, .InstalledVersion] | @tsv
    ' "$trivy_src" 2>/dev/null | head -1 || true)
    [[ -n "$raw" ]] && IFS=$'\t' read -r pkg installed <<< "$raw"
    echo "- $cve_id | ${pkg}@${installed} | found in: TRIVY only" >> "$DISCREPANCY_LOG"
  done <<< "$trivy_only"

  # ── npm CVEs with NO fix → POAM ───────────────────────────────────────────
  if $grype_present; then
    while IFS=$'\t' read -r cve_id pkg installed severity cvss; do
      [[ -z "$cve_id" ]] && continue
      has_poam=true
      image_scan_status="FAIL"
      image_poam=$((image_poam + 1))
      poam_blocks+="## $cve_id — $pkg

- **Severity:** $severity
- **CVSS:** $cvss
- **Affected component:** ${pkg}@${installed}
- **Fix availability:** No upstream fix available
- **Reason for POAM routing:** No fixed version released as of scan date.
- **Next step:** Follow \`engine/agent-cve-poam-guidelines.md\` to submit a Change Request to the platform team.

"
    done < <(jq -r '
      .matches[]? |
      select(.artifact.type == "npm") |
      select(.vulnerability.fix.state != "fixed" or (.vulnerability.fix.versions | length) == 0) |
      [
        .vulnerability.id,
        .artifact.name,
        .artifact.version,
        .vulnerability.severity,
        ((.vulnerability.cvss[0].metrics.baseScore // "N/A") | tostring)
      ] | @tsv
    ' "$grype_src" 2>/dev/null || true)
  fi

  # ── OS-level / base image layer CVEs → POAM ────────────────────────────────
  if $grype_present; then
    while IFS=$'\t' read -r cve_id pkg installed artifact_type severity cvss; do
      [[ -z "$cve_id" ]] && continue
      has_poam=true
      image_scan_status="FAIL"
      image_poam=$((image_poam + 1))
      poam_blocks+="## $cve_id — $pkg

- **Severity:** $severity
- **CVSS:** $cvss
- **Affected component:** ${pkg}@${installed} (type: $artifact_type)
- **Fix availability:** Base image layer (not patchable by application team)
- **Reason for POAM routing:** OS-level package ($artifact_type) in container image base layer; application team cannot patch OS packages inside a running image. It clears when the base image is rebuilt on a newer tag.
- **Next step:** Follow \`engine/agent-cve-poam-guidelines.md\` to submit a Change Request to the platform team.

"
    done < <(jq -r '
      .matches[]? |
      select(.artifact.type != "npm") |
      [
        .vulnerability.id,
        .artifact.name,
        .artifact.version,
        .artifact.type,
        .vulnerability.severity,
        ((.vulnerability.cvss[0].metrics.baseScore // "N/A") | tostring)
      ] | @tsv
    ' "$grype_src" 2>/dev/null || true)
  fi
}

# ─── Assemble and write output ────────────────────────────────────────────────

write_output() {
  mkdir -p "$OUTPUT_DIR"

  if $has_poam; then
    {
      echo "# POAM Candidates — $TIMESTAMP"
      echo ""
      echo "These findings require a platform team Change Request."
      echo "Follow \`engine/agent-cve-poam-guidelines.md\` for the POAM submission process."
      echo ""
      printf '%s' "$poam_blocks"
    } > "$POAM_FILE"
    echo "[generate-dispatch] Written: $POAM_FILE"
  fi

  local self_healing_exists=false
  ($has_amelia || $has_frank || $has_clamav_infection) && self_healing_exists=true

  if ! $self_healing_exists; then
    echo "[generate-dispatch] No self-healing items found — dispatch.md not written"
    return 0
  fi

  {
    echo "# Compliance Scan Dispatch — $TIMESTAMP"
    echo ""
    echo "## Summary"
    echo ""
    echo "| Tool | Status | Self-healing findings | POAM candidates |"
    echo "|---|---|---|---|"
    echo "| hadolint | $hadolint_status | $hadolint_self_healing | $hadolint_poam |"
    echo "| Checkov | $checkov_status | $checkov_self_healing | $checkov_poam |"
    echo "| ClamAV | $clamav_status | $clamav_self_healing | $clamav_poam |"
    echo "| Grype+Trivy | $image_scan_status | $image_self_healing | $image_poam |"
    echo "| npm audit | $npm_audit_status | $npm_audit_self_healing | $npm_audit_poam |"
    echo "| eslint | $eslint_status | $eslint_self_healing | $eslint_poam |"
    echo "| pip-audit | $pip_audit_status | $pip_audit_self_healing | $pip_audit_poam |"
    [[ "$npm_audit_reported" -gt 0 ]] && echo "" && echo "npm audit also reported $npm_audit_reported Moderate/Low advisor$([[ "$npm_audit_reported" -eq 1 ]] && echo y || echo ies) — not blocking, listed in \`audit.log\`."
    echo ""

    if $has_clamav_infection; then
      printf '%s' "$clamav_critical_block"
    fi

    if $has_amelia; then
      echo "## Amelia — npm, PyPI and lint remediation"
      echo ""
      printf '%s' "$amelia_blocks"
    fi

    if $has_frank; then
      echo "## Frank — Dockerfile / Helm / Terraform Remediation"
      echo ""
      printf '%s' "$frank_blocks"
    fi

    if $has_poam; then
      echo "## POAM Candidates (No Self-Healing — Manual Review Required)"
      echo ""
      echo "See \`gate-records/scan/latest/poam-candidates.md\` for the full list."
      echo "Follow \`engine/agent-cve-poam-guidelines.md\` for POAM submission process."
      echo ""
    fi

    echo "---"
    echo ""
    echo "## How to Trigger Agent Remediation"
    echo ""
    echo "Paste this file into a new Claude Code session. Bob will dispatch Amelia for npm findings"
    echo "and Frank for Dockerfile/Helm/Terraform findings. User must say \"approved\" before any"
    echo "patch is committed."
  } > "$DISPATCH_FILE"

  echo "[generate-dispatch] Written: $DISPATCH_FILE"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

process_clamav
process_hadolint
process_checkov
process_npm_audit
process_eslint
process_pip_audit
process_image_scans
write_output
