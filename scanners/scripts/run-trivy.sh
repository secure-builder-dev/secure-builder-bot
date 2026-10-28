#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
RESULTS_DIR="${SCAN_RESULTS_DIR:-$PROJECT_ROOT/gate-records/scan/latest}"

# shellcheck source=tool-runner.sh
. "$SCRIPT_DIR/tool-runner.sh"
# shellcheck source=scan-receipt.sh
. "$SCRIPT_DIR/scan-receipt.sh"

# FIRST, before any check that can exit: drop this run's receipt. A runner that bails out early —
# tool missing, Docker down, jq absent — must not leave the PREVIOUS run's receipt behind, or the
# verdict counts a scanner that did not run this time and reads last run's result file as current.
# Found while closing SEC-SC2-1: 0 exit path(s) in this script precede the checks below.
scan_begin trivy

# This scanner needs no registry credentials, whatever the base image is. It reads images that
# are already built and present locally (docker image inspect, then the socket), so every layer it
# reads is on disk. Registry auth matters when PULLING a base — that is build-images.sh's
# `docker build --pull`, not this. ADR-034: Chainguard is the primary base; any credentialed
# registry is a documented fallback, and its credentials belong at build time if it is ever used.

if ! have_tool trivy; then
  tool_missing trivy trivy
  exit 1
fi

mkdir -p "$RESULTS_DIR"
cd "$PROJECT_ROOT" || exit 1   # dir:. and fs . are the checkout, whatever the caller's cwd

# ── Android track: scan the filesystem, there is no image ────────────────────
# `trivy fs android` reads gradle.lockfile for the dependency tree (vuln), plus secrets and
# misconfigurations in the tree. Without a committed lockfile Trivy sees no Gradle dependencies at
# all, which the receipt says out loud. See run-grype.sh for the same branch and why.
# Every trivy scan reads the bot's config, ignore file and secret config, never the checkout's
# .trivyignore, trivy.yaml or trivy-secret.yaml (own_config_args, B-5).
OWN=(); while IFS= read -r a; do OWN+=("$a"); done < <(own_config_args trivy-scan)
GLOBAL=(); while IFS= read -r a; do GLOBAL+=("$a"); done < <(own_config_args trivy)

# trivy_db_date — Trivy's report carries no vulnerability-database date, and the Scan gate holds
# that date to the profile's age limit, so every path writes it beside the report. Until gate run 1
# (B-2) only the repository-filesystem path did, and every image scan read as stale data at il4/il6.
# No date is not a pass: the file is removed and the gate says the age cannot be shown.
trivy_db_date() {
  rm -f "$RESULTS_DIR/trivy-version.json"
  tool_trivy version --format json "${GLOBAL[@]}" > "$RESULTS_DIR/trivy-version.json" 2>/dev/null || rm -f "$RESULTS_DIR/trivy-version.json"
}

# shellcheck source=scan-track.sh
. "$SCRIPT_DIR/scan-track.sh"
if [ "$(scan_track "$PROJECT_ROOT")" = android ]; then
  if [ ! -d "$PROJECT_ROOT/android" ]; then
    echo "[trivy] NOTHING SCANNED — APP_TRACK=android but there is no android/ directory. This is NOT a clean result."
    exit 1
  fi
  lock_note="gradle.lockfile present"
  [ -n "$(find "$PROJECT_ROOT/android" -name 'gradle.lockfile' -print -quit 2>/dev/null)" ] \
    || lock_note="NO gradle.lockfile — Gradle dependencies were NOT scanned; run ./gradlew dependencies --write-locks and commit the lockfile"
  echo "[trivy] Android track — scanning android/ as a filesystem via $(scan_engine_for trivy) engine ($lock_note)..."
  TRIVY_JSON_TMP=$(mktemp); TRIVY_LOG_TMP=$(mktemp)
  tool_trivy fs --scanners vuln,secret,misconfig --format json --quiet "${OWN[@]}" android > "$TRIVY_JSON_TMP" 2>"$TRIVY_LOG_TMP" || true
  tool_trivy fs --scanners vuln,secret,misconfig --format table --quiet "${OWN[@]}" android >> "$TRIVY_LOG_TMP" 2>/dev/null || true
  if ! jq -e '.Results // .SchemaVersion' "$TRIVY_JSON_TMP" >/dev/null 2>&1; then
    echo "[trivy] FAIL — no parseable report from the filesystem scan. The scanner did not run."
    head -20 "$TRIVY_LOG_TMP" | sed 's/^/  │ /'
    rm -f "$TRIVY_JSON_TMP" "$TRIVY_LOG_TMP"
    exit 1
  fi
  cp "$TRIVY_JSON_TMP" "$RESULTS_DIR/trivy.json"; cp "$TRIVY_LOG_TMP" "$RESULTS_DIR/trivy.log"
  rm -f "$TRIVY_JSON_TMP" "$TRIVY_LOG_TMP"
  trivy_db_date
  scan_ran trivy "android/ filesystem ($lock_note)"
  FINDING_COUNT=$(count_json "$RESULTS_DIR/trivy.json" '[.Results[]? | .Vulnerabilities[]?] | length' trivy) || exit 2
  echo "[trivy] Complete — $FINDING_COUNT finding(s) in android/. Results: $RESULTS_DIR/trivy.json"
  exit 0
fi

# ── No container image in this repository: scan its files ────────────────────
# image-plan.sh found nothing to build and no image was named. A repository that ships no image (a
# library, a CLI, this tool itself) still has dependencies, and scanning nothing then failing is as
# wrong as scanning nothing then passing. The repository is scanned as a filesystem instead: every
# manifest and lockfile in it. A repository WITH a Dockerfile whose image is missing still fails
# below — that is a build to run, not an empty scope. The scanners' own canned fixtures are excluded:
# they are test data, not dependencies.
if [ -z "${SCAN_IMAGES:-}" ] && [ -z "$(bash "$SCRIPT_DIR/image-plan.sh" 2>/dev/null)" ]; then
  echo "[trivy] No container image in this repository — scanning the repository filesystem via $(scan_engine_for trivy) engine..."
  TRIVY_JSON_TMP=$(mktemp); TRIVY_LOG_TMP=$(mktemp)
  tool_trivy fs --scanners vuln --skip-dirs scanners/fixtures --format json --quiet "${OWN[@]}" . > "$TRIVY_JSON_TMP" 2>"$TRIVY_LOG_TMP" || true
  tool_trivy fs --scanners vuln --skip-dirs scanners/fixtures --format table --quiet "${OWN[@]}" . >> "$TRIVY_LOG_TMP" 2>/dev/null || true
  if ! jq -e '.Results // .SchemaVersion' "$TRIVY_JSON_TMP" >/dev/null 2>&1; then
    echo "[trivy] FAIL — no parseable report from the filesystem scan. The scanner did not run."
    head -20 "$TRIVY_LOG_TMP" | sed 's/^/  │ /'
    rm -f "$TRIVY_JSON_TMP" "$TRIVY_LOG_TMP"
    exit 1
  fi
  cp "$TRIVY_JSON_TMP" "$RESULTS_DIR/trivy.json"; cp "$TRIVY_LOG_TMP" "$RESULTS_DIR/trivy.log"
  rm -f "$TRIVY_JSON_TMP" "$TRIVY_LOG_TMP"
  trivy_db_date
  scan_ran trivy "repository filesystem (no container image to build)"
  FINDING_COUNT=$(count_json "$RESULTS_DIR/trivy.json" '[.Results[]? | .Vulnerabilities[]?] | length' trivy) || exit 2
  echo "[trivy] Complete — $FINDING_COUNT finding(s) in the repository filesystem. Results: $RESULTS_DIR/trivy.json"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[trivy] Docker not available"
  exit 1
fi

# Images to scan. Names and build contexts come from scanners/scripts/image-plan.sh, which
# reads the platform CI file when present — the authority on what actually SHIPS. Do not default to
# Docker Compose's "<repo>-<service>" names: those are the DEV images (plain node/alpine base), so
# scanning them yields a number that looks like evidence and is not. Findings F-12, F-15.
# Override with: SCAN_IMAGES="name:tag name:tag"
SCANNED=0
IMAGES=()
if [ -n "${SCAN_IMAGES:-}" ]; then
  read -r -a IMAGES <<< "$SCAN_IMAGES"
else
  while IFS="$(printf '\t')" read -r name _df _ctx; do
    [ -n "$name" ] || continue
    # Take the first tag that exists: :scan (built by the nightly), :local (make dev), :latest.
    for tag in scan local latest; do
      if docker image inspect "${name}:${tag}" >/dev/null 2>&1; then IMAGES+=("${name}:${tag}"); break; fi
    done
  done < <(bash "$SCRIPT_DIR/image-plan.sh" 2>/dev/null)
fi
[ ${#IMAGES[@]} -eq 0 ] && IMAGES=("none-built")

# A stale image is worse than no image: it yields a plausible number describing an old build.
# `|| exit 1` is required — this script runs under `set -euo pipefail`, where a bare call returning
# 1 aborts before the guard can explain itself. Finding F-18.
# shellcheck source=/dev/null
. "$SCRIPT_DIR/image-age-guard.sh"
guard_image_age "${IMAGES[@]}" || exit 1
TRIVY_JSON_TMP=$(mktemp)
TRIVY_LOG_TMP=$(mktemp)

echo '{"SchemaVersion":2,"Results":[]}' > "$TRIVY_JSON_TMP"

for IMAGE in "${IMAGES[@]}"; do
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[trivy] IMAGE NOT FOUND: $IMAGE. Build the image first with docker build."
    continue
  fi

  echo "[trivy] Scanning $IMAGE via $(scan_engine_for trivy) engine..."
  SCANNED=$((SCANNED + 1))
  img_json=$(mktemp)

  tool_trivy image --format json --quiet "${OWN[@]}" "$IMAGE" > "$img_json" 2>/dev/null || true
  tool_trivy image --format table --quiet "${OWN[@]}" "$IMAGE" >> "$TRIVY_LOG_TMP" 2>/dev/null || true

  # Merge Results array from this image into accumulated results
  TRIVY_JSON_TMP_NEXT=$(mktemp)
  jq -s '.[0].Results += (.[1].Results // []) | .[0]' "$TRIVY_JSON_TMP" "$img_json" > "$TRIVY_JSON_TMP_NEXT"
  mv "$TRIVY_JSON_TMP_NEXT" "$TRIVY_JSON_TMP"

  rm -f "$img_json"
done

if [ "$SCANNED" -eq 0 ]; then
  rm -f "$TRIVY_JSON_TMP" "$TRIVY_LOG_TMP"
  echo ""
  echo "[trivy] NOTHING SCANNED — no images found. This is NOT a clean result."
  echo "         Looked for: ${IMAGES[*]}"
  echo "         Build them first:   make dev     (or: docker compose build)"
  echo "         Or choose images:   SCAN_IMAGES=\"name:tag name:tag\" make scan-images"
  exit 1
fi

# Only now: something was examined, so there is a result worth leaving behind. Until 2026-09-24
# these three lines sat above the branch, so a run that scanned nothing still wrote a valid, empty
# result and the verdict counted it as a scanner that ran (SEC-SC2-1).
cp "$TRIVY_JSON_TMP" "$RESULTS_DIR/trivy.json"
cp "$TRIVY_LOG_TMP" "$RESULTS_DIR/trivy.log"
rm -f "$TRIVY_JSON_TMP" "$TRIVY_LOG_TMP"
trivy_db_date
scan_ran trivy "$SCANNED image(s)"

FINDING_COUNT=$(count_json "$RESULTS_DIR/trivy.json" '[.Results[]? | .Vulnerabilities[]?] | length' trivy) || exit 2
echo "[trivy] Complete — $FINDING_COUNT finding(s). Results: $RESULTS_DIR/trivy.json"

exit 0
