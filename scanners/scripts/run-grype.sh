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
scan_begin grype

# This scanner needs no registry credentials, whatever the base image is. It reads images that
# are already built and present locally (docker image inspect, then the socket), so every layer it
# reads is on disk. Registry auth matters when PULLING a base — that is build-images.sh's
# `docker build --pull`, not this. ADR-034: Chainguard is the primary base; any credentialed
# registry is a documented fallback, and its credentials belong at build time if it is ever used.

if ! have_tool grype; then
  tool_missing grype grype
  exit 1
fi

mkdir -p "$RESULTS_DIR"
cd "$PROJECT_ROOT" || exit 1   # dir:. and fs . are the checkout, whatever the caller's cwd

# ── Android track: scan the filesystem, there is no image ────────────────────
# A plugin ships as an APK, not a container, so the image path below has nothing to examine. Grype
# scans android/ as a directory instead: Syft catalogs what is there — jars and aars (the ATAK SDK
# and anything vendored under libs/), pom files, and the Gradle lockfile where Syft's catalogers
# read it. Trivy reads gradle.lockfile directly, so between the two the dependency tree is covered
# only when `gradle.lockfile` is committed; a project without one has its direct jars scanned and
# nothing else, and the receipt says so. Not a skip, not a pass: a scanner that examined android/.
# Every grype call reads the bot's config, never a .grype.yaml in the checkout (own_config_args, B-5).
OWN=(); while IFS= read -r a; do OWN+=("$a"); done < <(own_config_args grype)

# shellcheck source=scan-track.sh
. "$SCRIPT_DIR/scan-track.sh"
if [ "$(scan_track "$PROJECT_ROOT")" = android ]; then
  if [ ! -d "$PROJECT_ROOT/android" ]; then
    echo "[grype] NOTHING SCANNED — APP_TRACK=android but there is no android/ directory. This is NOT a clean result."
    exit 1
  fi
  lock_note="gradle.lockfile present"
  [ -n "$(find "$PROJECT_ROOT/android" -name 'gradle.lockfile' -print -quit 2>/dev/null)" ] \
    || lock_note="NO gradle.lockfile — only vendored jars were cataloged; run ./gradlew dependencies --write-locks and commit the lockfile"
  echo "[grype] Android track — scanning android/ as a filesystem via $(scan_engine_for grype) engine ($lock_note)..."
  GRYPE_JSON_TMP=$(mktemp); GRYPE_LOG_TMP=$(mktemp)
  tool_grype "${OWN[@]}" dir:android --output json > "$GRYPE_JSON_TMP" 2>"$GRYPE_LOG_TMP" || true
  tool_grype "${OWN[@]}" dir:android --output table >> "$GRYPE_LOG_TMP" 2>/dev/null || true
  if ! jq -e '.matches' "$GRYPE_JSON_TMP" >/dev/null 2>&1; then
    echo "[grype] FAIL — no parseable report from the filesystem scan. The scanner did not run."
    head -20 "$GRYPE_LOG_TMP" | sed 's/^/  │ /'
    rm -f "$GRYPE_JSON_TMP" "$GRYPE_LOG_TMP"
    exit 1
  fi
  cp "$GRYPE_JSON_TMP" "$RESULTS_DIR/grype.json"; cp "$GRYPE_LOG_TMP" "$RESULTS_DIR/grype.log"
  rm -f "$GRYPE_JSON_TMP" "$GRYPE_LOG_TMP"
  scan_ran grype "android/ filesystem ($lock_note)"
  FINDING_COUNT=$(count_json "$RESULTS_DIR/grype.json" \
    '(.matches // error("no .matches key — output shape changed")) | length' grype) || exit 2
  echo "[grype] Complete — $FINDING_COUNT finding(s) in android/. Results: $RESULTS_DIR/grype.json"
  exit 0
fi

# ── No container image in this repository: scan its files ────────────────────
# image-plan.sh found nothing to build and no image was named. A repository that ships no image (a
# library, a CLI, this tool itself) still has dependencies, and scanning nothing then failing is as
# wrong as scanning nothing then passing. The repository is scanned as a filesystem instead: every
# manifest and lockfile in it. A repository WITH a Dockerfile whose image is missing still fails
# below — that is a build to run, not an empty scope. The scanners' own canned fixtures are excluded:
# they are test data, not dependencies. So is node_modules: the lockfiles name every package in it, and
# the install the gates job runs first would otherwise count each one twice.
if [ -z "${SCAN_IMAGES:-}" ] && [ -z "$(bash "$SCRIPT_DIR/image-plan.sh" 2>/dev/null)" ]; then
  echo "[grype] No container image in this repository — scanning the repository filesystem via $(scan_engine_for grype) engine..."
  GRYPE_JSON_TMP=$(mktemp); GRYPE_LOG_TMP=$(mktemp)
  tool_grype "${OWN[@]}" dir:. --exclude './scanners/fixtures/**' --exclude './.git/**' --exclude './**/node_modules/**' --output json > "$GRYPE_JSON_TMP" 2>"$GRYPE_LOG_TMP" || true
  tool_grype "${OWN[@]}" dir:. --exclude './scanners/fixtures/**' --exclude './.git/**' --exclude './**/node_modules/**' --output table >> "$GRYPE_LOG_TMP" 2>/dev/null || true
  if ! jq -e '.matches' "$GRYPE_JSON_TMP" >/dev/null 2>&1; then
    echo "[grype] FAIL — no parseable report from the filesystem scan. The scanner did not run."
    head -20 "$GRYPE_LOG_TMP" | sed 's/^/  │ /'
    rm -f "$GRYPE_JSON_TMP" "$GRYPE_LOG_TMP"
    exit 1
  fi
  cp "$GRYPE_JSON_TMP" "$RESULTS_DIR/grype.json"; cp "$GRYPE_LOG_TMP" "$RESULTS_DIR/grype.log"
  rm -f "$GRYPE_JSON_TMP" "$GRYPE_LOG_TMP"
  scan_ran grype "repository filesystem (no container image to build)"
  FINDING_COUNT=$(count_json "$RESULTS_DIR/grype.json" \
    '(.matches // error("no .matches key — output shape changed")) | length' grype) || exit 2
  echo "[grype] Complete — $FINDING_COUNT finding(s) in the repository filesystem. Results: $RESULTS_DIR/grype.json"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[grype] Docker not available"
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
GRYPE_JSON_TMP=$(mktemp)
GRYPE_LOG_TMP=$(mktemp)

GRYPE_DESC_TMP=$(mktemp)

echo '{"matches":[],"source":{"type":"multi-image"},"descriptor":{"name":"grype","version":"merged"}}' > "$GRYPE_JSON_TMP"

for IMAGE in "${IMAGES[@]}"; do
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[grype] IMAGE NOT FOUND: $IMAGE. Build the image first with docker build."
    continue
  fi

  echo "[grype] Scanning $IMAGE via $(scan_engine_for grype) engine..."
  SCANNED=$((SCANNED + 1))
  img_json=$(mktemp)
  img_log=$(mktemp)

  tool_grype "${OWN[@]}" "$IMAGE" --output json > "$img_json" 2>"$img_log" || true
  tool_grype "${OWN[@]}" "$IMAGE" --output table >> "$GRYPE_LOG_TMP" 2>/dev/null || true

  # Merge matches from this image into accumulated results
  GRYPE_JSON_TMP_NEXT=$(mktemp)
  jq -s '.[0].matches += .[1].matches | .[0]' "$GRYPE_JSON_TMP" "$img_json" > "$GRYPE_JSON_TMP_NEXT"
  mv "$GRYPE_JSON_TMP_NEXT" "$GRYPE_JSON_TMP"
  jq -c '.descriptor // {}' "$img_json" >> "$GRYPE_DESC_TMP" 2>/dev/null || echo '{}' >> "$GRYPE_DESC_TMP"

  rm -f "$img_json" "$img_log"
done

# The merged report carries ONE database date, and the Scan gate holds it to the profile's age limit.
# The accumulator above has none, and until gate run 1 (B-2) the merge kept the accumulator's
# descriptor, so every image scan read as undated — stale data at il4 and il6 on every checkout that
# ships an image. Each image's own descriptor is kept instead: the one with the OLDEST database date,
# so the age judged is the worst of them; and if any image's report carries no date, the merged
# descriptor carries none either, because the age of that scan cannot be shown.
if [ "$SCANNED" -gt 0 ]; then
  GRYPE_JSON_TMP_NEXT=$(mktemp)
  jq --slurpfile d "$GRYPE_DESC_TMP" '
    def built: (.db.status.built // .db.built // null);
    if ($d | length) > 0 and all($d[]; built != null)
    then .descriptor = ($d | min_by(built))
    else .descriptor = (($d[0] // .descriptor) | del(.db)) end' "$GRYPE_JSON_TMP" > "$GRYPE_JSON_TMP_NEXT"
  mv "$GRYPE_JSON_TMP_NEXT" "$GRYPE_JSON_TMP"
fi
rm -f "$GRYPE_DESC_TMP"

if [ "$SCANNED" -eq 0 ]; then
  rm -f "$GRYPE_JSON_TMP" "$GRYPE_LOG_TMP"
  echo ""
  echo "[grype] NOTHING SCANNED — no images found. This is NOT a clean result."
  echo "         Looked for: ${IMAGES[*]}"
  echo "         Build them first:   make dev     (or: docker compose build)"
  echo "         Or choose images:   SCAN_IMAGES=\"name:tag name:tag\" make scan-images"
  exit 1
fi

# Only now: something was examined, so there is a result worth leaving behind. Until 2026-09-24
# these three lines sat above the branch, so a run that scanned nothing still wrote a valid, empty
# result and the verdict counted it as a scanner that ran (SEC-SC2-1).
cp "$GRYPE_JSON_TMP" "$RESULTS_DIR/grype.json"
cp "$GRYPE_LOG_TMP" "$RESULTS_DIR/grype.log"
rm -f "$GRYPE_JSON_TMP" "$GRYPE_LOG_TMP"
scan_ran grype "$SCANNED image(s)"

FINDING_COUNT=$(count_json "$RESULTS_DIR/grype.json" \
  '(.matches // error("no .matches key — output shape changed")) | length' grype) || exit 2
echo "[grype] Complete — $FINDING_COUNT finding(s). Results: $RESULTS_DIR/grype.json"

exit 0
