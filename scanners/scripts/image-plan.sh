#!/usr/bin/env bash
# image-plan.sh — what images does this project actually ship, and how are they built?
#
# WHY THIS EXISTS
#   Scanning the wrong image is worse than not scanning: it produces a number that looks like
#   evidence and is not. Docker Compose builds DEV images (`<repo>-<service>`, often a plain
#   node/alpine base) while the platform pipeline builds the hardened production images under
#   different names and different build contexts. Defaulting to the Compose names silently scanned
#   images the project never deploys. Finding F-15.
#
#   The platform CI file is the source of truth for what ships, so read it when it is there and
#   fall back to convention when it is not. This file is READ, never written — it is platform-owned.
#
# OUTPUT  one line per image:  name<TAB>dockerfile<TAB>context
# USAGE   scanners/scripts/image-plan.sh
#         SCAN_IMAGES="a:tag=Dockerfile:ctx ..." overrides entirely (see run-grype.sh)

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 0
CI=".gitlab-ci.yml"

if [ -f "$CI" ] && command -v jq >/dev/null 2>&1 \
   && grep -q 'MULTI_DOCKERFILE_PAYLOAD' "$CI" 2>/dev/null; then
  # The payload is a JSON array inside a YAML block scalar. Take the indented lines that follow
  # the key until the indentation ends, then let jq do the parsing.
  payload=$(awk '
    /MULTI_DOCKERFILE_PAYLOAD:/ { grab = 1; next }
    grab && /^[[:space:]]*$/    { next }
    grab && /^[[:space:]]{4,}/  { print; next }
    grab                        { exit }
  ' "$CI")
  if [ -n "$payload" ]; then
    plan=$(echo "$payload" | jq -r '.[] | [.image_name, .docker_file, .docker_context] | @tsv' 2>/dev/null)
    # An unsubstituted <IMAGE_NAME_*> means this is an uninitialised template — fall through to
    # convention rather than emitting a name no image will ever carry.
    if [ -n "$plan" ] && ! grep -q '<[A-Z_]*>' <<<"$plan"; then
      printf '%s\n' "$plan"; exit 0
    fi
  fi
fi

# Fallback: every Dockerfile in the checkout (scan-scope.sh), named by its directory (svc/api →
# svc-api; the checkout's own name at the root; Dockerfile.worker → <dir>-worker) and built from
# that directory, which is where its COPY lines resolve from in the conventional layout. A project
# whose contexts differ names them in its pipeline file above.
#
# Every name is unique and docker-valid (gate run 1, B-6, N-01). The readable name is lower-cased
# and every run of characters docker refuses becomes one `-`, which is lossy: svc/api and svc-api
# are both svc-api, and at the root of a checkout mounted at /src the root Dockerfile and
# src/Dockerfile are both src. build-images.sh tags each name:scan, so one build overwrote the other
# and that image was never scanned. A readable name that two Dockerfiles share is therefore given a
# suffix from the Dockerfile's own path, the same on every run; a name nothing else shares stays
# as it was. If a suffix still collides, every name takes the full hash of its path.
#
# The bot's own image (scanners/Dockerfile in the bot's own checkout) is never in the plan: the
# bot's scan of itself scans the filesystem and lints that Dockerfile; building it is the release
# workflow's job (scanners/pins.md).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scan-scope.sh
. "$SCRIPT_DIR/scan-scope.sh"
self="$(cd "$SCRIPT_DIR/.." && pwd)/Dockerfile"
root="$(pwd)"

slug() {   # slug <text> — lower case, each run of anything but [a-z0-9] one '-', trimmed, never empty
  local s
  s=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' | cut -c1-100)
  printf '%s' "${s:-image}"
}
path_hash() {   # path_hash <dockerfile path> — stable across runs and machines
  printf '%s' "$1" | git hash-object --stdin 2>/dev/null || printf '%s' "$1" | cksum | cut -d' ' -f1
}

DFS=(); CTXS=(); NAMES=()
while IFS= read -r df; do
  [ -n "$df" ] || continue
  [ "$root/$df" = "$self" ] && continue
  dir=$(dirname "$df"); base=$(basename "$df")
  if [ "$dir" = "." ]; then name=$(basename "$root"); ctx="."; else name="$dir"; ctx="./$dir"; fi
  case "$base" in Dockerfile.*) name="${name}-${base#Dockerfile.}" ;; esac
  DFS+=("$df"); CTXS+=("$ctx"); NAMES+=("$(slug "$name")")
done < <(scan_targets "$root" -name Dockerfile -o -name 'Dockerfile.*')
[ "${#DFS[@]}" -gt 0 ] || exit 0

shared=$(printf '%s\n' "${NAMES[@]}" | LC_ALL=C sort | uniq -d)
for i in "${!NAMES[@]}"; do
  if grep -qxF -- "${NAMES[$i]}" <<<"$shared"; then
    NAMES[i]="${NAMES[$i]}-$(path_hash "${DFS[$i]}" | cut -c1-10)"
  fi
done
if [ -n "$(printf '%s\n' "${NAMES[@]}" | LC_ALL=C sort | uniq -d)" ]; then
  for i in "${!NAMES[@]}"; do NAMES[i]="image-$(path_hash "${DFS[$i]}")"; done
fi
for i in "${!NAMES[@]}"; do printf '%s\t%s\t%s\n' "${NAMES[$i]}" "${DFS[$i]}" "${CTXS[$i]}"; done
exit 0
