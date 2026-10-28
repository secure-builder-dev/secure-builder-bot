#!/usr/bin/env bash
# build-images.sh — build the images that ship, so a scan measures the current tree.
#
# WHY --pull AND --no-cache ARE NOT OPTIONAL
#   Both defaults silently produce a scan of something old:
#
#   --pull      `FROM chainguard/wolfi-base:latest` resolves to whatever copy of :latest is in the
#               local cache. A tag is a moving pointer; without --pull you rebuild onto a base that
#               may be months stale while believing you are on :latest.
#   --no-cache  `RUN apk update && apk upgrade` is a permanent cache hit. Docker keys a RUN layer on
#               the instruction TEXT, which never changes, so the upgrade is skipped on every
#               rebuild after the first. Observed 2026-09-18: a plain rebuild kept libssl3 3.6.3-r4
#               while Wolfi had published 3.6.4-r7.
#
#   Consequence: a scan run without these is a verdict on an image from an arbitrary past date.
#   That is worse than not scanning, because the number looks current. Finding F-17.
#
#   CI runners are ephemeral and so are accidentally immune — until someone adds layer caching to
#   speed the pipeline up, at which point this returns silently. Stating the flags keeps the intent
#   in the file rather than in the runner's configuration.
#
# REGISTRY AUTH
#   `--pull` fetches the base named in each Dockerfile. Chainguard is public, so nothing is needed
#   (ADR-034). If a project ever takes a credentialed-registry fallback, its `docker login`
#   belongs HERE, before the build — not in the scanners, which only ever read images already
#   present locally and so never authenticate to anything.
#
# USAGE   scanners/scripts/build-images.sh   ·   SCAN_NO_BUILD=1 skips (already built by hand)
# EXIT    0 = built, or skipped deliberately · 1 = a build failed

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "${SCAN_NO_BUILD:-0}" = "1" ]; then
  echo "[build] SCAN_NO_BUILD=1 — skipping. The scan will measure whatever image already exists."
  exit 0
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "[build] docker unavailable — skipping build; image scans will report NOTHING SCANNED."
  exit 0
fi

# One tag per image. Two plan lines with one name would both be tagged name:scan, the second build
# overwriting the first, and the first image would never be scanned (gate run 1, B-6). image-plan.sh
# never names two images alike; a pipeline file can, and then nothing is built until it is fixed.
PLAN=$(bash "$SCRIPT_DIR/image-plan.sh" 2>/dev/null)
dups=$(cut -f1 <<<"$PLAN" | grep . | LC_ALL=C sort | uniq -d)
if [ -n "$dups" ]; then
  echo "[build] FAILED: the image plan names more than one image $(tr '\n' ' ' <<<"$dups")— each would overwrite the other's :scan tag."
  echo "[build]   Give each image its own image_name in the pipeline file's MULTI_DOCKERFILE_PAYLOAD."
  exit 1
fi

rc=0; built=0
while IFS="$(printf '\t')" read -r name df ctx; do
  [ -n "$name" ] || continue
  [ -f "$df" ] || { echo "[build] SKIP $name — $df not found"; continue; }
  echo "[build] $name  ($df, context $ctx)  --pull --no-cache"
  if docker build --pull --no-cache -f "$df" -t "${name}:scan" "$ctx"; then
    built=$((built + 1))
  else
    echo "[build] FAILED: $name"; rc=1
  fi
done <<<"$PLAN"

[ "$built" -eq 0 ] && echo "[build] nothing built — check scanners/scripts/image-plan.sh"
exit $rc
