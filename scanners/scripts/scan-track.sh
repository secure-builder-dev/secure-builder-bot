#!/usr/bin/env bash
# scan-track.sh — which track is this project on, as the scanners need to know it.
#
# WHY THIS EXISTS
#   The seven scanners were written for the web track: two of them scan built container images, two
#   scan npm app dirs. On the android track there is no image to scan and no app dir to audit, so
#   until 2026-10-07 four of seven exited 1 on a plugin repo and gate-line reported "did not run" —
#   the verdict could never pass, and nothing had been examined. Each runner now asks this one
#   question and takes the android path (filesystem scan, or a declared empty scope) or the web
#   path as before.
#
#   Same resolution as qa/scripts/_lib.sh: APP_TRACK from project.config.yaml, the single
#   source of truth; when it is UNSET or the file is missing, inferred from what is on disk, so a
#   half-initialised repo still scans rather than erroring out.
#
# USAGE   . "$SCRIPT_DIR/scan-track.sh"; scan_track [root]   → prints android | web
#         SCAN_TRACK=android|web overrides (tests, and a mixed repo scanned one way on purpose)
scan_track() {
  local root="${1:-.}" v
  case "${SCAN_TRACK:-}" in android|web) printf '%s' "$SCAN_TRACK"; return 0 ;; esac
  if [ -f "$root/project.config.yaml" ]; then
    v="$(sed -nE 's/^[[:space:]]*APP_TRACK:[[:space:]]*"?([^"#]*)"?[[:space:]]*(#.*)?$/\1/p' "$root/project.config.yaml" \
         | head -1 | sed -E 's/[[:space:]]+$//')"
    case "$v" in android|web) printf '%s' "$v"; return 0 ;; esac
  fi
  # Inference: a Gradle wrapper or Kotlin source under android/ is a plugin repo; the engine
  # template ships an empty android/ tree with neither, which is why a bare directory is not enough.
  if [ -x "$root/android/gradlew" ] || [ -n "$(find "$root/android" -name '*.kt' -print -quit 2>/dev/null)" ]; then
    printf 'android'
  else
    printf 'web'
  fi
}
