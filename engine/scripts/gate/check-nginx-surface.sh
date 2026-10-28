#!/usr/bin/env bash
# check-nginx-surface.sh — keep the nginx attack surface as small as it was when it was assessed.
#
# WHY THIS EXISTS
#   On 2026-09-18 the frontend image carried 4 Critical/High nginx CVEs with no Wolfi package
#   available. Every one was shown to be UNREACHABLE: each requires a directive the config does not
#   have. That is a stronger disposition than "accepted risk" — but it is only true while the config
#   stays that way. Add a `map` with regex captures, or turn on SSI, and the argument silently
#   expires with nobody noticing.
#
#   CLAUDE.md: "Findings become checks." This turns a one-time analysis into a standing guarantee.
#   If the surface grows, CI says so and the disposition gets re-examined on purpose.
#
# WHAT IT GUARDS (directive -> the CVE class it re-opens)
#   map + regex captures        CVE-2026-42533 class — heap overflow in map regex handling
#   proxy_http_version 2        CVE-2026-42055 class — large upstream headers (needs 2 more conditions)
#   grpc_pass                   same class
#   ignore_invalid_headers off  same class
#   large_client_header_buffers same class
#   slice                       CVE-2026-60005 class — uninitialised memory via slice + regex captures
#   ssi                         CVE-2026-56434 class — use-after-free (needs proxy_pass + buffering off)
#   charset / source_charset    CVE-2026-48142 class — heap over-read
#
#   Presence is not by itself a vulnerability — most need several conditions together. It means the
#   assessment is stale and must be redone, which is the thing worth catching.
#
# USAGE   engine/scripts/gate/check-nginx-surface.sh   (in make check)
# EXIT    0 = surface unchanged, or no nginx config in this project · 1 = a guarded directive appeared

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 0

cfg() {   # $1 = key in project.config.yaml
  [ -f project.config.yaml ] || return 0
  sed -nE "s/^[[:space:]]*$1:[[:space:]]*\"?([^\"#]*)\"?[[:space:]]*(#.*)?$/\1/p" project.config.yaml | head -1 | sed -E 's/[[:space:]]+$//'
}
is_android() { [ -f android/gradlew ] || [ "$(cfg APP_TRACK)" = android ]; }

# Portable list build: mapfile is bash 4+, and macOS ships bash 3.2. Engine scripts run on both.
CONF=()
while IFS= read -r _f; do [ -n "$_f" ] && CONF+=("$_f"); done < <(
  git ls-files | grep -E 'nginx.*\.(conf|template)$|\.conf\.template$' 2>/dev/null || true
)
if [ "${#CONF[@]}" -eq 0 ]; then
  # Same reasoning as sql-scan: name the difference between "nothing to check here" and
  # "this check did not run". A plugin build serves nothing over nginx.
  if is_android; then
    echo "check-nginx-surface: NOT APPLICABLE on the android track — a plugin build serves nothing over nginx"
  else
    echo "check-nginx-surface: no nginx config tracked yet in this repo"
  fi
  exit 0
fi

FOUND=0
guard() {   # $1 = directive label, $2 = ERE, $3 = CVE class
  local hits
  hits=$(grep -inE "$2" "${CONF[@]}" 2>/dev/null | grep -v 'nginx-surface: allow') || true
  [ -n "$hits" ] || return 0
  FOUND=$((FOUND + 1))
  echo "  APPEARED  $1   (re-opens $3)"
  printf '%s\n' "$hits" | sed 's/^/      /'
}

guard "map directive"               '^[[:space:]]*map[[:space:]]'                  "CVE-2026-42533 class"
guard "proxy_http_version 2"        'proxy_http_version[[:space:]]+2'              "CVE-2026-42055 class"
guard "grpc_pass"                   'grpc_pass'                                    "CVE-2026-42055 class"
guard "ignore_invalid_headers off"  'ignore_invalid_headers[[:space:]]+off'        "CVE-2026-42055 class"
guard "large_client_header_buffers" 'large_client_header_buffers'                  "CVE-2026-42055 class"
guard "slice directive"             '^[[:space:]]*slice[[:space:]]'                "CVE-2026-60005 class"
guard "ssi on"                      '^[[:space:]]*ssi[[:space:]]+on'               "CVE-2026-56434 class"
guard "charset directive"           '^[[:space:]]*(source_)?charset[[:space:]]'    "CVE-2026-48142 class"

if [ "$FOUND" -gt 0 ]; then
  echo ""
  echo "check-nginx-surface: ${FOUND} guarded directive(s) appeared in the nginx config."
  echo "  The 'not reachable' disposition in gate-records/cve-remediation-log.md was assessed"
  echo "  against a config without these. Re-assess before shipping, then update that log."
  echo "  Deliberate and reviewed? add 'nginx-surface: allow' to the line and say why in the log."
  exit 1
fi
echo "check-nginx-surface: attack surface unchanged (${#CONF[@]} config file(s))"
exit 0
