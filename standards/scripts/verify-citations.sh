#!/usr/bin/env bash
# verify-citations.sh — every standard cited in the documents exists and is still current.
#
# WHY THIS EXISTS
#   Sentinel's authority rests on its checks being grounded in real controls. Nothing in the engine
#   ever read a control ID and asked whether it was real, so nothing could catch a citation that was
#   wrong the day it was written. Three were: SA-12 (withdrawn in Rev 5, incorporated into SR) was
#   cited as the PRIMARY control for the dependency check for four months; IR-10 (withdrawn) sat in
#   the IL4 baseline; AU-9(2) carried AU-9(4)'s title. A wrong citation is worse than an absent one,
#   because it reads as diligence. "Findings become checks" — this is that rule applied to the
#   citations themselves.
#
# WHAT IT CHECKS
#   The rules live in one place, standards/securebuilderbot_standards/citations.py, and this script
#   is the list of documents they run over: NIST 800-53 ids (unknown and withdrawn fail), OWASP ids
#   (a renumbered title fails), DISA STIG ids (unknown on an indexed platform fails; an unindexed
#   platform is reported, never judged), OWASP MASVS ids (unknown and v1 numbering fail) and NIST
#   SP / FIPS revisions (never published fails; superseded is reported). A line carrying the allow
#   marker is a deliberate mention and is skipped. The indexes are read from the repository this
#   runs in, under standards/data/controls/, so the self-test can drive it inside a fixture.
#
#   It does NOT check that the cited control is the RIGHT one for the check it sits next to. That
#   judgment is human, made at the governance review when a checklist item changes.
#
# FILES
#   The list is DOCUMENTS in citations.py, shared with the refresh (which must not adopt a catalog
#   that breaks a citation in the same documents). Kept explicit rather than globbed over the repo so
#   that adding a doc is a deliberate act and a stray example in a skill file never fails CI.
#
# USAGE   standards/scripts/verify-citations.sh [--quiet] [--advisory] [--list-cited]
#           --advisory    also report MISLABELLED (title mismatch); does not affect exit code
#           --list-cited  print the distinct NIST ids cited and stop (refresh-frameworks reads it)
# EXIT    0 = every citation resolves to an active control
#         1 = at least one unknown or withdrawn citation
#         2 = the index is missing — nothing was verified

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for a in "$@"; do
  case "$a" in
    --quiet|--advisory|--list-cited) ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    *) echo "verify-citations: unknown flag $a" >&2; exit 2 ;;
  esac
done

exec "$HERE/../run" verify --tracked --data standards/data/controls "$@"
