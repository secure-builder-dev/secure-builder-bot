#!/usr/bin/env bash
# refresh-frameworks.sh — fetch the published standards and rebuild the vendored indexes.
#
# WHY THIS EXISTS
#   "Unverified" was being used as a resting state. It should be a queue that empties. This is the
#   command that empties it: it goes and gets the current published edition, rebuilds what the gate
#   verifies against, and reports exactly what moved.
#
# THE RULE IT IMPLEMENTS
#   Live fetch for reporting, vendored copy for verdicts. This script does the fetching — deliberate,
#   online, producing a reviewable diff. The gate never fetches, because a verdict must be
#   re-derivable: two runs over the same commit have to agree, and a gate-log row has to point at
#   something checkable months later.
#
# PIN, NOT LATEST
#   An ATO is granted against a specific baseline revision. Silently adopting a newer one would make
#   Sentinel check against a baseline the authorizing official never approved — a worse failure than
#   being a revision behind, because it is invisible. So this script REPORTS a newer revision and
#   adopts it only when asked (--adopt). The pin lives in project.config.yaml as NIST_CATALOG_PIN,
#   falling back to whatever the vendored index records.
#
# USAGE
#   standards/scripts/refresh-frameworks.sh [--check|--adopt] [--quiet]
#     --check   (default) fetch, compare against the vendored index, report. Writes nothing.
#     --adopt   also rebuild the vendored index from what was fetched. Deliberate act; commit the diff.
#
#   Five sources are refreshed: the NIST 800-53 OSCAL catalogue (pinned), the two OWASP Top 10
#   lists, the DISA STIGs via ComplianceAsCode, OWASP MASVS for the Android track, and NIST's
#   publication list, which answers whether a cited SP or FIPS revision is still the current one.
#   OFFLINE=1   skip the fetch entirely and say so. For the air-gapped sibling engine, or a
#               deliberately disconnected run. Never the silent fallback — an unreachable source
#               without OFFLINE=1 is an error, because that is what made "unverified" possible.
#
# EXIT  0 = pin matches upstream, or --adopt succeeded, or OFFLINE=1
#       1 = a source could not be reached (and OFFLINE was not set)
#       3 = upstream has a newer revision than the pin  (a signal, not a failure — CI opens a PR)

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1
SELF="$(cd "$(dirname "$0")" && pwd)"

MODE="check"; QUIET=0
for a in "$@"; do
  case "$a" in
    --check) MODE="check" ;;
    --adopt) MODE="adopt" ;;
    --quiet) QUIET=1 ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    *) echo "refresh-frameworks: unknown flag $a" >&2; exit 1 ;;
  esac
done
say() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }

NIST_URL="https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
INDEX="standards/data/controls/nist-800-53r5-index.json"

cfg() {  # $1 = key -> value, or empty
  [ -f project.config.yaml ] || return 0
  sed -nE "s/^[[:space:]]*$1:[[:space:]]*\"?([^\"#]*)\"?[[:space:]]*(#.*)?\$/\1/p" project.config.yaml \
    | head -1 | sed -E 's/[[:space:]]+$//'
}
idx_val() { [ -f "$INDEX" ] && sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" "$INDEX" | head -1; }

stig_refresh() {
  # DISA publishes STIGs behind DoD PKI at cyber.mil; no CI job holds a CAC. ComplianceAsCode
  # redistributes the XCCDF manuals verbatim, which is a weaker provenance chain and is recorded as
  # such in the index and in FRAMEWORKS.md. Good enough to catch an invented rule id before a
  # reviewer sees it; not a substitute for the STIG Viewer at assessment time.
  local OUT="standards/data/controls/stig-index.json" d
  d="$(mktemp -d)"
  say ""
  say "── DISA STIGs (via ComplianceAsCode) ───────────────────────────"
  if ! git clone --depth 1 --filter=blob:none --quiet \
        https://github.com/ComplianceAsCode/content.git "$d/cac" 2>"$d/err"; then
    say "  UNREACHABLE — ComplianceAsCode"
    say "    $(head -1 "$d/err" 2>/dev/null)"
    rm -rf "$d"; return 1
  fi
  python3 "$SELF/build-stig-index.py" "$d/cac" "$d/new.json" | sed 's/^/  /' || { rm -rf "$d"; return 1; }
  if [ -f "$OUT" ] && python3 -c 'import json,sys;a=json.load(open(sys.argv[1]));b=json.load(open(sys.argv[2]));sys.exit(0 if a["rules"]==b["rules"] else 1)' "$OUT" "$d/new.json"; then
    say "  CURRENT — the vendored STIG index matches the redistributed content."
    rm -rf "$d"; return 0
  fi
  say "  CHANGED — the redistributed STIG content differs from the vendored index."
  if [ "$MODE" = "adopt" ]; then cp "$d/new.json" "$OUT"; say "  adopted -> $OUT"
  else say "  run with --adopt to take it, then make verify-citations"; fi
  rm -rf "$d"; return 3
}

owasp_refresh() {
  # OWASP publishes no catalogue format, but both lists live in the projects' own repositories:
  # the web list in <edition>/mkdocs.yml nav, the LLM list in 2_0_vulns/ filenames. A shallow clone
  # of each is the primary source. OWASP is not an accreditation baseline, so unlike NIST there is
  # no pin to respect — newest is simply correct.
  local OUT="standards/data/controls/owasp-index.json" d rc=0
  d="$(mktemp -d)"
  say ""
  say "── OWASP lists ─────────────────────────────────────────────────"
  for r in "Top10:https://github.com/OWASP/Top10.git" \
           "llm:https://github.com/OWASP/www-project-top-10-for-large-language-model-applications.git"; do
    if ! git clone --depth 1 --quiet "${r#*:}" "$d/${r%%:*}" 2>"$d/err"; then
      say "  UNREACHABLE — ${r#*:}"
      say "    $(head -1 "$d/err" 2>/dev/null)"
      rc=1
    fi
  done
  if [ "$rc" -ne 0 ]; then
    say ""
    say "  An OWASP list could not be fetched. Error, not a fallback — see the NIST note above."
    rm -rf "$d"; return 1
  fi
  local before after
  before="$( [ -f "$OUT" ] && python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(json.dumps({k:d[k]["editions"][d[k]["current"]] for k in ("web","llm")},sort_keys=True))' "$OUT" 2>/dev/null )"
  python3 "$SELF/build-owasp-index.py" "$d/Top10" "$d/llm" "$d/new.json" | sed 's/^/  /'
  after="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(json.dumps({k:d[k]["editions"][d[k]["current"]] for k in ("web","llm")},sort_keys=True))' "$d/new.json")"
  if [ "$before" = "$after" ]; then
    say "  CURRENT — the vendored OWASP index matches both published lists."
  else
    say "  CHANGED — the published lists differ from the vendored index."
    if [ "$MODE" = "adopt" ]; then cp "$d/new.json" "$OUT"; say "  adopted -> $OUT"
  else say "  run with --adopt to take it, then make verify-citations"; fi
    rm -rf "$d"; return 3
  fi
  rm -rf "$d"; return 0
}

masvs_refresh() {
  # OWASP MASVS is the Android track's grounding because the DISA Mobile Application STIG cannot be
  # one here: it is CUI-marked and behind DoD PKI, and these are not CUI workstations. MASVS ships a
  # machine-readable catalogue in the project's own repository, so unlike the mobile STIG it can
  # actually be checked. Not an accreditation baseline, so like OWASP there is no pin — newest is
  # simply correct.
  local OUT="standards/data/controls/masvs-index.json" d
  d="$(mktemp -d)"
  say ""
  say "── OWASP MASVS ─────────────────────────────────────────────────"
  if ! git clone --depth 1 --quiet https://github.com/OWASP/masvs.git "$d/masvs" 2>"$d/err"; then
    say "  UNREACHABLE — https://github.com/OWASP/masvs"
    say "    $(head -1 "$d/err" 2>/dev/null)"
    say "  Error, not a fallback — see the NIST note above."
    rm -rf "$d"; return 1
  fi
  python3 "$SELF/build-masvs-index.py" "$d/masvs" "$d/new.json" | sed 's/^/  /' || { rm -rf "$d"; return 1; }
  if [ -f "$OUT" ] && python3 -c 'import json,sys;a=json.load(open(sys.argv[1]));b=json.load(open(sys.argv[2]));sys.exit(0 if a["controls"]==b["controls"] else 1)' "$OUT" "$d/new.json"; then
    say "  CURRENT — the vendored MASVS index matches the published catalogue."
    rm -rf "$d"; return 0
  fi
  say "  CHANGED — the published MASVS catalogue differs from the vendored index."
  say "  A renumbering here invalidates Android checklist citations; verify-citations will name them."
  if [ "$MODE" = "adopt" ]; then cp "$d/new.json" "$OUT"; say "  adopted -> $OUT"
  else say "  run with --adopt to take it, then make verify-citations"; fi
  rm -rf "$d"; return 3
}

nistpubs_refresh() {
  # Answers "is Rev 1 still the current revision of SP 800-163" — supersession, not renumbering.
  # NIST's own publication metadata repository, because csrc.nist.gov is unreachable from some CI
  # networks and this one is on GitHub. Only filenames are needed, so the clone is blobless and the
  # builder reads the git tree rather than 20,000 files.
  local OUT="standards/data/controls/nist-pubs-index.json" d
  d="$(mktemp -d)"
  say ""
  say "── NIST publications (SP / FIPS currency) ──────────────────────"
  if ! git clone --depth 1 --filter=blob:none --quiet \
        https://github.com/usnistgov/NIST-Tech-Pubs.git "$d/ntp" 2>"$d/err"; then
    say "  UNREACHABLE — usnistgov/NIST-Tech-Pubs"
    say "    $(head -1 "$d/err" 2>/dev/null)"
    say "  Error, not a fallback — see the NIST note above."
    rm -rf "$d"; return 1
  fi
  python3 "$SELF/build-nistpubs-index.py" "$d/ntp" "$d/new.json" | sed 's/^/  /' || { rm -rf "$d"; return 1; }
  if [ -f "$OUT" ] && python3 -c 'import json,sys;a=json.load(open(sys.argv[1]));b=json.load(open(sys.argv[2]));sys.exit(0 if a["pubs"]==b["pubs"] else 1)' "$OUT" "$d/new.json"; then
    say "  CURRENT — the vendored publication index matches what NIST lists."
    rm -rf "$d"; return 0
  fi
  say "  CHANGED — NIST has published something the vendored index does not list."
  say "  A new revision of a cited SP shows up as SUPERSEDED in verify-citations, not as a failure."
  if [ "$MODE" = "adopt" ]; then cp "$d/new.json" "$OUT"; say "  adopted -> $OUT"
  else say "  run with --adopt to take it, then make verify-citations"; fi
  rm -rf "$d"; return 3
}

VENDORED="$(idx_val _catalog_version)"
PIN="$(cfg NIST_CATALOG_PIN)"
case "$PIN" in ""|UNSET) PIN="$VENDORED" ;; esac

say "── framework refresh ───────────────────────────────────────────"
say "  pinned            : 800-53 ${PIN:-none} $([ -n "$PIN" ] && [ "$PIN" != "$VENDORED" ] && echo "(project.config.yaml)")"
say "  vendored index    : 800-53 ${VENDORED:-none}  ($INDEX)"

if [ "${OFFLINE:-0}" = "1" ]; then
  say "  upstream          : NOT CHECKED — OFFLINE=1  (NIST, OWASP, STIG, MASVS and NIST pubs skipped)"
  say ""
  say "  Currency is unknown for this run, by request. The vendored index still verifies"
  say "  every citation; it just cannot tell you whether a newer revision exists."
  exit 0
fi

command -v curl >/dev/null || { say "  upstream          : curl not available"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

say "  fetching          : $NIST_URL"
if ! curl -sSL --fail --max-time 300 -o "$TMP/oscal.json" "$NIST_URL" 2>"$TMP/err"; then
  say ""
  say "  UNREACHABLE — NIST OSCAL catalogue could not be fetched."
  say "    $(head -1 "$TMP/err" 2>/dev/null)"
  say ""
  say "  This is an error, not a fallback. A refresh that quietly used the stale copy is"
  say "  how a project ends up unknowingly out of date. Re-run when the network is back,"
  say "  or pass OFFLINE=1 to state plainly that currency was not checked this run."
  exit 1
fi

UPSTREAM="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["catalog"]["metadata"].get("version",""))' "$TMP/oscal.json" 2>/dev/null)"
MODIFIED="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["catalog"]["metadata"].get("last-modified","")[:10])' "$TMP/oscal.json" 2>/dev/null)"
say "  upstream          : 800-53 ${UPSTREAM:-?} (published ${MODIFIED:-?})"
say ""

if [ "$UPSTREAM" = "$VENDORED" ]; then
  say "  CURRENT — the vendored index matches the published catalogue."
  owasp_refresh; ow=$?
  [ "$ow" -eq 1 ] && exit 1
  stig_refresh; st=$?
  [ "$st" -eq 1 ] && exit 1
  masvs_refresh; ms=$?
  [ "$ms" -eq 1 ] && exit 1
  nistpubs_refresh; np=$?
  [ "$np" -eq 1 ] && exit 1
  { [ "$ow" -eq 3 ] || [ "$st" -eq 3 ] || [ "$ms" -eq 3 ] || [ "$np" -eq 3 ]; } && exit 3
  exit 0
fi

# Newer upstream. Report which CITED controls actually move — the delta that matters is not
# "N controls changed" but "N controls YOU cite changed", which is usually a much shorter list.
say "  NEWER REVISION AVAILABLE: ${VENDORED:-none} → ${UPSTREAM}"
python3 "$SELF/build-control-index.py" "$TMP/oscal.json" "$TMP/new-index.json" >/dev/null 2>&1 \
  || { say "  could not build an index from the fetched catalogue"; exit 1; }

bash "$SELF/verify-citations.sh" --list-cited 2>/dev/null > "$TMP/cited.txt"
python3 - "$INDEX" "$TMP/new-index.json" "$TMP/cited.txt" <<'PY'
import json, sys
old = json.load(open(sys.argv[1]))["controls"] if len(sys.argv) > 1 else {}
new = json.load(open(sys.argv[2]))["controls"]
cited = {l.strip() for l in open(sys.argv[3]) if l.strip()}
moved = []
for cid in sorted(cited):
    o, n = old.get(cid), new.get(cid)
    if n is None:
        moved.append(f"    {cid:<12} REMOVED from the catalogue")
    elif o is None:
        continue
    elif o.get("s") != n.get("s"):
        into = ", ".join(n.get("into", [])) or "no replacement named"
        moved.append(f"    {cid:<12} {o.get('s')} -> {n.get('s')}  (use: {into})")
    elif o.get("t") != n.get("t"):
        moved.append(f"    {cid:<12} retitled: {o.get('t')!r} -> {n.get('t')!r}")
print(f"  controls you cite : {len(cited)}")
if moved:
    print(f"  CHANGED ({len(moved)}):")
    print("\n".join(moved))
else:
    print("  none of the controls you cite changed status or title")
PY

owasp_refresh; OW_RC=$?
[ "$OW_RC" -eq 1 ] && exit 1
stig_refresh; ST_RC=$?
[ "$ST_RC" -eq 1 ] && exit 1
masvs_refresh; MS_RC=$?
[ "$MS_RC" -eq 1 ] && exit 1
nistpubs_refresh; NP_RC=$?
[ "$NP_RC" -eq 1 ] && exit 1

say ""
if [ "$MODE" = "adopt" ]; then
  python3 "$SELF/build-control-index.py" "$TMP/oscal.json" "$INDEX" || exit 1
  say ""
  say "  ADOPTED. Now, in order:"
  say "    1. make verify-citations            — a newly withdrawn control is a finding everywhere it is cited"
  say "    2. make verify-citations ARGS=--advisory  — reconcile title drift"
  say "    3. update the NIST row in standards/data/FRAMEWORKS.md (version, date, SHA)"
  say "    4. update NIST_CATALOG_PIN in project.config.yaml once your ATO baseline moves"
  say "    5. a checklist item that changes as a result is a governance edit — engine/GOVERNANCE.md"
  exit 0
fi

say "  Not adopted. The pin is deliberate: an ATO is granted against a named revision, and"
say "  adopting a newer one is a decision, not a sync. When your baseline moves, run:"
say "    make refresh-frameworks ARGS=--adopt"
exit 3
