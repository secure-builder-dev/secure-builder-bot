#!/usr/bin/env bash
# standards-selftest.sh — fixture-backed regression tests for the standards module's scripts.
#
# WHY THIS EXISTS
#   The citation verifier, the STIG ingester, the index builders and the framework refresh each
#   exist because a specific defect shipped: a withdrawn control cited as live for four months, an
#   OWASP id that silently changed meaning between editions, a STIG id shape the pattern could not
#   see, a CUI-marked document that must never enter the repository. Every one of those cases is
#   replayed here against a throwaway git repository shaped like the one that bit, so the scripts
#   cannot regress to the state that let it happen. These sections lived in the engine's gate
#   self-test until the standards module took its scripts; the assertions are the same.
#
# USAGE   standards/tests/standards-selftest.sh        (or: make gate-selftest)
# EXIT    0 = all assertions hold · 1 = at least one failed

set -uo pipefail
STD_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"
FX="$(mktemp -d)"; trap 'rm -rf "$FX"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$3] got [$2]"; fi; }
assert_has() { if grep -qF -- "$3" <<<"$2"; then ok "$1"; else bad "$1" "output lacks [$3]"; fi; }
assert_not() { if grep -qF -- "$3" <<<"$2"; then bad "$1" "output contains [$3]"; else ok "$1"; fi; }

# ── fixture: a repository that cites standards, with indexes written per section ──────────────
cd "$FX" && git init -q && git config user.email t@t && git config user.name t
git commit -q --allow-empty -m base

# ── verify-citations ──────────────────────────────────────────────────────────
# The defects this exists for: a withdrawn control cited as live (SA-12 for four months), an
# invented ID, and the CM-nn manifest prefix colliding with the NIST CM family.
echo "── verify-citations ──"
mkdir -p standards/data/controls docs/security
cat > standards/data/controls/nist-800-53r5-index.json <<'JSON'
{"_catalog_version":"5.2.0","_retrieved":"2026-09-19","controls":{
"AC-3":{"t":"Access Enforcement","s":"active"},
"CM-6":{"t":"Configuration Settings","s":"active"},
"SA-12":{"t":"Supply Chain Protection","s":"withdrawn","into":["SR"]}}}
JSON
mkdir -p engine
cat > engine/SENTINEL-CHECKLIST.md <<'MD'
- token gate AC-3 (Access Enforcement)
MD
git add -A >/dev/null 2>&1; git commit -qm "citations fixture" >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1); rc=$?
assert_eq "clean citations exit 0" "$rc" "0"
assert_has "clean run names the catalogue version" "$out" "800-53 5.2.0"

printf -- '- supply chain SA-12 (Supply Chain Protection)\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm wd >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1); rc=$?
assert_eq "withdrawn control fails" "$rc" "1"
assert_has "withdrawn names its replacement" "$out" "use: SR"

printf -- '- invented XX marker AC-99\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm unk >/dev/null 2>&1
assert_has "unknown id reported" "$(bash "$STD_DIR/verify-citations.sh" 2>&1)" "UNKNOWN     AC-99"

sed -i.bak 's/- supply chain SA-12 (Supply Chain Protection)/- supply chain SA-12 moved here citations: allow/' engine/SENTINEL-CHECKLIST.md
sed -i.bak '/AC-99/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak
git add -A >/dev/null 2>&1; git commit -qm allow >/dev/null 2>&1
assert_eq "citations: allow suppresses a deliberate mention" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "0"

printf '| id | control |\n|---|---|\n| CM-01 | row id, not NIST |\n| CM-20 | row id, not NIST |\n' > docs/security/CONTROL-MANIFEST.md
git add -A >/dev/null 2>&1; git commit -qm manifest >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1); rc=$?
assert_eq "manifest CM-nn row ids are not read as NIST controls" "$rc" "0"
assert_not "…and are not reported unknown" "$out" "CM-20"

mv standards/data/controls/nist-800-53r5-index.json "$FX/idx.bak"
assert_eq "missing index exits 2 rather than passing silently" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "2"
mv "$FX/idx.bak" standards/data/controls/nist-800-53r5-index.json

# ── verify-citations: OWASP renumbering ───────────────────────────────────────
# The defect this exists for: excessive agency was LLM08 in the 2023 edition and is LLM06 in 2025.
# Every ID still "exists", so only comparing the TITLE catches it.
echo "── owasp renumbering ──"
cat > standards/data/controls/owasp-index.json <<'JSON'
{"web":{"current":"2025","editions":{"2025":{"A01":"Broken Access Control","A02":"Security Misconfiguration","A04":"Cryptographic Failures"}}},
 "llm":{"current":"2025","editions":{"2025":{"LLM06":"Excessive Agency","LLM08":"Vector and Embedding Weaknesses"}}}}
JSON
printf -- '- agent ceiling LLM06 — excessive agency\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm owasp-ok >/dev/null 2>&1
assert_eq "correct OWASP numbering passes" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "0"

printf -- '- agent ceiling LLM08 — excessive agency\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm owasp-bad >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1); rc=$?
assert_eq "stale edition numbering fails" "$rc" "1"
assert_has "renumbering names the right id" "$out" "did you mean LLM06"
assert_has "…and the title the stale id now carries" "$out" "Vector and Embedding Weaknesses"

printf -- '- prose mention (LLM01 above) is not a title claim\n' >> engine/SENTINEL-CHECKLIST.md
sed -i.bak '/LLM08 — excessive agency/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak
git add -A >/dev/null 2>&1; git commit -qm prose >/dev/null 2>&1
assert_eq "prose after an id is not read as a title" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "0"

printf -- '- web A02 Cryptographic Failures\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm web-bad >/dev/null 2>&1
assert_has "web list renumbering caught too" "$(bash "$STD_DIR/verify-citations.sh" 2>&1)" "did you mean A04"
sed -i.bak '/A02 Cryptographic Failures/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak
git add -A >/dev/null 2>&1; git commit -qm cleanup >/dev/null 2>&1

# ── verify-citations: STIG id shapes ──────────────────────────────────────────
# Regression for the defect where the citation pattern matched only ONE id shape, so APSC-DV and
# every SRG id were invisible — not adjudicated, and absent from the uncovered tally, while the
# summary line read as though all STIG citations had been checked.
echo "── stig id shapes ──"
cat > standards/data/controls/stig-index.json <<'JSON'
{"rules":{"RHEL-08-010000":{"t":"a","s":"x"},"SRG-APP-000001-AS-000001":{"t":"b","s":"y"}},
 "sources":{"x":1,"y":1}}
JSON
printf -- '- covered os rule RHEL-08-010000\n- covered srg rule SRG-APP-000001-AS-000001\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm stig-shapes-ok >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1)
assert_eq "indexed OS and SRG ids both resolve" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "0"
assert_has "SRG ids are counted, not dropped" "$out" "2 STIG"

printf -- '- app stig APSC-DV-002000\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm stig-uncovered >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1)
assert_has "an uncovered prefix is reported without --advisory" "$out" "NOT COVERED"
assert_has "…and names the prefix" "$out" "(APSC)"
assert_has "…and the summary says how many of how many" "$out" "2 of 3 STIG"
assert_eq "an uncovered citation is reported, not failed" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "0"

printf -- '- rfc reference RFC5280 and a bare word\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm stig-prose >/dev/null 2>&1
assert_not "prose like RFC5280 is not read as a STIG id" "$(bash "$STD_DIR/verify-citations.sh" 2>&1)" "3 of 4 STIG"

printf -- '- typo in a covered platform RHEL-08-999999\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm stig-bad >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1); rc=$?
assert_eq "a bad id on a COVERED platform still fails" "$rc" "1"
assert_has "…and says its platform is indexed" "$out" "UNKNOWN STIG RHEL-08-999999"
sed -i.bak '/RHEL-08-999999/d;/APSC-DV-002000/d;/RFC5280/d;/SRG-APP-000001/d;/RHEL-08-010000/d' engine/SENTINEL-CHECKLIST.md
rm -f engine/SENTINEL-CHECKLIST.md.bak
git add -A >/dev/null 2>&1; git commit -qm stig-cleanup >/dev/null 2>&1

# ── ingest-stig: a STIG nobody redistributes ──────────────────────────────────
# The APSC-DV case. 52 citations that no reachable source can verify; a human downloads the STIG and
# this path makes them checkable. Asserted end to end because "it would work when the file arrives"
# is exactly the kind of claim this suite exists to stop taking on faith.
echo "── ingest-stig ──"
mk_xccdf() {  # $1 = out path · $2 = front-matter marking · $3.. = rule ids
  local out="$1" marking="$2"; shift 2
  { printf '<?xml version="1.0" encoding="utf-8"?>\n<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="t">'
    printf '<status>accepted</status><title>Test STIG</title><description>x %s</description>' "$marking"
    local i=0
    for sid in "$@"; do i=$((i+1))
      printf '<Group id="V-%d"><Rule id="SV-%d_rule"><version>%s</version><title>Text for %s.</title>' "$i" "$i" "$sid" "$sid"
      printf '<description>guidance mentioning classified or FOUO data</description></Rule></Group>'
    done
    printf '</Benchmark>'; } > "$out"
}
cat > standards/data/controls/stig-index.json <<'JSON'
{"rules":{"RHEL-08-010000":{"t":"a","s":"x"}},"sources":{"x":1}}
JSON
printf -- '- app stig APSC-DV-002000\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm ingest-before >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1)
assert_has "before ingest: the citation is uncovered" "$out" "NOT COVERED"
assert_has "…and the run points at the way to fix it" "$out" "make ingest-stig"

mk_xccdf "$FX/asd.xml" "" APSC-DV-002000
assert_eq "--dry-run writes nothing" \
  "$(python3 "$STD_DIR/ingest-stig.py" "$FX/asd.xml" --dry-run >/dev/null 2>&1; echo $?)$(test -f standards/data/controls/stig-index-supplied.json && echo FILE)" "0"
python3 "$STD_DIR/ingest-stig.py" "$FX/asd.xml" >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1)
assert_not "after ingest: nothing is uncovered" "$out" "NOT COVERED"
assert_has "…and the supplied rules are declared, not hidden" "$out" "human-supplied STIG rules"

# A supplied STIG must survive a CaC refresh. It lives in its own file for exactly this reason:
# refresh-frameworks --adopt regenerates stig-index.json and would otherwise delete it.
cat > standards/data/controls/stig-index.json <<'JSON'
{"rules":{"RHEL-08-010000":{"t":"a","s":"x"},"RHEL-08-010001":{"t":"b","s":"x"}},"sources":{"x":2}}
JSON
assert_not "a supplied STIG survives the CaC index being rewritten" \
  "$(bash "$STD_DIR/verify-citations.sh" 2>&1)" "NOT COVERED"

# A typo inside a NOW-COVERED prefix must fail, or ingesting bought nothing.
printf -- '- typo APSC-DV-999999\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm ingest-typo >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1); rc=$?
assert_eq "a bad id in a supplied STIG's prefix now fails" "$rc" "1"
assert_has "…and is named" "$out" "UNKNOWN STIG APSC-DV-999999"
sed -i.bak '/APSC-DV-999999/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak

mk_xccdf "$FX/cui.xml" "CUI" APSC-DV-002001
assert_eq "a CUI-marked document is refused" \
  "$(python3 "$STD_DIR/ingest-stig.py" "$FX/cui.xml" >/dev/null 2>&1; echo $?)" "1"
assert_eq "…and accepted only on an explicit acknowledgement" \
  "$(python3 "$STD_DIR/ingest-stig.py" "$FX/cui.xml" --acknowledge-cui >/dev/null 2>&1; echo $?)" "0"
assert_has "FOUO in RULE text is not a document marking" \
  "$(python3 "$STD_DIR/ingest-stig.py" "$FX/asd.xml" --dry-run 2>&1)" "1 rules"
rm -f standards/data/controls/stig-index-supplied.json
sed -i.bak '/APSC-DV-002000/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak
git add -A >/dev/null 2>&1; git commit -qm ingest-cleanup >/dev/null 2>&1

# ── verify-citations: MASVS ───────────────────────────────────────────────────
# The Android track's grounding. Two defect classes: an id that is not in the pinned catalogue, and
# an `MSTG-*` id — MASVS v1 numbering, which v2 renumbered wholesale. Same shape as LLM08→LLM06.
echo "── masvs ──"
cat > standards/data/controls/masvs-index.json <<'JSON'
{"_latest_release":"v2.1.0",
 "controls":{"MASVS-NETWORK-1":"The app secures all network traffic according to the current best practices.",
             "MASVS-STORAGE-1":"The app securely stores sensitive data."}}
JSON
printf -- '- android tls MASVS-NETWORK-1\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm masvs-ok >/dev/null 2>&1
assert_eq "valid MASVS id passes" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "0"

printf -- '- android tls MASVS-NETWORK-9\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm masvs-unknown >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1); rc=$?
assert_eq "unknown MASVS id fails" "$rc" "1"
assert_has "unknown MASVS id is named" "$out" "UNKNOWN MASVS MASVS-NETWORK-9"
sed -i.bak '/MASVS-NETWORK-9/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak

printf -- '- android storage MSTG-STORAGE-1\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm masvs-legacy >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1); rc=$?
assert_eq "MASVS v1 numbering fails" "$rc" "1"
assert_has "…and the message names the current release" "$out" "MASVS v2.1.0"

printf -- '- historical pointer (was MSTG-STORAGE-1) is not a live citation\n' >> engine/SENTINEL-CHECKLIST.md
sed -i.bak '/- android storage MSTG-STORAGE-1/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak
git add -A >/dev/null 2>&1; git commit -qm masvs-was >/dev/null 2>&1
assert_eq "(was MSTG-…) is read as a superseded pointer, not a citation" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "0"

# The builder must fail loudly on a checkout it cannot parse. A silent empty index would make the
# whole MASVS check inert while still reporting green — the exact failure ADR-036 calls blocking.
assert_eq "masvs builder refuses a checkout with no catalogue" \
  "$(python3 "$STD_DIR/build-masvs-index.py" "$FX" /dev/null >/dev/null 2>&1; echo $?)" "1"

# ── verify-citations: NIST publication currency ───────────────────────────────
# Supersession, not renumbering: "is Rev 1 still the current revision of SP 800-163".
echo "── nist pubs ──"
cat > standards/data/controls/nist-pubs-index.json <<'JSON'
{"pubs":{"SP 800-163":{"revisions":["","r1"],"drafts":[],"latest":"r1"},
         "SP 800-124":{"revisions":["","r1","r2"],"drafts":[],"latest":"r2"},
         "FIPS 140-3":{"revisions":[""],"drafts":[],"latest":""}}}
JSON
printf -- '- vetting NIST SP 800-163 Rev 1 and NIST SP 800-124 Rev 2 and FIPS 140-3\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm pubs-ok >/dev/null 2>&1
assert_eq "current revisions pass" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "0"

printf -- '- old NIST SP 800-124 Rev 1\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm pubs-old >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1)
assert_eq "a superseded revision is REPORTED, not failed" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "0"
assert_has "…and says which revision is published" "$out" "r1 cited, r2 published"
sed -i.bak '/800-124 Rev 1/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak

printf -- '- invented NIST SP 800-163 Rev 4\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm pubs-badrev >/dev/null 2>&1
out=$(bash "$STD_DIR/verify-citations.sh" 2>&1); rc=$?
assert_eq "a revision that was never published FAILS" "$rc" "1"
assert_has "…and lists what was published" "$out" "published revisions: (original), r1"
sed -i.bak '/800-163 Rev 4/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak

printf -- '- invented FIPS 141\n' >> engine/SENTINEL-CHECKLIST.md
git add -A >/dev/null 2>&1; git commit -qm pubs-badfips >/dev/null 2>&1
assert_eq "an invented FIPS number fails" "$(bash "$STD_DIR/verify-citations.sh" >/dev/null 2>&1; echo $?)" "1"
sed -i.bak '/FIPS 141/d' engine/SENTINEL-CHECKLIST.md; rm -f engine/SENTINEL-CHECKLIST.md.bak
git add -A >/dev/null 2>&1; git commit -qm pubs-cleanup >/dev/null 2>&1

# The file list is a glob, and `standards/data/**/*.md` does not match a file directly under
# standards/data/ — git's `**/` needs an intermediate directory. FRAMEWORKS.md, the provenance
# record itself, went unscanned because of it.
mkdir -p standards/data
printf -- '# top level\n\n- bogus control AC-99 at the top of the tree\n' > standards/data/FRAMEWORKS.md
git add -A >/dev/null 2>&1; git commit -qm toplevel >/dev/null 2>&1
assert_has "a file directly under standards/data/ is scanned" \
  "$(bash "$STD_DIR/verify-citations.sh" 2>&1)" "standards/data/FRAMEWORKS.md"
rm -f standards/data/FRAMEWORKS.md
git add -A >/dev/null 2>&1; git commit -qm toplevel-cleanup >/dev/null 2>&1

# ── refresh-frameworks (deterministic paths only) ─────────────────────────────
# The fetch itself needs the network, so it is not asserted here. What IS asserted: the offline
# path never silently degrades, the pin is read from project.config.yaml, and a bad flag is an
# error rather than a default.
echo "── refresh-frameworks ──"
cat > project.config.yaml <<'YML'
APP_TRACK: web
NIST_CATALOG_PIN: 5.1.0
YML
git add -A >/dev/null 2>&1; git commit -qm "pin fixture" >/dev/null 2>&1

out=$(OFFLINE=1 bash "$STD_DIR/refresh-frameworks.sh" 2>&1); rc=$?
assert_eq "OFFLINE=1 exits 0" "$rc" "0"
assert_has "OFFLINE=1 says currency was not checked" "$out" "NOT CHECKED"
assert_not "OFFLINE=1 does not claim to be current" "$out" "CURRENT —"
assert_has "pin is read from project.config.yaml" "$out" "800-53 5.1.0"

out=$(OFFLINE=1 bash "$STD_DIR/refresh-frameworks.sh" --nonsense 2>&1); rc=$?
assert_eq "unknown flag is an error, not a default" "$rc" "1"

rm -f project.config.yaml
out=$(OFFLINE=1 bash "$STD_DIR/refresh-frameworks.sh" 2>&1)
assert_has "no config: falls back to the vendored index version" "$out" "vendored index"


printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
