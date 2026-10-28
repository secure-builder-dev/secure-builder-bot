#!/usr/bin/env python3
"""build-stig-index.py — vendored index of DISA STIG rule IDs, via ComplianceAsCode.

WHY THIS SOURCE, AND WHAT IT COSTS
  DISA publishes STIGs at cyber.mil behind DoD PKI. No CI job holds a CAC, so the automated path
  used for NIST and OWASP does not exist here. ComplianceAsCode redistributes the DISA XCCDF
  manuals verbatim in its repository, which makes an index possible — at the cost of provenance:
  the chain is "a third party says this is what DISA published", not DISA directly.

  That is an acceptable trade for a DEVELOPMENT tool whose job is to catch a typo'd or invented
  STIG ID before it reaches a reviewer. It is NOT a substitute for the STIG Viewer when someone is
  preparing an assessment, and FRAMEWORKS.md says so. The redistributor and the retrieved commit
  are both recorded so the weaker chain is visible rather than implied.

WHAT IT COVERS — and pointedly does not
  Covered: RHEL 8/9/10, Oracle Linux 7/8/9, SLES 12/15, SLE Micro, Ubuntu 22.04/24.04, OpenShift 4
  and RHCOS 4, plus the Application, Container, OS and DNS SRGs. Run the script to see the counts —
  do not trust this paragraph over `_counts` in the output, which is how the SRG claim went stale.

  NOT parsed: the browser STIGs (Chrome `DTBC-0001`, Firefox `DTBF003`, BIND). Their IDs carry no
  dashes or a different shape entirely, and a citation-side pattern loose enough to match them would
  also match prose like "RFC5280". The engine cites none of them, so the cost of excluding them is
  zero and the cost of including them is false positives in every document.

  NOT covered: the DISA Application Security and Development STIG (`APSC-DV-*`), which the provider
  checklists cite 52 times. It is NOT redistributed here — `APSC-DV` appears nowhere in
  ComplianceAsCode. Those citations are reported as uncovered by verify-citations rather than
  adjudicated, so the gap is stated rather than mistaken for coverage.
  NOT covered: any mobile STIG. The DISA Mobile Application STIG has no redistribution here, and
  could not be vendored even by hand — it is CUI-marked and these are not CUI workstations. The
  Android track is therefore grounded in OWASP MASVS instead, which ships a machine-readable
  catalogue; see build-masvs-index.py. That is a recorded scope boundary, not a gap.
  Also not covered: end-of-life releases. Ubuntu 20.04 is gone from upstream, so UBTU-20-* IDs do
  not resolve. That is a true signal, not a gap: citing an EOL platform's STIG is itself stale.

USAGE
    git clone --depth 1 --filter=blob:none https://github.com/ComplianceAsCode/content.git /tmp/cac
    python3 standards/scripts/build-stig-index.py /tmp/cac \\
        standards/data/controls/stig-index.json

  `make refresh-frameworks` does this for you.
"""
import datetime
import glob
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import xml.parsers.expat


class _HasDTD(Exception):
    pass


def _qualified(name):
    """Expat's "ns}local" (namespace_separator="}") back to ElementTree's "{ns}local"."""
    return "{" + name if "}" in name else name


def safe_root(path):
    """The root element of an XCCDF file, or None when it is not well-formed or declares a DTD.

    A STIG is a file someone downloaded, so it is untrusted input. XCCDF needs no DTD. Expat is
    driven directly into an ElementTree builder with its DOCTYPE and entity-declaration handlers
    refusing, which is what defusedxml does, so no entity is ever declared or expanded (external
    entities, the billion-laughs bomb) and a UTF-16 file cannot hide one, since expat decodes it.
    Semgrep's use-defused-xml-parse found the bare ET.parse this replaces in both STIG readers.
    """
    with open(path, "rb") as f:
        data = f.read()
    builder = ET.TreeBuilder()
    parser = xml.parsers.expat.ParserCreate(namespace_separator="}")
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def refuse(*_):
        raise _HasDTD()

    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.StartElementHandler = lambda name, attrs: builder.start(
        _qualified(name), {_qualified(k): v for k, v in attrs.items()})
    parser.EndElementHandler = lambda name: builder.end(_qualified(name))
    parser.CharacterDataHandler = builder.data
    try:
        parser.Parse(data, True)
        return builder.close()
    except (_HasDTD, xml.parsers.expat.ExpatError, AssertionError):
        return None  # AssertionError: TreeBuilder closed with an element still open


# The ID shapes DISA actually uses in an XCCDF <version> element, counted across every manual
# ComplianceAsCode redistributes. The first pattern alone was the original, and it silently dropped
# every SRG (SRG-APP-000001-AS-000001) and every CNTR-OS rule — 862 rules — while FRAMEWORKS.md and
# the docstring below both claimed the SRGs were carried. A parser that drops what it cannot match
# and says nothing is how an index ends up smaller than its own provenance record claims.
STIG_ID = re.compile(r"""^(?:
      [A-Z][A-Z0-9]{3}-\d{2}-\d{6}                      # RHEL-08-010000, OL07-00-010020, PGS9-00-…
    | [A-Z]{2,4}-[A-Z]{2}-\d{6}                          # CNTR-OS-000010, APSC-DV-002000
    | SRG-[A-Z]{2,3}-\d{6}(?:-[A-Z]{2,4}-\d{5,6})?      # SRG-APP-000001-AS-000001, SRG-OS-…-GPOS-…
  )$""", re.X)


def rules(path):
    """Yield (stig_id, title) from an XCCDF manual. The <version> element carries the STIG ID."""
    root = safe_root(path)
    if root is None:
        return
    for rule in root.iter():
        if not rule.tag.endswith("}Rule"):
            continue
        ver = title = None
        for child in rule:
            if child.tag.endswith("}version"):
                ver = (child.text or "").strip()
            elif child.tag.endswith("}title"):
                title = (child.text or "").strip()
        if ver and STIG_ID.match(ver):
            yield ver, (title or "")


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: build-stig-index.py <ComplianceAsCode-repo> <out.json>")
    repo, out = sys.argv[1], sys.argv[2]
    refs = os.path.join(repo, "shared", "references")
    if not os.path.isdir(refs):
        sys.exit(f"build-stig-index: {refs} not found — is that a ComplianceAsCode checkout?")

    files = sorted(glob.glob(os.path.join(refs, "disa-*.xml")))
    # A product ships both a -manual and a -scap rendering of the same STIG. Prefer the manual: it
    # is the human-readable authority and carries every rule, where the SCAP subset does not.
    manuals = {os.path.basename(f).replace("-xccdf-manual.xml", "") for f in files if f.endswith("-manual.xml")}
    idx, sources = {}, {}
    for f in files:
        base = os.path.basename(f)
        stem = base.replace("-xccdf-manual.xml", "").replace("-xccdf-scap.xml", "").replace(".xml", "")
        if base.endswith("-xccdf-scap.xml") and stem in manuals:
            continue
        n = 0
        for sid, title in rules(f):
            idx[sid] = {"t": title, "s": stem}
            n += 1
        if n:
            sources[stem] = n

    if not idx:
        sys.exit("build-stig-index: no STIG rules parsed — check the checkout")

    try:
        commit = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=20).stdout.strip()[:12]
    except Exception:
        commit = ""

    doc = {
        "_retrieved": datetime.date.today().isoformat(),
        "_generator": "standards/scripts/build-stig-index.py",
        "_redistributor": "https://github.com/ComplianceAsCode/content",
        "_redistributor_commit": commit,
        "_publisher": "DISA (cyber.mil) — behind DoD PKI; this index is a redistribution, not the publisher",
        "_not_covered": ["DISA Mobile Application STIG (CUI-marked, behind DoD PKI; see build-masvs-index.py)",
                         "DISA Application Security and Development STIG, APSC-DV-* (not redistributed here)",
                         "browser STIGs, e.g. Chrome DTBC-0001 / Firefox DTBF003 (id shape collides with prose)",
                         "end-of-life platforms, e.g. Ubuntu 20.04"],
        "_counts": {"rules": len(idx), "stigs": len(sources)},
        "sources": sources,
        "rules": idx,
    }
    json.dump(doc, open(out, "w"), indent=0, sort_keys=True)
    print(f"{out}: {len(idx)} rules from {len(sources)} STIGs, {os.path.getsize(out)//1024} KB")


if __name__ == "__main__":
    main()
