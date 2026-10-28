#!/usr/bin/env python3
"""ingest-stig.py — add a STIG a human downloaded to the verified set.

WHY THIS EXISTS
  Some DISA STIGs are not redistributed anywhere a CI job can reach. The Application Security and
  Development STIG is the one that matters here: the provider checklists cite `APSC-DV-*` 52 times,
  ComplianceAsCode does not carry it, and cyber.mil, dl.dod.cyber.mil and stigviewer.com are all
  behind either DoD PKI or a network policy. Those 52 citations are verified by nobody.

  The missing piece was never the parser. `build-stig-index.py` already reads DISA's XCCDF format
  and has been proven on 4,010 rules across 18 STIGs; this script reuses that exact code rather than
  reimplementing it. The missing piece was delivery. So this script takes the file from a HUMAN —
  whoever can reach the download — and does every part that can be checked mechanically.

  No URL is hardcoded. A recalled download URL is a guess, and a guess is what this engine is for
  eliminating. You bring the file; the script does the rest and records where it came from.

WHY A SEPARATE FILE
  Human-supplied content goes to stig-index-supplied.json, never into stig-index.json.
  `make refresh-frameworks --adopt` REGENERATES the latter from ComplianceAsCode, which would
  silently delete anything merged into it. verify-citations reads both.

PROVENANCE IS RECORDED, NOT IMPLIED
  The SHA-256 of the file you supplied, its name, and the date are written into the index. That is a
  stronger chain than the redistributed content — "this exact file, and here is its hash" beats "a
  third party says this is what DISA published" — but it is only as good as the person's source, so
  it says plainly that a human supplied it.

CUI
  A document DISA marks as controlled must not enter this repository; that is the standing rule that
  keeps the Mobile Application STIG out (see build-masvs-index.py). This script reads the XCCDF's
  own front matter — title, description, notice — and refuses if it carries a control marking.
  It deliberately does NOT search rule bodies: real STIG guidance says things like "marking data as
  classified or FOUO", and failing on that would make the check useless. Override with
  --acknowledge-cui only if you have determined the marking does not apply.

USAGE
    standards/scripts/ingest-stig.py <file.zip|file.xml> [more…] [--acknowledge-cui] [--dry-run]
    make ingest-stig FILE=~/Downloads/U_ASD_V5R3_STIG.zip

    Then:  make verify-citations      — the newly covered ids are adjudicated from now on
           and update the row in standards/data/FRAMEWORKS.md, naming the edition and the date.

EXIT  0 = ingested (or --dry-run, or nothing changed) · 1 = bad input, or a refusal
"""
import datetime
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = "standards/data/controls/stig-index-supplied.json"

# Reuse the parser that is already proven, rather than a second copy that can drift from it.
# No .pyc: importing a sibling by path would otherwise drop a __pycache__ into standards/scripts/,
# and a committed tree must never be found modified by a read.
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("bsi", os.path.join(HERE, "build-stig-index.py"))
bsi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bsi)

CONTROLLED = re.compile(r"\b(CUI|CONTROLLED UNCLASSIFIED INFORMATION|NOFORN|"
                        r"DISTRIBUTION STATEMENT [B-F])\b", re.I)
FRONT = ("title", "description", "notice", "metadata", "plain-text")


def front_matter(path):
    """Text of the Benchmark's own front matter — not rule bodies. See the CUI note above."""
    root = bsi.safe_root(path)  # refuses a DTD: a downloaded STIG is untrusted input
    if root is None:
        return None
    parts = []
    for child in root:
        tag = child.tag.split("}")[-1]
        if tag == "Rule":
            break
        if tag in FRONT:
            parts.append(" ".join(t.strip() for t in child.itertext() if t and t.strip()))
    return "\n".join(parts)


def xccdfs(path, tmp):
    """Yield XCCDF paths from an .xml, or from the manual inside a DISA .zip."""
    if path.lower().endswith(".xml"):
        yield path
        return
    if not zipfile.is_zipfile(path):
        sys.exit(f"ingest-stig: {path} is neither an XML file nor a zip archive")
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".xml") and "xccdf" in n.lower()]
        # A DISA package ships a Manual and sometimes a SCAP rendering of the same STIG. The manual
        # is the authority and carries every rule, the same preference build-stig-index.py makes.
        manual = [n for n in names if "manual" in n.lower()]
        for n in (manual or names):
            z.extract(n, tmp)
            yield os.path.join(tmp, n)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    unknown = flags - {"--acknowledge-cui", "--dry-run"}
    if unknown:
        sys.exit(f"ingest-stig: unknown flag {', '.join(sorted(unknown))}")
    if not args:
        sys.exit(__doc__.split("USAGE")[1].strip())

    doc = {"rules": {}, "sources": {}}
    if os.path.exists(OUT):
        doc = json.load(open(OUT))
        doc.setdefault("rules", {})
        doc.setdefault("sources", {})

    added = 0
    with tempfile.TemporaryDirectory() as tmp:
        for path in args:
            if not os.path.isfile(path):
                sys.exit(f"ingest-stig: {path} not found")
            digest = sha256(path)
            for x in xccdfs(path, tmp):
                fm = front_matter(x)
                if fm is None:
                    sys.exit(f"ingest-stig: {x} is not parseable XML")
                hit = CONTROLLED.search(fm)
                if hit and "--acknowledge-cui" not in flags:
                    print(f"REFUSED — {os.path.basename(x)} front matter carries {hit.group(0)!r}.\n"
                          f"  A document DISA marks as controlled must not enter this repository.\n"
                          f"  This is the same rule that keeps the Mobile Application STIG out.\n"
                          f"  If you have determined the marking does not apply, re-run with"
                          f" --acknowledge-cui.", file=sys.stderr)
                    return 1
                stem = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(x))
                stem = re.sub(r"(-xccdf)?(-manual)?\.xml$", "", stem, flags=re.I)
                n = 0
                for sid, title in bsi.rules(x):
                    doc["rules"][sid] = {"t": title, "s": stem}
                    n += 1
                if not n:
                    print(f"  {os.path.basename(x)}: no rule ids matched the published id shapes —"
                          f" skipped. See build-stig-index.py for the shapes it accepts.")
                    continue
                doc["sources"][stem] = {
                    "rules": n,
                    "supplied_file": os.path.basename(path),
                    "sha256": digest,
                    "ingested": datetime.date.today().isoformat(),
                    "acknowledged_cui": "--acknowledge-cui" in flags,
                }
                added += n
                print(f"  {os.path.basename(x)}: {n} rules"
                      + (f"  (prefixes {', '.join(sorted({s.split('-')[0] for s, _ in bsi.rules(x)}))})"))

    if not added:
        print("ingest-stig: nothing ingested.")
        return 0

    doc["_generator"] = "standards/scripts/ingest-stig.py"
    doc["_provenance"] = ("HUMAN-SUPPLIED files, not a redistribution. Each source records the name "
                          "and SHA-256 of the file it came from. Never regenerated by "
                          "make refresh-frameworks, which would overwrite it.")
    doc["_counts"] = {"rules": len(doc["rules"]), "stigs": len(doc["sources"])}

    if "--dry-run" in flags:
        print(f"ingest-stig: --dry-run, {OUT} not written "
              f"({added} rules would be added, {len(doc['rules'])} total)")
        return 0
    json.dump(doc, open(OUT, "w"), indent=0, sort_keys=True)
    print(f"{OUT}: {len(doc['rules'])} rules from {len(doc['sources'])} human-supplied STIG(s)")
    print("Next: make verify-citations, then update the row in standards/data/FRAMEWORKS.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
