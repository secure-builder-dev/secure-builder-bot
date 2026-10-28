#!/usr/bin/env python3
"""build-control-index.py — regenerate the vendored NIST 800-53 control index.

WHY THIS EXISTS
  verify-citations.sh has to answer "does this control ID exist, and is it still current?"
  offline. The engine cites ~170 distinct control IDs across the security docs, and until this
  index existed nothing could check a single one of them. SA-12 was cited as a live Rev 5 control
  for four months; it has been withdrawn since Rev 5 shipped. IR-10 likewise.

WHY VENDORED, NOT FETCHED
  Not connectivity — determinism. The engine develops low and ships high, so it has internet. But a
  gate verdict has to be reproducible: two runs on the same commit must reach the same answer, and a
  gate-log row has to point at a verdict someone can re-derive later. Fetch at gate time and the
  catalogue can move between two runs of the same range. So the index is committed, refreshing it is
  a deliberate act that lands in a diff, and every gate-log row is anchored to a known revision.

  (The engine also has an air-gapped sibling that genuinely cannot fetch. Committing the index means
  the same code path serves both without a special case.)

USAGE
  Run only when NIST publishes a new revision of the catalogue, then commit the result and update
  the row in standards/data/FRAMEWORKS.md with the new version, date and SHA.

    curl -sSL -o /tmp/oscal.json \\
      https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
    python3 standards/scripts/build-control-index.py /tmp/oscal.json \\
      standards/data/controls/nist-800-53r5-index.json

  The OSCAL catalogue is ~10MB; the index it produces is ~85KB, because all the checker needs is
  id, title and status. The full catalogue is public domain (NIST) but too large and too noisy to
  carry in the repo.

OUTPUT
  {"_source":..., "_source_sha256":..., "_catalog_version":..., "_retrieved":...,
   "controls": {"AC-3": {"t": "Access Enforcement", "s": "active"},
                "SA-12": {"t": "Supply Chain Protection", "s": "withdrawn", "into": ["SR"]}, ...}}

  ID format is normalised to the form the documents use: OSCAL "ac-3" -> "AC-3",
  "ac-3.7" -> "AC-3(7)", "ac-3.7.1" -> "AC-3(7)(1)".
"""
import datetime
import hashlib
import json
import os
import sys


def fmt(oscal_id):
    """ac-3.7 -> AC-3(7). Enhancements nest, so every dotted segment becomes a parenthesis."""
    parts = oscal_id.split(".")
    return parts[0].upper() + "".join(f"({p})" for p in parts[1:])


def walk(ctrl, idx):
    props = ctrl.get("props", [])
    status = next((p["value"] for p in props if p["name"] == "status"), "active")
    # A withdrawn control names its replacement through an "incorporated-into" link. Carrying that
    # forward is what lets the checker say "SA-12 is withdrawn, use SR" instead of just "unknown".
    into = [fmt(link["href"].lstrip("#")) for link in ctrl.get("links", []) if link.get("rel") == "incorporated-into"]
    entry = {"t": ctrl.get("title", ""), "s": status}
    if into:
        entry["into"] = into
    idx[fmt(ctrl["id"])] = entry
    for child in ctrl.get("controls", []):
        walk(child, idx)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: build-control-index.py <oscal-catalog.json> <out-index.json>")
    src, out = sys.argv[1], sys.argv[2]
    raw = open(src, "rb").read()
    catalog = json.loads(raw)["catalog"]
    md = catalog["metadata"]

    idx = {}
    for group in catalog.get("groups", []):
        for ctrl in group.get("controls", []):
            walk(ctrl, idx)

    withdrawn = sum(1 for v in idx.values() if v["s"] != "active")
    doc = {
        "_source": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
                   "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
        "_catalog_title": md["title"],
        "_catalog_version": md.get("version"),
        "_catalog_last_modified": md.get("last-modified"),
        "_source_sha256": hashlib.sha256(raw).hexdigest(),
        "_retrieved": datetime.date.today().isoformat(),
        "_generator": "standards/scripts/build-control-index.py",
        "_counts": {"controls": len(idx), "withdrawn": withdrawn},
        "controls": idx,
    }
    json.dump(doc, open(out, "w"), indent=0, sort_keys=True)
    print(f"{out}: {len(idx)} controls, {withdrawn} withdrawn, "
          f"{os.path.getsize(out)//1024} KB, catalogue {md.get('version')}")


if __name__ == "__main__":
    main()
