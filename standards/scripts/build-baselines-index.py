#!/usr/bin/env python3
"""build-baselines-index.py — vendored NIST SP 800-53 Rev 5 baseline membership (SP 800-53B).

WHY THIS EXISTS
  A profile names a baseline: il4 is Moderate, il6 is High. The receipt must list the baseline's
  controls that no gate assessed, so nothing is implied that was not checked. That needs the
  baseline's membership, which the catalog index does not carry. NIST publishes each baseline as an
  OSCAL profile beside the catalog; this reads the Moderate and High profiles and writes their
  control ids in the catalog index's spelling (AC-2(1), not ac-2.1), so the two files join.

USAGE
  python3 standards/scripts/build-baselines-index.py MODERATE.json HIGH.json \\
      > standards/data/controls/nist-800-53r5-baselines.json
  The inputs are NIST_SP-800-53_rev5_{MODERATE,HIGH}-baseline_profile.json from
  https://github.com/usnistgov/oscal-content (nist.gov/SP800-53/rev5/json/).
EXIT  0 written · 1 an input is not a baseline profile or names a control the catalog lacks
"""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path

SOURCE = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/"
          "NIST_SP-800-53_rev5_{level}-baseline_profile.json")
CATALOG = Path(__file__).resolve().parents[1] / "data" / "controls" / "nist-800-53r5-index.json"


def catalog_id(oscal_id: str) -> str:
    """ac-2.1 → AC-2(1); sc-7 → SC-7."""
    m = re.fullmatch(r"([a-z]{2})-(\d+)(?:\.(\d+))?", oscal_id)
    if not m:
        raise ValueError(f"not a control id: {oscal_id!r}")
    family, number, enhancement = m.groups()
    return f"{family.upper()}-{number}" + (f"({enhancement})" if enhancement else "")


def baseline(path: str) -> tuple[str, str, list[str]]:
    doc = json.loads(Path(path).read_text())["profile"]
    title = doc["metadata"]["title"]
    level = "high" if "HIGH" in title.upper() else "moderate" if "MODERATE" in title.upper() else None
    if level is None:
        raise ValueError(f"{path}: not a MODERATE or HIGH baseline profile ({title!r})")
    ids = [catalog_id(i) for imp in doc["imports"] for inc in imp.get("include-controls", []) for i in inc.get("with-ids", [])]
    return level, doc["metadata"].get("version", ""), sorted(set(ids), key=_order)


def _order(cid: str) -> tuple[str, int, int]:
    m = re.fullmatch(r"([A-Z]{2})-(\d+)(?:\((\d+)\))?", cid)
    return (m.group(1), int(m.group(2)), int(m.group(3) or 0)) if m else (cid, 0, 0)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 1
    known = set(json.loads(CATALOG.read_text())["controls"])
    out: dict[str, object] = {
        "_generator": "standards/scripts/build-baselines-index.py",
        "_retrieved": datetime.date.today().isoformat(),
    }
    for path in argv:
        level, version, ids = baseline(path)
        missing = [i for i in ids if i not in known]
        if missing:
            print(f"{path}: {len(missing)} id(s) not in the catalog index, e.g. {missing[:3]}", file=sys.stderr)
            return 1
        out["_catalog_version"] = version
        out[f"_source_{level}"] = SOURCE.format(level=level.upper())
        out[level] = ids
    out["_counts"] = {k: len(out[k]) for k in ("moderate", "high") if k in out}
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
