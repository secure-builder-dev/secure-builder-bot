#!/usr/bin/env python3
"""make-upstream.py — the offline refresh fixtures, generated from the vendored indexes.

The refresh (`standards/run refresh --offline DIR`) reads each upstream as the builders expect it:
NIST's OSCAL catalog and baseline profiles as JSON, the OWASP lists as checkouts (`Top10/<year>/
mkdocs.yml`, `llm/2_0_vulns/LLMnn_Title.md`), MASVS as `masvs/OWASP_MASVS.yaml`. The real catalog is
ten megabytes; the builders read only ids, titles, status and the incorporated-into links, so a
catalog carrying just those regenerates an index identical to the vendored one. That is what makes
"nothing to do" provable offline against the real vendored data.

Three fixtures: `upstream-unchanged` regenerates to the vendored indexes exactly; `upstream-added-
control` is the same catalog at version 5.2.1 with one control added; `upstream-withdrawn-cited`
withdraws AC-3, which engine/SENTINEL-CHECKLIST.md cites, so the refresh must refuse it. STIG and
NIST-publication upstreams need a git checkout and are exercised from tests with temporary repos.

USAGE   python3 standards/tests/fixtures/make-upstream.py   (from the repository root; rewrites all three)
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE.parents[1] / "data" / "controls"
CATALOG_NAME = "NIST_SP-800-53_rev5_catalog.json"
BASELINE_NAME = "NIST_SP-800-53_rev5_{LEVEL}-baseline_profile.json"


def oscal_id(cid: str) -> str:
    """AC-2(1) → ac-2.1, the catalog's own spelling."""
    return re.sub(r"\(([^)]+)\)", r".\1", cid).lower()


def catalog_doc(controls: dict, version: str, last_modified: str) -> dict:
    by_family: dict[str, dict[str, dict]] = {}
    for cid, e in controls.items():
        node = {"id": oscal_id(cid), "title": e["t"], "props": [{"name": "status", "value": e["s"]}]}
        if e.get("into"):
            node["links"] = [{"rel": "incorporated-into", "href": "#" + oscal_id(i)} for i in e["into"]]
        fam = cid.split("-")[0].lower()
        base = cid.split("(")[0]
        if "(" in cid:
            by_family.setdefault(fam, {})[base].setdefault("controls", []).append(node)
        else:
            by_family.setdefault(fam, {})[cid] = node
    groups = [{"id": fam, "class": "family", "controls": list(members.values())} for fam, members in by_family.items()]
    return {"catalog": {"uuid": "00000000-0000-4000-8000-000000000000",
                        "metadata": {"title": "Electronic (OSCAL) Version of NIST SP 800-53 Rev 5 Controls (fixture)",
                                     "version": version, "last-modified": last_modified, "oscal-version": "1.1.2"},
                        "groups": groups}}


def profile_doc(level: str, ids: list[str], version: str) -> dict:
    return {"profile": {"uuid": "00000000-0000-4000-8000-00000000000" + ("1" if level == "MODERATE" else "2"),
                        "metadata": {"title": f"NIST SP 800-53 Rev 5 {level} Baseline Profile (fixture)", "version": version},
                        "imports": [{"href": "#catalog", "include-controls": [{"with-ids": [oscal_id(i) for i in ids]}]}]}}


def write_nist(out: Path, controls: dict, version: str, last_modified: str, baselines: dict) -> None:
    (out / CATALOG_NAME).write_text(json.dumps(catalog_doc(controls, version, last_modified), separators=(",", ":")) + "\n")
    for level in ("MODERATE", "HIGH"):
        (out / BASELINE_NAME.format(LEVEL=level)).write_text(
            json.dumps(profile_doc(level, baselines[level.lower()], version), separators=(",", ":")) + "\n")


def write_owasp(out: Path, owasp: dict) -> None:
    for year, items in owasp["web"]["editions"].items():
        d = out / "Top10" / year
        d.mkdir(parents=True, exist_ok=True)
        nav = "".join(f"  - {oid} {title}: '{year}/{oid}_{title.replace(' ', '_')}.md'\n" for oid, title in items.items())
        (d / "mkdocs.yml").write_text(f"site_name: OWASP Top 10 {year} (fixture)\nnav:\n  - Home: 'index.md'\n{nav}")
    for year, folder in (("2025", "2_0_vulns"), ("2023", "1_1_vulns")):
        items = owasp["llm"]["editions"].get(year)
        if not items:
            continue
        d = out / "llm" / folder
        d.mkdir(parents=True, exist_ok=True)
        for oid, title in items.items():
            (d / f"{oid}_{title.replace(' ', '')}.md").write_text(f"# {oid}: {title}\n")


def write_masvs(out: Path, masvs: dict) -> None:
    d = out / "masvs"
    d.mkdir(parents=True, exist_ok=True)
    lines = ["metadata:", "  title: OWASP MASVS (fixture)", "  version: vx.x.x", "groups:"]
    for i, (gid, title) in enumerate(masvs["groups"].items(), 1):
        lines += [f"- id: {gid}", f"  index: {i}", f"  title: {title}", "  controls:"]
        for cid, statement in masvs["controls"].items():
            if cid.startswith(gid + "-"):
                lines += [f"  - id: {cid}", f"    statement: {statement}"]
    (d / "OWASP_MASVS.yaml").write_text("\n".join(lines) + "\n")


def build(name: str, controls: dict, version: str, last_modified: str, baselines: dict, owasp: dict, masvs: dict) -> None:
    out = HERE / name
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    write_nist(out, controls, version, last_modified, baselines)
    write_owasp(out, owasp)
    write_masvs(out, masvs)
    print(f"{out.relative_to(HERE.parents[2])}: {len(controls)} controls, catalog {version}")


def main() -> int:
    nist = json.loads((DATA / "nist-800-53r5-index.json").read_text())
    baselines = json.loads((DATA / "nist-800-53r5-baselines.json").read_text())
    owasp = json.loads((DATA / "owasp-index.json").read_text())
    masvs = json.loads((DATA / "masvs-index.json").read_text())
    controls = dict(nist["controls"])
    version, modified = nist["_catalog_version"], nist["_catalog_last_modified"]
    build("upstream-unchanged", controls, version, modified, baselines, owasp, masvs)

    added = dict(controls)
    added["AC-99"] = {"t": "Example Control Added Upstream", "s": "active"}
    build("upstream-added-control", added, "5.2.1", "2026-11-01T00:00:00.00000-00:00", baselines, owasp, masvs)

    withdrawn = dict(controls)
    withdrawn["AC-3"] = {"t": controls["AC-3"]["t"], "s": "withdrawn", "into": ["AC-2"]}
    build("upstream-withdrawn-cited", withdrawn, "5.2.1", "2026-11-01T00:00:00.00000-00:00", baselines, owasp, masvs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
