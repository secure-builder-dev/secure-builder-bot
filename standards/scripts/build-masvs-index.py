#!/usr/bin/env python3
"""build-masvs-index.py — vendored index of the OWASP MASVS controls.

WHY THIS SOURCE
  The Android track needs a mobile security baseline that can actually be VERIFIED. The obvious
  candidate, the DISA Mobile Application STIG, cannot be: DISA publishes it behind DoD PKI, it is
  CUI-marked, and the development machines this engine runs on are not CUI workstations — so it
  cannot enter this repository at all. That is a boundary, not a gap, and FRAMEWORKS.md records it
  as one.

  OWASP MASVS is the replacement with the property that matters here: it ships a machine-readable
  catalogue, `OWASP_MASVS.yaml`, in the project's own repository. Every id the Android checklist
  cites can therefore be checked against the publisher's own file, the same way NIST and the OWASP
  Top 10 already are. MASVS is not a DoD authority and does not pretend to be — see the Android
  checklist header. It is what makes "no verifiable mobile grounding" untrue.

THE DEFECT CLASS IT CATCHES
  MASVS v1 numbered its requirements `MSTG-*`; v2 renumbered the whole standard to `MASVS-<GROUP>-n`
  and dropped or merged several. A v1 id is not a typo — it is a citation against a superseded
  edition, the same defect that put `LLM08` next to excessive agency for months. The index carries
  the edition so verify-citations can name it.

SOURCE (primary — the MASVS project's own repository)
    github.com/OWASP/masvs — OWASP_MASVS.yaml, `groups:` -> `controls:` with id + statement

USAGE
    git clone --depth 1 https://github.com/OWASP/masvs.git /tmp/masvs
    python3 standards/scripts/build-masvs-index.py /tmp/masvs \\
        standards/data/controls/masvs-index.json

  `make refresh-frameworks` does this for you.
"""
import datetime
import json
import os
import re
import subprocess
import sys

# The YAML is small, regular and hand-maintained; parsing it with two regexes keeps this script
# dependency-free (PyYAML is not guaranteed present in CI). If upstream ever restructures the file,
# the "no controls parsed" exit below is the tripwire — it fails loudly rather than emitting an
# empty index that would make the checker inert.
CONTROL = re.compile(r"^  - id: (MASVS-[A-Z]+-\d+)\n    statement: (.+)$", re.M)
GROUP = re.compile(r"^- id: (MASVS-[A-Z]+)\n  index: \d+\n  title: (.+)$", re.M)


def release(repo):
    """The newest published release tag. Informational only — see `_edition_note` below: the
    machine-readable catalogue is maintained on the default branch and post-dates the tag, so the
    reproducible pin is the COMMIT, not this."""
    try:
        out = subprocess.run(["git", "-C", repo, "ls-remote", "--tags", "origin"],
                             capture_output=True, text=True, timeout=60).stdout
        tags = {m.group(1) for m in re.finditer(r"refs/tags/(v[\d.]+)(?:\^\{\})?$", out, re.M)}
        if tags:
            return max(tags, key=lambda v: [int(x) for x in v.lstrip("v").split(".")])
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""  # no tags reachable: informational only, the commit is the pin
    return ""


def head(repo):
    try:
        return subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=20).stdout.strip()[:12]
    except Exception:
        return ""


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: build-masvs-index.py <masvs-repo> <out.json>")
    repo, out = sys.argv[1], sys.argv[2]
    src = os.path.join(repo, "OWASP_MASVS.yaml")
    if not os.path.isfile(src):
        sys.exit(f"build-masvs-index: {src} not found — is that an OWASP/masvs checkout?")

    txt = open(src, encoding="utf-8", errors="replace").read()
    controls = {m.group(1): m.group(2).strip() for m in CONTROL.finditer(txt)}
    groups = {m.group(1): m.group(2).strip() for m in GROUP.finditer(txt)}
    if not controls:
        sys.exit("build-masvs-index: no controls parsed — OWASP_MASVS.yaml has changed shape")

    # The repository carries the same controls twice: the YAML catalogue and one markdown file per
    # control. Cross-checking them catches a regex that silently stopped matching a group — the
    # failure mode that would hand the gate a short index and a false green.
    cdir = os.path.join(repo, "controls")
    if os.path.isdir(cdir):
        on_disk = {f[:-3] for f in os.listdir(cdir) if f.startswith("MASVS-") and f.endswith(".md")}
        if on_disk and on_disk != set(controls):
            missing = sorted(on_disk - set(controls)) or sorted(set(controls) - on_disk)
            sys.exit(f"build-masvs-index: YAML and controls/ disagree — {missing}")

    doc = {
        "_retrieved": datetime.date.today().isoformat(),
        "_generator": "standards/scripts/build-masvs-index.py",
        "_source": {
            "repo": "https://github.com/OWASP/masvs",
            "commit": head(repo),
            "parsed_from": "OWASP_MASVS.yaml groups[].controls[]",
        },
        "_latest_release": release(repo),
        "_edition_note": (
            "OWASP_MASVS.yaml is maintained on the default branch and its own metadata.version is a "
            "placeholder ('vx.x.x'); the newest release tag ships the same controls as per-control "
            "markdown but no machine-readable catalogue. The reproducible pin is _source.commit. "
            "Verified by hand on 2026-09-19 that this id set matches the v2.1.0 release's controls/ "
            "directory exactly; the builder re-checks the YAML against controls/ on every run."),
        "_superseded_numbering": "MSTG-* — MASVS v1 requirement ids, renumbered wholesale in v2",
        "_counts": {"controls": len(controls), "groups": len(groups)},
        "groups": groups,
        "controls": controls,
    }
    json.dump(doc, open(out, "w"), indent=1, sort_keys=True)
    print(f"{out}: {len(controls)} MASVS controls in {len(groups)} groups "
          f"(release {doc['_latest_release'] or '?'}, commit {doc['_source']['commit'] or '?'}), "
          f"{os.path.getsize(out)//1024} KB")


if __name__ == "__main__":
    main()
