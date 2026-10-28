#!/usr/bin/env python3
"""build-nistpubs-index.py — which revision of each NIST SP and FIPS is the current one.

WHY THIS EXISTS
  Six rows in FRAMEWORKS.md sat at "verified: —". The engine cites NIST SP 800-163 Rev 1, SP 800-124
  Rev 2, SP 800-157 and the FIPS set by name, and nothing could answer the only question that
  matters for a named-by-revision citation: has NIST published a newer one? "Unverified" was being
  used as a resting state, which is the thing this whole workstream exists to delete.

  It is a different check from verify-citations' 800-53 work. That one asks "does this control ID
  exist and is it withdrawn". This one asks "is Rev 1 still the current revision of this document".
  Renumbering is not the risk here — supersession is.

SOURCE (primary — NIST's own publication metadata repository)
    github.com/usnistgov/NIST-Tech-Pubs — the filenames under bib/ encode series, number, revision
    and draft stage: NIST.SP.800-124r2.ris, NIST.SP.800-157r1.ipd.ris, NIST.FIPS.140-3.ris.

  Only the filenames are needed, so the clone is blobless and this script reads the git tree rather
  than 20,000 files. csrc.nist.gov would be the more direct source; it is unreachable from some CI
  networks, and this repository is NIST's own, on a host that is not.

DRAFTS ARE NOT REVISIONS
  A `.ipd` (initial public draft), `.fpd` (final public draft) or `.2pd` suffix marks a document
  that is not published yet. Counting one as the current revision would tell a project to cite
  something that does not exist. Drafts are recorded in their own field and reported as a heads-up,
  never as supersession.

USAGE
    git clone --depth 1 --filter=blob:none https://github.com/usnistgov/NIST-Tech-Pubs.git /tmp/ntp
    python3 standards/scripts/build-nistpubs-index.py /tmp/ntp \\
        standards/data/controls/nist-pubs-index.json

  `make refresh-frameworks` does this for you.
"""
import datetime
import json
import os
import re
import subprocess
import sys

# NIST.<SERIES>.<NUMBER>[r<REV>][.<draft stage>].ris
# The number is non-greedy so an optional `r<n>` revision is split off correctly: 800-56Ar2 is
# number 800-56A revision 2, while FIPS 140-3 is number 140-3 with no revision at all — the 3 is
# part of the publication number, not a revision of 140. Getting that backwards would report a
# nonexistent "FIPS 140 Rev 3".
NAME = re.compile(r"^NIST\.(SP|FIPS)\.(\d.*?)(?:r(\d+))?(?:\.(ipd|fpd|2pd|3pd|upd\d*))?\.ris$")


def names(repo):
    """Filenames under bib/, straight from the git tree — no blobs are fetched."""
    out = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "--name-only", "HEAD", "--", "bib/"],
                         capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        sys.exit(f"build-nistpubs-index: git ls-tree failed — {out.stderr.strip()[:200]}")
    return [os.path.basename(line) for line in out.stdout.splitlines() if line.endswith(".ris")]


def head(repo):
    try:
        return subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=20).stdout.strip()[:12]
    except Exception:
        return ""


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: build-nistpubs-index.py <NIST-Tech-Pubs-repo> <out.json>")
    repo, out = sys.argv[1], sys.argv[2]
    if not os.path.isdir(os.path.join(repo, ".git")):
        sys.exit(f"build-nistpubs-index: {repo} is not a git checkout")

    pubs = {}
    for fn in names(repo):
        m = NAME.match(fn)
        if not m:
            continue
        series, number, rev, stage = m.group(1), m.group(2), m.group(3), m.group(4)
        key = f"{series} {number}"
        e = pubs.setdefault(key, {"revisions": [], "drafts": []})
        label = f"r{rev}" if rev else ""
        if stage:
            e["drafts"].append(f"{label}.{stage}" if label else stage)
        elif label not in e["revisions"]:
            e["revisions"].append(label)

    if len(pubs) < 100:
        sys.exit(f"build-nistpubs-index: only {len(pubs)} publications parsed — bib/ has changed shape")

    for e in pubs.values():
        # "" is the original, unrevised edition and is the lowest, not the highest.
        e["revisions"].sort(key=lambda r: int(r[1:]) if r else 0)
        e["drafts"].sort()
        e["latest"] = e["revisions"][-1] if e["revisions"] else ""

    doc = {
        "_retrieved": datetime.date.today().isoformat(),
        "_generator": "standards/scripts/build-nistpubs-index.py",
        "_source": {
            "repo": "https://github.com/usnistgov/NIST-Tech-Pubs",
            "commit": head(repo),
            "parsed_from": "bib/ filenames via git ls-tree (blobless clone; no file contents read)",
        },
        "_note": ("`latest` is the newest PUBLISHED revision. Drafts (.ipd/.fpd/.2pd) are listed "
                  "separately and never counted as one — citing a draft as current would point a "
                  "project at a document that does not exist yet."),
        "_counts": {"publications": len(pubs)},
        "pubs": dict(sorted(pubs.items())),
    }
    json.dump(doc, open(out, "w"), indent=0, sort_keys=True)
    print(f"{out}: {len(pubs)} NIST publications, {os.path.getsize(out)//1024} KB")


if __name__ == "__main__":
    main()
