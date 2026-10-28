"""Refuse a gate handoff when the tree has not been scanned green. Port of scan-precondition.sh.

A CVE fix is a dependency bump. Bump after the quality gate has passed and the coverage it blessed
was measured against a dependency set that no longer ships. Scanning BEFORE the gate, and fixing on
the branch, is the only order that avoids a second full pass; this makes that true rather than
remembered. A commit that changes only records (gate-records/, planning/, docs/, tasks/, any
markdown) does not invalidate the scan of the commit before it: a scan reads dependencies, images
and source, and records are none of those.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

RECORD = re.compile(r"^(gate-records/|planning/|docs/|tasks/)|\.md$")
FIX = ("             Fix it on this branch like any other work, then re-run `make gate-scan`.\n"
       "             The gate runs once, against a settled tree.\n"
       "             Cannot scan at all (no Docker)? SKIP_SCAN_CHECK=1 make gate-prompt")


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def check(repo: Path, results: Path, skip_check: bool = False) -> tuple[bool, str]:
    """(ok, message). The message is printed either way when it is not empty."""
    if skip_check:
        return True, ("gate-prompt: WARNING — scan precondition skipped by SKIP_SCAN_CHECK=1.\n"
                      "             The reviewer is being handed a range whose CVE state is unknown. Say so in\n"
                      "             the gate-log row.")

    def refuse(why: str) -> tuple[bool, str]:
        return False, f"gate-prompt: {why}\n{FIX}"

    stamp = results / ".scan-stamp"
    if not stamp.is_file():
        return refuse("no scan recorded for this tree. Run `make gate-scan` first.")
    parts = stamp.read_text(errors="replace").split()
    if len(parts) < 2:
        return refuse(f"scan stamp at {stamp} is unreadable.")
    stamp_sha, verdict = parts[0], parts[1]
    head = _git(repo, "rev-parse", "HEAD").stdout.strip() or "unknown"
    note = ""
    if stamp_sha != head:
        # The stamp must name a commit we can diff; otherwise "only records changed" is unprovable.
        if _git(repo, "rev-parse", "--verify", "-q", f"{stamp_sha}^{{commit}}").returncode != 0:
            return refuse(f"the last scan names {stamp_sha[:8]}, which is not a commit in this repository, and HEAD is {head[:8]}.")
        changed = [f for f in _git(repo, "diff", "--name-only", stamp_sha, head).stdout.splitlines() if f]
        drift = [f for f in changed if not RECORD.search(f)]
        if drift:
            return refuse(f"the last scan describes {stamp_sha[:8]}, HEAD is {head[:8]}, and these non-record files "
                          f"changed between them: {' '.join(drift[:5])}")
        note = (f"gate-prompt: the scan describes {stamp_sha[:8]} and HEAD is {head[:8]}, but every file\n"
                "             between them is a record (gate-records/, planning/, docs/, tasks/, *.md), so the scan\n"
                "             verdict still describes this tree. Not re-scanning.")
    if verdict != "PASS":
        return refuse(f"the last scan on this commit was {verdict}.")
    return True, note
