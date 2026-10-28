"""Verdicts: the scan's one line, and the run's verdict across gates.

The scan line is a port of gate-line.sh. Its rule, unchanged: a scanner counts as having run only
if it left a receipt saying so AND its result file is present and readable; a declared empty scope
counts as ran and is named; anything in dispatch.md (a fixable High/Critical or malware) blocks; a
scanner that did not run blocks, because a partial scan reporting nothing is indistinguishable from
a clean one. POAM candidates (no upstream fix) are carried, never blocking.
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .gate import GateResult

SCANNERS = (("hadolint", "hadolint.json"), ("checkov", "checkov.json"), ("clamav", "clamav.log"),
            ("grype", "grype.json"), ("trivy", "trivy.json"), ("npm-audit", "audit.json"), ("eslint", "eslint.json"))
DEFAULT_RESULTS = "gate-records/scan/latest"


@dataclass(frozen=True)
class ScanVerdict:
    verdict: str                 # PASS, FAIL, or NOT RUN
    ran: int
    total: int
    missing: tuple[str, ...]     # "name" or "name(why)"
    empty_scope: tuple[str, ...]
    skipped: tuple[str, ...]     # turned off by the config: not counted, always named
    fixable: int
    poam: int
    malware: bool
    line: str

    @property
    def passed(self) -> bool:
        return self.verdict == "PASS"


def _receipt_kinds(results: Path) -> dict[str, str]:
    kinds: dict[str, str] = {}
    f = results / "scanners-ran"
    if f.is_file():
        for line in f.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] not in kinds:
                kinds[parts[0]] = parts[1]
    return kinds


def _readable(path: Path) -> str | None:
    """None when the file is a usable result; otherwise why not."""
    if not path.is_file() or path.stat().st_size == 0:
        return "no result"
    if path.suffix == ".json":
        try:
            json.loads(path.read_text(errors="replace"))
        except ValueError:
            return "unreadable"
    elif path.name == "clamav.log" and "Infected files:" not in path.read_text(errors="replace"):
        return "no summary"
    return None


def _count(path: Path, prefix: str) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(errors="replace").splitlines() if line.startswith(prefix))


def scan_verdict(results: Path, skip: tuple[str, ...] = ()) -> ScanVerdict:
    if not results.is_dir() or not any(results.iterdir()):
        line = f"Scan: NOT RUN — no results at {results}. This is not a pass; run `make scan`."
        return ScanVerdict("NOT RUN", 0, len(SCANNERS), (), (), tuple(skip), 0, 0, False, line)
    kinds = _receipt_kinds(results)
    ran, missing, empty = 0, [], []
    counted = [(n, f) for n, f in SCANNERS if n not in skip]
    for name, filename in counted:
        kind = kinds.get(name)
        if not kind:
            missing.append(name)
            continue
        why = _readable(results / filename)
        if why:
            missing.append(f"{name}({why})")
            continue
        ran += 1
        if kind == "none":
            empty.append(name)
    dispatch = results / "dispatch.md"
    fixable = _count(dispatch, "### ")
    poam = _count(results / "poam-candidates.md", "## ")
    malware = dispatch.is_file() and "INFECTION DETECTED" in dispatch.read_text(errors="replace")
    total = len(counted)
    blocking = dispatch.is_file() or ran < total
    verdict = "FAIL" if blocking else "PASS"
    line = (f"Scan: {verdict} — {ran}/{total} scanners ran"
            + (f" (did not run: {' '.join(missing)})" if missing else "")
            + (f" (nothing in scope: {' '.join(empty)})" if empty else "")
            + (f" (skipped by config: {' '.join(skip)})" if skip else "")
            + f" · {fixable} fixable" + (" · MALWARE DETECTED" if malware else "")
            + f" · {poam} POAM candidate(s), not blocking")
    return ScanVerdict(verdict, ran, total, tuple(missing), tuple(empty), tuple(skip), fixable, poam, malware, line)


def write_stamp(results: Path, repo: Path, verdict: str) -> None:
    """Record which commit was scanned. Only a caller that actually scanned may stamp."""
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip() or "unknown"
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        (results / ".scan-stamp").write_text(f"{sha} {verdict} {now}\n")
    except OSError:
        pass  # a stamp that cannot be written leaves the precondition refusing, which is the safe side


def results_dir(repo: Path, explicit: str | None) -> Path:
    raw = explicit or os.environ.get("SCAN_RESULTS_DIR") or DEFAULT_RESULTS
    p = Path(raw)
    return p if p.is_absolute() else repo / p


# ── The run's verdict across gates ────────────────────────────────────────────────────────────

GATE_LABEL = {"scan": "Scan", "qa": "QA", "sentinel": "Sentinel"}


def overall(results: list[GateResult], relaxations: tuple[str, ...]) -> str:
    if any(r.status in ("fail", "not_run") for r in results):
        return "fail"
    if relaxations or any(r.status == "yellow" for r in results):
        return "yellow"
    return "pass"


def verdict_block(results: list[GateResult], relaxations: tuple[str, ...]) -> list[str]:
    lines = []
    for r in results:
        text = f"{GATE_LABEL[r.gate]}: {r.status.upper().replace('_', ' ')}"
        if r.reason:
            text += f" — {r.reason}"
        lines.append(text)
    for x in relaxations:
        lines.append(f"Relaxed: {x}")
    lines.append(f"Overall: {overall(results, relaxations).upper()}")
    return lines


def verdict_json(results: list[GateResult], relaxations: tuple[str, ...], exit_code: int) -> dict:
    return {
        "overall": overall(results, relaxations),
        "exit_code": exit_code,
        "relaxations": list(relaxations),
        "gates": [{"gate": r.gate, "status": r.status, "reason": r.reason,
                   "blocking_findings": sum(1 for f in r.findings if f.severity == "blocking"),
                   "advisory_findings": sum(1 for f in r.findings if f.severity == "advisory")}
                  for r in results],
    }
