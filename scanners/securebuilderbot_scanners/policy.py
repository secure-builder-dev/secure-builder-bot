"""The profile's scan policy, applied to what the scanners found (docs/PRD.md § Compliance profiles).

"Any critical or high CVE without an accepted-risk entry fails the gate": a CVE at or above the
profile's `fail_on` severity that no valid accepted-risk entry covers is blocking, fix available or
not. At il6 a medium CVE published more than `medium_max_age_days` ago is blocking too, and one whose
published date no scanner carries cannot be shown to be young, so it blocks as well. A CVE no scanner
rated (pip-audit emits no severity) is treated as blocking at every profile: an unknown severity is
not a low one.

Accepted risks live in the file `scan.accepted_risks` names (docs/security/accepted-risks.yml): a list
of {id, reason, expires: YYYY-MM-DD, scope?}. An entry is usable only with an id, a reason and a date
that is neither past nor further out than the profile's `accepted_risk_expiry_days`; an entry that is
not usable is itself a blocking finding, and covers nothing. An applied entry turns the run yellow.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

import yaml

from securebuilderbot_core.profiles import ScanPolicy

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0}
_NPM_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "negligible"}
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class Cve:
    id: str
    severity: str            # critical | high | medium | low | negligible | unknown
    package: str
    version: str
    fix: str                 # a version, or "none"
    published: datetime | None
    scanner: str
    file: str                # evidence under the run directory
    aliases: tuple[str, ...] = ()
    note: str = ""           # e.g. "dev-only" for an npm advisory outside the production tree
    app: str = ""            # the npm app an npm audit record came from

    @property
    def ids(self) -> frozenset[str]:
        return frozenset((self.id, *self.aliases))


@dataclass(frozen=True)
class AcceptedRisk:
    id: str
    reason: str
    expires: str
    scope: str | None = None


@dataclass
class Policy:
    blocking: list[tuple[Cve, str]] = field(default_factory=list)   # (cve, why)
    advisory: list[tuple[Cve, str]] = field(default_factory=list)
    applied: list[dict] = field(default_factory=list)               # accepted risks that covered a CVE
    bad_entries: list[tuple[str, str]] = field(default_factory=list)  # (id, why the entry is not usable)


def _json(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def parse_utc(stamp: str | None) -> datetime | None:
    """A scanner's timestamp to an aware UTC datetime. Seconds precision: Trivy writes nanoseconds."""
    m = re.match(r"(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}:\d{2}))?", stamp or "")
    return datetime.fromisoformat(f"{m.group(1)}T{m.group(2) or '00:00:00'}+00:00") if m else None


_when = parse_utc


def cves_from_results(results: Path) -> list[Cve]:
    """Every vulnerability the scanners reported, one record per (id, package), the best-rated scanner's word.

    Grype and Trivy rate and (Trivy) date; npm audit rates; pip-audit does neither, so a pip-audit
    finding that another scanner also reported, by id or alias and package, takes that scanner's
    rating and is not reported twice.
    """
    rated: list[Cve] = []
    for m in _json(results / "grype.json").get("matches", []) or []:
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        fixes = (v.get("fix") or {}).get("versions") or []
        rated.append(Cve(id=str(v.get("id", "")), severity=str(v.get("severity", "unknown")).lower(), package=str(a.get("name", "")),
                         version=str(a.get("version", "")), fix=str(fixes[0]) if fixes else "none", published=None,
                         scanner="grype", file="scan/results/grype.json"))
    for r in _json(results / "trivy.json").get("Results", []) or []:
        for v in r.get("Vulnerabilities", []) or []:
            rated.append(Cve(id=str(v.get("VulnerabilityID", "")), severity=str(v.get("Severity", "unknown")).lower(),
                             package=str(v.get("PkgName", "")), version=str(v.get("InstalledVersion", "")),
                             fix=str(v.get("FixedVersion") or "none"), published=_when(v.get("PublishedDate")),
                             scanner="trivy", file="scan/results/trivy.json"))
    audit = _json(results / "audit.json")
    for key, note in (("blocking", ""), ("allowlisted", "npm allowlist entry"), ("dev_only", "dev-only"), ("reported", "")):
        for a in audit.get(key, []) or []:
            rated.append(Cve(id=str(a.get("id", "")), severity=_NPM_SEVERITY.get(str(a.get("severity", "")).lower(), "unknown"),
                             package=str(a.get("package", "")), version=str(a.get("range", "")), fix=str(a.get("fix") or "none"),
                             published=None, scanner="npm-audit", file="scan/results/audit.json", note=note,
                             app=str(a.get("app", ""))))
    pip = _json(results / "pip-audit.json")
    unrated: list[Cve] = []
    for key in ("blocking", "reported"):
        for v in pip.get(key, []) or []:
            c = Cve(id=str(v.get("id", "")), severity="unknown", package=str(v.get("package", "")), version=str(v.get("version", "")),
                    fix=str(v.get("fix") or "none"), published=None, scanner="pip-audit", file="scan/results/pip-audit.json",
                    aliases=tuple(str(x) for x in v.get("aliases", []) or []))
            if not any(c.ids & r.ids and r.package.lower() == c.package.lower() and r.note != "dev-only" for r in rated):
                unrated.append(c)
    # A dev-only grade is npm audit's statement about ONE app's dependency tree. It is never merged
    # with another record: merged on (id, package) it suppressed the same advisory where it IS
    # production-reachable in another app, or found by Grype or Trivy in a shipped image (gate run 1,
    # B-3). It keeps a key of its own, so it is reported as itself and covers nothing else.
    seen: dict[tuple[str, ...], Cve] = {}
    for c in rated + unrated:
        if not c.id:
            continue
        key: tuple[str, ...] = (c.id, c.package.lower())
        if c.note == "dev-only":
            key = (*key, "dev-only", c.app)
        prev = seen.get(key)
        if prev is None:
            seen[key] = c
            continue
        # Two scanners on the same CVE and package: keep the higher rating, and a date if either has one.
        best = c if SEVERITY_RANK.get(c.severity, 5) > SEVERITY_RANK.get(prev.severity, 5) else prev
        published = prev.published or c.published
        fix = prev.fix if prev.fix != "none" else c.fix
        seen[key] = Cve(id=best.id, severity=best.severity, package=best.package, version=best.version, fix=fix, published=published,
                        scanner=f"{prev.scanner}+{c.scanner}" if c.scanner != prev.scanner else prev.scanner, file=best.file,
                        aliases=tuple(sorted((prev.ids | c.ids) - {best.id})), note=prev.note or c.note)
    return list(seen.values())


def is_blocking(cve: Cve, policy: ScanPolicy, now: datetime) -> str | None:
    """Why this CVE blocks under the profile, or None when it does not. The fail-on rule (CM-21)."""
    if cve.note == "dev-only":
        return None  # npm audit proved it is outside the production tree (DEPENDENCY_POLICY rule 7 as amended)
    if cve.severity not in SEVERITY_RANK:
        return "unrated by every scanner that reported it, and an unknown severity is not a low one"
    if cve.severity in policy.fail_on:
        return f"{cve.severity} is at or above the profile's fail-on severity"
    if cve.severity == "medium" and policy.medium_max_age_days is not None:
        if cve.published is None:
            return f"medium with no published date in any result file, so it cannot be shown to be under {policy.medium_max_age_days} days old"
        if cve.published > now:  # a negative age is under every limit; a future date shows nothing (N-07)
            return f"medium with a published date in the future ({cve.published.date()}), so it cannot be shown to be under {policy.medium_max_age_days} days old"
        age = (now - cve.published).days
        if age > policy.medium_max_age_days:
            return f"medium and published {age} days ago; the profile allows {policy.medium_max_age_days}"
    return None


def entry_problem(entry: dict, today: date, max_days: int | None) -> str | None:
    """Why an accepted-risk entry cannot be used, or None when it can. The expiry rule (CM-22)."""
    if not isinstance(entry, dict):
        return "an entry must be a mapping with id, reason and expires"
    if not str(entry.get("id") or "").strip():
        return "no id"
    if not str(entry.get("reason") or "").strip():
        return "no reason"
    expires = str(entry.get("expires") or "")
    if not DATE.match(expires):
        return "expires is not a YYYY-MM-DD date"
    try:
        when = date.fromisoformat(expires)
    except ValueError:
        return "expires is not a real date"
    if when < today:
        return f"expired on {expires}"
    if max_days is not None and when > today + timedelta(days=max_days):
        return f"expires {expires}, further out than the {max_days} days the profile allows"
    return None


def load_accepted_risks(path: Path, today: date, max_days: int | None) -> tuple[list[AcceptedRisk], list[tuple[str, str]]]:
    """(usable entries, [(id, why) for the rest]). A missing file is no entries; an unreadable one is one bad entry."""
    if not path.is_file():
        return [], []
    try:
        doc = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as e:
        return [], [(path.name, f"not readable as YAML: {type(e).__name__}")]
    entries = doc.get("entries", doc.get("accepted_risks", [])) if isinstance(doc, dict) else doc
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        return [], [(path.name, "the file must hold a list of entries")]
    good, bad = [], []
    for i, e in enumerate(entries):
        why = entry_problem(e, today, max_days)
        ident = str(e.get("id") or f"entry {i + 1}") if isinstance(e, dict) else f"entry {i + 1}"
        if why:
            bad.append((ident, why))
        else:
            scope = e.get("scope")
            good.append(AcceptedRisk(id=str(e["id"]).strip(), reason=str(e["reason"]).strip(), expires=str(e["expires"]),
                                     scope=str(scope).strip() if scope else None))
    return good, bad


def covers(entry: AcceptedRisk, cve: Cve) -> bool:
    if entry.id not in cve.ids:
        return False
    if entry.scope is None:
        return True
    # A package name, or a result file by its path or its name, matched whole. A substring match let
    # `scope: json` or `scope: results` cover the id in every result file (gate run 1, N-05).
    return entry.scope.lower() == cve.package.lower() or entry.scope in (cve.file, Path(cve.file).name)


def apply(cves: list[Cve], policy: ScanPolicy, accepted: list[AcceptedRisk], bad: list[tuple[str, str]], now: datetime) -> Policy:
    out = Policy(bad_entries=list(bad))
    for cve in sorted(cves, key=lambda c: (-SEVERITY_RANK.get(c.severity, 5), c.id, c.package)):
        why = is_blocking(cve, policy, now)
        if why is None:
            out.advisory.append((cve, f"{cve.severity}, below the profile's fail-on severity" if cve.note != "dev-only" else "dev-only (outside the production tree)"))
            continue
        entry = next((e for e in accepted if covers(e, cve)), None)
        if entry is None:
            out.blocking.append((cve, why))
        else:
            out.applied.append({"id": cve.id, "package": cve.package, "expires": entry.expires, "reason": entry.reason})
            out.advisory.append((cve, f"{why}; accepted until {entry.expires}: {entry.reason}"))
    return out
