"""Compliance profiles: one word in the config that selects a baseline, STIGs, checklist blocks and
thresholds together (docs/PRD.md § Compliance profiles).

Profiles are data, never code: `core/profiles/<name>.yml` holds the numbers, and the baseline's
control list comes from NIST's own OSCAL baselines, vendored as
`standards/data/controls/nist-800-53r5-baselines.json`. A profile file with an unknown or missing
key is refused, because a typo in a threshold must never become a silently lower bar.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

from .receipt import shown

PACKAGE_DIR = Path(__file__).resolve().parent
PROFILES_DIR = PACKAGE_DIR.parent / "profiles"
CONTROLS_DIR = PACKAGE_DIR.parents[1] / "standards" / "data" / "controls"
NAMES = ("none", "il4", "il6")
_SEVERITIES = ("critical", "high", "medium", "low")
_BLOCKS = ("base", "moderate", "high")


class ProfileError(ValueError):
    """A profile that does not exist, or a profile file that does not say what a profile must."""


@dataclass(frozen=True)
class ScanPolicy:
    fail_on: tuple[str, ...]
    medium_max_age_days: int | None
    cve_data_max_age_days: int | None


@dataclass(frozen=True)
class QaPolicy:
    coverage_changed_lines: int
    mutation_required: bool


@dataclass(frozen=True)
class Profile:
    name: str
    title: str
    baseline: str | None
    catalog_version: str
    controls: frozenset[str]
    owasp_top10: bool
    stigs: tuple[str, ...]
    stigs_where_present: tuple[str, ...]
    stig_cat1_enforced: bool
    checklist_blocks: tuple[str, ...]
    scan: ScanPolicy
    qa: QaPolicy
    accepted_risk_expiry_days: int | None


@functools.cache
def _baselines() -> dict:
    return json.loads((CONTROLS_DIR / "nist-800-53r5-baselines.json").read_text())


@functools.cache
def catalog_ids() -> frozenset[str]:
    return frozenset(json.loads((CONTROLS_DIR / "nist-800-53r5-index.json").read_text())["controls"])


def _expect(doc: dict, key: str, kinds: tuple[type, ...], where: str) -> object:
    if key not in doc:
        raise ProfileError(f"{where}: missing key {key!r}")
    value = doc[key]
    if not isinstance(value, kinds) or (isinstance(value, bool) and bool not in kinds):
        raise ProfileError(f"{where}: {key!r} has the wrong type ({type(value).__name__})")
    return value


def _strings(doc: dict, key: str, where: str, allowed: tuple[str, ...] | None = None) -> tuple[str, ...]:
    items = _expect(doc, key, (list,), where)
    for item in items:
        if not isinstance(item, str) or (allowed is not None and item not in allowed):
            raise ProfileError(f"{where}: {key!r} has an invalid entry {item!r}")
    return tuple(items)


def _days(doc: dict, key: str, where: str) -> int | None:
    value = _expect(doc, key, (int, type(None)), where)
    if value is not None and value <= 0:
        raise ProfileError(f"{where}: {key!r} must be a positive number of days")
    return value


def _check_keys(doc: dict, expected: set[str], where: str) -> None:
    unknown = sorted(set(doc) - expected)
    if unknown:
        raise ProfileError(f"{where}: unknown key {unknown[0]!r}")


def load_profile(name: str) -> Profile:
    if name not in NAMES:
        raise ProfileError(f"unknown profile {name!r} — one of {', '.join(NAMES)}, or custom")
    where = f"core/profiles/{name}.yml"
    doc = yaml.safe_load((PROFILES_DIR / f"{name}.yml").read_text())
    if not isinstance(doc, dict):
        raise ProfileError(f"{where}: not a mapping")
    _check_keys(doc, {"title", "baseline", "owasp_top10", "stigs", "stigs_where_present", "stig_cat1_enforced",
                      "checklist_blocks", "scan", "qa", "accepted_risk_expiry_days"}, where)
    baseline = _expect(doc, "baseline", (str, type(None)), where)
    if baseline not in (None, "moderate", "high"):
        raise ProfileError(f"{where}: baseline must be moderate, high or null")
    scan = _expect(doc, "scan", (dict,), where)
    _check_keys(scan, {"fail_on", "medium_max_age_days", "cve_data_max_age_days"}, f"{where} scan")
    qa = _expect(doc, "qa", (dict,), where)
    _check_keys(qa, {"coverage_changed_lines", "mutation_required"}, f"{where} qa")
    coverage = _expect(qa, "coverage_changed_lines", (int,), f"{where} qa")
    if not 0 <= coverage <= 100:
        raise ProfileError(f"{where} qa: coverage_changed_lines must be 0–100")
    data = _baselines()
    return Profile(
        name=name,
        title=str(_expect(doc, "title", (str,), where)),
        baseline=baseline,
        catalog_version=str(data["_catalog_version"]),
        controls=frozenset(data[baseline]) if baseline else frozenset(),
        owasp_top10=bool(_expect(doc, "owasp_top10", (bool,), where)),
        stigs=_strings(doc, "stigs", where),
        stigs_where_present=_strings(doc, "stigs_where_present", where),
        stig_cat1_enforced=bool(_expect(doc, "stig_cat1_enforced", (bool,), where)),
        checklist_blocks=_strings(doc, "checklist_blocks", where, _BLOCKS),
        scan=ScanPolicy(
            fail_on=_strings(scan, "fail_on", f"{where} scan", _SEVERITIES),
            medium_max_age_days=_days(scan, "medium_max_age_days", f"{where} scan"),
            cve_data_max_age_days=_days(scan, "cve_data_max_age_days", f"{where} scan"),
        ),
        qa=QaPolicy(coverage_changed_lines=coverage,
                    mutation_required=bool(_expect(qa, "mutation_required", (bool,), f"{where} qa"))),
        accepted_risk_expiry_days=_days(doc, "accepted_risk_expiry_days", where),
    )


def custom_profile(base: str, add: Iterable[str], remove: Iterable[str]) -> Profile:
    """il4 or il6 with control ids added or removed — a tailored baseline (PRD § Custom profiles)."""
    if base not in ("il4", "il6"):
        raise ProfileError(f"custom base must be il4 or il6, not {shown(base)}")
    add, remove = list(add), list(remove)
    unknown = [c for c in add + remove if c not in catalog_ids()]
    if unknown:
        raise ProfileError(f"custom: {', '.join(shown(u) for u in unknown)} is not a control in the NIST 800-53 Rev 5 catalog")
    p = load_profile(base)
    return replace(p, name="custom", title=f"Custom (tailored from {base})",
                   controls=(p.controls | frozenset(add)) - frozenset(remove))


def _fails_on(scan: ScanPolicy) -> str:
    text = " or ".join(scan.fail_on) + " CVEs"
    if scan.medium_max_age_days:
        text += f", and medium CVEs older than {scan.medium_max_age_days} days"
    return text


def render(p: Profile) -> str:
    stigs = ", ".join(p.stigs) or "none"
    if p.stigs_where_present:
        stigs += "; where the repository has them: " + ", ".join(p.stigs_where_present)
    if p.stig_cat1_enforced:
        stigs += "; every CAT I enforced"
    rows = [
        ("NIST 800-53 Rev 5 baseline",
         f"{p.baseline.capitalize()} (catalog {p.catalog_version})" if p.baseline else "not applied"),
        ("Controls in baseline", str(len(p.controls))),
        ("OWASP Top 10", "yes" if p.owasp_top10 else "no"),
        ("DISA STIGs", stigs),
        ("Sentinel checklist blocks", " + ".join(b.capitalize() if b != "base" else b for b in p.checklist_blocks)),
        ("Scan: fails on", _fails_on(p.scan)),
        ("Scan: CVE data older than",
         f"{p.scan.cve_data_max_age_days} days fails the scan" if p.scan.cve_data_max_age_days else "no limit"),
        ("QA: coverage on changed lines", f"{p.qa.coverage_changed_lines}%"),
        ("QA: mutation of controls", "required" if p.qa.mutation_required else "optional"),
        ("Accepted-risk entries expire after",
         f"{p.accepted_risk_expiry_days} days" if p.accepted_risk_expiry_days else "never"),
    ]
    width = max(len(k) for k, _ in rows)
    return "\n".join([f"Profile {p.name} — {p.title}"] + [f"  {k:<{width}}  {v}" for k, v in rows])
