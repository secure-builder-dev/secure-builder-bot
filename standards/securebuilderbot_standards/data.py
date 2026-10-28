"""The vendored standards, read as objects (SPEC-standards.md § Interface).

Every index under standards/data/controls/ is a JSON file a builder under standards/scripts/ wrote
from the publisher's own source; this module is the one place that knows their shapes. Readers get
frozen dataclasses and plain mappings, never the raw files. A data directory other than the vendored
one can be named, which is how the verifier runs against a fixture repository and how a refresh
compares a freshly built index with the one that is committed.

The catalog is required: a missing catalog raises rather than reading as an empty one, because an
empty catalog would make every citation unknown and the verifier useless while still running. The
other indexes are optional and read as None when absent, so a repository that carries only the NIST
index still verifies its NIST citations and nothing else.
"""

from __future__ import annotations

import functools
import json
import re
from dataclasses import dataclass
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR.parent / "data" / "controls"
CATALOG_FILE = "nist-800-53r5-index.json"
BASELINES_FILE = "nist-800-53r5-baselines.json"
STIG_FILE = "stig-index.json"
STIG_SUPPLIED_FILE = "stig-index-supplied.json"
OWASP_FILE = "owasp-index.json"
MASVS_FILE = "masvs-index.json"
PUBS_FILE = "nist-pubs-index.json"
LEVELS = ("moderate", "high")
_BENCHMARK = re.compile(r"^disa-stig-(?P<benchmark>.+?)-(?P<version>v\d+r\d+)$")


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    family: str
    in_moderate: bool
    in_high: bool
    withdrawn: bool
    into: tuple[str, ...] = ()  # what a withdrawn control was incorporated into


@dataclass(frozen=True)
class StigRule:
    id: str
    title: str
    severity: str | None  # CAT level where the index carries it; the redistributed manuals do not
    benchmark: str        # rhel8, rhcos4, srg-app …
    version: str | None   # v2r8 …
    supplied: bool = False  # from the human-supplied index, not the redistribution


@dataclass(frozen=True)
class OwaspLists:
    web_edition: str
    llm_edition: str
    web: dict[str, str]  # the current web Top 10, id → title
    llm: dict[str, str]  # the current LLM Top 10, id → title
    editions: dict[str, dict[str, dict[str, str]]]  # every vendored edition, by list then year


@dataclass(frozen=True)
class NistPub:
    id: str  # "SP 800-53", "FIPS 140-3"
    revisions: tuple[str, ...]  # "" is the original, unrevised edition
    latest: str
    drafts: tuple[str, ...]


@dataclass(frozen=True)
class Masvs:
    release: str
    controls: dict[str, str]  # id → statement
    groups: dict[str, str]


def _dir(data_dir: Path | str | None) -> Path:
    return Path(data_dir) if data_dir is not None else DATA_DIR


@functools.cache
def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _read(data_dir: Path | str | None, name: str, required: bool = False) -> dict | None:
    path = _dir(data_dir) / name
    if not path.is_file():
        if required:
            raise FileNotFoundError(f"no {name} under {path.parent} — see standards/scripts/ for its builder")
        return None
    return _load(path.resolve())


def raw_catalog(data_dir: Path | str | None = None) -> dict:
    """The catalog index as written: {"_catalog_version": …, "controls": {id: {"t", "s", "into"?}}}."""
    return _read(data_dir, CATALOG_FILE, required=True)


def raw_index(name: str, data_dir: Path | str | None = None) -> dict | None:
    """Any optional index by file name, or None when it is not there."""
    return _read(data_dir, name)


def catalog(data_dir: Path | str | None = None) -> dict[str, Control]:
    """Every control and enhancement in the vendored NIST SP 800-53 Rev 5 catalog, by id."""
    raw = raw_catalog(data_dir)
    baselines = raw_index(BASELINES_FILE, data_dir) or {}
    moderate, high = set(baselines.get("moderate", ())), set(baselines.get("high", ()))
    out = {}
    for cid, entry in raw["controls"].items():
        out[cid] = Control(id=cid, title=entry.get("t", ""), family=cid.split("-", 1)[0],
                           in_moderate=cid in moderate, in_high=cid in high,
                           withdrawn=entry.get("s", "active") != "active", into=tuple(entry.get("into", ())))
    return out


def baseline(level: str, data_dir: Path | str | None = None) -> frozenset[str]:
    """The control ids in the Moderate or High baseline (SP 800-53B, vendored from NIST's OSCAL profiles)."""
    if level not in LEVELS:
        raise ValueError(f"a baseline is moderate or high, not {level!r}")
    raw = _read(data_dir, BASELINES_FILE, required=True)
    return frozenset(raw[level])


def _rule(rid: str, entry: dict, supplied: bool) -> StigRule:
    stem = entry.get("s", "")
    m = _BENCHMARK.match(stem)
    return StigRule(id=rid, title=entry.get("t", ""), severity=entry.get("sev") or entry.get("cat"),
                    benchmark=m.group("benchmark") if m else stem, version=m.group("version") if m else None,
                    supplied=supplied)


def stigs(data_dir: Path | str | None = None) -> dict[str, StigRule]:
    """Every STIG rule the index carries, the human-supplied index merged over the redistribution."""
    out: dict[str, StigRule] = {}
    for name, supplied in ((STIG_FILE, False), (STIG_SUPPLIED_FILE, True)):
        raw = raw_index(name, data_dir)
        if raw:
            out.update({rid: _rule(rid, e, supplied) for rid, e in raw.get("rules", {}).items()})
    return out


def owasp(data_dir: Path | str | None = None) -> OwaspLists | None:
    raw = raw_index(OWASP_FILE, data_dir)
    if raw is None:
        return None
    web, llm = raw["web"], raw["llm"]
    return OwaspLists(web_edition=web["current"], llm_edition=llm["current"],
                      web=dict(web["editions"][web["current"]]), llm=dict(llm["editions"][llm["current"]]),
                      editions={"web": web["editions"], "llm": llm["editions"]})


def nist_pubs(data_dir: Path | str | None = None) -> dict[str, NistPub]:
    raw = raw_index(PUBS_FILE, data_dir)
    if raw is None:
        return {}
    return {k: NistPub(id=k, revisions=tuple(e.get("revisions", ())), latest=e.get("latest", ""),
                       drafts=tuple(e.get("drafts", ()))) for k, e in raw["pubs"].items()}


def masvs(data_dir: Path | str | None = None) -> Masvs | None:
    raw = raw_index(MASVS_FILE, data_dir)
    if raw is None:
        return None
    return Masvs(release=raw.get("_latest_release", ""), controls=dict(raw["controls"]), groups=dict(raw.get("groups", {})))


def versions(data_dir: Path | str | None = None) -> dict[str, str | None]:
    """What a receipt records: the version or retrieval date of each vendored standard, None when absent."""
    def field(name: str, key: str) -> str | None:
        raw = raw_index(name, data_dir)
        return None if raw is None else raw.get(key)
    ow = raw_index(OWASP_FILE, data_dir)
    return {
        "catalog": raw_catalog(data_dir).get("_catalog_version"),
        "baselines_retrieved": field(BASELINES_FILE, "_retrieved"),
        "stig_index": field(STIG_FILE, "_retrieved"),
        "owasp": None if ow is None else ow["web"]["current"],
        "owasp_llm": None if ow is None else ow["llm"]["current"],
        "masvs": field(MASVS_FILE, "_latest_release"),
        "nist_pubs": field(PUBS_FILE, "_retrieved"),
    }
