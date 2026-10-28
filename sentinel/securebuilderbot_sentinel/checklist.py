"""The Sentinel checklist as data (docs/PRD.md § Compliance profiles: how a profile is checked, not just named).

`sentinel/checklist/{base,moderate,high}.yml` hold every item of engine/SENTINEL-CHECKLIST.md and of
standards/data/checklists/IL6.md, word for word, each with the NIST SP 800-53 Rev 5 controls it
serves. A profile selects blocks (`profile.checklist_blocks`); `items_for` returns that profile's
items in file order. `gaps` is the receipt's "not assessed" list: the baseline's controls that no
item cites, or, given what the reviewer actually answered with evidence, the baseline minus that.

Every control and STIG id is verified through the standards module when the files are read, so a
checklist that cites a control the catalog does not have, or one NIST withdrew, never loads.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from securebuilderbot_core.profiles import Profile
from securebuilderbot_standards import verify_citations

DATA_DIR = Path(__file__).resolve().parents[1] / "checklist"
BLOCKS = ("base", "moderate", "high")
ITEM_KEYS = {"id", "block", "text", "controls", "stig", "applies_when", "reads", "source"}


class ChecklistError(ValueError):
    """A checklist file that does not say what a checklist must: the file and the item name why."""


@dataclass(frozen=True)
class Item:
    id: str
    block: str
    text: str
    controls: tuple[str, ...]
    source: str
    stig: tuple[str, ...] = ()
    applies_when: tuple[str, ...] = ()
    reads: tuple[str, ...] = ()


@dataclass(frozen=True)
class Question:
    id: str
    label: str
    question: str


def _strings(raw: dict, key: str, where: str, required: bool = False) -> tuple[str, ...]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ChecklistError(f"{where}: {key} must be a list of strings")
    if required and not value:
        raise ChecklistError(f"{where}: {key} must name at least one control")
    return tuple(value)


def _safe_path(path: str) -> bool:
    """A repository-relative path that stays inside the repository."""
    p = PurePosixPath(path)
    return not p.is_absolute() and ".." not in p.parts and path.strip() == path


def _verify(item: Item, where: str) -> None:
    for cid in item.controls + item.stig:
        cites = verify_citations(cid, path=where)
        if [c.id for c in cites] != [cid] or not all(c.ok and c.status == "ok" for c in cites):
            why = "; ".join(c.reason or c.status for c in cites) or "not read as a control or STIG rule id"
            raise ChecklistError(f"{where}: {cid} does not verify against the vendored standards ({why})")


def _item(raw: object, block: str, where: str) -> Item:
    if not isinstance(raw, dict):
        raise ChecklistError(f"{where}: an item must be a mapping")
    unknown = sorted(set(raw) - ITEM_KEYS)
    if unknown:
        raise ChecklistError(f"{where}: unknown key {unknown[0]!r}")
    for key in ("id", "text", "source"):
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            raise ChecklistError(f"{where}: {key} must be a non-empty string")
    where = f"{where} {raw['id']}"
    if raw.get("block") not in BLOCKS:
        raise ChecklistError(f"{where}: block must be one of {', '.join(BLOCKS)}")
    if raw["block"] != block:
        raise ChecklistError(f"{where}: a {raw['block']} item in the {block} file")
    reads = _strings(raw, "reads", where)
    if not all(_safe_path(r) for r in reads):
        raise ChecklistError(f"{where}: reads must name repository-relative paths inside the repository")
    item = Item(id=raw["id"], block=raw["block"], text=raw["text"], source=raw["source"],
                controls=_strings(raw, "controls", where, required=True), stig=_strings(raw, "stig", where),
                applies_when=_strings(raw, "applies_when", where), reads=reads)
    _verify(item, where)
    return item


@functools.cache
def _load(data_dir: Path) -> tuple[Item, ...]:
    items: list[Item] = []
    for block in BLOCKS:
        path = data_dir / f"{block}.yml"
        if not path.is_file():
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw = doc.get("items") if isinstance(doc, dict) else None
        if not isinstance(raw, list):
            raise ChecklistError(f"{path.name}: items must be a list")
        items += [_item(r, block, path.name) for r in raw]
    seen: set[str] = set()
    for i in items:
        if i.id in seen:
            raise ChecklistError(f"item {i.id} is defined twice")
        seen.add(i.id)
    return tuple(items)


def load_items(data_dir: Path | str | None = None) -> list[Item]:
    """Every item of every block, in block then file order."""
    return list(_load(Path(data_dir) if data_dir is not None else DATA_DIR))


def items_for(profile: Profile, data_dir: Path | str | None = None) -> list[Item]:
    """The items a profile runs: the blocks it names (base; + moderate at il4; + high at il6)."""
    return [i for i in load_items(data_dir) if i.block in profile.checklist_blocks]


def gaps(profile: Profile, assessed: set[str] | frozenset[str] | None = None,
         data_dir: Path | str | None = None) -> frozenset[str]:
    """The baseline's controls not assessed: by default, those no item of the profile cites;
    given `assessed` (the controls the reviewer answered with evidence), the baseline minus those."""
    if assessed is None:
        assessed = {c for i in items_for(profile, data_dir) for c in i.controls}
    return frozenset(profile.controls) - frozenset(assessed)


@functools.cache
def cc_questions(data_dir: Path | None = None) -> tuple[Question, ...]:
    """The six Control Completeness questions, word for word from the checklist's table."""
    doc = yaml.safe_load(((data_dir or DATA_DIR) / "control-completeness.yml").read_text(encoding="utf-8"))
    return tuple(Question(id=q["id"], label=q["label"], question=q["question"]) for q in doc["questions"])
