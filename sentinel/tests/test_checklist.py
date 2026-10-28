"""The checklist as data (SPEC-sentinel.md § The checklist): the YAML twins of the markdown items,
their citations, the items a profile runs and the baseline controls no item cites."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from securebuilderbot_core.profiles import custom_profile, load_profile
from securebuilderbot_sentinel import checklist
from securebuilderbot_sentinel.checklist import ChecklistError, Item, cc_questions, gaps, items_for, load_items
from securebuilderbot_standards import baseline, verify_citations

ROOT = Path(__file__).resolve().parents[2]
MARKDOWN = {
    "engine/SENTINEL-CHECKLIST.md": "### Control Completeness Review",
    "standards/data/checklists/IL6.md": None,
}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def markdown_items(path: str, stop: str | None) -> list[str]:
    """Every top-level bullet of a checklist file, continuation lines joined, up to `stop`."""
    items: list[str] = []
    for line in (ROOT / path).read_text().splitlines():
        if stop and line.startswith(stop):
            break
        if line.startswith("- "):
            items.append(line[2:])
        elif line.startswith("  ") and items and line.strip():
            items[-1] += " " + line.strip()
        elif not line.strip() and items:
            items.append("")  # a blank line ends a bullet; dropped below
    return [_norm(i) for i in items if i]


def test_every_markdown_item_has_a_yaml_twin_with_the_same_text():
    by_text = {(_norm(i.text), i.source): i.id for i in load_items()}
    missing = [(p, t) for p, stop in MARKDOWN.items() for t in markdown_items(p, stop) if (t, p) not in by_text]
    assert missing == [], f"markdown items with no YAML twin: {missing}"


def test_every_yaml_item_from_a_markdown_file_is_still_in_it():
    texts = {p: set(markdown_items(p, stop)) for p, stop in MARKDOWN.items()}
    orphans = [i.id for i in load_items() if i.source in texts and _norm(i.text) not in texts[i.source]]
    assert orphans == []


def test_the_markdown_reader_sees_every_item():
    assert len(markdown_items("engine/SENTINEL-CHECKLIST.md", "### Control Completeness Review")) == 26
    assert len(markdown_items("standards/data/checklists/IL6.md", None)) == 7


def test_only_the_prd_table_topics_have_no_markdown_twin():
    assert sorted(i.id for i in load_items() if i.source == "docs/PRD.md") == ["H-08", "H-09", "H-10"]


def test_ids_are_unique_and_each_file_holds_its_own_block():
    items = load_items()
    assert len({i.id for i in items}) == len(items)
    for i in items:
        assert i.id[0] == {"base": "B", "moderate": "M", "high": "H"}[i.block]


def test_every_control_and_stig_id_verifies_through_the_standards_module():
    for item in load_items():
        for cid in item.controls + item.stig:
            cites = verify_citations(cid, path=f"sentinel/checklist ({item.id})")
            assert [c.id for c in cites] == [cid], f"{item.id}: {cid} is not read as one citation"
            assert all(c.ok and c.status == "ok" for c in cites), f"{item.id}: {cid} does not verify: {cites}"


def test_a_bad_citation_cannot_ship(tmp_path: Path):
    (tmp_path / "base.yml").write_text("items:\n  - {id: B-01, block: base, text: t, controls: [AC-99], source: x}\n")
    with pytest.raises(ChecklistError, match="AC-99"):
        load_items(tmp_path)


def test_a_withdrawn_control_cannot_ship(tmp_path: Path):
    (tmp_path / "base.yml").write_text("items:\n  - {id: B-01, block: base, text: t, controls: [SA-12], source: x}\n")
    with pytest.raises(ChecklistError, match="SA-12"):
        load_items(tmp_path)


def test_an_unknown_stig_rule_cannot_ship(tmp_path: Path):
    (tmp_path / "base.yml").write_text(
        "items:\n  - {id: B-01, block: base, text: t, controls: [AC-3], stig: [SRG-APP-999999-AS-999999], source: x}\n")
    with pytest.raises(ChecklistError, match="SRG-APP-999999"):
        load_items(tmp_path)


@pytest.mark.parametrize("body, message", [
    ("items:\n  - {id: B-01, block: base, text: t, controls: [AC-3], source: x, colour: red}\n", "unknown key"),
    ("items:\n  - {id: B-01, block: low, text: t, controls: [AC-3], source: x}\n", "block"),
    ("items:\n  - {id: B-01, block: base, text: t, controls: [], source: x}\n", "controls"),
    ("items:\n  - {id: B-01, block: base, controls: [AC-3], source: x}\n", "text"),
    ("items:\n  - {id: B-01, block: base, text: t, controls: [AC-3], source: x, reads: [../etc/passwd]}\n", "reads"),
    ("items:\n  - {id: B-01, block: base, text: t, controls: [AC-3], source: x}\n"
     "  - {id: B-01, block: base, text: u, controls: [AC-3], source: x}\n", "twice"),
    ("items: nope\n", "list"),
])
def test_a_malformed_item_is_refused(tmp_path: Path, body: str, message: str):
    (tmp_path / "base.yml").write_text(body)
    with pytest.raises(ChecklistError, match=message):
        load_items(tmp_path)


def test_il4_runs_base_and_moderate_only():
    items = items_for(load_profile("il4"))
    assert {i.block for i in items} == {"base", "moderate"}
    assert [i.id for i in items][:2] == ["B-01", "B-02"]
    assert not any(i.block == "high" for i in items)


def test_none_runs_base_only_and_il6_runs_every_block():
    assert {i.block for i in items_for(load_profile("none"))} == {"base"}
    assert {i.block for i in items_for(load_profile("il6"))} == {"base", "moderate", "high"}
    assert len(items_for(load_profile("il6"))) == len(load_items())


def test_gaps_il6_is_the_high_baseline_minus_every_cited_control():
    il6 = load_profile("il6")
    cited = {c for i in items_for(il6) for c in i.controls}
    missing = gaps(il6)
    assert missing == frozenset(baseline("high")) - cited
    assert len(missing) > 300  # SPEC-sentinel.md success criterion 1 records the number
    assert "AC-3" not in missing and "AU-10" not in missing and "AC-1" in missing


def test_gaps_with_what_was_assessed_is_the_baseline_minus_only_that():
    il4 = load_profile("il4")
    assert gaps(il4, {"AC-3"}) == il4.controls - {"AC-3"}
    assert gaps(il4, set()) == il4.controls
    assert gaps(load_profile("none")) == frozenset()


def test_a_custom_profile_runs_its_base_profiles_blocks():
    assert {i.block for i in items_for(custom_profile("il4", ["AU-10"], []))} == {"base", "moderate"}


def test_the_control_completeness_questions_are_the_markdown_tables_rows():
    text = _norm((ROOT / "engine/SENTINEL-CHECKLIST.md").read_text())
    qs = cc_questions()
    assert [q.id for q in qs] == ["Q1", "Q2", "Q3", "Q4", "Q5", "Q6"]
    for q in qs:
        assert f"| {q.id} | {_norm(q.question)} |" in text


def test_items_are_read_as_item_objects_with_tuples():
    item = load_items()[0]
    assert isinstance(item, Item)
    assert isinstance(item.controls, tuple) and item.controls == ("IA-5(7)", "SC-28")


def test_the_data_directory_is_the_package_neighbour():
    assert checklist.DATA_DIR == ROOT / "sentinel" / "checklist"
