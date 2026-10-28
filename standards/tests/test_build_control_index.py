"""standards/scripts/build-control-index.py, in process: an OSCAL catalog becomes the vendored 800-53 index.

test_refresh drives the builder as a subprocess, which coverage never sees. These import it and hold
what verify-citations depends on: the ID spelling, the withdrawn status and its replacement, and the
provenance fields a gate-log row is anchored to. Every input is a local fixture.
"""

from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import runpy
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-control-index.py"
spec = importlib.util.spec_from_file_location("build_control_index", SCRIPT)
bci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bci)

CATALOG = {
    "catalog": {
        "metadata": {"title": "NIST SP 800-53 Rev 5 (fixture)", "version": "5.9.9", "last-modified": "2026-01-02T00:00:00Z"},
        "groups": [
            {"id": "ac", "controls": [
                {"id": "ac-3", "title": "Access Enforcement", "props": [{"name": "label", "value": "AC-3"}],
                 "controls": [
                     {"id": "ac-3.7", "title": "Role-based Access Control",
                      "controls": [{"id": "ac-3.7.1", "title": "Nested"}]},
                 ]},
            ]},
            {"id": "sa", "controls": [
                {"id": "sa-12", "title": "Supply Chain Protection",
                 "props": [{"name": "status", "value": "withdrawn"}],
                 "links": [{"rel": "incorporated-into", "href": "#sr"},
                           {"rel": "related", "href": "#sa-11"},
                           {"href": "#no-rel"}]},
                {"id": "sa-11", "props": [{"name": "status", "value": "active"}]},
            ]},
            {"id": "empty"},
        ],
    }
}


@pytest.mark.parametrize(("oscal", "doc"), [("ac-3", "AC-3"), ("ac-3.7", "AC-3(7)"), ("ac-3.7.1", "AC-3(7)(1)"), ("sr", "SR")])
def test_oscal_ids_take_the_spelling_the_documents_use(oscal, doc):
    assert bci.fmt(oscal) == doc


def test_walk_records_status_title_replacement_and_every_nested_enhancement():
    idx: dict = {}
    for group in CATALOG["catalog"]["groups"]:
        for ctrl in group.get("controls", []):
            bci.walk(ctrl, idx)
    assert idx == {
        "AC-3": {"t": "Access Enforcement", "s": "active"},  # a props list without status is active
        "AC-3(7)": {"t": "Role-based Access Control", "s": "active"},
        "AC-3(7)(1)": {"t": "Nested", "s": "active"},
        "SA-12": {"t": "Supply Chain Protection", "s": "withdrawn", "into": ["SR"]},  # only incorporated-into links
        "SA-11": {"t": "", "s": "active"},  # no title is an empty title, not a crash
    }


def run_main(monkeypatch, *argv: str) -> None:
    monkeypatch.setattr(sys, "argv", ["build-control-index.py", *argv])
    bci.main()


def test_main_writes_the_index_with_its_provenance(tmp_path, monkeypatch, capsys):
    src = tmp_path / "oscal.json"
    src.write_text(json.dumps(CATALOG))
    out = tmp_path / "index.json"
    run_main(monkeypatch, str(src), str(out))

    doc = json.loads(out.read_text())
    assert doc["_source_sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    assert doc["_catalog_title"] == "NIST SP 800-53 Rev 5 (fixture)"
    assert doc["_catalog_version"] == "5.9.9"
    assert doc["_catalog_last_modified"] == "2026-01-02T00:00:00Z"
    assert doc["_retrieved"] == datetime.date.today().isoformat()
    assert doc["_generator"] == "standards/scripts/build-control-index.py"
    assert doc["_source"].endswith("/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json")
    assert doc["_counts"] == {"controls": 5, "withdrawn": 1}
    assert doc["controls"]["SA-12"] == {"t": "Supply Chain Protection", "s": "withdrawn", "into": ["SR"]}
    assert capsys.readouterr().out == (
        f"{out}: 5 controls, 1 withdrawn, {out.stat().st_size // 1024} KB, catalogue 5.9.9\n")


def test_a_catalog_without_groups_or_version_is_an_empty_index_not_a_crash(tmp_path, monkeypatch, capsys):
    src = tmp_path / "oscal.json"
    src.write_text(json.dumps({"catalog": {"metadata": {"title": "bare"}}}))
    out = tmp_path / "index.json"
    run_main(monkeypatch, str(src), str(out))
    doc = json.loads(out.read_text())
    assert doc["controls"] == {} and doc["_counts"] == {"controls": 0, "withdrawn": 0}
    assert doc["_catalog_version"] is None and doc["_catalog_last_modified"] is None
    assert capsys.readouterr().out.endswith(
        f"0 controls, 0 withdrawn, {out.stat().st_size // 1024} KB, catalogue None\n")


def test_a_catalog_without_a_title_is_refused(tmp_path, monkeypatch):
    src = tmp_path / "oscal.json"
    src.write_text(json.dumps({"catalog": {"metadata": {}}}))
    out = tmp_path / "index.json"
    with pytest.raises(KeyError, match="title"):
        run_main(monkeypatch, str(src), str(out))
    assert not out.exists()


@pytest.mark.parametrize("argv", [(), ("one",), ("one", "two", "three")])
def test_the_wrong_number_of_arguments_is_the_usage(monkeypatch, argv):
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, *argv)
    assert exc.value.code == "usage: build-control-index.py <oscal-catalog.json> <out-index.json>"


def test_run_as_a_script(tmp_path, monkeypatch, capsys):
    src = tmp_path / "oscal.json"
    src.write_text(json.dumps(CATALOG))
    out = tmp_path / "index.json"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(src), str(out)])
    runpy.run_path(str(SCRIPT), run_name="__main__")
    assert json.loads(out.read_text())["_counts"]["controls"] == 5
    assert "5 controls, 1 withdrawn" in capsys.readouterr().out
