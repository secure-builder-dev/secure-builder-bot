"""standards/scripts/build-baselines-index.py — the generator behind the profiles' baseline counts.

test_profiles asserts the vendored output's counts; these hold the generator that wrote it, so a
regeneration that misreads NIST's profile ids, or lets in a control the catalog lacks, fails here
before it reaches a receipt (gate finding N-13).
"""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "standards" / "scripts" / "build-baselines-index.py"
VENDORED = ROOT / "standards" / "data" / "controls" / "nist-800-53r5-baselines.json"
CATALOG = ROOT / "standards" / "data" / "controls" / "nist-800-53r5-index.json"

spec = importlib.util.spec_from_file_location("build_baselines_index", SCRIPT)
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


def profile(tmp_path: Path, name: str, title: str, ids: list[str], version: str = "5.2.0") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps({"profile": {"metadata": {"title": title, "version": version},
                                         "imports": [{"include-controls": [{"with-ids": ids}]}]}}))
    return p


@pytest.mark.parametrize(("oscal", "catalog"), [("ac-2", "AC-2"), ("ac-2.1", "AC-2(1)"), ("sc-7.12", "SC-7(12)")])
def test_oscal_ids_become_the_catalog_spelling(oscal, catalog):
    assert gen.catalog_id(oscal) == catalog


@pytest.mark.parametrize("bad", ["ac2", "AC-2", "ac-2.x", "ac-2(1)"])
def test_anything_else_is_not_a_control_id(bad):
    with pytest.raises(ValueError):
        gen.catalog_id(bad)


def test_a_profile_reads_its_level_and_sorts_numerically(tmp_path):
    level, version, ids = gen.baseline(profile(tmp_path, "m.json", "NIST SP 800-53 Rev 5 MODERATE Baseline",
                                               ["ac-2.10", "ac-2", "ac-2.2", "ac-10", "ac-2"]))
    assert (level, version) == ("moderate", "5.2.0")
    assert ids == ["AC-2", "AC-2(2)", "AC-2(10)", "AC-10"]  # numeric, not string, order; duplicates once


def test_a_profile_that_is_neither_moderate_nor_high_is_refused(tmp_path):
    with pytest.raises(ValueError, match="not a MODERATE or HIGH"):
        gen.baseline(profile(tmp_path, "l.json", "NIST SP 800-53 Rev 5 LOW Baseline", ["ac-2"]))


def test_main_writes_both_levels_with_counts(tmp_path, capsys):
    m = profile(tmp_path, "m.json", "MODERATE Baseline", ["ac-2", "ac-2.1"])
    h = profile(tmp_path, "h.json", "HIGH Baseline", ["ac-2", "ac-2.1", "ac-2.2"])
    assert gen.main([str(m), str(h)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["moderate"] == ["AC-2", "AC-2(1)"] and out["high"] == ["AC-2", "AC-2(1)", "AC-2(2)"]
    assert out["_counts"] == {"moderate": 2, "high": 3} and out["_catalog_version"] == "5.2.0"


def test_a_control_the_catalog_lacks_refuses_the_whole_index(tmp_path, capsys):
    m = profile(tmp_path, "m.json", "MODERATE Baseline", ["ac-2", "zz-99"])
    h = profile(tmp_path, "h.json", "HIGH Baseline", ["ac-2"])
    assert gen.main([str(m), str(h)]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "not in the catalog index" in captured.err


def test_the_wrong_number_of_inputs_prints_usage(capsys):
    assert gen.main(["only-one.json"]) == 1
    assert "USAGE" in capsys.readouterr().err


def test_the_vendored_index_is_what_the_generator_would_accept():
    vendored = json.loads(VENDORED.read_text())
    known = set(json.loads(CATALOG.read_text())["controls"])
    assert set(vendored["moderate"]) <= set(vendored["high"]) <= known
    assert vendored["high"] == sorted(vendored["high"], key=gen._order)
    assert vendored["_generator"] == "standards/scripts/build-baselines-index.py"
