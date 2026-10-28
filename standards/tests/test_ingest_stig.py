"""standards/scripts/ingest-stig.py, in process: a STIG a human downloaded joins the verified set.

standards-selftest.sh drives it as a subprocess, which coverage never sees. These import it and hold
its refusals (an unknown flag, a missing or unparseable file, a control marking in the front matter,
an archive that is neither) and what it records: the rules, the supplied file's SHA-256, a manual
preferred over a SCAP rendering, an existing supplied index merged into rather than replaced, and a
dry run that writes nothing. Every STIG here is a small local fixture.
"""

from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import runpy
import sys
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ingest-stig.py"
_bytecode = sys.dont_write_bytecode
spec = importlib.util.spec_from_file_location("ingest_stig", SCRIPT)
ing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ing)
sys.dont_write_bytecode = _bytecode  # the script sets it for its own process; not for the whole test run

NS = "http://checklists.nist.gov/xccdf/1.1"


def xccdf(*rules: tuple[str, str], title: str = "Application Security STIG", notice: str = "",
          body: str = "") -> bytes:
    front = f"<title>{title}</title><description>Front matter.</description>"
    if notice:
        front += f'<notice id="n">{notice}</notice>'
    rows = "".join(f'<Rule id="r{i}"><version>{v}</version><title>{t}</title>'
                   f"<description>{body}</description></Rule>" for i, (v, t) in enumerate(rules))
    # a <plain-text> after the first Rule is not front matter, so a marking there is never read
    return f'<?xml version="1.0"?><Benchmark xmlns="{NS}">{front}<status>accepted</status>{rows}<plain-text>CUI</plain-text></Benchmark>'.encode()


ASD = xccdf(("APSC-DV-000010", "Limit sessions"), ("SRG-APP-000001-AS-000001", "An SRG rule"), ("not-an-id", "Prose"))


@pytest.fixture
def cwd(tmp_path, monkeypatch) -> Path:
    """A working directory with the data directory OUT is written under."""
    (tmp_path / "standards" / "data" / "controls").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def supplied(cwd: Path) -> dict:
    return json.loads((cwd / ing.OUT).read_text())


def run(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["ingest-stig.py", *argv])
    return ing.main()


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


# ── front_matter ─────────────────────────────────────────────────────────────


def test_front_matter_is_the_benchmark_text_before_the_first_rule(tmp_path):
    p = write(tmp_path / "a.xml", xccdf(("APSC-DV-000010", "t"), notice="Distribution unlimited", body="FOUO data"))
    assert ing.front_matter(str(p)) == "Application Security STIG\nFront matter.\nDistribution unlimited"


def test_front_matter_of_a_document_with_a_dtd_is_none(tmp_path):
    p = write(tmp_path / "a.xml", b'<?xml version="1.0"?><!DOCTYPE b [<!ENTITY x "y">]><b>&x;</b>')
    assert ing.front_matter(str(p)) is None


@pytest.mark.parametrize("marking", ["CUI", "Controlled Unclassified Information", "NOFORN", "DISTRIBUTION STATEMENT D"])
def test_the_controlled_markings_match(marking):
    assert ing.CONTROLLED.search(f"This document is {marking}.")


@pytest.mark.parametrize("text", ["DISTRIBUTION STATEMENT A", "a CUIRASS", "unclassified"])
def test_unmarked_text_does_not_match(text):
    assert ing.CONTROLLED.search(text) is None


# ── xccdfs ───────────────────────────────────────────────────────────────────


def zipped(tmp_path: Path, members: dict[str, bytes], name: str = "U_ASD_V5R3_STIG.zip") -> Path:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as z:
        for n, data in members.items():
            z.writestr(n, data)
    return p


def test_an_xml_path_is_itself(tmp_path):
    assert list(ing.xccdfs(str(tmp_path / "A.XML"), str(tmp_path))) == [str(tmp_path / "A.XML")]


def test_a_zip_yields_the_manual_over_the_scap_rendering(tmp_path):
    z = zipped(tmp_path, {"pkg/U_ASD_V5R3_Manual-xccdf.xml": ASD, "pkg/U_ASD_V5R3_SCAP-xccdf.xml": ASD,
                          "pkg/readme.xml": b"<x/>", "pkg/notes.txt": b"x"})
    out = tmp_path / "out"
    got = list(ing.xccdfs(str(z), str(out)))
    assert got == [str(out / "pkg" / "U_ASD_V5R3_Manual-xccdf.xml")]
    assert Path(got[0]).read_bytes() == ASD


def test_a_zip_without_a_manual_yields_every_xccdf(tmp_path):
    z = zipped(tmp_path, {"a-xccdf.xml": ASD, "b-XCCDF.xml": ASD, "c.xml": b"<x/>"})
    out = tmp_path / "out"
    assert list(ing.xccdfs(str(z), str(out))) == [str(out / "a-xccdf.xml"), str(out / "b-XCCDF.xml")]


def test_a_file_that_is_neither_xml_nor_zip_is_refused(tmp_path):
    p = write(tmp_path / "stig.pdf", b"%PDF-1.7")
    with pytest.raises(SystemExit) as exc:
        list(ing.xccdfs(str(p), str(tmp_path)))
    assert exc.value.code == f"ingest-stig: {p} is neither an XML file nor a zip archive"


def test_sha256_is_the_digest_of_the_file(tmp_path):
    data = b"x" * ((1 << 20) + 7)  # more than one read chunk
    assert ing.sha256(str(write(tmp_path / "f", data))) == hashlib.sha256(data).hexdigest()


# ── main ─────────────────────────────────────────────────────────────────────


def test_an_xml_is_ingested_with_its_provenance(cwd, monkeypatch, capsys):
    p = write(cwd / "U_ASD_V5R3-xccdf-manual.xml", ASD)
    assert run(monkeypatch, str(p)) == 0
    doc = supplied(cwd)
    assert doc["rules"] == {"APSC-DV-000010": {"t": "Limit sessions", "s": "U_ASD_V5R3"},
                            "SRG-APP-000001-AS-000001": {"t": "An SRG rule", "s": "U_ASD_V5R3"}}
    assert doc["sources"] == {"U_ASD_V5R3": {
        "rules": 2, "supplied_file": "U_ASD_V5R3-xccdf-manual.xml", "sha256": hashlib.sha256(ASD).hexdigest(),
        "ingested": datetime.date.today().isoformat(), "acknowledged_cui": False}}
    assert doc["_counts"] == {"rules": 2, "stigs": 1}
    assert doc["_generator"] == "standards/scripts/ingest-stig.py"
    assert doc["_provenance"].startswith("HUMAN-SUPPLIED files, not a redistribution.")
    out = capsys.readouterr().out
    assert "  U_ASD_V5R3-xccdf-manual.xml: 2 rules  (prefixes APSC, SRG)\n" in out
    assert f"{ing.OUT}: 2 rules from 1 human-supplied STIG(s)\n" in out
    assert "Next: make verify-citations" in out


def test_a_zip_is_ingested_and_its_hash_is_the_zips(cwd, monkeypatch):
    z = zipped(cwd, {"U ASD (V5)/U_ASD_V5R3_Manual-xccdf.xml": ASD})
    assert run(monkeypatch, str(z)) == 0
    doc = supplied(cwd)
    assert list(doc["sources"]) == ["U_ASD_V5R3_Manual"]
    src = doc["sources"]["U_ASD_V5R3_Manual"]
    assert src["supplied_file"] == "U_ASD_V5R3_STIG.zip"
    assert src["sha256"] == hashlib.sha256(z.read_bytes()).hexdigest()


def test_a_second_ingest_merges_into_the_supplied_index(cwd, monkeypatch):
    (cwd / ing.OUT).write_text(json.dumps({"rules": {"CNTR-OS-000010": {"t": "Old", "s": "cntr"}},
                                           "sources": {"cntr": {"rules": 1}}, "_note": "kept"}))
    p = write(cwd / "asd.xml", ASD)
    assert run(monkeypatch, str(p)) == 0
    doc = supplied(cwd)
    assert set(doc["rules"]) == {"CNTR-OS-000010", "APSC-DV-000010", "SRG-APP-000001-AS-000001"}
    assert set(doc["sources"]) == {"cntr", "asd"}
    assert doc["_counts"] == {"rules": 3, "stigs": 2}
    assert doc["_note"] == "kept"


def test_an_existing_index_missing_its_tables_gets_them(cwd, monkeypatch):
    (cwd / ing.OUT).write_text(json.dumps({"_note": "bare"}))
    assert run(monkeypatch, str(write(cwd / "asd.xml", ASD))) == 0
    assert supplied(cwd)["_counts"] == {"rules": 2, "stigs": 1}


def test_a_dry_run_writes_nothing(cwd, monkeypatch, capsys):
    assert run(monkeypatch, str(write(cwd / "asd.xml", ASD)), "--dry-run") == 0
    assert not (cwd / ing.OUT).exists()
    assert capsys.readouterr().out.endswith(
        f"ingest-stig: --dry-run, {ing.OUT} not written (2 rules would be added, 2 total)\n")


def test_a_controlled_marking_in_the_front_matter_is_refused(cwd, monkeypatch, capsys):
    p = write(cwd / "mobile.xml", xccdf(("APSC-DV-000010", "t"), notice="CUI // controlled"))
    assert run(monkeypatch, str(p)) == 1
    err = capsys.readouterr().err
    assert err.startswith("REFUSED — mobile.xml front matter carries 'CUI'.")
    assert "--acknowledge-cui" in err
    assert not (cwd / ing.OUT).exists()


def test_an_acknowledged_marking_is_ingested_and_recorded(cwd, monkeypatch):
    p = write(cwd / "mobile.xml", xccdf(("APSC-DV-000010", "t"), title="NOFORN benchmark"))
    assert run(monkeypatch, str(p), "--acknowledge-cui") == 0
    assert supplied(cwd)["sources"]["mobile"]["acknowledged_cui"] is True


def test_a_marking_in_a_rule_body_is_not_a_refusal(cwd, monkeypatch):
    p = write(cwd / "asd.xml", xccdf(("APSC-DV-000010", "t"), body="mark data as CUI or FOUO"))
    assert run(monkeypatch, str(p)) == 0
    assert supplied(cwd)["sources"]["asd"]["acknowledged_cui"] is False


def test_no_matching_rule_ids_is_nothing_ingested(cwd, monkeypatch, capsys):
    p = write(cwd / "browser.xml", xccdf(("DTBC-0001", "Chrome")))
    assert run(monkeypatch, str(p)) == 0
    out = capsys.readouterr().out
    assert "  browser.xml: no rule ids matched the published id shapes — skipped." in out
    assert out.endswith("ingest-stig: nothing ingested.\n")
    assert not (cwd / ing.OUT).exists()


def test_an_unparseable_xml_is_refused(cwd, monkeypatch):
    p = write(cwd / "broken.xml", b"<Benchmark><unclosed></Benchmark>")
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, str(p))
    assert exc.value.code == f"ingest-stig: {p} is not parseable XML"


def test_a_missing_file_is_refused(cwd, monkeypatch):
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, "nowhere.zip")
    assert exc.value.code == "ingest-stig: nowhere.zip not found"


def test_an_unknown_flag_is_refused_before_anything_is_read(cwd, monkeypatch):
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, "nowhere.zip", "--force", "--dry-run", "--all")
    assert exc.value.code == "ingest-stig: unknown flag --all, --force"


def test_no_file_is_the_usage(cwd, monkeypatch):
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, "--dry-run")
    assert exc.value.code.startswith("standards/scripts/ingest-stig.py <file.zip|file.xml> [more…]")
    assert "make ingest-stig FILE=" in exc.value.code


def test_run_as_a_script(cwd, monkeypatch):
    p = write(cwd / "asd.xml", ASD)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(p), "--dry-run"])
    monkeypatch.setattr(sys, "dont_write_bytecode", sys.dont_write_bytecode)
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exc.value.code == 0
    assert not (cwd / ing.OUT).exists()
