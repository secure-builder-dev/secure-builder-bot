"""standards/run: verify, versions, catalog — exit 0 ok, 1 refused, 2 could not run, like core's."""

from __future__ import annotations

import json
import subprocess

import pytest
from smallindex import ROOT, write_indexes

from securebuilderbot_standards.__main__ import main

RUN = ROOT / "standards" / "run"


def test_verify_a_clean_file_exits_0_and_names_the_catalogue_version(small, tmp_path, capsys):
    doc = tmp_path / "d.md"
    doc.write_text("- token gate AC-3 (Access Enforcement)\n- vetting NIST SP 800-163 Rev 1\n")
    assert main(["verify", "--data", str(small), str(doc)]) == 0
    out = capsys.readouterr().out
    assert "1 NIST + 0 OWASP + 0 STIG + 0 MASVS + 1 NIST-pub citations resolve (800-53 5.2.0)" in out


def test_verify_an_unknown_or_withdrawn_id_exits_1_and_names_file_and_line(small, tmp_path, capsys):
    doc = tmp_path / "d.md"
    doc.write_text("- supply chain SA-12\n- invented AC-99\n")
    assert main(["verify", "--data", str(small), str(doc)]) == 1
    out = capsys.readouterr().out
    assert f"WITHDRAWN   SA-12        {doc}:1  — withdrawn; use: SR" in out
    assert f"UNKNOWN     AC-99        {doc}:2" in out
    assert "2 bad citation(s) of 2" in out


def test_verify_without_a_catalog_exits_2_not_0(tmp_path, capsys):
    doc = tmp_path / "d.md"
    doc.write_text("AC-3\n")
    assert main(["verify", "--data", str(tmp_path / "nowhere"), str(doc)]) == 2
    assert "no control index" in capsys.readouterr().out


def test_verify_list_cited_prints_the_distinct_nist_ids(small, tmp_path, capsys):
    doc = tmp_path / "d.md"
    doc.write_text("AC-3 and AC-2 and AC-3 and LLM06 — excessive agency\n")
    assert main(["verify", "--list-cited", "--data", str(small), str(doc)]) == 0
    assert capsys.readouterr().out == "AC-2\nAC-3\n"


def test_verify_advisory_reports_a_title_mismatch_without_failing(small, tmp_path, capsys):
    doc = tmp_path / "d.md"
    doc.write_text("AC-3 (Account Management)\n")
    assert main(["verify", "--advisory", "--data", str(small), str(doc)]) == 0
    out = capsys.readouterr().out
    assert "MISLABELLED AC-3" in out and "(1 title mismatches, advisory)" in out


def test_verify_a_file_that_does_not_exist_is_skipped_not_a_crash(small, tmp_path, capsys):
    assert main(["verify", "--data", str(small), str(tmp_path / "missing.md")]) == 0
    assert "0 NIST" in capsys.readouterr().out


def test_versions_prints_json_for_the_receipt(capsys):
    assert main(["versions"]) == 0
    v = json.loads(capsys.readouterr().out)
    assert v["catalog"] == "5.2.0" and v["masvs"] == "v2.1.0"


def test_catalog_prints_each_control_and_refuses_an_unknown_one(small, capsys):
    assert main(["catalog", "--data", str(small), "AC-2", "SA-12"]) == 0
    out = capsys.readouterr().out
    assert "AC-2  Account Management  (AC; moderate, high)" in out
    assert "SA-12  Supply Chain Protection  (SA; withdrawn, into SR)" in out
    assert main(["catalog", "--data", str(small), "AC-2", "AC-99"]) == 1
    assert "AC-99  not in the catalog" in capsys.readouterr().out


def test_catalog_with_a_missing_index_exits_2(tmp_path, capsys):
    assert main(["catalog", "--data", str(tmp_path), "AC-2"]) == 2


def test_no_command_prints_help_and_exits_2(capsys):
    assert main([]) == 2


def test_the_run_script_puts_the_package_on_the_path(tmp_path):
    out = subprocess.run([str(RUN), "versions"], capture_output=True, text=True, cwd=tmp_path)
    assert out.returncode == 0 and json.loads(out.stdout)["catalog"] == "5.2.0"


def test_the_shell_wrapper_scans_the_same_documents_from_the_repository_root():
    """verify-citations.sh lists the documents and hands them to the CLI; its summary is the one the Makefile prints."""
    out = subprocess.run(["bash", str(ROOT / "standards" / "scripts" / "verify-citations.sh")], capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "NIST +" in out.stdout.splitlines()[-1] and "(800-53 5.2.0)" in out.stdout


@pytest.mark.parametrize("flag", ["--quiet", "--advisory"])
def test_the_shell_wrapper_passes_its_flags_through(flag):
    out = subprocess.run(["bash", str(ROOT / "standards" / "scripts" / "verify-citations.sh"), flag], capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0


def test_the_wrapper_reads_the_indexes_of_the_repository_it_runs_in(tmp_path):
    """The self-test runs it inside a fixture repository: the indexes come from there, not from the bot's tree."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    write_indexes(tmp_path / "standards" / "data" / "controls", only={"nist-800-53r5-index.json"})
    (tmp_path / "CLAUDE.md").write_text("AC-99 is invented\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    out = subprocess.run(["bash", str(ROOT / "standards" / "scripts" / "verify-citations.sh")], capture_output=True, text=True, cwd=tmp_path)
    assert out.returncode == 1 and "UNKNOWN     AC-99        CLAUDE.md:1" in out.stdout
