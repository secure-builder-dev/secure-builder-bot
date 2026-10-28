"""Unit tests for the scan line. The full behavioural suite is scanners/tests/scan-test-runner.sh,
which drives this same code through core/run scan-verdict against every fixture set."""

from pathlib import Path

from securebuilderbot_core.__main__ import main
from securebuilderbot_core.gate import GateResult
from securebuilderbot_core.verdict import overall, scan_verdict, verdict_block, write_stamp

FIXTURES = Path(__file__).resolve().parents[2] / "scanners" / "fixtures"


def test_clean_fixture_passes_seven_of_seven():
    v = scan_verdict(FIXTURES / "clean")
    assert v.passed and v.ran == 7 and v.total == 7
    assert v.line == "Scan: PASS — 7/7 scanners ran · 0 fixable · 0 POAM candidate(s), not blocking"


def test_a_skipped_scanner_is_not_counted_and_is_named(tmp_path):
    v = scan_verdict(FIXTURES / "clean", skip=("clamav",))
    assert v.total == 6 and v.passed
    assert "(skipped by config: clamav)" in v.line


def test_no_results_is_not_run(tmp_path):
    v = scan_verdict(tmp_path / "nothing")
    assert v.verdict == "NOT RUN" and not v.passed
    assert "This is not a pass" in v.line


def test_stamp_records_the_commit(repo, tmp_path):
    results = tmp_path / "r"
    results.mkdir()
    write_stamp(results, repo, "PASS")
    sha, verdict, _ = (results / ".scan-stamp").read_text().split()
    assert len(sha) == 40 and verdict == "PASS"


def test_cli_reads_results_without_stamping(tmp_path, capsys, monkeypatch, repo):
    import shutil
    results = tmp_path / "copy"
    shutil.copytree(FIXTURES / "clean", results)
    monkeypatch.chdir(repo)
    assert main(["scan-verdict", "--results", str(results)]) == 0
    assert not (results / ".scan-stamp").exists()
    assert main(["scan-verdict", "--results", str(results), "--stamp"]) == 0
    assert (results / ".scan-stamp").read_text().split()[1] == "PASS"
    assert main(["scan-verdict", "--results", str(tmp_path / "none")]) == 1
    assert "NOT RUN" in capsys.readouterr().out


def test_overall_and_block():
    p = GateResult(gate="scan", status="pass")
    y = GateResult(gate="qa", status="yellow", reason="accepted risk")
    f = GateResult(gate="sentinel", status="fail", reason="AC-3 unguarded")
    assert overall([p], ()) == "pass"
    assert overall([p], ("qa.mutation off",)) == "yellow"
    assert overall([p, y], ()) == "yellow"
    assert overall([p, y, f], ()) == "fail"
    assert verdict_block([p, f], ("x",)) == ["Scan: PASS", "Sentinel: FAIL — AC-3 unguarded", "Relaxed: x", "Overall: FAIL"]


def test_a_partial_scan_with_nothing_found_is_still_a_fail(tmp_path):
    import shutil
    results = tmp_path / "r"
    shutil.copytree(FIXTURES / "clean", results)
    ran = (results / "scanners-ran").read_text().splitlines()
    (results / "scanners-ran").write_text("\n".join(x for x in ran if not x.startswith("grype ")) + "\n")
    v = scan_verdict(results)
    assert not (results / "dispatch.md").exists()  # nothing fixable: the gap alone must fail it
    assert v.verdict == "FAIL" and not v.passed and v.ran == 6
    assert "(did not run: grype)" in v.line


def test_a_scanner_whose_result_file_is_unreadable_did_not_run(tmp_path):
    import shutil
    results = tmp_path / "r"
    shutil.copytree(FIXTURES / "clean", results)
    (results / "trivy.json").write_text("{not json")
    v = scan_verdict(results)
    assert v.verdict == "FAIL" and v.ran == 6
    assert "trivy(" in v.line


def _dated(tmp_path, grype_built):
    import json
    import shutil
    results = tmp_path / "dated"
    shutil.copytree(FIXTURES / "clean", results)
    g = json.loads((results / "grype.json").read_text())
    g.setdefault("descriptor", {})["db"] = {"status": {"built": grype_built}}
    (results / "grype.json").write_text(json.dumps(g))
    (results / "trivy-version.json").write_text(json.dumps({"VulnerabilityDB": {"UpdatedAt": grype_built}}))
    return results


def test_a_stamp_holds_the_scan_to_the_repository_profile_age_limit(tmp_path, capsys, monkeypatch, repo):
    (repo / ".securebuilderbot.yml").write_text("profile: il6\ngates: [scan]\nversion: latest\n")
    monkeypatch.chdir(repo)
    results = _dated(tmp_path, "2026-03-09T00:31:20Z")
    assert main(["scan-verdict", "--results", str(results)]) == 0  # a read repeats what the scanners found
    assert main(["scan-verdict", "--results", str(results), "--stamp"]) == 1
    assert (results / ".scan-stamp").read_text().split()[1] == "FAIL"
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("Scan: PASS") and out[1].startswith("Scan: FAIL")
    assert "stale CVE data: grype's database is" in out[1] and "trivy's database is" in out[1]


def test_a_stamp_with_fresh_data_or_no_config_passes(tmp_path, monkeypatch, repo):
    import datetime
    monkeypatch.chdir(repo)
    old = _dated(tmp_path, "2026-03-09T00:31:20Z")
    assert main(["scan-verdict", "--results", str(old), "--stamp"]) == 0  # no config: no profile, no limit
    (repo / ".securebuilderbot.yml").write_text("profile: il6\ngates: [scan]\nversion: latest\n")
    fresh = _dated(tmp_path / "f", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert main(["scan-verdict", "--results", str(fresh), "--stamp"]) == 0
    assert (fresh / ".scan-stamp").read_text().split()[1] == "PASS"


def test_a_stamp_is_not_written_when_the_config_is_invalid(tmp_path, capsys, monkeypatch, repo):
    (repo / ".securebuilderbot.yml").write_text("profile: il9\ngates: [scan]\nversion: latest\n")
    monkeypatch.chdir(repo)
    results = _dated(tmp_path, "2026-03-09T00:31:20Z")
    assert main(["scan-verdict", "--results", str(results), "--stamp"]) == 2
    assert not (results / ".scan-stamp").exists()
    assert "not stamped" in capsys.readouterr().out


def test_a_stamp_judges_cve_age_through_the_scanners_module_and_refuses_without_it(tmp_path, monkeypatch, repo):
    import shutil
    import sys
    results = tmp_path / "copy"
    shutil.copytree(FIXTURES / "clean", results)
    monkeypatch.chdir(repo)
    monkeypatch.setitem(sys.modules, "securebuilderbot_scanners.gate", None)  # not installed
    (repo / ".securebuilderbot.yml").write_text("profile: il6\ngates: [scan]\nversion: latest\n")
    assert main(["scan-verdict", "--results", str(results), "--stamp"]) == 1
    assert (results / ".scan-stamp").read_text().split()[1] == "FAIL"  # age unjudgeable is never a PASS stamp
    (results / ".scan-stamp").unlink()
    (repo / ".securebuilderbot.yml").write_text("profile: none\ngates: [scan]\nversion: latest\n")
    assert main(["scan-verdict", "--results", str(results), "--stamp"]) == 0  # none sets no limit: nothing to judge
    assert (results / ".scan-stamp").read_text().split()[1] == "PASS"
