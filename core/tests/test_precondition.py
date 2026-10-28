from pathlib import Path

from securebuilderbot_core.__main__ import main
from securebuilderbot_core.precondition import check

from .conftest import commit_all, git


def stamp(results: Path, sha: str, verdict: str = "PASS") -> None:
    results.mkdir(parents=True, exist_ok=True)
    (results / ".scan-stamp").write_text(f"{sha} {verdict} 2026-10-15T00:00:00Z\n")


def test_no_scan_recorded_refuses_and_says_what_to_run(repo, tmp_path):
    ok, msg = check(repo, tmp_path / "r")
    assert not ok and "make gate-scan" in msg


def test_a_green_scan_of_this_commit_passes(repo, tmp_path):
    stamp(tmp_path / "r", git(repo, "rev-parse", "HEAD"))
    assert check(repo, tmp_path / "r") == (True, "")


def test_a_red_scan_refuses(repo, tmp_path):
    stamp(tmp_path / "r", git(repo, "rev-parse", "HEAD"), "FAIL")
    ok, msg = check(repo, tmp_path / "r")
    assert not ok and "was FAIL" in msg


def test_a_stamp_naming_no_commit_refuses(repo, tmp_path):
    stamp(tmp_path / "r", "deadbeef" * 5)
    ok, msg = check(repo, tmp_path / "r")
    assert not ok and "not a commit in this repository" in msg


def test_record_only_drift_keeps_the_scan(repo, tmp_path):
    scanned = git(repo, "rev-parse", "HEAD")
    (repo / "tasks").mkdir()
    (repo / "tasks" / "todo.md").write_text("- [x] done\n")
    (repo / "gate-records").mkdir()
    (repo / "gate-records" / "gate-log.md").write_text("| row |\n")
    commit_all(repo)
    stamp(tmp_path / "r", scanned)
    ok, msg = check(repo, tmp_path / "r")
    assert ok and "every file" in msg


def test_source_drift_refuses_and_names_the_file(repo, tmp_path):
    scanned = git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("x = 1\n")
    commit_all(repo)
    stamp(tmp_path / "r", scanned)
    ok, msg = check(repo, tmp_path / "r")
    assert not ok and "app.py" in msg


def test_an_unreadable_stamp_refuses(repo, tmp_path):
    (tmp_path / "r").mkdir()
    (tmp_path / "r" / ".scan-stamp").write_text("onlyonefield\n")
    ok, msg = check(repo, tmp_path / "r")
    assert not ok and "unreadable" in msg


def test_skip_is_loud(repo, tmp_path):
    ok, msg = check(repo, tmp_path / "r", skip_check=True)
    assert ok and "CVE state is unknown" in msg


def test_cli(repo, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    assert main(["scan-precondition", "--results", str(tmp_path / "r")]) == 1
    assert "make gate-scan" in capsys.readouterr().err
    stamp(tmp_path / "r", git(repo, "rev-parse", "HEAD"))
    assert main(["scan-precondition", "--results", str(tmp_path / "r")]) == 0
    monkeypatch.setenv("SKIP_SCAN_CHECK", "1")
    assert main(["scan-precondition", "--results", str(tmp_path / "none")]) == 0
