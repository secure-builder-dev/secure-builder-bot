"""scripts/coverage-changed.py, in process: the added-line coverage check refuses, passes and cannot-run
for the reasons its docstring states. constraints-test.sh runs it as a subprocess; these import it, so
the lines it adds are measured too. Every case is a real throwaway git repository, never a mock."""

from __future__ import annotations

import importlib.util
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "coverage-changed.py"


def load():
    spec = importlib.util.spec_from_file_location("coverage_changed", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cc = load()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repository on `main` with core/securebuilderbot_core/old.py committed, checked out on a branch, cwd there."""
    r = tmp_path / "repo"
    (r / "core" / "securebuilderbot_core").mkdir(parents=True)
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    git(r, "config", "commit.gpgsign", "false")
    (r / "core" / "securebuilderbot_core" / "old.py").write_text("def a():\n    return 1\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "base")
    git(r, "checkout", "-q", "-b", "work")
    monkeypatch.chdir(r)
    return r


def commit(repo: Path) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "change")


def write_lcov(repo: Path, records: dict[str, dict[int, int]], absolute: bool = True) -> None:
    out = []
    for f, lines in records.items():
        out.append(f"SF:{repo / f if absolute else f}")
        out += [f"DA:{n},{h}" for n, h in lines.items()]
        out.append("end_of_record")
    state = repo / "gate-records" / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "core.lcov").write_text("\n".join(out) + "\n")


NEW = "core/securebuilderbot_core/new.py"


def add_new(repo: Path) -> None:
    (repo / NEW).write_text("def b():\n    return 2\n\n\ndef c():\n    return 3\n")


# ── default_base ────────────────────────────────────────────────────────────


def test_default_base_prefers_origin_main(repo: Path) -> None:
    git(repo, "update-ref", "refs/remotes/origin/main", "main")
    assert cc.default_base() == "origin/main"


def test_default_base_falls_back_to_main(repo: Path) -> None:
    assert cc.default_base() == "main"


def test_default_base_is_none_without_either(repo: Path) -> None:
    git(repo, "branch", "-q", "-D", "main")
    assert cc.default_base() is None


# ── the added lines it measures ─────────────────────────────────────────────
# On this branch the diff is the qa package's (securebuilderbot_qa.diff.added_lines), so the lines
# are read back through main(): every candidate line is marked uncovered, and the lines the script
# lists as uncovered are exactly the added lines it measured.


def measured(repo: Path, capsys: pytest.CaptureFixture[str], *include: str) -> dict[str, set[int]]:
    candidates = [p.relative_to(repo).as_posix() for p in repo.rglob("*.py") if ".git" not in p.parts]
    write_lcov(repo, {f: {n: 0 for n in range(1, 41)} for f in candidates})
    args = ["--base", "main"] + [a for i in include for a in ("--include", i)]
    code, out = run(capsys, *args)
    got: dict[str, set[int]] = {}
    for line in out.splitlines():
        if line.startswith("  uncovered  "):
            f, n = line.split("  uncovered  ", 1)[1].rsplit(":", 1)
            got.setdefault(f, set()).add(int(n))
    assert code == (1 if got else 0), out
    return got


def test_added_lines_counts_new_tracked_and_untracked_files(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_new(repo)
    commit(repo)
    (repo / "core" / "securebuilderbot_core" / "loose.py").write_text("x = 1\ny = 2\n")
    assert measured(repo, capsys, "core/") == {
        NEW: {1, 2, 3, 4, 5, 6},
        "core/securebuilderbot_core/loose.py": {1, 2},
    }


def test_added_lines_takes_only_the_added_lines_of_a_modified_file(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "core" / "securebuilderbot_core" / "old.py").write_text("def a():\n    return 1\n\n\ndef z():\n    return 9\n")
    commit(repo)
    assert measured(repo, capsys, "core/") == {"core/securebuilderbot_core/old.py": {3, 4, 5, 6}}


def test_added_lines_drops_a_file_that_only_lost_lines(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "core" / "securebuilderbot_core" / "old.py").write_text("def a():\n")
    commit(repo)
    assert measured(repo, capsys, "core/") == {}


def test_added_lines_excludes_tests_other_prefixes_and_non_python(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "core" / "tests").mkdir()
    (repo / "core" / "tests" / "test_x.py").write_text("def test_x():\n    assert True\n")
    (repo / "other").mkdir()
    (repo / "other" / "m.py").write_text("x = 1\n")
    (repo / "core" / "notes.md").write_text("words\n")
    commit(repo)
    assert measured(repo, capsys, "core/") == {}
    assert measured(repo, capsys, "other/") == {"other/m.py": {1}}


def test_added_lines_raises_without_a_merge_base(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "--base", "no-such-ref")
    assert code == 2
    assert "no merge base against no-such-ref" in out


# ── lcov_lines ──────────────────────────────────────────────────────────────


def test_lcov_lines_reads_absolute_and_relative_paths(repo: Path, tmp_path: Path) -> None:
    lcov = tmp_path / "x.lcov"
    lcov.write_text(
        f"SF:{repo / NEW}\nDA:1,3\nDA:2,0,checksum\nend_of_record\n"
        "SF:core/rel.py\nDA:7,1\nend_of_record\n"
        "DA:9,1\n"  # outside any record: ignored, never attributed to the last file
    )
    assert cc.lcov_lines(lcov, repo.resolve()) == {NEW: {1: 3, 2: 0}, "core/rel.py": {7: 1}}


# ── main: exit codes ────────────────────────────────────────────────────────


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = cc.main(list(argv))
    return code, capsys.readouterr().out


def test_fully_covered_added_lines_pass(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_new(repo)
    commit(repo)
    write_lcov(repo, {NEW: {1: 1, 2: 1, 5: 1, 6: 2}})
    code, out = run(capsys, "--base", "main", "--min", "80")
    assert code == 0
    assert "4/4 added executable lines covered (100.0%, minimum 80%) ok" in out


def test_relative_lcov_paths_are_matched_too(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_new(repo)
    commit(repo)
    write_lcov(repo, {NEW: {1: 1, 2: 1, 5: 1, 6: 1}}, absolute=False)
    assert run(capsys, "--base", "main")[0] == 0


def test_below_the_minimum_fails_and_lists_the_uncovered_lines(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_new(repo)
    commit(repo)
    write_lcov(repo, {NEW: {1: 1, 2: 0, 5: 1, 6: 0}})
    code, out = run(capsys, "--base", "main", "--min", "80")
    assert code == 1
    assert "2/4 added executable lines covered (50.0%, minimum 80%) BELOW" in out
    assert f"  uncovered  {NEW}:2\n" in out
    assert f"  uncovered  {NEW}:6\n" in out
    assert f"{NEW}:1" not in out


def test_exactly_at_the_minimum_passes(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_new(repo)
    commit(repo)
    write_lcov(repo, {NEW: {1: 1, 2: 0, 5: 1, 6: 0}})
    code, out = run(capsys, "--base", "main", "--min", "50")
    assert code == 0
    assert "(50.0%, minimum 50%) ok" in out
    assert "uncovered" not in out


def test_the_default_minimum_is_80(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_new(repo)
    commit(repo)
    write_lcov(repo, {NEW: {1: 1, 2: 1, 5: 1, 6: 0}})  # 75%
    code, out = run(capsys, "--base", "main")
    assert code == 1
    assert "minimum 80%" in out


def test_a_file_never_imported_counts_every_added_line_as_missed(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_new(repo)
    commit(repo)
    write_lcov(repo, {"core/securebuilderbot_core/old.py": {1: 1, 2: 1}})
    code, out = run(capsys, "--base", "main")
    assert code == 1
    assert "0/6 added executable lines covered (0.0%" in out
    assert f"  uncovered  {NEW}: not in the coverage report (never imported by a test)" in out


def test_the_uncovered_list_stops_at_forty(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / NEW).write_text("".join(f"x{i} = {i}\n" for i in range(50)))
    commit(repo)
    write_lcov(repo, {NEW: {n: 0 for n in range(1, 51)}})
    code, out = run(capsys, "--base", "main")
    assert code == 1
    assert out.count("  uncovered  ") == 40
    assert f"{NEW}:40\n" in out
    assert f"{NEW}:41\n" not in out


def test_only_lines_lcov_calls_executable_count(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "core" / "securebuilderbot_core" / "old.py").write_text("def a():\n    return 1\n# a comment\n")
    commit(repo)
    write_lcov(repo, {"core/securebuilderbot_core/old.py": {1: 1, 2: 1}})
    code, out = run(capsys, "--base", "main")
    assert code == 0
    assert out == "coverage-changed: no executable lines added — nothing to measure\n"


def test_nothing_added_is_nothing_to_measure(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "--base", "main", "--include", "core/")
    assert code == 0
    assert out == "coverage-changed: no Python added under core/ — nothing to measure\n"


def test_includes_default_to_every_module_package(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "qa" / "securebuilderbot_qa").mkdir(parents=True)
    (repo / "qa" / "securebuilderbot_qa" / "m.py").write_text("x = 1\n")
    (repo / "qa" / "tests").mkdir()  # a module counts when its tests sit beside its package
    (repo / "qa" / "tests" / "test_m.py").write_text("def test_m():\n    assert True\n")
    (repo / "loose").mkdir()
    (repo / "loose" / "m.py").write_text("x = 1\n")
    commit(repo)
    write_lcov(repo, {"qa/securebuilderbot_qa/m.py": {1: 0}, "loose/m.py": {1: 0}})
    code, out = run(capsys, "--base", "main")
    assert code == 1
    assert "0/1 added" in out
    assert "qa/securebuilderbot_qa/m.py:1" in out
    assert "loose/m.py" not in out


def test_includes_fall_back_to_core_without_any_package(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    git(repo, "rm", "-q", "-r", "core/securebuilderbot_core")
    (repo / "core").mkdir(exist_ok=True)
    (repo / "core" / "m.py").write_text("x = 1\n")
    commit(repo)
    code, out = run(capsys, "--base", "main")
    assert code == 2
    assert "no coverage file" in out


def test_a_missing_coverage_file_is_never_a_pass(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_new(repo)
    commit(repo)
    code, out = run(capsys, "--base", "main", "--lcov", "nowhere.lcov")
    assert code == 2
    assert out == "coverage-changed: no coverage file at nowhere.lcov — run `make test` first\n"


def test_no_merge_base_is_exit_2(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "--base", "no-such-ref")
    assert code == 2
    assert out == "coverage-changed: no merge base against no-such-ref\n"


def test_no_main_to_diff_against_is_exit_2(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    git(repo, "branch", "-q", "-D", "main")
    code, out = run(capsys)
    assert code == 2
    assert out == "coverage-changed: no origin/main or main to diff against\n"


def test_base_defaults_to_main(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_new(repo)
    commit(repo)
    write_lcov(repo, {NEW: {1: 1, 2: 1, 5: 1, 6: 1}})
    assert run(capsys)[0] == 0


def test_run_as_a_script_exits_with_mains_code(repo: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--base", "no-such-ref"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exc.value.code == 2
    assert "no merge base against no-such-ref" in capsys.readouterr().out
