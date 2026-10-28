"""qa/scripts/mutate-frontend.py, imported in-process: the bash suite runs it as a subprocess, which
no coverage report sees. These cases drive its parser and main() against a throwaway repository,
with canned suite commands, and assert what it decides: proven only when a test went red.
"""

from __future__ import annotations

import importlib.util
import signal
import sys
from pathlib import Path

import pytest

from .conftest import commit_all

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mutate-frontend.py"
RED = "echo 'Tests  1 failed'; exit 1"
MANIFEST = (
    "| id | file | from | to | proves |\n|---|---|---|---|---|\n"
    "| FM-01 | src/stub.ts | `const guard = true;` | `const guard = false;` | the guard holds |\n"
)


def load():
    spec = importlib.util.spec_from_file_location("mutate_frontend", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # @dataclass looks its module up while the class is built
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(spec.name, None)
    return mod


@pytest.fixture
def mf():
    handlers = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)
    yield load()
    signal.signal(signal.SIGINT, handlers[0])
    signal.signal(signal.SIGTERM, handlers[1])


@pytest.fixture
def front(repo: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (repo / "frontend" / "src").mkdir(parents=True)
    (repo / "docs" / "security").mkdir(parents=True)
    (repo / "docs" / "security" / "FRONTEND-MUTATIONS.md").write_text(MANIFEST)
    (repo / "frontend" / "src" / "stub.ts").write_text("const guard = true;\nexport default guard;\n")
    commit_all(repo, "front")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("MUTATE_FRONTEND_TEST_CMD", "true")
    monkeypatch.setenv("MUTATE_FRONTEND_ROW_TEST_CMD", RED)
    return repo


def run(mf, monkeypatch: pytest.MonkeyPatch, capsys, *args: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["mutate-frontend.py", *args])
    rc = mf.main()
    return rc, capsys.readouterr().out


def test_a_cell_is_read_literally_escaped_pipes_and_wrapping_backticks_included(mf, tmp_path: Path):
    assert mf.unescape_cell(" `a \\| b` ") == "a | b" and mf.unescape_cell("`x \\` y`") == "x ` y"
    m = tmp_path / "m.md"
    m.write_text(MANIFEST + "| FM-02 | src/a.ts | `x \\|\\| y` | `x` | or |\n| FM-03 | short |\n| not a row |\n")
    rows = mf.parse_manifest(str(m))
    assert [(r.id, r.frm, r.to) for r in rows] == [("FM-01", "const guard = true;", "const guard = false;"), ("FM-02", "x || y", "x")]
    assert rows[0].path == "frontend/src/stub.ts"


def test_a_row_is_proven_only_when_a_test_goes_red_and_the_source_is_restored(mf, front: Path, monkeypatch, capsys):
    rc, out = run(mf, monkeypatch, capsys)
    assert rc == 0 and "FM-01  proven" in out and "baseline: running frontend suite unmutated ... green" in out
    assert (front / "frontend" / "src" / "stub.ts").read_text() == "const guard = true;\nexport default guard;\n"


def test_a_row_the_suite_survives_is_not_proven(mf, front: Path, monkeypatch, capsys):
    monkeypatch.setenv("MUTATE_FRONTEND_ROW_TEST_CMD", "true")
    rc, out = run(mf, monkeypatch, capsys)
    assert rc == 1 and "FM-01  NOT PROVEN" in out and "NOT PROVEN: FM-01" in out


def test_a_mutation_that_breaks_the_build_with_no_test_failing_is_not_proven(mf, front: Path, monkeypatch, capsys):
    monkeypatch.setenv("MUTATE_FRONTEND_ROW_TEST_CMD", "echo 'transform error'; exit 1")
    rc, out = run(mf, monkeypatch, capsys)
    assert rc == 1 and "mutation broke the build, no test failed" in out


def test_a_red_baseline_stops_the_run_and_shows_why(mf, front: Path, monkeypatch, capsys):
    monkeypatch.setenv("MUTATE_FRONTEND_TEST_CMD", "echo the reason; exit 1")
    rc, out = run(mf, monkeypatch, capsys)
    assert rc == 1 and "RED" in out and "the reason" in out and "FM-01" not in out


def test_since_refuses_a_revision_it_cannot_scope_and_names_unchanged_rows(mf, front: Path, monkeypatch, capsys):
    rc, _ = run(mf, monkeypatch, capsys, "--since", "no-such-rev")
    assert rc == 2
    rc, out = run(mf, monkeypatch, capsys, "--since", "HEAD")
    assert rc == 0 and "FM-01  unchanged" in out and "0 row(s) re-mutated, 1 unchanged" in out
    (front / "frontend" / "src" / "stub.ts").write_text("const guard = true;\nexport default guard;\n// edit\n")
    commit_all(front, "touch the row's file")
    rc, out = run(mf, monkeypatch, capsys, "--since", "HEAD~1")
    assert rc == 0 and "1 row(s) re-mutated, 0 unchanged" in out and "FM-01  proven" in out


def test_list_dry_run_and_an_unlocatable_row(mf, front: Path, monkeypatch, capsys):
    rc, out = run(mf, monkeypatch, capsys, "--list")
    assert rc == 0 and "FM-01" in out and "the guard holds" in out
    rc, out = run(mf, monkeypatch, capsys, "--dry-run")
    assert rc == 0 and "1 row(s) locatable" in out and "nothing was run" in out
    (front / "frontend" / "src" / "stub.ts").write_text("const guard = maybe;\n")
    rc, out = run(mf, monkeypatch, capsys, "--only", "FM-01")
    assert rc == 1 and "UNLOCATABLE" in out and "matched 0 times" in out


def test_no_manifest_is_exit_2(mf, repo: Path, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    rc, out = run(mf, monkeypatch, capsys)
    assert rc == 2 and "none at docs/security/FRONTEND-MUTATIONS.md" in out
