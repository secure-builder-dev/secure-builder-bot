"""Changed-line coverage: the lines a range adds to production code, against every adapter's lcov."""

from __future__ import annotations

from pathlib import Path

from securebuilderbot_qa.coverage_changed import CoverageReport, changed_line_coverage, is_test_path, lcov_lines, meets, production_files
from securebuilderbot_qa.diff import added_lines, changed_files

from .conftest import commit_all, git


def two_commits(repo: Path) -> tuple[str, str]:
    (repo / "pkg").mkdir()
    (repo / "pkg" / "a.py").write_text("x = 1\ny = 2\n")
    (repo / "README.md").write_text("one\n")
    base = commit_all(repo, "base")
    (repo / "pkg" / "a.py").write_text("x = 1\nz = 3\ny = 2\nw = 4\n")
    (repo / "pkg" / "b.py").write_text("def f():\n    return 1\n")
    (repo / "README.md").write_text("one\ntwo\n")
    (repo / "pkg" / "c.py").write_text("gone\n")
    commit_all(repo, "add")
    (repo / "pkg" / "c.py").unlink()
    head = commit_all(repo, "remove c")
    return base, head


def test_changed_files_and_added_lines_come_from_the_range(repo: Path):
    base, head = two_commits(repo)
    assert changed_files(repo, base, head) == ["README.md", "pkg/a.py", "pkg/b.py"]
    added = added_lines(repo, base, head)
    assert added["pkg/a.py"] == {2: "z = 3", 4: "w = 4"}
    assert added["pkg/b.py"] == {1: "def f():", 2: "    return 1"}
    assert added["README.md"] == {2: "two"}
    assert "pkg/c.py" not in added  # added and removed inside the range: nothing to cover at head


def test_a_renamed_file_is_changed_and_only_its_edits_are_added(repo: Path):
    # A rename with an edit used to vanish from the range (--diff-filter=AM), so a skip marker
    # added while moving a test file was never seen. Only the edit is new: the moved lines are not.
    # The marker is assembled from pieces so this file's own lines never read as a skip to the floor guard.
    marker = "@pytest.mark." + "skip"
    (repo / "tests").mkdir()
    body = "".join(f"def test_{i}():\n    assert {i}\n\n\n" for i in range(8))
    (repo / "tests" / "test_old.py").write_text("import pytest\n\n\n" + body)
    base = commit_all(repo, "base")
    git(repo, "mv", "tests/test_old.py", "tests/test_new.py")
    (repo / "tests" / "test_new.py").write_text("import pytest\n\n\n" + marker + "\n" + body)
    head = commit_all(repo, "move and skip")
    assert changed_files(repo, base, head) == ["tests/test_new.py"]
    assert added_lines(repo, base, head) == {"tests/test_new.py": {4: marker}}
    assert added_lines(repo, base, head, ["tests/test_new.py"]) == {"tests/test_new.py": {4: marker}}


def test_an_added_line_that_looks_like_a_diff_header_is_still_an_added_line(repo: Path):
    (repo / "a.txt").write_text("one\n")
    base = commit_all(repo, "base")
    (repo / "a.txt").write_text("one\n++ b/x\n-- a/y\n")
    head = commit_all(repo, "headerish")
    assert added_lines(repo, base, head) == {"a.txt": {2: "++ b/x", 3: "-- a/y"}}


def test_added_lines_of_the_working_tree_include_untracked_files(repo: Path):
    base, head = two_commits(repo)
    (repo / "pkg" / "d.py").write_text("new = 1\n")
    (repo / "pkg" / "a.py").write_text("x = 1\nz = 3\ny = 2\nw = 4\nv = 5\n")
    added = added_lines(repo, base, None)
    assert added["pkg/d.py"] == {1: "new = 1"} and added["pkg/a.py"] == {2: "z = 3", 4: "w = 4", 5: "v = 5"}
    assert git(repo, "status", "--porcelain") != ""  # the tree was read, not touched


def test_test_paths_are_the_measure_not_the_measured():
    assert is_test_path("core/tests/test_x.py") and is_test_path("api/src/__tests__/a.test.ts")
    assert is_test_path("web/src/a.spec.tsx") and is_test_path("pkg/x_test.py") and is_test_path("qa/tests/conftest.py")
    assert not is_test_path("core/securebuilderbot_core/runner.py") and not is_test_path("api/src/testing.ts")
    files = ["a.py", "b.ts", "c.tsx", "d.js", "e.mjs", "f.md", "g.sh", "tests/test_a.py", "h.cjs"]
    assert production_files(files) == ["a.py", "b.ts", "c.tsx", "d.js", "e.mjs", "h.cjs"]


TOOLS = ("karma", "rollup", "webpack", "vite", "vitest", "jest", "ava", "babel", "nyc", "cypress", "tsup", "build", "eslint", "prettier")


def test_a_tool_config_file_is_not_production_code_but_any_other_config_file_is():
    # The files vitest's own coverage leaves out by default, `**/{karma,…,prettier}.config.*`: no test
    # imports them, so measured they read as every added line uncovered.
    tools = [f"{t}.config.{ext}" for t in TOOLS for ext in ("js", "ts", "mjs", "cjs")]
    nested = ["adapter-github/eslint.config.js", "web/vitest.config.ts", "a/b/vite.config.mts", "cli/jest.config.cjs"]
    assert production_files(tools + nested) == []
    # Only those basenames: a config module that holds logic is measured like any other source.
    real = ["app.config.ts", "src/config.ts", "src/app.config.js", "eslint.config.helper/index.ts", "myvite.config.ts",
            "vite.configure.ts", "vite.config", "eslint-config.js", "src/build.ts", "jest.setup.ts"]
    assert production_files(real) == ["app.config.ts", "src/config.ts", "src/app.config.js", "eslint.config.helper/index.ts",
                                      "myvite.config.ts", "vite.configure.ts", "eslint-config.js", "src/build.ts", "jest.setup.ts"]


def test_lcov_paths_are_made_repo_relative_from_the_apps_root(tmp_path: Path):
    lcov = tmp_path / "x.lcov"
    lcov.write_text("TN:\nSF:src/a.js\nDA:1,1\nDA:2,0\nend_of_record\nSF:" + str(tmp_path / "pkg" / "m.py") + "\nDA:3,2\nend_of_record\n")
    hits = lcov_lines(lcov, tmp_path, "api")
    assert hits["api/src/a.js"] == {1: 1, 2: 0}
    assert hits["pkg/m.py"] == {3: 2}  # absolute paths are relative to the repository, whatever the app


def test_changed_line_coverage_counts_only_executable_added_lines():
    added = {"pkg/a.py": {1, 2, 3, 4}, "pkg/b.py": {1}, "pkg/none.py": {7}}
    hits = {"pkg/a.py": {1: 1, 2: 0, 4: 3, 9: 1}, "pkg/b.py": {1: 1}}
    r = changed_line_coverage(added, hits)
    assert (r.covered, r.executable) == (3, 5)  # a.py: 1,2,4 executable (3 is a blank or comment); b.py: 1; none.py: 1 unmeasured
    assert r.missed == ("pkg/a.py:2", "pkg/none.py: not in the coverage report (never imported by a test)")
    assert round(r.pct, 1) == 60.0


def test_meets_is_the_threshold_decision():
    assert meets(CoverageReport(covered=9, executable=10, missed=()), 90)
    assert not meets(CoverageReport(covered=8, executable=10, missed=()), 90)
    assert meets(CoverageReport(covered=0, executable=0, missed=()), 100)  # nothing executable added: nothing to hold
