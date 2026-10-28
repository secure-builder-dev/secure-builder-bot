"""What a range changed: every file `changed_files` names is the same key `added_lines` uses.

The gate's checks read `added_lines` by the names `changed_files` returns, so a path the two spell
differently is a file no check ever sees. Git quotes and decorates names in a patch header (a tab
after a name holding a space, C-quoting for a quote, a tab, a newline, a backslash or non-ASCII
bytes), so these cases put each such name through both, at a commit and in the working tree.
"""

from __future__ import annotations

from pathlib import Path

from securebuilderbot_qa.diff import added_lines, changed_files

from .conftest import commit_all, git

# Every shape git decorates in a header. A tab, a newline and a backslash are legal in a path on Linux.
ODD = [
    "tests/check_more items.py",
    "tests/check_ünï.py",
    'tests/check_"quoted".py',
    "tests/check_tab\there.py",
    "tests/check_new\nline.py",
    "tests/check_back\\slash.py",
    "tests/check_[glob]*.py",
    "tests/-dash.py",
]


def write(repo: Path, path: str, text: str) -> None:
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def assert_keyed(repo: Path, base: str, head: str | None, expect: dict[str, dict[int, str]]) -> None:
    changed = changed_files(repo, base, head)
    assert changed == sorted(expect)
    added = added_lines(repo, base, head, changed)
    assert added == expect
    assert added_lines(repo, base, head) == expect


def test_every_changed_file_is_keyed_in_added_lines_whatever_its_name_at_a_commit(repo: Path):
    write(repo, "tests/keep.py", "x = 1\n")
    base = commit_all(repo, "base")
    for i, name in enumerate(ODD):
        write(repo, name, f"value = {i}\n")
    head = commit_all(repo, "odd names")
    assert_keyed(repo, base, head, {name: {1: f"value = {i}"} for i, name in enumerate(ODD)})


def test_every_changed_file_is_keyed_in_added_lines_whatever_its_name_in_the_working_tree(repo: Path):
    tracked = ODD[: len(ODD) // 2]
    untracked = ["new file.py", "tests/ünï new.py", 'q"uote.py', "t\tab.py"] + ODD[len(ODD) // 2:]
    for name in tracked:
        write(repo, name, "a = 0\n")
    base = commit_all(repo, "base")
    expect: dict[str, dict[int, str]] = {}
    for i, name in enumerate(tracked):
        write(repo, name, f"a = 0\nb = {i}\n")
        expect[name] = {2: f"b = {i}"}
    for i, name in enumerate(untracked):
        write(repo, name, f"c = {i}\n")
        expect[name] = {1: f"c = {i}"}
    assert_keyed(repo, base, None, expect)
    assert added_lines(repo, base, None, ["new file.py"]) == {"new file.py": {1: "c = 0"}}


def test_attributes_and_config_in_the_checkout_never_change_what_is_read(repo: Path):
    # A pull request can add `*.py -diff` or `binary` to .gitattributes; the checkout's config can
    # name a textconv driver, an external diff or forced colour. None may hide an added line.
    write(repo, "tests/check_a.py", "a = 1\n")
    write(repo, "notes.md", "one\n")
    base = commit_all(repo, "base")
    write(repo, ".gitattributes", "*.py -diff\n*.md diff=hide\n*.txt binary\n")
    git(repo, "config", "diff.hide.textconv", "sed s/./Z/g")
    git(repo, "config", "diff.external", "true")
    git(repo, "config", "color.diff", "always")
    write(repo, "tests/check_a.py", "a = 1\nb = 2\n")
    write(repo, "notes.md", "one\ntwo\n")
    write(repo, "data.txt", "plain\n")
    head = commit_all(repo, "blind the diff")
    expect = {".gitattributes": {1: "*.py -diff", 2: "*.md diff=hide", 3: "*.txt binary"},
              "tests/check_a.py": {2: "b = 2"}, "notes.md": {2: "two"}, "data.txt": {1: "plain"}}
    assert_keyed(repo, base, head, expect)
    write(repo, "tests/check_a.py", "a = 1\nb = 2\nc = 3\n")
    write(repo, "untracked.py", "u = 1\n")
    assert_keyed(repo, base, None, {**expect, "tests/check_a.py": {2: "b = 2", 3: "c = 3"}, "untracked.py": {1: "u = 1"}})


def test_a_rename_in_the_working_tree_is_changed_and_only_its_edits_are_added(repo: Path):
    body = "".join(f"def test_{i}():\n    assert {i}\n\n\n" for i in range(8))
    write(repo, "tests/test_old.py", "import pytest\n\n\n" + body)
    base = commit_all(repo, "base")
    git(repo, "mv", "tests/test_old.py", "tests/test new.py")
    write(repo, "tests/test new.py", "import pytest\n\n\nEDIT = 1\n" + body)
    assert_keyed(repo, base, None, {"tests/test new.py": {4: "EDIT = 1"}})


def test_a_symlink_replaced_by_a_file_is_a_change_whose_lines_are_all_added(repo: Path):
    write(repo, "target.txt", "t\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "check_link.py").symlink_to("../target.txt")
    base = commit_all(repo, "a link")
    (repo / "tests" / "check_link.py").unlink()
    write(repo, "tests/check_link.py", "import pytest\nx = 1\n")
    assert_keyed(repo, base, None, {"tests/check_link.py": {1: "import pytest", 2: "x = 1"}})
    head = commit_all(repo, "the link becomes a file")
    assert_keyed(repo, base, head, {"tests/check_link.py": {1: "import pytest", 2: "x = 1"}})
