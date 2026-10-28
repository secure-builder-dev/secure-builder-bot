"""What a range changed, read from git and nothing else: the files, and the lines it added.

The gate's range is two commits (the merge base and the head). The changed-line coverage script
reads the working tree instead, untracked files included, because that is what a developer is
about to commit; both go through the same parser here.

Names come only from NUL-separated lists (`-z`), never from a patch header: git ends a `+++` header
with a tab when the name holds a space and C-quotes it for a quote, a tab, a newline, a backslash or
non-ASCII bytes, so a header is not a name. Each file's patch is then read for its hunks alone, under
the name the list gave it. Every diff runs with `--text --no-textconv --no-ext-diff --no-color`, so
no attribute the checkout carries (`-diff`, `binary`, a diff driver) and no config it sets changes
what the gate reads; pathspecs are literal, so a name holding `*` or `[` is only itself.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")
# Added, modified, renamed and type-changed: a symlink replaced by a file is a file every line of which is new.
FILTER = "--diff-filter=AMRT"
# Whatever the checkout's attributes or config say, the gate reads the text of every file and the plain patch.
PLAIN = ("--text", "--no-textconv", "--no-ext-diff", "--no-color", "--no-relative")


def _run(repo: Path, *args: str, check: bool = True) -> bytes:
    out = subprocess.run(["git", "--literal-pathspecs", "-C", str(repo), *args], capture_output=True, check=check)
    return out.stdout


def _git(repo: Path, *args: str, check: bool = True) -> str:
    return _run(repo, *args, check=check).decode("utf-8", "surrogateescape")


def _names(out: str) -> list[str]:
    return [p for p in out.split("\0") if p]


def _pairs(repo: Path, base: str, head: str | None) -> list[tuple[str, ...]]:
    """(path,) or (old path, new path) for every file the range added, modified, renamed or changed the type of."""
    out = _git(repo, "diff", "-z", "--name-status", "--find-renames", FILTER, *PLAIN, base, *([head] if head else []))
    fields, pairs, i = out.split("\0"), [], 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        width = 2 if status[0] in "RC" else 1
        pairs.append(tuple(fields[i + 1:i + 1 + width]))
        i += 1 + width
    return pairs


def _untracked(repo: Path) -> list[str]:
    return _names(_git(repo, "ls-files", "-z", "--others", "--exclude-standard"))


def changed_files(repo: Path, base: str, head: str | None) -> list[str]:
    """Files added, modified, renamed or type-changed between base and head (or the working tree, untracked included, when head is None).

    A renamed file is listed by its new path. Copies are not detected, so a copy reads as an added file.
    """
    files = {pair[-1] for pair in _pairs(repo, base, head)}
    if head is None:
        files.update(_untracked(repo))
    return sorted(files)


def _added_from_patch(patch: str) -> dict[int, str]:
    """{line: text} added by one file's `git diff --unified=0`; its header lines are skipped, never read for a name.

    Header lines are only those between `diff --git` and the first hunk, so an added line whose
    text begins `++ ` or `-- ` is still an added line. A type change prints as a deletion and an
    addition, two headers for one name; both are read.
    """
    lines: dict[int, str] = {}
    in_header = False
    n = 0
    for raw in patch.split("\n"):
        if raw.startswith("diff --git "):
            in_header = True
            continue
        m = HUNK.match(raw)
        if m:
            in_header, n = False, int(m.group(1))
            continue
        if in_header:
            continue
        if raw.startswith("+"):
            lines[n] = raw[1:-1] if raw.endswith("\r") else raw[1:]
            n += 1
    return lines


def _patch(repo: Path, *args: str, check: bool = True) -> dict[int, str]:
    out = _run(repo, "diff", "--unified=0", "--find-renames", FILTER, *PLAIN, *args, check=check)
    return _added_from_patch(out.decode("utf-8", "replace"))


def added_lines(repo: Path, base: str, head: str | None, files: list[str] | None = None) -> dict[str, dict[int, str]]:
    """{file: {line number at head: text}} for every line the range added, in every file (or the given ones).

    Each file is diffed under the name `changed_files` gives it. A renamed file is diffed together
    with its old path, so the rename pairs and only the lines it really added count; a pathspec of
    the new path alone would hide the old one and make every line new.
    """
    wanted = None if files is None else set(files)
    rev = [base] if head is None else [base, head]
    parsed: dict[str, dict[int, str]] = {}
    for pair in _pairs(repo, base, head):
        if wanted is None or pair[-1] in wanted:
            parsed[pair[-1]] = _patch(repo, *rev, "--", *pair)
    if head is None:  # untracked: every line is new
        for f in _untracked(repo):
            if wanted is None or f in wanted:
                parsed[f] = _patch(repo, "--no-index", "--", "/dev/null", f, check=False)
    return {f: lines for f, lines in parsed.items() if lines}


def commits_touching(repo: Path, base: str, head: str, path: str) -> list[str]:
    """The messages of the commits in base..head that touch the path, newest first."""
    out = _git(repo, "log", "--format=%x00%B", f"{base}..{head}", "--", path)
    return [m.strip() for m in out.split("\x00") if m.strip()]
