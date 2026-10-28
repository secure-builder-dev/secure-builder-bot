"""Shared fixtures for the sentinel module's tests: a real throwaway git repository (never a mocked
one), a way to write a tree and commit it, and the gate context core would build for a range."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from securebuilderbot_core.gate import GateContext
from securebuilderbot_core.profiles import load_profile


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return out.stdout.strip()


def write_tree(repo: Path, files: dict[str, str | bytes | None]) -> None:
    """Write (or, for None, delete) each file under the repository."""
    for rel, content in files.items():
        p = repo / rel
        if content is None:
            p.unlink()
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)


def commit(repo: Path, files: dict[str, str | bytes | None], message: str = "c") -> str:
    write_tree(repo, files)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """An initialised repository on `main` with one empty commit and a committer identity."""
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    git(r, "config", "commit.gpgsign", "false")
    git(r, "commit", "-q", "--allow-empty", "-m", "base")
    return r


def context(repo: Path, base: str, head: str, run_root: Path, profile: str = "il6", depth: str = "light") -> GateContext:
    """The context core's runner would hand the gate: run_dir is <run>/sentinel beside <run>/qa."""
    run_dir = run_root / "sentinel"
    run_dir.mkdir(parents=True, exist_ok=True)
    return GateContext(repo=repo, base=base, head=head, profile=load_profile(profile), depth=depth, run_dir=run_dir)
