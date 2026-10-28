"""Shared fixtures for the qa module's tests: a real throwaway git repository, a fake npm on PATH."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return out.stdout.strip()


def commit_all(repo: Path, message: str = "c") -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
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


FAKE_NPM = """#!/usr/bin/env bash
# A fake npm, as the scan suite fakes its scanners: records its arguments, writes the lcov file a
# real `npm test -- --coverage` would, prints a runner-shaped summary, exits as told.
printf '%s\\n' "$*" >> "${FAKE_NPM_LOG:?}"
if [ -n "${FAKE_NPM_ENV_DUMP:-}" ]; then env > "$FAKE_NPM_ENV_DUMP"; fi
mkdir -p coverage
printf '%s\\n' "${FAKE_NPM_LCOV:-}" > coverage/lcov.info
if [ "${FAKE_NPM_RUNNER:-jest}" = vitest ]; then
  printf ' Test Files  1 passed (1)\\n      Tests  3 passed | 1 skipped (4)\\n'
else
  printf 'Tests:       1 skipped, 3 passed, 4 total\\n'
fi
exit "${FAKE_NPM_EXIT:-0}"
"""


@pytest.fixture
def fake_npm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Puts a fake `npm` first on PATH; returns the file its calls are logged to."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    npm = bin_dir / "npm"
    npm.write_text(FAKE_NPM)
    npm.chmod(npm.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "npm-calls.log"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_NPM_LOG", str(log))
    monkeypatch.delenv("FAKE_NPM_EXIT", raising=False)
    monkeypatch.delenv("FAKE_NPM_LCOV", raising=False)
    return log


def write_package_json(app: Path, **fields) -> None:
    app.mkdir(parents=True, exist_ok=True)
    (app / "package.json").write_text(json.dumps({"name": app.name, "version": "1.0.0", **fields}))
