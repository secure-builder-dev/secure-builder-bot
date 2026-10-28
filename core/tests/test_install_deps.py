"""core/install-deps: every tracked npm lockfile's app gets `npm ci` before the gates, once, and a failed install never stops the run."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "install-deps"
FAKE_NPM = '#!/usr/bin/env bash\necho "$PWD $*" >> "$NPM_CALLS"\nexit "${NPM_EXIT:-0}"\n'


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    for rel in ("backend/package-lock.json", "frontend/npm-shrinkwrap.json", "frontend/package-lock.json",
                "tools/node_modules/x/package-lock.json", "docs/old-package-lock.json", "web/package-lock.json"):
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text("{}\n")
    (repo / "web" / "node_modules").mkdir()
    (repo / "untracked").mkdir()
    (repo / "untracked" / "package-lock.json").write_text("{}\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "backend", "frontend", "tools", "docs", "web"], cwd=repo, check=True)
    return repo


def run(repo: Path, tmp_path: Path, *, npm: bool = True, **env: str) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    if npm:
        (bin_dir / "npm").write_text(FAKE_NPM)
        (bin_dir / "npm").chmod(0o755)
    path = f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin"
    return subprocess.run(["bash", str(SCRIPT), str(repo)], capture_output=True, text=True,
                          env={"PATH": path, "NPM_CALLS": str(tmp_path / "calls"), **env})


def calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls"
    return log.read_text().splitlines() if log.is_file() else []


def test_each_tracked_app_without_node_modules_gets_npm_ci_once(checkout: Path, tmp_path: Path):
    out = run(checkout, tmp_path)
    assert out.returncode == 0, out.stderr
    # Not the lockfile inside node_modules, not a file merely ending in the name, not an untracked
    # one, not an app that already has node_modules, and frontend once for its two lockfiles.
    assert calls(tmp_path) == [f"{checkout}/backend ci --no-fund --no-audit --loglevel=error",
                               f"{checkout}/frontend ci --no-fund --no-audit --loglevel=error"]
    assert "web already has node_modules" in out.stdout


def test_a_failed_install_is_said_and_the_run_goes_on(checkout: Path, tmp_path: Path):
    out = run(checkout, tmp_path, NPM_EXIT="1")
    assert out.returncode == 0
    assert len(calls(tmp_path)) == 2
    assert "npm ci failed in backend" in out.stdout and "npm ci failed in frontend" in out.stdout


def test_no_npm_installs_nothing_and_says_so(checkout: Path, tmp_path: Path):
    out = run(checkout, tmp_path, npm=False)
    assert out.returncode == 0 and calls(tmp_path) == []
    assert "npm is not on PATH" in out.stdout


def test_a_repository_without_an_npm_lockfile_is_left_alone(tmp_path: Path):
    repo = tmp_path / "py"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='x'\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    out = run(repo, tmp_path)
    assert out.returncode == 0 and calls(tmp_path) == []
    assert "no npm lockfile tracked" in out.stdout


def test_a_checkout_that_is_not_a_directory_is_a_usage_error(tmp_path: Path):
    assert run(tmp_path / "nope", tmp_path).returncode == 2
