"""The scan's scope, as the gate expects it: every manifest in the checkout the runners should have audited.

The runners find their targets with scanners/scripts/scan-scope.sh; this is the same walk in Python,
with the same prune list, so the gate can hold the runners to it. A manifest that is in the checkout
and not in a runner's decision file was not audited, and "not audited" is never "nothing in scope"
(SPEC-scanners.md § Scope).
"""

from __future__ import annotations

import fnmatch
import json
import subprocess
from pathlib import Path

PRUNE_NAMES = frozenset({"node_modules", ".git", "dist", "build", "vendor", ".venv", "venv"})
PRUNE_PATHS = ("scanners/fixtures",)
NPM = ("package.json", "package-lock.json")
PYTHON = ("requirements*.txt", "pyproject.toml")


def _ignored(repo: Path, files: list[str]) -> set[str]:
    """The paths git ignores, in one call; nothing when the checkout is not a repository."""
    if not files:
        return set()
    out = subprocess.run(["git", "-C", str(repo), "check-ignore", "--stdin"], input="\n".join(files) + "\n",
                         capture_output=True, text=True)
    return set(out.stdout.split()) if out.returncode in (0, 1) else set()


def targets(repo: Path, *patterns: str) -> list[str]:
    """Repo-relative files matching any pattern, pruned the way scan-scope.sh prunes, gitignored ones dropped."""
    found: list[str] = []
    stack = [repo]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            rel = e.relative_to(repo).as_posix()
            if e.is_dir():
                if e.name not in PRUNE_NAMES and rel not in PRUNE_PATHS:
                    stack.append(e)
            elif any(fnmatch.fnmatch(e.name, p) for p in patterns):
                found.append(rel)
    ignored = _ignored(repo, found)
    return sorted(f for f in found if f not in ignored)


def _apps(path: Path) -> set[str]:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return set()
    return {str(a.get("app")) for a in doc.get("apps", []) if isinstance(a, dict)}


def _files(path: Path) -> set[str]:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return set()
    return {str(a.get("file")) for a in doc.get("apps", []) if isinstance(a, dict)}


def unaudited_manifests(repo: Path, results: Path) -> list[str]:
    """Manifests in the checkout that no runner's decision file says it audited. Empty is the only pass."""
    audited_apps = _apps(results / "audit.json")
    audited_files = _files(results / "pip-audit.json")
    out = []
    for f in targets(repo, *NPM):
        if Path(f).parent.as_posix() not in audited_apps:
            out.append(f)
    for f in targets(repo, *PYTHON):
        # A pyproject beside a requirements file is covered by that file (run-pip-audit.sh audits the file).
        beside = any(a.rsplit("/", 1)[0] == Path(f).parent.as_posix() for a in audited_files if "/" in a) \
            or any(Path(a).parent.as_posix() == Path(f).parent.as_posix() for a in audited_files)
        if f not in audited_files and not (f.endswith("pyproject.toml") and beside):
            out.append(f)
    return sorted(set(out))
