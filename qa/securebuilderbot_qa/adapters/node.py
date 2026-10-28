"""Node: Jest and Vitest, detected from package.json, run through `npm test -- --coverage` with an lcov reporter."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from . import SuiteResult, parse_counts, run_logged

REPORTER_FLAGS = {
    "jest": ["--coverage", "--coverageReporters=lcov", "--coverageReporters=text"],
    "vitest": ["--coverage", "--coverage.reporter=lcov", "--coverage.reporter=text"],
}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage"}


def _kind(doc: dict) -> str | None:
    deps = {**doc.get("dependencies", {}), **doc.get("devDependencies", {})}
    script = str(doc.get("scripts", {}).get("test", ""))
    for kind in ("vitest", "jest"):  # the test script's own word wins over what happens to be installed
        if kind in script.split() or script.startswith(kind):
            return kind
    for kind in ("jest", "vitest"):
        if kind in deps:
            return kind
    return None


def detect_node(repo: Path, log_dir: Path | None = None) -> list[NodeRunner]:
    """One runner per package.json (outside node_modules and build output) whose test runner is Jest or Vitest."""
    out = []
    for pj in sorted(repo.rglob("package.json")):
        rel = pj.relative_to(repo)
        if SKIP_DIRS & set(rel.parts[:-1]):
            continue
        try:
            doc = json.loads(pj.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        kind = _kind(doc) if isinstance(doc, dict) else None
        if kind:
            out.append(NodeRunner(rel.parent.as_posix(), kind, log_dir or repo / ".securebuilderbot-qa"))
    return out


@dataclass
class NodeRunner:
    app: str        # repo-relative app directory
    kind: str       # jest or vitest
    log_dir: Path

    @property
    def runner(self) -> str:
        return self.kind

    def detect(self, repo: Path) -> bool:
        pj = repo / self.app / "package.json"
        try:
            return _kind(json.loads(pj.read_text(encoding="utf-8"))) == self.kind
        except (OSError, ValueError, AttributeError):
            return False

    def coverage_lcov(self, repo: Path) -> Path:
        return repo / self.app / "coverage" / "lcov.info"

    def _script_words(self, repo: Path) -> set[str]:
        try:
            doc = json.loads((repo / self.app / "package.json").read_text(encoding="utf-8"))
            return set(str(doc.get("scripts", {}).get("test", "")).split())
        except (OSError, ValueError, AttributeError):
            return set()

    def run(self, repo: Path, changed_files: Sequence[str]) -> SuiteResult:
        # A flag the package's own test script already passes is not passed again: vitest 4 refuses a
        # repeated --coverage, and the suite would never run ("Expected a single value").
        present = self._script_words(repo)
        argv = ["npm", "test", "--", *(f for f in REPORTER_FLAGS[self.kind] if f not in present)]
        log = self.log_dir / f"suite-{self.app.replace('/', '_')}.log"
        code, output, error = run_logged(argv, repo / self.app, log)
        lcov = self.coverage_lcov(repo)
        return SuiteResult(runner=self.kind, app=self.app, command=" ".join(argv), passed=code == 0 and not error,
                           counts=parse_counts(output), log=log, lcov=lcov if lcov.is_file() else None,
                           lcov_root=self.app, error=error)
