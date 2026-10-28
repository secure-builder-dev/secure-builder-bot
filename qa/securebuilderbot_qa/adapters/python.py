"""Python: pytest with pytest-cov's lcov reporter, detected from pytest.ini, pyproject.toml, conftest.py or tests/."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from . import SuiteResult, parse_counts, run_logged

MARKERS = ("pytest.ini", "pyproject.toml", "conftest.py", "tests")


@dataclass
class PytestRunner:
    log_dir: Path
    runner: str = "pytest"
    app: str = "."

    def detect(self, repo: Path) -> bool:
        return any((repo / m).exists() for m in MARKERS)

    def coverage_lcov(self, repo: Path) -> Path:
        return self.log_dir / "pytest.lcov"

    def run(self, repo: Path, changed_files: Sequence[str]) -> SuiteResult:
        lcov = self.coverage_lcov(repo)
        lcov.parent.mkdir(parents=True, exist_ok=True)
        # No -q of our own: a project whose ini already says -q would then print no summary line at all.
        argv = ["python3", "-m", "pytest", "-p", "no:cacheprovider", "--cov=.", f"--cov-report=lcov:{lcov}"]
        log = self.log_dir / "suite-pytest.log"
        code, output, error = run_logged(argv, repo, log)
        if not error and "unrecognized arguments: --cov" in output:
            error = "pytest-cov is not installed, so coverage cannot be measured (pip install pytest-cov)"
        elif not error and code == 5:
            error = "pytest collected no tests"
        return SuiteResult(runner=self.runner, app=self.app, command=" ".join(argv), passed=code == 0 and not error,
                           counts=parse_counts(output), log=log, lcov=lcov if lcov.is_file() else None,
                           lcov_root=".", error=error)
