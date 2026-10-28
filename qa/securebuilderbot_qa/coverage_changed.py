"""Coverage on changed lines (PRD § The QA gate, check 2): the lines a range adds to production code,
against the lcov every adapter wrote. The pre-commit changed-line coverage script imports this.

Only lines lcov reports as executable count, so blank lines, comments and docstrings never pull the
number down. Test files are the measure, not the measured, and are left out. A production file the
range added that no lcov mentions was never imported by a test: every added line in it counts as
uncovered, because "not measured" must never read as "covered".
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

PRODUCTION_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
# Tool configuration, exactly the files vitest's coverage leaves out by default
# (`**/{karma,rollup,webpack,vite,vitest,jest,ava,babel,nyc,cypress,tsup,build,eslint,prettier}.config.*`):
# no test imports them. Only these basenames; `app.config.ts` holding real logic is still measured.
TOOL_CONFIG = re.compile(r"(^|/)(karma|rollup|webpack|vite|vitest|jest|ava|babel|nyc|cypress|tsup|build|eslint|prettier)\.config\.[^/]+$")
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|__mocks__|spec)/|\.(test|spec)\.[cm]?[jt]sx?$|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$")


@dataclass(frozen=True)
class CoverageReport:
    covered: int
    executable: int
    missed: tuple[str, ...]  # "file:line", or "file: not in the coverage report (…)"

    @property
    def pct(self) -> float:
        return 100.0 * self.covered / self.executable if self.executable else 100.0


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(path))


def production_files(files: Iterable[str]) -> list[str]:
    """The files coverage is measured on: source in a language an adapter measures, never a test or a tool's config file."""
    return [f for f in files if f.endswith(PRODUCTION_EXTS) and not is_test_path(f) and not TOOL_CONFIG.search(f)]


def lcov_lines(path: Path, root: Path, prefix: str = ".") -> dict[str, dict[int, int]]:
    """{repo-relative file: {line: hits}} for every executable line an lcov file reports.

    SF: paths are relative to the app the runner ran in (`prefix`), or absolute; both become
    paths relative to the repository root, so every adapter's report merges into one map.
    """
    data: dict[str, dict[int, int]] = {}
    current: dict[int, int] | None = None
    for raw in path.read_text(errors="replace").splitlines():
        if raw.startswith("SF:"):
            sf = Path(raw[3:])
            if sf.is_absolute():
                try:
                    rel = sf.resolve().relative_to(root.resolve()).as_posix()
                except ValueError:
                    rel = sf.as_posix()
            else:
                rel = (Path(prefix) / sf).as_posix() if prefix not in ("", ".") else sf.as_posix()
            current = data.setdefault(rel, {})
        elif raw.startswith("DA:") and current is not None:
            line, hits = raw[3:].split(",")[:2]
            current[int(line)] = max(current.get(int(line), 0), int(hits))
        elif raw == "end_of_record":
            current = None
    return data


def merge_hits(reports: Iterable[Mapping[str, Mapping[int, int]]]) -> dict[str, dict[int, int]]:
    out: dict[str, dict[int, int]] = {}
    for r in reports:
        for f, lines in r.items():
            mine = out.setdefault(f, {})
            for n, h in lines.items():
                mine[n] = max(mine.get(n, 0), h)
    return out


def changed_line_coverage(added: Mapping[str, Iterable[int]], hits: Mapping[str, Mapping[int, int]]) -> CoverageReport:
    covered = executable = 0
    missed: list[str] = []
    for f, lines in sorted(added.items()):
        known = hits.get(f, {})
        lines = set(lines)
        if not known:
            executable += len(lines)
            missed.append(f"{f}: not in the coverage report (never imported by a test)")
            continue
        for n in sorted(lines & set(known)):
            executable += 1
            if known[n] > 0:
                covered += 1
            else:
                missed.append(f"{f}:{n}")
    return CoverageReport(covered=covered, executable=executable, missed=tuple(missed))


def meets(report: CoverageReport, minimum: float) -> bool:
    """The profile's threshold, held on the added executable lines; nothing executable added is nothing to hold."""
    return report.executable == 0 or report.pct >= minimum


def summary(report: CoverageReport, minimum: float) -> str:
    if report.executable == 0:
        return "no executable lines added — nothing to measure"
    verdict = "ok" if meets(report, minimum) else "BELOW"
    return f"{report.covered}/{report.executable} added executable lines covered ({report.pct:.1f}%, minimum {minimum:g}%) {verdict}"
