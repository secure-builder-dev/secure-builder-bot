#!/usr/bin/env python3
"""coverage-changed.py — the lines a change adds to a module's Python must be covered.

CONSTRAINTS.md holds changed-line coverage at or above a minimum. Project-wide coverage is an
inherited number; the lines a change adds are the number an agent can move. This reads the lcov
file `make test` already wrote (no second test run) and intersects it with the added lines.

The logic is the qa module's (qa/securebuilderbot_qa/coverage_changed.py and diff.py), which the
QA gate runs on every pull request; this script is the same measure for the working tree before a
commit: tracked changes and untracked files, test files excluded.

Usage:  scripts/coverage-changed.py [--lcov PATH] [--base REF] [--min N] [--include PREFIX]...
Exit:   0 at or above the minimum, or nothing executable added
        1 below the minimum (the uncovered lines are listed)
        2 could not run: no lcov file, no merge base, no qa package. Never read as a pass.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "qa"))
try:
    from securebuilderbot_qa.coverage_changed import changed_line_coverage, is_test_path, lcov_lines, meets, summary
    from securebuilderbot_qa.diff import added_lines
except ImportError as e:  # the package is the measure; without it nothing is measured
    print(f"coverage-changed: the qa package is not importable from {ROOT / 'qa'} ({e})")
    sys.exit(2)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def default_base() -> str | None:
    for ref in ("origin/main", "main"):
        if subprocess.run(["git", "rev-parse", "--verify", "-q", ref], capture_output=True).returncode == 0:
            return ref
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lcov", default="gate-records/state/core.lcov")
    ap.add_argument("--base", default=None)
    ap.add_argument("--min", type=float, default=80.0)
    ap.add_argument("--include", action="append", default=None)
    args = ap.parse_args(argv)
    # Every module is measured: a package <module>/securebuilderbot_<module>/ with its tests beside it
    # (the convention in SPEC-core.md); a new module adds nothing here.
    modules = {p.parent for p in Path(".").glob("*/securebuilderbot_*/") if (p.parent / "tests").is_dir()}
    includes = args.include or sorted(f"{m.name}/" for m in modules) or ["core/"]

    root = Path(git("rev-parse", "--show-toplevel").strip())
    lcov = root / args.lcov
    base = args.base or default_base()
    if base is None:
        print("coverage-changed: no origin/main or main to diff against")
        return 2
    try:
        merge_base = git("merge-base", base, "HEAD").strip()
    except subprocess.CalledProcessError:
        print(f"coverage-changed: no merge base against {base}")
        return 2
    added = {f: set(lines) for f, lines in added_lines(root, merge_base, None).items()
             if f.endswith(".py") and any(f.startswith(i) for i in includes) and not is_test_path(f)}
    if not added:
        print("coverage-changed: no Python added under " + ", ".join(includes) + " — nothing to measure")
        return 0
    if not lcov.is_file():
        print(f"coverage-changed: no coverage file at {args.lcov} — run `make test` first")
        return 2

    report = changed_line_coverage(added, lcov_lines(lcov, root))
    print(f"coverage-changed: {summary(report, args.min)}")
    if not meets(report, args.min):
        for m in report.missed[:40]:
            print(f"  uncovered  {m}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
