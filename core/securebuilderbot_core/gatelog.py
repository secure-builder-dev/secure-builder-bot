"""One row per run in gate-records/gate-log.md. A tracker, never a blocker.

The row travels with the code, so the history of every gate survives a platform migration. A log
that cannot be written produces a warning and nothing else: a record that can refuse the thing it
records is a record that has to be worked around.
"""

from __future__ import annotations

from pathlib import Path

HEADER = ("| Date | Epic | Range | Run | Findings | Retro tickets | Verdict | Reviewer |\n"
          "|------|------|-------|-----|----------|---------------|---------|----------|\n")
OLD_HEADER_START = "| Date | Story | Quality |"


def epic_column(branch: str) -> str:
    return branch[len("epic/"):] if branch.startswith("epic/") else f"{branch} (branch `{branch}`)"


def append_row(log: Path, *, date: str, branch: str, base: str, head: str, run_id: str,
               findings: str, verdict: str, reviewer: str = "securebuilderbot core") -> str | None:
    """Append the row. Returns a warning string instead of raising, whatever goes wrong."""
    row = f"| {date} | {epic_column(branch)} | `{base[:7]}..{head[:7]}` | {run_id} | {findings} | — | {verdict} | {reviewer} |\n"
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        text = log.read_text() if log.is_file() else ""
        data_rows = [line for line in text.splitlines()[2:] if line.startswith("| ")]
        if not text.strip() or (text.startswith(OLD_HEADER_START) and not data_rows):
            text = HEADER  # a missing log, or the empty template from before this format: start the new one
        if not text.endswith("\n"):
            text += "\n"
        log.write_text(text + row)
    except OSError as e:
        return f"gate log not written ({e.strerror or e}); the run's verdict is unaffected"
    return None
