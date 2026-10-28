"""Check 5, the control manifest: the gate wraps qa/scripts/derive-controls.sh, verify-controls.sh and
mutate-controls.sh and reads their output; the scripts' own semantics do not change.

- derive-controls: a guard-shaped function with no manifest row is a blocking finding ("the bot
  refuses to run QA if a new control-shaped function appears with no row", PRD § The control
  manifest), and the draft it writes is the receipt's evidence for the rows a human should confirm.
- verify-controls: a FAIL row (symbol gone, no production call site, proving test missing) blocks.
- mutate-controls: every NOT PROVEN, manual or unlocatable row blocks; the table is the receipt's
  mutation table (PRD § What the user sees: control id, test file, red or green).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .adapters import keep_log, user_env

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
MANIFEST = "docs/security/CONTROL-MANIFEST.md"  # the one path the control tools read
# One tool run's ceiling. mutate-controls runs the suite once per row, and a pull request that edits the
# control list re-proves every row; each run inside it has its own cap (MUTATE_TARGET_TIMEOUT for a row's
# own test, MUTATE_SUITE_TIMEOUT for the full suite), so this only bounds the whole, under the six hours a
# hosted job may take. At one hour this repository's own list (about ninety rows) no longer fit.
TIMEOUT_SECONDS = 4 * 3600
UNREGISTERED = re.compile(r"^\s*UNREGISTERED\s+(\S+?):(\d+)\s+(\S+)\s+\[(\w+)\]", re.M)
VERIFY_FAIL = re.compile(r"^\s*FAIL\s+(CM-\d+)\s+(.*?)\n\s+(.*)$", re.M)
MUTATION_ROW = re.compile(r"^\| (CM-\d+) \| (.*?) \| (.*?) \| (.*?) \| (.*?) \|$", re.M)
NOT_PROVEN = re.compile(r"NOT PROVEN|manual|unlocatable", re.I)


@dataclass(frozen=True)
class ToolRun:
    tool: str
    code: int
    output: str
    log: Path


@dataclass(frozen=True)
class Guard:
    path: str
    line: int
    symbol: str
    kind: str


@dataclass(frozen=True)
class MutationRow:
    id: str
    control: str
    mutation: str
    suite: str
    verdict: str


def row_ids(text: str) -> list[str]:
    """The control ids a manifest's text declares, in order: only rows the tools act on, so none for an empty
    text, a header-only table, or rows whose implementation cell is empty, `-` or a `<placeholder>`."""
    ids = []
    for line in text.splitlines():
        m = re.match(r"\| (CM-\d+) ", line)
        cells = line.split("|")
        impl = cells[3].replace("`", "").strip() if m and len(cells) > 3 else ""
        if m and impl not in ("", "-") and not impl.startswith("<"):
            ids.append(m.group(1))
    return ids


def rows_in(text: str) -> int:
    """How many control rows a manifest's text declares: 0 for none, a header-only table, or only placeholders."""
    return len(row_ids(text))




def run_tool(repo: Path, run_dir: Path, tool: str, *args: str, manifest: Path | None = None) -> ToolRun:
    """Run one of the control scripts from the repository root; its output is an evidence file in the run directory.

    mutate-controls runs the user's suite once per row, so the scripts get user_env(), never the bot's secrets,
    and what they print is kept redacted.
    """
    log = run_dir / f"{tool}.log"
    env = user_env()
    env.pop("CONTROL_MANIFEST", None)  # only the gate points a tool at another list, never the environment
    if manifest is not None:
        env["CONTROL_MANIFEST"] = str(manifest)
    try:
        proc = subprocess.run(["bash", str(SCRIPTS / f"{tool}.sh"), *args], cwd=repo, capture_output=True, text=True,
                              timeout=TIMEOUT_SECONDS, env=env)
        output, code = proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as e:
        output, code = f"{e.stdout or ''}{e.stderr or ''}\n{tool} timed out after {TIMEOUT_SECONDS}s\n", 124
    return ToolRun(tool, code, keep_log(log, output), log)


def unregistered_guards(output: str) -> list[Guard]:
    """The guard sites derive-controls lists as UNREGISTERED: a control-shaped function with no manifest row and no written reason."""
    return [Guard(p, int(n), sym, kind) for p, n, sym, kind in UNREGISTERED.findall(output)]


def failed_rows(output: str) -> list[tuple[str, str, str]]:
    """(id, control, problems) for every row verify-controls marked FAIL."""
    return [(i, name.strip(), why.strip()) for i, name, why in VERIFY_FAIL.findall(output)]


def parse_mutation_table(output: str) -> list[MutationRow]:
    """The rows of mutate-controls' table, in order; an unchanged row under --since is carried with its own verdict."""
    return [MutationRow(*[c.strip() for c in row]) for row in MUTATION_ROW.findall(output)]


def unproven_rows(rows: list[MutationRow]) -> list[MutationRow]:
    """Every row the suite did not go red for: NOT PROVEN, manual, or unlocatable. Each is a blocking finding."""
    return [r for r in rows if NOT_PROVEN.search(r.verdict)]
