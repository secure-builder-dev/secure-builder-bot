"""The Gate protocol: the one interface every gate module implements (SPEC-core.md § Interface).

scanners, qa and sentinel implement `Gate` and see nothing else of core's internals. A gate gets a
`GateContext` and returns a `GateResult`; the runner decides order, stopping and what is written.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

from .profiles import Profile

if TYPE_CHECKING:
    from .config import Config

GateName = Literal["scan", "qa", "sentinel"]
Status = Literal["pass", "fail", "yellow", "not_run"]


@dataclass(frozen=True)
class GateContext:
    repo: Path        # checkout root
    base: str         # git ref
    head: str         # git ref
    profile: Profile  # resolved thresholds, never the raw config
    depth: Literal["light", "deep"]
    run_dir: Path     # where this gate writes its files
    skip: tuple[str, ...] = ()  # parts of this gate the config turned off (scanner names for scan)
    config: Config | None = None  # the config that governs the run (the base branch's): read it, not the checkout's file
    config_ref: str = ""          # the commit the config and every excusing list are read from (the target branch's tip, not `base`)


@dataclass(frozen=True)
class Finding:
    severity: Literal["blocking", "advisory"]
    rule_id: str          # control, STIG rule, CVE or scanner rule id
    message: str          # one sentence, what would fix it
    path: str | None = None
    line: int | None = None
    file: str | None = None  # evidence file under run_dir, if any


@dataclass(frozen=True)
class GateResult:
    gate: GateName
    status: Status
    reason: str = ""      # the one line that says why, when status is not pass
    findings: tuple[Finding, ...] = ()
    receipt: dict = field(default_factory=dict)  # this gate's section of the receipt


class Gate(Protocol):
    """A gate may also define prepare(ctx) -> None. The runner calls it for every enabled gate before
    any gate runs, with the context it later passes to run(): where a gate reads what it needs while
    the checkout is still as the CI left it, before QA runs the pull request's code there."""

    name: GateName

    def run(self, ctx: GateContext) -> GateResult: ...


def not_built(name: GateName) -> Gate:
    """A gate whose module does not exist yet. Enabling it is honest: it reports not_run, never a pass."""

    class _NotBuilt:
        def __init__(self) -> None:
            self.name = name

        def run(self, ctx: GateContext) -> GateResult:
            return GateResult(gate=name, status="not_run",
                              reason=f"the {name} module is not built yet — remove {name} from gates or wait for its release")

    return _NotBuilt()
