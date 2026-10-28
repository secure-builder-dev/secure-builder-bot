"""The runner: order, stop on the first red, and the three outputs (SPEC-core.md § Runner).

1. Load the config, resolve the profile, classify the range (merge base to head).
2. Create gate-records/runs/<utc-timestamp>-<head-short-sha>/.
3. Prepare every enabled gate, then run each in the fixed order scan → qa → sentinel. Stop at the
   first fail or not_run: every later gate is recorded not_run, never silently absent. A gate's
   optional prepare(ctx) is called before ANY gate runs, so a gate can read the checkout and .git
   before QA runs the pull request's own code in them (sentinel gate run 2, B-01); a prepare that
   raises is that gate not running, reported at its turn.
4. Write receipt.json, receipt.md, verdict.json, and one gate-log row.

A run can be one part of two (PRD § Configuration): `untrusted` runs Scan and QA, the gates that run pull
request code, in a job that holds no secret and no write token; `trusted` runs Sentinel and decides the
verdict in another job, carrying the untrusted part's results in as claims read by untrusted.py.
Exit 0 when every gate that ran passed or was yellow; 1 on any fail or not_run; 2 when the run could
not start or its receipt could not be written. Exit 2 is never clean.
"""

from __future__ import annotations

import datetime
import json
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import get_args

from .classify import classify
from .config import GATES, Config, Governing
from .gate import Gate, GateContext, GateResult, Status, not_built
from .gatelog import append_row
from .receipt import SCHEMA, ReceiptError, atomic_write, redact, shown, write_receipt
from .untrusted import UNTRUSTED_GATES, read_untrusted
from .verdict import overall, verdict_block, verdict_json


class RunError(RuntimeError):
    """The run could not start: not a repository, a ref that does not resolve, no merge base."""


@dataclass
class RunOutcome:
    exit_code: int
    run_dir: Path | None
    results: list[GateResult]
    lines: list[str]
    warnings: list[str] = field(default_factory=list)


# Each gate is its own module (CAPABILITY-MAP.md), found by name: the package exposes GATE, a
# callable returning a Gate. Core never imports a module's code at import time, so the map's
# dependency direction holds: a gate module depends on core, and core knows only the name to look up.
GATE_MODULES = {"scan": "securebuilderbot_scanners", "qa": "securebuilderbot_qa", "sentinel": "securebuilderbot_sentinel"}


def discover_gate(name: str) -> Callable[[], Gate] | None:
    """The gate module's GATE factory, or None when the module is not installed."""
    import importlib
    try:
        module = importlib.import_module(GATE_MODULES[name])
    except ImportError:
        return None
    factory = getattr(module, "GATE", None)
    return factory if callable(factory) else None


def default_factory(name: str) -> Callable[[], Gate]:
    """The installed gate module's factory; a module that is not installed reports not_run, never a pass.

    Called inside the per-gate guard in run(), so a module that raises or exits while it is imported
    is that one gate not running, reported and redacted, never a run that stops or passes silently.
    """
    found = discover_gate(name)
    return found if found is not None else (lambda n=name: not_built(n))


def default_gates() -> dict[str, Callable[[], Gate]]:
    """Every gate's factory, resolved now. run() resolves each one lazily, inside its guard, instead."""
    return {name: default_factory(name) for name in GATE_MODULES}


def standards_versions() -> dict | None:
    """The versions of the vendored standards, for the receipt: the one guarded import of the standards module.

    Core knows the module by name only, like a gate module. When it is not installed the receipt says
    so with None rather than omitting the key, so an assessor can see the difference between "not
    recorded" and "not available".
    """
    try:
        from securebuilderbot_standards import versions
    except ImportError:
        return None
    return versions()


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RunError(f"git {' '.join(args)}: {out.stderr.strip() or 'failed'}")
    return out.stdout.strip()


def _findings_summary(results: list[GateResult]) -> str:
    blocking = sum(1 for r in results for f in r.findings if f.severity == "blocking")
    advisory = sum(1 for r in results for f in r.findings if f.severity == "advisory")
    return f"{blocking} blocking, {advisory} advisory"


def _redacted(result: GateResult) -> tuple[GateResult, int]:
    """The result with its reason and every finding's text redacted; the one place output text is cleaned."""
    reason, n = redact(result.reason)
    findings = []
    for f in result.findings:
        message, m = redact(f.message)
        rule_id, k = redact(f.rule_id)
        findings.append(replace(f, message=message, rule_id=rule_id))
        n += m + k
    return replace(result, reason=reason, findings=tuple(findings)), n


def _checked(name: str, result: object) -> GateResult:
    """The gate's result, or not_run naming what was wrong with it: never a pass by accident.

    A status outside the declared ones read as a pass; a run() returning None crashed the runner
    outside its guard; a result naming another gate replaced that gate's receipt entry.
    """
    if not isinstance(result, GateResult):
        return GateResult(gate=name, status="not_run", reason=f"the gate returned {type(result).__name__}, not a GateResult")
    if result.status not in get_args(Status):
        return GateResult(gate=name, status="not_run", reason=f"the gate returned an undeclared status {shown(result.status)}")
    if result.gate != name:
        return GateResult(gate=name, status="not_run", reason=f"the {name} gate's result names the gate {shown(result.gate)}")
    return result


def run(config: Config, repo: Path, base: str, head: str = "HEAD",
        gates: Mapping[str, Callable[[], Gate]] | None = None,
        now: datetime.datetime | None = None, governing: Governing | None = None,
        part: str = "", untrusted_run: Path | None = None) -> RunOutcome:
    repo = Path(_git(repo, "rev-parse", "--show-toplevel"))
    head_sha = _git(repo, "rev-parse", "--verify", f"{head}^{{commit}}")
    base_sha = _git(repo, "rev-parse", "--verify", f"{base}^{{commit}}")
    config_ref = governing.ref if governing and governing.ref else base_sha
    merge_base = _git(repo, "merge-base", base, head_sha)
    branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    depth = {"always-deep": "deep", "always-light": "light"}.get(config.sentinel.depth) \
        or classify(merge_base, head_sha, repo).depth
    started = now or datetime.datetime.now(datetime.timezone.utc)
    run_id = f"{started:%Y%m%dT%H%M%SZ}-{head_sha[:7]}"
    run_dir = repo / "gate-records" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    factories = None if gates is None else dict(gates)
    if part not in ("", "untrusted", "trusted") or (part == "trusted") != (untrusted_run is not None):
        raise RunError("a run is whole, --part untrusted, or --part trusted with the untrusted part's run directory")
    carried: dict[str, GateResult] = {}
    carried_warnings: list[str] = []
    if part == "trusted":
        carried, carried_warnings = read_untrusted(untrusted_run, head_sha, merge_base, config.gates)
    here = tuple(g for g in GATES if g in config.gates and g not in carried
                 and (part != "untrusted" or g in UNTRUSTED_GATES))

    # Every enabled gate is built and prepared before the first one runs; each keeps the context it was
    # prepared with. A factory or prepare that raises or exits is that gate's not_run, held for its turn.
    prepared: dict[str, tuple[GateContext, Gate | GateResult]] = {}
    for name in here:
        ctx = GateContext(repo=repo, base=merge_base, head=head_sha, profile=config.profile, depth=depth,
                          run_dir=run_dir / name, skip=config.scan.skip if name == "scan" else (), config=config,
                          config_ref=config_ref)
        ctx.run_dir.mkdir(parents=True, exist_ok=True)
        try:
            gate = (default_factory(name) if factories is None else factories[name])()
            prepare = getattr(gate, "prepare", None)
            if callable(prepare):
                prepare(ctx)
            prepared[name] = (ctx, gate)
        except KeyboardInterrupt:
            raise
        except BaseException as e:  # as in run() below: never a pass, never a stopped run
            prepared[name] = (ctx, GateResult(gate=name, status="not_run", reason=f"the gate crashed: {type(e).__name__}: {e}"))

    results: list[GateResult] = []
    redactions = 0
    stopped = False
    for name in (g for g in GATES if g in prepared or g in carried):
        if stopped:
            results.append(GateResult(gate=name, status="not_run", reason="an earlier gate did not pass; this gate did not run"))
            continue
        if name in carried:  # already validated and capped; redacted below like any gate's own output
            result, n = _redacted(carried[name])
            redactions += n
            results.append(result)
            stopped = result.status in ("fail", "not_run")
            continue
        ctx, gate = prepared[name]
        try:
            result = gate if isinstance(gate, GateResult) else _checked(name, gate.run(ctx))
        except KeyboardInterrupt:
            raise
        except BaseException as e:  # a crashed or exiting gate did not run, never a pass (SystemExit included)
            result = GateResult(gate=name, status="not_run", reason=f"the gate crashed: {type(e).__name__}: {e}")
        result, n = _redacted(result)
        redactions += n
        results.append(result)
        stopped = result.status in ("fail", "not_run")

    exit_code = 1 if any(r.status in ("fail", "not_run") for r in results) else 0
    # A carried gate's controls are its job's claim (controls_claimed), never counted as assessed here.
    assessed = {c for r in results for c in r.receipt.get("controls_assessed", [])}
    claimed = {c for r in results for c in r.receipt.get("controls_claimed", [])}
    finished = datetime.datetime.now(datetime.timezone.utc)
    receipt = {
        "schema": SCHEMA, "run_id": run_id, "part": part or "whole",
        "started": started.isoformat(timespec="seconds"), "finished": finished.isoformat(timespec="seconds"),
        "base": merge_base, "head": head_sha, "branch": branch, "depth": depth,
        "profile": {"name": config.profile.name, "title": config.profile.title, "baseline": config.profile.baseline,
                    "catalog_version": config.profile.catalog_version, "controls": len(config.profile.controls)},
        "config": {"path": str(config.path), "sha256": config.sha256, "gates": list(config.gates), "version": config.version,
                   "source": governing.source if governing else "given", "changed_by_pr": list(governing.changed) if governing else [],
                   "ref": config_ref, "workflow_changed": list(governing.workflow_changed) if governing else []},
        "relaxations": list(config.relaxations),
        "standards": standards_versions(),
        "sent_to_model_endpoint": sorted({f for r in results for f in r.receipt.get("sent_to_model_endpoint", [])}),
        "gates": {r.gate: {"status": r.status, "reason": r.reason,
                           "findings": [f.__dict__ for f in r.findings],
                           **{k: v for k, v in r.receipt.items() if k != "sent_to_model_endpoint"}} for r in results},
        "controls_assessed": sorted(assessed & config.profile.controls),
        "controls_not_assessed": sorted(config.profile.controls - assessed),
        **({"controls_claimed": sorted((claimed - assessed) & config.profile.controls)} if part == "trusted" else {}),
        "overall": overall(results, config.relaxations),
    }
    lines = verdict_block(results, config.relaxations)
    warnings: list[str] = list(carried_warnings)
    if governing and governing.workflow_changed:
        warnings.append(f"config: this pull request changes the CI workflow ({', '.join(governing.workflow_changed)}); the workflow "
                        "decides what runs, so require it from outside the pull request (a GitHub ruleset, a GitLab pipeline execution policy)")
    if governing and governing.changed:
        warnings.append(f"config: this pull request changes {', '.join(governing.changed)}; "
                        "the base branch's settings apply until it is merged")
    elif governing and governing.source == "pull request":
        warnings.append("config: no config on the base branch, so this pull request's own is used; "
                        "from the next pull request on, the merged copy governs")
    if redactions:
        warnings.append(f"{redactions} secret-shaped string(s) in gate output were redacted before anything was written")
    try:
        write_receipt(run_dir, receipt)
    except ReceiptError as e:
        exit_code = 2
        lines.append(f"Receipt: REFUSED — {e}")
    atomic_write(run_dir / "verdict.json", json.dumps(verdict_json(results, config.relaxations, exit_code), indent=1) + "\n")
    verdict = " · ".join(f"{r.gate.capitalize() if r.gate != 'qa' else 'QA'} {r.status.upper().replace('_', ' ')}" for r in results)
    warning = append_row(repo / "gate-records" / "gate-log.md", date=started.date().isoformat(), branch=branch,
                         base=merge_base, head=head_sha, run_id=run_id, findings=_findings_summary(results),
                         verdict=f"{verdict} · Overall {receipt['overall'].upper()}")
    if warning:
        warnings.append(warning)
    return RunOutcome(exit_code=exit_code, run_dir=run_dir, results=results, lines=lines, warnings=warnings)
