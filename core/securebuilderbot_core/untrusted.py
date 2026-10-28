"""The result of the job that ran the pull request's code, read as untrusted input (PRD § Configuration).

Scan and QA run pull request code: the scanners load its build scripts and configs, QA runs its tests.
Run apart (`core/run run --part untrusted`), they hold no secret and no write token. The job that
decides the verdict (`--part trusted`) reads their receipt.json as data from another job: capped in
size, checked field by field against the shape core writes, and never executed. What that job's code
could forge, it still can. So every status read here is marked as a claim of that job, and the controls
it would assess are listed as claimed, never as assessed.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import get_args

from .gate import Finding, GateResult, Status
from .receipt import redact

UNTRUSTED_GATES = ("scan", "qa")  # the gates that run pull request code; Sentinel reads the diff and runs none
MAX_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 2000
MAX_TEXT = 4000
ATTESTED = "the job that ran this pull request's code, which could have changed it: a claim, not re-derived here"
# The receipt keys each carried gate writes beside status, reason and findings; every other key is dropped,
# so nothing that job invents (a `line` for another gate, a key the renderer prints) reaches a check.
KNOWN = {"scan": ("line", "results", "scanners", "cve_data_max_age_days", "stale", "policy"),
         "qa": ("checks", "mutation_table", "profile_minimum_coverage", "mutation_required")}
MAX_DEPTH = 8


class UntrustedRunError(ValueError):
    """The untrusted job's receipt cannot be read as one core wrote for this range."""


def _text(value: object, field: str, limit: int = MAX_TEXT) -> str:
    """One line of redacted text: a newline would let that job's words start a heading of another gate's."""
    if not isinstance(value, str):
        raise UntrustedRunError(f"{field} is not text")
    if len(value) > limit or "\0" in value:
        raise UntrustedRunError(f"{field} is longer than {limit} characters or carries a NUL")
    return redact(" ".join(value.splitlines()))[0]


def _data(value: object, field: str, depth: int = 0) -> object:
    """A carried receipt value: JSON data at most MAX_DEPTH deep, every string one redacted line."""
    if depth > MAX_DEPTH:
        raise UntrustedRunError(f"{field} nests deeper than {MAX_DEPTH}")
    if isinstance(value, str):
        return _text(value, field)
    if isinstance(value, list):
        return [_data(v, f"{field}[{i}]", depth + 1) for i, v in enumerate(value)]
    if isinstance(value, dict):
        return {_text(k, f"{field} key", 200): _data(v, f"{field}.{k}", depth + 1) for k, v in value.items()}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise UntrustedRunError(f"{field} is not JSON data")


def _optional_text(value: object, field: str) -> str | None:
    return None if value is None else _text(value, field, 1000)


def _finding(raw: object, at: str) -> Finding:
    if not isinstance(raw, dict) or raw.get("severity") not in ("blocking", "advisory"):
        raise UntrustedRunError(f"{at} is not a finding core writes (severity blocking or advisory)")
    line = raw.get("line")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
        raise UntrustedRunError(f"{at}.line is not a line number")
    return Finding(severity=raw["severity"], rule_id=_text(raw.get("rule_id"), f"{at}.rule_id", 200),
                   message=_text(raw.get("message"), f"{at}.message"), path=_optional_text(raw.get("path"), f"{at}.path"),
                   line=line, file=_optional_text(raw.get("file"), f"{at}.file"))


def _result(name: str, raw: object) -> GateResult:
    if not isinstance(raw, dict) or raw.get("status") not in get_args(Status):
        raise UntrustedRunError(f"gates.{name} has no status core writes")
    findings = raw.get("findings", [])
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise UntrustedRunError(f"gates.{name}.findings is not a list of at most {MAX_FINDINGS}")
    claimed = raw.get("controls_assessed", [])
    if not isinstance(claimed, list) or not all(isinstance(c, str) and len(c) <= 40 for c in claimed):
        raise UntrustedRunError(f"gates.{name}.controls_assessed is not a list of control ids")
    extra = {k: _data(raw[k], f"gates.{name}.{k}") for k in KNOWN[name] if k in raw}
    return GateResult(gate=name, status=raw["status"], reason=_text(raw.get("reason", ""), f"gates.{name}.reason"),
                      findings=tuple(_finding(f, f"gates.{name}.findings[{i}]") for i, f in enumerate(findings)),
                      receipt={**extra, "controls_claimed": sorted(set(claimed)), "attested_by": ATTESTED})


def _load(run: Path, head: str, base: str) -> dict:
    path = run / "receipt.json"
    try:
        info = path.lstat()
    except OSError as e:
        raise UntrustedRunError(f"no receipt.json in {run}: {e.strerror}") from None
    if not stat.S_ISREG(info.st_mode):
        raise UntrustedRunError(f"{path} is not a regular file")
    if info.st_size > MAX_BYTES:
        raise UntrustedRunError(f"{path} is {info.st_size} bytes, over the {MAX_BYTES} a receipt may be")
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError) as e:  # a nesting deep enough to exhaust the parser included
        raise UntrustedRunError(f"{path} is not JSON: {type(e).__name__}") from None
    if not isinstance(raw, dict) or raw.get("part") != "untrusted" or not isinstance(raw.get("gates"), dict):
        raise UntrustedRunError(f"{path} is not the receipt of a `--part untrusted` run")
    if raw.get("head") != head or raw.get("base") != base:
        raise UntrustedRunError(f"{path} gated {str(raw.get('base'))[:12]}..{str(raw.get('head'))[:12]}, not {base[:12]}..{head[:12]}")
    return raw


def read_untrusted(run: Path, head: str, base: str, enabled: tuple[str, ...]) -> tuple[dict[str, GateResult], list[str]]:
    """(each enabled Scan and QA gate's result as the untrusted job reported it, warnings). A gate the
    receipt does not carry, or carries in a shape core does not write, did not run; a receipt that cannot
    be read at all is every one of them not running. Never a pass by default."""
    wanted = [g for g in UNTRUSTED_GATES if g in enabled]
    try:
        raw = _load(run, head, base)
    except UntrustedRunError as e:
        why = f"the result of the job that ran this pull request's code could not be read: {e}"
        return {g: GateResult(gate=g, status="not_run", reason=why) for g in wanted}, []
    warnings = [f"the job that ran this pull request's code reported a {shown_name(n)} result, which only this job decides; it was ignored"
                for n in raw["gates"] if n not in wanted]
    out: dict[str, GateResult] = {}
    for g in wanted:
        if g not in raw["gates"]:
            out[g] = GateResult(gate=g, status="not_run", reason="the job that ran this pull request's code reported no result for this gate")
            continue
        try:
            out[g] = _result(g, raw["gates"][g])
        except (UntrustedRunError, RecursionError) as e:
            out[g] = GateResult(gate=g, status="not_run", reason=f"the job that ran this pull request's code reported a result core does not write: {e}")
    return out, warnings


def shown_name(name: object) -> str:
    text = str(name)
    return repr(text[:40]) if not text.isidentifier() or len(text) > 40 else text
