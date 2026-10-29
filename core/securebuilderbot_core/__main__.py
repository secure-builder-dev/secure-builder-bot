"""The core command line. Every subcommand prints to stdout and exits 0 ok, 1 refused, 2 could not run."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from pathlib import Path

from .classify import LIGHT_WHY, ClassifyError, classify
from .config import ConfigError, Governing, governing_config, load_config
from .profiles import ProfileError, load_profile, render
from .verdict import results_dir, scan_verdict, write_stamp


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="core/run", description=__doc__)
    parser.add_argument("--version", action="version", version=f"securebuilderbot-core {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")
    profile = sub.add_parser("profile", help="show what a compliance profile checks")
    profile_sub = profile.add_subparsers(dest="action", required=True)
    show = profile_sub.add_parser("show", help="print a profile's rows")
    show.add_argument("name", help="none, il4 or il6")
    config = sub.add_parser("config", help="validate .securebuilderbot.yml")
    config_sub = config.add_subparsers(dest="action", required=True)
    check = config_sub.add_parser("check", help="validate the config and print what it resolves to")
    check.add_argument("--config", default=".securebuilderbot.yml")
    cls = sub.add_parser("classify", help="deep or light, by the paths a range touches")
    cls.add_argument("range", nargs="?", help="<base>..<head>")
    cls.add_argument("--base")
    cls.add_argument("--head", default="HEAD")
    cls.add_argument("--why", action="store_true", help="one line per reason (max 12)")
    sv = sub.add_parser("scan-verdict", help="the scan's one line, from the last results")
    sv.add_argument("--results", help="results directory (default: $SCAN_RESULTS_DIR or gate-records/scan/latest)")
    sv.add_argument("--stamp", action="store_true", help="record this commit as scanned (only after a real scan; also GATE_LINE_STAMP=1)")
    pc = sub.add_parser("scan-precondition", help="refuse a gate handoff unless this tree was scanned green")
    pc.add_argument("--results", help="results directory (default: $SCAN_RESULTS_DIR or gate-records/scan/latest)")
    r = sub.add_parser("run", help="run the enabled gates on a range and write the receipt, verdict and gate-log row")
    r.add_argument("--base", default="origin/main")
    r.add_argument("--head", default="HEAD")
    r.add_argument("--config", default=".securebuilderbot.yml")
    r.add_argument("--config-ref", help="the commit the config and the excusing lists are read from (default: --base itself, "
                                        "the target branch's tip; never the merge base, which the pull request chooses)")
    r.add_argument("--part", choices=("untrusted", "trusted"),
                   help="untrusted: only Scan and QA, the gates that run pull request code, in a job with no secret and no write "
                        "token; trusted: Sentinel and the verdict, in another job, reading the untrusted part's run as a claim")
    r.add_argument("--untrusted-run", help="with --part trusted: the untrusted part's run directory, as downloaded from its job")
    return parser


def cmd_scan_precondition(args: argparse.Namespace) -> int:
    import os
    from .precondition import check
    repo = _toplevel()
    ok, message = check(repo, results_dir(repo, args.results), skip_check=os.environ.get("SKIP_SCAN_CHECK") == "1")
    if message:
        print(message, file=sys.stderr)
    return 0 if ok else 1


def _misnamed(path: Path) -> str:
    """The hint for a config file that is not there: the same name spelled .yaml or .yml is the usual slip."""
    twin = path.with_suffix({".yml": ".yaml", ".yaml": ".yml"}.get(path.suffix, path.suffix))
    return f"; found {twin} beside it: rename it to {path.name}" if twin != path and twin.is_file() else ""


def cmd_run(args: argparse.Namespace) -> int:
    from .classify import ClassifyError
    from .runner import RunError, run
    path = Path(args.config)
    if not path.is_file():
        print(f"run: no config file at {path}{_misnamed(path)} — write one (core/run config check validates it)")
        return 2
    try:
        head = load_config(path)
        # The base's copy governs: a pull request cannot loosen its own gate (docs/PRD.md § Configuration).
        governing = _governing(head, args)
        outcome = run(governing.config, Path.cwd(), args.base, args.head, governing=governing, part=args.part or "",
                      untrusted_run=Path(args.untrusted_run) if args.untrusted_run else None)
    except (ConfigError, RunError, ClassifyError) as e:
        print(f"run: could not start — {e}")
        return 2
    for line in outcome.lines:
        print(line)
    if outcome.run_dir is not None:
        print(f"Receipt: {outcome.run_dir.relative_to(_toplevel())}/receipt.md")
    for w in outcome.warnings:
        print(f"warning: {w}")
    return outcome.exit_code


WORKFLOW_PATHS = (".github/workflows", ".github/actions", ".gitlab-ci.yml", ".gitlab")  # what decides what runs the bot


def _git_out(*args: str) -> str:
    import subprocess

    from .runner import RunError
    out = subprocess.run(["git", "--no-replace-objects", *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RunError(f"git {' '.join(args)}: {out.stderr.strip() or 'failed'}")
    return out.stdout.strip()


def _governing(head, args: argparse.Namespace):
    """The config the run obeys, read from the target branch's tip (`--config-ref`, default `--base`).

    Never the merge base: the pull request chooses that, by branching from a commit before the config
    was adopted or tightened. A base that is the head itself holds the run to nothing, so the head's
    config is used and the run carries a relaxation; a range that edits the CI workflow is reported."""
    import dataclasses
    ref = _git_out("rev-parse", "--verify", f"{args.config_ref or args.base}^{{commit}}")
    head_sha = _git_out("rev-parse", "--verify", f"{args.head}^{{commit}}")
    top = Path(_toplevel())
    if ref == head_sha:
        relaxed = dataclasses.replace(head, relaxations=(*head.relaxations, "the base is the head commit itself: "
                                                         "no other branch's rules hold this run"))
        governing = Governing(config=relaxed, source="head", changed=(), ref=ref)
    else:
        governing = governing_config(head, top, ref)
    merge_base = _git_out("merge-base", args.base, args.head)
    touched = tuple(t for t in _git_out("diff", "--name-only", "--no-renames", merge_base, head_sha, "--", *WORKFLOW_PATHS).splitlines() if t)
    if touched:  # a relaxation, so it shows on the run and on every check, never as a clean pass
        note = f"this pull request changes the CI workflow ({', '.join(touched)}), which decides what runs the bot"
        governing = dataclasses.replace(governing, config=dataclasses.replace(
            governing.config, relaxations=(*governing.config.relaxations, note)))
    return dataclasses.replace(governing, workflow_changed=touched)


def _toplevel() -> Path:
    import subprocess
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    return Path(out.stdout.strip()) if out.returncode == 0 else Path.cwd()


def _stale_at_stamp(repo: Path, results: Path) -> dict[str, str]:
    """The CVE databases this repository's own profile would call stale. Empty with no config.

    The age check is the scanners module's (securebuilderbot_scanners.gate), found by name the way
    the runner finds the gate itself; without that module nothing can judge age, and a scan whose
    CVE-data age cannot be judged is stamped FAIL (never a pass).
    """
    import datetime
    import importlib
    config = repo / ".securebuilderbot.yml"
    if not config.is_file():
        return {}
    limit = load_config(config).profile.scan.cve_data_max_age_days
    if limit is None:
        return {}
    try:
        scanners = importlib.import_module("securebuilderbot_scanners.gate")
    except ImportError:
        return {"scanners": "the scanners module is not installed, so the CVE data's age cannot be judged"}
    return scanners.stale_databases(results, scanners.ran_scanners(results), limit, datetime.datetime.now(datetime.timezone.utc))


def cmd_scan_verdict(args: argparse.Namespace) -> int:
    import os
    repo = _toplevel()
    results = results_dir(repo, args.results)
    v = scan_verdict(results)
    verdict, line = v.verdict, v.line
    stamping = (args.stamp or os.environ.get("GATE_LINE_STAMP") == "1") and v.verdict != "NOT RUN"
    if stamping:
        # The stamp is what the gate-handoff precondition trusts, so it holds the scan to the same
        # CVE-data age limit the Scan gate does (gate finding N-04). A read never judges age: it
        # repeats what the scanners found.
        try:
            stale = _stale_at_stamp(repo, results)
        except ConfigError as e:
            print(f"scan-verdict: not stamped — the config the age limit comes from is invalid: {e}")
            return 2
        if stale:
            verdict = "FAIL"
            line = line.replace("Scan: PASS", "Scan: FAIL", 1) + " · stale CVE data: " + "; ".join(stale.values())
    print(line)
    if stamping:
        write_stamp(results, repo, verdict)
    return 0 if verdict == "PASS" else 1


def cmd_classify(args: argparse.Namespace) -> int:
    if args.range and ".." in args.range:
        base, head = args.range.split("..", 1)
    elif args.base:
        base, head = args.base, args.head
    else:
        print("classify: give <base>..<head> or --base REF [--head REF]: the range does not resolve", file=sys.stderr)
        return 2
    try:
        c = classify(base, head)
    except ClassifyError as e:
        print(f"classify: {e}", file=sys.stderr)
        return 2
    print(c.depth)
    if args.why:
        for reason in c.reasons[:12] or (LIGHT_WHY,):
            print(f"  {reason}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if not path.is_file():
        print(f"config: no config file at {path}{_misnamed(path)}")
        return 2
    try:
        c = load_config(path)
    except ConfigError as e:
        print(f"config: {e}")
        return 2
    print(f"config ok: profile {c.profile.name} ({len(c.profile.controls)} controls) · gates {', '.join(c.gates)} · version {c.version}")
    for r in c.relaxations:
        print(f"  relaxed: {r}")
    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    try:
        print(render(load_profile(args.name)))
    except ProfileError as e:
        print(f"profile: {e}")
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    commands = {"profile": cmd_profile, "config": cmd_config, "classify": cmd_classify, "scan-verdict": cmd_scan_verdict, "run": cmd_run, "scan-precondition": cmd_scan_precondition}
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
