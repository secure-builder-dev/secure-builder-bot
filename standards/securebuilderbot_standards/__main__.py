"""The standards command line. Every subcommand prints to stdout and exits 0 ok, 1 refused, 2 could not run.

  verify [--quiet] [--advisory] [--list-cited] [--tracked] [--data DIR] [FILE...]
                                                         every citation in the tracked documents and FILE... resolves
  versions [--data DIR]                                               the versions a receipt records, as JSON
  catalog [--data DIR] ID...                                          each control's title, family, baselines
  refresh [--dry-run] [--offline DIR] [--data DIR] [--docs FILE...]    fetch the upstreams, adopt what changed

`--data DIR` names the index directory (default: the vendored standards/data/controls); the shell
wrapper standards/scripts/verify-citations.sh passes the one in the repository it runs in, which is
how the self-test drives it inside a fixture repository.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import data
from .citations import render_report, tracked_documents, verify_files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="standards/run", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", metavar="command")
    v = sub.add_parser("verify", help="every citation in the given files exists and is current")
    v.add_argument("--quiet", action="store_true", help="print only the summary line")
    v.add_argument("--advisory", action="store_true", help="also report title mismatches; never affects the exit code")
    v.add_argument("--list-cited", action="store_true", help="print the distinct NIST ids cited and stop")
    v.add_argument("--data", default=None, help="index directory (default: the vendored one)")
    v.add_argument("--tracked", action="store_true", help="verify the tracked documents the repository holds to its citations")
    v.add_argument("files", nargs="*", metavar="FILE")
    ver = sub.add_parser("versions", help="the version or date of each vendored standard, as JSON")
    ver.add_argument("--data", default=None)
    c = sub.add_parser("catalog", help="look up controls by id")
    c.add_argument("--data", default=None)
    c.add_argument("ids", nargs="+", metavar="ID")
    r = sub.add_parser("refresh", help="fetch each upstream, compare with the vendored copy, adopt what changed")
    r.add_argument("--dry-run", action="store_true", help="report what would change; write nothing")
    r.add_argument("--offline", metavar="DIR", default=None, help="read the upstream files from DIR instead of the network")
    r.add_argument("--data", default=None)
    r.add_argument("--docs", nargs="*", metavar="FILE", default=None,
                   help="the documents whose citations a new catalog must not break (default: the ones verify-citations scans)")
    return parser


def _no_catalog(where: str) -> int:
    print(f"CITATIONS: no control index at {where}")
    print("  Rebuild it:  see standards/scripts/build-control-index.py")
    print("  Until then this check is inert — it cannot tell a correct citation from an invented one.")
    return 2


def cmd_verify(args: argparse.Namespace) -> int:
    files = list(args.files) + (tracked_documents() if args.tracked else [])
    if not files:
        print("verify: name a FILE or pass --tracked")
        return 2
    try:
        v, cites = verify_files(files, args.data)
    except FileNotFoundError as e:
        return _no_catalog(str(e))
    if args.list_cited:
        for cid in sorted({c.id for c in cites if c.kind == "nist"}):
            print(cid)
        return 0
    report, code = render_report(v, cites, advisory=args.advisory)
    if args.quiet:
        report = report.rstrip("\n").rsplit("\n", 1)[-1] + "\n" if code == 0 else report
    sys.stdout.write(report)
    return code


def cmd_versions(args: argparse.Namespace) -> int:
    try:
        print(json.dumps(data.versions(args.data), indent=1))
    except FileNotFoundError as e:
        return _no_catalog(str(e))
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    try:
        controls = data.catalog(args.data)
    except FileNotFoundError as e:
        return _no_catalog(str(e))
    missing = 0
    for cid in args.ids:
        c = controls.get(cid)
        if c is None:
            print(f"{cid}  not in the catalog")
            missing += 1
            continue
        if c.withdrawn:
            tail = "withdrawn" + (f", into {', '.join(c.into)}" if c.into else "")
        else:
            tail = ", ".join(x for x, keep in (("moderate", c.in_moderate), ("high", c.in_high)) if keep) or "no baseline"
        print(f"{c.id}  {c.title}  ({c.family}; {tail})")
    return 1 if missing else 0


def cmd_refresh(args: argparse.Namespace) -> int:
    from .refresh import refresh
    return refresh(data_dir=args.data, offline=args.offline, dry_run=args.dry_run, docs=args.docs, out=sys.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    commands = {"verify": cmd_verify, "versions": cmd_versions, "catalog": cmd_catalog, "refresh": cmd_refresh}
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
