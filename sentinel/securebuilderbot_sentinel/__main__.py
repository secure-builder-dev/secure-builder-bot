"""The sentinel module's command line: `sentinel/run proofset [--case NAME]`."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] != "proofset":
        print("usage: sentinel/run proofset [--case NAME] [--cases DIR]")
        return 2
    from .replay import main as replay
    return replay(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
