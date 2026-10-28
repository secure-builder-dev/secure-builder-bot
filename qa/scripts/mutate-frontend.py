#!/usr/bin/env python3
"""mutate-frontend.py — break each declared frontend behaviour on purpose; the suite must go red.

WHY THIS EXISTS
    qa/scripts/mutate-controls.sh does this for docs/security/CONTROL-MANIFEST.md, whose
    every row points at backend/src/ and whose default suite command is the backend's. The frontend
    had no equivalent, and the frontend-coverage epic produced the evidence that one was needed:
    src/lib/api.ts read 100% lines with zero tests, and two of the five sites in T-064 were in files
    at 96% and 97% statements whose tests all passed both before and after the fix, because not one
    asserted a date. Coverage measures reach; this measures strength. T-053.

    Project-owned rather than engine-owned on purpose: engine/ is overwritten by `make sync-engine`,
    and the standalone shape T-053 offers avoids teaching the engine's verify-controls.sh about .tsx.
    This IS the engine's frontend lane. It began as a project-owned script because engine/ is
    overwritten by `make sync-engine`; it now lives in engine/ and is synced like the rest.

    Python rather than bash because the manifest cells contain backticks, pipes and regex
    metacharacters, and BSD sed/tr differ from GNU on every escape that would take to parse safely.

HOW IT WORKS
    For each row of docs/security/FRONTEND-MUTATIONS.md: replace `from` with `to` in `file`, run the
    frontend suite, and require it to FAIL. Green under mutation means nothing tests that behaviour.

SAFETY
    Each file's original bytes are held in memory and rewritten afterwards — on success, on failure,
    and on Ctrl-C. One row is mutated at a time. Nothing else is written. The suite runs once
    unmutated first, and a red baseline aborts: a suite that is already failing makes every row look
    proven. `from` must occur exactly once; zero or several is UNLOCATABLE rather than a guess.
    A red baseline prints the last 40 lines it captured, so the reason is on screen rather than
    needing a second run by hand (T-077). `--no-baseline` skips that check, and skipping it is the
    only way an already-red suite can make every row report proven — so it wants a stated reason.

USAGE   python3 qa/scripts/mutate-frontend.py [--dry-run] [--only FM-01,FM-05]
        [--no-baseline] [--list]   ·   or `make mutate-frontend ARGS="..."`
EXIT    0 = every row proven   1 = a row NOT PROVEN or UNLOCATABLE, or the baseline is red
        2 = manifest missing or unreadable
"""
from __future__ import annotations

import argparse
import time
import os
import re
import signal
import subprocess
import sys
from dataclasses import dataclass

MANIFEST = "docs/security/FRONTEND-MUTATIONS.md"
APP_DIR = "frontend"
DEFAULT_TEST_CMD = "npx vitest run --reporter=dot --silent"

# T-071 fix 2. Per ROW, run only the tests whose module graph reaches the mutated file, instead of
# all 64 files. `--changed` selects from the WORKING TREE diff, which is exactly where this harness
# writes its mutation, so no per-row path plumbing is needed. Measured: 590s -> 201s for 35 rows,
# with all 35 still proven.
#
# `--related` does NOT exist in vitest 4.x (`CACError: Unknown option --related`); `--changed` is
# the v4 form.
#
# Safe in one direction only, and that is why this is allowed: a row is `proven` only when the suite
# goes RED (see the grading in main()). A smaller test set makes RED *less* likely, so a too-narrow
# selection can only produce a false NOT PROVEN — a loud finding someone investigates — and never a
# false `proven`. There is no path from narrowing to a silent pass.
#
# NEVER use this for the baseline. On a clean tree `--changed` selects zero test files, vitest exits
# 0, and the baseline would print "green" having run NOTHING — silently disabling the guard that
# stops an already-red suite making every row look proven. The baseline runs the full suite; because
# the narrowed set is a subset of it, one green full baseline covers every row.
DEFAULT_ROW_TEST_CMD = "npx vitest run --changed --reporter=dot --silent"


@dataclass
class Row:
    id: str
    file: str
    frm: str
    to: str
    proves: str

    @property
    def path(self) -> str:
        return os.path.join(APP_DIR, self.file)


def repo_root() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except Exception:
        return "."


def unescape_cell(cell: str) -> str:
    """A manifest cell to its literal text.

    Cells are markdown, so a literal pipe is written `\\|` and code spans are wrapped in backticks.
    The backtick stripping is deliberately outermost-only: a cell may legitimately contain backticks,
    and only the wrapping pair is markup.
    """
    s = cell.strip()
    s = s.replace("\\|", "|")
    if len(s) >= 2 and s.startswith("`") and s.endswith("`"):
        s = s[1:-1]
    return s.replace("\\`", "`")


def parse_manifest(path: str) -> list[Row]:
    rows: list[Row] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.startswith("| FM-"):
                continue
            body = line.strip()
            if body.startswith("|"):
                body = body[1:]
            if body.endswith("|"):
                body = body[:-1]
            # Split on unescaped pipes only.
            cells = re.split(r"(?<!\\)\|", body)
            if len(cells) < 5:
                continue
            rows.append(Row(*(unescape_cell(c) for c in cells[:5])))
    return rows


def run_suite(cmd: str) -> tuple[bool, bool, str]:
    """
    Run the frontend suite. Returns (passed, a_test_actually_failed, captured_output).

    T-074. The old version returned only `proc.returncode == 0`, and the caller graded any non-zero
    exit as "the mutation was caught". That is wrong in the one direction that matters: a mutation
    which breaks the *build* also exits non-zero, with no test having asserted anything, and the row
    reported `proven`. Since GOV-010 made a NOT PROVEN row blocking, this function is a gate input
    whose only failure mode was a false PASS.

    So we distinguish. vitest prints a `Tests  N failed` summary only when tests ran and failed; a
    transform or collection error produces no such line. `mutate-controls.sh` already separates
    these two states as "RED" and "RED (build error)" — this mirrors it.
    """
    # The command is a shell command line by design: the operator's own MUTATE_FRONTEND_TEST_CMD,
    # or a constant, never data from the code under test. It runs as an explicit `bash -c`, the
    # same way mutate-controls.sh runs its suite, rather than through shell=True.
    proc = subprocess.run(["bash", "-c", cmd], cwd=APP_DIR,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = proc.stdout.decode("utf-8", "replace")
    passed = proc.returncode == 0
    test_failed = bool(re.search(r"Tests\s+\d+\s+failed", out))
    # T-077: the capture is returned, not discarded. The baseline branch used to print two sentences
    # and throw away the only evidence of why the suite was red, so the first thing anyone did was
    # re-run the suite by hand to see what this run had already seen.
    return passed, test_failed, out


def main() -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--no-baseline", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--since", default="")
    ap.add_argument("--no-narrow", action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    args = ap.parse_args()

    if args.help:
        print(__doc__)
        return 0

    os.chdir(repo_root())
    if not os.path.isfile(MANIFEST):
        print(f"FRONTEND MUTATIONS: none at {MANIFEST}")
        return 2
    if not os.path.isdir(APP_DIR):
        print(f"no {APP_DIR}/ directory")
        return 2

    rows = parse_manifest(MANIFEST)
    if not rows:
        print(f"FRONTEND MUTATIONS: no rows parsed from {MANIFEST}")
        return 2

    only = {s.strip() for s in args.only.split(",") if s.strip()}
    test_cmd = os.environ.get("MUTATE_FRONTEND_TEST_CMD", DEFAULT_TEST_CMD)
    # Baseline always runs `test_cmd` (full suite). Rows run `row_test_cmd` unless --no-narrow.
    row_test_cmd = test_cmd if args.no_narrow else os.environ.get(
        "MUTATE_FRONTEND_ROW_TEST_CMD", DEFAULT_ROW_TEST_CMD)

    # T-071. Scoping, mirroring `mutate-controls.sh --since`. The gate passes the range's base (the
    # last gated head on a re-gate); an unchanged row is cited to the gate-log row that last ran it,
    # or run — there is no nightly (2026-10-12).
    since_skip: set[str] = set()
    since_note = ""
    if args.since:
        # T-080. Both guards mirror qa/scripts/mutate-controls.sh:69-74. Without them an
        # unresolvable or non-ancestor revision yields an EMPTY change list, every row lands in
        # since_skip, and the harness exits 0 having proven nothing — in a tool GOV-010 made
        # blocking. The predicate is "the scope could not be computed", never "zero rows ran":
        # zero rows is the legitimate records-only case and must still exit 0.
        if subprocess.run(["git", "rev-parse", "--verify", "-q", f"{args.since}^{{commit}}"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            print(f"--since {args.since}: not a commit", file=sys.stderr)
            return 2
        # The rebase case, which T-080 originally omitted: after a force-push the old head often
        # still resolves from the object store, so rev-parse alone does not catch it.
        if subprocess.run(["git", "merge-base", "--is-ancestor", args.since, "HEAD"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            print(f"--since {args.since}: not an ancestor of HEAD — run the full mutation check",
                  file=sys.stderr)
            return 2
        proc = subprocess.run(["git", "diff", "--name-only", f"{args.since}..HEAD"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if proc.returncode != 0:
            print(f"--since {args.since}: git diff failed; cannot compute scope", file=sys.stderr)
            return 2
        changed = proc.stdout.decode().split()
        # T-080. Mirrors mutate-controls.sh:77's harness_re. The previous two-literal-path check
        # missed every file that can change whether ANY row goes red without being any row's `file`:
        # src/test/setup.ts is loaded before all 64 test files, and vitest.config.ts owns the
        # include list and the setup hook. Neither would widen, and neither runs a row.
        harness_re = re.compile(
            r"^(frontend/src/test/|frontend/vitest\.config\.|frontend/package(-lock)?\.json$"
            r"|qa/scripts/mutate-frontend\.py$)")
        harness_changed = any(c == MANIFEST or harness_re.match(c) for c in changed)
        # We cannot map a row to its proving test: FRONTEND-MUTATIONS.md has no `proving test`
        # column, unlike CONTROL-MANIFEST.md. So any test change widens to every row rather than
        # guessing. Adding that column would let this narrow further; until then, conservative.
        tests_changed = any(re.search(r"\.test\.tsx?$", c) for c in changed)
        if harness_changed or tests_changed:
            why = "harness changed" if harness_changed else "a test file changed"
            since_note = f"--since {args.since}: {why} -- every row re-mutated"
        else:
            touched = {c for c in changed if c.startswith(f"{APP_DIR}/")}
            # T-SLIM-14/15 need no id check here: a row added or re-pointed since --since is an edit
            # to FRONTEND-MUTATIONS.md, and `c == MANIFEST` above already widens to every row.
            for r in rows:
                if f"{APP_DIR}/{r.file}" not in touched:
                    since_skip.add(r.id)
            since_note = (f"--since {args.since}: {len(rows) - len(since_skip)} row(s) re-mutated, "
                          f"{len(since_skip)} unchanged since that revision")

    if args.list:
        print(f"FRONTEND MUTATIONS — {len(rows)} rows\n")
        for r in rows:
            print(f"  {r.id:<6} {r.file:<42} {r.proves}")
        return 0

    # Restore-on-exit, including Ctrl-C. Only ever holds one file at a time.
    pending: dict[str, str] = {}

    def restore() -> None:
        for p, original in list(pending.items()):
            open(p, "w", encoding="utf-8").write(original)
            pending.pop(p, None)

    def on_signal(_sig, _frm):
        restore()
        print("\ninterrupted — sources restored", file=sys.stderr)
        sys.exit(130)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        if not args.no_baseline and not args.dry_run:
            print(f"baseline: running {APP_DIR} suite unmutated ... ", end="", flush=True)
            baseline_passed, _, baseline_out = run_suite(test_cmd)
            if baseline_passed:
                print("green\n")
            else:
                print("RED\n")
                print("The unmutated suite is already failing, so every row would look proven.")
                tail = baseline_out.strip().splitlines()[-40:]
                if tail:
                    print("captured baseline output (last 40 lines):")
                    print("-" * 72)
                    for line in tail:
                        print(line)
                    print("-" * 72)
                print("Fix the suite first. --no-baseline skips this check — which is the only thing")
                print("stopping an already-red suite from making every row report proven.")
                return 1

        print(f"FRONTEND MUTATIONS — {len(rows)} rows from {MANIFEST}")
        if since_note:
            print(f"  {since_note}")
        print(flush=True)
        t_all = time.time()
        proven: list[str] = []
        unproven: list[str] = []
        unlocatable: list[str] = []
        skipped = 0

        for r in rows:
            if only and r.id not in only:
                skipped += 1
                continue
            if r.id in since_skip:
                # Named, never silently omitted: a reader must be able to see which rows this run
                # did not re-prove and go find the run that did.
                print(f"  {r.id:<6} unchanged    {r.file} — not re-mutated; cite the last full gate")
                skipped += 1
                continue

            if not os.path.isfile(r.path):
                print(f"  {r.id:<6} UNLOCATABLE  {r.file} — no such file")
                unlocatable.append(r.id)
                continue

            # A cell containing the two characters \ and n would be inserted as literal text and
            # produce a syntax error. A syntax error makes the suite go red, so the row would report
            # PROVEN without any test having caught anything — the harness must refuse it, not grade
            # it. Found the first time a row was written with a \n in it.
            if "\\n" in r.frm or "\\n" in r.to:
                print(f"  {r.id:<6} UNLOCATABLE  {r.file} — cell contains a literal \\n; cells are "
                      f"single-line (see the manifest header)")
                unlocatable.append(r.id)
                continue

            source = open(r.path, encoding="utf-8").read()
            hits = source.count(r.frm)
            if hits != 1:
                print(f"  {r.id:<6} UNLOCATABLE  {r.file} — `from` matched {hits} times, expected exactly 1")
                unlocatable.append(r.id)
                continue

            if args.dry_run:
                print(f"  {r.id:<6} {r.file}")
                print(f"         - {r.frm}")
                print(f"         + {r.to}")
                print(f"         proves: {r.proves}")
                proven.append(r.id)
                continue

            pending[r.path] = source
            open(r.path, "w", encoding="utf-8").write(source.replace(r.frm, r.to))
            t_row = time.time()
            try:
                survived, test_failed, _row_out = run_suite(row_test_cmd)
            finally:
                restore()
            secs = int(time.time() - t_row)

            if survived:
                print(f"  {r.id:<6} NOT PROVEN   {r.file}  ({secs}s)", flush=True)
                print(f"         suite stayed green with: {r.frm}  ->  {r.to}")
                print(f"         nothing tests: {r.proves}")
                unproven.append(r.id)
            elif not test_failed:
                # T-074: red, but no test asserted anything. Grading this `proven` is the false PASS.
                print(f"  {r.id:<6} NOT PROVEN   {r.file}  ({secs}s) — mutation broke the build, "
                      f"no test failed", flush=True)
                print(f"         the suite went red without asserting: {r.frm}  ->  {r.to}")
                unproven.append(r.id)
            else:
                print(f"  {r.id:<6} proven       {r.file}  ({secs}s)", flush=True)
                proven.append(r.id)

        print()
        if args.dry_run:
            print(f"dry run: {len(proven)} row(s) locatable, {len(unlocatable)} unlocatable, "
                  f"{skipped} skipped — nothing was run")
            return 1 if unlocatable else 0

        print(f"mutate-frontend: {len(proven)} proven, {len(unproven)} NOT PROVEN, "
              f"{len(unlocatable)} unlocatable, {skipped} skipped (of {len(rows)}) "
              f"· elapsed {int(time.time() - t_all)}s")
        if unproven:
            print(f"  NOT PROVEN: {' '.join(unproven)} — each is a blocking finding for the gate log")
        if unlocatable:
            print(f"  UNLOCATABLE: {' '.join(unlocatable)} — fix the manifest row; do not delete it")
        return 1 if (unproven or unlocatable) else 0
    finally:
        restore()


if __name__ == "__main__":
    sys.exit(main())
