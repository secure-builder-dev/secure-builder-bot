"""The QA gate: five mechanical checks, in order, each a section of the receipt with its evidence file
(PRD § The three gates). Status not_run whenever the gate could not do its job; it is never a pass.

1. The suite runs green, with no skipped test added without a ticket reference.
2. Coverage on the changed lines meets the profile's threshold.
3. Every new or changed route has a negative test.
4. No mocked database on an integration path.
5. Mutation of controls: an unregistered guard, a FAIL row, a row that survives mutation — each blocks.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from securebuilderbot_core.config import ConfigError, QaConfig, blob_at, load_config
from securebuilderbot_core.gate import Finding, GateContext, GateResult

from . import checks, controls
from .adapters import CommandRunner, SuiteResult, detect_runners, withholding
from .coverage_changed import changed_line_coverage, is_test_path, lcov_lines, meets, merge_hits, production_files, summary
from .diff import added_lines, changed_files, commits_touching

CONFIG_FILE = ".securebuilderbot.yml"
DRAFT_MUTATION_CAP = 20  # drafted controls sabotage-tested per run: the suite runs once per row, under one timeout
WHERE_HINT = (", or, if they live outside the directories derive-controls read (named in derive-controls.log), name them "
              "with CONTROL_SRC_ROOTS, and CONTROL_SRC_EXT: py for Python, in project.config.yaml")
INFER = ("--infer-roots",)  # the drafted mode's roots and suite command, from the layout when nothing names them
INFERRED_RED = 3  # mutate-controls: the inferred suite is red before any mutation, or there was none to infer
IGNORE_FILE = ".constraintsignore"  # files that carry the patterns a check looks for, as data: the floor guard's list, read the same way
TEST_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
LCOV_FALLBACKS = ("coverage.lcov", "coverage/lcov.info", "lcov.info")  # where a user's own test_command may leave coverage


@dataclass
class _Pinned:
    ignore: str              # .constraintsignore at the target tip
    target_rows: int         # control rows the target branch's list declares
    base_rows: int           # control rows at the range's base: whether this branch's own history held them
    head_list: bytes | None  # the list at the head commit, read by blob; None when the commit has none
    error: str = ""          # why a list could not be read: the control check never runs on a guess

    @property
    def head_rows(self) -> int:
        return controls.rows_in(self.head_list.decode("utf-8", errors="replace")) if self.head_list else 0


@dataclass
class _Section:
    result: str  # pass, fail, not_run, skipped, yellow (the drafted controls were tested; none is confirmed)
    evidence: str | None = None
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"result": self.result, "evidence": self.evidence, **self.detail}


class QaGate:
    name = "qa"

    # ── config: the qa section of the repository's own file; core validated it before this ran ──
    @staticmethod
    def _config(repo: Path) -> tuple[QaConfig, str | None, str]:
        """(the qa section, sentinel.key_secret or None, why the file could not be read or "")."""
        path = repo / CONFIG_FILE
        if not path.is_file():
            return QaConfig(), None, ""
        try:
            config = load_config(path)
        except ConfigError as e:
            return QaConfig(), None, str(e)
        return config.qa, config.sentinel.key_secret, ""

    _prepared: tuple[GateContext, _Pinned] | None = None

    @staticmethod
    def _ignore_list(ctx: GateContext) -> str:
        """.constraintsignore as the target branch holds it (config_ref, else base), read by blob: a pull
        request cannot excuse its own skip or mock. Absent, a link or unreadable excuses nothing."""
        try:
            _, data = blob_at(ctx.repo, ctx.config_ref or ctx.base, IGNORE_FILE)
        except ConfigError:
            data = None
        return data.decode("utf-8", errors="replace") if data is not None else ""

    @staticmethod
    def _ignored(text: str):
        """A predicate over repo-relative paths: one prefix per line of .constraintsignore, comments and blanks skipped."""
        prefixes = [line.strip().rstrip("*") for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        return lambda f: any(f.startswith(p) for p in prefixes)

    @classmethod
    def _pin(cls, ctx: GateContext) -> _Pinned:
        """What QA must know before pull request code can change it: the ignore list, and the control list at
        the target tip, the range's base and the head commit, each read by blob. The control tools are pointed
        at the head commit's bytes, never the checkout's file, which the pull request's own tests could rewrite."""
        def read(rev: str) -> bytes | None:
            mode, data = blob_at(ctx.repo, rev, controls.MANIFEST)
            if mode == "120000":
                raise ConfigError(Path(controls.MANIFEST), 1, f"{controls.MANIFEST} at {rev[:12]} is a link, not a file")
            return data

        def rows(data: bytes | None) -> int:
            return controls.rows_in(data.decode("utf-8", errors="replace")) if data else 0

        try:
            target, base, head = read(ctx.config_ref or ctx.base), read(ctx.base), read(ctx.head)
        except ConfigError as e:
            return _Pinned(ignore=cls._ignore_list(ctx), target_rows=0, base_rows=0, head_list=None, error=str(e))
        return _Pinned(ignore=cls._ignore_list(ctx), target_rows=rows(target), base_rows=rows(base), head_list=head)

    def prepare(self, ctx: GateContext) -> None:
        """Core calls this before any gate runs: the Scan gate before this one runs pull request code, and git
        does not verify a loose object on read, so what QA takes from git, and from the checkout's list, is taken now."""
        self._prepared = (ctx, self._pin(ctx))

    def run(self, ctx: GateContext) -> GateResult:
        qa_config, key_secret, config_error = self._config(ctx.repo)
        if config_error:
            return GateResult(gate="qa", status="not_run", reason=f"the config could not be read: {config_error}")
        names = {key_secret}
        if ctx.config is not None:  # core's copy governs (the base branch's); the checkout's file cannot loosen it
            qa_config = ctx.config.qa
            names.add(ctx.config.sentinel.key_secret)
        # The model key's CI secret is withheld from the user's code by every name either copy gives it.
        with withholding(sorted(n for n in names if n)):
            return self._run(ctx, qa_config)

    def _run(self, ctx: GateContext, qa_config: QaConfig) -> GateResult:
        rel = ctx.run_dir.name
        pinned = self._prepared[1] if self._prepared is not None and self._prepared[0] == ctx else self._pin(ctx)
        ignored = self._ignored(pinned.ignore)

        def ev(name: str) -> str:  # evidence paths are relative to the run directory: "qa/<file>"
            return f"{rel}/{name}"

        findings: list[Finding] = []
        sections: dict[str, _Section] = {}
        not_run: list[str] = []

        runners = detect_runners(ctx.repo, ctx.run_dir)
        if not runners:
            return GateResult(gate="qa", status="not_run",
                              reason="no test runner detected — the QA gate needs a package.json with jest or vitest, or pytest.ini, pyproject.toml, conftest.py or tests/")
        changed = changed_files(ctx.repo, ctx.base, ctx.head)
        added = added_lines(ctx.repo, ctx.base, ctx.head, changed)

        # ── 1. the suite, and no skip added without a ticket ─────────────────────
        if qa_config.test_command != "auto":
            results = [CommandRunner(qa_config.test_command, ctx.run_dir).run(ctx.repo, changed)]
        else:
            results = [r.run(ctx.repo, changed) for r in runners]
        errors = [f"{r.runner} ({r.app}): {r.error}" for r in results if r.error]
        red = [r for r in results if not r.passed and not r.error]
        skips = checks.added_skips(added, excused=lambda p: ignored(p) or checks.has_ticket_reference(commits_touching(ctx.repo, ctx.base, ctx.head, p)))
        findings += [Finding("blocking", "suite", f"the {r.runner} suite in {r.app} is red: {self._counts(r)} — fix it before anything can be proven",
                             path=None, file=ev(r.log.name) if r.log else None) for r in red]
        findings += [Finding("blocking", "skip", f"{s.detail}: {s.text}", path=s.path, line=s.line) for s in skips]
        sections["suite"] = _Section("not_run" if errors else ("fail" if red or skips else "pass"),
                                     ev(results[0].log.name) if results and results[0].log else None,
                                     {"runners": [self._runner_dict(r, rel) for r in results], "skips_added": len(skips),
                                      "errors": errors})
        if errors:
            not_run += errors

        # ── 2. coverage on the changed lines ─────────────────────────────────────
        lcovs = [(r.lcov, r.lcov_root) for r in results if r.lcov]
        if qa_config.test_command != "auto":
            lcovs = [(r.coverage_lcov(ctx.repo), r.app) for r in runners if r.coverage_lcov(ctx.repo).is_file()]
            lcovs += [(ctx.repo / f, ".") for f in LCOV_FALLBACKS if (ctx.repo / f).is_file()]
        prod = {f: set(lines) for f, lines in added.items() if f in production_files([f])}
        minimum = ctx.profile.qa.coverage_changed_lines
        if prod and not lcovs and not errors:
            not_run.append("the suite wrote no lcov coverage file, so coverage on the changed lines cannot be measured")
            sections["coverage"] = _Section("not_run", None, {"minimum": minimum})
        else:
            hits = merge_hits(lcov_lines(p, ctx.repo, root) for p, root in lcovs)
            report = changed_line_coverage(prod, hits)
            text = summary(report, minimum) + "\n" + "\n".join(f"uncovered  {m}" for m in report.missed) + "\n"
            (ctx.run_dir / "coverage.txt").write_text(text)
            ok = meets(report, minimum)
            if not ok:
                findings.append(Finding("blocking", "coverage", f"{summary(report, minimum)} — cover the added lines or remove them", file=ev("coverage.txt")))
            sections["coverage"] = _Section("pass" if ok else "fail", ev("coverage.txt"),
                                            {"minimum": minimum, "covered": report.covered, "executable": report.executable,
                                             "percent": round(report.pct, 1), "lcov": [str(p.relative_to(ctx.repo)) if p.is_relative_to(ctx.repo) else p.name for p, _ in lcovs]})

        # ── 3. negative tests for changed routes ─────────────────────────────────
        routes = checks.added_routes(added)
        tests = self._test_texts(ctx.repo)
        gaps = checks.routes_without_negative_tests(routes, tests)
        lines = [f"{r.path}:{r.line} {r.route}" + (" (id)" if r.has_id else "") for r in routes]
        lines += [f"GAP {g.route.path}:{g.route.line} {g.route.route}: {g.missing}" + (f" (named in {', '.join(g.tests)})" if g.tests else "") for g in gaps]
        (ctx.run_dir / "routes.txt").write_text(("\n".join(lines) or "no route definition added or changed in the range") + "\n")
        findings += [Finding("blocking", "AC-3", f"{g.missing} — add a test that requests {g.route.route} without credentials and expects 401 or 403"
                             + (" and one where user A is denied user B's record" if g.route.has_id else ""), path=g.route.path, line=g.route.line, file=ev("routes.txt")) for g in gaps]
        sections["negative_tests"] = _Section("fail" if gaps else "pass", ev("routes.txt"), {"routes": len(routes), "without_negative_test": len(gaps)})

        # ── 4. no mocked database on an integration path ─────────────────────────
        mocks = [s for s in checks.mocked_db_sites(added, lambda p: tests.get(p, "")) if not ignored(s.path)]
        (ctx.run_dir / "mocked-db.txt").write_text(("\n".join(f"{s.path}:{s.line} {s.text}" for s in mocks) or "no database module mocked on an integration path") + "\n")
        findings += [Finding("blocking", "mocked-db", f"a mocked database module ({s.detail}) behind an integration test proves the mock, not the code — use the test database",
                             path=s.path, line=s.line, file=ev("mocked-db.txt")) for s in mocks]
        sections["mocked_db"] = _Section("fail" if mocks else "pass", ev("mocked-db.txt"), {"sites": len(mocks)})

        # ── 5. mutation of controls ──────────────────────────────────────────────
        skipped_mutation = qa_config.mutation is False
        with tempfile.TemporaryDirectory(prefix="securebuilderbot-draft-") as scratch:
            mutation = self._mutation(ctx, qa_config, pinned, Path(scratch), findings, not_run, ev)
        sections["mutation"], mutation_table, mutation_ran, drafted_note = mutation

        # ── the verdict ──────────────────────────────────────────────────────────
        blocking = [f for f in findings if f.severity == "blocking"]
        suite_ran = bool(results) and not errors
        assessed = ["SA-11", "SA-11(1)"] if suite_ran and mutation_ran else []
        receipt = {"checks": {k: v.as_dict() for k, v in sections.items()}, "mutation_table": mutation_table,
                   "controls_assessed": assessed, "profile_minimum_coverage": minimum, "mutation_required": ctx.profile.qa.mutation_required}
        if not_run:
            return GateResult(gate="qa", status="not_run", reason="; ".join(not_run), findings=tuple(findings), receipt=receipt)
        if blocking:
            first = blocking[0]
            where = f" at {first.path}:{first.line}" if first.path and first.line else ""
            return GateResult(gate="qa", status="fail", findings=tuple(findings), receipt=receipt,
                              reason=f"{len(blocking)} blocking finding(s); first: {first.rule_id}{where} — {first.message}")
        if drafted_note:
            return GateResult(gate="qa", status="yellow", findings=tuple(findings), receipt=receipt, reason=drafted_note)
        if skipped_mutation and ctx.profile.qa.mutation_required:
            return GateResult(gate="qa", status="yellow", findings=tuple(findings), receipt=receipt,
                              reason=f"mutation of controls is off in the config and profile {ctx.profile.name} requires it")
        return GateResult(gate="qa", status="pass", findings=tuple(findings), receipt=receipt)

    def _mutation(self, ctx: GateContext, qa_config: QaConfig, pinned: _Pinned, scratch: Path,
                  findings: list[Finding], not_run: list[str], ev) -> tuple[_Section, list[dict], bool, str]:
        """Check 5: (its section, the mutation table, whether mutation ran on a declared list, the yellow reason
        when nothing is declared). Appends its findings and its reasons for not running to the lists it is given.

        Which list governs is pinned before pull request code ran: a list the target branch declares rows in
        and the head commit does not blocks; none on either side is the drafted mode."""
        if qa_config.manifest != controls.MANIFEST:
            not_run.append(f"qa.manifest is {qa_config.manifest!r}; the control tools read {controls.MANIFEST} only")
            return _Section("not_run", None, {"manifest": qa_config.manifest}), [], False, ""
        if pinned.error:
            not_run.append(f"the control list could not be read: {pinned.error}")
            return _Section("not_run", None, {"manifest": controls.MANIFEST}), [], False, ""
        if pinned.target_rows and not pinned.head_rows:
            why = (f"this pull request removes every row of {controls.MANIFEST} ({pinned.base_rows} where it branched) — restore the list; "
                   "a repository loses its controls only by a reviewed edit of the target branch") if pinned.base_rows else (
                   f"the target branch's {controls.MANIFEST} declares {pinned.target_rows} control(s) and this branch has none of them "
                   "— merge the target branch in, so its controls are tested against this change")
            findings.append(Finding("blocking", "control-list-removed", why, path=controls.MANIFEST))
            return _Section("fail", None, {"manifest": controls.MANIFEST, "target_rows": pinned.target_rows,
                                           "base_rows": pinned.base_rows, "head_rows": 0}), [], False, ""
        declared = pinned.head_rows > 0
        # The tools read the head commit's list as pinned, written out only now, after the suite has run.
        listed = scratch / "control-list.md"
        if pinned.head_list is not None:
            listed.write_bytes(pinned.head_list)
        # The draft is written outside the checkout, so nothing in the repository's tree can be read as it, and
        # copied into the run directory as evidence once the tools are done with it.
        draft = scratch / "manifest-draft.md"
        # Only the drafted mode infers roots from the layout; a declared list reads the config exactly as before.
        infer = () if declared else INFER
        derive = controls.run_tool(ctx.repo, ctx.run_dir, "derive-controls", "--list", "--draft", str(draft), *infer, manifest=listed)
        guards = controls.unregistered_guards(derive.output)
        draft_text = draft.read_text(errors="replace") if draft.is_file() else ""
        if draft_text:
            (ctx.run_dir / "manifest-draft.md").write_text(draft_text)
        # With a list, a guard with no row blocks. With none, every guard is unregistered by definition:
        # each is drafted and sabotage-tested below, and named here so the person confirming sees it.
        findings += [Finding("blocking" if declared else "advisory", "unregistered-control",
                             f"{g.symbol} refuses with {g.kind} and has no CONTROL-MANIFEST row — confirm the drafted row or write a not-a-control reason",
                             path=g.path, line=g.line, file=ev("manifest-draft.md")) for g in guards]
        if not declared:
            guards = []
        verify = controls.run_tool(ctx.repo, ctx.run_dir, "verify-controls", manifest=listed)
        fails = controls.failed_rows(verify.output)
        findings += [Finding("blocking", "verify-controls", f"{i} {name}: {why}", path=controls.MANIFEST, file=ev("verify-controls.log")) for i, name, why in fails]
        detail = {"manifest": controls.MANIFEST, "unregistered_guards": len(guards), "verify_failed": len(fails),
                  "manifest_draft": ev("manifest-draft.md") if draft_text else None,
                  "derive": ev("derive-controls.log"), "verify": ev("verify-controls.log")}
        drafted = controls.row_ids(draft_text)
        none_declared = f"no security controls are declared in {controls.MANIFEST}"
        if not declared:
            detail["drafted"] = len(drafted)
        if qa_config.mutation is False:
            detail["mutation"] = "skipped: qa.mutation is false in the config"
            note = "" if declared else (f"{none_declared}, and mutation is off in the config, so nothing was sabotage-tested: "
                                        f"confirm the draft ({ev('manifest-draft.md')}) as the repository's list" if drafted
                                        else f"{none_declared}, none were found to draft, and mutation is off in the config: add the controls by hand{WHERE_HINT}")
            return _Section("fail" if guards or fails else "skipped", ev("derive-controls.log"), detail), [], False, note
        if not declared:
            return self._mutate_draft(ctx, draft, drafted, findings, not_run, ev, detail, none_declared)
        # Only the rows this range touches: a row added or edited in the list, or whose implementation or
        # proving test changed, is re-proven; a change to the test harness re-proves every row (mutate-controls
        # --since). An edit to the list no longer re-runs all of it: each row is compared with its own line.
        args = ("--since", ctx.base)
        mutate = controls.run_tool(ctx.repo, ctx.run_dir, "mutate-controls", *args, manifest=listed)
        rows = controls.parse_mutation_table(mutate.output)
        unproven = controls.unproven_rows(rows)
        ran = mutate.code in (0, 1) and (bool(rows) or "0 mutated" in mutate.output)
        if not ran:
            last = next((line for line in reversed(mutate.output.splitlines()) if line.strip()), "no output")
            not_run.append(f"mutate-controls could not run: {last.strip()} ({ev('mutate-controls.log')})")
        findings += [Finding("blocking", "SA-11", f"{r.id} {r.control}: {r.verdict} — the suite stays green with the control disabled; give it a test with teeth",
                             path=controls.MANIFEST, file=ev("mutate-controls.log")) for r in unproven]
        escalated = "every control re-proven" in mutate.output
        detail.update({"mutation": ev("mutate-controls.log"),
                       "scope": "every row: the test harness changed" if escalated else f"rows changed since {ctx.base[:7]}",
                       "rows": len(rows), "not_proven": len(unproven)})
        section = _Section("not_run" if not ran else ("fail" if guards or fails or unproven else "pass"), ev("mutate-controls.log"), detail)
        return section, [r.__dict__ for r in rows], ran, ""

    @staticmethod
    def _mutate_draft(ctx: GateContext, draft: Path, drafted: list[str], findings: list[Finding], not_run: list[str], ev,
                      detail: dict, none_declared: str) -> tuple[_Section, list[dict], bool, str]:
        """No list, or one with no rows: sabotage-test the drafted controls (every function that refuses access,
        and the ones whose names say they protect something), the first DRAFT_MUTATION_CAP of them, and stay
        yellow until a person confirms the draft. Never a clean pass on zero controls (PRD § The control manifest)."""
        if not drafted:
            detail["mutation"] = "nothing declared and nothing drafted: nothing mutated"
            return (_Section("skipped", ev("derive-controls.log"), detail), [], False,
                    f"{none_declared}, and none were found to draft, so the sabotage check proved nothing: add the controls by hand{WHERE_HINT}")
        tested = drafted[:DRAFT_MUTATION_CAP]
        args = ("--only", ",".join(tested)) if len(tested) < len(drafted) else ()
        mutate = controls.run_tool(ctx.repo, ctx.run_dir, "mutate-controls", *args, *INFER, manifest=draft)
        if mutate.code == INFERRED_RED:
            # The roots were inferred and the suite command they imply did not run green: an inference that
            # did not fit, never a reason for not_run. Yellow, as with nothing drafted, and says which command.
            why = next((line for line in mutate.output.splitlines() if line.startswith("INFERRED SUITE NOT GREEN: ")), "INFERRED SUITE NOT GREEN: ")
            detail.update({"mutation": ev("mutate-controls.log"), "scope": "the drafted controls", "rows": 0, "inferred_suite": "not green"})
            return (_Section("yellow", ev("mutate-controls.log"), detail), [], False,
                    f"{none_declared}: {len(drafted)} control(s) drafted from roots inferred from the layout, but "
                    f"{why.removeprefix('INFERRED SUITE NOT GREEN: ')} ({ev('mutate-controls.log')}); confirm the draft ({ev('manifest-draft.md')})")
        rows = controls.parse_mutation_table(mutate.output)
        unproven = controls.unproven_rows(rows)
        if not (mutate.code in (0, 1) and (bool(rows) or "0 mutated" in mutate.output)):
            last = next((line for line in reversed(mutate.output.splitlines()) if line.strip()), "no output")
            not_run.append(f"mutate-controls could not run on the drafted controls: {last.strip()} ({ev('mutate-controls.log')})")
        findings += [Finding("advisory", "SA-11", f"drafted {r.id} {r.control}: {r.verdict} — if it is a control, it has no test "
                             "with teeth; if not, delete the row when you confirm the draft", file=ev("manifest-draft.md")) for r in unproven]
        scope = f"the first {len(rows)} of {len(drafted)}" if args else f"{len(rows)}"
        note = (f"{none_declared}: {scope} drafted control(s) sabotage-tested, {len(rows) - len(unproven)} caught; "
                f"confirm the draft ({ev('manifest-draft.md')}) as the repository's list to make QA green")
        detail.update({"mutation": ev("mutate-controls.log"), "scope": "the drafted controls", "rows": len(rows),
                       "not_proven": len(unproven), "cap": DRAFT_MUTATION_CAP})
        return _Section("yellow", ev("mutate-controls.log"), detail), [r.__dict__ for r in rows], False, note

    @staticmethod
    def _counts(r: SuiteResult) -> str:
        return ", ".join(f"{v} {k}" for k, v in r.counts.items() if k != "total" and v) or "no summary line found"

    @staticmethod
    def _runner_dict(r: SuiteResult, rel: str) -> dict:
        return {"runner": r.runner, "app": r.app, "command": r.command, "passed": r.passed, "counts": r.counts,
                "log": f"{rel}/{r.log.name}" if r.log else None, "error": r.error}

    @staticmethod
    def _test_texts(repo: Path) -> dict[str, str]:
        """Every test file in the tree, by repo-relative path: the place a route's negative test must exist."""
        out: dict[str, str] = {}
        for p in repo.rglob("*"):
            if not p.is_file() or p.suffix not in TEST_EXTS:
                continue
            rel = p.relative_to(repo).as_posix()
            if {"node_modules", ".git", "dist", "build", "coverage", "__pycache__"} & set(rel.split("/")):
                continue
            if is_test_path(rel):
                out[rel] = p.read_text(errors="replace")
        return out

