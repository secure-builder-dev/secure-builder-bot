import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from securebuilderbot_core.__main__ import main
from securebuilderbot_core.config import load_config
from securebuilderbot_core.gate import Finding, GateContext, GateResult, not_built
from securebuilderbot_core.runner import RunError, run

from .conftest import commit_all, git


@dataclass
class Fake:
    name: str
    status: str
    calls: list

    def run(self, ctx: GateContext) -> GateResult:
        self.calls.append((self.name, ctx))
        findings = (Finding("blocking", "CVE-2026-0001", "bump the package"),) if self.status == "fail" else ()
        return GateResult(gate=self.name, status=self.status, reason="" if self.status == "pass" else f"{self.name} said {self.status}",
                          findings=findings, receipt={"controls_assessed": ["RA-5"]} if self.name == "scan" else {})


def fakes(calls, **statuses):
    return {name: (lambda n=name, s=status: Fake(n, s, calls)) for name, status in statuses.items()}


@pytest.fixture
def project(repo: Path) -> Path:
    (repo / ".securebuilderbot.yml").write_text(
        "profile: il6\ngates: [scan, qa, sentinel]\nversion: latest\nsentinel:\n  key_secret: SB_MODEL_KEY\n")
    commit_all(repo, "config")
    git(repo, "checkout", "-q", "-b", "epic/demo")
    (repo / "docs").mkdir()
    (repo / "docs" / "x.md").write_text("words\n")
    commit_all(repo, "docs")
    return repo


def cfg(repo: Path):
    return load_config(repo / ".securebuilderbot.yml")


def test_all_pass_exits_0_and_writes_the_three_outputs(project):
    calls = []
    out = run(cfg(project), project, "main", gates=fakes(calls, scan="pass", qa="pass", sentinel="pass"))
    assert out.exit_code == 0
    assert [c[0] for c in calls] == ["scan", "qa", "sentinel"]
    assert (out.run_dir / "receipt.json").is_file() and (out.run_dir / "receipt.md").is_file()
    v = json.loads((out.run_dir / "verdict.json").read_text())
    assert v["overall"] == "pass" and v["exit_code"] == 0
    assert out.lines[-1] == "Overall: PASS"
    row = (project / "gate-records" / "gate-log.md").read_text().splitlines()[-1]
    assert row.startswith("| ") and "| demo |" in row and "Scan PASS · QA PASS · Sentinel PASS · Overall PASS" in row


def test_a_failing_gate_stops_the_run_and_later_gates_are_not_run(project):
    calls = []
    out = run(cfg(project), project, "main", gates=fakes(calls, scan="fail", qa="pass", sentinel="pass"))
    assert out.exit_code == 1
    assert [c[0] for c in calls] == ["scan"]
    v = json.loads((out.run_dir / "verdict.json").read_text())
    assert [(g["gate"], g["status"]) for g in v["gates"]] == [("scan", "fail"), ("qa", "not_run"), ("sentinel", "not_run")]
    assert v["gates"][1]["reason"].startswith("an earlier gate did not pass")
    assert v["gates"][0]["blocking_findings"] == 1
    rows = [x for x in (project / "gate-records" / "gate-log.md").read_text().splitlines() if x.startswith("| 2")]
    assert len(rows) == 1 and "1 blocking, 0 advisory" in rows[0]


def test_a_gate_that_did_not_run_is_never_a_pass(project):
    calls = []
    out = run(cfg(project), project, "main", gates=fakes(calls, scan="not_run", qa="pass", sentinel="pass"))
    assert out.exit_code == 1
    assert [c[0] for c in calls] == ["scan"]  # a scan that never ran stops the run like a failed one
    assert out.lines[0].startswith("Scan: NOT RUN — scan said not_run")
    assert out.lines[-1] == "Overall: FAIL"


def test_an_unbuilt_module_reports_not_run(project):
    out = run(cfg(project), project, "main", gates={"scan": lambda: Fake("scan", "pass", []),
                                                     "qa": lambda: not_built("qa"), "sentinel": lambda: not_built("sentinel")})
    assert out.exit_code == 1
    assert "the qa module is not built yet" in out.lines[1]


def test_a_crashing_gate_is_not_run_with_the_reason(project):
    class Boom:
        name = "scan"

        def run(self, ctx):
            raise RuntimeError("scanner exploded")

    out = run(cfg(project), project, "main", gates={"scan": Boom, **fakes([], qa="pass", sentinel="pass")})
    assert out.exit_code == 1
    assert "the gate crashed: RuntimeError: scanner exploded" in out.lines[0]


def test_only_enabled_gates_run_in_the_fixed_order(project):
    (project / ".securebuilderbot.yml").write_text("profile: il4\ngates: [qa, scan]\nversion: latest\n")
    calls = []
    out = run(cfg(project), project, "main", gates=fakes(calls, scan="pass", qa="pass", sentinel="pass"))
    assert [c[0] for c in calls] == ["scan", "qa"]
    assert out.exit_code == 0


def test_a_relaxation_makes_the_run_yellow_not_red(project):
    (project / ".securebuilderbot.yml").write_text("profile: il4\ngates: [scan]\nversion: latest\nscan:\n  skip: [clamav]\n")
    calls = []
    out = run(cfg(project), project, "main", gates=fakes(calls, scan="pass"))
    assert out.exit_code == 0
    assert out.lines[-1] == "Overall: YELLOW"
    assert calls[0][1].skip == ("clamav",)


def test_the_context_carries_the_merge_base_the_depth_and_the_profile(project):
    calls = []
    run(cfg(project), project, "main", gates=fakes(calls, scan="pass", qa="pass", sentinel="pass"))
    ctx = calls[0][1]
    assert ctx.base == git(project, "merge-base", "main", "HEAD")
    assert ctx.head == git(project, "rev-parse", "HEAD")
    assert ctx.depth == "light"  # docs only
    assert ctx.profile.name == "il6"
    assert ctx.run_dir.name == "scan" and ctx.run_dir.is_dir()


def test_depth_override_from_config(project):
    (project / ".securebuilderbot.yml").write_text(
        "profile: il6\ngates: [scan]\nversion: latest\nsentinel:\n  depth: always-deep\n")
    calls = []
    run(cfg(project), project, "main", gates=fakes(calls, scan="pass"))
    assert calls[0][1].depth == "deep"


def test_receipt_lists_assessed_and_unassessed_baseline_controls(project):
    out = run(cfg(project), project, "main", gates=fakes([], scan="pass", qa="pass", sentinel="pass"))
    r = json.loads((out.run_dir / "receipt.json").read_text())
    assert r["profile"]["controls"] == 370
    assert r["controls_assessed"] == ["RA-5"]
    assert len(r["controls_not_assessed"]) == 369
    assert r["sent_to_model_endpoint"] == []
    assert r["config"]["sha256"] == cfg(project).sha256
    assert "369 of 370 controls" in (out.run_dir / "receipt.md").read_text()


def test_a_secret_in_a_gate_receipt_refuses_the_receipt_and_exits_2(project):
    class Leaky:
        name = "scan"

        def run(self, ctx):
            return GateResult(gate="scan", status="pass", receipt={"note": "AKIA" + "ABCDEFGHIJKLMNOP"})

    out = run(cfg(project), project, "main", gates={"scan": Leaky, **fakes([], qa="pass", sentinel="pass")})
    assert out.exit_code == 2
    assert not (out.run_dir / "receipt.json").exists()
    assert out.lines[-1].startswith("Receipt: REFUSED — the receipt would have carried a secret-shaped string at $.gates.scan.note")
    assert json.loads((out.run_dir / "verdict.json").read_text())["exit_code"] == 2


def test_an_unresolvable_base_cannot_start(project):
    with pytest.raises(RunError):
        run(cfg(project), project, "no-such-ref", gates=fakes([], scan="pass"))


def test_run_cli_exit_codes(project, monkeypatch, capsys):
    import securebuilderbot_core.runner as runner_mod
    monkeypatch.chdir(project)
    fake = fakes([], scan="fail", qa="pass", sentinel="pass")
    monkeypatch.setattr(runner_mod, "default_factory", lambda name: fake[name])  # run() resolves each gate here
    assert main(["run", "--base", "main"]) == 1
    out = capsys.readouterr().out
    assert "Scan: FAIL" in out and "Receipt: gate-records/runs/" in out
    assert main(["run", "--base", "nope"]) == 2
    assert "could not start" in capsys.readouterr().out
    assert main(["run", "--config", "missing.yml"]) == 2
    assert "no config file" in capsys.readouterr().out


SECRET = "sk-ant-" + "b" * 24  # secret-shaped, not a secret


def _everything_written(out, project) -> str:
    files = [p.read_text() for p in out.run_dir.rglob("*") if p.is_file()]
    return "\n".join([*files, *out.lines, *out.warnings, (project / "gate-records" / "gate-log.md").read_text()])


def test_a_secret_in_a_gate_reason_or_finding_is_redacted_from_every_output(project):
    class Leaky:
        name = "scan"

        def run(self, ctx):
            return GateResult(gate="scan", status="fail", reason=f"auth failed with {SECRET}",
                              findings=(Finding("blocking", SECRET, f"rotate {SECRET}"),))

    out = run(cfg(project), project, "main", gates={"scan": Leaky, **fakes([], qa="pass", sentinel="pass")})
    assert out.exit_code == 1  # redacted, so the receipt is written and the gate's own verdict stands
    assert (out.run_dir / "receipt.json").is_file()
    written = _everything_written(out, project)
    assert SECRET not in written
    assert "auth failed with [redacted: secret-shaped string]" in out.lines[0]
    assert json.loads((out.run_dir / "verdict.json").read_text())["gates"][0]["reason"].endswith("[redacted: secret-shaped string]")
    assert out.warnings == ["3 secret-shaped string(s) in gate output were redacted before anything was written"]


def test_a_secret_in_a_crash_message_is_redacted(project):
    class Crash:
        name = "scan"

        def run(self, ctx):
            raise RuntimeError(f"token={SECRET}")

    out = run(cfg(project), project, "main", gates={"scan": Crash, **fakes([], qa="pass", sentinel="pass")})
    assert out.exit_code == 1
    assert SECRET not in _everything_written(out, project)
    assert "the gate crashed: RuntimeError: token=[redacted: secret-shaped string]" in out.lines[0]


def test_a_secret_shaped_receipt_key_refuses_the_receipt(project):
    class Leaky:
        name = "scan"

        def run(self, ctx):
            return GateResult(gate="scan", status="pass", receipt={SECRET: "value"})

    out = run(cfg(project), project, "main", gates={"scan": Leaky, **fakes([], qa="pass", sentinel="pass")})
    assert out.exit_code == 2
    assert not (out.run_dir / "receipt.json").exists()
    assert SECRET not in _everything_written(out, project)


def test_a_gate_module_is_found_by_name_and_a_missing_one_is_not_built(monkeypatch):
    import sys
    import types
    from securebuilderbot_core import runner as runner_mod

    fake = types.ModuleType("securebuilderbot_qa")
    fake.GATE = lambda: Fake("qa", "pass", [])
    monkeypatch.setitem(sys.modules, "securebuilderbot_qa", fake)
    monkeypatch.setitem(sys.modules, "securebuilderbot_scanners", None)  # not installed: no shim stands in
    monkeypatch.setitem(sys.modules, "securebuilderbot_sentinel", None)  # not installed, now that the module exists
    gates = runner_mod.default_gates()
    assert gates["qa"]().run(None).status == "pass"
    assert gates["scan"]().run(None).status == "not_run"
    assert gates["sentinel"]().run(None).status == "not_run"


def test_a_module_without_a_factory_is_not_a_gate(monkeypatch):
    import sys
    import types
    from securebuilderbot_core import runner as runner_mod

    monkeypatch.setitem(sys.modules, "securebuilderbot_sentinel", types.ModuleType("securebuilderbot_sentinel"))
    assert runner_mod.discover_gate("sentinel") is None


def test_receipt_carries_the_versions_of_the_vendored_standards(project):
    """One guarded import of the standards module: the receipt says which catalog the run resolved against."""
    out = run(cfg(project), project, "main", gates=fakes([], scan="pass", qa="pass", sentinel="pass"))
    r = json.loads((out.run_dir / "receipt.json").read_text())
    assert r["standards"]["catalog"] == "5.2.0"
    assert r["standards"]["masvs"] == "v2.1.0"


# ── a gate module is resolved inside the per-gate guard (core gate run 4, B-02) ──
# Discovery used to run before the gate loop and outside its try: a gate module that raised at
# import stopped every gate with a raw, unredacted traceback and no receipt, and one that called
# sys.exit(0), at import or inside run(), ended the run with exit 0 having checked nothing.


def _module(tmp_path: Path, monkeypatch, name: str, body: str) -> None:
    pkg = tmp_path / "mods" / name
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(body)
    monkeypatch.syspath_prepend(str(tmp_path / "mods"))
    # Leave sys.modules as the test found it. delitem alone restores an entry that was there and
    # forgets one that was not, so when the real module had not been imported yet the fake stayed
    # behind, and `pytest core/tests` on its own then failed test_verdict.py's age-limit tests
    # (gate run 3, N-06). setitem first records the original state, present or absent, for undo.
    modules = __import__("sys").modules
    for key in [name, *(k for k in modules if k.startswith(name + "."))]:
        monkeypatch.setitem(modules, key, modules.get(key))
        monkeypatch.delitem(modules, key)


def test_a_gate_module_that_raises_at_import_is_not_run_and_redacted(project, tmp_path, monkeypatch):
    (project / ".securebuilderbot.yml").write_text("profile: il6\ngates: [scan, qa]\nversion: latest\n")
    _module(tmp_path, monkeypatch, "securebuilderbot_scanners",
            "class _S:\n    def run(self, ctx):\n        from securebuilderbot_core.gate import GateResult\n"
            "        return GateResult(gate='scan', status='pass', reason='')\nGATE = _S\n")
    _module(tmp_path, monkeypatch, "securebuilderbot_qa", f"raise RuntimeError('broken qa install {SECRET}')\n")
    out = run(cfg(project), project, "main")
    assert out.exit_code == 1
    assert [r.gate for r in out.results] == ["scan", "qa"]
    assert out.results[0].status == "pass"  # the enabled scan gate still ran
    assert out.results[1].status == "not_run" and "RuntimeError" in out.results[1].reason
    assert (out.run_dir / "receipt.json").is_file() and (out.run_dir / "verdict.json").is_file()
    assert SECRET not in _everything_written(out, project)


def test_a_gate_module_that_exits_at_import_is_not_run_never_a_pass(project, tmp_path, monkeypatch):
    (project / ".securebuilderbot.yml").write_text("profile: il6\ngates: [scan]\nversion: latest\n")
    _module(tmp_path, monkeypatch, "securebuilderbot_scanners", "import sys\nsys.exit(0)\n")
    out = run(cfg(project), project, "main")
    assert out.exit_code == 1
    assert out.results[0].status == "not_run" and "SystemExit" in out.results[0].reason


def test_a_gate_that_exits_inside_run_is_not_run_never_a_pass(project):
    class Exits:
        name = "scan"

        def run(self, ctx):
            raise SystemExit(0)

    out = run(cfg(project), project, "main", gates={"scan": Exits, **fakes([], qa="pass", sentinel="pass")})
    assert out.exit_code == 1
    assert out.results[0].status == "not_run" and "SystemExit" in out.results[0].reason
    assert (out.run_dir / "verdict.json").is_file()


def test_a_keyboard_interrupt_still_stops_the_run(project):
    class Interrupted:
        name = "scan"

        def run(self, ctx):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run(cfg(project), project, "main", gates={"scan": Interrupted, **fakes([], qa="pass", sentinel="pass")})


# ── a gate's result is checked before it counts (core gate run 5, N-01, N-02, N-05) ──
# A status outside pass/fail/not_run read as a pass (Overall PASS, exit 0); a run() returning None
# crashed the runner after the guard with no receipt; a result naming another gate replaced that
# gate's receipt entry. Each is now that gate not running, named, with every output still written.


@pytest.mark.parametrize("bad", ["skipped", "PASS", "", None])
def test_a_status_outside_the_declared_ones_is_not_run_never_a_pass(project, bad):
    class Odd:
        name = "scan"

        def run(self, ctx):
            return GateResult(gate="scan", status=bad, reason="")

    out = run(cfg(project), project, "main", gates={"scan": Odd, **fakes([], qa="pass", sentinel="pass")})
    assert out.exit_code == 1
    assert out.results[0].status == "not_run" and "status" in out.results[0].reason
    assert (out.run_dir / "verdict.json").is_file()


def test_a_run_that_returns_no_result_is_not_run_and_the_outputs_are_written(project):
    class Nothing:
        name = "scan"

        def run(self, ctx):
            return None

    out = run(cfg(project), project, "main", gates={"scan": Nothing, **fakes([], qa="pass", sentinel="pass")})
    assert out.exit_code == 1 and out.results[0].status == "not_run"
    assert (out.run_dir / "receipt.json").is_file() and (out.run_dir / "verdict.json").is_file()


def test_a_result_naming_another_gate_is_not_run_and_cannot_replace_that_gate(project):
    calls = []
    gates = fakes(calls, scan="pass", sentinel="pass")

    class Impostor:
        name = "qa"

        def run(self, ctx):
            return GateResult(gate="scan", status="pass", reason="")

    out = run(cfg(project), project, "main", gates={**gates, "qa": Impostor})
    assert [r.gate for r in out.results] == ["scan", "qa", "sentinel"][: len(out.results)]
    assert out.results[1].gate == "qa" and out.results[1].status == "not_run"
    assert out.exit_code == 1
    receipt = json.loads((out.run_dir / "receipt.json").read_text())
    assert receipt["gates"]["scan"]["status"] == "pass" and receipt["gates"]["qa"]["status"] == "not_run"


# ── every gate is prepared before any gate runs (sentinel gate run 2, B-01) ──
# QA runs the pull request's own suite in this checkout. A gate that reads the checkout or .git
# after that reads what the suite left there, so core offers each gate a prepare(ctx) step first.


def test_every_gate_is_prepared_before_any_gate_runs_with_the_context_it_then_runs_with(project):
    events = []

    class Prepared:
        def __init__(self, name):
            self.name = name

        def prepare(self, ctx):
            events.append(("prepare", self.name, ctx))

        def run(self, ctx):
            events.append(("run", self.name, ctx))
            return GateResult(gate=self.name, status="pass")

    out = run(cfg(project), project, "main", gates={n: (lambda n=n: Prepared(n)) for n in ("scan", "qa", "sentinel")})
    assert out.exit_code == 0
    assert [e[:2] for e in events] == [("prepare", "scan"), ("prepare", "qa"), ("prepare", "sentinel"),
                                       ("run", "scan"), ("run", "qa"), ("run", "sentinel")]
    for name in ("scan", "qa", "sentinel"):
        prepared, ran = (e[2] for e in events if e[1] == name)
        assert prepared is ran and ran.run_dir.is_dir()


def test_a_gate_whose_prepare_crashes_is_not_run_at_its_turn_and_the_others_still_run(project):
    calls = []

    class BadPrepare:
        name = "qa"

        def prepare(self, ctx):
            raise RuntimeError("could not read the checkout")

        def run(self, ctx):
            raise AssertionError("never reached")

    out = run(cfg(project), project, "main", gates={**fakes(calls, scan="pass", sentinel="pass"), "qa": BadPrepare})
    assert [r.status for r in out.results] == ["pass", "not_run", "not_run"]
    assert out.results[1].reason == "the gate crashed: RuntimeError: could not read the checkout"
    assert [c[0] for c in calls] == ["scan"]
