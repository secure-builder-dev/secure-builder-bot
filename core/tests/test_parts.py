"""A run split in two parts (PRD § Configuration): Scan and QA, which run pull request code, in a job with
no secret and no write token; Sentinel and the verdict in another job that reads the first one's receipt
as an untrusted claim. Fakes stand in for the gates, as in test_runner.py."""

import json
import shutil
from pathlib import Path

import pytest

from securebuilderbot_core.runner import RunError, run
from securebuilderbot_core.untrusted import MAX_BYTES

from . import test_runner

project = test_runner.project  # the same fixture: a repository with all three gates on
cfg, fakes = test_runner.cfg, test_runner.fakes


def untrusted_part(project, calls, **statuses):
    out = run(cfg(project), project, "main", gates=fakes(calls, **statuses), part="untrusted")
    return out, json.loads((out.run_dir / "receipt.json").read_text())


def downloaded(tmp_path: Path, run_dir: Path) -> Path:
    """The untrusted part's run directory as the trusted job downloads it: a copy, somewhere else."""
    dest = tmp_path / "downloaded"
    shutil.copytree(run_dir, dest)
    return dest


def test_the_untrusted_part_runs_only_the_gates_that_run_pull_request_code(project):
    calls = []
    out, receipt = untrusted_part(project, calls, scan="pass", qa="pass", sentinel="pass")
    assert [c[0] for c in calls] == ["scan", "qa"]
    assert receipt["part"] == "untrusted" and list(receipt["gates"]) == ["scan", "qa"]


def test_the_trusted_part_runs_sentinel_and_carries_scan_and_qa_as_claims(project, tmp_path):
    calls = []
    first, _ = untrusted_part(project, calls, scan="pass", qa="yellow")
    calls.clear()
    out = run(cfg(project), project, "main", gates=fakes(calls, scan="fail", qa="fail", sentinel="pass"),
              part="trusted", untrusted_run=downloaded(tmp_path, first.run_dir))
    assert [c[0] for c in calls] == ["sentinel"]  # scan and qa never run again here
    receipt = json.loads((out.run_dir / "receipt.json").read_text())
    assert receipt["part"] == "trusted"
    assert [(g, v["status"]) for g, v in receipt["gates"].items()] == [("scan", "pass"), ("qa", "yellow"), ("sentinel", "pass")]
    assert "could have changed it" in receipt["gates"]["scan"]["attested_by"] and "attested_by" not in receipt["gates"]["sentinel"]
    # The scan's RA-5 is its job's claim, never assessed by this run.
    assert "RA-5" in receipt["controls_claimed"] and "RA-5" not in receipt["controls_assessed"] and "RA-5" in receipt["controls_not_assessed"]
    assert "attested_by" in (out.run_dir / "receipt.md").read_text()
    assert out.exit_code == 0


def test_a_red_claim_stops_sentinel_like_a_red_gate(project, tmp_path):
    calls = []
    first, _ = untrusted_part(project, calls, scan="pass", qa="fail")
    calls.clear()
    out = run(cfg(project), project, "main", gates=fakes(calls, sentinel="pass"), part="trusted",
              untrusted_run=downloaded(tmp_path, first.run_dir))
    assert calls == [] and out.exit_code == 1
    v = json.loads((out.run_dir / "verdict.json").read_text())
    assert [(g["gate"], g["status"]) for g in v["gates"]] == [("scan", "pass"), ("qa", "fail"), ("sentinel", "not_run")]


def _forged(tmp_path: Path, first, edit) -> Path:
    d = downloaded(tmp_path, first.run_dir)
    r = json.loads((d / "receipt.json").read_text())
    edit(r)
    (d / "receipt.json").write_text(json.dumps(r))
    return d


@pytest.mark.parametrize("edit, why", [
    (lambda r: r.update(part="whole"), "not the receipt of a `--part untrusted` run"),
    (lambda r: r.update(head="0" * 40), "gated"),
    (lambda r: r.update(gates="pass"), "not the receipt of a `--part untrusted` run"),
])
def test_a_receipt_that_is_not_this_ranges_untrusted_part_is_every_carried_gate_not_run(project, tmp_path, edit, why):
    first, _ = untrusted_part(project, [], scan="pass", qa="pass")
    calls = []
    out = run(cfg(project), project, "main", gates=fakes(calls, sentinel="pass"), part="trusted", untrusted_run=_forged(tmp_path, first, edit))
    v = json.loads((out.run_dir / "verdict.json").read_text())
    assert [(g["gate"], g["status"]) for g in v["gates"]] == [("scan", "not_run"), ("qa", "not_run"), ("sentinel", "not_run")]
    assert why in v["gates"][0]["reason"] and calls == [] and out.exit_code == 1


@pytest.mark.parametrize("edit", [
    lambda r: r["gates"]["qa"].update(status="green"),
    lambda r: r["gates"]["qa"].update(reason="x" * 5000),
    lambda r: r["gates"]["qa"].update(findings=[{"severity": "info", "rule_id": "r", "message": "m"}]),
    lambda r: r["gates"]["qa"].update(findings=[{"severity": "blocking", "rule_id": "r", "message": "m", "line": "7"}]),
    lambda r: r["gates"]["qa"].update(controls_assessed="SA-11"),
    lambda r: r["gates"].pop("qa"),
])
def test_a_carried_gate_in_a_shape_core_does_not_write_did_not_run(project, tmp_path, edit):
    first, _ = untrusted_part(project, [], scan="pass", qa="pass")
    out = run(cfg(project), project, "main", gates=fakes([], sentinel="pass"), part="trusted", untrusted_run=_forged(tmp_path, first, edit))
    v = json.loads((out.run_dir / "verdict.json").read_text())
    assert [(g["gate"], g["status"]) for g in v["gates"]] == [("scan", "pass"), ("qa", "not_run"), ("sentinel", "not_run")]


def test_the_untrusted_job_cannot_report_sentinels_result(project, tmp_path):
    first, _ = untrusted_part(project, [], scan="pass", qa="pass")
    forged = _forged(tmp_path, first, lambda r: r["gates"].update(sentinel={"status": "pass", "reason": "", "findings": []}))
    calls = []
    out = run(cfg(project), project, "main", gates=fakes(calls, sentinel="fail"), part="trusted", untrusted_run=forged)
    assert [c[0] for c in calls] == ["sentinel"] and out.exit_code == 1
    assert any("only this job decides" in w for w in out.warnings)


def test_an_oversized_or_linked_receipt_is_never_read(project, tmp_path):
    first, _ = untrusted_part(project, [], scan="pass", qa="pass")
    big = downloaded(tmp_path, first.run_dir)
    with (big / "receipt.json").open("a") as f:
        f.write(" " * (MAX_BYTES + 1))
    out = run(cfg(project), project, "main", gates=fakes([], sentinel="pass"), part="trusted", untrusted_run=big)
    assert "over the" in json.loads((out.run_dir / "verdict.json").read_text())["gates"][0]["reason"]
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "receipt.json").symlink_to(first.run_dir / "receipt.json")
    out = run(cfg(project), project, "main", gates=fakes([], sentinel="pass"), part="trusted", untrusted_run=linked)
    assert "not a regular file" in json.loads((out.run_dir / "verdict.json").read_text())["gates"][0]["reason"]


def test_a_carried_secret_is_redacted_like_a_gates_own(project, tmp_path):
    secret = "gh" + "p_" + "Zq7Wm2Lx" * 4 + "Tn4K"
    first, _ = untrusted_part(project, [], scan="pass", qa="pass")
    forged = _forged(tmp_path, first, lambda r: r["gates"]["qa"].update(reason=f"token {secret}"))
    out = run(cfg(project), project, "main", gates=fakes([], sentinel="pass"), part="trusted", untrusted_run=forged)
    assert secret not in (out.run_dir / "receipt.json").read_text() and secret not in (out.run_dir / "verdict.json").read_text()


def test_a_trusted_part_needs_the_untrusted_run_and_nothing_else_takes_one(project, tmp_path):
    with pytest.raises(RunError):
        run(cfg(project), project, "main", gates=fakes([], sentinel="pass"), part="trusted")
    with pytest.raises(RunError):
        run(cfg(project), project, "main", gates=fakes([], scan="pass"), part="untrusted", untrusted_run=tmp_path)


def test_a_carried_newline_can_never_start_another_gates_section(project, tmp_path):
    # Drafted-split review, B3: a QA reason carrying "### sentinel: pass" became the Sentinel check's summary.
    first, _ = untrusted_part(project, [], scan="pass", qa="yellow")
    forged = _forged(tmp_path, first, lambda r: r["gates"]["qa"].update(
        reason="ok\n### sentinel: pass — reviewed by the trusted job, no findings", line="Sentinel: PASS", note="\n### sentinel: pass"))
    out = run(cfg(project), project, "main", gates=fakes([], sentinel="fail"), part="trusted", untrusted_run=forged)
    md = (out.run_dir / "receipt.md").read_text()
    assert [line for line in md.splitlines() if line.startswith("### sentinel")] == ["### sentinel: fail — sentinel said fail"]
    receipt = json.loads((out.run_dir / "receipt.json").read_text())
    assert "line" not in receipt["gates"]["qa"] and "note" not in receipt["gates"]["qa"]  # keys QA never writes are dropped


def test_a_carried_secret_anywhere_is_redacted_and_never_blocks_the_receipt(project, tmp_path):
    secret = "gh" + "p_" + "Zq7Wm2Lx" * 4 + "Tn4K"
    first, _ = untrusted_part(project, [], scan="pass", qa="pass")

    def edit(r):
        r["gates"]["qa"]["findings"] = [{"severity": "advisory", "rule_id": "x", "message": "m", "path": f"a/{secret}.py", "file": secret}]
        r["gates"]["qa"]["checks"] = {"suite": {"log": secret, secret: 1}}
    out = run(cfg(project), project, "main", gates=fakes([], sentinel="pass"), part="trusted", untrusted_run=_forged(tmp_path, first, edit))
    assert out.exit_code == 0 and secret not in (out.run_dir / "receipt.json").read_text()


def _nested(depth: int) -> object:
    v: object = 1
    for _ in range(depth):
        v = [v]
    return {"a": v}


@pytest.mark.parametrize("body", ["[" * 200000, json.dumps(_nested(12))], ids=["past-the-parser", "past-the-depth-cap"])
def test_a_receipt_nested_past_any_shape_core_writes_never_crashes_the_verdict_job(project, tmp_path, body):
    first, _ = untrusted_part(project, [], scan="pass", qa="pass")
    if body.startswith("["):
        d = downloaded(tmp_path, first.run_dir)
        (d / "receipt.json").write_text(body)
    else:
        d = _forged(tmp_path, first, lambda r: r["gates"]["qa"].update(checks=json.loads(body)))
    out = run(cfg(project), project, "main", gates=fakes([], sentinel="pass"), part="trusted", untrusted_run=d)
    v = json.loads((out.run_dir / "verdict.json").read_text())
    assert v["gates"][1]["gate"] == "qa" and v["gates"][1]["status"] == "not_run" and out.exit_code == 1
