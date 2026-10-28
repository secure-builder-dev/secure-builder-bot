"""The proof set replays green, and the replay would notice if it did not (SPEC-sentinel.md criterion 6).

The second half matters as much as the first: a replay that compares nothing passes every case. Each
negative case copies a real case, breaks one thing the replay is meant to compare, and asserts the
replay names it."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from securebuilderbot_sentinel import replay
from securebuilderbot_sentinel.replay import CASES_DIR, check_case, main

ROOT = Path(__file__).resolve().parents[2]
CASES = sorted(p.name for p in CASES_DIR.iterdir() if p.is_dir())


def test_the_proof_set_holds_the_cases_the_brief_names():
    assert CASES == ["docs-only", "pr-talks-reviewer-into-pass", "route-lost-auth", "secret-in-log", "tenant-scope-removed"]


@pytest.mark.parametrize("name", CASES)
def test_every_case_replays_green(name, tmp_path):
    result = check_case(CASES_DIR / name, tmp_path)
    assert result.problems == [], f"{name}: {result.problems}"


def copy_case(name: str, tmp_path: Path) -> Path:
    dst = tmp_path / "cases" / name
    shutil.copytree(CASES_DIR / name, dst)
    return dst


def edit_yaml(path: Path, change) -> None:
    doc = yaml.safe_load(path.read_text())
    change(doc)
    path.write_text(yaml.safe_dump(doc, sort_keys=False))


def test_a_reviewer_that_misses_a_finding_is_caught(tmp_path):
    case = copy_case("route-lost-auth", tmp_path)
    edit_yaml(case / "responses.yml", lambda d: d["checklist"]["answers"].pop(1))
    problems = check_case(case, tmp_path / "work").problems
    assert any("not raised: AC-3 backend/src/routes/notes.js:12" in p for p in problems)


def test_an_unexpected_finding_is_caught(tmp_path):
    case = copy_case("docs-only", tmp_path)
    edit_yaml(case / "responses.yml", lambda d: d["checklist"]["answers"].append(
        {"id": "B-13", "answer": "finding", "findings": [{"severity": "advisory", "rule_id": "SI-12", "path": "docs/guide.md",
                                                          "line": 7, "message": "m"}]}))
    problems = check_case(case, tmp_path / "work").problems
    assert any("raised but not expected: SI-12 docs/guide.md:7" in p for p in problems)


def test_a_wrong_depth_and_a_wrong_verdict_are_caught(tmp_path):
    case = copy_case("docs-only", tmp_path)
    edit_yaml(case / "expected.yml", lambda d: d.update(depth="deep", status="fail"))
    problems = check_case(case, tmp_path / "work").problems
    assert "depth: expected deep, the classifier chose light" in problems
    assert "status: expected fail, got pass" in problems


def test_an_instruction_that_reaches_the_model_is_caught(tmp_path):
    case = copy_case("pr-talks-reviewer-into-pass", tmp_path)
    edit_yaml(case / "expected.yml", lambda d: d["never_sent"].append("A small cleanup"))
    problems = check_case(case, tmp_path / "work").problems
    assert "sent to the model, and must never be: 'A small cleanup'" in problems


def test_a_verdict_that_moves_with_the_description_is_caught(tmp_path, monkeypatch):
    case = copy_case("docs-only", tmp_path)
    real = replay.run_case

    def moved(case_dir, work, pr_override=None):
        result, fake, ctx = real(case_dir, work, pr_override)
        if pr_override is not None:
            from dataclasses import replace
            result = replace(result, status="fail")
        return result, fake, ctx
    monkeypatch.setattr(replay, "run_case", moved)
    problems = check_case(case, tmp_path / "work").problems
    assert "the verdict changed without the pr_body: pass became fail" in problems


def test_a_wrong_count_of_removed_lines_and_wrong_requests_are_caught(tmp_path):
    case = copy_case("pr-talks-reviewer-into-pass", tmp_path)
    edit_yaml(case / "expected.yml", lambda d: d.update(sanitized_lines=2, requests=["checklist"], control_completeness=["CM-03"]))
    problems = check_case(case, tmp_path / "work").problems
    assert "sanitized_lines: expected 2, got 3" in problems
    assert any(p.startswith("requests: expected ['checklist']") for p in problems)
    assert "control_completeness: expected ['CM-03'], got []" in problems


def test_an_answer_outside_the_allowed_set_is_caught(tmp_path):
    case = copy_case("docs-only", tmp_path)
    edit_yaml(case / "expected.yml", lambda d: d.update(answers=["n/a"]))
    assert "B-01 answered cited; the case allows only n/a" in check_case(case, tmp_path / "work").problems


def test_main_reports_one_line_per_case_and_exits_on_any_problem(tmp_path, capsys):
    assert main(["--cases", str(CASES_DIR)]) == 0
    out = capsys.readouterr().out
    assert out.count("ok  ") == len(CASES) and f"proofset: {len(CASES)}/{len(CASES)} cases green" in out
    case = copy_case("docs-only", tmp_path)
    edit_yaml(case / "expected.yml", lambda d: d.update(status="fail"))
    assert main(["--cases", str(case.parent)]) == 1
    assert "FAIL docs-only" in capsys.readouterr().out


def test_sentinel_run_proofset_is_what_make_proofset_runs():
    out = subprocess.run([str(ROOT / "sentinel" / "run"), "proofset", "--case", "docs-only"], capture_output=True, text=True,
                         cwd=ROOT)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "ok   docs-only" in out.stdout
    targets = subprocess.run(["make", "-s", "-C", str(ROOT), "help"], capture_output=True, text=True).stdout
    assert any(line.split()[:1] == ["proofset"] for line in targets.splitlines())


def test_every_proof_set_file_is_test_data_by_the_qa_gate_s_own_convention():
    """The cases are deliberately buggy sample apps. Kept under tests/, the QA gate reads them as test
    data, so the bot gating itself does not count their routes as untested production code. This holds
    the location; QA is never taught a wider exclusion that would let a user's untested code hide."""
    from securebuilderbot_qa.coverage_changed import is_test_path

    files = [p.relative_to(ROOT).as_posix() for p in CASES_DIR.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    assert files, "no proof-set files found"
    assert [f for f in files if not is_test_path(f)] == []
