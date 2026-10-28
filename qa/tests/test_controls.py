"""The control-tool wrapper: what the gate reads out of derive-controls, verify-controls and mutate-controls."""

from __future__ import annotations

from pathlib import Path

from securebuilderbot_qa.controls import (
    MutationRow,
    failed_rows,
    parse_mutation_table,
    run_tool,
    unproven_rows,
    unregistered_guards,
)

from .conftest import commit_all

DERIVE = """  registered CM-01 pkg/auth.py:6  require_admin  [403]
  UNREGISTERED  pkg/auth.py:11  require_login  [401]
  not-a-control pkg/auth.py:26  exempt  [403]
  UNREGISTERED  pkg/views/orders.py:40  delete_order  [404]
── derive-controls: 2 of 4 guard site(s) belong to no manifest row and carry no reason
"""
VERIFY = """  ok    CM-01  token gate  (1 call site)
  FAIL  CM-11  comment-only
        NO production call site
  FAIL  CM-12  never wired
        symbol 'neverWired' not defined in x.ts; NO production call site
"""
MUTATE = """suite: python3 -m pytest -q -x

| id | control | mutation | suite | verdict |
|---|---|---|---|---|
| CM-01 | token gate | noop → `return None` @ pkg/auth.py:6 | RED (own test) | ✓ proven |
| CM-02 | redaction | redact → `return text` @ pkg/guard.py:12 | GREEN | ✗ NOT PROVEN |
| CM-03 | ghost | — | — | ✗ unlocatable: nothingHere not defined in pkg/x.py |
| CM-04 | one-liner | pkg/y.py:3 (noop) | — | ✗ manual: one-line def — give it a block body |
| CM-05 | old | — | — | ○ unchanged since abc1234 — not re-proven here; cite the last full run |

5 control(s) · elapsed 3s
NOT PROVEN: CM-02 — the suite stays green with the control disabled; these tests have no teeth
"""


def test_unregistered_guards_are_read_from_the_list():
    assert [(g.path, g.line, g.symbol, g.kind) for g in unregistered_guards(DERIVE)] == [
        ("pkg/auth.py", 11, "require_login", "401"), ("pkg/views/orders.py", 40, "delete_order", "404")]
    assert unregistered_guards("derive-controls: 0 guard site(s) in 0 function(s)") == []


def test_failed_verify_rows_carry_their_problems():
    assert failed_rows(VERIFY) == [("CM-11", "comment-only", "NO production call site"),
                                   ("CM-12", "never wired", "symbol 'neverWired' not defined in x.ts; NO production call site")]
    assert failed_rows("  ok    CM-01  x  (2 call sites)\n  1 controls · 0 FAIL\n") == []


def test_the_mutation_table_is_parsed_and_every_row_the_suite_survived_is_unproven():
    rows = parse_mutation_table(MUTATE)
    assert [r.id for r in rows] == ["CM-01", "CM-02", "CM-03", "CM-04", "CM-05"]
    assert rows[0] == MutationRow("CM-01", "token gate", "noop → `return None` @ pkg/auth.py:6", "RED (own test)", "✓ proven")
    assert [r.id for r in unproven_rows(rows)] == ["CM-02", "CM-03", "CM-04"]  # NOT PROVEN, unlocatable and manual; unchanged is not


def test_run_tool_keeps_the_output_as_an_evidence_file(repo: Path, tmp_path: Path):
    (repo / "project.config.yaml").write_text("APP_TRACK: web\n")
    commit_all(repo, "cfg")
    t = run_tool(repo, tmp_path / "run", "derive-controls", "--list")
    assert t.tool == "derive-controls" and t.code == 0 and t.log == tmp_path / "run" / "derive-controls.log"
    assert "0 unregistered" in t.log.read_text()


def test_run_tool_keeps_no_secret_shaped_string_a_tool_printed(repo: Path, tmp_path: Path, monkeypatch):
    # mutate-controls prints the user's suite output; whatever it echoes is redacted before the run keeps it.
    import securebuilderbot_qa.controls as controls
    from securebuilderbot_core.receipt import REDACTED
    secret = "gl" + "pat-" + "Zy9Xw8Vu7Ts6Rq5Po4Nm"
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "mutate-controls.sh").write_text(f"echo 'suite said {secret}'\nexit 1\n")
    monkeypatch.setattr(controls, "SCRIPTS", scripts)
    t = run_tool(repo, tmp_path / "run", "mutate-controls")
    assert t.code == 1 and secret not in t.output and REDACTED in t.log.read_text()
    assert not [f for f in (tmp_path / "run").rglob("*") if f.is_file() and secret in f.read_text()]


def test_only_the_gate_points_a_control_tool_at_another_list(tmp_path: Path, monkeypatch):
    # CONTROL_MANIFEST redirects mutate-controls to a drafted list. An inherited one (a CI variable, or one
    # pull request code exported) must never reach a tool: only run_tool's own argument sets it.
    import securebuilderbot_qa.controls as controls
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "probe.sh").write_text('echo "list=[${CONTROL_MANIFEST:-unset}]"\n')
    monkeypatch.setattr(controls, "SCRIPTS", scripts)
    monkeypatch.setenv("CONTROL_MANIFEST", str(tmp_path / "a-forged-list.md"))
    repo = tmp_path / "repo"
    repo.mkdir()
    assert "list=[unset]" in run_tool(repo, tmp_path / "run", "probe").log.read_text()
    draft = tmp_path / "draft.md"
    assert f"list=[{draft}]" in run_tool(repo, tmp_path / "run2", "probe", manifest=draft).log.read_text()


def test_a_list_declares_its_control_rows_only():
    from securebuilderbot_qa.controls import rows_in
    header = "| id | control | implementation | required artifact | proving test | note |\n|---|---|---|---|---|---|\n"
    assert rows_in("") == 0 and rows_in(header) == 0
    text = header + "| CM-01 | x | `a.py:f` | - | - | n |\n| CM-02 | y | `a.py:g` | - | - | n |\n"
    assert rows_in(text) == 2
    text += "| CM-03 | a placeholder | <file>:<symbol> | - | - | n |\n| CM-04 | not yet | - | - | - | n |\n"
    assert rows_in(text) == 2  # a row the tools skip declares nothing
