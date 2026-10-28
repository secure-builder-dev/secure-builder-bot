"""The QA gate end to end, on the fixture Python project (SPEC-qa.md success criterion 1).

Every case copies the fixture into a real git repository, commits it as the base, makes the
change under test, commits it as the head, and runs the gate on that range: the real pytest,
the real control tools, no mocks.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from securebuilderbot_core.config import load_config
from securebuilderbot_core.gate import GateContext
from securebuilderbot_core.profiles import load_profile
from securebuilderbot_qa import GATE
from securebuilderbot_qa.gate import QaGate

from .conftest import commit_all, git

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "pyapp"
DOT = "."
MARK_SKIP = "@pytest.mark" + DOT + "skip(reason='later')"


@pytest.fixture
def project(repo: Path) -> Path:
    shutil.copytree(FIXTURE, repo, dirs_exist_ok=True)
    commit_all(repo, "fixture")
    return repo


def write(repo: Path, path: str, text: str) -> None:
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def append(repo: Path, path: str, text: str) -> None:
    (repo / path).write_text((repo / path).read_text() + text)


def run_gate(repo: Path, tmp_path: Path, profile: str = "il6", config=None):
    base = git(repo, "rev-parse", "HEAD~1")
    head = git(repo, "rev-parse", "HEAD")
    run_dir = tmp_path / "run" / "qa"
    run_dir.mkdir(parents=True)
    ctx = GateContext(repo=repo, base=base, head=head, profile=load_profile(profile), depth="deep", run_dir=run_dir, config=config)
    return QaGate().run(ctx)


def blocking(result):
    return [(f.rule_id, f.path, f.line) for f in result.findings if f.severity == "blocking"]


def test_gate_is_exported_by_name_for_core():
    assert GATE().name == "qa"


def test_a_green_suite_with_covered_lines_and_a_proven_control_passes(project: Path, tmp_path: Path):
    append(project, "app/routes.py", "\n\ndef item_names():\n    return sorted(i['name'] for i in ITEMS.values())\n")
    append(project, "tests/check_routes.py", "\n\ndef test_item_names():\n    from app.routes import item_names\n    assert item_names() == ['one', 'two']\n")
    commit_all(project, "a covered helper")
    r = run_gate(project, tmp_path)
    assert r.status == "pass", (r.reason, blocking(r))
    assert r.receipt["controls_assessed"] == ["SA-11", "SA-11(1)"]
    checks = r.receipt["checks"]
    assert [checks[c]["result"] for c in ("suite", "coverage", "negative_tests", "mocked_db", "mutation")] == ["pass"] * 5
    assert checks["suite"]["runners"][0]["runner"] == "pytest" and checks["suite"]["runners"][0]["counts"]["passed"] == 4
    assert checks["coverage"]["covered"] == checks["coverage"]["executable"] == 2 and checks["coverage"]["minimum"] == 90
    assert [(m["id"], m["verdict"]) for m in r.receipt["mutation_table"]] == [("CM-01", "✓ proven"), ("CM-02", "✓ proven")]
    assert (tmp_path / "run" / "qa" / "mutate-controls.log").is_file() and (tmp_path / "run" / "qa" / "coverage.txt").is_file()
    assert json.dumps(r.receipt)  # the receipt section is plain JSON


def test_a_route_without_a_negative_test_fails_at_its_line(project: Path, tmp_path: Path):
    append(project, "app/routes.py", "\n\n@route(\"/items\")\ndef list_items(request):\n    require_user(request)\n    return list(ITEMS)\n")
    append(project, "tests/check_routes.py", "\n\ndef test_list():\n    assert handle(\"/items\", Request(\"alice\")) == (200, [\"1\", \"2\"])\n")
    commit_all(project, "a route with no 403 test")
    r = run_gate(project, tmp_path)
    assert r.status == "fail"
    assert ("AC-3", "app/routes.py", 13) in blocking(r)
    assert any("unauthenticated rejection" in f.message for f in r.findings)
    assert r.receipt["checks"]["negative_tests"]["result"] == "fail"


def test_a_mocked_database_in_an_integration_test_fails(project: Path, tmp_path: Path):
    write(project, "api/test/integration/orders.test.js", "jest.mock('./db');\ntest('x', () => {});\n")
    commit_all(project, "mocked db")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and ("mocked-db", "api/test/integration/orders.test.js", 1) in blocking(r)


def test_a_skip_added_in_the_range_fails_unless_a_commit_names_a_ticket(project: Path, tmp_path: Path):
    append(project, "tests/check_routes.py", "\n\nimport pytest\n\n\n" + MARK_SKIP + "\ndef test_later():\n    assert False\n")
    commit_all(project, "skip one")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and ("skip", "tests/check_routes.py", 20) in blocking(r)
    append(project, "tests/check_routes.py", "\n# tracked\n")
    commit_all(project, "quarantine the flaky case, tracked in T-QA-99")
    git(project, "reset", "-q", "--soft", "HEAD~2")
    commit_all(project, "skip one, tracked in T-QA-99")
    assert run_gate(project, tmp_path / "again").status == "pass"


def test_coverage_below_the_profile_fails_and_above_passes(project: Path, tmp_path: Path):
    append(project, "app/routes.py", "\n\ndef describe(id):\n    if id in ITEMS:\n        return ITEMS[id]['name']\n    return 'none'\n")
    append(project, "tests/check_routes.py", "\n\ndef test_describe():\n    from app.routes import describe\n    assert describe('1') == 'one'\n")
    commit_all(project, "three of four lines covered")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and ("coverage", None, None) in blocking(r)
    assert r.receipt["checks"]["coverage"]["percent"] == pytest.approx(75.0, abs=0.1)
    assert run_gate(project, tmp_path / "none", profile="none").status == "pass"  # 60% at profile none


def test_a_manifest_row_that_survives_mutation_fails(project: Path, tmp_path: Path):
    append(project, "app/auth.py", "\n\ndef redact_token(text):\n    return text.replace('secret', '[x]')\n")
    append(project, "app/routes.py", "\nfrom app.auth import redact_token\n\n\ndef shown(text):\n    return redact_token(text)\n")
    append(project, "tests/check_routes.py", "\n\ndef test_shown_runs():\n    from app.routes import shown\n    assert shown('secret') is not None\n")
    append(project, "docs/security/CONTROL-MANIFEST.md", "| CM-03 | token redaction | `app/auth.py:redact_token` | - | `check_routes.py` | mutate:redact |\n")
    commit_all(project, "a control no test has teeth for")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and ("SA-11", "docs/security/CONTROL-MANIFEST.md", None) in blocking(r)
    assert [(m["id"], m["verdict"]) for m in r.receipt["mutation_table"]] == [("CM-01", "✓ proven"), ("CM-02", "✓ proven"), ("CM-03", "✗ NOT PROVEN")]


def test_a_guard_with_no_manifest_row_is_refused_and_drafted(project: Path, tmp_path: Path):
    append(project, "app/auth.py", "\n\ndef require_admin(request):\n    if request.user != 'root':\n        raise PermissionDenied('admins only')\n")
    append(project, "app/routes.py", "\nfrom app.auth import require_admin\n\n\n@route('/admin')\ndef admin(request):\n    require_admin(request)\n    return 'ok'\n")
    append(project, "tests/check_routes.py", "\n\ndef test_admin_refused_403():\n    from app.auth import require_admin\n    assert handle('/admin', Request('alice')) == (403, None)\n    assert handle('/admin', Request('root')) == (200, 'ok')\n    assert require_admin(Request('root')) is None\n")
    commit_all(project, "an unregistered guard")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and ("unregistered-control", "app/auth.py", 19) in blocking(r)
    draft = (tmp_path / "run" / "qa" / "manifest-draft.md").read_text()
    assert "`app/auth.py:require_admin`" in draft and "`check_routes.py`" in draft
    assert r.receipt["checks"]["mutation"]["manifest_draft"] == "qa/manifest-draft.md"


# ── A declared list: only the rows a pull request touches are sabotage-tested again ─────────────

def _verdicts(r) -> dict[str, str]:
    return {row["id"]: row["verdict"] for row in r.receipt["mutation_table"]}


def test_a_pull_request_that_touches_no_control_reproves_none(project: Path, tmp_path: Path):
    append(project, "app/routes.py", "\n")
    commit_all(project, "a change no control rests on")
    r = run_gate(project, tmp_path)
    assert r.status == "pass", r.reason
    assert all(v.startswith("○") for v in _verdicts(r).values()), _verdicts(r)


def test_a_pull_request_that_edits_one_row_of_the_list_reproves_that_row_only(project: Path, tmp_path: Path):
    manifest = project / "docs" / "security" / "CONTROL-MANIFEST.md"
    manifest.write_text(manifest.read_text().replace("| the owner only |", "| the owner only, never another user |"))
    commit_all(project, "reword one row")
    r = run_gate(project, tmp_path)
    verdicts = _verdicts(r)
    assert r.status == "pass", r.reason
    assert verdicts["CM-02"] == "✓ proven" and verdicts["CM-01"].startswith("○"), verdicts
    assert r.receipt["checks"]["mutation"]["scope"].startswith("rows changed since")


# ── No control list: QA drafts one and sabotage-tests it, yellow until a person confirms it ─────────

def _without_list(project: Path, body: str | None = None) -> None:
    """A repository whose target branch keeps no list (or only its header), and a pull request on top of it."""
    manifest = project / "docs" / "security" / "CONTROL-MANIFEST.md"
    if body is None:
        manifest.unlink()
    else:
        manifest.write_text(body)
    commit_all(project, "no control list on the target branch")
    append(project, "app/routes.py", "\n")
    commit_all(project, "the pull request")


def test_with_no_control_list_qa_sabotage_tests_the_drafted_controls_and_is_yellow_never_green(project: Path, tmp_path: Path):
    _without_list(project)
    r = run_gate(project, tmp_path)
    assert r.status == "yellow", (r.reason, blocking(r))
    assert "no security controls are declared" in r.reason and "2 drafted control(s) sabotage-tested, 2 caught" in r.reason
    assert [(m["control"].split(" ")[0], m["verdict"]) for m in r.receipt["mutation_table"]] == [("require_user", "✓ proven"), ("require_owner", "✓ proven")]
    assert all(f.severity == "advisory" for f in r.findings if f.rule_id == "unregistered-control")
    mutation = r.receipt["checks"]["mutation"]
    assert mutation["drafted"] == 2 and mutation["manifest_draft"] == "qa/manifest-draft.md"
    assert r.receipt["controls_assessed"] == []  # nothing a person confirmed is claimed


def test_an_empty_control_list_is_the_same_as_none(project: Path, tmp_path: Path):
    _without_list(project, "| id | control | implementation | required artifact | proving test | note |\n|---|---|---|---|---|---|\n")
    r = run_gate(project, tmp_path)
    assert r.status == "yellow" and "no security controls are declared" in r.reason


def test_a_drafted_control_the_suite_survives_is_named_but_does_not_block(project: Path, tmp_path: Path):
    append(project, "app/auth.py", "\n\ndef redact_token(text):\n    return text.replace('secret', '[x]')\n")
    append(project, "app/routes.py", "\nfrom app.auth import redact_token\n\n\ndef shown(text):\n    return redact_token(text)\n")
    append(project, "tests/check_routes.py", "\n\ndef test_shown_runs():\n    from app.routes import shown\n    assert shown('secret') is not None\n")
    _without_list(project)
    r = run_gate(project, tmp_path)
    assert r.status == "yellow", (r.reason, blocking(r))
    weak = [f for f in r.findings if f.rule_id == "SA-11"]
    assert len(weak) == 1 and weak[0].severity == "advisory" and "redact_token" in weak[0].message
    assert "3 drafted control(s) sabotage-tested, 2 caught" in r.reason


HEADER_ONLY = "| id | control | implementation | required artifact | proving test | note |\n|---|---|---|---|---|---|\n"


def _gate_at(project: Path, tmp_path: Path, base: str, head: str, config_ref: str = "") -> tuple[QaGate, GateContext]:
    run_dir = tmp_path / "run" / "qa"
    run_dir.mkdir(parents=True)
    ctx = GateContext(repo=project, base=base, head=head, profile=load_profile("il6"), depth="deep", run_dir=run_dir, config_ref=config_ref)
    g = QaGate()
    g.prepare(ctx)
    return g, ctx


def test_a_pull_request_that_deletes_or_empties_the_target_branchs_control_list_fails(project: Path, tmp_path: Path):
    # The target branch declares rows; a pull request that removes them must not drop QA to the drafted
    # mode's yellow (drafted-mode review, B-1).
    manifest = project / "docs" / "security" / "CONTROL-MANIFEST.md"
    removed = ("control-list-removed", "docs/security/CONTROL-MANIFEST.md", None)
    manifest.unlink()
    commit_all(project, "delete the list")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and removed in blocking(r) and "removes every row" in r.reason
    git(project, "reset", "-q", "--hard", "HEAD~1")
    manifest.write_text(HEADER_ONLY)
    commit_all(project, "empty it instead")
    r = run_gate(project, tmp_path / "empty")
    assert r.status == "fail" and removed in blocking(r)


def test_a_branch_cut_before_the_target_gained_its_list_is_told_to_merge_it_in(project: Path, tmp_path: Path):
    manifest = project / "docs" / "security" / "CONTROL-MANIFEST.md"
    kept = manifest.read_text()
    manifest.unlink()
    commit_all(project, "no list yet")
    fork = git(project, "rev-parse", "HEAD")
    manifest.write_text(kept)
    commit_all(project, "the target branch gains its list")
    target = git(project, "rev-parse", "HEAD")
    git(project, "checkout", "-q", "-b", "pr", fork)
    append(project, "app/routes.py", "\n")
    commit_all(project, "the pull request")
    g, ctx = _gate_at(project, tmp_path, fork, git(project, "rev-parse", "HEAD"), config_ref=target)
    r = g.run(ctx)
    assert r.status == "fail" and "merge the target branch in" in r.reason and "removes" not in r.reason


def test_the_control_tools_read_the_head_commits_list_never_the_checkouts_file(project: Path, tmp_path: Path):
    # The list is pinned by blob in prepare(): deleting the checkout's file afterwards changes nothing.
    append(project, "app/auth.py", "\n")  # the controls' own file, so both rows are sabotage-tested again
    commit_all(project, "a pull request")
    g, ctx = _gate_at(project, tmp_path, git(project, "rev-parse", "HEAD~1"), git(project, "rev-parse", "HEAD"))
    (project / "docs" / "security" / "CONTROL-MANIFEST.md").unlink()  # what the Scan gate's PR code could do
    r = g.run(ctx)
    assert r.status == "pass" and len(r.receipt["mutation_table"]) == 2


def test_a_pull_requests_tests_cannot_rewrite_the_list_the_mutation_reads(project: Path, tmp_path: Path):
    # Drafted-mode review round 2, B1: the PR drops CM-02's proving test and ships a conftest that, while
    # the suite runs, rewrites CM-02's mutation into one any suite survives. The committed list is untouched.
    tests = project / "tests" / "check_routes.py"
    tests.write_text(tests.read_text().split("def test_user_a_cannot_read_user_b_item")[0])
    write(project, "tests/conftest.py",
          "from pathlib import Path\n"
          "p = Path(__file__).resolve().parents[1] / 'docs/security/CONTROL-MANIFEST.md'\n"
          "p.write_text(p.read_text().replace('mutate:replace=item[\"owner\"] != user ~> False', 'mutate:replace=return item ~> return None'))\n")
    commit_all(project, "the pull request")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and any(f.rule_id == "SA-11" and "CM-02" in f.message for f in r.findings)


def test_a_control_list_that_is_a_link_is_never_read_as_none(project: Path, tmp_path: Path):
    manifest = project / "docs" / "security" / "CONTROL-MANIFEST.md"
    manifest.unlink()
    manifest.symlink_to("/dev/null")
    commit_all(project, "the list is a link")
    r = run_gate(project, tmp_path)
    assert r.status == "not_run" and "is a link" in r.reason


def test_mutation_off_with_no_control_list_is_yellow_never_green(project: Path, tmp_path: Path):
    write(project, ".securebuilderbot.yml", "profile: none\ngates: [qa]\nversion: latest\nqa:\n  mutation: false\n")
    _without_list(project)
    r = run_gate(project, tmp_path, profile="none")
    assert r.status == "yellow" and "no security controls are declared" in r.reason


def test_a_long_draft_is_sabotage_tested_up_to_a_cap_and_says_so(project: Path, tmp_path: Path, monkeypatch):
    import securebuilderbot_qa.gate as qa_gate
    monkeypatch.setattr(qa_gate, "DRAFT_MUTATION_CAP", 1)
    _without_list(project)
    r = run_gate(project, tmp_path)
    assert r.status == "yellow" and len(r.receipt["mutation_table"]) == 1
    assert "the first 1 of 2 drafted control(s) sabotage-tested" in r.reason


def test_no_control_list_and_nothing_to_draft_is_yellow_and_says_the_check_proved_nothing(project: Path, tmp_path: Path):
    config = project / "project.config.yaml"
    config.write_text(config.read_text().replace("CONTROL_SRC_ROOTS: app", "CONTROL_SRC_ROOTS: nowhere"))
    _without_list(project)
    r = run_gate(project, tmp_path)
    assert r.status == "yellow" and "none were found to draft, so the sabotage check proved nothing" in r.reason
    assert r.receipt["mutation_table"] == []


# ── No config either: the roots and the suite command come from the layout (2026-10-28) ────────────

def _no_config(project: Path) -> None:
    """A Python repository that names no control roots: no project.config.yaml, a requirements.txt."""
    (project / "project.config.yaml").unlink()
    write(project, "requirements.txt", "pytest\n")


def test_a_python_repository_with_no_config_has_its_drafted_controls_sabotage_tested_from_the_layout(project: Path, tmp_path: Path):
    _no_config(project)
    _without_list(project)
    r = run_gate(project, tmp_path)
    assert r.status == "yellow", (r.reason, blocking(r))
    assert "2 drafted control(s) sabotage-tested, 2 caught" in r.reason
    assert [(m["control"].split(" ")[0], m["verdict"]) for m in r.receipt["mutation_table"]] == [("require_user", "✓ proven"), ("require_owner", "✓ proven")]
    run = tmp_path / "run" / "qa"
    assert "inferred the control roots app (*.py) from the layout" in (run / "derive-controls.log").read_text()
    assert "suite: python3 -m pytest -q -x (inferred from the layout" in (run / "mutate-controls.log").read_text()
    assert r.receipt["controls_assessed"] == []


def test_an_inferred_suite_command_that_is_not_green_leaves_qa_yellow_and_says_why_never_not_run(project: Path, tmp_path: Path):
    _no_config(project)
    write(project, "tests/conftest.py", "import sys\n\nif '-x' in sys.argv:\n    raise SystemExit('this suite has its own command')\n")
    _without_list(project)
    r = run_gate(project, tmp_path)
    assert r.status == "yellow", (r.reason, blocking(r))
    assert "python3 -m pytest -q -x is red before any mutation" in r.reason and "CONTROL_TEST_CMD" in r.reason
    assert "2 control(s) drafted" in r.reason and r.receipt["mutation_table"] == []
    assert r.receipt["checks"]["mutation"]["result"] == "yellow"


def test_a_declared_list_reads_the_config_as_before_never_the_inferred_roots(project: Path, tmp_path: Path):
    # The list is declared and nothing names its roots: the tools read the track's defaults, exactly as
    # before inference existed, so the default suite runs and QA cannot run, rather than borrowing the layout's.
    _no_config(project)
    commit_all(project, "no config")
    append(project, "app/auth.py", "\n")  # the controls' own file, so they are sabotage-tested on any narrowing
    commit_all(project, "the pull request")
    r = run_gate(project, tmp_path)
    assert r.status == "not_run" and "mutate-controls could not run" in r.reason
    run = tmp_path / "run" / "qa"
    assert "inferred" not in (run / "derive-controls.log").read_text() and "inferred" not in (run / "mutate-controls.log").read_text()


def test_mutation_off_by_config_is_yellow_when_the_profile_requires_it(project: Path, tmp_path: Path):
    write(project, ".securebuilderbot.yml", "profile: il6\ngates: [qa]\nversion: latest\nqa:\n  mutation: false\n")
    commit_all(project, "turn mutation off")
    r = run_gate(project, tmp_path)
    assert r.status == "yellow" and "mutation" in r.reason
    assert r.receipt["checks"]["mutation"]["result"] == "skipped" and r.receipt["controls_assessed"] == []


def test_the_config_core_hands_the_gate_governs_not_the_checkouts_file(project: Path, tmp_path: Path):
    # The pull request turns mutation off in its own copy; the base branch's copy, which core hands the
    # gate, leaves it on, so mutation runs and the result is not the relaxation's yellow.
    write(project, ".securebuilderbot.yml", "profile: il6\ngates: [qa]\nversion: latest\nqa:\n  mutation: false\n")
    commit_all(project, "turn mutation off")
    base_copy = tmp_path / "base" / ".securebuilderbot.yml"
    base_copy.parent.mkdir()
    base_copy.write_text("profile: il6\ngates: [qa]\nversion: latest\n")
    r = run_gate(project, tmp_path, config=load_config(base_copy))
    assert r.status == "pass", (r.reason, blocking(r))
    assert r.receipt["checks"]["mutation"]["result"] != "skipped"


def test_a_file_listed_in_constraintsignore_may_carry_the_patterns_as_data(project: Path, tmp_path: Path):
    # The floor guard's answer to a test that holds the very strings it looks for; the gate honours the same list.
    write(project, ".constraintsignore", "# fixture data for the pattern checks\ntests/check_patterns.py\n")
    commit_all(project, "the ignore list, merged first")  # it is read from the base, like every excusing list
    write(project, "tests/check_patterns.py", 'SKIP = "' + MARK_SKIP + '"\nMOCK = "jest.mock(\'./db\')"\nSERVER = "import app from \'./server\'"\n')
    commit_all(project, "pattern fixtures")
    r = run_gate(project, tmp_path)
    assert r.status == "pass", (r.reason, blocking(r))


def test_an_ignore_list_the_pull_request_adds_excuses_nothing_until_it_is_merged(project: Path, tmp_path: Path):
    write(project, "tests/check_patterns.py", 'SKIP = "' + MARK_SKIP + '"\n')
    write(project, ".constraintsignore", "tests/\n")  # the pull request excusing its own skip
    commit_all(project, "skip a test and excuse it")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and any(rule == "skip" for rule, _, _ in blocking(r))


def test_the_ignore_list_is_read_in_prepare_before_any_gate_runs_pull_request_code(project: Path, tmp_path: Path, monkeypatch):
    import securebuilderbot_qa.gate as qa_gate
    write(project, "tests/check_patterns.py", 'SKIP = "' + MARK_SKIP + '"\n')
    commit_all(project, "skip a test")
    base, head = git(project, "rev-parse", "HEAD~1"), git(project, "rev-parse", "HEAD")
    run_dir = tmp_path / "run" / "qa"
    run_dir.mkdir(parents=True)
    ctx = GateContext(repo=project, base=base, head=head, profile=load_profile("il6"), depth="deep", run_dir=run_dir)
    g = QaGate()
    g.prepare(ctx)
    monkeypatch.setattr(qa_gate, "blob_at", lambda *a: ("100644", b"tests/\n"))  # a forged object, after prepare
    r = g.run(ctx)
    assert r.status == "fail" and any(rule == "skip" for rule, _, _ in blocking(r))


def test_no_test_runner_is_not_run_never_a_pass(repo: Path, tmp_path: Path):
    write(repo, "README.md", "nothing here\n")
    commit_all(repo, "docs")
    r = run_gate(repo, tmp_path)
    assert r.status == "not_run" and "no test runner" in r.reason


def test_the_users_own_test_command_runs_in_place_of_the_adapters(project: Path, tmp_path: Path):
    write(project, ".securebuilderbot.yml", "profile: il6\ngates: [qa]\nversion: latest\nqa:\n  test_command: 'python3 -m pytest -q -p no:cacheprovider --cov=. --cov-report=lcov:coverage.lcov'\n")
    commit_all(project, "own command")
    r = run_gate(project, tmp_path)
    assert r.receipt["checks"]["suite"]["runners"][0]["runner"] == "command"
    assert r.status == "pass", (r.reason, blocking(r))


def test_a_skip_in_a_test_file_whose_name_holds_a_space_fails(project: Path, tmp_path: Path):
    # Git ends the `+++` header with a tab after such a name; keyed by the header, the file was never read.
    write(project, "tests/check_more items.py", "import pytest\n\n\n" + MARK_SKIP + "\ndef test_later():\n    assert False\n")
    commit_all(project, "skip one")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and ("skip", "tests/check_more items.py", 4) in blocking(r)


def test_a_route_in_a_file_whose_name_holds_a_space_needs_its_negative_test(project: Path, tmp_path: Path):
    write(project, "app/more routes.py", "from app.framework import route\n\n\n@route(\"/more\")\ndef more(request):\n    return 'more'\n")
    commit_all(project, "a route with no 403 test and no coverage")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and ("AC-3", "app/more routes.py", 4) in blocking(r)
    assert ("coverage", None, None) in blocking(r)


def test_a_gitattributes_line_that_makes_python_binary_hides_nothing(project: Path, tmp_path: Path):
    write(project, ".gitattributes", "*.py -diff\n")
    append(project, "tests/check_routes.py", "\n\nimport pytest\n\n\n" + MARK_SKIP + "\ndef test_later():\n    assert False\n")
    commit_all(project, "skip one behind a binary attribute")
    r = run_gate(project, tmp_path)
    assert r.status == "fail" and ("skip", "tests/check_routes.py", 20) in blocking(r)


def test_neither_the_suite_nor_the_mutation_runs_see_the_bots_secrets(project: Path, tmp_path: Path, monkeypatch):
    # The pull request's tests run in the suite and again under every mutation; each run appends its environment.
    dump = tmp_path / "env.txt"
    monkeypatch.setenv("SB_ENV_DUMP", str(dump))
    for name in ("GITHUB_TOKEN", "CI_JOB_TOKEN", "SB_MODEL_KEY", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "DEPLOY_PASSWORD"):
        monkeypatch.setenv(name, "sekrit-value")
    append(project, "tests/check_routes.py", "\n\ndef test_records_env():\n    import os\n"
           "    with open(os.environ['SB_ENV_DUMP'], 'a') as f:\n        f.write(''.join(f'{k}={v}\\n' for k, v in os.environ.items()) + '--\\n')\n")
    commit_all(project, "a test that prints its environment")
    r = run_gate(project, tmp_path)
    assert r.status == "pass", (r.reason, blocking(r))
    runs = dump.read_text().split("--\n")
    assert len([x for x in runs if x]) >= 3  # the suite, then each control's mutation
    assert "sekrit-value" not in dump.read_text() and "PATH=" in runs[0]


def test_the_model_key_named_in_the_config_and_a_token_in_a_url_never_reach_the_suite(project: Path, tmp_path: Path, monkeypatch):
    # qa gate run 3, B-01: the job token rides in CI_REPOSITORY_URL's value, and sentinel.key_secret may
    # name a variable no suffix rule knows; a secret the suite prints is redacted from every kept file.
    dump = tmp_path / "env.txt"
    monkeypatch.setenv("SB_ENV_DUMP", str(dump))
    monkeypatch.setenv("CI_REPOSITORY_URL", "https://gitlab-ci-token:sekrit-value" + "@" + "gitlab.example/g/r.git")
    monkeypatch.setenv("MODEL_CREDENTIAL", "sekrit-value")
    printed = "gh" + "p_" + "Q7w8E9r0" * 5
    write(project, ".securebuilderbot.yml", "profile: il6\ngates: [qa]\nversion: latest\nsentinel:\n  key_secret: MODEL_CREDENTIAL\n")
    append(project, "tests/check_routes.py", "\n\ndef test_records_env():\n    import os\n"
           "    with open(os.environ['SB_ENV_DUMP'], 'a') as f:\n        f.write(''.join(f'{k}={v}\\n' for k, v in os.environ.items()))\n"
           f"    print('{printed[:4]}' + '{printed[4:]}')\n    assert False\n")
    commit_all(project, "a red test that prints a token and its environment")
    r = run_gate(project, tmp_path)
    assert r.status in ("fail", "not_run"), r.reason  # a red suite: the baseline mutate-controls refuses too
    assert "sekrit-value" not in dump.read_text() and "PATH=" in dump.read_text()
    kept = [f for f in (tmp_path / "run").rglob("*") if f.is_file()]
    assert kept and not [f for f in kept if printed in f.read_text(errors="replace")]
