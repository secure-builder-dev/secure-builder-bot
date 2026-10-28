"""The per-ecosystem adapters: detection, the command each runs, and what each reports back."""

from __future__ import annotations

from pathlib import Path

import pytest

from securebuilderbot_core.receipt import REDACTED
from securebuilderbot_qa.adapters import CommandRunner, SuiteResult, detect_runners, user_env, withholding
from securebuilderbot_qa.adapters.node import NodeRunner, detect_node
from securebuilderbot_qa.adapters.python import PytestRunner

from .conftest import commit_all, write_package_json

LCOV = "SF:src/a.js\nDA:1,1\nDA:2,0\nend_of_record\n"


# ── node ───────────────────────────────────────────────────────────────────────

def test_node_detects_jest_and_vitest_from_package_json(repo: Path):
    write_package_json(repo / "api", devDependencies={"jest": "29.0.0"}, scripts={"test": "jest"})
    write_package_json(repo / "web", devDependencies={"vitest": "4.0.0"}, scripts={"test": "vitest run"})
    write_package_json(repo / "lib", scripts={"build": "tsc"})
    (repo / "api" / "node_modules" / "x").mkdir(parents=True)
    write_package_json(repo / "api" / "node_modules" / "x", devDependencies={"jest": "1"})
    found = {r.app: r.kind for r in detect_node(repo)}
    assert found == {"api": "jest", "web": "vitest"}


def test_node_prefers_the_runner_the_test_script_names(repo: Path):
    write_package_json(repo / "app", devDependencies={"jest": "29", "vitest": "4"}, scripts={"test": "vitest run"})
    assert [r.kind for r in detect_node(repo)] == ["vitest"]


def test_node_runs_npm_test_with_an_lcov_reporter(repo: Path, fake_npm: Path, tmp_path: Path, monkeypatch):
    write_package_json(repo / "api", devDependencies={"jest": "29"}, scripts={"test": "jest"})
    monkeypatch.setenv("FAKE_NPM_LCOV", LCOV)
    log_dir = tmp_path / "run"
    r = NodeRunner("api", "jest", log_dir)
    assert r.detect(repo)
    res = r.run(repo, ["api/src/a.js"])
    assert isinstance(res, SuiteResult)
    assert fake_npm.read_text().splitlines() == ["test -- --coverage --coverageReporters=lcov --coverageReporters=text"]
    assert res.passed and res.counts == {"passed": 3, "failed": 0, "skipped": 1, "errors": 0, "total": 4}
    assert res.lcov == repo / "api" / "coverage" / "lcov.info" and res.lcov.read_text().strip() == LCOV.strip()
    assert res.lcov_root == "api" and res.runner == "jest" and res.app == "api"
    assert res.log.is_file() and "Tests:" in res.log.read_text()
    assert r.coverage_lcov(repo) == repo / "api" / "coverage" / "lcov.info"


def test_vitest_gets_its_own_reporter_flag_and_summary(repo: Path, fake_npm: Path, tmp_path: Path, monkeypatch):
    write_package_json(repo / "web", devDependencies={"vitest": "4"}, scripts={"test": "vitest run"})
    monkeypatch.setenv("FAKE_NPM_RUNNER", "vitest")
    res = NodeRunner("web", "vitest", tmp_path / "run").run(repo, [])
    assert fake_npm.read_text().splitlines() == ["test -- --coverage --coverage.reporter=lcov --coverage.reporter=text"]
    assert res.counts == {"passed": 3, "failed": 0, "skipped": 1, "errors": 0, "total": 4}


def test_a_flag_the_test_script_already_passes_is_not_passed_twice(repo: Path, fake_npm: Path, tmp_path: Path, monkeypatch):
    # vitest 4 refuses a repeated --coverage ("Expected a single value"), so a package whose test
    # script is `vitest run --coverage` never ran under the QA gate: the bot's own adapter was one.
    write_package_json(repo / "web", devDependencies={"vitest": "4"}, scripts={"test": "vitest run --coverage"})
    monkeypatch.setenv("FAKE_NPM_RUNNER", "vitest")
    NodeRunner("web", "vitest", tmp_path / "run").run(repo, [])
    assert fake_npm.read_text().splitlines() == ["test -- --coverage.reporter=lcov --coverage.reporter=text"]


def test_a_red_npm_run_is_not_passed(repo: Path, fake_npm: Path, tmp_path: Path, monkeypatch):
    write_package_json(repo / "api", devDependencies={"jest": "29"}, scripts={"test": "jest"})
    monkeypatch.setenv("FAKE_NPM_EXIT", "1")
    res = NodeRunner("api", "jest", tmp_path / "run").run(repo, [])
    assert not res.passed and res.error == ""


def test_a_missing_npm_is_an_error_not_a_failure(repo: Path, tmp_path: Path, monkeypatch):
    write_package_json(repo / "api", devDependencies={"jest": "29"}, scripts={"test": "jest"})
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    res = NodeRunner("api", "jest", tmp_path / "run").run(repo, [])
    assert not res.passed and "npm" in res.error


# ── python ─────────────────────────────────────────────────────────────────────

def pyapp(repo: Path) -> None:
    (repo / "pkg").mkdir()
    (repo / "pkg" / "__init__.py").write_text("")
    (repo / "pkg" / "m.py").write_text("def f(x):\n    if x:\n        return 1\n    return 2\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_m.py").write_text("from pkg.m import f\n\n\ndef test_f():\n    assert f(1) == 1\n")
    (repo / "pytest.ini").write_text("[pytest]\naddopts = -p no:cacheprovider\n")
    commit_all(repo, "pyapp")


def test_pytest_is_detected_from_the_usual_markers(repo: Path, tmp_path: Path):
    r = PytestRunner(tmp_path / "run")
    assert not r.detect(repo)
    (repo / "conftest.py").write_text("")
    assert r.detect(repo)
    (repo / "conftest.py").unlink()
    (repo / "tests").mkdir()
    assert r.detect(repo)


def test_pytest_runs_with_lcov_coverage_into_the_run_dir(repo: Path, tmp_path: Path):
    pyapp(repo)
    res = PytestRunner(tmp_path / "run").run(repo, ["pkg/m.py"])
    assert res.passed and res.error == "" and res.runner == "pytest" and res.app == "."
    assert res.counts["passed"] == 1 and res.counts["failed"] == 0 and res.counts["total"] == 1
    assert res.lcov == tmp_path / "run" / "pytest.lcov" and res.lcov_root == "."
    text = res.lcov.read_text()
    assert "pkg/m.py" in text and "DA:3,1" in text and "DA:4,0" in text


def test_a_failing_pytest_suite_reports_its_counts(repo: Path, tmp_path: Path):
    pyapp(repo)
    (repo / "tests" / "test_bad.py").write_text("def test_bad():\n    assert False\n")
    res = PytestRunner(tmp_path / "run").run(repo, [])
    assert not res.passed and res.counts["failed"] == 1 and res.counts["passed"] == 1


# ── discovery and the user's own command ──────────────────────────────────────

def test_detect_runners_finds_every_app_and_nothing_in_an_empty_repo(repo: Path, tmp_path: Path):
    assert detect_runners(repo, tmp_path / "run") == []
    write_package_json(repo / "api", devDependencies={"jest": "29"}, scripts={"test": "jest"})
    (repo / "tests").mkdir()
    names = sorted(f"{r.runner}:{r.app}" for r in detect_runners(repo, tmp_path / "run"))
    assert names == ["jest:api", "pytest:."]


def test_a_custom_test_command_runs_at_the_root_and_reports_exit_status(repo: Path, tmp_path: Path):
    ok = CommandRunner("echo hello; echo '2 passed'", tmp_path / "run").run(repo, [])
    assert ok.passed and ok.runner == "command" and ok.lcov is None and "hello" in ok.log.read_text()
    assert ok.counts["passed"] == 2
    bad = CommandRunner("exit 3", tmp_path / "run2").run(repo, [])
    assert not bad.passed and bad.counts == {"passed": 0, "failed": 0, "skipped": 0, "errors": 0, "total": 0}


@pytest.mark.parametrize("text,want", [
    ("Tests:       2 failed, 5 passed, 7 total", {"passed": 5, "failed": 2, "skipped": 0, "errors": 0, "total": 7}),
    ("      Tests  12 passed | 2 failed | 1 skipped (15)", {"passed": 12, "failed": 2, "skipped": 1, "errors": 0, "total": 15}),
    ("3 passed, 1 skipped, 2 errors in 0.5s", {"passed": 3, "failed": 0, "skipped": 1, "errors": 2, "total": 6}),
])
def test_summaries_are_read_into_counts(text, want):
    from securebuilderbot_qa.adapters import parse_counts
    assert parse_counts(text) == want


# ── the environment the user's code runs in ────────────────────────────────────
# A pull request's own tests run here, and their output lands in the run directory CI uploads, so
# the bot's secrets and the CI platform's tokens must never reach them (adapter-gitlab gate, B-03).

SECRETS = ["GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "SECURE_BUILDER_TOKEN", "SB_MODEL_KEY", "CI_JOB_TOKEN",
           "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "CI_JOB_JWT", "CI_JOB_JWT_V2", "NPM_TOKEN",
           "ANTHROPIC_API_KEY", "DB_SECRET", "CI_REGISTRY_PASSWORD", "my_api_key"]
KEPT = ["CI", "SB_KEEP", "MONKEY", "TOKENIZERS_PARALLELISM", "KEY_PATH"]


# Variables whose names say nothing but whose values carry a credential (qa gate run 3, B-01): GitLab's
# predefined CI_REPOSITORY_URL holds the job token as URL userinfo. Built from pieces so this file
# never holds a credential-shaped literal.
AT = "@"
GHP = "gh" + "p_" + "A1b2C3d4" * 5
VALUE_SECRETS = {
    "CI_REPOSITORY_URL": "https://gitlab-ci-token:sekrit-value-url" + AT + "gitlab.example/g/r.git",
    "UPSTREAM": "https://" + GHP + AT + "github.com/o/r.git",
    "PROXY_URL": "http://user:sekrit-value-proxy" + AT + "proxy.example:3128",
    "MIRROR": "https://x-access-token" + AT + "github.com/o/r.git",
    "SOME_SETTING": "prefix " + GHP,
}
VALUE_KEPT = {"PLAIN_URL": "https://gitlab.example/g/r.git", "SSH_URL": "ssh://git" + AT + "gitlab.example/g/r.git",
              "MAILTO": "someone" + AT + "example.com", "HTTP_PROXY_PLAIN": "http://proxy.example:3128"}


@pytest.fixture
def secret_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in SECRETS:
        monkeypatch.setenv(name, "sekrit-value-" + name)
    for name in KEPT:
        monkeypatch.setenv(name, "kept")
    for name, value in {**VALUE_SECRETS, **VALUE_KEPT}.items():
        monkeypatch.setenv(name, value)


def env_names(dump: str) -> set[str]:
    return {line.split("=", 1)[0] for line in dump.splitlines() if "=" in line}


def assert_scrubbed(dump: str) -> None:
    names = env_names(dump)
    assert not names & (set(SECRETS) | set(VALUE_SECRETS)), sorted(names & (set(SECRETS) | set(VALUE_SECRETS)))
    assert "sekrit-value" not in dump and GHP not in dump
    assert set(KEPT) | set(VALUE_KEPT) <= names and {"PATH", "HOME"} <= names


def test_the_users_own_command_never_sees_the_bots_secrets(repo: Path, tmp_path: Path, secret_env):
    res = CommandRunner("env; echo '1 passed'", tmp_path / "run").run(repo, [])
    assert res.passed
    assert_scrubbed(res.log.read_text())


def test_the_pytest_suite_never_sees_the_bots_secrets(repo: Path, tmp_path: Path, secret_env, monkeypatch):
    dump = tmp_path / "env.txt"
    monkeypatch.setenv("SB_ENV_DUMP", str(dump))
    pyapp(repo)
    (repo / "tests" / "test_env.py").write_text(
        "import os\n\n\ndef test_print_env():\n    with open(os.environ['SB_ENV_DUMP'], 'w') as f:\n"
        "        f.write(''.join(f'{k}={v}\\n' for k, v in os.environ.items()))\n")
    res = PytestRunner(tmp_path / "run").run(repo, [])
    assert res.passed, res.log.read_text()
    assert_scrubbed(dump.read_text())


def test_the_node_suite_never_sees_the_bots_secrets(repo: Path, fake_npm: Path, tmp_path: Path, secret_env, monkeypatch):
    dump = tmp_path / "env.txt"
    monkeypatch.setenv("FAKE_NPM_ENV_DUMP", str(dump))
    write_package_json(repo / "api", devDependencies={"jest": "29"}, scripts={"test": "jest"})
    assert NodeRunner("api", "jest", tmp_path / "run").run(repo, []).passed
    assert_scrubbed(dump.read_text())


def test_user_env_drops_secret_names_and_keeps_the_rest():
    env = {name: "v" for name in SECRETS + KEPT + ["PATH", "HOME"]}
    assert user_env(env) == {name: "v" for name in KEPT + ["PATH", "HOME"]}
    assert "PATH" in user_env() and "HOME" in user_env()


def test_user_env_drops_a_variable_whose_value_carries_a_credential():
    env = {**VALUE_SECRETS, **VALUE_KEPT, "PATH": "/bin"}
    assert user_env(env) == {**VALUE_KEPT, "PATH": "/bin"}


def test_user_env_withholds_the_configured_model_key_name_whatever_it_is_called():
    env = {"MODEL_CREDENTIAL": "plain", "OTHER": "1"}
    assert user_env(env) == env
    with withholding(["MODEL_CREDENTIAL"]):
        assert user_env(env) == {"OTHER": "1"}
    assert user_env(env) == env  # only for the run that set it


def test_nothing_a_suite_prints_is_kept_secret_shaped(repo: Path, tmp_path: Path):
    run_dir = tmp_path / "run"
    res = CommandRunner(f"echo 'the key is {GHP}'; echo '1 passed'", run_dir).run(repo, [])
    assert res.passed and REDACTED in res.log.read_text()
    assert not [f for f in run_dir.rglob("*") if f.is_file() and GHP in f.read_text()]
