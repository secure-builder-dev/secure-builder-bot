"""Dogfood, honestly (SPEC-sentinel.md § Decisions): the bot's own config keeps scan and qa, because
without a model key a Sentinel gate is not_run and that must never be hidden; the full config turns all
three on, and CI runs it only when the maintainer has added the key, saying so when it has not."""

from __future__ import annotations

from pathlib import Path

import yaml

from securebuilderbot_core.config import load_config

ROOT = Path(__file__).resolve().parents[2]


def workflow() -> dict:
    return yaml.safe_load((ROOT / ".github" / "workflows" / "scan.yml").read_text())


def test_the_bots_own_config_keeps_scan_and_qa():
    assert load_config(ROOT / ".securebuilderbot.yml").gates == ("scan", "qa")


def test_the_full_config_turns_on_all_three_gates_with_a_secret_name():
    c = load_config(ROOT / ".github" / "securebuilderbot-full.yml")
    assert c.gates == ("scan", "qa", "sentinel")
    assert (c.profile.name, c.sentinel.provider, c.sentinel.key_secret, c.sentinel.depth) == ("il6", "anthropic", "SB_MODEL_KEY", "auto")


def test_the_sentinel_job_runs_only_when_the_key_is_set_and_says_so_otherwise():
    job = workflow()["jobs"]["sentinel"]
    assert job["env"]["HAS_KEY"] == "${{ secrets.SB_MODEL_KEY != '' }}"
    steps = job["steps"]
    notice = [s for s in steps if s.get("if") == "env.HAS_KEY != 'true'"]
    assert len(notice) == 1 and "::notice" in notice[0]["run"] and "SB_MODEL_KEY" in notice[0]["run"]
    assert all(s.get("if", "").startswith("env.HAS_KEY == 'true'") for s in steps if s not in notice)


def test_the_sentinel_job_runs_core_with_the_full_config_and_the_key_from_the_secret():
    run = next(s for s in workflow()["jobs"]["sentinel"]["steps"] if "core/run run" in s.get("run", ""))
    assert "--config .github/securebuilderbot-full.yml" in run["run"]
    assert run["env"]["SB_MODEL_KEY"] == "${{ secrets.SB_MODEL_KEY }}"
    assert run["env"]["SB_CONFIG"] == ".github/securebuilderbot-full.yml"
    assert "continue-on-error" not in run  # a red reviewer is a red check, never hidden


def test_the_workflow_stays_read_only():
    assert workflow()["permissions"] == {"contents": "read"}


def _steps(job: str) -> list[dict]:
    return workflow()["jobs"][job]["steps"]


def test_the_sentinel_job_keeps_the_token_out_of_the_checkout():  # gate run 1, N-05
    checkout = next(s for s in _steps("sentinel") if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["persist-credentials"] is False
    assert checkout["with"]["fetch-depth"] == 0


def test_the_sentinel_job_installs_every_npm_package_from_its_lockfile_as_the_scan_job_does():
    def npm_step(job):
        return next(s for s in _steps(job) if "npm ci" in s.get("run", ""))
    assert npm_step("sentinel")["run"] == npm_step("scan-gate")["run"]
    assert npm_step("sentinel")["if"] == "env.HAS_KEY == 'true'"
    assert any(str(s.get("uses", "")).startswith("actions/setup-node") for s in _steps("sentinel"))


def test_the_sentinel_job_reads_origin_main_from_the_checkout_and_never_fetches():
    runs = "\n".join(s.get("run", "") for s in _steps("sentinel"))
    assert "git fetch" not in runs
    assert "git rev-parse --verify -q origin/main" in runs
