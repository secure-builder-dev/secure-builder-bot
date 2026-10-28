"""The base branch's config governs a pull request: the pull request cannot change its own rules."""

import json
import os
from pathlib import Path

import pytest

from securebuilderbot_core.__main__ import main
from securebuilderbot_core.config import ConfigError, governing_config, load_config

from .conftest import commit_all, git
from .test_runner import fakes

BASE = "profile: il6\ngates: [scan, qa, sentinel]\nversion: latest\nsentinel:\n  key_secret: SB_MODEL_KEY\n"
LOOSER = "profile: none\ngates: [scan]\nversion: latest\nscan:\n  skip: [clamav]\n  accepted_risks: mine.yml\n"


@pytest.fixture
def adopted(repo: Path) -> Path:
    """A repository whose main carries BASE, on a branch that loosens every rule it can."""
    (repo / ".securebuilderbot.yml").write_text(BASE)
    commit_all(repo, "config")
    git(repo, "checkout", "-q", "-b", "loosen")
    (repo / ".securebuilderbot.yml").write_text(LOOSER)
    commit_all(repo, "loosen the rules")
    return repo


def _run(repo: Path, monkeypatch, calls: list) -> int:
    import securebuilderbot_core.runner as runner_mod
    monkeypatch.chdir(repo)
    fake = fakes(calls, scan="pass", qa="pass", sentinel="pass")
    monkeypatch.setattr(runner_mod, "default_factory", lambda name: fake[name])
    return main(["run", "--base", "main"])


def _receipt(repo: Path) -> dict:
    runs = sorted((repo / "gate-records" / "runs").iterdir())
    return json.loads((runs[-1] / "receipt.json").read_text())


def test_a_pull_request_that_loosens_the_config_is_still_held_to_the_base_branchs(adopted, monkeypatch, capsys):
    calls = []
    assert _run(adopted, monkeypatch, calls) == 0
    assert [name for name, _ in calls] == ["scan", "qa", "sentinel"]  # the PR's gates: [scan] did not apply
    ctx = calls[0][1]
    assert ctx.profile.name == "il6" and ctx.skip == ()  # nor its profile or its skipped scanner
    assert ctx.config.scan.accepted_risks == "docs/security/accepted-risks.yml"  # nor its exceptions file
    r = _receipt(adopted)
    assert r["config"]["source"] == "base"
    assert r["config"]["changed_by_pr"] == ["gates", "profile", "scan.accepted_risks", "scan.skip", "sentinel.key_secret"]
    assert r["relaxations"] == []
    out = capsys.readouterr().out
    assert "this pull request changes gates, profile, scan.accepted_risks, scan.skip, sentinel.key_secret" in out
    assert "the base branch's settings apply until it is merged" in out


def test_every_gate_is_handed_the_config_that_governs_the_run(adopted, monkeypatch):
    calls = []
    _run(adopted, monkeypatch, calls)
    assert {ctx.config.sha256 for _, ctx in calls} == {_receipt(adopted)["config"]["sha256"]}
    assert calls[0][1].config.gates == ("scan", "qa", "sentinel")


def test_an_unchanged_config_is_read_from_the_base_and_reports_no_change(repo, monkeypatch, capsys):
    (repo / ".securebuilderbot.yml").write_text(BASE)
    commit_all(repo, "config")
    git(repo, "checkout", "-q", "-b", "work")
    (repo / "x.md").write_text("words\n")
    commit_all(repo, "docs")
    _run(repo, monkeypatch, [])
    r = _receipt(repo)
    assert r["config"]["source"] == "base" and r["config"]["changed_by_pr"] == []
    assert "this pull request changes" not in capsys.readouterr().out


def test_with_no_config_on_the_base_the_pull_requests_own_is_used_and_said(repo, monkeypatch, capsys):
    git(repo, "checkout", "-q", "-b", "adopt")
    (repo / ".securebuilderbot.yml").write_text(LOOSER)
    commit_all(repo, "adopt the bot")
    calls = []
    _run(repo, monkeypatch, calls)
    assert [name for name, _ in calls] == ["scan"] and calls[0][1].profile.name == "none"
    r = _receipt(repo)
    assert r["config"]["source"] == "pull request"
    assert "no config on the base branch" in capsys.readouterr().out


def test_a_config_that_is_a_symlink_in_the_base_commit_is_refused(repo, monkeypatch, capsys):
    (repo / "real.yml").write_text(BASE)
    os.symlink("real.yml", repo / ".securebuilderbot.yml")
    commit_all(repo, "linked config")
    git(repo, "checkout", "-q", "-b", "work")
    (repo / ".securebuilderbot.yml").unlink()
    (repo / ".securebuilderbot.yml").write_text(BASE)
    commit_all(repo, "plain file")
    assert _run(repo, monkeypatch, []) == 2
    assert "symbolic link in the base commit" in capsys.readouterr().out


def test_a_base_config_that_does_not_validate_cannot_start(repo, monkeypatch, capsys):
    (repo / ".securebuilderbot.yml").write_text("profile: il5\ngates: [scan]\nversion: latest\n")
    commit_all(repo, "broken config")
    git(repo, "checkout", "-q", "-b", "work")
    (repo / ".securebuilderbot.yml").write_text(BASE)
    commit_all(repo, "fixed config")
    assert _run(repo, monkeypatch, []) == 2
    assert "the config at the base commit" in capsys.readouterr().out


def test_a_config_outside_the_checkout_is_not_the_pull_requests_and_is_used_whole(adopted, tmp_path):
    outside = tmp_path / "ops" / "bot.yml"
    outside.parent.mkdir()
    outside.write_text(LOOSER)
    g = governing_config(load_config(outside), adopted, git(adopted, "rev-parse", "main"))
    assert g.source == "outside the checkout" and g.config.profile.name == "none" and g.changed == ()


def test_replace_refs_cannot_swap_the_base_config(adopted):
    base = git(adopted, "rev-parse", "main")
    blob = git(adopted, "hash-object", "-w", ".securebuilderbot.yml")  # the loosened copy
    real = git(adopted, "rev-parse", f"{base}:.securebuilderbot.yml")
    git(adopted, "replace", real, blob)
    g = governing_config(load_config(adopted / ".securebuilderbot.yml"), adopted, base)
    assert g.config.profile.name == "il6"


def test_an_unresolvable_base_is_a_config_error(adopted):
    with pytest.raises(ConfigError, match="base commit"):
        governing_config(load_config(adopted / ".securebuilderbot.yml"), adopted, "0" * 40)


# ── Round 2 (adversarial review): the pull request cannot choose the commit that governs it ──────────

def test_a_branch_cut_from_before_the_config_is_held_to_the_target_branchs(repo, monkeypatch, capsys):
    old = git(repo, "rev-parse", "HEAD")  # main before the bot was adopted
    (repo / ".securebuilderbot.yml").write_text(BASE)
    commit_all(repo, "adopt the bot")
    git(repo, "checkout", "-q", "-b", "evil", old)  # the merge base with main is `old`, which has no config
    (repo / ".securebuilderbot.yml").write_text(LOOSER)
    commit_all(repo, "my own rules")
    calls = []
    _run(repo, monkeypatch, calls)
    assert [name for name, _ in calls] == ["scan", "qa", "sentinel"] and calls[0][1].profile.name == "il6"
    r = _receipt(repo)
    assert r["config"]["source"] == "base" and r["config"]["ref"] == git(repo, "rev-parse", "main")
    assert calls[0][1].config_ref == git(repo, "rev-parse", "main") and calls[0][1].base == old  # the diff still starts at the merge base


def test_config_ref_names_the_commit_the_rules_are_read_from(adopted, monkeypatch):
    import securebuilderbot_core.runner as runner_mod
    tight = git(adopted, "rev-parse", "main")
    monkeypatch.chdir(adopted)
    calls = []
    fake = fakes(calls, scan="pass", qa="pass", sentinel="pass")
    monkeypatch.setattr(runner_mod, "default_factory", lambda name: fake[name])
    assert main(["run", "--base", "main", "--config-ref", tight]) == 0
    assert calls[0][1].config_ref == tight and _receipt(adopted)["config"]["ref"] == tight


def test_a_base_that_is_the_head_itself_holds_the_run_to_nothing_and_is_never_a_clean_pass(adopted, monkeypatch, capsys):
    import securebuilderbot_core.runner as runner_mod
    monkeypatch.chdir(adopted)
    fake = fakes([], scan="pass")
    monkeypatch.setattr(runner_mod, "default_factory", lambda name: fake[name])
    assert main(["run", "--base", "HEAD"]) == 0
    r = _receipt(adopted)
    assert r["config"]["source"] == "head" and r["overall"] == "yellow"
    assert any("the base is the head commit itself" in x for x in r["relaxations"])


def test_a_range_that_changes_the_ci_workflow_is_reported(adopted, monkeypatch, capsys):
    (adopted / ".github" / "workflows").mkdir(parents=True)
    (adopted / ".github" / "workflows" / "secure-builder.yml").write_text("on: push\n")
    commit_all(adopted, "edit the workflow")
    _run(adopted, monkeypatch, [])
    r = _receipt(adopted)
    assert r["config"]["workflow_changed"] == [".github/workflows/secure-builder.yml"]
    assert "this pull request changes the CI workflow (.github/workflows/secure-builder.yml)" in capsys.readouterr().out


def test_a_base_config_git_cannot_read_cannot_start(adopted, monkeypatch, capsys):
    blob = git(adopted, "rev-parse", "main:.securebuilderbot.yml")
    obj = adopted / ".git" / "objects" / blob[:2] / blob[2:]
    assert obj.is_file()
    obj.chmod(0o644)
    obj.unlink()  # a partial clone's lazy fetch that failed reads the same way
    assert _run(adopted, monkeypatch, []) == 2
    assert "could not be read" in capsys.readouterr().out


def test_a_config_reached_through_a_linked_directory_is_still_the_checkouts(adopted, tmp_path):
    link = tmp_path / "via-link"
    os.symlink(adopted, link)
    g = governing_config(load_config(link / ".securebuilderbot.yml"), adopted, git(adopted, "rev-parse", "main"))
    assert g.source == "base" and g.config.profile.name == "il6"


# ── Round 3 (second adversarial review) ─────────────────────────────────────────────────────────────

def test_a_directory_in_the_checkout_that_is_a_link_is_refused_never_followed(repo):
    (repo / "ci").mkdir()
    (repo / "ci" / "sb.yml").write_text(BASE)
    commit_all(repo, "config under ci/")
    git(repo, "checkout", "-q", "-b", "evil")
    (repo / "ci" / "sb.yml").unlink()
    (repo / "ci").rmdir()
    (repo / "ci2").mkdir()
    (repo / "ci2" / "sb.yml").write_text(LOOSER)  # no ci2/sb.yml on the target: it would read as adoption
    os.symlink("ci2", repo / "ci")
    commit_all(repo, "ci is a link now")
    with pytest.raises(ConfigError, match="symbolic link"):
        governing_config(load_config(repo / "ci" / "sb.yml"), repo, git(repo, "rev-parse", "main"))


@pytest.mark.parametrize("path", [".github/actions/setup/action.yml", ".gitlab/ci/jobs.yml", ".gitlab-ci.yml"])
def test_a_workflow_change_is_a_relaxation_so_the_run_is_never_a_clean_pass(adopted, monkeypatch, path):
    (adopted / path).parent.mkdir(parents=True, exist_ok=True)
    (adopted / path).write_text("x: 1\n")
    commit_all(adopted, "edit what runs the bot")
    _run(adopted, monkeypatch, [])
    r = _receipt(adopted)
    assert r["config"]["workflow_changed"] == [path] and r["overall"] == "yellow"
    assert any("changes the CI workflow" in x for x in r["relaxations"])
