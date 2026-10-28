"""standards/scripts/build-masvs-index.py, in process: OWASP_MASVS.yaml becomes the vendored MASVS index.

test_refresh drives the builder as a subprocess, which coverage never sees. These import it and hold
its refusals (no catalogue, nothing parsed, YAML and controls/ disagreeing) and the provenance it
records (commit pin, newest release tag). Every repository is a local throwaway, never the network.
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-masvs-index.py"
spec = importlib.util.spec_from_file_location("build_masvs_index", SCRIPT)
bmi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bmi)

YAML = """metadata:
  title: OWASP MASVS (fixture)
  version: vx.x.x
groups:
- id: MASVS-AUTH
  index: 1
  title: Authentication and Authorization
  controls:
  - id: MASVS-AUTH-1
    statement: The app uses secure authentication.
  - id: MASVS-AUTH-2
    statement:   The app performs local authentication securely.\t\x20
- id: MASVS-CODE
  index: 2
  title: Code Quality
  controls:
  - id: MASVS-CODE-1
    statement: The app requires an up-to-date platform version.
  - id: MSTG-ARCH-1
    statement: A v1 id is not a v2 control.
"""
IDS = {"MASVS-AUTH-1", "MASVS-AUTH-2", "MASVS-CODE-1"}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def masvs(tmp_path: Path, yaml: str = YAML, controls: set[str] | None = None, commit: bool = True) -> Path:
    repo = tmp_path / "masvs"
    repo.mkdir()
    (repo / "OWASP_MASVS.yaml").write_text(yaml)
    if controls is not None:
        (repo / "controls").mkdir()
        for c in controls:
            (repo / "controls" / f"{c}.md").write_text(f"# {c}\n")
    if commit:
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "t")
        git(repo, "config", "commit.gpgsign", "false")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "fixture")
    return repo


def with_tags(tmp_path: Path, repo: Path, *tags: str) -> None:
    """An `origin` that is a local bare repository carrying these tags (annotated, so peeled refs appear too)."""
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    for t in tags:
        git(repo, "tag", "-a", t, "-m", t)
    git(repo, "remote", "add", "origin", str(bare))
    if tags:
        git(repo, "push", "-q", "origin", "--tags")


def run_main(monkeypatch, *argv: str) -> None:
    monkeypatch.setattr(sys, "argv", ["build-masvs-index.py", *argv])
    bmi.main()


# ── release / head ───────────────────────────────────────────────────────────


def test_release_is_the_numerically_newest_tag(tmp_path):
    repo = masvs(tmp_path)
    with_tags(tmp_path, repo, "v2.9.0", "v2.10.0", "v1.5.0", "notes-2024")
    assert bmi.release(str(repo)) == "v2.10.0"  # numeric, not string, order; a non-version tag is ignored


def test_release_without_tags_is_empty(tmp_path):
    repo = masvs(tmp_path)
    with_tags(tmp_path, repo)
    assert bmi.release(str(repo)) == ""


def test_release_with_an_unparseable_version_tag_is_empty_not_a_crash(tmp_path):
    repo = masvs(tmp_path)
    with_tags(tmp_path, repo, "v.2", "v2.0.0")
    assert bmi.release(str(repo)) == ""


def test_release_and_head_without_git_are_empty(tmp_path, monkeypatch):
    repo = masvs(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "no-bin"))
    assert bmi.release(str(repo)) == ""
    assert bmi.head(str(repo)) == ""


def test_head_is_the_twelve_character_commit(tmp_path):
    repo = masvs(tmp_path)
    assert bmi.head(str(repo)) == git(repo, "rev-parse", "HEAD")[:12]
    assert len(bmi.head(str(repo))) == 12


def test_head_of_a_directory_that_is_not_a_checkout_is_empty(tmp_path):
    assert bmi.head(str(masvs(tmp_path, commit=False))) == ""


# ── main ─────────────────────────────────────────────────────────────────────


def test_main_writes_controls_groups_and_provenance(tmp_path, monkeypatch, capsys):
    repo = masvs(tmp_path, controls=IDS)
    with_tags(tmp_path, repo, "v2.1.0")
    out = tmp_path / "masvs-index.json"
    run_main(monkeypatch, str(repo), str(out))

    doc = json.loads(out.read_text())
    assert doc["controls"] == {
        "MASVS-AUTH-1": "The app uses secure authentication.",
        "MASVS-AUTH-2": "The app performs local authentication securely.",  # whitespace stripped
        "MASVS-CODE-1": "The app requires an up-to-date platform version.",
    }  # the MSTG-* v1 id never matches
    assert doc["groups"] == {"MASVS-AUTH": "Authentication and Authorization", "MASVS-CODE": "Code Quality"}
    assert doc["_counts"] == {"controls": 3, "groups": 2}
    assert doc["_source"]["commit"] == git(repo, "rev-parse", "HEAD")[:12]
    assert doc["_source"]["repo"] == "https://github.com/OWASP/masvs"
    assert doc["_latest_release"] == "v2.1.0"
    assert doc["_retrieved"] == datetime.date.today().isoformat()
    assert doc["_generator"] == "standards/scripts/build-masvs-index.py"
    assert doc["_superseded_numbering"].startswith("MSTG-*")
    commit = doc["_source"]["commit"]
    assert capsys.readouterr().out == (
        f"{out}: 3 MASVS controls in 2 groups (release v2.1.0, commit {commit}), {out.stat().st_size // 1024} KB\n")


def test_unknown_release_and_commit_print_as_a_question_mark(tmp_path, monkeypatch, capsys):
    repo = masvs(tmp_path, commit=False)
    out = tmp_path / "masvs-index.json"
    run_main(monkeypatch, str(repo), str(out))
    doc = json.loads(out.read_text())
    assert doc["_latest_release"] == "" and doc["_source"]["commit"] == ""
    assert "(release ?, commit ?)" in capsys.readouterr().out


def test_a_controls_directory_without_masvs_files_is_not_compared(tmp_path, monkeypatch):
    repo = masvs(tmp_path, controls=set(), commit=False)
    (repo / "controls" / "README.md").write_text("index\n")
    out = tmp_path / "masvs-index.json"
    run_main(monkeypatch, str(repo), str(out))
    assert set(json.loads(out.read_text())["controls"]) == IDS


def test_a_control_on_disk_the_yaml_lacks_is_refused_and_named(tmp_path, monkeypatch):
    repo = masvs(tmp_path, controls=IDS | {"MASVS-CODE-2"}, commit=False)
    out = tmp_path / "masvs-index.json"
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, str(repo), str(out))
    assert exc.value.code == "build-masvs-index: YAML and controls/ disagree — ['MASVS-CODE-2']"
    assert not out.exists()


def test_a_control_in_the_yaml_missing_on_disk_is_refused_and_named(tmp_path, monkeypatch):
    repo = masvs(tmp_path, controls=IDS - {"MASVS-AUTH-2"}, commit=False)
    out = tmp_path / "masvs-index.json"
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, str(repo), str(out))
    assert exc.value.code == "build-masvs-index: YAML and controls/ disagree — ['MASVS-AUTH-2']"
    assert not out.exists()


def test_a_yaml_that_changed_shape_is_refused_rather_than_an_empty_index(tmp_path, monkeypatch):
    repo = masvs(tmp_path, yaml="groups:\n  - {id: MASVS-AUTH, controls: [{id: MASVS-AUTH-1}]}\n", commit=False)
    out = tmp_path / "masvs-index.json"
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, str(repo), str(out))
    assert exc.value.code == "build-masvs-index: no controls parsed — OWASP_MASVS.yaml has changed shape"
    assert not out.exists()


def test_a_directory_without_the_catalogue_is_refused(tmp_path, monkeypatch):
    out = tmp_path / "masvs-index.json"
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, str(tmp_path), str(out))
    assert exc.value.code == f"build-masvs-index: {tmp_path / 'OWASP_MASVS.yaml'} not found — is that an OWASP/masvs checkout?"


@pytest.mark.parametrize("argv", [(), ("one",), ("one", "two", "three")])
def test_the_wrong_number_of_arguments_is_the_usage(monkeypatch, argv):
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, *argv)
    assert exc.value.code == "usage: build-masvs-index.py <masvs-repo> <out.json>"


def test_run_as_a_script(tmp_path, monkeypatch, capsys):
    repo = masvs(tmp_path, commit=False)
    out = tmp_path / "masvs-index.json"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(repo), str(out)])
    runpy.run_path(str(SCRIPT), run_name="__main__")
    assert json.loads(out.read_text())["_counts"] == {"controls": 3, "groups": 2}
    assert "3 MASVS controls in 2 groups" in capsys.readouterr().out
