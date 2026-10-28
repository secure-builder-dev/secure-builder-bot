"""standards/scripts/build-owasp-index.py, in process: the OWASP Top 10 and LLM Top 10 repositories become the index.

test_refresh drives the builder as a subprocess, which coverage never sees. These import it and hold
what the edition check depends on: every edition kept, not just the current one, the mkdocs nav read
as the ordered list, LLM00 left out, and the refusal when nothing parses. Local fixtures only.
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

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-owasp-index.py"
spec = importlib.util.spec_from_file_location("build_owasp_index", SCRIPT)
boi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boi)

NAV_2021 = """site_name: OWASP Top 10 2021
nav:
  - 'Home': 'index.md'
  - A01 Broken Access Control: 'A01_2021-Broken_Access_Control.md'
  - A02 Cryptographic Failures: 'A02_2021-Cryptographic_Failures.md'
"""
NAV_2025 = """nav:
    - A01 Broken Access Control: 'A01_2025.md'
    - A02 Security Misconfiguration:   'A02_2025.md'
    - A04 Cryptographic Failures: "double-quoted is not the nav shape"
"""


def top10(tmp_path: Path) -> Path:
    t10 = tmp_path / "Top10"
    for edition, nav in (("2021", NAV_2021), ("2025", NAV_2025), ("2017", "nav:\n  - 'Home': 'index.md'\n"),
                         ("assets", NAV_2021)):
        (t10 / edition).mkdir(parents=True)
        (t10 / edition / "mkdocs.yml").write_text(nav)
    (t10 / "2013").mkdir()  # an edition directory with no mkdocs.yml
    (t10 / "2020").write_text("a file, not a directory\n")
    return t10


def llm(tmp_path: Path) -> Path:
    repo = tmp_path / "llm"
    (repo / "2_0_vulns").mkdir(parents=True)
    for fn in ("LLM00_Preface.md", "LLM01_PromptInjection.md", "LLM02_SensitiveInformationDisclosure.md",
               "LLM06_ExcessiveAgency.md", "LLM10_LLMOutputHandling.md", "README.md", "LLM07.md"):
        (repo / "2_0_vulns" / fn).write_text("x\n")
    (repo / "1_1_vulns").mkdir()
    (repo / "1_1_vulns" / "LLM08_ExcessiveAgency.md").write_text("x\n")
    return repo


def git_init(repo: Path) -> str:
    def g(*a: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout.strip()
    g("init", "-q", "-b", "main")
    g("config", "user.email", "t@example.invalid")
    g("config", "user.name", "t")
    g("config", "commit.gpgsign", "false")
    g("add", "-A")
    g("commit", "-q", "-m", "fixture")
    return g("rev-parse", "HEAD")[:12]


def run_main(monkeypatch, *argv: str) -> None:
    monkeypatch.setattr(sys, "argv", ["build-owasp-index.py", *argv])
    boi.main()


@pytest.mark.parametrize(("name", "words"), [
    ("SensitiveInformationDisclosure", "Sensitive Information Disclosure"),
    ("PromptInjection", "Prompt Injection"),
    ("LLMOutputHandling", "LLM Output Handling"),
    ("Misinformation", "Misinformation"),
])
def test_split_camel(name, words):
    assert boi.split_camel(name) == words


def test_web_editions_reads_every_numbered_edition_with_a_nav(tmp_path):
    assert boi.web_editions(str(top10(tmp_path))) == {
        "2021": {"A01": "Broken Access Control", "A02": "Cryptographic Failures"},
        "2025": {"A01": "Broken Access Control", "A02": "Security Misconfiguration"},
    }  # 2017 has no A-items, 2013 no mkdocs.yml, assets is not an edition, 2020 is a file


def test_llm_editions_reads_both_directories_and_leaves_out_llm00(tmp_path):
    assert boi.llm_editions(str(llm(tmp_path))) == {
        "2025": {"LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure",
                 "LLM06": "Excessive Agency", "LLM10": "LLM Output Handling"},
        "2023": {"LLM08": "Excessive Agency"},
    }


def test_llm_editions_skips_a_directory_with_nothing_matching(tmp_path):
    repo = tmp_path / "llm"
    (repo / "2_0_vulns").mkdir(parents=True)
    (repo / "2_0_vulns" / "LLM00_Preface.md").write_text("x\n")
    assert boi.llm_editions(str(repo)) == {}


def test_head_is_the_commit_and_empty_without_git(tmp_path, monkeypatch):
    repo = top10(tmp_path)
    commit = git_init(repo)
    assert boi.head(str(repo)) == commit
    monkeypatch.setenv("PATH", str(tmp_path / "no-bin"))
    assert boi.head(str(repo)) == ""


def test_main_writes_every_edition_and_names_the_current_one(tmp_path, monkeypatch, capsys):
    t10, lm = top10(tmp_path), llm(tmp_path)
    c_web, c_llm = git_init(t10), git_init(lm)
    out = tmp_path / "owasp-index.json"
    run_main(monkeypatch, str(t10), str(lm), str(out))

    doc = json.loads(out.read_text())
    assert doc["web"]["current"] == "2025"
    assert sorted(doc["web"]["editions"]) == ["2021", "2025"]
    assert doc["web"]["editions"]["2021"]["A02"] == "Cryptographic Failures"
    assert doc["llm"]["current"] == "2025"
    assert doc["llm"]["editions"]["2023"] == {"LLM08": "Excessive Agency"}
    assert doc["_sources"]["web"]["commit"] == c_web
    assert doc["_sources"]["llm"]["commit"] == c_llm
    assert doc["_sources"]["web"]["repo"] == "https://github.com/OWASP/Top10"
    assert doc["_retrieved"] == datetime.date.today().isoformat()
    assert doc["_generator"] == "standards/scripts/build-owasp-index.py"
    assert capsys.readouterr().out == (
        f"{out}: web editions ['2021', '2025'] (current 2025), "
        f"llm editions ['2023', '2025'] (current 2025), {out.stat().st_size // 1024} KB\n")


def test_no_web_edition_is_refused(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    out = tmp_path / "owasp-index.json"
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, str(empty), str(llm(tmp_path)), str(out))
    assert exc.value.code == "build-owasp-index: no editions parsed — check the repository paths"
    assert not out.exists()


def test_no_llm_edition_is_refused(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    out = tmp_path / "owasp-index.json"
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, str(top10(tmp_path)), str(empty), str(out))
    assert exc.value.code == "build-owasp-index: no editions parsed — check the repository paths"
    assert not out.exists()


@pytest.mark.parametrize("argv", [(), ("one", "two"), ("one", "two", "three", "four")])
def test_the_wrong_number_of_arguments_is_the_usage(monkeypatch, argv):
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, *argv)
    assert exc.value.code == "usage: build-owasp-index.py <Top10-repo> <llm-repo> <out.json>"


def test_run_as_a_script(tmp_path, monkeypatch, capsys):
    out = tmp_path / "owasp-index.json"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(top10(tmp_path)), str(llm(tmp_path)), str(out)])
    runpy.run_path(str(SCRIPT), run_name="__main__")
    doc = json.loads(out.read_text())
    assert doc["_sources"]["web"]["commit"] == "" and doc["_sources"]["llm"]["commit"] == ""  # not checkouts
    assert "web editions ['2021', '2025']" in capsys.readouterr().out
