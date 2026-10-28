"""standards/scripts/build-nistpubs-index.py, in process: NIST-Tech-Pubs bib/ filenames become the revision index.

test_refresh drives the builder as a subprocess, which coverage never sees. These import it and hold
the parse that a named-by-revision citation depends on: a revision split off its number, FIPS 140-3
never read as "FIPS 140 Rev 3", drafts never counted as published, and the shape tripwire. Every
repository is a local throwaway git checkout, never the network.
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

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-nistpubs-index.py"
spec = importlib.util.spec_from_file_location("build_nistpubs_index", SCRIPT)
bni = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bni)

NAMED = [
    "NIST.SP.800-124r2.ris", "NIST.SP.800-124r1.ris", "NIST.SP.800-124.ris",
    "NIST.SP.800-157.ris", "NIST.SP.800-157r1.ipd.ris",
    "NIST.SP.800-56Ar2.ris", "NIST.SP.800-56Ar3.ris",
    "NIST.SP.800-163r10.ris", "NIST.SP.800-163r9.ris",
    "NIST.FIPS.140-3.ris", "NIST.FIPS.140-2.ris",
    "NIST.SP.800-90C.fpd.ris", "NIST.SP.800-90C.2pd.ris",
    "NIST.SP.800-124r2.ris",  # again, under another folder: one revision, not two
]
NOISE = ["NIST.IR.8000.ris", "NIST.SP.800-1.txt", "README.ris"]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def pubs_repo(tmp_path: Path, filler: int = 100, named: list[str] = NAMED, commit: bool = True) -> Path:
    """A checkout whose bib/ holds the named files, `filler` distinct SP numbers, and some noise."""
    repo = tmp_path / "ntp"
    (repo / "bib" / "a").mkdir(parents=True)
    (repo / "bib" / "b").mkdir()
    for i, fn in enumerate(named):
        (repo / "bib" / ("a" if i < len(named) - 1 else "b") / fn).write_text("TY  - RPRT\n")
    for n in range(filler):
        (repo / "bib" / "a" / f"NIST.SP.900-{n}.ris").write_text("TY  - RPRT\n")
    for fn in NOISE:
        (repo / "bib" / "a" / fn).write_text("x\n")
    (repo / "NIST.SP.999-1.ris").write_text("outside bib/\n")
    git(repo, "init", "-q", "-b", "main")
    if commit:
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "t")
        git(repo, "config", "commit.gpgsign", "false")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "fixture")
    return repo


def run_main(monkeypatch, *argv: str) -> None:
    monkeypatch.setattr(sys, "argv", ["build-nistpubs-index.py", *argv])
    bni.main()


@pytest.mark.parametrize(("fn", "groups"), [
    ("NIST.SP.800-124r2.ris", ("SP", "800-124", "2", None)),
    ("NIST.SP.800-56Ar2.ris", ("SP", "800-56A", "2", None)),
    ("NIST.FIPS.140-3.ris", ("FIPS", "140-3", None, None)),
    ("NIST.SP.800-157r1.ipd.ris", ("SP", "800-157", "1", "ipd")),
    ("NIST.SP.800-90C.upd1.ris", ("SP", "800-90C", None, "upd1")),
])
def test_the_name_splits_series_number_revision_and_draft_stage(fn, groups):
    assert bni.NAME.match(fn).groups() == groups


@pytest.mark.parametrize("fn", ["NIST.IR.8000.ris", "NIST.SP.800-1.txt", "NIST.SP.x.ris"])
def test_other_series_and_shapes_do_not_match(fn):
    assert bni.NAME.match(fn) is None


def test_names_reads_ris_basenames_under_bib_from_the_git_tree(tmp_path):
    repo = pubs_repo(tmp_path, filler=0)
    (repo / "bib" / "a" / "NIST.SP.800-999.ris").write_text("untracked: not in the tree\n")
    got = bni.names(str(repo))
    assert sorted(got) == sorted([*NAMED, "NIST.IR.8000.ris", "README.ris"])


def test_names_refuses_when_git_cannot_read_the_tree(tmp_path):
    repo = pubs_repo(tmp_path, commit=False)
    with pytest.raises(SystemExit) as exc:
        bni.names(str(repo))
    assert exc.value.code.startswith("build-nistpubs-index: git ls-tree failed — ")


def test_head_is_the_twelve_character_commit_and_empty_without_git(tmp_path, monkeypatch):
    repo = pubs_repo(tmp_path, filler=0)
    assert bni.head(str(repo)) == git(repo, "rev-parse", "HEAD")[:12]
    monkeypatch.setenv("PATH", str(tmp_path / "no-bin"))
    assert bni.head(str(repo)) == ""


def test_main_writes_latest_published_revisions_and_drafts_apart(tmp_path, monkeypatch, capsys):
    repo = pubs_repo(tmp_path)
    out = tmp_path / "nist-pubs-index.json"
    run_main(monkeypatch, str(repo), str(out))

    doc = json.loads(out.read_text())
    pubs = doc["pubs"]
    assert pubs["SP 800-124"] == {"revisions": ["", "r1", "r2"], "drafts": [], "latest": "r2"}
    assert pubs["SP 800-157"] == {"revisions": [""], "drafts": ["r1.ipd"], "latest": ""}  # a draft is never latest
    assert pubs["SP 800-56A"] == {"revisions": ["r2", "r3"], "drafts": [], "latest": "r3"}
    assert pubs["SP 800-163"]["revisions"] == ["r9", "r10"]  # numeric, not string, order
    assert pubs["SP 800-163"]["latest"] == "r10"
    assert pubs["FIPS 140-3"] == {"revisions": [""], "drafts": [], "latest": ""}  # never "FIPS 140 Rev 3"
    assert "FIPS 140" not in pubs
    assert pubs["SP 800-90C"] == {"revisions": [], "drafts": ["2pd", "fpd"], "latest": ""}
    assert "IR 8000" not in pubs and "SP 999-1" not in pubs
    assert list(pubs) == sorted(pubs)
    assert doc["_counts"] == {"publications": 100 + 7}
    assert doc["_source"]["commit"] == git(repo, "rev-parse", "HEAD")[:12]
    assert doc["_source"]["repo"] == "https://github.com/usnistgov/NIST-Tech-Pubs"
    assert doc["_retrieved"] == datetime.date.today().isoformat()
    assert doc["_generator"] == "standards/scripts/build-nistpubs-index.py"
    assert capsys.readouterr().out == f"{out}: 107 NIST publications, {out.stat().st_size // 1024} KB\n"


def test_fewer_than_a_hundred_publications_is_a_changed_shape(tmp_path, monkeypatch):
    repo = pubs_repo(tmp_path, filler=100 - 7 - 1)
    out = tmp_path / "nist-pubs-index.json"
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, str(repo), str(out))
    assert exc.value.code == "build-nistpubs-index: only 99 publications parsed — bib/ has changed shape"
    assert not out.exists()


def test_exactly_a_hundred_publications_is_enough(tmp_path, monkeypatch):
    repo = pubs_repo(tmp_path, filler=100 - 7)
    out = tmp_path / "nist-pubs-index.json"
    run_main(monkeypatch, str(repo), str(out))
    assert json.loads(out.read_text())["_counts"] == {"publications": 100}


def test_a_directory_that_is_not_a_checkout_is_refused(tmp_path, monkeypatch):
    out = tmp_path / "nist-pubs-index.json"
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, str(tmp_path), str(out))
    assert exc.value.code == f"build-nistpubs-index: {tmp_path} is not a git checkout"


@pytest.mark.parametrize("argv", [(), ("one",), ("one", "two", "three")])
def test_the_wrong_number_of_arguments_is_the_usage(monkeypatch, argv):
    with pytest.raises(SystemExit) as exc:
        run_main(monkeypatch, *argv)
    assert exc.value.code == "usage: build-nistpubs-index.py <NIST-Tech-Pubs-repo> <out.json>"


def test_run_as_a_script(tmp_path, monkeypatch, capsys):
    repo = pubs_repo(tmp_path)
    out = tmp_path / "nist-pubs-index.json"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(repo), str(out)])
    runpy.run_path(str(SCRIPT), run_name="__main__")
    assert json.loads(out.read_text())["_counts"] == {"publications": 107}
    assert "107 NIST publications" in capsys.readouterr().out
