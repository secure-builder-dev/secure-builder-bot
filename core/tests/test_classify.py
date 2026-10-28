"""Ported from engine/scripts/tests/classify-range-test.sh, case for case, plus the spec's own.

Deep must be reachable by every route and light must be reachable at all: a classifier that always
says deep is safe and useless; one that says light on a real control change is the failure the
light/deep split depends on not having. Each deep case takes a different route to deep.
"""

import subprocess
from pathlib import Path

import pytest

from securebuilderbot_core.__main__ import main
from securebuilderbot_core.classify import ClassifyError, classify

from .conftest import commit_all, git


@pytest.fixture
def base_repo(repo: Path) -> tuple[Path, str]:
    for d in ("backend/src/services", "frontend/src/components/ui", "frontend/src/pages", "docs/security",
              "backend/src/migrations", "engine/scripts/gate"):
        (repo / d).mkdir(parents=True, exist_ok=True)
    (repo / "docs/security/CONTROL-MANIFEST.md").write_text("| CM-01 | x | `backend/src/services/ledger.ts:post` | - | `x.test.ts` | n |\n")
    (repo / "backend/src/services/ledger.ts").write_text("export function post() { return 1 }\n")
    (repo / "backend/src/services/math.ts").write_text("export function sum(a, b) { return a + b }\n")
    (repo / "backend/src/services/keeper.ts").write_text('export function gate(u) { if (u.role !== "admin") throw new AppError(403, "F", "no") }\n')
    (repo / "frontend/src/index.css").write_text(".x { color: red }\n")
    (repo / "frontend/src/components/ui/button.tsx").write_text("export const Button = () => null\n")
    (repo / "frontend/src/pages/Page.tsx").write_text("export const Page = () => null\n")
    return repo, commit_all(repo, "base")


def append(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(text)


CASES = [
    ("a ui component and a stylesheet are light", "light",
     [("frontend/src/components/ui/button.tsx", "x\n"), ("frontend/src/index.css", ".y{}\n")]),
    ("a test file alone is light, even under a security path", "light",
     [("backend/src/middleware/__tests__/auth.test.ts", "it()\n")]),
    ("a file under middleware/ is deep", "deep", [("backend/src/middleware/m.ts", "export const m=1\n")]),
    ("a security word in the name is deep", "deep", [("backend/src/services/tokenStore.ts", "export const t=1\n")]),
    ("a manifest implementation file is deep", "deep", [("backend/src/services/ledger.ts", "// edit\n")]),
    ("a new 403 in an innocent file is deep", "deep",
     [("backend/src/services/math.ts", 'if (x) throw new AppError(403, "F", "no")\n')]),
    ("a new role branch in a page is deep", "deep", [("frontend/src/pages/Page.tsx", 'if (user.role === "admin") {}\n')]),
    ("a 403 written across two lines is deep", "deep",
     [("backend/src/services/math.ts", 'if (x) throw new AppError(\n  403, "F", "no")\n')]),
    ("a res.status(404) refusal is deep", "deep", [("backend/src/services/math.ts", "if (x) return res.status(404).json({})\n")]),
    ("a commented-out 403 is not a guard", "light", [("backend/src/services/math.ts", "// throw new AppError(403)\n")]),
    ("a migration is deep", "deep", [("backend/src/migrations/001_x.ts", "x\n")]),
    ("a change to the gate is deep", "deep", [("engine/scripts/gate/x.sh", "x\n")]),
    ("a frontend mutation row change is deep", "deep", [("docs/security/FRONTEND-MUTATIONS.md", "| FM-01 |\n")]),
    ("a change to core, the gate runner itself, is deep", "deep", [("core/securebuilderbot_core/runner.py", "x = 1\n")]),
    ("a change to a vendored standards index is deep", "deep", [("standards/data/controls/owasp-index.json", "{}\n")]),
    ("a change to an index builder is deep", "deep", [("standards/scripts/build-owasp-index.py", "x = 1\n")]),
    ("a change to the reviewer, sentinel, is deep", "deep", [("sentinel/securebuilderbot_sentinel/review.py", "x = 1\n")]),
    ("a change to the reviewer's checklist is deep", "deep", [("sentinel/checklist/base.yml", "items: []\n")]),
    ("a docs-only change is light", "light", [("docs/guide.md", "words\n")]),
]


@pytest.mark.parametrize("label, expected, edits", CASES, ids=[c[0] for c in CASES])
def test_route(base_repo, label, expected, edits):
    repo, base = base_repo
    for rel, text in edits:
        append(repo, rel, text)
    head = commit_all(repo)
    assert classify(base, head, repo).depth == expected


def test_deleting_a_guarded_file_nobody_registered_is_deep(base_repo):
    repo, base = base_repo
    git(repo, "rm", "-q", "backend/src/services/keeper.ts")
    head = commit_all(repo)
    c = classify(base, head, repo)
    assert c.depth == "deep"
    assert any("keeper.ts" in r for r in c.reasons)


def test_deleting_a_manifest_row_alone_is_deep(base_repo):
    repo, base = base_repo
    (repo / "docs/security/CONTROL-MANIFEST.md").write_text("")
    assert classify(base, commit_all(repo), repo).depth == "deep"


def test_an_unresolvable_range_raises(base_repo):
    repo, _ = base_repo
    with pytest.raises(ClassifyError, match="'nope' does not resolve"):
        classify("nope", "HEAD", repo)


def test_cli_range_form_and_why(base_repo, capsys, monkeypatch):
    repo, base = base_repo
    append(repo, "backend/src/migrations/002.ts", "x\n")
    commit_all(repo)
    monkeypatch.chdir(repo)
    assert main(["classify", f"{base}..HEAD", "--why"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "deep"
    assert out[1].startswith("  migration: backend/src/migrations/002.ts")


def test_cli_base_head_form_light_with_why(base_repo, capsys, monkeypatch):
    repo, base = base_repo
    append(repo, "README.md", "hi\n")
    commit_all(repo)
    monkeypatch.chdir(repo)
    assert main(["classify", "--base", base, "--head", "HEAD", "--why"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == ["light", "  no security path, control implementation, guard site, migration or gate file in the range"]


def test_cli_unresolvable_exits_2(base_repo, capsys, monkeypatch):
    repo, _ = base_repo
    monkeypatch.chdir(repo)
    assert main(["classify", "nope..HEAD"]) == 2
    assert main(["classify"]) == 2
    assert "does not resolve" in capsys.readouterr().err


def test_launcher_prints_depth_first_line_for_shell_callers(base_repo):
    repo, base = base_repo
    append(repo, "core/securebuilderbot_core/x.py", "x = 1\n")
    commit_all(repo)
    root = Path(__file__).resolve().parents[2]
    out = subprocess.run([str(root / "core" / "run"), "classify", f"{base}..HEAD"], cwd=repo, capture_output=True, text=True)
    assert out.returncode == 0
    assert out.stdout.splitlines()[0] == "deep"


def test_a_registered_control_outside_the_app_source_paths_is_deep(base_repo):
    # Gate finding B-02 (standards run 1): a manifest row naming a file outside backend/src,
    # frontend/src or android was skipped before the control-implementation test, so weakening it read light.
    repo, base = base_repo
    append(repo, "pkg/guard.py", "def is_active(x):\n    return x\n")
    append(repo, "docs/security/CONTROL-MANIFEST.md", "| CM-02 | y | `pkg/guard.py:is_active` | - | `t.py` | n |\n")
    base = commit_all(repo, "a control outside the app paths")
    append(repo, "pkg/guard.py", "# weakened\n")
    head = commit_all(repo, "weaken it")
    c = classify(base, head, repo)
    assert c.depth == "deep" and "control implementation: pkg/guard.py" in c.reasons


def test_a_file_under_a_configured_control_root_is_deep(base_repo):
    repo, base = base_repo
    (repo / "project.config.yaml").write_text("APP_TRACK: web\nCONTROL_SRC_ROOTS: core/x pkg/securebuilderbot_pkg\n")
    base = commit_all(repo, "control roots")
    append(repo, "pkg/securebuilderbot_pkg/data.py", "LOADED = 1\n")
    head = commit_all(repo, "a module the controls read")
    c = classify(base, head, repo)
    assert c.depth == "deep" and "control root: pkg/securebuilderbot_pkg/data.py" in c.reasons


def test_a_file_beside_a_control_root_is_not_deep_on_that_account(base_repo):
    repo, base = base_repo
    (repo / "project.config.yaml").write_text("CONTROL_SRC_ROOTS: pkg/securebuilderbot_pkg\n")
    base = commit_all(repo, "control roots")
    append(repo, "pkg/securebuilderbot_pkgextra/notes.py", "X = 1\n")
    head = commit_all(repo, "a sibling directory")
    assert classify(base, head, repo).depth == "light"


def test_replace_refs_cannot_make_a_control_change_read_as_light(base_repo):
    """Sentinel classifies again after QA ran the pull request's code in this checkout (sentinel gate
    run 2, B-01; run 3, N-04): refs/replace pointing the head at the base must not empty the range."""
    repo, base = base_repo
    append(repo, "backend/src/services/ledger.ts", "export function post2() { return 2 }\n")
    head = commit_all(repo, "control change")
    assert classify(base, head, repo).depth == "deep"
    git(repo, "replace", head, base)
    assert classify(base, head, repo).depth == "deep"
