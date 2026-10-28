"""The proof set's replay: every case through the real pipeline, with the fake provider (PRD § Sentinel gate).

For each case under sentinel/tests/proofset/: commit base/ and then head/ into a throwaway repository,
let core's classifier choose the depth, run the Sentinel gate on the range with the case's scripted
answers and its pr.md, and compare what came out with expected.yml — the depth, the verdict, every
finding (rule id, path, line, severity; none missing and none extra), the requests made, the controls
Control Completeness covered, the lines the sanitizer removed, the strings that must never reach the
model, and that the verdict is the same with the PR description taken away.

The answers are scripted, so this proves the pipeline, not the model (sentinel/tests/proofset/README.md).
Usage:  sentinel/run proofset [--case NAME] [--cases DIR]      Exit: 0 every case green · 1 a case red
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from securebuilderbot_core.classify import classify
from securebuilderbot_core.gate import GateContext, GateResult
from securebuilderbot_core.profiles import load_profile

from .checklist import items_for
from .gate import SentinelGate
from .providers.fake import FakeProvider
from .review import SUFFIX

CASES_DIR = Path(__file__).resolve().parents[1] / "tests" / "proofset"
KEY_NAME = "SB_MODEL_KEY"
KEY_VALUE = "proofset-placeholder-not-a-key"


@dataclass
class CaseResult:
    name: str
    problems: list[str] = field(default_factory=list)
    status: str = ""
    depth: str = ""


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _commit_tree(repo: Path, tree: Path, message: str) -> str:
    for p in repo.iterdir():
        if p.name != ".git":
            shutil.rmtree(p) if p.is_dir() else p.unlink()
    shutil.copytree(tree, repo, dirs_exist_ok=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _fenced(doc: object) -> str:
    return "```json\n" + json.dumps(doc, indent=1) + "\n```"


def scripted_answers(case: Path, profile: str) -> dict[str, str]:
    """responses.yml as the fake provider's answers. A checklist given as `answers` plus `not_applicable`
    becomes every item of the profile, the named ones as written and the rest n/a with that reason."""
    doc = yaml.safe_load((case / "responses.yml").read_text())
    out: dict[str, str] = {}
    for kind, value in doc.items():
        if isinstance(value, str):
            out[kind] = value
        elif kind == "checklist":
            given = {a["id"]: a for a in value.get("answers", [])}
            items = [given.get(i.id, {"id": i.id, "answer": "n/a", "reason": value["not_applicable"]})
                     for i in items_for(load_profile(profile))]
            out[kind] = _fenced({"items": items})
        else:
            out[kind] = _fenced(value)
    return out


def run_case(case: Path, work: Path, pr_override: str | None = None) -> tuple[GateResult, FakeProvider, GateContext]:
    expected = yaml.safe_load((case / "expected.yml").read_text())
    profile = expected.get("profile", "il6")
    repo = work / "repo"
    if repo.exists():
        shutil.rmtree(repo)
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    for k, v in (("user.email", "proofset@example.invalid"), ("user.name", "proofset"), ("commit.gpgsign", "false")):
        _git(repo, "config", k, v)
    pr = (case / "pr.md").read_text() if pr_override is None else pr_override
    title = pr.lstrip("\n").partition("\n")[0].lstrip("#").strip() or "change"
    staging = work / "base-tree"
    shutil.rmtree(staging, ignore_errors=True)
    shutil.copytree(case / "base", staging)
    (staging / ".securebuilderbot.yml").write_text(
        f"profile: {profile}\ngates: [sentinel]\nversion: latest\nsentinel:\n  key_secret: {KEY_NAME}\n")
    base = _commit_tree(repo, staging, "base")
    shutil.copy(staging / ".securebuilderbot.yml", work / "config.yml")
    head_tree = work / "head-tree"
    shutil.rmtree(head_tree, ignore_errors=True)
    shutil.copytree(case / "head", head_tree)
    shutil.copy(work / "config.yml", head_tree / ".securebuilderbot.yml")
    head = _commit_tree(repo, head_tree, title)
    run_dir = work / "run" / "sentinel"
    shutil.rmtree(run_dir.parent, ignore_errors=True)
    run_dir.mkdir(parents=True)
    pr_file = work / "pr.md"
    pr_file.write_text(pr)
    ctx = GateContext(repo=repo, base=base, head=head, profile=load_profile(profile),
                      depth=classify(base, head, repo).depth, run_dir=run_dir)
    fake = FakeProvider(scripted_answers(case, profile))
    gate = SentinelGate(provider_factory=lambda config, key: fake,
                        environ={KEY_NAME: KEY_VALUE, "SB_PR_CONTEXT": str(pr_file)})
    return gate.run(ctx), fake, ctx


def _key(f: dict | object) -> tuple:
    get = f.get if isinstance(f, dict) else lambda k, d=None: getattr(f, k, d)
    return (get("rule_id"), get("path"), get("line"), get("severity"))


def _show(k: tuple) -> str:
    return f"{k[0]} {k[1]}" + (f":{k[2]}" if k[2] else "") + (f" ({k[3]})" if k[3] else "")


def check_case(case: Path, work: Path) -> CaseResult:
    expected = yaml.safe_load((case / "expected.yml").read_text())
    work.mkdir(parents=True, exist_ok=True)
    result, fake, ctx = run_case(case, work)
    out = CaseResult(name=case.name, status=result.status, depth=ctx.depth)
    p = out.problems
    if ctx.depth != expected["depth"]:
        p.append(f"depth: expected {expected['depth']}, the classifier chose {ctx.depth}")
    if result.status != expected["status"]:
        p.append(f"status: expected {expected['status']}, got {result.status}" + (f" ({result.reason})" if result.status == "not_run" else ""))
    want = [_key(f) for f in expected.get("findings", [])]
    got = [_key(f) for f in result.findings]
    p += [f"not raised: {_show(k)}" for k in want if k not in got]
    p += [f"raised but not expected: {_show(k)}" for k in got if k not in want]
    p += [f"a finding without the cold-reviewer suffix: {f.message}" for f in result.findings if not f.message.endswith(SUFFIX)]
    kinds = [c.kind for c in fake.calls]
    if "requests" in expected and kinds != expected["requests"]:
        p.append(f"requests: expected {expected['requests']}, got {kinds}")
    cc = result.receipt.get("control_completeness")
    covered = [b["id"] for b in cc] if isinstance(cc, list) else []
    if covered != expected.get("control_completeness", []):
        p.append(f"control_completeness: expected {expected.get('control_completeness', [])}, got {covered}")
    if "sanitized_lines" in expected and result.receipt.get("sanitized_lines") != expected["sanitized_lines"]:
        p.append(f"sanitized_lines: expected {expected['sanitized_lines']}, got {result.receipt.get('sanitized_lines')}")
    sent = "".join(c.system + c.user for c in fake.calls)
    p += [f"sent to the model, and must never be: {s!r}" for s in expected.get("never_sent", []) if s in sent]
    allowed = expected.get("answers")
    if allowed:
        p += [f"{a['id']} answered {a['answer']}; the case allows only {', '.join(allowed)}"
              for a in result.receipt.get("checklist", []) if a["answer"] not in allowed]
    for part in expected.get("unchanged_without", []):
        pr = (case / "pr.md").read_text()
        title = pr.lstrip("\n").partition("\n")[0]
        stripped = title + "\n" if part == "pr_body" else "\n" + pr.lstrip("\n").partition("\n")[2]
        again, _, _ = run_case(case, work / f"without-{part}", stripped)
        if again.status != result.status:
            p.append(f"the verdict changed without the {part}: {result.status} became {again.status}")
        elif sorted(map(_key, again.findings)) != sorted(got):
            p.append(f"the findings changed without the {part}")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel/run proofset", description=__doc__.splitlines()[0])
    ap.add_argument("--case", action="append", help="replay only this case (repeatable)")
    ap.add_argument("--cases", default=str(CASES_DIR), help="the directory that holds the cases")
    args = ap.parse_args(argv)
    root = Path(args.cases)
    cases = sorted(d for d in root.iterdir() if d.is_dir() and (d / "expected.yml").is_file())
    if args.case:
        cases = [c for c in cases if c.name in args.case]
    if not cases:
        print(f"proofset: no cases under {root} — nothing replayed is never a pass")
        return 1
    red = 0
    with tempfile.TemporaryDirectory(prefix="sb-proofset-") as tmp:
        for case in cases:
            r = check_case(case, Path(tmp) / case.name)
            if r.problems:
                red += 1
                print(f"FAIL {r.name} ({r.depth}, {r.status})")
                for problem in r.problems:
                    print(f"       {problem}")
            else:
                print(f"ok   {r.name} ({r.depth}, {r.status})")
    print(f"proofset: {len(cases) - red}/{len(cases)} cases green (scripted answers: this proves the pipeline, not the model)")
    return 1 if red else 0
