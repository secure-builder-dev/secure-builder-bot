"""Is this range deep or light? Decided by paths, never by the reviewer. Port of classify-range.sh.

The expensive half of the Sentinel review (Control Completeness, the adversarial review, the
edge-case hunt) is where missing guards are found; it also used to run on restyles and doc edits.
This makes the call mechanical and deliberately over-inclusive: a light verdict on a real control
change is the one failure that matters, so anything that could be one is deep.

DEEP when any changed file (tests excluded, outside the gate's own code) is:
  1. under a path or name that says security, in backend/src, frontend/src or android/app/src/main
  2. the implementation file of a populated CONTROL-MANIFEST.md row, read at both ends of the range
  3. a file holding a guard site: a 403/404 refusal or a role branch, comments dropped, the file read
     as one line so a refusal split across lines still counts
  4. a migration
  5. the gate itself: core/, scanners/, qa/, sentinel/, engine/scripts/gate/, gate-prompt.sh, QUALITY_GATE.md,
     SENTINEL-CHECKLIST.md, the review skills, .claude/agents/, the vendored standards indexes
     and their builders (standards/data/controls/, standards/scripts/)
  6. a control record: CONTROL-MANIFEST.md, FRONTEND-MUTATIONS.md, PROOF-SET.md
A deleted file is judged by its content at the base. Otherwise LIGHT.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

GATE_TOOLING = ("core/", "scanners/", "qa/", "sentinel/", "engine/scripts/gate/", "engine/skills/review-", ".claude/agents/", "standards/data/controls/", "standards/scripts/")
GATE_FILES = ("engine/scripts/gate-prompt.sh", "engine/QUALITY_GATE.md", "engine/SENTINEL-CHECKLIST.md")
CONTROL_RECORDS = ("docs/security/CONTROL-MANIFEST.md", "docs/security/FRONTEND-MUTATIONS.md", "docs/security/PROOF-SET.md")
SRC = re.compile(r"^(backend/src/|frontend/src/|frontend/index\.html$|android/app/src/main/)")
TEST = re.compile(r"(/__tests__/|/__mocks__/|/test/|\.(test|spec)\.[jt]sx?$|android/app/src/(test|androidTest)/)")
NAME = re.compile(r"(^|/)(middleware|routes|controllers)/|auth|rbac|acl|permission|polic(y|ies)|scope|session|token|"
                  r"crypto|audit|redact|saniti[sz]|upload|document|rate[-_]?limit", re.I)
GUARD = re.compile(r"(AppError|res\.status)\(\s*40[34]|role\s*[!=]==\s*[\"']")
COMMENT_LINE = re.compile(r"^\s*(//|\*|/\*)")
LIGHT_WHY = "no security path, control implementation, guard site, migration or gate file in the range"


class ClassifyError(ValueError):
    """The range does not resolve to two commits."""


@dataclass(frozen=True)
class Classification:
    depth: str  # "deep" or "light"
    reasons: tuple[str, ...]


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    # --no-replace-objects: Sentinel classifies again after QA ran the pull request's code here, and
    # refs/replace would let that code make the range read as docs-only (sentinel gate run 2, B-01).
    return subprocess.run(["git", "--no-replace-objects", "-C", str(repo), *args], capture_output=True, text=True, check=check)


def _show(repo: Path, rev: str, path: str) -> str | None:
    out = _git(repo, "show", f"{rev}:{path}", check=False)
    return out.stdout if out.returncode == 0 else None


def _manifest_impls(repo: Path, revs: tuple[str, str]) -> set[str]:
    impls: set[str] = set()
    for rev in revs:
        for line in (_show(repo, rev, "docs/security/CONTROL-MANIFEST.md") or "").splitlines():
            if not re.match(r"^\| CM-\d+ ", line):
                continue
            cells = line.split("|")
            impl = cells[3].replace("`", "").strip() if len(cells) > 3 else ""
            if impl and not impl.startswith("<") and impl != "-":
                impls.add(impl.split(":")[0])
    return impls


def _has_guard(text: str) -> bool:
    kept = " ".join(line for line in text.splitlines() if not COMMENT_LINE.match(line))
    return bool(GUARD.search(re.sub(r"\s+", " ", kept)))


def _control_roots(repo: Path, rev: str) -> tuple[str, ...]:
    """CONTROL_SRC_ROOTS from project.config.yaml at rev: the directories a project's controls live in."""
    text = _show(repo, rev, "project.config.yaml") or ""
    m = re.search(r"^[ \t]*CONTROL_SRC_ROOTS:[ \t]*\"?([^\"#\n]*)", text, re.M)
    return tuple(r.rstrip("/") + "/" for r in (m.group(1).split() if m else ()))


def classify(base: str, head: str, repo: Path | str = ".") -> Classification:
    repo = Path(repo)
    for rev in (base, head):
        if _git(repo, "rev-parse", "--verify", "-q", f"{rev}^{{commit}}", check=False).returncode != 0:
            raise ClassifyError(f"{rev!r} does not resolve")
    changed = [f for f in _git(repo, "diff", "--name-only", base, head).stdout.splitlines() if f]
    impls = _manifest_impls(repo, (base, head))
    roots = _control_roots(repo, head)
    reasons: list[str] = []
    for f in changed:
        if f.startswith(GATE_TOOLING) or f in GATE_FILES:
            reasons.append(f"gate tooling: {f}")
        elif "/migrations/" in f:
            reasons.append(f"migration: {f}")
        elif f in CONTROL_RECORDS:
            reasons.append(f"control record: {f}")
        # A registered control, or a file under a configured control root, is deep wherever it lives:
        # these were skipped by the app-path test below, so weakening one read light (standards run 1, B-02).
        elif f in impls:
            reasons.append(f"control implementation: {f}")
        elif roots and f.startswith(roots) and not TEST.search(f):
            reasons.append(f"control root: {f}")
        elif not SRC.search(f) or TEST.search(f):
            continue
        elif NAME.search(f):
            reasons.append(f"security path: {f}")
        elif f in impls:
            reasons.append(f"control implementation: {f}")
        else:
            content = _show(repo, head, f)
            if content is None:  # deleted in the range: judge what was removed
                content = _show(repo, base, f) or ""
            if _has_guard(content):
                reasons.append(f"guard site in: {f}")
    return Classification("deep" if reasons else "light", tuple(reasons))
