"""What the reviewer is given, built from the gate context (docs/PRD.md § Architecture: where the LLM sits).

The provider gets the diff of base..head, the files the checklist names (the control manifest, the
config, a file an item names), the profile's items, the PR's title, description and commit
messages, and what QA proved in this run. Everything is read from git at the head, never from the
working tree, and nothing else is read at all.

Never sent, whatever the diff or a checklist item says: environment files, deployment values files,
Terraform variables, key material and credentials files, binary files, and a lockfile's contents
beyond package names and versions. Such a file in the diff is replaced by its path and a note, so the
reviewer still knows it changed. `may_send` is the one door every byte of file content passes
through (CM-53); the receipt lists `sent_to_model_endpoint` from the same set.

Every text input is sanitized (sanitize.py) and redacted for secret-shaped strings before it is
kept; the counts go to the receipt. A diff over `sentinel.max_diff_bytes` is cut by whole files and
the omitted files are listed, so the review says what it did not see.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

from securebuilderbot_core.gate import GateContext
from securebuilderbot_core.profiles import Profile
from securebuilderbot_qa.controls import parse_mutation_table

from .checklist import Item, items_for
from .sanitize import (REMOVED, data_block, is_instruction_like, path_is_instruction_like, quote, redact_secrets, sanitize_diff,
                       sanitize_text, unsafe_text)

NAMED_FILE_MAX_BYTES = 100_000
PR_TEXT_MAX_BYTES = 64_000
COMMITS_MAX = 100
COMMITS_MAX_BYTES = 20_000
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "Cargo.lock",
             "poetry.lock", "uv.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "packages.lock.json"}
# What is never sent, matched case-insensitively on the file name (and, for .docker/ and .kube/, the
# directory): the PRD's "no environment files, no values files", widened after gate run 1, S-03,
# which found deploy/prod.env, .ENV, values.prod.yaml, a chart's values.yaml outside helm/,
# terraform.tfstate, credentials.json, .git-credentials, .docker/config.json and kubeconfig sent.
# Widened again after gate run 2, B-03, which found prod-values.yaml, prod.env.local, .env-prod,
# secrets.json, client_secret.json, .s3cfg, .vault-token and *.ppk / *.p8 / *.keytab sent.
_ENV = re.compile(r"\.env([._-].*)?|.*\.env|\.envrc", re.I)
_ENV_INFIX = re.compile(r".*\.env[._-].*", re.I)          # prod.env.local; app.env.ts is code (below)
_VALUES = re.compile(r".*values.*\.ya?ml", re.I)
_TERRAFORM = re.compile(r".*\.(tfstate|tfvars)(\..*)?", re.I)
_CREDENTIALS = re.compile(r"credentials.*\.json|credentials|\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.htpasswd"
                          r"|kubeconfig|.*\.kubeconfig|secrets?(\..*)?\.ya?ml|.*[-_]key\.json|service[-_]?account.*\.json"
                          r"|\.s3cfg|\.dockercfg|\.vault-token|\.terraformrc", re.I)
_SECRET_NAMED = re.compile(r".*(secret|credential).*", re.I)  # secrets.toml, client_secret.json; secrets.py is code
_KEYS = re.compile(r".*\.(pem|key|p12|pfx|jks|keystore|crt|der|ppk|p8|keytab)|id_(rsa|dsa|ecdsa|ed25519).*", re.I)
# A source-code file is reviewable whatever its name: withholding secret_handler.py or app.env.ts
# would let an author keep a change from review just by naming it so. Only the name-contains
# families (_ENV_INFIX, _SECRET_NAMED) exempt these extensions; every other pattern exempts nothing.
_CODE = frozenset("py pyi js mjs cjs jsx ts mts cts tsx go rs java kt kts scala groovy rb php cs fs vb swift m mm c h cc "
                  "cpp cxx hpp sh bash zsh ps1 pl lua dart ex exs erl clj sql vue svelte".split())
_CREDENTIAL_PATHS = re.compile(r"(^|.*/)(\.docker/config\.json|\.kube/config)", re.I)
_NAME = re.compile(r"[A-Za-z0-9@/._+~-]{1,214}")
_VERSION = re.compile(r"[A-Za-z0-9._+~-]{1,64}")
_HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")
_ROW = re.compile(r"^\| (CM-\d+) \|")
WITHHELD_PATH = "[path withheld: instruction-like, {n}]"


# ── what may be sent ──────────────────────────────────────────────────────────────────────────

def withheld(path: str) -> str | None:
    """Why a file is never sent to a model endpoint, or None when it may be."""
    name = PurePosixPath(path).name
    code = "." in name.lstrip(".") and name.rsplit(".", 1)[1].lower() in _CODE
    if _ENV.fullmatch(name) or (_ENV_INFIX.fullmatch(name) and not code):
        return "an environment file: never sent to a model endpoint"
    if _TERRAFORM.fullmatch(name):
        kind = "state" if "tfstate" in name.lower() else "variables"
        return f"a Terraform {kind} file: never sent to a model endpoint"
    if _VALUES.fullmatch(name):
        return "a deployment values file: never sent to a model endpoint"
    if _CREDENTIALS.fullmatch(name) or _CREDENTIAL_PATHS.fullmatch(path) or _KEYS.fullmatch(name) or \
            (_SECRET_NAMED.fullmatch(name) and not code):
        return "key material or a credentials file: never sent to a model endpoint"
    return None


def may_send(path: str, allowed: frozenset[str]) -> bool:
    """CM-53: a file's content goes to the model only when it is in the diff or the named set AND is
    not a file that holds values. Every read of content for a prompt asks this first."""
    return path in allowed and withheld(path) is None


def lock_packages(path: str, text: str) -> set[str] | None:
    """`name@version` for every package a lockfile pins, and nothing else from it; None for a format
    this does not read, which is then withheld whole."""
    name = PurePosixPath(path).name
    out: set[str] = set()
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        try:
            doc = json.loads(text)
        except ValueError:
            return set()
        for key, entry in (doc.get("packages") or {}).items():
            if key and isinstance(entry, dict) and "version" in entry:
                out.add(f"{key.rsplit('node_modules/', 1)[-1]}@{entry['version']}")
        for dep, entry in (doc.get("dependencies") or {}).items():
            if isinstance(entry, dict) and "version" in entry:
                out.add(f"{dep}@{entry['version']}")
    elif name == "go.sum":
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                out.add(f"{parts[0]}@{parts[1].removesuffix('/go.mod')}")
    elif name in ("Cargo.lock", "poetry.lock", "uv.lock"):
        for m in re.finditer(r'^name = "([^"]+)"\s*\nversion = "([^"]+)"', text, re.M):
            out.add(f"{m.group(1)}@{m.group(2)}")
    else:
        return None
    return {p for p in out if _NAME.fullmatch(p.rsplit("@", 1)[0]) and _VERSION.fullmatch(p.rsplit("@", 1)[1])}


# ── the request ───────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Settings:
    config_path: str | None  # repository-relative, or None when the config is outside the checkout
    manifest: str
    max_diff_bytes: int


@dataclass(frozen=True)
class FileDiff:
    path: str
    block: str               # the data block sent: the sanitized diff, or a lockfile's package list
    lines: frozenset[int]    # head line numbers the diff shows (added and context): where a finding may land


@dataclass(frozen=True)
class NamedFile:
    path: str
    text: str
    why: str


@dataclass(frozen=True)
class ManifestRow:
    id: str
    control: str
    implementation: str
    proving_test: str
    note: str

    @property
    def path(self) -> str:
        return self.implementation.split(":", 1)[0]

    @property
    def symbol(self) -> str:
        return self.implementation.split(":", 1)[1] if ":" in self.implementation else ""


@dataclass(frozen=True)
class QaEvidence:
    trusted: bool
    proven: frozenset[str]
    note: str


@dataclass(frozen=True)
class ReviewRequest:
    profile: Profile
    depth: str
    items: tuple[Item, ...]
    files: tuple[FileDiff, ...]
    withheld_blocks: tuple[str, ...]
    not_sent: tuple[tuple[str, str], ...]
    omitted: tuple[str, ...]
    named: tuple[NamedFile, ...]
    missing_named: tuple[str, ...]
    pr_title: str
    pr_body: str
    commits: str
    manifest_rows: tuple[ManifestRow, ...]
    touched: tuple[ManifestRow, ...]
    qa: QaEvidence
    sanitized_lines: int
    redacted_secrets: int
    notes: tuple[str, ...] = field(default=())
    unsafe_paths: int = 0  # changed paths that carried a control character, an instruction or the delimiter
    path_labels: tuple[tuple[str, str], ...] = ()  # (real path, what the prompt shows in its place)

    def shown(self, path: str) -> str:
        """CM-50: the path as a prompt may show it — the placeholder for one that reads as an instruction."""
        return dict(self.path_labels).get(path, path)

    def real(self, path: str | None) -> str | None:
        """The real path behind a placeholder the reviewer cited; any other path as it is."""
        return {label: real for real, label in self.path_labels}.get(path, path) if path is not None else None

    def diff_text(self) -> str:
        return "\n".join([f.block for f in self.files] + list(self.withheld_blocks))

    def sent_paths(self) -> list[str]:
        return sorted({f.path for f in self.files} | {f.path for f in self.named})

    def file_lines(self) -> dict[str, frozenset[int]]:
        return {f.path: f.lines for f in self.files}


class _Counter:
    def __init__(self) -> None:
        self.sanitized = 0
        self.redacted = 0

    def text(self, raw: str, diff: bool = False) -> str:
        cleaned, n = (sanitize_diff if diff else sanitize_text)(raw)
        cleaned, m = redact_secrets(cleaned)
        self.sanitized += n
        self.redacted += m
        return cleaned


# Every git call Sentinel makes starts with GIT. --literal-pathspecs: a changed file's path is the
# author's text, and a file named * (or ?, [a-z]*, :(glob)**) must name itself, never every withheld
# file (gate run 1, S-04). --no-replace-objects: refs/replace, which any code run in this checkout can
# write, would otherwise change what a commit or blob reads as — an empty diff, another base config
# (gate run 2, B-01). Every patch also runs with --no-textconv --no-ext-diff, so no driver named in
# .git/config runs, with the model key in this process's environment, or rewrites what is sent; the
# --numstat listing runs no textconv driver at all, which test_review.py's marker test holds it to.
GIT = ("git", "--no-replace-objects", "--literal-pathspecs")


def _git(repo: Path, *args: str, check: bool = True) -> str:
    out = subprocess.run([*GIT, "-C", str(repo), *args], capture_output=True, check=check)
    return out.stdout.decode("utf-8", errors="replace") if out.returncode == 0 else ""


def _show(repo: Path, rev: str, path: str) -> str | None:
    out = subprocess.run([*GIT, "-C", str(repo), "show", f"{rev}:{path}"], capture_output=True)
    return out.stdout.decode("utf-8", errors="replace") if out.returncode == 0 else None


def tracked_blob(repo: Path, rev: str, path: str) -> tuple[str, bytes | None]:
    """(the tree entry's mode, the blob's bytes) for `path` at `rev`, read by blob id from the commit's
    own tree: ("", None) when the commit has no such file, (mode, None) when the entry is not a blob."""
    out = subprocess.run([*GIT, "-C", str(repo), "ls-tree", "-z", "--full-tree", rev, "--", path], capture_output=True)
    meta, _, name = (out.stdout.split(b"\0")[0] if out.returncode == 0 else b"").partition(b"\t")
    parts = meta.decode("ascii", errors="replace").split()
    if len(parts) != 3 or name.decode("utf-8", errors="replace") != path:
        return "", None
    mode, kind, sha = parts
    if kind != "blob" or mode == "120000":
        return mode, None
    blob = subprocess.run([*GIT, "-C", str(repo), "cat-file", "blob", sha], capture_output=True)
    return mode, (blob.stdout if blob.returncode == 0 else None)


def _changed(repo: Path, base: str, head: str) -> list[tuple[str, bool]]:
    """(path, is_binary) for every file the range changes, renames read as a delete and an add."""
    raw = _git(repo, "diff", "--numstat", "-z", "--no-renames", "--no-ext-diff", base, head)  # a stat runs no textconv
    out = []
    for entry in raw.split("\0"):
        parts = entry.split("\t", 2)
        if len(parts) == 3 and parts[2]:
            out.append((parts[2], parts[0] == "-" and parts[1] == "-"))
    return out


_NAMING_HEADER = re.compile(r"^(diff --git |--- (?!/dev/null$)|\+\+\+ (?!/dev/null$)|rename |copy )")


def _without_path_headers(diff: str) -> tuple[str, int]:
    """A placeholdered file's diff with the header lines that name it removed, and how many: the block's
    path attribute shows the placeholder, and these lines would show the real path (gate run 3, N-02)."""
    out, n, in_hunk = [], 0, False
    for line in diff.split("\n"):
        in_hunk = in_hunk or line.startswith("@@")
        if not in_hunk and _NAMING_HEADER.match(line):
            out.append(REMOVED)
            n += 1
        else:
            out.append(line)
    return "\n".join(out), n


def _head_lines(diff: str) -> frozenset[int]:
    lines: set[int] = set()
    n = 0
    in_hunk = False
    for raw in diff.split("\n"):
        m = _HUNK.match(raw)
        if m:
            n, in_hunk = int(m.group(1)), True
            continue
        if not in_hunk or raw.startswith(("+++", "---")):
            continue
        if raw.startswith(("+", " ")):
            lines.add(n)
            n += 1
    return frozenset(lines)


def _lock_block(repo: Path, base: str, head: str, path: str, shown: str) -> str | None:
    before = lock_packages(path, _show(repo, base, path) or "")
    after = lock_packages(path, _show(repo, head, path) or "")
    if before is None or after is None:
        return None
    names_after = {p.rsplit("@", 1)[0] for p in after}
    lines = [f"+ {p}" for p in sorted(after - before)]
    lines += [f"- {p}" for p in sorted(before - after) if p.rsplit("@", 1)[0] not in names_after]
    body = "\n".join(lines) or "(no package name or version changed)"
    return data_block("lockfile", body, path=shown, note="package names and versions only; nothing else of the file is sent")


def _pr_context(environ: Mapping[str, str]) -> tuple[str, str, list[str]]:
    title, body, notes = "", "", []
    ctx_path = environ.get("SB_PR_CONTEXT")
    if ctx_path:
        try:
            text = Path(ctx_path).read_bytes()[:PR_TEXT_MAX_BYTES].decode("utf-8", errors="replace")
        except OSError:
            notes.append("the PR context file named by SB_PR_CONTEXT could not be read; the review has no PR description")
            text = ""
        doc = None
        if text.lstrip().startswith("{"):
            try:
                doc = json.loads(text)
            except ValueError:
                doc = None
        if isinstance(doc, dict):
            title, body = str(doc.get("title", "")), str(doc.get("body", ""))
        elif text:
            first, _, rest = text.lstrip("\n").partition("\n")
            title, body = first.lstrip("#").strip(), rest.strip("\n")
    title = environ.get("SB_PR_TITLE", title)[:PR_TEXT_MAX_BYTES]
    body = environ.get("SB_PR_BODY", body)[:PR_TEXT_MAX_BYTES]
    return title, body, notes


def _manifest_rows(text: str | None) -> dict[str, tuple[ManifestRow, str]]:
    rows: dict[str, tuple[ManifestRow, str]] = {}
    for line in (text or "").splitlines():
        if not _ROW.match(line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 6:
            continue
        impl = cells[2].replace("`", "").strip()
        rows[cells[0]] = (ManifestRow(id=cells[0], control=cells[1], implementation=impl,
                                      proving_test=cells[4].replace("`", ""), note=cells[5]), line)
    return rows


def row_cells(row: ManifestRow) -> tuple[str, str, str]:
    """The cells of a manifest row the Control Completeness request shows, each sanitized there."""
    return row.implementation, row.control, row.proving_test


def _qa_evidence(run_dir: Path, rows: tuple[ManifestRow, ...]) -> QaEvidence:
    qa_dir = run_dir.parent / "qa"
    if not qa_dir.is_dir():
        return QaEvidence(False, frozenset(), "QA did not run in this run: the manifest's rows are claims no test has "
                                              "been shown to prove here; treat each as unproven")
    log = qa_dir / "mutate-controls.log"
    if not log.is_file():
        return QaEvidence(False, frozenset(), "QA ran but did not mutate the controls in this run (mutation off, or no "
                                              "manifest): the manifest's rows are unproven claims")
    table = parse_mutation_table(log.read_text(errors="replace"))
    proven = frozenset(r.id for r in table if r.verdict.startswith("✓"))
    ids = [r.id for r in rows]
    unproven = [i for i in ids if i not in proven]
    if not ids:
        return QaEvidence(False, proven, "the manifest declares no rows, so there is nothing QA could prove")
    if unproven:
        return QaEvidence(False, proven, f"QA proved {len(ids) - len(unproven)} of {len(ids)} manifest rows in this run; "
                                         f"not proven here: {', '.join(unproven)} — treat those rows as claims")
    return QaEvidence(True, proven, f"QA proved every row of the manifest in this run ({len(ids)} rows went red under mutation)")


def with_qa_evidence(req: ReviewRequest, run_dir: Path) -> ReviewRequest:
    """The request with what QA proved read again now: a request built before QA ran (the gate's
    prepare step) said QA had not run, and that note is replaced where it stood."""
    qa = _qa_evidence(run_dir, req.manifest_rows)
    return replace(req, qa=qa, notes=tuple(qa.note if n == req.qa.note else n for n in req.notes))


def _commits(repo: Path, base: str, head: str) -> str:
    raw = _git(repo, "log", f"--max-count={COMMITS_MAX}", "--format=%h %s%n%b%x00", f"{base}..{head}")
    text = "\n".join(m.strip() for m in raw.split("\0") if m.strip())
    return text[:COMMITS_MAX_BYTES]


def _path_labels(paths: list[str]) -> dict[str, str]:
    """CM-50 for paths: each one that reads as an instruction (or could be mistaken for a placeholder)
    gets a numbered placeholder, the same in every prompt of the run (gate run 2, B-02). Quoting alone
    keeps a path inside its data block; this keeps its words away from the model."""
    labels: dict[str, str] = {}
    for path in paths:
        if path not in labels and (path_is_instruction_like(path) or path.startswith("[path withheld")):
            labels[path] = WITHHELD_PATH.format(n=len(labels) + 1)
    return labels


def build_request(ctx: GateContext, settings: Settings, environ: Mapping[str, str]) -> ReviewRequest:
    repo, base, head = ctx.repo, ctx.base, ctx.head
    count = _Counter()
    items = tuple(items_for(ctx.profile))
    changed = _changed(repo, base, head)
    diff_paths = frozenset(p for p, _ in changed)

    named_why: dict[str, str] = {settings.manifest: "the control manifest"}
    if settings.config_path:
        named_why.setdefault(settings.config_path, "the Secure Builder config")
    for item in items:
        for r in item.reads:
            named_why.setdefault(r, f"checklist item {item.id} names it")
    labels = _path_labels([p for p, _ in changed] + list(named_why))
    count.sanitized += len(labels)

    files: list[FileDiff] = []
    withheld_blocks: list[str] = []
    not_sent: list[tuple[str, str]] = []
    omitted: list[str] = []
    used = 0
    for path, binary in changed:
        why = None if may_send(path, diff_paths) else (withheld(path) or "not sendable")
        why = why or ("a binary file" if binary else None)
        block, lines = None, frozenset()
        shown = labels.get(path, path)
        if why is None and PurePosixPath(path).name in LOCKFILES:
            block = _lock_block(repo, base, head, path, shown)
            if block is None:
                why = "a lockfile in a format whose names and versions this does not read: withheld whole"
        if why is None and block is None:
            raw = _git(repo, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "-U3", base, head, "--",
                       path)
            lines = _head_lines(raw)
            if path in labels:
                raw, n = _without_path_headers(raw)
                count.sanitized += n
            block = data_block("diff", count.text(raw, diff=True), path=shown)
        if why is not None or block is None:
            why = why or "not sendable"
            not_sent.append((path, why))
            withheld_blocks.append(data_block("withheld", f"{quote(shown)} changed in this range; its content is not sent: {why}.",
                                              path=shown))
            continue
        size = len(block.encode())
        if used + size > settings.max_diff_bytes:
            omitted.append(path)
            continue
        used += size
        files.append(FileDiff(path=path, block=block, lines=lines))

    allowed = frozenset(named_why)
    named: list[NamedFile] = []
    missing: list[str] = []
    for path, why in named_why.items():
        if not may_send(path, allowed):
            not_sent.append((path, withheld(path) or "not sendable"))
            continue
        text = _show(repo, head, path)
        if text is None:
            missing.append(path)
            continue
        if len(text.encode()) > NAMED_FILE_MAX_BYTES:
            text = text.encode()[:NAMED_FILE_MAX_BYTES].decode("utf-8", errors="ignore") + \
                f"\n(cut at {NAMED_FILE_MAX_BYTES} bytes; the rest of the file was not sent)\n"
        named.append(NamedFile(path=path, text=count.text(text), why=why))

    title, body, notes = _pr_context(environ)
    title, body = count.text(title), count.text(body)
    commits = count.text(_commits(repo, base, head))

    head_rows = _manifest_rows(_show(repo, head, settings.manifest))
    base_rows = _manifest_rows(_show(repo, base, settings.manifest))
    rows = tuple(r for r, _ in head_rows.values())
    touched = tuple(r for i, (r, line) in head_rows.items()
                    if r.path in diff_paths or base_rows.get(i, (None, None))[1] != line)
    count.sanitized += sum(1 for r in touched for cell in row_cells(r) if is_instruction_like(cell))
    qa = _qa_evidence(ctx.run_dir, rows)
    notes.append(qa.note)
    if omitted:
        notes.append(f"the diff is over sentinel.max_diff_bytes ({settings.max_diff_bytes}); "
                     f"{len(omitted)} file(s) were not sent, listed in the omitted data block")
    return ReviewRequest(profile=ctx.profile, depth=ctx.depth, items=items, files=tuple(files),
                         withheld_blocks=tuple(withheld_blocks), not_sent=tuple(not_sent), omitted=tuple(omitted),
                         named=tuple(named), missing_named=tuple(missing), pr_title=title, pr_body=body,
                         commits=commits, manifest_rows=rows, touched=touched, qa=qa,
                         sanitized_lines=count.sanitized, redacted_secrets=count.redacted, notes=tuple(notes),
                         unsafe_paths=sum(1 for p in diff_paths if unsafe_text(p)), path_labels=tuple(labels.items()))
