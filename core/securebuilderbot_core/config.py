"""`.securebuilderbot.yml`: load it, validate it, resolve its profile (docs/PRD.md § Configuration).

Every refusal names the file and the line, because the file is the only interface most users ever
touch. Three keys are required; everything else defaults from the profile. A key shaped like a
credential (`*_key`, `*_secret`, `*_token`, `*_password`) must hold the NAME of a CI secret, never
its value, and the error for a bad one never repeats what was written there.
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import os
import re
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import yaml

from .profiles import Profile, ProfileError, custom_profile, load_profile
from .receipt import SECRET, shown

GATES = ("scan", "qa", "sentinel")
SCANNERS = ("hadolint", "checkov", "clamav", "grype", "trivy", "npm-audit", "eslint")
PROFILE_NAMES = ("none", "il4", "il6", "custom")
PROVIDERS = ("anthropic", "openai", "self-hosted")
DEPTHS = ("auto", "always-deep", "always-light")
SECRET_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
SECRET_SHAPED = re.compile(r".*_(key|secret|token|password)$")
VERSION = re.compile(r"latest|\d+\.\d+\.\d+")
MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}")
MIN_DIFF_BYTES = 1000
_shown = shown  # receipt.shown: one rule for every message that repeats a config value


def _is_secret_name(value: object) -> bool:
    """The name of a CI secret: A–Z, 0–9, _. A credential in that alphabet (an AWS key id) is a value, not a name."""
    return isinstance(value, str) and bool(SECRET_NAME.fullmatch(value)) and not SECRET.search(value)

SCHEMA: dict[str, set[str] | None] = {
    "profile": None, "gates": None, "version": None,
    "custom": {"base", "add", "remove"},
    "sentinel": {"provider", "key_secret", "depth", "endpoint", "model", "max_diff_bytes"},
    "qa": {"test_command", "manifest", "mutation"},
    "scan": {"accepted_risks", "skip"},
}


class ConfigError(Exception):
    """A config that cannot be used, with the line that says why."""

    def __init__(self, path: Path, line: int, message: str):
        super().__init__(f"{path}:{line}: {message}")
        self.path, self.line, self.message = path, line, message


@dataclass(frozen=True)
class SentinelConfig:
    provider: str = "anthropic"
    key_secret: str | None = None
    depth: str = "auto"
    endpoint: str | None = None  # a mirror or self-hosted model endpoint, for air-gapped installs
    model: str | None = None     # None: the provider's default (the sentinel module names it)
    max_diff_bytes: int = 300000  # a larger diff is cut by whole files, and the run is yellow at best


@dataclass(frozen=True)
class QaConfig:
    test_command: str = "auto"
    manifest: str = "docs/security/CONTROL-MANIFEST.md"
    mutation: bool | None = None  # None: the profile decides


@dataclass(frozen=True)
class ScanConfig:
    accepted_risks: str = "docs/security/accepted-risks.yml"
    skip: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    path: Path
    sha256: str
    profile: Profile
    gates: tuple[str, ...]
    version: str
    sentinel: SentinelConfig
    qa: QaConfig
    scan: ScanConfig
    relaxations: tuple[str, ...]  # profile requirements this config turned off: a yellow on every run


class _Doc:
    """The parsed file plus the line of every key and list item, by path."""

    def __init__(self, path: Path, text: str):
        self.path = path
        self.lines: dict[tuple, int] = {(): 1}
        self._seen: set[int] = set()
        try:
            node = yaml.compose(text)
            if node is not None:
                self._walk(node, ())  # before loading: an alias is refused before anything expands it
            self.data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)
            raise ConfigError(path, mark.line + 1 if mark else 1, f"not valid YAML: {getattr(e, 'problem', e)}") from None

    def _walk(self, node: yaml.Node, at: tuple) -> None:
        # A YAML alias is the same node reached twice. Walking it again would let a ten-line file
        # expand into millions of paths (a billion-laughs config in a pull request), so the config
        # does not allow them: it is three lines, and nothing in it needs to repeat.
        if isinstance(node, (yaml.MappingNode, yaml.SequenceNode)):
            if id(node) in self._seen:
                raise ConfigError(self.path, node.start_mark.line + 1, "YAML anchors and aliases are not allowed in this file")
            self._seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                if not isinstance(key_node, yaml.ScalarNode):  # `? [a, b]: x` — a key that is a list or a map
                    raise ConfigError(self.path, key_node.start_mark.line + 1, "a key must be a plain name, not a list or a mapping")
                key = key_node.value
                if at + (key,) in self.lines:
                    dotted = ".".join(map(str, at + (key,)))
                    raise ConfigError(self.path, key_node.start_mark.line + 1, f"duplicate key {_shown(dotted)}")
                self.lines[at + (key,)] = key_node.start_mark.line + 1
                self._walk(value_node, at + (key,))
        elif isinstance(node, yaml.SequenceNode):
            for i, item in enumerate(node.value):
                self.lines[at + (i,)] = item.start_mark.line + 1
                self._walk(item, at + (i,))

    def fail(self, at: tuple, message: str) -> ConfigError:
        while at not in self.lines:
            at = at[:-1]
        return ConfigError(self.path, self.lines[at], message)


def _check_secret_shaped(doc: _Doc, value: object, at: tuple) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and SECRET_SHAPED.match(k) and not _is_secret_name(v):
                dotted = ".".join(map(str, at + (k,)))
                raise doc.fail(at + (k,), f"{dotted} must be the name of a CI secret (A–Z, 0–9, _), "
                                          "not its value — the value written there is not shown")
            _check_secret_shaped(doc, v, at + (k,))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _check_secret_shaped(doc, v, at + (i,))


def _enum(doc: _Doc, value: object, allowed: tuple[str, ...], at: tuple, name: str) -> str:
    if value not in allowed:
        raise doc.fail(at, f"{name} must be one of {', '.join(allowed)}")
    return str(value)


def _endpoint(doc: _Doc, value: object) -> str | None:
    """An http(s) URL with a host and no credentials, query or fragment; the value is never repeated."""
    if value is None:
        return None
    at = ("sentinel", "endpoint")
    parts = urllib.parse.urlsplit(value) if isinstance(value, str) else None
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        raise doc.fail(at, "sentinel.endpoint must be an http or https URL, e.g. https://llm.internal.example/")
    if parts.username is not None or parts.password is not None:
        raise doc.fail(at, "sentinel.endpoint must not carry credentials — the key comes from sentinel.key_secret; "
                           "the value written there is not shown")
    if parts.query or parts.fragment:
        raise doc.fail(at, "sentinel.endpoint takes a base URL with no query or fragment")
    if parts.scheme == "http" and not _loopback(parts.hostname):
        # The model key travels in every request; plain http is allowed only where it never leaves the
        # machine (sentinel gate run 1, N-04).
        raise doc.fail(at, "sentinel.endpoint must be https unless it is this machine (localhost, 127.0.0.0/8 or ::1): "
                           "the model key travels in every request")
    return value


def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _sentinel(doc: _Doc, gates: tuple[str, ...]) -> SentinelConfig:
    s = _section(doc, "sentinel")
    model = s.get("model")
    if model is not None and not (isinstance(model, str) and MODEL_ID.fullmatch(model)):
        raise doc.fail(("sentinel", "model"), "sentinel.model must be a model id (letters, digits and . _ : / @ -)")
    budget = s.get("max_diff_bytes", SentinelConfig.max_diff_bytes)
    if isinstance(budget, bool) or not isinstance(budget, int) or budget < MIN_DIFF_BYTES:
        raise doc.fail(("sentinel", "max_diff_bytes"),
                       f"sentinel.max_diff_bytes must be a whole number of bytes, at least {MIN_DIFF_BYTES}")
    sentinel = SentinelConfig(
        provider=_enum(doc, s.get("provider", "anthropic"), PROVIDERS, ("sentinel", "provider"), "sentinel.provider"),
        key_secret=s.get("key_secret"),
        depth=_enum(doc, s.get("depth", "auto"), DEPTHS, ("sentinel", "depth"), "sentinel.depth"),
        endpoint=_endpoint(doc, s.get("endpoint")), model=model, max_diff_bytes=budget,
    )
    # A self-hosted or openai provider with no endpoint or model is a valid file (the setup PR writes one
    # before the user has a server to name); the sentinel gate reports it not_run, naming the key to add.
    if "sentinel" in gates and not sentinel.key_secret:
        raise doc.fail(("gates",), "the sentinel gate needs sentinel.key_secret, the name of the CI secret holding the model key")
    return sentinel


def _section(doc: _Doc, key: str) -> dict:
    value = doc.data.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise doc.fail((key,), f"{key} must be a mapping")
    allowed = SCHEMA[key] or set()
    for k in value:
        if k not in allowed:
            raise doc.fail((key, k), f"unknown key {_shown(f'{key}.{k}')}")
    return value


def _gates(doc: _Doc) -> tuple[str, ...]:
    gates = doc.data["gates"]
    if not isinstance(gates, list):
        raise doc.fail(("gates",), "gates must be a list, e.g. [scan, qa]")
    if not gates:
        raise doc.fail(("gates",), "gates is empty — turn on at least one of scan, qa, sentinel")
    seen: list[str] = []
    for i, g in enumerate(gates):
        if g not in GATES:
            raise doc.fail(("gates", i), f"unknown gate {_shown(g)} — one of {', '.join(GATES)}")
        if g in seen:
            raise doc.fail(("gates", i), f"gate {g!r} listed twice")
        seen.append(g)
    return tuple(g for g in GATES if g in seen)  # always run in the fixed order


def _profile(doc: _Doc) -> Profile:
    name = _enum(doc, doc.data["profile"], PROFILE_NAMES, ("profile",), "profile")
    has_block = "custom" in doc.data
    if name != "custom":
        if has_block:
            raise doc.fail(("custom",), "a custom block needs profile: custom")
        return load_profile(name)
    if not has_block:
        raise doc.fail(("profile",), "profile: custom needs a custom block with base, add and remove")
    block = _section(doc, "custom")
    lists = {}
    for key in ("add", "remove"):
        items = block.get(key, []) or []
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            raise doc.fail(("custom", key), f"custom.{key} must be a list of control ids")
        lists[key] = items
    try:
        return custom_profile(str(block.get("base")), lists["add"], lists["remove"])
    except ProfileError as e:
        raise doc.fail(("custom",), str(e)) from None


def load_config(path: Path) -> Config:
    path = Path(path)
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ConfigError(path, raw[:e.start].count(b"\n") + 1, "the config is not UTF-8 text") from None
    doc = _Doc(path, text)
    if not isinstance(doc.data, dict):
        raise ConfigError(path, 1, "the config must be a mapping of keys, starting with profile, gates and version")
    for key in doc.data:
        if key not in SCHEMA:
            raise doc.fail((key,), f"unknown key {_shown(key)}")
    for key in ("profile", "gates", "version"):
        if key not in doc.data:
            raise ConfigError(path, 1, f"missing required key {key!r}")
    _check_secret_shaped(doc, doc.data, ())

    version = doc.data["version"]
    if not (isinstance(version, str) and VERSION.fullmatch(version)):
        raise doc.fail(("version",), "version must be latest or x.y.z (quote it if YAML reads it as a number)")
    profile = _profile(doc)
    gates = _gates(doc)

    sentinel = _sentinel(doc, gates)

    q = _section(doc, "qa")
    mutation = q.get("mutation")
    if mutation is not None and not isinstance(mutation, bool):
        raise doc.fail(("qa", "mutation"), "qa.mutation must be true or false")
    qa = QaConfig(test_command=str(q.get("test_command", "auto")),
                  manifest=str(q.get("manifest", QaConfig.manifest)), mutation=mutation)

    sc = _section(doc, "scan")
    skip = sc.get("skip", []) or []
    if not isinstance(skip, list):
        raise doc.fail(("scan", "skip"), "scan.skip must be a list of scanner names")
    for i, name in enumerate(skip):
        if name not in SCANNERS:
            raise doc.fail(("scan", "skip", i), f"unknown scanner {_shown(name)} — one of {', '.join(SCANNERS)}")
    accepted = str(sc.get("accepted_risks", ScanConfig.accepted_risks))
    if Path(accepted).is_absolute() or ".." in Path(accepted).parts:
        raise doc.fail(("scan", "accepted_risks"), "scan.accepted_risks must be a path inside the repository, relative to its root: "
                                                   "the file is read from the base commit, so it has to be one")
    scan = ScanConfig(accepted_risks=accepted, skip=tuple(skip))

    relaxations = []
    if mutation is False and profile.qa.mutation_required:
        relaxations.append(f"qa.mutation is off; profile {profile.name} requires mutation of controls")
    if skip:
        relaxations.append(f"scan.skip turns off {', '.join(skip)}")
    return Config(path=path, sha256=hashlib.sha256(raw).hexdigest(), profile=profile, gates=gates,
                  version=version, sentinel=sentinel, qa=qa, scan=scan, relaxations=tuple(relaxations))


# ── Which copy governs a run: the base branch's, never the pull request's (docs/PRD.md § Configuration) ──

GIT = ("git", "--no-replace-objects", "--literal-pathspecs")  # a replace ref cannot swap the base's blob


@dataclass(frozen=True)
class Governing:
    config: Config               # the settings every gate runs with
    source: str                  # "base" · "pull request" (the base has no config yet) · "outside the checkout" · "head"
    changed: tuple[str, ...]     # settings the pull request's copy changes; they apply once it is merged
    ref: str = ""                # the commit the config and every excusing list are read from: the target branch's tip
    workflow_changed: tuple[str, ...] = ()  # CI workflow files the range changes: what runs is the workflow's to decide


def blob_at(repo: Path, rev: str, rel: str) -> tuple[str, bytes | None]:
    """(the tree entry's mode, its bytes) for `rel` at `rev`, read by blob id; ("", None) when absent."""
    out = subprocess.run([*GIT, "-C", str(repo), "ls-tree", "-z", "--full-tree", rev, "--", rel], capture_output=True)
    if out.returncode != 0:
        raise ConfigError(Path(rel), 1, f"the base commit {rev[:12]} could not be read: {out.stderr.decode(errors='replace').strip()}")
    meta, _, name = out.stdout.split(b"\0")[0].partition(b"\t")
    parts = meta.decode("ascii", errors="replace").split()
    if len(parts) != 3 or name.decode("utf-8", errors="replace") != rel:
        return "", None
    mode, kind, sha = parts
    if mode == "120000":
        return mode, None  # a link: every caller refuses it
    if kind != "blob":
        raise ConfigError(Path(rel), 1, f"{rel} at {rev[:12]} is a {kind}, not a file")
    blob = subprocess.run([*GIT, "-C", str(repo), "cat-file", "blob", sha], capture_output=True)
    if blob.returncode != 0:  # present in the tree but unreadable (a partial clone's failed fetch): never "absent"
        raise ConfigError(Path(rel), 1, f"{rel} at {rev[:12]} could not be read: {blob.stderr.decode(errors='replace').strip()}")
    return mode, blob.stdout


def _changes(head: Config, base: Config) -> tuple[str, ...]:
    out = [k for k in ("profile", "gates", "version") if getattr(head, k) != getattr(base, k)]
    for section in ("sentinel", "qa", "scan"):
        h, b = getattr(head, section), getattr(base, section)
        out += [f"{section}.{f.name}" for f in dataclasses.fields(h) if getattr(h, f.name) != getattr(b, f.name)]
    return tuple(sorted(out))


def _path_in_checkout(given: Path, repo_real: str) -> str | None:
    """`given` as a path inside the checkout, spelled as written, or None when it is outside.

    The nearest ancestor that resolves to the checkout's root is the root (so a linked prefix such as
    /tmp on macOS still finds it); every directory between it and the file is the checkout's own and
    must not be a link, or the pull request could point the lookup at a path the target does not
    have and run under its own copy as if it were the adoption pull request."""
    parts = [given.name]
    cur = given.parent
    while os.path.realpath(cur) != repo_real:
        if cur.parent == cur:
            return None
        parts.insert(0, cur.name)
        cur = cur.parent
    walk = cur
    for name in parts[:-1]:
        walk = walk / name
        if walk.is_symlink():
            raise ConfigError(given, 1, f"{walk} is a symbolic link in the checkout: the config is looked up by its "
                                        "path in the target branch's tip, never through a link the pull request could plant")
    return "/".join(parts)


def governing_config(head: Config, repo: Path, base: str) -> Governing:
    """The config a run on `repo` against `base` obeys.

    A pull request must not loosen its own gate: the copy in the base commit governs (gates, profile,
    skipped scanners, the exceptions file, mutation, Sentinel), and what the pull request's copy changes
    is reported, applying once it is merged. A base with no config yet is the adoption pull request, so
    its own copy is used and said; a config outside the checkout is not the pull request's to change.
    The pull request's copy is still validated, so a broken file fails before any gate runs."""
    rel = _path_in_checkout(Path(head.path).absolute(), os.path.realpath(repo))
    if rel is None:
        return Governing(config=head, source="outside the checkout", changed=(), ref=base)
    mode, data = blob_at(repo, base, rel)
    if mode == "120000":
        raise ConfigError(head.path, 1, f"the config is a symbolic link in the base commit {base[:12]}: "
                                        "the settings are read from a file in the base commit, never through a link")
    if data is None:
        return Governing(config=head, source="pull request", changed=(), ref=base)
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / Path(rel).name
        copy.write_bytes(data)
        try:
            base_config = load_config(copy)
        except ConfigError as e:
            raise ConfigError(head.path, e.line, f"the config at the base commit {base[:12]} does not validate: {e.message}") from None
    base_config = dataclasses.replace(base_config, path=head.path)
    return Governing(config=base_config, source="base", changed=_changes(head, base_config), ref=base)
