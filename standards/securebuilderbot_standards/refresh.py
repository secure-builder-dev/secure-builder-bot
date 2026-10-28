"""The weekly refresh, in this repository only (docs/PRD.md § Staying current).

Each vendored index records where it came from. This fetches every one of those upstreams, rebuilds
the index with the builder that wrote it, compares the result with the committed copy, and when
something moved regenerates the index and writes a changelog entry naming what moved: controls
added, withdrawn, renamed or removed; baseline membership; STIG rules; OWASP titles; MASVS controls;
NIST publication revisions. A maintainer reads the PR; users take the change as a release. Nothing
here is ever scheduled in a user's repository.

THE REFUSAL (CM-31)
  A catalog revision that withdraws or drops a control this repository cites is not adopted. The
  checklist would then cite a control that no longer exists, which is the defect the verifier exists
  to catch, and adopting it would turn every run red until a human re-cites. So the refresh stops,
  names each item (file, line, control, what became of it), writes that record to the changelog so the
  PR carries it, and exits 1. The human re-cites, then re-runs.

OFFLINE
  `--offline DIR` reads the upstream files from DIR instead of the network: the catalog and baseline
  profiles by their published file names, the OWASP lists as `Top10/` and `llm/` checkouts, the STIGs
  as `cac/`, MASVS as `masvs/`, NIST's publication list as `ntp/` (a git checkout; the builder reads
  its tree). An upstream absent from DIR is reported as not provided, never silently current. The
  tests run this way, against fixtures; so does the self-test.

EXIT  0 nothing to do · 3 something changed (written, or under --dry-run, reported)
      1 refused: the new catalog breaks a citation · 2 could not run (an upstream unreachable or
      unreadable, a baseline naming a control the catalog lacks, a bad offline directory)
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from . import data
from .citations import judge_nist, line_is_exempt, tracked_documents

SCRIPTS = data.PACKAGE_DIR.parent / "scripts"
CATALOG_URL = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/"
               "NIST_SP-800-53_rev5_catalog.json")
# The checkout this package belongs to: standards/securebuilderbot_standards/refresh.py → the repository root.
REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_URL = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/"
                "NIST_SP-800-53_rev5_{LEVEL}-baseline_profile.json")
REPOS = {  # offline directory name → (index file, key path to the recorded repository, default, blobless)
    "Top10": (data.OWASP_FILE, ("_sources", "web", "repo"), "https://github.com/OWASP/Top10.git", False),
    "llm": (data.OWASP_FILE, ("_sources", "llm", "repo"),
            "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications.git", False),
    "cac": (data.STIG_FILE, ("_redistributor",), "https://github.com/ComplianceAsCode/content", True),
    "masvs": (data.MASVS_FILE, ("_source", "repo"), "https://github.com/OWASP/masvs", False),
    "ntp": (data.PUBS_FILE, ("_source", "repo"), "https://github.com/usnistgov/NIST-Tech-Pubs", True),
}
FETCH_TIMEOUT = 300
CHANGELOG_HEADER = """# Standards changelog

Written by `standards/run refresh`, the weekly refresh this repository runs on itself, whenever a
vendored index under `standards/data/controls/` changes. Newest first. A refused entry records a
catalog revision that was NOT adopted because it withdraws or drops a control this repository cites.
"""


class RefreshError(RuntimeError):
    """The refresh could not run: an upstream unreachable or unreadable, or a built index that is not usable."""


@dataclass(frozen=True)
class Broken:
    id: str
    path: str
    line: int
    why: str


@dataclass
class Report:
    lines: list[str] = field(default_factory=list)       # what is printed
    changes: list[str] = field(default_factory=list)     # changelog bullets
    headline: list[str] = field(default_factory=list)    # changelog heading parts
    writes: list[tuple[Path, Path]] = field(default_factory=list)  # (built file, destination)
    broken: list[Broken] = field(default_factory=list)
    catalog_change: str | None = None

    def say(self, text: str) -> None:
        self.lines.append(text)


# ── CM-31 ─────────────────────────────────────────────────────────────────────────────────────

def refuse_broken_citations(old_controls: dict, new_controls: dict, docs: dict[str, str]) -> list[Broken]:
    """CM-31: the citations a new catalog would break — resolving today, not resolving under it. Non-empty refuses adoption."""
    broken: list[Broken] = []
    for path, text in docs.items():
        for n, line in enumerate(text.splitlines(), 1):
            if line_is_exempt(line):
                continue
            before = {c.id: c for c in judge_nist(line, n, path, old_controls)}
            for c in judge_nist(line, n, path, new_controls):
                was = before.get(c.id)
                if c.ok or was is None or not was.ok:
                    continue
                entry = new_controls.get(c.id)
                if entry is None:
                    why = "removed from the catalog"
                else:
                    into = ", ".join(entry.get("into", ()))
                    why = f"{entry.get('s', 'withdrawn')}" + (f", incorporated into {into}" if into else ", no replacement named")
                broken.append(Broken(c.id, path, n, why))
    return broken


# ── upstreams ─────────────────────────────────────────────────────────────────────────────────

class Upstreams:
    """Where each upstream is read from: a directory given with --offline, or the network."""

    def __init__(self, offline: Path | None, tmp: Path, data_dir: Path):
        self.offline, self.tmp, self.data_dir = offline, tmp, data_dir

    def _recorded(self, index: str, keys: tuple[str, ...], default: str) -> str:
        raw = data.raw_index(index, self.data_dir) or {}
        for k in keys:
            raw = raw.get(k, {}) if isinstance(raw, dict) else {}
        return raw if isinstance(raw, str) and raw else default

    def file(self, name: str, url: str) -> Path | None:
        """A single upstream file by its published name; None when offline and not provided."""
        if self.offline is not None:
            p = self.offline / name
            return p if p.is_file() else None
        dest = self.tmp / name
        # curl, as the shell refresh always fetched: it honours the proxy settings a CI runner or an
        # air-gapped mirror configures, and --fail turns an HTTP error into a non-zero exit.
        cmd = ["curl", "-sSL", "--fail", "--max-time", str(FETCH_TIMEOUT), "-o", str(dest), url]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=FETCH_TIMEOUT + 30)
        except (OSError, subprocess.SubprocessError) as e:
            raise RefreshError(f"UNREACHABLE — {url}: {e}") from None
        if out.returncode != 0 or not dest.is_file():
            raise RefreshError(f"UNREACHABLE — {url}: {out.stderr.strip().splitlines()[-1] if out.stderr.strip() else 'fetch failed'}")
        return dest

    def repo(self, name: str) -> Path | None:
        """An upstream git repository as a directory; None when offline and not provided."""
        index, keys, default, blobless = REPOS[name]
        if self.offline is not None:
            p = self.offline / name
            return p if p.is_dir() else None
        url = self._recorded(index, keys, default)
        dest = self.tmp / name
        cmd = ["git", "clone", "--depth", "1", "--quiet", *(["--filter=blob:none"] if blobless else []), url, str(dest)]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=FETCH_TIMEOUT * 4)
        except (OSError, subprocess.SubprocessError) as e:
            raise RefreshError(f"UNREACHABLE — {url}: {e}") from None
        if out.returncode != 0:
            raise RefreshError(f"UNREACHABLE — {url}: {out.stderr.strip().splitlines()[-1] if out.stderr.strip() else 'clone failed'}")
        return dest


def _build(script: str, *args: str) -> None:
    out = subprocess.run([sys.executable, str(SCRIPTS / script), *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RefreshError(f"{script}: {(out.stderr or out.stdout).strip().splitlines()[-1] if (out.stderr or out.stdout).strip() else 'failed'}")


def _load_module(script: str):
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(script.replace("-", "_").removesuffix(".py"), SCRIPTS / script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _title(controls: dict, cid: str) -> str:
    return controls.get(cid, {}).get("t", "")


# ── each source ───────────────────────────────────────────────────────────────────────────────

def _catalog(up: Upstreams, rep: Report, docs: dict[str, str]) -> dict | None:
    """The NIST catalog: returns the new controls mapping when it changed (adopted or refused), else None."""
    old = data.raw_catalog(up.data_dir)
    src = up.file(Path(CATALOG_URL).name, old.get("_source") or CATALOG_URL)
    if src is None:
        rep.say("  NIST SP 800-53 catalog : not provided in the offline directory — not checked")
        return None
    built = up.tmp / data.CATALOG_FILE
    _build("build-control-index.py", str(src), str(built))
    new = _json(built)
    old_v, new_v = str(old.get("_catalog_version")), str(new.get("_catalog_version"))
    if old["controls"] == new["controls"] and old_v == new_v:
        rep.say(f"  NIST SP 800-53 catalog : CURRENT {old_v} ({len(new['controls'])} controls)")
        return None
    oc, nc = old["controls"], new["controls"]
    added = sorted(k for k in nc if k not in oc)
    removed = sorted(k for k in oc if k not in nc)
    withdrawn = sorted(k for k in nc if k in oc and oc[k].get("s") == "active" and nc[k].get("s") != "active")
    reinstated = sorted(k for k in nc if k in oc and oc[k].get("s") != "active" and nc[k].get("s") == "active")
    renamed = sorted(k for k in nc if k in oc and oc[k].get("t") != nc[k].get("t"))
    rep.catalog_change = f"NIST SP 800-53 Rev 5 catalog {old_v} → {new_v}"
    rep.say(f"  NIST SP 800-53 catalog : CHANGED {old_v} → {new_v}: {len(added)} added, {len(withdrawn)} withdrawn, "
            f"{len(renamed)} renamed, {len(removed)} removed")
    rep.headline.append(rep.catalog_change)
    for k in added:
        rep.changes.append(f"- added: {k} ({_title(nc, k)})")
    for k in withdrawn:
        into = ", ".join(nc[k].get("into", ())) or "no replacement named"
        rep.changes.append(f"- withdrawn: {k} ({_title(nc, k)}), incorporated into {into}")
    for k in reinstated:
        rep.changes.append(f"- reinstated: {k} ({_title(nc, k)})")
    for k in renamed:
        rep.changes.append(f"- renamed: {k} {_title(oc, k)!r} → {_title(nc, k)!r}")
    for k in removed:
        rep.changes.append(f"- removed: {k} ({_title(oc, k)})")
    for b in rep.changes[-(len(added) + len(withdrawn) + len(reinstated) + len(renamed) + len(removed)):]:
        rep.say("    " + b[2:])
    rep.broken = refuse_broken_citations(oc, nc, docs)
    if not docs and (withdrawn or renamed or removed):
        # No document judged is not "no citation broken": with nothing read, a catalog that withdraws or
        # renames controls would be adopted unchecked (standards gate run 1, B-01). Refuse instead.
        rep.broken.append(Broken("(every control the catalog withdraws, renames or drops)", "(no document was judged)", 0,
                                 "cannot be checked: no document was judged, so the catalog is not adopted unchecked"))
    rep.writes.append((built, up.data_dir / data.CATALOG_FILE))
    return nc


def _baselines(up: Upstreams, rep: Report, new_controls: dict | None) -> None:
    old = data.raw_index(data.BASELINES_FILE, up.data_dir) or {}
    files = {level: up.file(Path(BASELINE_URL.format(LEVEL=level.upper())).name,
                            old.get(f"_source_{level}") or BASELINE_URL.format(LEVEL=level.upper())) for level in data.LEVELS}
    if any(f is None for f in files.values()):
        rep.say("  baselines              : not provided in the offline directory — not checked")
        return
    gen = _load_module("build-baselines-index.py")
    known = set(new_controls if new_controls is not None else data.raw_catalog(up.data_dir)["controls"])
    doc: dict[str, object] = {"_generator": "standards/scripts/build-baselines-index.py", "_retrieved": _today()}
    for level in data.LEVELS:
        lvl, version, ids = gen.baseline(str(files[level]))
        if lvl != level:
            raise RefreshError(f"{files[level].name}: is the {lvl} baseline, not {level}")
        missing = [i for i in ids if i not in known]
        if missing:
            raise RefreshError(f"{files[level].name}: names {len(missing)} control(s) the catalog lacks, e.g. {missing[:3]}")
        doc["_catalog_version"] = version
        doc[f"_source_{level}"] = old.get(f"_source_{level}") or BASELINE_URL.format(LEVEL=level.upper())
        doc[level] = ids
    doc["_counts"] = {k: len(doc[k]) for k in data.LEVELS}
    same = all(old.get(k) == doc[k] for k in data.LEVELS) and str(old.get("_catalog_version")) == str(doc["_catalog_version"])
    if same:
        rep.say(f"  baselines              : CURRENT ({doc['_counts']['moderate']} moderate, {doc['_counts']['high']} high)")
        return
    rep.say("  baselines              : CHANGED")
    for level in data.LEVELS:
        was, now = set(old.get(level, ())), set(doc[level])
        plus, minus = sorted(now - was), sorted(was - now)
        if plus or minus:
            rep.changes.append(f"- {level.capitalize()} baseline: " + ", ".join(
                [f"+{k}" for k in plus] + [f"-{k}" for k in minus]))
    if str(old.get("_catalog_version")) != str(doc["_catalog_version"]):
        rep.changes.append(f"- baselines now at catalog {doc['_catalog_version']} (were {old.get('_catalog_version')})")
    built = up.tmp / data.BASELINES_FILE
    built.write_text(json.dumps(doc, indent=1) + "\n")
    rep.writes.append((built, up.data_dir / data.BASELINES_FILE))


def _owasp(up: Upstreams, rep: Report) -> None:
    t10, llm = up.repo("Top10"), up.repo("llm")
    if t10 is None or llm is None:
        rep.say("  OWASP Top 10 lists     : not provided in the offline directory — not checked")
        return
    built = up.tmp / data.OWASP_FILE
    _build("build-owasp-index.py", str(t10), str(llm), str(built))
    old, new = data.raw_index(data.OWASP_FILE, up.data_dir) or {}, _json(built)

    def current(doc: dict, which: str) -> tuple[str, dict]:
        d = doc.get(which, {})
        return d.get("current", ""), d.get("editions", {}).get(d.get("current", ""), {})
    changed = False
    for which, label in (("web", "OWASP Top 10"), ("llm", "OWASP LLM Top 10")):
        (oe, ot), (ne, nt) = current(old, which), current(new, which)
        if oe != ne:
            changed = True
            rep.changes.append(f"- {label}: edition {oe or 'none'} → {ne}")
        for oid in sorted(set(ot) | set(nt)):
            if ot.get(oid) != nt.get(oid):
                changed = True
                rep.changes.append(f"- {label} {ne}: {oid} {ot.get(oid)!r} → {nt.get(oid)!r}")
    if not changed:
        rep.say("  OWASP Top 10 lists     : CURRENT")
        return
    rep.say("  OWASP Top 10 lists     : CHANGED")
    rep.writes.append((built, up.data_dir / data.OWASP_FILE))


def _stig(up: Upstreams, rep: Report) -> None:
    cac = up.repo("cac")
    if cac is None:
        rep.say("  DISA STIGs             : not provided in the offline directory — not checked")
        return
    built = up.tmp / data.STIG_FILE
    _build("build-stig-index.py", str(cac), str(built))
    old, new = data.raw_index(data.STIG_FILE, up.data_dir) or {}, _json(built)
    orules, nrules = old.get("rules", {}), new.get("rules", {})
    if orules == nrules:
        rep.say(f"  DISA STIGs             : CURRENT ({len(nrules)} rules)")
        return
    plus, minus = sorted(k for k in nrules if k not in orules), sorted(k for k in orules if k not in nrules)
    retitled = sorted(k for k in nrules if k in orules and orules[k].get("t") != nrules[k].get("t"))
    benchmarks = sorted(set(old.get("sources", {})) ^ set(new.get("sources", {})))
    rep.say(f"  DISA STIGs             : CHANGED: +{len(plus)} rules, -{len(minus)} rules, {len(retitled)} retitled")
    rep.changes.append(f"- STIG index: +{len(plus)} rule(s), -{len(minus)} rule(s), {len(retitled)} retitled"
                       + (f"; benchmarks changed: {', '.join(benchmarks)}" if benchmarks else ""))
    for k in plus[:50]:
        rep.changes.append(f"  - added {k}: {nrules[k].get('t', '')}")
    for k in minus[:50]:
        rep.changes.append(f"  - removed {k}: {orules[k].get('t', '')}")
    rep.writes.append((built, up.data_dir / data.STIG_FILE))


def _masvs(up: Upstreams, rep: Report) -> None:
    repo = up.repo("masvs")
    if repo is None:
        rep.say("  OWASP MASVS            : not provided in the offline directory — not checked")
        return
    built = up.tmp / data.MASVS_FILE
    _build("build-masvs-index.py", str(repo), str(built))
    old, new = data.raw_index(data.MASVS_FILE, up.data_dir) or {}, _json(built)
    oc, nc = old.get("controls", {}), new.get("controls", {})
    if oc == nc:
        rep.say(f"  OWASP MASVS            : CURRENT ({len(nc)} controls)")
        return
    rep.say("  OWASP MASVS            : CHANGED")
    for k in sorted(k for k in nc if k not in oc):
        rep.changes.append(f"- MASVS: added {k}: {nc[k]}")
    for k in sorted(k for k in oc if k not in nc):
        rep.changes.append(f"- MASVS: removed {k}")
    for k in sorted(k for k in nc if k in oc and oc[k] != nc[k]):
        rep.changes.append(f"- MASVS: {k} restated")
    rep.writes.append((built, up.data_dir / data.MASVS_FILE))


def _pubs(up: Upstreams, rep: Report) -> None:
    repo = up.repo("ntp")
    if repo is None:
        rep.say("  NIST publications      : not provided in the offline directory — not checked")
        return
    built = up.tmp / data.PUBS_FILE
    _build("build-nistpubs-index.py", str(repo), str(built))
    old, new = data.raw_index(data.PUBS_FILE, up.data_dir) or {}, _json(built)
    op, np_ = old.get("pubs", {}), new.get("pubs", {})
    if op == np_:
        rep.say(f"  NIST publications      : CURRENT ({len(np_)} publications)")
        return
    rep.say("  NIST publications      : CHANGED")
    for k in sorted(np_):
        if k not in op:
            rep.changes.append(f"- NIST publications: new {k}")
        elif op[k].get("latest") != np_[k].get("latest"):
            rep.changes.append(f"- NIST publications: {k} latest {op[k].get('latest') or '(original)'} → {np_[k].get('latest') or '(original)'}")
        elif op[k].get("drafts") != np_[k].get("drafts"):
            rep.changes.append(f"- NIST publications: {k} drafts {', '.join(np_[k].get('drafts', ())) or 'none'}")
    for k in sorted(k for k in op if k not in np_):
        rep.changes.append(f"- NIST publications: {k} no longer listed")
    rep.writes.append((built, up.data_dir / data.PUBS_FILE))


# ── the changelog ─────────────────────────────────────────────────────────────────────────────

def changelog_path(data_dir: Path) -> Path:
    return data_dir.parents[1] / "CHANGELOG.md"


def write_changelog(path: Path, entry: str) -> None:
    existing = path.read_text(encoding="utf-8") if path.is_file() else CHANGELOG_HEADER
    if "\n## " in existing:
        head, rest = existing.split("\n## ", 1)
        text = head.rstrip("\n") + "\n\n" + entry.rstrip("\n") + "\n\n## " + rest
    else:
        text = existing.rstrip("\n") + "\n\n" + entry.rstrip("\n") + "\n"
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _today() -> str:
    return datetime.date.today().isoformat()


# ── the run ───────────────────────────────────────────────────────────────────────────────────

def refresh(data_dir: Path | str | None = None, offline: Path | str | None = None, dry_run: bool = False,
            docs: list[str] | None = None, out: TextIO = sys.stdout, today: str | None = None) -> int:
    ddir = data._dir(data_dir)
    rep = Report()
    say = rep.say
    today = today or _today()
    off = Path(offline) if offline is not None else None
    if off is not None and not off.is_dir():
        print(f"refresh: --offline {off} is not a directory", file=out)
        return 2
    # The tracked documents are read from this package's own checkout, whatever the current directory:
    # a refresh run from a subdirectory once judged nothing and adopted what it should have refused.
    base = REPO_ROOT if docs is None else Path(".")
    paths = tracked_documents(REPO_ROOT) if docs is None else list(docs)
    docs_text = {p: (base / p).read_text(encoding="utf-8", errors="replace") for p in paths if (base / p).is_file()}
    say("── standards refresh " + (f"(offline: {off}) " if off else "(fetching every upstream) ") + "─" * 20)
    say(f"  vendored               : {ddir}")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            up = Upstreams(off, Path(tmp), ddir)
            new_controls = _catalog(up, rep, docs_text)
            _baselines(up, rep, new_controls)
            _owasp(up, rep)
            _stig(up, rep)
            _masvs(up, rep)
            _pubs(up, rep)
            code = _finish(rep, ddir, dry_run, today, len(docs_text))
    except RefreshError as e:
        for line in rep.lines:
            print(line, file=out)
        print(f"  ERROR — {e}", file=out)
        print("  This is an error, not a fallback: a refresh that quietly kept the stale copy is how a tree goes out of date unnoticed.", file=out)
        return 2
    for line in rep.lines:
        print(line, file=out)
    return code


def _finish(rep: Report, ddir: Path, dry_run: bool, today: str, n_docs: int) -> int:
    say = rep.say
    say("")
    if rep.broken:
        say(f"  REFUSED — {rep.catalog_change} withdraws or drops {len(rep.broken)} citation(s) in the {n_docs} documents checked;"
            " nothing adopted. Re-cite, then re-run:")
        bullets = [f"- {b.id} {b.why}: cited at {b.path}:{b.line}" for b in rep.broken]
        for b in bullets:
            say("    " + b[2:])
        entry = (f"## {today} — REFUSED: {rep.catalog_change} not adopted\n\n"
                 "The catalog withdraws or drops controls this repository cites; adopting it would make the citation check fail. "
                 "Re-cite each item, then re-run `standards/run refresh`.\n\n" + "\n".join(bullets) + "\n")
        if not dry_run:
            write_changelog(changelog_path(ddir), entry)
            say(f"  recorded in {changelog_path(ddir)}")
        return 1
    if not rep.writes:
        say("  nothing to do — every vendored index checked matches its upstream")
        return 0
    heading = "; ".join(rep.headline) or "vendored standards refreshed"
    entry = f"## {today} — {heading}\n\n" + "\n".join(rep.changes) + "\n"
    if dry_run:
        say(f"  dry run — would rewrite {', '.join(p.name for _, p in rep.writes)} and add this changelog entry:")
        for line in entry.splitlines():
            say("    " + line)
        return 3
    for built, dest in rep.writes:
        tmp = dest.with_name(f".{dest.name}.tmp")
        shutil.copyfile(built, tmp)
        os.replace(tmp, dest)
        say(f"  written {dest}")
    write_changelog(changelog_path(ddir), entry)
    say(f"  changelog {changelog_path(ddir)}")
    say("  Now: make verify-citations, make check-task, and read the diff before it merges.")
    return 3
