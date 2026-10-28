"""The citation verifier: every standard a document cites exists and is still current.

WHY THIS EXISTS
  Sentinel's authority rests on its checks being grounded in real controls. Nothing used to read a
  control id and ask whether it was real, so three wrong citations shipped: SA-12 (withdrawn in
  Rev 5, incorporated into SR) cited as the primary control for the dependency check for four
  months; IR-10 (withdrawn) in the IL4 baseline; AU-9(2) carrying AU-9(4)'s title. A wrong citation
  is worse than an absent one, because it reads as diligence.

WHAT IT CHECKS, per kind of citation
  nist     NIST SP 800-53 Rev 5 control ids (AC-3, SC-7(12)) against the vendored catalog index:
           unknown fails, withdrawn fails and names the replacement, a "(Title)" written next to
           an id that disagrees with the catalog is reported, never failed.
  owasp    OWASP Top 10 / LLM Top 10 ids followed by a title: renumbering between editions is the
           defect — every id still exists, it just means something else now — so the TITLE is
           compared, and a mismatch fails and names the id the title now carries.
  stig     DISA STIG rule ids against the redistributed index plus any human-supplied index. An id
           whose platform prefix the index carries and which is not in it fails; an id on a platform
           the index does not carry is reported as not covered, never judged, because failing what
           cannot be seen would be crying wolf.
  masvs    OWASP MASVS ids: unknown fails; an MSTG-* id is MASVS v1 numbering, renumbered wholesale
           in v2, and fails as superseded.
  nistpub  NIST SP and FIPS citations: a publication or revision that was never published fails; a
           revision NIST has since superseded is reported, never failed — adopting one is a decision.

  A line carrying the allow marker (ALLOW below) is a deliberate mention, a migration note, and yields nothing.
  A "(was X)" pointer is a historical reference to a superseded id, not a live citation.

  THE CM- COLLISION: docs/security/CONTROL-MANIFEST.md numbers its rows CM-01, CM-20 …, which
  collides with the NIST Configuration Management family. Three deterministic tells separate them:
  a manifest row id opens its table row, NIST never zero-pads, and the NIST CM family stops at
  CM-14. All three are skipped.

  It does NOT check that a cited control is the RIGHT one for the check it sits next to. That
  judgment is human, made at the governance review when a checklist item changes.

The six small decisions are the controls (docs/security/CONTROL-MANIFEST.md CM-30, CM-32..CM-36):
each is a function that answers one question, called from verify_citations, and broken on purpose
by make mutate-controls.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from . import data

# The documents the repository holds to its citations. Explicit rather than globbed, so that adding
# a document is a deliberate act and a stray example in a skill file never fails CI. Both spellings
# of the standards tree are listed: git's `**/` needs an intermediate directory, so the second
# alone never matched FRAMEWORKS.md, the provenance record itself.
DOCUMENTS = ("standards/data/*.md", "standards/data/**/*.md", "docs/architecture/*.md", "engine/SENTINEL-CHECKLIST.md",
             ".claude/agents/*.md", "CLAUDE.md", "docs/security/CONTROL-MANIFEST.md")

Kind = Literal["nist", "stig", "owasp", "masvs", "nistpub"]
Status = Literal["ok", "unknown", "withdrawn", "mislabelled", "renumbered", "not-covered", "superseded"]

FAM = "AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR"
# A lookahead, not a trailing \b: with \b, "SC-7(99)" at the end of a line backtracked to "SC-7" and the
# enhancement was never judged (found by the spec's own example when this moved out of the shell script).
# A range "IR-9(1–4)" names four enhancements and each is judged; "(was AC-3)" is a historical pointer.
CITE = re.compile(rf"\b(({FAM})-(\d{{1,2}})((?:\(\d{{1,2}}\))*))(?:\((\d{{1,2}})[–-](\d{{1,2}})\))?(?!\w|\(\d)")
LABEL = re.compile(r"\s*[\(—-]\s*([A-Za-z][A-Za-z0-9 /,'’-]{3,60})")  # "AC-3 (Access Enforcement)" / "AC-3 — Access Enforcement"
# The title must be at least two words: every category title in both OWASP lists is multi-word,
# and requiring it stops prose like "(LLM01 above)" being read as a title claim.
OWASP = re.compile(r"\b(A(?:0[1-9]|10)|LLM(?:0[1-9]|10))\b[ :—-]+([A-Za-z][A-Za-z0-9&/,'’-]*(?:[ ][A-Za-z0-9&/,'’-]+)+)")
# The shapes DISA publishes. Browser ids (DTBF003, DTBC-0001) are excluded on purpose: a pattern
# loose enough for them also matches prose like "RFC5280".
STIG = re.compile(r"""\b(
      [A-Z][A-Z0-9]{3}-\d{2}-\d{6}
    | [A-Z]{2,4}-[A-Z]{2}-\d{6}
    | SRG-[A-Z]{2,3}-\d{6}(?:-[A-Z]{2,4}-\d{5,6})?
  )\b""", re.X)
MASVS = re.compile(r"\b(MASVS-[A-Z]+-\d+)\b")
MSTG = re.compile(r"\b(MSTG-[A-Z]+-\d+)\b")
SP = re.compile(r"\b(?:NIST\s+)?SP\s+(800-\d+[A-Za-z]?)(?:\s*,?\s*(?:Rev(?:ision)?\.?\s*|r)(\d+))?")
FIPS = re.compile(r"\bFIPS\s+(\d{3}(?:-\d+)?)\b")
ALLOW = re.compile(r"citations:\s*allow\b")
CM_FAMILY_LAST = 14


@dataclass(frozen=True)
class Citation:
    id: str
    kind: Kind
    ok: bool
    reason: str = ""
    status: Status = "ok"
    path: str = "<text>"
    line: int = 0
    detail: dict = field(default_factory=dict)  # what a report needs beyond the one line: claimed/real titles


def _norm(s: str) -> str:
    return re.sub(r"[^a-z]", "", s.lower())


# ── The decisions ─────────────────────────────────────────────────────────────────────────────

def line_is_exempt(line: str) -> bool:
    """CM-36: a line carrying the allow marker is a deliberate mention; it exempts that line only."""
    return bool(ALLOW.search(line))


def is_active_control(cid: str, controls: dict) -> bool:
    """CM-30: a control id is acceptable only when the catalog has it and NIST has not withdrawn it."""
    entry = controls.get(cid)
    return entry is not None and entry.get("s", "active") == "active"


def owasp_title_matches(claimed: str, real: str) -> bool:
    """CM-32: the title written beside an OWASP id must be the title that id carries in the pinned edition."""
    c, r = _norm(claimed), _norm(real)
    return bool(c) and (c in r or r in c)


def stig_rule_known(sid: str, rules: dict) -> bool:
    """CM-33: a STIG id on a platform the index carries must be in the index."""
    return sid in rules


def masvs_id_current(mid: str, controls: dict) -> bool:
    """CM-34: a MASVS id must be in the pinned v2 catalog; MSTG-* is v1 numbering and never current."""
    return not mid.startswith("MSTG-") and mid in controls


def pub_revision_published(cited: str, entry: dict) -> bool:
    """CM-35: a cited revision of a NIST publication must be one NIST has published ("" is the original)."""
    return cited in entry.get("revisions", ())


# ── The scan ──────────────────────────────────────────────────────────────────────────────────

def _manifest_row_id(line: str, cid: str, fam: str, num: str, enh: str) -> bool:
    """A CM-nn that is a CONTROL-MANIFEST row id, not a NIST Configuration Management control."""
    if fam != "CM" or enh:
        return False
    if line.lstrip().startswith("| " + cid + " "):
        return True
    if len(num) == 2 and num.startswith("0"):
        return True
    return int(num) > CM_FAMILY_LAST


def _preceded_by_was(line: str, start: int) -> bool:
    return line[max(0, start - 5):start].endswith("was ")


class Verifier:
    """One data directory, loaded once; verify as many texts as needed against it."""

    def __init__(self, data_dir: Path | str | None = None):
        self.catalog = data.raw_catalog(data_dir)
        self.controls: dict = self.catalog["controls"]
        self.catalog_version: str = str(self.catalog.get("_catalog_version", "?"))
        self.owasp = data.owasp(data_dir)
        self.owasp_table: dict[str, str] = {**self.owasp.web, **self.owasp.llm} if self.owasp else {}
        stig = data.raw_index(data.STIG_FILE, data_dir)
        supplied = data.raw_index(data.STIG_SUPPLIED_FILE, data_dir) if stig else None
        self.stig_rules: dict | None = None if stig is None else {**stig.get("rules", {}), **(supplied or {}).get("rules", {})}
        self.supplied_rules = len((supplied or {}).get("rules", {}))
        self.stig_prefixes = {k.split("-")[0] for k in (self.stig_rules or {})}
        self.masvs = data.masvs(data_dir)
        pubs = data.raw_index(data.PUBS_FILE, data_dir)
        self.pubs: dict | None = None if pubs is None else pubs["pubs"]

    def verify(self, text: str, path: str = "<text>") -> list[Citation]:
        out: list[Citation] = []
        for n, line in enumerate(text.splitlines(), 1):
            if line_is_exempt(line):
                continue
            out += self._nist(line, n, path)
            if self.owasp is not None:
                out += self._owasp(line, n, path)
            if self.stig_rules is not None:
                out += self._stig(line, n, path)
            if self.masvs is not None:
                out += self._masvs(line, n, path)
            if self.pubs is not None:
                out += self._pubs(line, n, path)
        return out

    def _nist(self, line: str, n: int, path: str) -> list[Citation]:
        return judge_nist(line, n, path, self.controls)


    def _owasp(self, line: str, n: int, path: str) -> list[Citation]:
        out = []
        for m in OWASP.finditer(line):
            oid = m.group(1)
            if oid not in self.owasp_table:
                continue  # an id outside the pinned edition's range; not this namespace
            claimed = m.group(2).strip().rstrip(".,;)").split("  ")[0]
            real = self.owasp_table[oid]
            if owasp_title_matches(claimed, real):
                out.append(Citation(oid, "owasp", True, "", "ok", path, n))
                continue
            edition = self.owasp.web_edition if oid.startswith("A") else self.owasp.llm_edition
            right = [k for k, v in self.owasp_table.items() if owasp_title_matches(claimed, v)]
            hint = f"; did you mean {right[0]} {self.owasp_table[right[0]]!r}?" if right else ""
            out.append(Citation(oid, "owasp", False, f"renumbered — doc says: {claimed}; OWASP {edition}: {real}{hint}",
                                "renumbered", path, n, {"claimed": claimed, "real": real, "edition": edition,
                                                        "right": right[0] if right else None}))
        return out

    def _stig(self, line: str, n: int, path: str) -> list[Citation]:
        out = []
        for m in STIG.finditer(line):
            sid = m.group(1)
            if _preceded_by_was(line, m.start()):
                continue
            if sid.split("-")[0] not in self.stig_prefixes:
                out.append(Citation(sid, "stig", True, "not covered — its platform is not in the index; reported, not judged",
                                    "not-covered", path, n))
            elif stig_rule_known(sid, self.stig_rules):
                out.append(Citation(sid, "stig", True, "", "ok", path, n))
            else:
                out.append(Citation(sid, "stig", False, "its platform IS indexed and this rule is not in it "
                                    "(a renumbered rule, a typo, or an end-of-life release upstream has dropped)", "unknown", path, n))
        return out

    def _masvs(self, line: str, n: int, path: str) -> list[Citation]:
        out = []
        release = self.masvs.release or "?"
        for rx in (MASVS, MSTG):
            for m in rx.finditer(line):
                mid = m.group(1)
                if _preceded_by_was(line, m.start()):
                    continue
                if masvs_id_current(mid, self.masvs.controls):
                    out.append(Citation(mid, "masvs", True, "", "ok", path, n))
                elif mid.startswith("MSTG-"):
                    out.append(Citation(mid, "masvs", False, f"MSTG-* is MASVS v1 numbering; v2 renumbered the standard "
                                        f"wholesale — re-cite against MASVS {release}", "superseded", path, n, {"release": release}))
                else:
                    out.append(Citation(mid, "masvs", False, "not in the pinned MASVS catalogue", "unknown", path, n))
        return out

    def _pubs(self, line: str, n: int, path: str) -> list[Citation]:
        out = []
        for m in SP.finditer(line):
            key, rev = f"SP {m.group(1)}", m.group(2)
            cited = f"r{rev}" if rev else ""
            label = f"{key} Rev {rev}" if rev else key
            entry = self.pubs.get(key)
            if entry is None:
                out.append(Citation(label, "nistpub", False, "no such publication", "unknown", path, n))
            elif not pub_revision_published(cited, entry):
                have = ", ".join(r or "(original)" for r in entry["revisions"])
                out.append(Citation(label, "nistpub", False, f"published revisions: {have}", "unknown", path, n))
            elif cited and cited != entry["latest"]:
                out.append(Citation(label, "nistpub", True, f"{cited} cited, {entry['latest']} published", "superseded", path, n,
                                    {"key": key, "cited": cited, "latest": entry["latest"]}))
            else:
                out.append(Citation(label, "nistpub", True, "", "ok", path, n))
        for m in FIPS.finditer(line):
            key = f"FIPS {m.group(1)}"
            ok = key in self.pubs
            out.append(Citation(key, "nistpub", ok, "" if ok else "no such publication", "ok" if ok else "unknown", path, n))
        return out


def judge_nist(line: str, n: int, path: str, controls: dict) -> list[Citation]:
    """Every NIST id on one line, judged against a catalog's controls mapping."""
    out = []
    for m in CITE.finditer(line):
        cid, fam, num, enh, lo, hi = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)
        if _manifest_row_id(line, cid, fam, num, enh) or _preceded_by_was(line, m.start()):
            continue
        ids = [f"{cid}({k})" for k in range(int(lo), int(hi) + 1)] if lo and not enh and int(lo) <= int(hi) else [cid]
        for cid in ids:
            out += _judge_nist_one(cid, line, m.end(), n, path, controls)
    return out


def _judge_nist_one(cid: str, line: str, end: int, n: int, path: str, controls: dict) -> list[Citation]:
    out = []
    entry = controls.get(cid)
    if not is_active_control(cid, controls):
        if entry is None:
            out.append(Citation(cid, "nist", False, "not in the 800-53 catalogue", "unknown", path, n))
        else:
            into = ", ".join(entry.get("into", [])) or "no replacement named"
            out.append(Citation(cid, "nist", False, f"{entry['s']}; use: {into}", "withdrawn", path, n,
                                {"status": entry["s"], "into": into}))
        return out
    lm = LABEL.match(line[end:])
    claimed = lm.group(1).strip().rstrip(".,;") if lm else ""
    real = entry["t"]
    if claimed and _norm(claimed) and _norm(claimed) not in _norm(real) and _norm(real) not in _norm(claimed):
        out.append(Citation(cid, "nist", True, f"mislabelled — doc says: {claimed}; catalogue: {real}", "mislabelled",
                            path, n, {"claimed": claimed, "real": real}))
    else:
        out.append(Citation(cid, "nist", True, "", "ok", path, n))
    return out


def tracked_documents(repo: Path | str = ".") -> list[str]:
    """The tracked files DOCUMENTS names, relative to the repository root, as git lists them."""
    import subprocess
    out = subprocess.run(["git", "-C", str(repo), "ls-files", "--", *DOCUMENTS], capture_output=True, text=True)
    return [line for line in out.stdout.splitlines() if line] if out.returncode == 0 else []


def verify_citations(text: str, *, path: str = "<text>", data_dir: Path | str | None = None) -> list[Citation]:
    """Every citation in `text`, judged against the vendored indexes (or those under data_dir)."""
    return Verifier(data_dir).verify(text, path)


def verify_files(paths: Iterable[str], data_dir: Path | str | None = None) -> tuple[Verifier, list[Citation]]:
    """Every citation in every file that exists, with the verifier that judged them."""
    v = Verifier(data_dir)
    out: list[Citation] = []
    for p in paths:
        f = Path(p)
        if f.is_file():
            out += v.verify(f.read_text(encoding="utf-8", errors="replace"), p)
    return v, out


# ── The report, in the shape the self-test has always asserted ──────────────────────────────

def render_report(v: Verifier, cites: list[Citation], advisory: bool = False) -> tuple[str, int]:
    """The verify-citations output and its exit code: 0 every citation resolves, 1 at least one bad."""
    lines: list[str] = []
    w = lines.append

    def by(kind: str, status: str) -> list[Citation]:
        return [c for c in cites if c.kind == kind and c.status == status]

    unknown, withdrawn, mislabelled = by("nist", "unknown"), by("nist", "withdrawn"), by("nist", "mislabelled")
    for c in unknown:
        w(f"  UNKNOWN     {c.id:<12} {c.path}:{c.line}  — not in the 800-53 catalogue")
    for c in withdrawn:
        w(f"  WITHDRAWN   {c.id:<12} {c.path}:{c.line}  — {c.detail['status']}; use: {c.detail['into']}")
    if advisory:
        for c in mislabelled:
            w(f"  MISLABELLED {c.id:<12} {c.path}:{c.line}\n                 doc says : {c.detail['claimed']}\n"
              f"                 catalogue: {c.detail['real']}")
    owasp_bad = by("owasp", "renumbered")
    for c in owasp_bad:
        right = c.detail["right"]
        hint = f"  -> did you mean {right} {v.owasp_table[right]!r}?" if right else ""
        w(f"  RENUMBERED  {c.id:<12} {c.path}:{c.line}\n                 doc says : {c.detail['claimed']}\n"
          f"                 OWASP {c.detail['edition']}: {c.detail['real']}{hint}")
    stig_bad, stig_uncovered = by("stig", "unknown"), by("stig", "not-covered")
    for c in stig_bad:
        w(f"  UNKNOWN STIG {c.id:<14} {c.path}:{c.line}  — its platform IS indexed and this rule is not in it\n"
          f"                 (a renumbered rule, a typo, or an end-of-life release upstream has dropped)")
    masvs_bad, masvs_legacy = by("masvs", "unknown"), by("masvs", "superseded")
    for c in masvs_bad:
        w(f"  UNKNOWN MASVS {c.id:<18} {c.path}:{c.line}  — not in the pinned MASVS catalogue")
    for c in masvs_legacy:
        w(f"  SUPERSEDED   {c.id:<18} {c.path}:{c.line}  — MSTG-* is MASVS v1 numbering; v2 renumbered the\n"
          f"                 standard wholesale. Re-cite against MASVS {c.detail['release']}, or mark the line\n"
          f"                 `citations: allow` if the v1 id is quoted deliberately.")
    pub_bad, pub_old = by("nistpub", "unknown"), by("nistpub", "superseded")
    for c in pub_bad:
        w(f"  UNKNOWN PUB  {c.id:<18} {c.path}:{c.line}  — {c.reason}")
    if pub_old:
        w(f"  SUPERSEDED   {len(pub_old)} NIST publication citation(s) name an older revision"
          f" — reported, not failed; adopting a revision is a decision")
        for c in pub_old:
            w(f"                 {c.detail['key']} {c.detail['cited']} cited, {c.detail['latest']} published   {c.path}:{c.line}")
    if stig_uncovered:
        seen_pfx = sorted({c.id.split("-")[0] for c in stig_uncovered})
        w(f"  NOT COVERED  {len(stig_uncovered)} STIG citation(s) on platforms this index does not carry"
          f" ({', '.join(seen_pfx)}) — reported, not judged. See `_not_covered` in the index.")
        w("                 A STIG nobody redistributes can still be verified:"
          " make ingest-stig FILE=<the .zip you downloaded>")
        if advisory:
            for c in stig_uncovered:
                w(f"                 {c.id:<26} {c.path}:{c.line}")

    seen = {k: sum(1 for c in cites if c.kind == k) for k in ("nist", "owasp", "stig", "masvs", "nistpub")}
    bad = len(unknown) + len(withdrawn) + len(owasp_bad) + len(stig_bad) + len(masvs_bad) + len(masvs_legacy) + len(pub_bad)
    if bad == 0:
        stig_note = (f"{seen['stig'] - len(stig_uncovered)} of {seen['stig']} STIG" if stig_uncovered else f"{seen['stig']} STIG")
        w(f"verify-citations: {seen['nist']} NIST + {seen['owasp']} OWASP + {stig_note} + {seen['masvs']} MASVS"
          f" + {seen['nistpub']} NIST-pub citations resolve (800-53 {v.catalog_version})"
          + (f" [+{v.supplied_rules} human-supplied STIG rules]" if v.supplied_rules else "")
          + (f" ({len(mislabelled)} title mismatches, advisory)" if advisory and mislabelled else ""))
    else:
        w(f"verify-citations: {bad} bad citation(s) of {sum(seen.values())}"
          f" (800-53 {v.catalog_version} + OWASP + STIG + MASVS + NIST pubs)")
        w("  A withdrawn or invented control ID reads as diligence and is worse than no citation.")
        w("  Deliberate mentions of a withdrawn ID carry `citations: allow` on the line.")
    return "\n".join(lines) + "\n", 1 if bad else 0
