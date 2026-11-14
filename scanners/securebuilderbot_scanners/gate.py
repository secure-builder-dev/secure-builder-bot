"""The Scan gate: the scanners, through their runners (scanners/scripts), judged by the profile's policy.

scanners/scan.sh runs the scanners into this run's directory against the checkout the context names
(PROJECT_ROOT), then three things decide: core's scan verdict says whether every scanner the line
counts ran and left a readable result; this module holds the eighth scanner (pip-audit) and the
checkout's manifests to the same standard; and the profile's policy (policy.py) says which of the
CVEs they found block. The receipt records, per scanner, the pinned version, the vulnerability-
database date where the scanner has one, what its runner said it examined, its exit code and its
findings count, so an assessor can see exactly what "scanned" meant on this run.

Stale data is not a pass (PRD § Staying current): when the profile sets a CVE-data age limit, a
CVE database older than the limit, or one whose date the result file does not carry, fails the gate.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from securebuilderbot_core.config import ConfigError, ScanConfig, blob_at, load_config
from securebuilderbot_core.gate import Finding, GateContext, GateResult
from securebuilderbot_core.receipt import redact, shown
from securebuilderbot_core.verdict import SCANNERS, scan_verdict

from . import policy as policy_mod
from .environment import scanner_env
from .policy import parse_utc
from .scope import unaudited_manifests

PACKAGE_DIR = Path(__file__).resolve().parent
MODULE_DIR = PACKAGE_DIR.parent
SHIM = MODULE_DIR / "scan.sh"
BOT_ROOT = MODULE_DIR.parent
TOOL_VERSIONS = MODULE_DIR / "scripts" / "tool-versions.env"
RULE_BASED = "n/a — rule-based, no vulnerability database"
CVE = re.compile(r"(CVE-\d{4}-\d{4,}|GHSA-[\w-]+|PYSEC-[\w-]+)")
TIMEOUT_SECONDS = 3600
# The scanners whose database is CVE data, and so is held to the profile's age limit. ClamAV's
# signatures are recorded, not judged: the PRD's limit is on CVE data.
CVE_DATABASES = ("grype", "trivy")
# The scanners the receipt lists: core's seven (the verdict line counts those) plus the ecosystem
# audit for Python and the Wolfi package freshness check, which this module accounts for itself
# (missing_extra_scanners).
EXTRA_SCANNERS = (("pip-audit", "pip-audit.json"), ("wolfi-freshness", "wolfi-freshness.json"))
# A Wolfi line not built for this long, while a newer line of the same package is, has been left behind
# upstream: no CVE says so yet, because nobody rebuilds the version a CVE would be filed against.
WOLFI_STALE_DAYS = 45
ALL_SCANNERS = tuple(SCANNERS) + EXTRA_SCANNERS
__all__ = ["ScanGate", "parse_utc", "pinned_images", "database_dates", "stale_databases", "stale_wolfi_packages", "redact_results", "ran_scanners"]


def pinned_images() -> dict[str, str]:
    """{scanner: image ref}, from tool-versions.env, honouring the same environment overrides the runners do."""
    images = {}
    for m in re.finditer(r'SCAN_IMAGE_(\w+)="\$\{SCAN_IMAGE_\w+:-([^}]+)\}"', TOOL_VERSIONS.read_text()):
        key = m.group(1)
        images[key.lower()] = os.environ.get(f"SCAN_IMAGE_{key}", m.group(2))
    return images


def pinned_pip_audit() -> str:
    m = re.search(r'SCAN_PIP_AUDIT_VERSION="\$\{SCAN_PIP_AUDIT_VERSION:-([^}]+)\}"', TOOL_VERSIONS.read_text())
    return os.environ.get("SCAN_PIP_AUDIT_VERSION", m.group(1) if m else "not pinned")


def _receipts(results: Path) -> dict[str, str]:
    out = {}
    f = results / "scanners-ran"
    if f.is_file():
        for line in f.read_text(errors="replace").splitlines():
            name, _, rest = line.partition(" ")
            out.setdefault(name, rest)
    return out


def _exit_codes(results: Path) -> dict[str, int]:
    """{scanner: exit code}, as scan.sh recorded them; a scanner with no line was not run by the shim."""
    out: dict[str, int] = {}
    f = results / "scanners-exit"
    if f.is_file():
        for line in f.read_text(errors="replace").splitlines():
            name, _, code = line.partition(" ")
            if code.strip().isdigit():
                out[name] = int(code)
    return out


def redact_results(results: Path) -> dict[str, int]:
    """Redact every text file the scanners wrote; {file: strings redacted}. Gate finding B-01.

    The run directory is uploaded as a CI artifact, and a scanner's log or report can quote a
    secret-shaped string it read from the repository. A replacement holds no quote or backslash,
    so a JSON report stays valid JSON. A file that is not UTF-8 text is left as it is.
    """
    out: dict[str, int] = {}
    for f in sorted(results.rglob("*")):
        if not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        cleaned, n = redact(text)
        if n:
            f.write_text(cleaned, encoding="utf-8")
            out[f.relative_to(results).as_posix()] = n
    return out


def ran_scanners(results: Path) -> set[str]:
    """The scanners whose runner says it examined something; a CVE database is judged only for these."""
    return {name for name, rest in _receipts(results).items() if rest.startswith("ran")}


def _json(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, (dict, list)) else {}


def _raw_dates(results: Path) -> dict[str, str | None]:
    """The CVE databases' own timestamps, as their result files carry them."""
    grype_db = _json(results / "grype.json").get("descriptor", {}).get("db", {})
    return {
        "grype": grype_db.get("built") or grype_db.get("status", {}).get("built"),
        "trivy": _json(results / "trivy-version.json").get("VulnerabilityDB", {}).get("UpdatedAt"),
    }


def stale_databases(results: Path, ran: set[str], limit_days: int | None, now: datetime) -> dict[str, str]:
    """{scanner: why its CVE data is not acceptable} for each CVE database that ran. Empty when none is stale."""
    if limit_days is None:
        return {}
    raw, out = _raw_dates(results), {}
    for name in CVE_DATABASES:
        if name not in ran:
            continue
        built = parse_utc(raw[name])
        if built is None:
            out[name] = f"{name}'s database date is not in its result file, so its age cannot be shown to be within {limit_days} days"
        elif now - built > timedelta(days=limit_days):
            out[name] = f"{name}'s database is {(now - built).days} days old (built {built.date()}); the profile allows {limit_days}"
    return out


def database_dates(results: Path, log: str) -> dict[str, str]:
    raw = _raw_dates(results)
    clam = re.search(r"\[clamav\] Signature database: (\d+) day\(s\) old", log)
    return {
        "grype": f"built {raw['grype']}" if raw["grype"] else "not reported by the result file",
        "trivy": f"updated {raw['trivy']}" if raw["trivy"] else "not reported by the result file",
        "clamav": f"signatures {clam.group(1)} day(s) old at scan time" if clam else "not reported by the scan log",
        "npm-audit": "live registry advisories at scan time",
        "pip-audit": "live PyPI advisories at scan time",
        "wolfi-freshness": "live Wolfi package index at scan time",
        "hadolint": RULE_BASED, "checkov": RULE_BASED, "eslint": RULE_BASED,
    }


def findings_count(results: Path, name: str) -> int:
    """What each scanner's result file counts as findings: the number the receipt shows beside its exit code."""
    doc = _json(results / dict(ALL_SCANNERS).get(name, "")) if name != "clamav" else {}
    try:
        if name == "hadolint":
            return len(doc) if isinstance(doc, list) else 0
        if name == "checkov":
            return len(doc.get("results", {}).get("failed_checks", []))
        if name == "clamav":
            m = re.search(r"Infected files: (\d+)", (results / "clamav.log").read_text(errors="replace"))
            return int(m.group(1)) if m else 0
        if name == "grype":
            return len(doc.get("matches", []))
        if name == "trivy":
            return sum(len(r.get("Vulnerabilities", []) or []) for r in doc.get("Results", []) or [])
        if name == "npm-audit":
            return sum(len(doc.get(k, []) or []) for k in ("blocking", "allowlisted", "dev_only", "reported"))
        if name == "eslint":
            return len(doc.get("blocking", []))
        if name == "pip-audit":
            return len(doc.get("blocking", [])) + len(doc.get("reported", []))
        if name == "wolfi-freshness":
            return len(doc.get("packages", []))
    except (OSError, AttributeError, TypeError, ValueError):
        return 0
    return 0


def missing_extra_scanners(results: Path, skip: tuple[str, ...]) -> list[str]:
    """The scanners the verdict line does not count that did not run or left no readable result (CM-24)."""
    kinds = _receipts(results)
    out = []
    for name, filename in EXTRA_SCANNERS:
        if name in skip:
            continue
        kind = kinds.get(name, "").split(" ", 1)[0]
        if kind not in ("ran", "none"):
            out.append(name)
        elif not (results / filename).is_file() or not _json(results / filename):
            out.append(f"{name}(no result)")
    return out


def stale_wolfi_packages(results: Path, now: datetime) -> list[Finding]:
    """A Wolfi package a Dockerfile installs whose last build is over WOLFI_STALE_DAYS old while a newer
    line of the same package was built within them blocks: upstream moved on (nodejs-22 to nodejs-24).
    A line with no newer one still built is left alone, and a package missing from the index is said."""
    out = []
    for p in _json(results / "wolfi-freshness.json").get("packages", []) or []:
        name, at = str(p.get("package", "")), dict(path=p.get("dockerfile"), line=p.get("line"))
        built = parse_utc(p.get("last_build"))
        if built is None:
            out.append(Finding("advisory", f"wolfi-missing:{name}", f"{name} is not in Wolfi's package index: retired, or from another repository", **at))
            continue
        live = [n for n in p.get("newer", []) or [] if (b := parse_utc(n.get("last_build"))) and (now - b).days <= WOLFI_STALE_DAYS]
        if (now - built).days > WOLFI_STALE_DAYS and live:
            newest = live[-1]
            out.append(Finding("blocking", f"stale-package:{name}",
                               f"{name} was last built {built.date()} ({(now - built).days} days ago) while {newest['package']} was built "
                               f"{str(newest['last_build'])[:10]}: move the install to {newest['package']}", **at))
    return out


def _headings(path: Path, prefix: str) -> list[str]:
    if not path.is_file():
        return []
    return [line[len(prefix):].strip() for line in path.read_text(errors="replace").splitlines() if line.startswith(prefix)]


def scan_status(blocking: int, applied: int, not_run: bool, skipped: int = 0) -> str:
    """fail on any blocking finding; yellow when an accepted risk was applied or the config switched a
    scanner off; pass only with neither (CM-25)."""
    if not_run:
        return "not_run"
    if blocking:
        return "fail"
    return "yellow" if applied or skipped else "pass"


def model_key_secret(repo: Path) -> str | None:
    """The name `sentinel.key_secret` gives the model key's CI secret in the checkout's config, read
    the way the QA gate reads it; None when there is none or the file cannot be read (the runner
    refused an invalid config before any gate ran)."""
    config = repo / ".securebuilderbot.yml"
    if not config.is_file():
        return None
    try:
        return load_config(config).sentinel.key_secret
    except ConfigError:
        return None


def _risk_entries(text: str | None) -> list:
    """The raw entries of an accepted-risks file, as policy.load_accepted_risks reads them; [] when unreadable."""
    try:
        doc = yaml.safe_load(text) if text else None
    except yaml.YAMLError:
        return []
    entries = doc.get("entries", doc.get("accepted_risks", [])) if isinstance(doc, dict) else doc
    return entries if isinstance(entries, list) else []


# The lists a scanner script reads to excuse a finding, each by the variable that names its file. Like the
# exceptions file, each is read from the base commit: a pull request cannot excuse its own finding.
BASE_LISTS = (("CHECKOV_JUSTIFICATIONS", "docs/security/checkov-justifications.yaml"),
              ("NPM_AUDIT_ALLOWLIST", "docs/security/npm-audit-allowlist.yaml"))


def _base_copy(ctx: GateContext, rel: str, copy: Path) -> bytes | None:
    """Write `rel` as the base commit holds it to `copy` and return its bytes; remove `copy` and return
    None when the base has no such file, holds a link there, or cannot be read: absent grants nothing."""
    copy.unlink(missing_ok=True)
    try:
        _, data = blob_at(ctx.repo, ctx.config_ref or ctx.base, rel)
    except ConfigError:
        data = None
    if data is not None:
        copy.write_bytes(data)
    return data


def scanner_lists_at_base(ctx: GateContext) -> dict[str, str]:
    """{variable: the base commit's copy of the list, in the run directory} for every list in BASE_LISTS.
    The path is set even when the base has no list, so a script's checkout default is never read."""
    out = {}
    for var, rel in BASE_LISTS:
        copy = ctx.run_dir / f"base-{Path(rel).name}"
        _base_copy(ctx, rel, copy)
        out[var] = str(copy)
    return out


def accepted_risks_at_base(ctx: GateContext) -> tuple[Path, str, list[str], bytes | None]:
    """(the exceptions file this run obeys, how the receipt names it, the ids the pull request adds or
    changes, the bytes read from git, which the gate writes back over the copy just before loading it).

    The file the governing config names (always a path inside the repository: load_config refuses any
    other) is read from the target's tip by blob, never from the checkout and never through a link: a
    pull request cannot accept its own risk. What its own copy adds or changes is reported and applies
    once it is merged."""
    rel = (ctx.config.scan if ctx.config is not None else ScanConfig()).accepted_risks
    if ctx.config is None:  # run outside core's runner: the checkout's config names the file, as before
        config = ctx.repo / ".securebuilderbot.yml"
        if config.is_file():
            try:
                rel = load_config(config).scan.accepted_risks
            except ConfigError:
                pass  # the runner already refused an invalid config before any gate ran; the default is the safe side
    copy = ctx.run_dir / "accepted-risks-at-base.yml"
    data = _base_copy(ctx, Path(rel).as_posix(), copy)
    head = ctx.repo / rel
    head_text = head.read_text(errors="replace") if head.is_file() and not head.is_symlink() else None
    base_entries = _risk_entries(data.decode("utf-8", errors="replace") if data is not None else None)
    pending = [_safe_id(e.get("id")) for e in _risk_entries(head_text) if isinstance(e, dict) and e not in base_entries]
    ref = ctx.config_ref or ctx.base
    return copy, (f"{rel} at {ref[:12]}" if ctx.config_ref else f"{rel} at the base commit {ref[:12]}"), pending, data


def _safe_id(value: object) -> str:
    """An id from the pull request's own file, as a finding may repeat it: an advisory id as it is, anything
    else through receipt.shown, so the file cannot put markdown or a line break into a posted comment."""
    text = str(value)
    return text if CVE.fullmatch(text) else shown(text)


class ScanGate:
    name = "scan"

    def __init__(self, now: Callable[[], datetime] | None = None, accepted_risks: Path | None = None) -> None:
        self._now = now or (lambda: datetime.now(UTC))
        self._accepted = accepted_risks
        self._prepared: tuple[GateContext, tuple] | None = None

    def _read_from_git(self, ctx: GateContext) -> tuple[dict[str, str], tuple[Path, str, list[str], bytes | None]]:
        """Every file the gate takes from the base, copied into the run directory: the scanners' lists and
        the exceptions file. Read once, in prepare(), before any gate runs the pull request's code."""
        risks = (self._accepted, str(self._accepted), [], None) if self._accepted is not None else accepted_risks_at_base(ctx)
        return scanner_lists_at_base(ctx), risks

    def prepare(self, ctx: GateContext) -> None:
        """Core calls this before any gate runs: git does not verify a loose object on read, and the scanners
        (and QA before them) run pull request code as the job user, so the base's copies are taken now."""
        self._prepared = (ctx, self._read_from_git(ctx))

    def run(self, ctx: GateContext) -> GateResult:
        results = ctx.run_dir / "results"
        results.mkdir(parents=True, exist_ok=True)
        # The scanners run PR code (a local requirement's setup.py, a JavaScript eslint config), so they
        # never get the bot's secrets or the CI tokens (environment.py, gate run 2, B-8).
        if self._prepared is not None and self._prepared[0] == ctx:
            lists, (risks_file, risks_named, pending, risks_bytes) = self._prepared[1]
        else:  # run on its own, outside core's runner: read now
            lists, (risks_file, risks_named, pending, risks_bytes) = self._read_from_git(ctx)
        keys = {model_key_secret(ctx.repo), ctx.config.sentinel.key_secret if ctx.config is not None else None}
        env = {**scanner_env(withhold=sorted(k for k in keys if k)), "SCAN_RESULTS_DIR": str(results), "SCAN_SKIP": " ".join(ctx.skip), "PROJECT_ROOT": str(ctx.repo),
               **lists}
        try:
            proc = subprocess.run(["bash", str(SHIM)], cwd=ctx.repo, env=env, capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
            log, code = proc.stdout + proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as e:
            log, code = f"{e.stdout or ''}{e.stderr or ''}\n[scan] timed out after {TIMEOUT_SECONDS}s", 2
        (ctx.run_dir / "scan.log").write_text(redact(log)[0])  # uploaded as a CI artifact
        redacted = redact_results(results)  # so is everything the scanners wrote
        if code == 2:
            last = next((line for line in reversed(log.splitlines()) if line.strip()), "no output")
            return GateResult(gate="scan", status="not_run", reason=f"the scan could not start — {last.strip()} (scan/scan.log)")

        v = scan_verdict(results, skip=ctx.skip)
        now = self._now()
        kinds, codes = _receipts(results), _exit_codes(results)
        images, dates = pinned_images(), database_dates(results, log)
        scanners = {}
        for name, _ in ALL_SCANNERS:
            image = images.get(name.replace("-", "_"), "")
            examined = "skipped by config" if name in ctx.skip else (kinds.get(name) or "did not run")
            version = image.rsplit(":", 1)[-1] if image else (pinned_pip_audit() if name == "pip-audit" else "n/a — reads the index" if name == "wolfi-freshness"
                                                               else "the project's own (not pinned by the bot)")
            scanners[name] = {
                "version": version,
                "image": image or None,
                # A database that was not consulted has no date worth recording.
                "database": "n/a — nothing in scope" if examined.startswith("none") else dates[name],
                "examined": examined,
                "exit_code": codes.get(name, "not recorded"),
                "findings": findings_count(results, name),
            }
        ran = {n for n, d in scanners.items() if d["examined"].startswith("ran")}
        findings = [Finding("blocking", f"scanner:{m.split('(')[0]}", f"{m} did not run — a partial scan is not a pass") for m in v.missing]
        findings += [Finding("blocking", f"scanner:{m.split('(')[0]}", f"{m} did not run — a partial scan is not a pass; the verdict line does not count it, this gate does")
                     for m in missing_extra_scanners(results, ctx.skip)]
        # dispatch.md routes fixable work. Its CVE-shaped headings are governed by the profile's policy
        # below; everything else there (a Dockerfile error, an unjustified checkov check, an eslint
        # message, a secret or misconfiguration Trivy found) is the project's own file and blocks as before.
        for h in _headings(results / "dispatch.md", "### "):
            if not CVE.search(h):
                findings.append(Finding("blocking", re.match(r"\S+", h).group(0), h, file="scan/results/dispatch.md"))
        if v.malware:
            findings.append(Finding("blocking", "malware", "ClamAV found an infected file — see dispatch.md", file="scan/results/dispatch.md"))
        # The profile's policy over every CVE the scanners found (SPEC-scanners.md § Policy).
        if self._accepted is None:
            # The scanners ran pull request code, which may have rewritten the copy (or left a process to): the
            # entries load from the bytes held since prepare(), written under a name chosen only now.
            risks_file = ctx.run_dir / f"accepted-risks-{os.urandom(8).hex()}.yml"
            if risks_bytes is not None:
                risks_file.write_bytes(risks_bytes)
        accepted, bad = policy_mod.load_accepted_risks(risks_file, now.date(), ctx.profile.accepted_risk_expiry_days)
        findings += [Finding("advisory", f"accepted-risk-pending:{ident}", f"accepted-risk entry {ident} is added or changed by this "
                             "pull request; exceptions are read from the base branch, so it applies once it is merged and covers nothing until then")
                     for ident in pending]
        pol = policy_mod.apply(policy_mod.cves_from_results(results), ctx.profile.scan, accepted, bad, now)
        findings += [Finding("blocking", f"accepted-risk:{ident}", f"accepted-risk entry {ident} cannot be used: {why} — fix the entry; it covers nothing until then")
                     for ident, why in pol.bad_entries]
        findings += [Finding("blocking", c.id, f"{c.id} ({c.severity}) in {c.package}@{c.version}, fix: {c.fix}, found by {c.scanner} — {why}; "
                             "upgrade, or add an accepted-risk entry with a reason and an expiry", file=c.file) for c, why in pol.blocking]
        findings += [Finding("advisory", c.id, f"{c.id} ({c.severity}) in {c.package}@{c.version}, fix: {c.fix}, found by {c.scanner} — {why}", file=c.file)
                     for c, why in pol.advisory]
        findings += stale_wolfi_packages(results, now)
        for f in unaudited_manifests(ctx.repo, results):
            findings.append(Finding("blocking", f"unaudited:{f}", f"{f} is in the checkout and no runner audited it — a manifest that was not audited is never nothing in scope", path=f))
        # Conservative on purpose (PRD § What a profile does not do): vulnerability scanning that ran is
        # RA-5, malware scanning that ran is SI-3. Nothing else is claimed.
        controls = (["RA-5"] if ran & {"grype", "trivy", "npm-audit", "pip-audit"} else []) + (["SI-3"] if "clamav" in ran else [])
        findings += [Finding("advisory", "redacted-output", f"{n} secret-shaped string(s) in this scanner output were redacted "
                             "before it was kept; the repository may hold a secret — run a secret scan", file=f"scan/results/{name}")
                     for name, n in redacted.items()]
        stale = stale_databases(results, ran, ctx.profile.scan.cve_data_max_age_days, now)
        findings += [Finding("blocking", f"stale-data:{n}", why) for n, why in stale.items()]
        blocking = [f for f in findings if f.severity == "blocking"]
        status = scan_status(len(blocking), len(pol.applied), v.verdict == "NOT RUN", len(ctx.skip))
        reasons = []
        if stale:
            reasons.append("stale CVE data, which is not a pass: " + "; ".join(stale.values()))
        if any(f.rule_id.startswith("scanner:") for f in blocking):
            reasons.append("a scanner the gate counts did not run")
        if pol.blocking:
            reasons.append(f"{len(pol.blocking)} CVE(s) block under profile {ctx.profile.name}: " + ", ".join(c.id for c, _ in pol.blocking[:6]))
        if pol.bad_entries:
            reasons.append(f"{len(pol.bad_entries)} accepted-risk entr{'y' if len(pol.bad_entries) == 1 else 'ies'} cannot be used")
        other = [f for f in blocking if f.file == "scan/results/dispatch.md" or f.rule_id.startswith(("unaudited:", "stale-package:"))]
        if other:
            reasons.append(f"{len(other)} fixable finding(s) that are not CVEs: " + ", ".join(f.rule_id for f in other[:6]))
        if status in ("fail", "not_run"):
            reason = "; ".join([*reasons, v.line.split(" — ", 1)[-1]])  # the verdict block prints "Scan: FAIL —" itself
        else:
            notes = ([f"{len(pol.applied)} accepted risk(s) applied"] if pol.applied else []) \
                + ([f"scan.skip turns off {', '.join(ctx.skip)}"] if ctx.skip else [])
            reason = "; ".join(notes) if status == "yellow" else ""
        return GateResult(gate="scan", status=status, reason=reason, findings=tuple(findings),
                          receipt={"line": v.line, "results": "scan/results", "scanners": scanners, "controls_assessed": controls,
                                   "cve_data_max_age_days": ctx.profile.scan.cve_data_max_age_days, "stale": stale,
                                   "policy": {"profile": ctx.profile.name, "fail_on": list(ctx.profile.scan.fail_on),
                                              "medium_max_age_days": ctx.profile.scan.medium_max_age_days,
                                              "accepted_risk_expiry_days": ctx.profile.accepted_risk_expiry_days,
                                              "cves_blocking": len(pol.blocking), "cves_advisory": len(pol.advisory)},
                                   "accepted_risks_applied": pol.applied, "accepted_risks_file": risks_named,
                                   "accepted_risks_pending": pending, "redacted": redacted})
