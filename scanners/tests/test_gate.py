import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from securebuilderbot_core.gate import GateContext
from securebuilderbot_core.profiles import load_profile
from securebuilderbot_scanners import GATE
from securebuilderbot_scanners import gate as scangate
from securebuilderbot_scanners.gate import (
    BOT_ROOT, MODULE_DIR, TOOL_VERSIONS, ScanGate, database_dates, parse_utc, pinned_images, stale_databases,
)

FIXTURES = MODULE_DIR / "fixtures"
DISPATCH = MODULE_DIR / "scripts" / "generate-dispatch.sh"
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)  # a fixed clock, so a database date never ages out of a test
FRESH = "2026-10-14T01:13:01.189995254Z"  # Trivy's own nanosecond form


def gate(accepted: Path | None = None) -> ScanGate:
    return ScanGate(now=lambda: NOW, accepted_risks=accepted)


# Writes the CVE databases' dates the way Grype and Trivy record them. A standalone script, so the
# fake shim runs it with nothing from this test module on its path.
STAMPER = """
import json, sys
from pathlib import Path
results, grype, trivy = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
g = results / "grype.json"
if g.is_file() and grype:
    doc = json.loads(g.read_text())
    doc.setdefault("descriptor", {})["db"] = {"status": {"built": grype}}
    g.write_text(json.dumps(doc))
if trivy:
    (results / "trivy-version.json").write_text(json.dumps({"VulnerabilityDB": {"UpdatedAt": trivy}}))
"""


def stamp_dates(results: Path, grype: str | None, trivy: str | None) -> None:
    subprocess.run(["python3", "-I", "-c", STAMPER, str(results), grype or "", trivy or ""], check=True)


def fake_shim(tmp_path: Path, fixture: str | None, exit_code: int = 0, extra: str = "",
              grype_db: str | None = FRESH, trivy_db: str | None = FRESH, after: str = "") -> Path:
    """A shim that lays down a fixture's results, dated as the profile requires, and runs the real dispatch over them.

    `extra` runs first (before the fixture), `after` once the fixture is in place and dated.
    """
    body = "#!/usr/bin/env bash\nset -u\n" + extra
    if fixture:
        body += f'cp -r "{FIXTURES / fixture}/." "$SCAN_RESULTS_DIR/"\n'
        stamper = tmp_path / "stamp.py"
        stamper.write_text(STAMPER)
        body += f'python3 -I "{stamper}" "$SCAN_RESULTS_DIR" "{grype_db or ""}" "{trivy_db or ""}"\n'
    body += after
    if fixture:
        body += f'bash "{DISPATCH}" >/dev/null 2>&1 || true\n'
    body += f'echo "SKIP=[$SCAN_SKIP] ROOT=[$PROJECT_ROOT]"\nexit {exit_code}\n'
    shim = tmp_path / "shim.sh"
    shim.write_text(body)
    return shim


def ctx(tmp_path: Path, skip=(), repo: Path | None = None) -> GateContext:
    """A context on an empty scratch checkout: the canned fixtures describe a scan of nothing in particular."""
    run_dir = tmp_path / "run" / "scan"
    run_dir.mkdir(parents=True, exist_ok=True)
    if repo is None:
        repo = tmp_path / "checkout"
        repo.mkdir(exist_ok=True)
    return GateContext(repo=repo, base="a", head="b", profile=load_profile("il6"), depth="light", run_dir=run_dir, skip=skip)


def test_shim_runs_the_same_scanners_in_the_same_order_as_make_gate_scan():
    recipe = re.search(r"(?ms)^gate-scan:.*?\n(?=\S)", (BOT_ROOT / "Makefile").read_text()).group(0)
    make_order = re.findall(r"(pull-images|build-images|run-[a-z-]+|generate-dispatch)\.sh", recipe)
    shim = (MODULE_DIR / "scan.sh").read_text()
    shim_order = re.findall(r"(pull-images|build-images|run-[a-z-]+|generate-dispatch)\.sh", shim.split("set -uo pipefail", 1)[1])
    assert shim_order == make_order


def test_core_finds_this_module_by_name():
    from securebuilderbot_core.runner import default_gates, discover_gate
    assert GATE is ScanGate and discover_gate("scan") is ScanGate
    assert default_gates()["scan"] is ScanGate


def test_a_clean_scan_passes_and_the_receipt_names_every_scanner(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", extra='echo "[clamav] Signature database: 2 day(s) old"\n'))
    r = gate().run(ctx(tmp_path))
    assert r.status == "pass" and r.reason == ""
    s = r.receipt["scanners"]
    assert set(s) == {"hadolint", "checkov", "clamav", "grype", "trivy", "npm-audit", "eslint", "pip-audit", "wolfi-freshness"}
    assert s["grype"]["image"] == pinned_images()["grype"] and s["trivy"]["image"] == pinned_images()["trivy"]
    assert s["grype"]["version"] == pinned_images()["grype"].rsplit(":", 1)[-1]
    assert r.receipt["stale"] == {} and r.receipt["cve_data_max_age_days"] == 30
    assert s["npm-audit"]["version"] == "the project's own (not pinned by the bot)"
    assert s["clamav"]["database"] == "signatures 2 day(s) old at scan time"
    assert s["hadolint"]["database"].startswith("n/a — rule-based")
    assert s["grype"]["examined"] == "ran 2 image(s)"
    assert r.receipt["controls_assessed"] == ["RA-5", "SI-3"]
    assert (r.receipt["line"]).startswith("Scan: PASS — 7/7")
    assert (tmp_path / "run" / "scan" / "scan.log").is_file()


def test_fixable_findings_fail_with_blocking_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "frank-findings"))
    r = gate().run(ctx(tmp_path))
    assert r.status == "fail"
    assert not r.reason.startswith("Scan:")  # the verdict block adds the label once
    assert "scanners ran" in r.reason
    blocking = [f for f in r.findings if f.severity == "blocking"]
    assert blocking and all(f.file == "scan/results/dispatch.md" for f in blocking)


def test_a_critical_with_no_upstream_fix_blocks_under_the_profile_until_it_is_accepted(tmp_path, monkeypatch):
    """PRD: any critical or high CVE without an accepted-risk entry fails the gate, fix available or not."""
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))  # CVE-2022-37434, critical, not fixed
    r = gate().run(ctx(tmp_path))
    assert r.status == "fail"
    f = next(x for x in r.findings if x.rule_id == "CVE-2022-37434")
    assert f.severity == "blocking" and "fix: none" in f.message and f.file == "scan/results/grype.json"
    assert (tmp_path / "run" / "scan" / "results" / "poam-candidates.md").is_file()  # the routing is kept as it is
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))
    risks = tmp_path / "risks.yml"
    risks.write_text("- id: CVE-2022-37434\n  reason: zlib inflate is never given attacker input here; no fixed version published\n  expires: 2026-12-01\n")
    r = gate(risks).run(ctx(tmp_path))
    assert r.status == "yellow" and r.reason == "1 accepted risk(s) applied"
    assert [x["id"] for x in r.receipt["accepted_risks_applied"]] == ["CVE-2022-37434"]


def test_a_scanner_that_did_not_run_is_a_blocking_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", extra="", grype_db=None))
    original = scangate.scan_verdict

    def drop_grype(results, skip=()):
        (results / "grype.json").unlink()
        return original(results, skip)

    monkeypatch.setattr(scangate, "scan_verdict", drop_grype)
    r = gate().run(ctx(tmp_path))
    assert r.status == "fail"
    assert any(f.rule_id == "scanner:grype" for f in r.findings)


def test_a_scan_that_could_not_start_is_not_run(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, None, exit_code=2, extra='echo "[pull] could not pull hadolint"\n'))
    r = gate().run(ctx(tmp_path))
    assert r.status == "not_run"
    assert "the scan could not start" in r.reason and "scan/scan.log" in r.reason


def test_no_results_at_all_is_not_run(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, None))
    assert gate().run(ctx(tmp_path)).status == "not_run"


def test_skipped_scanners_reach_the_shim_and_are_named(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean"))
    r = gate().run(ctx(tmp_path, skip=("clamav",)))
    assert "SKIP=[clamav]" in (tmp_path / "run" / "scan" / "scan.log").read_text()
    assert r.receipt["scanners"]["clamav"]["examined"] == "skipped by config"
    assert "(skipped by config: clamav)" in r.receipt["line"]


def test_a_scanner_switched_off_in_the_config_is_yellow_never_a_pass(tmp_path, monkeypatch):
    # PRD § Configuration: disabling a scanner is allowed and shows as yellow on every PR check, so a
    # clean scan with one scanner off can never read green (GitHub's neutral, GitLab's yellow).
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean"))
    r = gate().run(ctx(tmp_path, skip=("clamav",)))
    assert r.status == "yellow" and r.reason == "scan.skip turns off clamav"
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))
    risks = tmp_path / "risks.yml"
    risks.write_text("- id: CVE-2022-37434\n  reason: zlib inflate is never given attacker input here; no fixed version published\n  expires: 2026-12-01\n")
    r = gate(risks).run(ctx(tmp_path, skip=("clamav", "hadolint")))
    assert r.status == "yellow" and r.reason == "1 accepted risk(s) applied; scan.skip turns off clamav, hadolint"


def test_another_checkout_is_scanned_as_the_project_root(tmp_path, monkeypatch):
    """The scanners image runs the bot from /bot against a checkout at /src: the runners get PROJECT_ROOT."""
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean"))
    r = gate().run(ctx(tmp_path, repo=other))
    assert r.status == "pass"
    assert f"ROOT=[{other}]" in (tmp_path / "run" / "scan" / "scan.log").read_text()


def test_database_dates_read_each_scanners_own_record(tmp_path):
    (tmp_path / "grype.json").write_text('{"descriptor": {"db": {"built": "2026-10-14T01:02:03Z"}}}')
    (tmp_path / "trivy-version.json").write_text('{"VulnerabilityDB": {"UpdatedAt": "2026-10-14T06:00:00Z"}}')
    d = database_dates(tmp_path, "")
    assert d["grype"] == "built 2026-10-14T01:02:03Z"
    assert d["trivy"] == "updated 2026-10-14T06:00:00Z"
    assert d["clamav"] == "not reported by the scan log"
    (tmp_path / "grype.json").write_text('{"descriptor": {"db": {"status": {"built": "2026-10-13"}}}}')
    assert database_dates(tmp_path, "")["grype"] == "built 2026-10-13"


def test_pins_honour_the_same_overrides_as_the_runners(monkeypatch):
    pin = re.search(r'SCAN_IMAGE_GRYPE:-([^}]+)\}', TOOL_VERSIONS.read_text()).group(1)
    assert pinned_images()["grype"] == pin
    monkeypatch.setenv("SCAN_IMAGE_GRYPE", "anchore/grype:v9.9.9")
    assert pinned_images()["grype"] == "anchore/grype:v9.9.9"


@pytest.mark.parametrize("name", ["hadolint", "checkov", "clamav", "grype", "trivy"])
def test_every_containerised_scanner_is_pinned(name):
    assert ":" in pinned_images()[name]


def test_an_empty_scope_records_no_database_date(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", extra="", grype_db=None))
    original = scangate.scan_verdict

    def npm_nothing_in_scope(results, skip=()):
        text = (results / "scanners-ran").read_text().replace("npm-audit ran 2 app(s)", "npm-audit none no npm app")
        (results / "scanners-ran").write_text(text)
        return original(results, skip)

    monkeypatch.setattr(scangate, "scan_verdict", npm_nothing_in_scope)
    r = gate().run(ctx(tmp_path))
    assert r.receipt["scanners"]["npm-audit"]["database"] == "n/a — nothing in scope"
    assert r.receipt["scanners"]["grype"]["database"] == "not reported by the result file"


def test_a_cve_database_older_than_the_profile_allows_fails_the_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", grype_db="2026-03-09T00:31:20Z"))
    r = gate().run(ctx(tmp_path))
    assert r.status == "fail"
    assert r.reason.startswith("stale CVE data, which is not a pass: grype's database is 220 days old (built 2026-03-09)")
    assert [f.rule_id for f in r.findings if f.severity == "blocking"] == ["stale-data:grype"]
    assert set(r.receipt["stale"]) == {"grype"}


def test_a_cve_database_with_no_date_cannot_pass_a_profile_with_a_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", trivy_db=None))
    r = gate().run(ctx(tmp_path))
    assert r.status == "fail"
    assert "trivy's database date is not in its result file" in r.reason


def test_the_limit_is_inclusive_and_only_ran_databases_are_judged(tmp_path):
    stamp_dates(tmp_path, None, "2026-09-15T12:00:00Z")
    assert stale_databases(tmp_path, {"trivy"}, 30, NOW) == {}
    stamp_dates(tmp_path, None, "2026-09-15T11:59:59Z")
    assert set(stale_databases(tmp_path, {"trivy"}, 30, NOW)) == {"trivy"}
    assert stale_databases(tmp_path, {"clamav"}, 30, NOW) == {}  # signatures are recorded, not judged


def test_a_profile_without_a_limit_never_judges_age(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", grype_db=None, trivy_db=None))
    c = ctx(tmp_path)
    r = gate().run(GateContext(repo=c.repo, base=c.base, head=c.head, profile=load_profile("none"), depth=c.depth, run_dir=c.run_dir))
    assert r.receipt["stale"] == {} and r.receipt["cve_data_max_age_days"] is None


def test_stale_data_is_added_to_a_scan_that_already_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "frank-findings", grype_db="2026-01-01"))
    r = gate().run(ctx(tmp_path))
    assert r.status == "fail"
    assert r.reason.startswith("stale CVE data") and "scanners ran" in r.reason


@pytest.mark.parametrize(("stamp", "expected"), [
    ("2026-10-14T01:13:01.189995254Z", datetime(2026, 10, 14, 1, 13, 1, tzinfo=UTC)),
    ("2026-10-13", datetime(2026, 10, 13, tzinfo=UTC)),
    ("not a date", None),
    (None, None),
])
def test_scanner_timestamps_parse_to_utc(stamp, expected):
    assert parse_utc(stamp) == expected


def test_a_secret_in_scanner_output_never_reaches_the_scan_log(tmp_path, monkeypatch):
    secret = "sk-ant-" + "c" * 24  # secret-shaped, not a secret
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", extra=f'echo "[trivy] env leaked {secret}"\n'))
    c = ctx(tmp_path)
    gate().run(c)
    log = (c.run_dir / "scan.log").read_text()
    assert secret not in log and "env leaked [redacted: secret-shaped string]" in log


def test_secret_shaped_text_in_any_scanner_file_is_redacted_before_it_is_kept(tmp_path, monkeypatch):
    secret = "sk-ant-" + "d" * 24  # secret-shaped, not a secret
    extra = (f'printf "[trivy] read {secret}\\n" > "$SCAN_RESULTS_DIR/trivy.log"\n'
             f'mkdir -p "$SCAN_RESULTS_DIR/sub" && printf \'{{"note": "{secret}"}}\' > "$SCAN_RESULTS_DIR/sub/x.json"\n'
             'printf "\\377\\376binary" > "$SCAN_RESULTS_DIR/blob.bin"\n')
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", extra=extra))
    c = ctx(tmp_path)
    r = gate().run(c)
    results = c.run_dir / "results"
    assert r.status == "pass"  # redaction is recorded, it does not change the scan's verdict
    for f in results.rglob("*"):
        if f.is_file():
            assert secret.encode() not in f.read_bytes(), f
    assert json.loads((results / "sub" / "x.json").read_text())["note"] == "[redacted: secret-shaped string]"
    assert r.receipt["redacted"] == {"sub/x.json": 1, "trivy.log": 1}
    advisories = [f for f in r.findings if f.rule_id == "redacted-output"]
    assert {f.file for f in advisories} == {"scan/results/sub/x.json", "scan/results/trivy.log"}
    assert all(f.severity == "advisory" for f in advisories)


# ── The profile's policy (SPEC-scanners.md § Policy) ──────────────────────────────────────────

def trivy_cve(cve: str, severity: str, published: str | None, pkg: str = "libx", installed: str = "1.0", fixed: str = "1.1") -> dict:
    v = {"VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": installed, "FixedVersion": fixed, "Severity": severity}
    if published:
        v["PublishedDate"] = published
    return v


def cve_results(tmp_path: Path, *vulns: dict) -> str:
    """An `after` hook that replaces the fixture's trivy.json with these vulnerabilities (filesystem scan shape)."""
    doc = {"SchemaVersion": 2, "ArtifactName": ".", "ArtifactType": "filesystem",
           "Results": [{"Target": "core/requirements.txt", "Type": "pip", "Vulnerabilities": list(vulns)}]}
    f = tmp_path / "trivy-with-cves.json"
    f.write_text(json.dumps(doc))
    return f'cp "{f}" "$SCAN_RESULTS_DIR/trivy.json"\n'


def profile_ctx(tmp_path: Path, name: str, repo: Path | None = None) -> GateContext:
    c = ctx(tmp_path, repo=repo)
    return GateContext(repo=c.repo, base=c.base, head=c.head, profile=load_profile(name), depth=c.depth, run_dir=c.run_dir)


def accepted(tmp_path: Path, *entries: dict) -> Path:
    import yaml
    p = tmp_path / "accepted-risks.yml"
    p.write_text(yaml.safe_dump(list(entries)))
    return p


def blocking_ids(r) -> list[str]:
    return [f.rule_id for f in r.findings if f.severity == "blocking"]


def test_at_il4_a_high_cve_with_no_accepted_risk_fails_fix_or_no_fix(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-1111", "HIGH", "2026-10-01T00:00:00Z", fixed=""))))
    r = gate().run(profile_ctx(tmp_path, "il4"))
    assert r.status == "fail"
    assert blocking_ids(r) == ["CVE-2026-1111"]
    f = next(x for x in r.findings if x.rule_id == "CVE-2026-1111")
    assert "libx" in f.message and "1.0" in f.message and f.file == "scan/results/trivy.json"
    assert "CVE-2026-1111" in r.reason


def test_the_same_cve_accepted_with_a_valid_expiry_is_yellow_and_listed(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-1111", "HIGH", "2026-10-01T00:00:00Z"))))
    risks = accepted(tmp_path, {"id": "CVE-2026-1111", "reason": "not reachable: the parser is never given untrusted input", "expires": "2026-12-01"})
    r = gate(risks).run(profile_ctx(tmp_path, "il4"))
    assert r.status == "yellow" and blocking_ids(r) == []
    assert r.receipt["accepted_risks_applied"] == [{"id": "CVE-2026-1111", "package": "libx", "expires": "2026-12-01",
                                                    "reason": "not reachable: the parser is never given untrusted input"}]
    assert any(f.severity == "advisory" and f.rule_id == "CVE-2026-1111" and "accepted" in f.message for f in r.findings)


def test_an_expired_entry_is_itself_a_blocking_finding_and_covers_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-1111", "HIGH", "2026-10-01T00:00:00Z"))))
    risks = accepted(tmp_path, {"id": "CVE-2026-1111", "reason": "x", "expires": "2026-10-01"})
    r = gate(risks).run(profile_ctx(tmp_path, "il4"))
    assert r.status == "fail"
    assert sorted(blocking_ids(r)) == ["CVE-2026-1111", "accepted-risk:CVE-2026-1111"]
    assert r.receipt["accepted_risks_applied"] == []


def test_an_expiry_further_out_than_the_profile_allows_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-1111", "HIGH", "2026-10-01T00:00:00Z"))))
    risks = accepted(tmp_path, {"id": "CVE-2026-1111", "reason": "x", "expires": "2027-06-01"})  # il4 allows 180 days
    r = gate(risks).run(profile_ctx(tmp_path, "il4"))
    assert r.status == "fail" and "accepted-risk:CVE-2026-1111" in blocking_ids(r)
    why = next(f.message for f in r.findings if f.rule_id == "accepted-risk:CVE-2026-1111")
    assert "180" in why


def test_an_entry_missing_its_reason_or_date_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean"))
    risks = accepted(tmp_path, {"id": "CVE-2026-2222", "expires": "2026-11-01"}, {"id": "CVE-2026-3333", "reason": "x", "expires": "soon"})
    r = gate(risks).run(profile_ctx(tmp_path, "il4"))
    assert r.status == "fail"
    assert sorted(blocking_ids(r)) == ["accepted-risk:CVE-2026-2222", "accepted-risk:CVE-2026-3333"]


def test_a_scope_limits_an_entry_to_one_package(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(
        tmp_path, trivy_cve("CVE-2026-1111", "HIGH", "2026-10-01T00:00:00Z", pkg="libx"), trivy_cve("CVE-2026-1111", "HIGH", "2026-10-01T00:00:00Z", pkg="liby"))))
    risks = accepted(tmp_path, {"id": "CVE-2026-1111", "reason": "x", "expires": "2026-12-01", "scope": "libx"})
    r = gate(risks).run(profile_ctx(tmp_path, "il4"))
    assert r.status == "fail"
    assert [f.message for f in r.findings if f.severity == "blocking"] and all("liby" in f.message for f in r.findings if f.severity == "blocking")


def test_at_il6_a_medium_cve_older_than_30_days_blocks_and_a_young_one_does_not(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-4040", "MEDIUM", "2026-09-05T00:00:00Z"))))
    r = gate().run(profile_ctx(tmp_path, "il6"))
    assert r.status == "fail" and blocking_ids(r) == ["CVE-2026-4040"]
    assert "40 days" in next(f.message for f in r.findings if f.rule_id == "CVE-2026-4040")
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-4010", "MEDIUM", "2026-10-05T00:00:00Z"))))
    r = gate().run(profile_ctx(tmp_path, "il6"))
    assert r.status == "pass" and blocking_ids(r) == []
    assert any(f.severity == "advisory" and f.rule_id == "CVE-2026-4010" for f in r.findings)


def test_at_il6_a_medium_cve_with_no_published_date_cannot_be_shown_young(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-4099", "MEDIUM", None))))
    r = gate().run(profile_ctx(tmp_path, "il6"))
    assert r.status == "fail" and blocking_ids(r) == ["CVE-2026-4099"]


def test_at_il4_a_medium_cve_is_advisory_whatever_its_age(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-4040", "MEDIUM", "2026-01-05T00:00:00Z"))))
    r = gate().run(profile_ctx(tmp_path, "il4"))
    assert r.status == "pass" and blocking_ids(r) == []


def test_at_none_a_high_is_advisory_and_a_critical_blocks(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-5555", "HIGH", "2026-10-01T00:00:00Z"))))
    r = gate().run(profile_ctx(tmp_path, "none"))
    assert r.status == "pass" and blocking_ids(r) == []
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-5556", "CRITICAL", "2026-10-01T00:00:00Z"))))
    r = gate().run(profile_ctx(tmp_path, "none"))
    assert r.status == "fail" and blocking_ids(r) == ["CVE-2026-5556"]


def test_an_unrated_cve_blocks_at_every_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-6666", "UNKNOWN", "2026-10-01T00:00:00Z"))))
    r = gate().run(profile_ctx(tmp_path, "none"))
    assert r.status == "fail" and blocking_ids(r) == ["CVE-2026-6666"]
    assert "unrated" in next(f.message for f in r.findings if f.rule_id == "CVE-2026-6666")


def test_a_pip_audit_finding_takes_its_rating_from_the_scanner_that_has_one(tmp_path, monkeypatch):
    pip = {"scanner": "pip-audit", "apps": [{"app": "svc", "file": "svc/requirements.txt", "dependencies": 1, "vulns": 1}],
           "blocking": [{"app": "svc", "file": "svc/requirements.txt", "id": "PYSEC-2026-1", "aliases": ["CVE-2026-7777"], "package": "libx", "version": "1.0", "fix": "1.1"}],
           "reported": []}
    f = tmp_path / "pa.json"
    f.write_text(json.dumps(pip))
    after = cve_results(tmp_path, trivy_cve("CVE-2026-7777", "LOW", "2026-10-01T00:00:00Z")) + f'cp "{f}" "$SCAN_RESULTS_DIR/pip-audit.json"\n'
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=after))
    r = gate().run(profile_ctx(tmp_path, "il4"))
    assert r.status == "pass" and blocking_ids(r) == []  # trivy rates it low; pip-audit alone would be unrated
    ids = [x.rule_id for x in r.findings if x.severity == "advisory"]
    assert "CVE-2026-7777" in ids and "PYSEC-2026-1" not in ids


def test_npm_advisories_are_judged_by_the_profile_too(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "npm-audit-blocking"))
    r = gate().run(profile_ctx(tmp_path, "il4"))
    assert r.status == "fail" and "GHSA-fixt-high-0001" in blocking_ids(r)
    r = gate().run(profile_ctx(tmp_path, "none"))
    assert "GHSA-fixt-high-0001" not in blocking_ids(r)  # high is not critical


def test_non_cve_fixable_work_still_blocks_whatever_the_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "frank-findings"))  # hadolint and checkov findings
    r = gate().run(profile_ctx(tmp_path, "none"))
    assert r.status == "fail" and blocking_ids(r)


# ── Every scanner accounted for, every manifest audited ───────────────────────────────────────

def test_the_receipt_lists_nine_scanners_with_exit_codes_and_counts(tmp_path, monkeypatch):
    after = 'printf "hadolint 0\ntrivy 1\npip-audit 0\n" > "$SCAN_RESULTS_DIR/scanners-exit"\n'
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=after))
    r = gate().run(ctx(tmp_path))
    s = r.receipt["scanners"]
    assert list(s) == ["hadolint", "checkov", "clamav", "grype", "trivy", "npm-audit", "eslint", "pip-audit", "wolfi-freshness"]
    assert s["wolfi-freshness"]["version"] == "n/a — reads the index" and s["wolfi-freshness"]["database"] == "n/a — nothing in scope"
    assert database_dates(tmp_path, "")["wolfi-freshness"].startswith("live Wolfi package index")
    assert s["hadolint"]["exit_code"] == 0 and s["trivy"]["exit_code"] == 1 and s["checkov"]["exit_code"] == "not recorded"
    assert s["pip-audit"]["version"] == "2.10.1" and s["pip-audit"]["examined"] == "ran 1 manifest(s)"
    assert s["pip-audit"]["database"].startswith("live PyPI advisories")
    assert all(isinstance(x["findings"], int) for x in s.values())
    assert s["hadolint"]["findings"] == 0 and s["pip-audit"]["findings"] == 0


def test_pip_audit_not_running_fails_the_gate_even_though_the_line_counts_seven(tmp_path, monkeypatch):
    after = 'rm -f "$SCAN_RESULTS_DIR/pip-audit.json"\n'
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=after))
    r = gate().run(ctx(tmp_path))
    assert r.status == "fail" and "scanner:pip-audit" in blocking_ids(r)
    assert r.receipt["line"].startswith("Scan: PASS — 7/7")  # the core line gains nothing new


def test_a_manifest_the_runners_did_not_audit_is_a_blocking_finding(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "tools" / "x").mkdir(parents=True)
    (repo / "tools" / "x" / "package.json").write_text("{}")
    (repo / "svc").mkdir()
    (repo / "svc" / "requirements.txt").write_text("pyyaml==6.0.2\n")
    (repo / "node_modules" / "dep").mkdir(parents=True)
    (repo / "node_modules" / "dep" / "package.json").write_text("{}")  # pruned, never expected
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean"))  # the fixture audited backend/ only
    r = gate().run(ctx(tmp_path, repo=repo))
    assert r.status == "fail"
    assert sorted(blocking_ids(r)) == ["unaudited:svc/requirements.txt", "unaudited:tools/x/package.json"]


def test_unaudited_manifests_are_computed_against_what_the_runners_said_they_examined(tmp_path):
    from securebuilderbot_scanners.scope import unaudited_manifests
    repo = tmp_path / "repo"
    (repo / "a").mkdir(parents=True)
    (repo / "a" / "package.json").write_text("{}")
    (repo / "a" / "requirements-dev.txt").write_text("")
    (repo / "b").mkdir()
    (repo / "b" / "pyproject.toml").write_text("")
    results = tmp_path / "results"
    results.mkdir()
    (results / "audit.json").write_text(json.dumps({"apps": [{"app": "a"}]}))
    (results / "pip-audit.json").write_text(json.dumps({"apps": [{"app": "a", "file": "a/requirements-dev.txt"}]}))
    assert unaudited_manifests(repo, results) == ["b/pyproject.toml"]


# ── The real runners, end to end into the gate (gate run 1, B-1) ──────────────────────────────

RUNNERS = MODULE_DIR / "scripts"


def fake_bin(tmp_path: Path, name: str, body: str) -> Path:
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    f = b / name
    f.write_text("#!/usr/bin/env bash\n" + body)
    f.chmod(0o755)
    return f


def runner_checkout(tmp_path: Path) -> Path:
    """A checkout with one Python app and one npm app, so pip-audit and npm audit both have work."""
    repo = tmp_path / "checkout"
    (repo / "web").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "requirements.txt").write_text("libx==1.0\n")
    (repo / "web" / "package.json").write_text("{}")
    (repo / "web" / "package-lock.json").write_text("{}")
    return repo


def real_runners(tmp_path: Path) -> str:
    """An `after` hook that runs the real pip-audit and npm-audit runners over the checkout, each
    given a fake tool that reports one vulnerability and exits 1, the way both tools do."""
    pa = fake_bin(tmp_path, "fake-pip-audit", f'[ "$1" = --version ] && {{ echo "pip-audit {scangate.pinned_pip_audit()}"; exit 0; }}\n'
                  """echo '{"dependencies":[{"name":"libx","version":"1.0","vulns":[{"id":"PYSEC-2026-1","aliases":["CVE-2026-7777"],"fix_versions":["1.1"]}]}]}'\nexit 1\n""")
    npm = fake_bin(tmp_path, "fake-npm", """echo '{"metadata":{"vulnerabilities":{"high":1}},"vulnerabilities":{"libq":{"isDirect":true,"fixAvailable":true,"via":[{"url":"https://github.com/advisories/GHSA-prob-e000-0001","severity":"high","range":"<2","title":"t"}]}}}'\nexit 1\n""")
    return (f'PIP_AUDIT_CMD="{pa}" bash "{RUNNERS}/run-pip-audit.sh" >/dev/null 2>&1\n'
            f'NPM_AUDIT_NPM="{npm}" bash "{RUNNERS}/run-npm-audit.sh" >/dev/null 2>&1\n')


def test_a_runner_that_found_something_still_says_it_ran(tmp_path, monkeypatch):
    """B-1: the real runners exit 1 on a finding; their receipt must still say they ran."""
    repo = runner_checkout(tmp_path)
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=real_runners(tmp_path)))
    r = gate().run(profile_ctx(tmp_path / "none", "none", repo=repo))
    s = r.receipt["scanners"]
    assert s["pip-audit"]["examined"] == "ran 1 manifest(s)"
    assert s["npm-audit"]["examined"].startswith("ran 1 app")
    assert not [i for i in blocking_ids(r) if i.startswith("scanner:")]
    assert "did not run" not in r.receipt["line"]


def test_the_profile_and_an_accepted_risk_decide_what_a_real_runner_found(tmp_path, monkeypatch):
    """B-1, the reviewer's probe: pip-audit's finding is accepted, npm's high is below `none`'s fail-on."""
    repo = runner_checkout(tmp_path)
    risks = accepted(tmp_path, {"id": "CVE-2026-7777", "reason": "probe: never reached", "expires": "2026-12-01"})
    for prof in ("none", "il4"):
        monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=real_runners(tmp_path)))
        r = gate(risks).run(profile_ctx(tmp_path / prof, prof, repo=repo))
        if prof == "none":
            assert r.status == "yellow" and blocking_ids(r) == [], (r.reason, blocking_ids(r))
        else:  # il4 fails on high: npm's production-reachable high blocks, and nothing else does
            assert r.status == "fail" and blocking_ids(r) == ["GHSA-prob-e000-0001"], (r.reason, blocking_ids(r))
        assert [x["id"] for x in r.receipt["accepted_risks_applied"]] == ["PYSEC-2026-1"]  # covered by its CVE alias


# ── Image scans carry their database dates (gate run 1, B-2) ──────────────────────────────────

def grype_image_doc(built: str | None, cve: str = "CVE-2026-0001") -> str:
    """Grype's own JSON for one image: the database date sits under descriptor.db.status."""
    db = {"status": {"schemaVersion": "v6.0.2", "from": "https://grype.anchore.io/databases", "built": built, "valid": True}} if built else {}
    return json.dumps({"matches": [{"vulnerability": {"id": cve, "severity": "Low", "fix": {"versions": []}}, "artifact": {"name": "libz", "version": "1"}}],
                       "source": {"type": "image", "target": {"userInput": "x"}},
                       "descriptor": {"name": "grype", "version": "0.104.0", "db": db}})


TRIVY_IMAGE_DOC = json.dumps({"SchemaVersion": 2, "ArtifactName": "x", "ArtifactType": "container_image", "Results": []})
TRIVY_VERSION_DOC = json.dumps({"Version": "0.67.2", "VulnerabilityDB": {"Version": 2, "UpdatedAt": FRESH, "NextUpdate": FRESH}})


def image_runners(tmp_path: Path, grype_docs: dict[str, str]) -> str:
    """An `after` hook that runs the real grype and trivy runners on the image path, with fakes for docker, grype and trivy."""
    canned = tmp_path / "canned"
    canned.mkdir(exist_ok=True)
    for img, doc in grype_docs.items():
        (canned / f"grype-{img.split(':')[0]}.json").write_text(doc)
    (canned / "trivy-image.json").write_text(TRIVY_IMAGE_DOC)
    (canned / "trivy-version.json").write_text(TRIVY_VERSION_DOC)
    fake_bin(tmp_path, "docker", 'case "$*" in *Created*) date -u +%Y-%m-%dT%H:%M:%SZ ;; esac\nexit 0\n')
    fake_bin(tmp_path, "grype", f'for a in "$@"; do case "$a" in *:scan) img="${{a%%:*}}" ;; esac; done\n'
             f'case "$*" in *json*) cat "{canned}/grype-$img.json" ;; *) echo table ;; esac\n')
    fake_bin(tmp_path, "trivy", f'case "$1" in version) cat "{canned}/trivy-version.json" ;; image) case "$*" in *json*) cat "{canned}/trivy-image.json" ;; *) echo table ;; esac ;; esac\n')
    images = " ".join(grype_docs)
    env = f'PATH="{tmp_path / "bin"}:$PATH" SCAN_ENGINE=native SCAN_IMAGES="{images}" SCAN_TRACK=web'
    return (f'rm -f "$SCAN_RESULTS_DIR/trivy-version.json"\n'
            f'{env} bash "{RUNNERS}/run-grype.sh" >/dev/null 2>&1\n{env} bash "{RUNNERS}/run-trivy.sh" >/dev/null 2>&1\n')


def test_an_image_scan_is_not_stale_data_when_its_databases_are_fresh(tmp_path, monkeypatch):
    """B-2: the image path's merged grype.json kept a descriptor with no date, and trivy wrote no version file."""
    after = image_runners(tmp_path, {"api:scan": grype_image_doc(FRESH), "web:scan": grype_image_doc(FRESH, "CVE-2026-0002")})
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", grype_db=None, trivy_db=None, after=after))
    r = gate().run(profile_ctx(tmp_path, "il4"))
    assert r.receipt["scanners"]["grype"]["examined"] == "ran 2 image(s)"
    assert r.receipt["scanners"]["trivy"]["examined"] == "ran 2 image(s)"
    assert r.receipt["stale"] == {}, r.receipt["stale"]
    assert r.status == "pass", (r.reason, blocking_ids(r))
    results = tmp_path / "run" / "scan" / "results"
    assert len(json.loads((results / "grype.json").read_text())["matches"]) == 2  # both images' matches are kept
    assert r.receipt["scanners"]["grype"]["database"] == f"built {FRESH}"


def test_merged_images_keep_the_oldest_database_date_and_an_undated_one_dates_nothing(tmp_path, monkeypatch):
    after = image_runners(tmp_path, {"api:scan": grype_image_doc(FRESH), "web:scan": grype_image_doc("2026-01-02T00:00:00Z")})
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", grype_db=None, trivy_db=None, after=after))
    r = gate().run(profile_ctx(tmp_path, "il4"))
    assert set(r.receipt["stale"]) == {"grype"} and "built 2026-01-02" in r.receipt["stale"]["grype"]
    after = image_runners(tmp_path, {"api:scan": grype_image_doc(FRESH), "web:scan": grype_image_doc(None)})
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", grype_db=None, trivy_db=None, after=after))
    r = gate().run(profile_ctx(tmp_path, "il4"))
    assert set(r.receipt["stale"]) == {"grype"} and "not in its result file" in r.receipt["stale"]["grype"]


# ── A dev-only grade covers its own record only (gate run 1, B-3) ─────────────────────────────

def npm_adv(app: str, severity: str = "critical") -> dict:
    return {"app": app, "id": "GHSA-prob-e000-0001", "severity": severity, "package": "libq", "range": "<2", "fix": "available"}


def grype_match(severity: str) -> dict:
    return {"vulnerability": {"id": "GHSA-prob-e000-0001", "severity": severity, "fix": {"versions": ["2.0"]}}, "artifact": {"name": "libq", "version": "1.0"}}


def policy_over(tmp_path: Path, profile: str, grype: list | None = None, **audit: list):
    from securebuilderbot_scanners import policy
    results = tmp_path / profile
    results.mkdir(parents=True, exist_ok=True)
    if grype is not None:
        (results / "grype.json").write_text(json.dumps({"matches": grype}))
    doc = {"blocking": [], "allowlisted": [], "dev_only": [], "reported": [], **audit}
    (results / "audit.json").write_text(json.dumps(doc))
    return policy.apply(policy.cves_from_results(results), load_profile(profile).scan, [], [], NOW)


@pytest.mark.parametrize("profile", ["none", "il4", "il6"])
def test_a_dev_only_grade_in_one_app_never_hides_the_same_advisory_in_a_shipped_image(tmp_path, profile):
    r = policy_over(tmp_path, profile, grype=[grype_match("Critical")], dev_only=[npm_adv("web")])
    assert [(c.id, c.scanner) for c, _ in r.blocking] == [("GHSA-prob-e000-0001", "grype")]
    assert [c.note for c, _ in r.advisory] == ["dev-only"]  # the npm record is still reported, as itself


@pytest.mark.parametrize("profile", ["none", "il4", "il6"])
def test_a_dev_only_grade_in_one_app_never_hides_the_advisory_reachable_in_another(tmp_path, profile):
    r = policy_over(tmp_path, profile, blocking=[npm_adv("api")], dev_only=[npm_adv("web")])
    assert [c.id for c, _ in r.blocking] == ["GHSA-prob-e000-0001"]
    assert all(c.note != "dev-only" for c, _ in r.blocking)


def test_a_dev_only_advisory_on_its_own_is_still_reported_not_blocking(tmp_path):
    r = policy_over(tmp_path, "il6", dev_only=[npm_adv("web")])
    assert r.blocking == [] and [why for _, why in r.advisory] == ["dev-only (outside the production tree)"]


def test_the_reviewers_dev_only_probe_through_the_gate(tmp_path, monkeypatch):
    g = tmp_path / "g.json"
    g.write_text(json.dumps({"matches": [grype_match("Critical")], "descriptor": {"db": {"status": {"built": FRESH}}}}))
    au = tmp_path / "au.json"
    au.write_text(json.dumps({"scanner": "npm-audit", "apps": [{"app": "web"}], "blocking": [], "allowlisted": [],
                              "dev_only": [npm_adv("web")], "reported": []}))
    after = f'cp "{g}" "$SCAN_RESULTS_DIR/grype.json"; cp "{au}" "$SCAN_RESULTS_DIR/audit.json"\n'
    for prof in ("none", "il6"):
        monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=after))
        r = gate().run(profile_ctx(tmp_path / prof, prof))
        assert r.status == "fail" and "GHSA-prob-e000-0001" in blocking_ids(r), (prof, r.reason)


# ── An entry's scope is a package name or a result file, matched whole (gate run 1, N-05) ─────

@pytest.mark.parametrize(("scope", "covered"), [
    ("libx", True), ("LibX", True), ("trivy.json", True), ("scan/results/trivy.json", True),
    ("json", False), ("scan", False), ("results", False), ("rivy.json", False), ("lib", False), ("grype.json", False),
])
def test_a_scope_matches_a_package_or_a_result_file_whole_never_a_substring(scope, covered):
    from securebuilderbot_scanners.policy import AcceptedRisk, Cve, covers
    cve = Cve(id="CVE-2026-1111", severity="high", package="libx", version="1.0", fix="1.1", published=None,
              scanner="trivy", file="scan/results/trivy.json")
    assert covers(AcceptedRisk(id="CVE-2026-1111", reason="r", expires="2026-12-01", scope=scope), cve) is covered


def test_at_il6_a_medium_cve_published_in_the_future_cannot_be_shown_young(tmp_path, monkeypatch):
    """N-07: a published date after now was a negative age, which is under every limit."""
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=cve_results(tmp_path, trivy_cve("CVE-2026-4098", "MEDIUM", "2026-11-20T00:00:00Z"))))
    r = gate().run(profile_ctx(tmp_path, "il6"))
    assert r.status == "fail" and blocking_ids(r) == ["CVE-2026-4098"]
    assert "future" in next(f.message for f in r.findings if f.rule_id == "CVE-2026-4098")


# ── The scanners never see the bot's secrets or the CI tokens (gate run 2, B-8) ───────────────

GHP = "ghp_" + "b" * 36  # secret-shaped, not a secret
SECRETS = {
    "GITHUB_TOKEN": "probe-not-a-real-token", "GH_TOKEN": "x", "GITLAB_TOKEN": "x", "SECURE_BUILDER_TOKEN": "x",
    "SB_MODEL_KEY": "x", "CI_JOB_TOKEN": "x", "CI_JOB_JWT": "x", "CI_JOB_JWT_V2": "x", "ACTIONS_RUNTIME_TOKEN": "x",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "x", "DOCKER_AUTH_CONFIG": "{}", "NPM_TOKEN": "x", "aws_secret_access_key": "x",
    "MY_API_KEY": "x", "DB_PASSWORD": "x", "SIGNING_SECRET": "x", "INNOCENT_NAME": GHP,
    "CI_REPOSITORY_URL": "https://gitlab-ci-token:abc123@gitlab.example/group/repo.git",
}
KEPT = {"PATH": os.environ["PATH"], "HOME": "/home/scanner", "HTTPS_PROXY": "http://proxy.example:3128", "NO_PROXY": "localhost",
        "SSL_CERT_FILE": "/etc/ssl/certs/ca.pem", "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca.pem", "LANG": "C.UTF-8",
        "CI_PROJECT_URL": "https://gitlab.example/group/repo"}


def test_the_scanner_environment_drops_every_secret_and_keeps_the_network(monkeypatch):
    from securebuilderbot_scanners.environment import scanner_env
    env = scanner_env({**SECRETS, **KEPT})
    assert not set(SECRETS) & set(env), set(SECRETS) & set(env)
    assert {k: env.get(k) for k in KEPT} == KEPT


def test_the_reviewers_probe_a_requirement_s_setup_py_never_sees_a_token(tmp_path, monkeypatch):
    """B-8: run-pip-audit.sh installs the checkout's requirements, so PR code runs inside the scan with
    whatever environment the gate passes. The fake pip-audit stands in for that code: it records its env."""
    for k, v in SECRETS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("HTTPS_PROXY", KEPT["HTTPS_PROXY"])
    repo = runner_checkout(tmp_path)
    seen = tmp_path / "seen-env"
    pa = fake_bin(tmp_path, "env-pip-audit", f'[ "$1" = --version ] && {{ echo "pip-audit {scangate.pinned_pip_audit()}"; exit 0; }}\n'
                  f'env > "{seen}"\necho \'{{"dependencies":[]}}\'\n')
    after = f'PIP_AUDIT_CMD="{pa}" bash "{RUNNERS}/run-pip-audit.sh" >/dev/null 2>&1\nenv > "{tmp_path / "shim-env"}"\n'
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=after))
    gate().run(profile_ctx(tmp_path, "none", repo=repo))
    for f in (seen, tmp_path / "shim-env"):
        names = {line.split("=", 1)[0] for line in f.read_text().splitlines() if "=" in line}
        text = f.read_text()
        assert not set(SECRETS) & names, (f.name, set(SECRETS) & names)
        assert "probe-not-a-real-token" not in text and GHP not in text and "abc123@" not in text
        assert "HTTPS_PROXY=http://proxy.example:3128" in text and "PATH=" in text


def test_the_scanner_environment_drops_every_npm_config_variable():
    """Gate run 3, N-01: npm reads npm_config_* (any case) as config, beside every .npmrc."""
    from securebuilderbot_scanners.environment import scanner_env
    env = scanner_env({"npm_config_registry": "http://evil.example/", "NPM_CONFIG_USERCONFIG": "/x", "Npm_Config_Omit": "dev", **KEPT})
    assert not [k for k in env if k.lower().startswith("npm_config_")]
    assert {k: env.get(k) for k in KEPT} == KEPT


def test_the_configured_model_key_secret_is_withheld_from_the_scanners_whatever_its_name(tmp_path, monkeypatch):
    """Gate run 3, N-02: sentinel.key_secret names the CI secret holding the model key, and it may be
    called anything. The QA gate withholds it by that name; the Scan gate must too."""
    monkeypatch.setenv("MODEL_CREDS", "plain-value-no-shape")
    monkeypatch.setenv("UNRELATED_SETTING", "kept")
    repo = tmp_path / "checkout"
    repo.mkdir()
    (repo / ".securebuilderbot.yml").write_text("profile: il4\ngates: [scan, sentinel]\nversion: latest\nsentinel:\n  key_secret: MODEL_CREDS\n")
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=f'env > "{tmp_path / "shim-env"}"\n'))
    gate().run(profile_ctx(tmp_path, "il4", repo=repo))
    names = {line.split("=", 1)[0] for line in (tmp_path / "shim-env").read_text().splitlines() if "=" in line}
    assert "MODEL_CREDS" not in names and "UNRELATED_SETTING" in names


def test_withheld_names_are_dropped_in_any_case():
    from securebuilderbot_scanners.environment import scanner_env
    env = scanner_env({"model_creds": "x", "Model_Creds": "y", "PATH": "/bin"}, withhold=("MODEL_CREDS",))
    assert env == {"PATH": "/bin"}


# ── Exceptions come from the base branch: a pull request cannot accept its own risk ──────────────────

ENTRY = "- id: CVE-2022-37434\n  reason: zlib inflate is never given attacker input here; no fixed version published\n  expires: 2026-12-01\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _repo(tmp_path: Path, base_files: dict[str, str], head_files: dict[str, str]) -> tuple[Path, str, str]:
    """A checkout whose base commit holds base_files and whose head adds or rewrites head_files."""
    repo = tmp_path / "checkout"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    for files, message in ((base_files, "base"), (head_files, "head")):
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return repo, _git(repo, "rev-parse", "HEAD~1"), _git(repo, "rev-parse", "HEAD")


def git_ctx(tmp_path: Path, repo: Path, base: str, head: str, config=None) -> GateContext:
    run_dir = tmp_path / "run" / "scan"
    run_dir.mkdir(parents=True, exist_ok=True)
    return GateContext(repo=repo, base=base, head=head, profile=load_profile("il4"), depth="light", run_dir=run_dir, config=config)


RISKS = "docs/security/accepted-risks.yml"


def test_an_exception_the_pull_request_adds_does_not_apply_until_it_is_merged(tmp_path, monkeypatch):
    repo, base, head = _repo(tmp_path, {}, {RISKS: ENTRY})
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))
    r = gate().run(git_ctx(tmp_path, repo, base, head))
    assert r.status == "fail" and "CVE-2022-37434" in blocking_ids(r)
    pending = [f for f in r.findings if f.rule_id == "accepted-risk-pending:CVE-2022-37434"]
    assert len(pending) == 1 and pending[0].severity == "advisory" and "applies once it is merged" in pending[0].message
    assert r.receipt["accepted_risks_pending"] == ["CVE-2022-37434"] and r.receipt["accepted_risks_applied"] == []


def test_an_exception_merged_on_the_base_branch_applies(tmp_path, monkeypatch):
    repo, base, head = _repo(tmp_path, {RISKS: ENTRY}, {"x.md": "words\n"})
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))
    r = gate().run(git_ctx(tmp_path, repo, base, head))
    assert r.status == "yellow" and [x["id"] for x in r.receipt["accepted_risks_applied"]] == ["CVE-2022-37434"]
    assert r.receipt["accepted_risks_pending"] == []
    assert r.receipt["accepted_risks_file"] == f"{RISKS} at the base commit {base[:12]}"


def test_a_pull_request_that_rewrites_a_merged_exception_is_held_to_the_base_copy(tmp_path, monkeypatch):
    expired = ENTRY.replace("2026-12-01", "2026-10-01")  # expired on the base; the PR pushes the date out
    repo, base, head = _repo(tmp_path, {RISKS: expired}, {RISKS: ENTRY})
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))
    r = gate().run(git_ctx(tmp_path, repo, base, head))
    assert r.status == "fail" and "accepted-risk:CVE-2022-37434" in blocking_ids(r)
    assert r.receipt["accepted_risks_pending"] == ["CVE-2022-37434"]


def test_the_exceptions_file_is_the_one_the_governing_config_names(tmp_path, monkeypatch):
    from securebuilderbot_core.config import load_config
    repo, base, head = _repo(tmp_path, {"risk/team.yml": ENTRY}, {RISKS: "[]\n"})
    cfg = tmp_path / "governing.yml"
    cfg.write_text("profile: il4\ngates: [scan]\nversion: latest\nscan:\n  accepted_risks: risk/team.yml\n")
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))
    r = gate().run(git_ctx(tmp_path, repo, base, head, config=load_config(cfg)))
    assert r.status == "yellow" and [x["id"] for x in r.receipt["accepted_risks_applied"]] == ["CVE-2022-37434"]


def test_an_exceptions_file_that_is_a_link_in_the_base_commit_covers_nothing(tmp_path, monkeypatch):
    repo, base, head = _repo(tmp_path, {"real.yml": ENTRY}, {"x.md": "words\n"})
    (repo / "docs" / "security").mkdir(parents=True)
    os.symlink("../../real.yml", repo / RISKS)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "link the exceptions")
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "head")
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))
    r = gate().run(git_ctx(tmp_path, repo, base, _git(repo, "rev-parse", "HEAD")))
    assert r.status == "fail" and r.receipt["accepted_risks_applied"] == []


def test_the_model_key_is_withheld_by_the_name_either_config_gives_it(tmp_path, monkeypatch):
    from securebuilderbot_core.config import load_config
    monkeypatch.setenv("BASE_CREDS", "plain-value-no-shape")
    monkeypatch.setenv("HEAD_CREDS", "plain-value-no-shape")
    repo, base, head = _repo(tmp_path, {}, {".securebuilderbot.yml": "profile: il4\ngates: [scan, sentinel]\nversion: latest\nsentinel:\n  key_secret: HEAD_CREDS\n"})
    cfg = tmp_path / "governing.yml"
    cfg.write_text("profile: il4\ngates: [scan, sentinel]\nversion: latest\nsentinel:\n  key_secret: BASE_CREDS\n")
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=f'env > "{tmp_path / "shim-env"}"\n'))
    gate().run(git_ctx(tmp_path, repo, base, head, config=load_config(cfg)))
    names = {line.split("=", 1)[0] for line in (tmp_path / "shim-env").read_text().splitlines() if "=" in line}
    assert "BASE_CREDS" not in names and "HEAD_CREDS" not in names


def test_the_checkov_justifications_and_npm_allowlist_the_scanners_read_are_the_base_commits(tmp_path, monkeypatch):
    # A pull request cannot justify its own Checkov failure or allowlist its own npm advisory: the
    # scanners are pointed at the base commit's copies, never the checkout's (and never the bot's own).
    lists = {"docs/security/checkov-justifications.yaml": "entries: []  # base\n",
             "docs/security/npm-audit-allowlist.yaml": "entries: []  # base\n"}
    repo, base, head = _repo(tmp_path, lists, {k: "entries: []  # head\n" for k in lists})
    seen = tmp_path / "seen"
    shim = fake_shim(tmp_path, "clean", after=f'{{ cat "$CHECKOV_JUSTIFICATIONS"; cat "$NPM_AUDIT_ALLOWLIST"; }} > "{seen}"\n')
    monkeypatch.setattr(scangate, "SHIM", shim)
    gate().run(git_ctx(tmp_path, repo, base, head))
    assert seen.read_text() == "entries: []  # base\nentries: []  # base\n"


def test_a_list_the_base_commit_does_not_have_points_the_scanner_at_nothing(tmp_path, monkeypatch):
    repo, base, head = _repo(tmp_path, {}, {"docs/security/checkov-justifications.yaml": "entries: []  # head\n"})
    seen = tmp_path / "seen"
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=f'[ -e "$CHECKOV_JUSTIFICATIONS" ] && echo there > "{seen}" || echo absent > "{seen}"\n'))
    gate().run(git_ctx(tmp_path, repo, base, head))
    assert seen.read_text() == "absent\n"


def test_the_lists_are_read_from_the_target_tip_never_the_merge_base(tmp_path, monkeypatch):
    # A branch cut from before an exception was revoked must not get it back: config_ref (the target
    # branch's tip) decides, the merge base only starts the diff.
    repo, merge_base, tip = _repo(tmp_path, {RISKS: ENTRY}, {RISKS: "[]\n"})  # the tip revoked the exception
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))
    c = git_ctx(tmp_path, repo, merge_base, tip)
    r = gate().run(GateContext(**{**c.__dict__, "config_ref": tip}))
    assert r.status == "fail" and r.receipt["accepted_risks_applied"] == []
    assert r.receipt["accepted_risks_file"] == f"{RISKS} at {tip[:12]}"


def test_what_the_gate_reads_from_git_is_read_before_any_gate_runs_pull_request_code(tmp_path, monkeypatch):
    # The scanners run PR code (an eslint config, a local setup.py) as the job user, and git does not
    # verify a loose object on read: the base's copies are taken in prepare(), before anything runs.
    repo, base, head = _repo(tmp_path, {RISKS: "[]\n"}, {"x.md": "words\n"})
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only"))
    c = git_ctx(tmp_path, repo, base, head)
    g = gate()
    g.prepare(c)
    monkeypatch.setattr(scangate, "blob_at", lambda *a: ("100644", ENTRY.encode()))  # a forged object, after prepare
    r = g.run(c)
    assert r.status == "fail" and r.receipt["accepted_risks_applied"] == []


def test_a_pending_entry_id_is_shown_safely_in_the_finding(tmp_path, monkeypatch):
    repo, base, head = _repo(tmp_path, {}, {RISKS: "- id: '[click](https://example.invalid)\\nline'\n  reason: x\n  expires: 2026-12-01\n"})
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean"))
    r = gate().run(git_ctx(tmp_path, repo, base, head))
    pending = [f for f in r.findings if f.rule_id.startswith("accepted-risk-pending:")]
    assert len(pending) == 1 and "\n" not in pending[0].message and "](" not in pending[0].rule_id


def test_the_exceptions_copy_rewritten_on_disk_by_scanner_run_code_is_not_what_applies(tmp_path, monkeypatch):
    # eslint loads the pull request's own config on the host while the scan runs; whatever it writes to
    # the run directory's copy, the entries taken in prepare() are the ones that apply.
    repo, base, head = _repo(tmp_path, {RISKS: "[]\n"}, {"x.md": "words\n"})
    copy = tmp_path / "run" / "scan" / "accepted-risks-at-base.yml"
    forged = tmp_path / "forged.yml"
    forged.write_text(ENTRY)
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "poam-only", after=f'cp "{forged}" "{copy}"\n'))
    c = git_ctx(tmp_path, repo, base, head)
    g = gate()
    g.prepare(c)
    r = g.run(c)
    assert r.status == "fail" and r.receipt["accepted_risks_applied"] == []


def test_the_scanners_that_read_an_excusing_list_run_before_any_scanner_that_runs_pull_request_code():
    # CM-29's copies are read from the run directory at scan time; they are safe because checkov and npm
    # audit run before eslint (the PR's own config) and pip-audit (a local setup.py). Reordering the
    # scanners reopens that hole, so the order is pinned here (third trust review, finding 6).
    text = (MODULE_DIR / "scan.sh").read_text()
    order = re.findall(r"([a-z-]+):run-[a-z-]+\.sh", text)
    assert order.index("checkov") < order.index("eslint") and order.index("npm-audit") < order.index("eslint")
    assert order.index("checkov") < order.index("pip-audit") and order.index("npm-audit") < order.index("pip-audit")


# The Wolfi freshness check. A line Wolfi stopped building while it builds a newer one blocks
# (nodejs-22 last built Aug 7, nodejs-24 Oct 21: the case that prompted it).
def wolfi_result(results: Path, *packages: dict) -> None:
    (results / "wolfi-freshness.json").write_text(json.dumps({"index": "fixture", "packages": list(packages)}))


def wolfi_pkg(name: str, built: str | None, *newer: tuple[str, str], path="backend/Dockerfile", line=6) -> dict:
    return {"package": name, "dockerfile": path, "line": line, "in_index": built is not None,
            "last_build": built, "newer": [{"package": n, "last_build": b} for n, b in newer]}


def test_a_wolfi_line_left_behind_by_a_newer_one_blocks_at_its_dockerfile_line(tmp_path):
    wolfi_result(tmp_path, wolfi_pkg("nodejs-22", "2026-08-07T12:00:00Z", ("nodejs-24", "2026-10-11T12:00:00Z")))
    [f] = scangate.stale_wolfi_packages(tmp_path, NOW)
    assert (f.severity, f.rule_id, f.path, f.line) == ("blocking", "stale-package:nodejs-22", "backend/Dockerfile", 6)
    assert "last built 2026-08-07 (69 days ago)" in f.message and "move the install to nodejs-24" in f.message


def test_a_wolfi_line_is_left_alone_while_fresh_or_while_no_newer_line_is_built(tmp_path):
    wolfi_result(tmp_path,
                 wolfi_pkg("nodejs-24", "2026-10-11T12:00:00Z"),                                       # fresh, no newer line
                 wolfi_pkg("nginx-mainline", "2026-06-01T12:00:00Z"),                                  # old, but no numbered line above it
                 wolfi_pkg("nodejs-22", "2026-09-10T12:00:00Z", ("nodejs-24", "2026-10-11T12:00:00Z")),  # 35 days: not yet stale
                 wolfi_pkg("python-3.11", "2026-05-01T12:00:00Z", ("python-3.13", "2026-06-01T12:00:00Z")))  # newer line stopped too
    assert scangate.stale_wolfi_packages(tmp_path, NOW) == []


def test_a_package_missing_from_the_wolfi_index_is_said_never_blocking(tmp_path):
    wolfi_result(tmp_path, wolfi_pkg("nodejs-18", None))
    [f] = scangate.stale_wolfi_packages(tmp_path, NOW)
    assert (f.severity, f.rule_id) == ("advisory", "wolfi-missing:nodejs-18")


def test_a_stale_wolfi_line_fails_the_scan_gate_and_names_it(tmp_path, monkeypatch):
    stale = json.dumps({"index": "fixture", "packages": [wolfi_pkg("nodejs-22", "2026-08-07T12:00:00Z", ("nodejs-24", "2026-10-11T12:00:00Z"))]})
    after = f"printf '%s' '{stale}' > \"$SCAN_RESULTS_DIR/wolfi-freshness.json\"\n"
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=after))
    r = gate().run(ctx(tmp_path))
    assert r.status == "fail" and "stale-package:nodejs-22" in blocking_ids(r)
    assert "stale-package:nodejs-22" in r.reason


def test_the_wolfi_check_not_running_fails_the_gate(tmp_path, monkeypatch):
    after = 'rm -f "$SCAN_RESULTS_DIR/wolfi-freshness.json"\n'
    monkeypatch.setattr(scangate, "SHIM", fake_shim(tmp_path, "clean", after=after))
    r = gate().run(ctx(tmp_path))
    assert r.status == "fail" and "scanner:wolfi-freshness" in blocking_ids(r)


def apkindex(path: Path, **built: str) -> Path:
    """A Wolfi APKINDEX.tar.gz holding one record per package, built at the given UTC day."""
    import io
    import tarfile
    recs = "\n\n".join(f"P:{p}\nV:1.0-r0\nt:{int(datetime.fromisoformat(d + 'T12:00:00+00:00').timestamp())}" for p, d in built.items())
    data = (recs + "\n").encode()
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("APKINDEX")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return path


def run_wolfi(repo: Path, results: Path, index: Path | None) -> subprocess.CompletedProcess:
    env = {**os.environ, "PROJECT_ROOT": str(repo), "SCAN_RESULTS_DIR": str(results)}
    env.update({"WOLFI_INDEX_FILE": str(index)} if index else {"WOLFI_INDEX_URL": "http://127.0.0.1:9/APKINDEX.tar.gz"})
    return subprocess.run(["bash", str(RUNNERS / "run-wolfi-freshness.sh")], env=env, capture_output=True, text=True)


def dockerfile_repo(tmp_path: Path, text: str) -> Path:
    repo = tmp_path / "repo"
    (repo / "backend").mkdir(parents=True)
    (repo / "backend" / "Dockerfile").write_text(text)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


def test_the_runner_records_each_wolfi_install_its_build_date_and_newer_lines(tmp_path):
    repo = dockerfile_repo(tmp_path, "FROM chainguard/wolfi-base:latest AS builder\n"
                                     "RUN apk add --no-cache nodejs-22 npm && node --version\n"
                                     "FROM node:22-alpine\nRUN apk add --no-cache curl\n"          # not Wolfi: not read
                                     "FROM cgr.dev/chainguard/wolfi-base\nRUN apk add \\\n    nginx-mainline=1.29.2-r0 \\\n    && echo done\n")
    index = apkindex(tmp_path / "APKINDEX.tar.gz", **{"nodejs-22": "2026-08-07", "nodejs-24": "2026-10-21", "nodejs-20": "2026-05-01",
                                                     "npm": "2026-10-20", "nginx-mainline": "2026-10-15"})
    results = tmp_path / "results"
    out = run_wolfi(repo, results, index)
    assert out.returncode == 0, out.stdout + out.stderr
    got = {(p["package"], p["line"]): p for p in json.loads((results / "wolfi-freshness.json").read_text())["packages"]}
    assert set(got) == {("nodejs-22", 2), ("npm", 2), ("nginx-mainline", 6)}  # not node, not curl, not the pin's version
    assert got[("nodejs-22", 2)]["last_build"] == "2026-08-07T12:00:00Z"
    assert [n["package"] for n in got[("nodejs-22", 2)]["newer"]] == ["nodejs-24"]  # nodejs-20 is older, not newer
    assert got[("nginx-mainline", 6)]["newer"] == [] and "wolfi-freshness ran 3" in (results / "scanners-ran").read_text()


def test_the_runner_without_wolfi_is_nothing_in_scope_and_an_unreachable_index_did_not_run(tmp_path):
    repo = dockerfile_repo(tmp_path, "FROM python:3.12-slim\nRUN pip install x\n")
    results = tmp_path / "results"
    assert run_wolfi(repo, results, None).returncode == 0
    assert "wolfi-freshness none" in (results / "scanners-ran").read_text()
    (repo / "backend" / "Dockerfile").write_text("FROM chainguard/wolfi-base\nRUN apk add nodejs-24\n")
    out = run_wolfi(repo, results, None)
    assert out.returncode == 1 and "did not run" in out.stdout
    assert not (results / "wolfi-freshness.json").exists()
    assert "wolfi-freshness" not in (results / "scanners-ran").read_text()
