"""The read API over the vendored indexes (SPEC-standards.md § Interface)."""

from __future__ import annotations

import pytest

from securebuilderbot_standards import baseline, catalog, masvs, nist_pubs, owasp, stigs, versions


def test_ac2_is_in_the_catalog_and_both_baselines(vendored):
    c = catalog(vendored)["AC-2"]
    assert c.title == "Account Management" and c.family == "AC"
    assert c.in_moderate and c.in_high and not c.withdrawn


def test_the_baselines_have_the_prd_counts(vendored):
    assert len(baseline("moderate", vendored)) == 287
    assert len(baseline("high", vendored)) == 370
    assert baseline("moderate", vendored) < baseline("high", vendored)


def test_a_withdrawn_control_names_what_replaced_it(small):
    c = catalog(small)["SA-12"]
    assert c.withdrawn and c.into == ("SR",) and not c.in_moderate and not c.in_high


def test_an_unknown_baseline_level_is_refused(small):
    with pytest.raises(ValueError, match="moderate or high"):
        baseline("low", small)


def test_stig_rules_carry_benchmark_version_and_severity_where_present(small):
    import json
    idx = small / "stig-index.json"
    doc = json.loads(idx.read_text())
    doc["rules"]["SRG-APP-000001-AS-000001"]["sev"] = "high"  # the redistribution carries none; a future index may
    idx.write_text(json.dumps(doc))
    rules = stigs(small)
    r = rules["RHEL-08-010000"]
    assert (r.benchmark, r.version, r.severity) == ("rhel8", "v2r8", None)
    assert rules["SRG-APP-000001-AS-000001"].severity == "high"


def test_the_vendored_stig_index_reads_as_objects(vendored):
    rules = stigs(vendored)
    assert len(rules) == 4010 and rules["CNTR-OS-000010"].benchmark == "rhcos4"


def test_owasp_current_editions_and_the_history_behind_them(small):
    o = owasp(small)
    assert o.web_edition == "2025" and o.llm_edition == "2025"
    assert o.web["A04"] == "Cryptographic Failures" and o.llm["LLM06"] == "Excessive Agency"
    assert o.editions["web"]["2021"]["A02"] == "Cryptographic Failures"


def test_nist_pubs_know_the_latest_published_revision(small):
    p = nist_pubs(small)["SP 800-124"]
    assert p.latest == "r2" and p.revisions == ("", "r1", "r2") and p.drafts == ("r3.ipd",)


def test_masvs_controls_and_release(small):
    m = masvs(small)
    assert m.release == "v2.1.0" and "MASVS-NETWORK-1" in m.controls


def test_versions_for_the_receipt(vendored):
    v = versions(vendored)
    assert v["catalog"] == "5.2.0"
    assert v["baselines_retrieved"] == "2026-10-15"
    assert v["stig_index"] == "2026-09-19" and v["owasp"] == "2025"
    assert v["masvs"] == "v2.1.0" and v["nist_pubs"] == "2026-09-19"


def test_versions_say_none_for_an_index_that_is_not_there(tmp_path):
    from smallindex import write_indexes
    v = versions(write_indexes(tmp_path / "c", only={"nist-800-53r5-index.json"}))
    assert v["catalog"] == "5.2.0" and v["stig_index"] is None and v["masvs"] is None


def test_a_missing_catalog_is_an_error_not_an_empty_catalog(tmp_path):
    with pytest.raises(FileNotFoundError):
        catalog(tmp_path)
