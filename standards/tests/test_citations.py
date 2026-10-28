"""verify_citations: the rules verify-citations.sh has always applied, as a function."""

from __future__ import annotations

from securebuilderbot_standards import verify_citations
from securebuilderbot_standards.citations import (
    is_active_control, line_is_exempt, masvs_id_current, owasp_title_matches, pub_revision_published, stig_rule_known,
)


def by_id(cites):
    return {c.id: c for c in cites}


def test_the_spec_example_marks_the_last_two_not_ok(vendored):
    c = by_id(verify_citations("AC-2 and AC-99 and SC-7(99)", data_dir=vendored))
    assert c["AC-2"].ok
    assert not c["AC-99"].ok and "not in the 800-53 catalogue" in c["AC-99"].reason
    assert not c["SC-7(99)"].ok and c["SC-7(99)"].kind == "nist"


def test_a_withdrawn_control_fails_and_names_its_replacement(small):
    c = by_id(verify_citations("supply chain SA-12 (Supply Chain Protection)", data_dir=small))
    assert not c["SA-12"].ok and c["SA-12"].status == "withdrawn" and "use: SR" in c["SA-12"].reason


def test_the_allow_marker_exempts_that_line_only(small):
    text = "- SA-12 moved here citations: allow\n- invented AC-99\n"
    c = by_id(verify_citations(text, data_dir=small))
    assert "SA-12" not in c and not c["AC-99"].ok and c["AC-99"].line == 2


def test_manifest_row_ids_are_not_nist_controls(small):
    text = "| CM-01 | row id, not NIST |\nprose mention CM-20 and CM-06 and a real CM-6\n"
    c = by_id(verify_citations(text, data_dir=small))
    assert set(c) == {"CM-6"} and c["CM-6"].ok


def test_a_title_mismatch_is_advisory_never_a_failure(small):
    c = by_id(verify_citations("AC-3 (Account Management)", data_dir=small))
    assert c["AC-3"].ok and c["AC-3"].status == "mislabelled" and "Access Enforcement" in c["AC-3"].reason


def test_owasp_renumbering_fails_and_points_at_the_right_id(small):
    c = verify_citations("- agent ceiling LLM08 — excessive agency\n- web A02 Cryptographic Failures\n", data_dir=small)
    bad = {x.id: x for x in c if x.kind == "owasp"}
    assert not bad["LLM08"].ok and "did you mean LLM06" in bad["LLM08"].reason
    assert "Vector And Embedding Weaknesses" in bad["LLM08"].reason
    assert not bad["A02"].ok and "did you mean A04" in bad["A02"].reason


def test_correct_owasp_numbering_passes_and_prose_is_not_a_title(small):
    c = verify_citations("- agent ceiling LLM06 — excessive agency\n- prose mention (LLM01 above) is not a title claim\n", data_dir=small)
    owasp = [x for x in c if x.kind == "owasp"]
    assert [x.id for x in owasp] == ["LLM06"] and owasp[0].ok


def test_stig_ids_resolve_fail_or_are_reported_uncovered(small):
    text = ("- covered os rule RHEL-08-010000\n- covered srg rule SRG-APP-000001-AS-000001\n"
            "- app stig APSC-DV-002000\n- rfc reference RFC5280 and a bare word\n- typo RHEL-08-999999\n- (was PGS9-00-000100) pointer\n")
    c = {x.id: x for x in verify_citations(text, data_dir=small) if x.kind == "stig"}
    assert c["RHEL-08-010000"].ok and c["SRG-APP-000001-AS-000001"].ok
    assert c["APSC-DV-002000"].ok and c["APSC-DV-002000"].status == "not-covered"
    assert not c["RHEL-08-999999"].ok and "platform IS indexed" in c["RHEL-08-999999"].reason
    assert "RFC5280" not in c and "PGS9-00-000100" not in c


def test_masvs_unknown_and_v1_numbering_fail(small):
    text = "- android tls MASVS-NETWORK-1\n- android tls MASVS-NETWORK-9\n- android storage MSTG-STORAGE-1\n- (was MSTG-STORAGE-2) pointer\n"
    c = {x.id: x for x in verify_citations(text, data_dir=small) if x.kind == "masvs"}
    assert c["MASVS-NETWORK-1"].ok
    assert not c["MASVS-NETWORK-9"].ok and c["MASVS-NETWORK-9"].status == "unknown"
    assert not c["MSTG-STORAGE-1"].ok and c["MSTG-STORAGE-1"].status == "superseded" and "v2.1.0" in c["MSTG-STORAGE-1"].reason
    assert "MSTG-STORAGE-2" not in c


def test_nist_publication_currency(small):
    text = ("- vetting NIST SP 800-163 Rev 1 and NIST SP 800-124 Rev 2 and FIPS 140-3\n- old NIST SP 800-124 Rev 1\n"
            "- invented NIST SP 800-163 Rev 4\n- invented FIPS 141\n- no such SP 800-999\n")
    c = [x for x in verify_citations(text, data_dir=small) if x.kind == "nistpub"]
    status = {(x.id, x.line): x for x in c}
    assert status[("SP 800-163 Rev 1", 1)].ok and status[("FIPS 140-3", 1)].ok
    assert status[("SP 800-124 Rev 1", 2)].ok and status[("SP 800-124 Rev 1", 2)].status == "superseded"
    assert "r1 cited, r2 published" in status[("SP 800-124 Rev 1", 2)].reason
    assert not status[("SP 800-163 Rev 4", 3)].ok and "published revisions: (original), r1" in status[("SP 800-163 Rev 4", 3)].reason
    assert not status[("FIPS 141", 4)].ok and not status[("SP 800-999", 5)].ok


def test_an_optional_index_that_is_missing_skips_its_kind(tmp_path):
    from smallindex import write_indexes
    d = write_indexes(tmp_path / "c", only={"nist-800-53r5-index.json"})
    c = verify_citations("AC-2 and LLM08 — excessive agency and MASVS-NETWORK-9 and FIPS 141", data_dir=d)
    assert [x.kind for x in c] == ["nist"]


def test_the_decisions_each_refuse_what_they_exist_to_refuse():
    controls = {"AC-2": {"t": "x", "s": "active"}, "SA-12": {"t": "y", "s": "withdrawn"}}
    assert is_active_control("AC-2", controls)
    assert not is_active_control("SA-12", controls) and not is_active_control("AC-99", controls)
    assert owasp_title_matches("excessive agency", "Excessive Agency")
    assert not owasp_title_matches("excessive agency", "Vector and Embedding Weaknesses")
    assert stig_rule_known("RHEL-08-010000", {"RHEL-08-010000": {}}) and not stig_rule_known("RHEL-08-999999", {"RHEL-08-010000": {}})
    assert masvs_id_current("MASVS-NETWORK-1", {"MASVS-NETWORK-1": "s"})
    assert not masvs_id_current("MASVS-NETWORK-9", {"MASVS-NETWORK-1": "s"})
    assert not masvs_id_current("MSTG-NETWORK-1", {"MSTG-NETWORK-1": "s"})  # v1 numbering, even if someone indexed it
    assert pub_revision_published("r1", {"revisions": ["", "r1"]}) and pub_revision_published("", {"revisions": [""]})
    assert not pub_revision_published("r4", {"revisions": ["", "r1"]})
    assert line_is_exempt("- SA-12 kept on purpose citations: allow") and line_is_exempt("<!-- citations: allow -->")
    assert not line_is_exempt("- SA-12 cited as live") and not line_is_exempt("citations:allowed? no")


def test_an_enhancement_range_names_each_enhancement_and_a_was_pointer_is_history(small):
    text = "- spillage SC-7(1–3) and (was SA-12) and SC-7(3-4)\n"
    c = [x for x in verify_citations(text, data_dir=small) if x.kind == "nist"]
    assert [x.id for x in c] == ["SC-7(1)", "SC-7(2)", "SC-7(3)", "SC-7(3)", "SC-7(4)"]
    assert [x.ok for x in c] == [False, False, True, True, False]
    assert "SA-12" not in {x.id for x in c}


def test_an_id_followed_by_a_title_in_parentheses_is_still_the_id(small):
    c = verify_citations("IR-9(Information Spillage Response) is not here; AC-3(Access Enforcement) is", data_dir=small)
    assert [(x.id, x.ok) for x in c] == [("IR-9", False), ("AC-3", True)]
