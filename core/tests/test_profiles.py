import pytest

from securebuilderbot_core.__main__ import main
from securebuilderbot_core.profiles import ProfileError, custom_profile, load_profile, render


def test_il6_is_the_high_baseline_with_the_prd_numbers():
    p = load_profile("il6")
    assert p.baseline == "high"
    assert len(p.controls) == 370
    assert p.catalog_version == "5.2.0"
    assert p.scan.fail_on == ("critical", "high")
    assert p.scan.medium_max_age_days == 30
    assert p.scan.cve_data_max_age_days == 30
    assert p.qa.coverage_changed_lines == 90
    assert p.qa.mutation_required is True
    assert p.accepted_risk_expiry_days == 90
    assert p.stig_cat1_enforced is True
    assert p.checklist_blocks == ("base", "moderate", "high")


def test_il4_is_the_moderate_baseline_with_the_prd_numbers():
    p = load_profile("il4")
    assert p.baseline == "moderate"
    assert len(p.controls) == 287
    assert p.scan.fail_on == ("critical", "high")
    assert p.scan.medium_max_age_days is None
    assert p.scan.cve_data_max_age_days == 90
    assert p.qa.coverage_changed_lines == 80
    assert p.qa.mutation_required is True
    assert p.accepted_risk_expiry_days == 180
    assert p.checklist_blocks == ("base", "moderate")


def test_none_applies_no_baseline():
    p = load_profile("none")
    assert p.baseline is None
    assert p.controls == frozenset()
    assert p.scan.fail_on == ("critical",)
    assert p.qa.coverage_changed_lines == 60
    assert p.qa.mutation_required is False
    assert p.accepted_risk_expiry_days is None
    assert p.owasp_top10 is True


def test_moderate_is_inside_high():
    assert load_profile("il4").controls < load_profile("il6").controls


def test_unknown_profile_is_refused():
    with pytest.raises(ProfileError, match="unknown profile 'il5'"):
        load_profile("il5")


def test_custom_adds_and_removes_controls_from_its_base():
    base = load_profile("il4")
    extra = sorted(load_profile("il6").controls - base.controls)[0]
    dropped = sorted(base.controls)[0]
    p = custom_profile("il4", add=[extra], remove=[dropped])
    assert p.name == "custom"
    assert extra in p.controls
    assert dropped not in p.controls
    assert len(p.controls) == len(base.controls)
    assert p.qa == base.qa


def test_custom_refuses_a_control_the_catalog_does_not_have():
    with pytest.raises(ProfileError, match="ZZ-99"):
        custom_profile("il6", add=["ZZ-99"], remove=[])


def test_custom_refuses_a_base_that_is_not_il4_or_il6():
    with pytest.raises(ProfileError, match="custom base must be il4 or il6"):
        custom_profile("none", add=[], remove=[])


def test_render_shows_the_rows_an_assessor_reads():
    text = render(load_profile("il6"))
    for row in ("High", "370", "catalog 5.2.0", "90%", "required", "90 days",
                "critical or high CVEs, and medium CVEs older than 30 days", "every CAT I enforced"):
        assert row in text, row


def test_profile_show_cli(capsys):
    assert main(["profile", "show", "il4"]) == 0
    out = capsys.readouterr().out
    assert "Moderate" in out
    assert "287" in out


def test_profile_show_unknown_exits_2(capsys):
    assert main(["profile", "show", "il5"]) == 2
    assert "unknown profile" in capsys.readouterr().out


@pytest.mark.parametrize("bad, message", [
    ("extra: 1\n", "unknown key 'extra'"),
    ("baseline: low\n", "baseline must be moderate, high or null"),
    ("qa:\n  coverage_changed_lines: 140\n  mutation_required: true\n", "coverage_changed_lines must be 0"),
    ("qa:\n  coverage_changed_lines: 80\n  mutation_required: 'yes'\n", "'mutation_required' has the wrong type"),
    ("scan:\n  fail_on: [severe]\n  medium_max_age_days: null\n  cve_data_max_age_days: 30\n", "'fail_on' has an invalid entry 'severe'"),
    ("scan:\n  fail_on: [high]\n  medium_max_age_days: null\n  cve_data_max_age_days: -1\n", "positive number of days"),
    ("accepted_risk_expiry_days: true\n", "'accepted_risk_expiry_days' has the wrong type"),
])
def test_a_bad_profile_file_is_refused(tmp_path, monkeypatch, bad, message):
    import yaml

    from securebuilderbot_core import profiles
    good = yaml.safe_load((profiles.PROFILES_DIR / "il4.yml").read_text())
    good.update(yaml.safe_load(bad))
    (tmp_path / "il4.yml").write_text(yaml.safe_dump(good))
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path)
    with pytest.raises(ProfileError, match=message):
        load_profile("il4")


def test_a_profile_file_missing_a_key_is_refused(tmp_path, monkeypatch):
    import yaml

    from securebuilderbot_core import profiles
    good = yaml.safe_load((profiles.PROFILES_DIR / "il4.yml").read_text())
    del good["owasp_top10"]
    (tmp_path / "il4.yml").write_text(yaml.safe_dump(good))
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path)
    with pytest.raises(ProfileError, match="missing key 'owasp_top10'"):
        load_profile("il4")
