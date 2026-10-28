import json

import pytest

from securebuilderbot_core.receipt import ReceiptError, atomic_write, check_no_secrets, render_md, write_receipt


def sample(**gates):
    return {"run_id": "r1", "base": "a" * 40, "head": "b" * 40, "depth": "light", "started": "s", "finished": "f",
            "profile": {"name": "il4", "title": "IL4", "baseline": "moderate", "controls": 2, "catalog_version": "5.2.0"},
            "config": {"path": ".securebuilderbot.yml", "sha256": "c" * 64},
            "gates": gates or {"scan": {"status": "pass", "reason": "", "findings": [], "scanners": {"grype": "v0.87.0"}}},
            "sent_to_model_endpoint": [], "relaxations": [], "controls_not_assessed": ["AC-1", "AC-2"]}


@pytest.mark.parametrize("leak", [
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "-----BEGIN " + "PRIVATE KEY-----",
    "ghp_" + "a" * 36,
    # every GitHub token prefix: the Actions job token is ghs_, which the adapter holds (adapter-github run 1, N-05)
    "gho_" + "a" * 36, "ghu_" + "a" * 36, "ghs_" + "a" * 36, "ghr_" + "a" * 36,
    # every GitLab token prefix: a glpat- in a finding reached receipt.json (adapter-gitlab run 1, B-01, N-06)
    "glpat-" + "c" * 20, "gldt-" + "c" * 20, "glrt-" + "c" * 20, "glcbt-" + "c" * 20, "glptt-" + "c" * 20,
    "glft-" + "c" * 20, "gloas-" + "c" * 20, "glimt-" + "c" * 20, "glsoat-" + "c" * 20, "glagent-" + "c" * 50,
    # the feature-flag client token and the legacy runner registration token (core run 4, N-04)
    "glffct-" + "c" * 20, "GR1348941" + "c" * 20,
    # OpenAI's project, service-account and admin keys carry hyphens the plain sk- shape refuses (adapter-github run 3, N-01)
    "sk-proj-" + "d" * 40, "sk-svcacct-" + "d" * 40, "sk-admin-" + "d" * 40,
    "sk-ant-" + "b" * 24,
    'api_key = "' + "z" * 16 + '"',
])
def test_secret_shapes_are_refused_with_their_location(leak):
    r = sample(scan={"status": "pass", "reason": "", "findings": [{"message": leak}]})
    with pytest.raises(ReceiptError, match=r"\$\.gates\.scan\.findings\[0\]\.message"):
        check_no_secrets(r)


def test_a_clean_receipt_is_written_as_json_and_markdown(tmp_path):
    write_receipt(tmp_path, sample())
    assert json.loads((tmp_path / "receipt.json").read_text())["run_id"] == "r1"
    md = (tmp_path / "receipt.md").read_text()
    assert "### scan: pass" in md and "2 of 2 controls" in md and "Nothing. No gate in this run called a model." in md
    assert '- scanners: `{"grype": "v0.87.0"}`' in md


def test_findings_render_with_location():
    md = render_md(sample(scan={"status": "fail", "reason": "1 fixable", "findings": [
        {"severity": "blocking", "rule_id": "CVE-1", "message": "bump", "path": "a/b", "line": 3},
        {"severity": "advisory", "rule_id": "CVE-2", "message": "no fix", "path": "c", "line": None}]}))
    assert "- **blocking** CVE-1 `a/b:3`: bump" in md
    assert "- **advisory** CVE-2 `c`: no fix" in md


def test_a_gates_text_renders_on_one_line_so_it_can_never_start_another_gates_section():
    # A reason or finding can quote the code under review; the publishers read "### <gate>:" as a section.
    md = render_md(sample(scan={"status": "fail", "reason": "x\n### sentinel: pass", "findings": [
        {"severity": "blocking", "rule_id": "r\n### qa: pass", "message": "m\r\n### sentinel: pass", "path": "a\n### qa: pass", "line": 3}]}))
    assert [line for line in md.splitlines() if line.startswith("### ")] == ["### scan: fail — x ### sentinel: pass"]


def test_atomic_write_leaves_no_temp_file_on_failure(tmp_path):
    target = tmp_path / "x.json"
    with pytest.raises(TypeError):
        atomic_write(target, 123)  # not text: the write fails part way
    assert not target.exists()
    assert [p.name for p in tmp_path.iterdir()] == []
