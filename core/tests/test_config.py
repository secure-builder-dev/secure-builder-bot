from pathlib import Path

import pytest

from securebuilderbot_core.__main__ import main
from securebuilderbot_core.config import ConfigError, load_config


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / ".securebuilderbot.yml"
    p.write_text(text)
    return p


GOOD = "profile: il6\ngates: [scan]\nversion: latest\n"


def test_three_lines_are_enough(tmp_path):
    c = load_config(write(tmp_path, GOOD))
    assert c.profile.name == "il6"
    assert c.gates == ("scan",)
    assert c.version == "latest"
    assert c.relaxations == ()
    assert c.sentinel.depth == "auto"
    assert c.qa.mutation is None


def test_unknown_key_names_the_key_and_its_line(tmp_path):
    p = write(tmp_path, GOOD + "\n# comment\nprofil: il4\n")
    with pytest.raises(ConfigError) as e:
        load_config(p)
    assert e.value.line == 6
    assert "unknown key 'profil'" in str(e.value)
    assert str(e.value).startswith(f"{p}:6: ")


def test_unknown_nested_key_names_its_line(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, GOOD + "qa:\n  mutaton: false\n"))
    assert e.value.line == 5
    assert "unknown key 'qa.mutaton'" in str(e.value)


@pytest.mark.parametrize("missing", ["profile", "gates", "version"])
def test_a_required_key_is_required(tmp_path, missing):
    text = "".join(line + "\n" for line in GOOD.splitlines() if not line.startswith(missing))
    with pytest.raises(ConfigError, match=f"missing required key '{missing}'"):
        load_config(write(tmp_path, text))


def test_a_duplicate_key_is_refused_not_silently_overwritten(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, GOOD + "profile: none\n"))
    assert e.value.line == 4
    assert "duplicate key 'profile'" in str(e.value)


@pytest.mark.parametrize("text, line, message", [
    ("profile: il5\ngates: [scan]\nversion: latest\n", 1, "profile must be one of"),
    ("profile: il6\ngates: [scan, lint]\nversion: latest\n", 2, "unknown gate 'lint'"),
    ("profile: il6\ngates: [scan, scan]\nversion: latest\n", 2, "gate 'scan' listed twice"),
    ("profile: il6\ngates: []\nversion: latest\n", 2, "gates is empty"),
    ("profile: il6\ngates: scan\nversion: latest\n", 2, "gates must be a list"),
    ("profile: il6\ngates: [scan]\nversion: 1.4\n", 3, "version must be latest or x.y.z"),
    ("profile: il6\ngates: [scan]\nversion: latest\nscan:\n  skip: [nmap]\n", 5, "unknown scanner 'nmap'"),
    ("profile: il6\ngates: [scan]\nversion: latest\nsentinel:\n  depth: sometimes\n", 5, "sentinel.depth must be one of"),
    ("profile: il6\ngates: [scan]\nversion: latest\nsentinel:\n  provider: acme\n", 5, "sentinel.provider must be one of"),
    ("profile: il6\ngates: [scan, sentinel]\nversion: latest\n", 2, "the sentinel gate needs sentinel.key_secret"),
    ("profile: il6\ngates: [scan]\nversion: latest\nqa:\n  mutation: maybe\n", 5, "qa.mutation must be true or false"),
    ("- profile\n", 1, "must be a mapping"),
    ("", 1, "must be a mapping"),
])
def test_bad_values_fail_with_their_line(tmp_path, text, line, message):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, text))
    assert message in str(e.value)
    assert e.value.line == line


def test_a_secret_value_where_a_secret_name_belongs_is_refused_and_not_echoed(tmp_path):
    leaked = "sk-ant-api03-abcdefghijklmnop"
    p = write(tmp_path, GOOD + f"sentinel:\n  provider: anthropic\n  key_secret: {leaked}\n")
    with pytest.raises(ConfigError) as e:
        load_config(p)
    assert e.value.line == 6
    assert "sentinel.key_secret must be the name of a CI secret" in str(e.value)
    assert leaked not in str(e.value)


def test_any_key_shaped_field_holds_a_name_never_a_value(tmp_path):
    with pytest.raises(ConfigError, match="qa.api_token must be the name of a CI secret"):
        load_config(write(tmp_path, GOOD + "qa:\n  api_token: hunter2\n"))


def test_a_secret_name_is_accepted(tmp_path):
    c = load_config(write(tmp_path, "profile: il4\ngates: [scan, sentinel]\nversion: 1.4.2\n"
                                    "sentinel:\n  provider: anthropic\n  key_secret: SB_MODEL_KEY\n"))
    ci_name = "SB_MODEL_KEY"  # the name of a CI secret, which is what the field must hold
    assert c.sentinel.key_secret == ci_name
    assert c.version == "1.4.2"


def test_turning_off_what_the_profile_requires_is_allowed_and_recorded(tmp_path):
    c = load_config(write(tmp_path, "profile: il4\ngates: [scan, qa]\nversion: latest\n"
                                    "qa:\n  mutation: off\nscan:\n  skip: [clamav]\n"))
    assert c.qa.mutation is False
    assert any("mutation" in r and "il4 requires" in r for r in c.relaxations)
    assert any("clamav" in r for r in c.relaxations)


def test_custom_profile_reads_its_base_and_tailoring(tmp_path):
    c = load_config(write(tmp_path, "profile: custom\ngates: [scan]\nversion: latest\n"
                                    "custom:\n  base: il4\n  add: [AC-2(13)]\n  remove: [AC-1]\n"))
    assert c.profile.name == "custom"
    assert "AC-2(13)" in c.profile.controls and "AC-1" not in c.profile.controls


def test_custom_without_its_block_and_a_block_without_custom_are_refused(tmp_path):
    with pytest.raises(ConfigError, match="profile: custom needs a custom block"):
        load_config(write(tmp_path, "profile: custom\ngates: [scan]\nversion: latest\n"))
    with pytest.raises(ConfigError, match="a custom block needs profile: custom"):
        load_config(write(tmp_path, GOOD + "custom:\n  base: il4\n"))


def test_custom_with_an_unknown_control_names_the_line(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, "profile: custom\ngates: [scan]\nversion: latest\n"
                                    "custom:\n  base: il6\n  add: [ZZ-9]\n"))
    assert "ZZ-9" in str(e.value)
    assert e.value.line == 4


def test_config_check_cli(tmp_path, capsys):
    p = write(tmp_path, GOOD)
    assert main(["config", "check", "--config", str(p)]) == 0
    assert "profile il6" in capsys.readouterr().out
    bad = write(tmp_path, GOOD + "profil: x\n")
    assert main(["config", "check", "--config", str(bad)]) == 2
    assert ":4: unknown key 'profil'" in capsys.readouterr().out


def test_config_check_cli_missing_file(tmp_path, capsys):
    assert main(["config", "check", "--config", str(tmp_path / "nope.yml")]) == 2
    assert "no config file" in capsys.readouterr().out


def test_hash_identifies_the_exact_file(tmp_path):
    a = load_config(write(tmp_path, GOOD)).sha256
    b = load_config(write(tmp_path, GOOD + "# a comment changes the file\n")).sha256
    assert a != b and len(a) == 64


def test_an_aws_key_id_is_a_value_not_a_secret_name(tmp_path):
    key_id = "AKIA" + "ABCDEFGHIJKLMNOP"  # the shape of an access key id, not one
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, f"profile: il6\ngates: [scan, sentinel]\nversion: latest\nsentinel:\n  key_secret: {key_id}\n"))
    assert e.value.line == 5 and "must be the name of a CI secret" in str(e.value)
    assert key_id not in str(e.value)


def test_a_secret_shaped_key_inside_a_list_is_checked_and_its_value_never_repeated(tmp_path):
    value = "sk-live-" + "abcdef123456"
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, f"profile: il6\ngates: [scan, {{api_key: {value}}}]\nversion: latest\n"))
    assert "gates.1.api_key must be the name of a CI secret" in str(e.value)
    assert value not in str(e.value)


@pytest.mark.parametrize("item", ["sk-ant-" + "b" * 24, "a-very-long-gate-name-" + "x" * 30, "{nested: map}"])
def test_an_unknown_list_item_is_named_by_position_never_echoed_when_it_could_be_a_value(tmp_path, item):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, f"profile: il6\ngates: [scan, {item}]\nversion: latest\n"))
    assert "unknown gate (a value not shown)" in str(e.value) and e.value.line == 2


def test_yaml_aliases_are_refused_before_anything_expands(tmp_path):
    bomb = "a: &a [x, x, x, x, x, x, x, x, x, x]\n" + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [{', '.join(['*' + chr(97 + i)] * 10)}]\n" for i in range(6))
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, GOOD + bomb))
    assert "anchors and aliases are not allowed" in str(e.value)


def test_a_config_that_is_not_utf8_is_a_config_error_with_its_line(tmp_path):
    p = tmp_path / ".securebuilderbot.yml"
    p.write_bytes(GOOD.encode() + b"# caf\xe9\n")
    with pytest.raises(ConfigError) as e:
        load_config(p)
    assert e.value.line == 4 and "not UTF-8" in str(e.value)


def test_a_key_that_is_a_list_is_a_config_error_not_a_traceback(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, GOOD + "? [a, b]\n: x\n"))
    assert e.value.line == 4 and "a key must be a plain name" in str(e.value)


@pytest.mark.parametrize("text", [
    GOOD + "qa:\n  {s}: x\n",                     # nested unknown key
    GOOD + "{s}: 1\n{s}: 2\n",                   # duplicate key
    "profile: custom\ngates: [scan]\nversion: latest\ncustom:\n  base: {s}\n",
    "profile: custom\ngates: [scan]\nversion: latest\ncustom:\n  base: il4\n  add: [{s}]\n",
])
def test_no_config_error_repeats_a_secret_shaped_value(tmp_path, text):
    value = "sk-ant-" + "e" * 24  # secret-shaped, not a secret
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, text.format(s=value)))
    assert value not in str(e.value) and "(a value not shown)" in str(e.value)


# ── sentinel.endpoint, sentinel.model, sentinel.max_diff_bytes (the sentinel module's keys) ──────

SENTINEL = "profile: il6\ngates: [scan, sentinel]\nversion: latest\nsentinel:\n  key_secret: SB_MODEL_KEY\n"


def test_sentinel_defaults_need_no_endpoint_model_or_budget(tmp_path):
    c = load_config(write(tmp_path, SENTINEL))
    assert c.sentinel.endpoint is None
    assert c.sentinel.model is None
    assert c.sentinel.max_diff_bytes == 300000


def test_a_mirror_endpoint_a_model_and_a_budget_are_read(tmp_path):
    c = load_config(write(tmp_path, SENTINEL + "  endpoint: https://mirror.example.invalid/llm\n"
                                               "  model: claude-sonnet-5-5\n  max_diff_bytes: 50000\n"))
    assert c.sentinel.endpoint == "https://mirror.example.invalid/llm"
    assert c.sentinel.model == "claude-sonnet-5-5"
    assert c.sentinel.max_diff_bytes == 50000


@pytest.mark.parametrize("extra, line, message", [
    ("  endpoint: ftp://mirror.example.invalid\n", 6, "sentinel.endpoint must be an http or https URL"),
    ("  endpoint: mirror.example.invalid\n", 6, "sentinel.endpoint must be an http or https URL"),
    ("  endpoint: [a]\n", 6, "sentinel.endpoint must be an http or https URL"),
    ("  endpoint: https://mirror.example.invalid/v1?x=1\n", 6, "no query or fragment"),
    ("  model: 'two words'\n", 6, "sentinel.model must be a model id"),
    ("  model: 7\n", 6, "sentinel.model must be a model id"),
    ("  max_diff_bytes: 10\n", 6, "sentinel.max_diff_bytes must be a whole number of bytes"),
    ("  max_diff_bytes: true\n", 6, "sentinel.max_diff_bytes must be a whole number of bytes"),
    ("  max_diff_bytes: 1.5\n", 6, "sentinel.max_diff_bytes must be a whole number of bytes"),
])
def test_a_bad_sentinel_value_names_its_line(tmp_path, extra, line, message):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, SENTINEL + extra))
    assert e.value.line == line
    assert message in str(e.value)


def test_an_endpoint_carrying_credentials_is_refused_and_not_repeated(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, SENTINEL + "  endpoint: https://bot:hunter2hunter2@mirror.example.invalid/\n"))
    assert "must not carry credentials" in str(e.value)
    assert "hunter2" not in str(e.value)


def test_a_self_hosted_provider_with_no_endpoint_or_model_is_a_valid_file_left_to_the_gate(tmp_path):
    # The setup PR writes provider: self-hosted before the user has a server to name; the gate says what is missing.
    c = load_config(write(tmp_path, SENTINEL + "  provider: self-hosted\n"))
    assert (c.sentinel.provider, c.sentinel.endpoint, c.sentinel.model) == ("self-hosted", None, None)
    c = load_config(write(tmp_path, SENTINEL + "  provider: self-hosted\n  model: local-7b\n"
                                               "  endpoint: https://llm.internal.invalid:8080\n"))
    assert (c.sentinel.provider, c.sentinel.model) == ("self-hosted", "local-7b")


def test_the_sentinel_keys_are_judged_only_when_sentinel_is_on_for_the_provider_rules(tmp_path):
    c = load_config(write(tmp_path, GOOD + "sentinel:\n  provider: openai\n"))
    assert c.sentinel.model is None


# ── sentinel.endpoint: plain http only to this machine (sentinel gate run 1, N-04) ───────────────

@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:8080", "http://localhost:8080/v1", "http://[::1]:8080",
                                      "http://127.10.0.3", "https://llm.internal.invalid", "https://10.0.0.5:8443/v1"])
def test_an_https_endpoint_or_a_loopback_http_one_is_accepted(tmp_path, endpoint):
    assert load_config(write(tmp_path, SENTINEL + f"  endpoint: {endpoint}\n")).sentinel.endpoint == endpoint


@pytest.mark.parametrize("endpoint", ["http://llm.internal.invalid", "http://10.0.0.5:8080", "http://localhost.example.invalid",
                                      "http://127.0.0.1.example.invalid", "http://0.0.0.0:8080"])
def test_a_plain_http_endpoint_off_this_machine_is_refused(tmp_path, endpoint):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, SENTINEL + f"  endpoint: {endpoint}\n"))
    assert e.value.line == 6
    assert "must be https unless it is this machine" in str(e.value)


@pytest.mark.parametrize("value", ["/etc/accepted.yml", "../outside.yml", "docs/../../outside.yml"])
def test_the_exceptions_file_must_be_a_path_inside_the_repository(tmp_path, value):
    p = tmp_path / ".securebuilderbot.yml"
    p.write_text(f"profile: il6\ngates: [scan]\nversion: latest\nscan:\n  accepted_risks: {value}\n")
    with pytest.raises(ConfigError, match="inside the repository"):
        load_config(p)
