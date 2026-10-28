import subprocess
from pathlib import Path

from securebuilderbot_core.__main__ import main

ROOT = Path(__file__).resolve().parents[2]


def test_no_command_prints_help_and_exits_2(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out


def test_launcher_runs_from_another_directory(tmp_path):
    out = subprocess.run([str(ROOT / "core" / "run"), "--version"], cwd=tmp_path, capture_output=True, text=True)
    assert out.returncode == 0
    assert out.stdout.startswith("securebuilderbot-core ")


def test_the_launcher_never_imports_a_module_from_the_checkout_it_runs_in(tmp_path):
    # The verdict job runs core with the pull request's checkout as its working directory. A file
    # there named like a module core imports (yaml.py, a package of core's own name) must never run.
    marker = tmp_path / "ran"
    plant = f"open({str(marker)!r}, 'a').write('ran')\n"
    (tmp_path / "yaml.py").write_text(plant)
    (tmp_path / "json.py").write_text(plant)
    (tmp_path / "securebuilderbot_core").mkdir()
    (tmp_path / "securebuilderbot_core" / "__init__.py").write_text(plant)
    (tmp_path / "securebuilderbot_core" / "__main__.py").write_text(plant)
    out = subprocess.run([str(ROOT / "core" / "run"), "profile", "show", "il4"], cwd=tmp_path, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert not marker.exists()


def test_the_launcher_leaves_the_users_own_python_alone(tmp_path):
    # The QA gate runs the user's suite as core's child: a safe-path setting inherited from the launcher
    # would take the working directory off the user's own python3 -m pytest (seen in CI: 3 failed).
    probe = tmp_path / "site"
    probe.mkdir()
    seen = tmp_path / "seen"
    (probe / "sitecustomize.py").write_text(f"import os\nopen({str(seen)!r}, 'w').write(os.environ.get('PYTHONSAFEPATH', 'unset'))\n")
    import os
    env = {**os.environ, "PYTHONPATH": str(probe)}
    env.pop("PYTHONSAFEPATH", None)
    out = subprocess.run([str(ROOT / "core" / "run"), "--version"], cwd=tmp_path, capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    assert seen.read_text() == "unset"
