"""Per-ecosystem test-runner adapters (PRD § Architecture: v1 is Node — Jest, Vitest — and Python — pytest).

An adapter knows how to detect its runner in a checkout, run the suite with an lcov coverage
reporter, and say where the lcov file landed. The gate treats every adapter the same way, so a
repository holding several apps runs each. A runner that cannot start (tool missing) reports an
`error`, which the gate turns into not_run: it is never a pass and never a failed suite.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from securebuilderbot_core.receipt import SECRET, redact

TIMEOUT_SECONDS = 3600
_COUNT_WORDS = ("passed", "failed", "skipped", "errors")
# The bot's own secrets and the CI platform's tokens, by name; and any name ending like a credential.
SECRET_NAMES = frozenset({
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "SECURE_BUILDER_TOKEN", "SB_MODEL_KEY", "CI_JOB_TOKEN",
    "CI_JOB_JWT", "CI_JOB_JWT_V1", "CI_JOB_JWT_V2", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
})
SECRET_SUFFIXES = ("_TOKEN", "_KEY", "_SECRET", "_PASSWORD")
# A value that carries a credential, whatever its name: a URL with a password in its userinfo
# (GitLab's CI_REPOSITORY_URL is https://gitlab-ci-token:<job token>@host/…), or one whose user is
# itself the token — a user name that only ever stands for one, or a token-shaped string.
TOKEN_USERS = ("gitlab-ci-token", "x-access-token", "x-token-auth", "oauth2", "oauth", "token")
URL_USERINFO = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://([^/\s@]+)@")
_TOKEN_SHAPED = re.compile(r"[A-Za-z0-9_-]{20,}")
# Names the gate withholds for the run in hand: the config's sentinel.key_secret, whatever it is called.
_withheld: ContextVar[frozenset[str]] = ContextVar("withheld", default=frozenset())


@dataclass(frozen=True)
class SuiteResult:
    runner: str                 # jest, vitest, pytest, command
    app: str                    # repo-relative app directory; "." for the repository root
    command: str
    passed: bool
    counts: dict[str, int] = field(default_factory=dict)  # passed, failed, skipped, errors, total
    log: Path | None = None     # evidence file under the run directory
    lcov: Path | None = None    # the lcov file this run wrote, if any
    lcov_root: str = "."        # repo-relative directory the lcov's SF: paths are relative to
    error: str = ""             # why the runner could not do its job; empty when it ran


class TestRunner(Protocol):
    runner: str
    app: str

    def detect(self, repo: Path) -> bool: ...

    def run(self, repo: Path, changed_files: Sequence[str]) -> SuiteResult: ...

    def coverage_lcov(self, repo: Path) -> Path: ...


def parse_counts(text: str) -> dict[str, int]:
    """Test counts from a runner's summary: Jest's `N passed, M total`, Vitest's `N passed | M failed (T)`, pytest's `N passed, M failed in`."""
    counts = {w: 0 for w in _COUNT_WORDS}
    for n, word in re.findall(r"(\d+)\s+(passed|failed|skipped|errors?|todo)\b", text):
        key = "errors" if word.startswith("error") else ("skipped" if word == "todo" else word)
        counts[key] = max(counts[key], int(n))
    m = re.search(r"(\d+)\s+total\b", text) or re.search(r"Tests\s+[^\n(]*\((\d+)\)", text)
    counts["total"] = int(m.group(1)) if m else sum(counts.values())
    return counts


@contextmanager
def withholding(names: Iterable[str]) -> Iterator[None]:
    """For the duration, user_env() also drops these names (the gate passes sentinel.key_secret)."""
    token = _withheld.set(_withheld.get() | frozenset(n.upper() for n in names if n))
    try:
        yield
    finally:
        _withheld.reset(token)


def carries_credential(value: str) -> bool:
    """A value holding a credential: core's secret pattern matches it, or it is a URL whose userinfo is one."""
    if SECRET.search(value):
        return True
    for userinfo in URL_USERINFO.findall(value):
        user, _, password = userinfo.partition(":")
        if password or user.lower() in TOKEN_USERS or _TOKEN_SHAPED.fullmatch(user):
            return True
    return False


def user_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment the user's own code is started with: this process's (or the given one), minus every secret.

    A pull request's tests are untrusted code and their output lands in the run directory CI
    uploads, so they are never started with the bot's secrets or the CI platform's tokens. Dropped
    by name: SECRET_NAMES, any name ending _TOKEN, _KEY, _SECRET or _PASSWORD in any case, and the
    names withholding() holds. Dropped by value: anything carries_credential() finds. PATH, HOME
    and the rest are kept, so the suite runs as it would anywhere else.

    What one process cannot promise: code running as the same user can still read this process's
    own environment from /proc/<pid>/environ. Only a job that holds no secret closes that.
    """
    source = os.environ if environ is None else environ
    withheld = _withheld.get()
    return {k: v for k, v in source.items()
            if k.upper() not in SECRET_NAMES and not k.upper().endswith(SECRET_SUFFIXES) and k.upper() not in withheld
            and not carries_credential(v)}


def keep_log(log: Path, output: str) -> str:
    """Write a tool's output as an evidence file, redacted with core's redact(); the redacted text is returned.

    The run directory is uploaded as a CI artifact, and the user's suite can print anything, so no
    secret-shaped string it printed is kept, the same rule core's scangate holds for scanner files.
    """
    cleaned, _ = redact(output)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(cleaned)
    return cleaned


def run_logged(argv: Sequence[str], cwd: Path, log: Path, *, shell: str | None = None) -> tuple[int, str, str]:
    """Run the user's command in user_env(), keep its output redacted as an evidence file; (exit code, redacted output, error). Exit 127 or a missing tool is an error."""
    log.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["bash", "-c", shell] if shell is not None else list(argv)
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, env=user_env())
        output, code = proc.stdout + proc.stderr, proc.returncode
    except FileNotFoundError:
        output, code = f"{cmd[0]}: not found on PATH\n", 127
    except subprocess.TimeoutExpired as e:
        output, code = f"{(e.stdout or b'')!s}{(e.stderr or b'')!s}\ntimed out after {TIMEOUT_SECONDS}s\n", 124
    output = keep_log(log, output)
    tool = shell.split()[0] if shell else cmd[0]
    error = ""
    if code == 127 or "command not found" in output:
        error = f"{tool} is not installed or not on PATH"
    elif code == 124:
        error = f"the suite ran past {TIMEOUT_SECONDS}s"
    return code, output, error


@dataclass
class CommandRunner:
    """The user's own `qa.test_command`, run once at the repository root. Coverage then comes from the detected adapters' lcov paths."""

    command: str
    log_dir: Path
    runner: str = "command"
    app: str = "."

    def detect(self, repo: Path) -> bool:
        return True

    def run(self, repo: Path, changed_files: Sequence[str]) -> SuiteResult:
        code, output, error = run_logged([], repo, self.log_dir / "suite-command.log", shell=self.command)
        counts = {w: 0 for w in (*_COUNT_WORDS, "total")} if error else parse_counts(output)
        return SuiteResult(runner=self.runner, app=self.app, command=self.command, passed=code == 0 and not error,
                           counts=counts, log=self.log_dir / "suite-command.log", lcov=None, error=error)

    def coverage_lcov(self, repo: Path) -> Path:
        return self.log_dir / "none.lcov"


def detect_runners(repo: Path, log_dir: Path) -> list[TestRunner]:
    """Every runner the checkout has: one Node runner per app with Jest or Vitest, pytest once at the root."""
    from .node import detect_node
    from .python import PytestRunner
    runners: list[TestRunner] = list(detect_node(repo, log_dir))
    py = PytestRunner(log_dir)
    if py.detect(repo):
        runners.append(py)
    return runners
