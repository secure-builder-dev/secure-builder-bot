"""The environment the scanners run in: the gate's own, minus every secret (gate run 2, B-8).

The scanners execute code from the pull request. run-pip-audit.sh has pip resolve the checkout's
requirements, so a local-path requirement's setup.py runs; run-eslint.sh loads the checkout's
eslint config, which is JavaScript. Started with the gate's environment, that code held the bot's
own secrets and the CI platform's tokens: the reviewer's probe wrote GITHUB_TOKEN to a file.

Dropped by name: SECRET_NAMES, any CI_JOB_JWT*, any name ending _TOKEN, _KEY, _SECRET or
_PASSWORD, and the name the config gives as sentinel.key_secret, in any case. Dropped by value: anything core's secret pattern matches, and a URL whose
userinfo carries a credential (GitLab's CI_REPOSITORY_URL is https://gitlab-ci-token:<job token>@…).
npm_config_* variables are dropped too: npm reads them as config, and the audit's config is the
bot's alone (run-npm-audit.sh). Everything else is kept — PATH, HOME, the proxy and CA settings —
because the scanners need the network and their own tools.

KEEP IN STEP: the QA gate applies the same rule to the test suites it runs (its adapters package's
user_env and carries_credential, control rows CM-46 and CM-47). The two must drop the same names and
values; this module may not import the QA module (.boundaries allows this module to reach core
only), so the rule is written twice and a change to one is a change to both.

What this cannot promise: code running as the same user can still read the gate process's own
environment from /proc/<ppid>/environ, and PR code still runs inside the scan. Only a job that
holds no secret, or a scanner that builds nothing, closes those.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping

from securebuilderbot_core.receipt import SECRET

SECRET_NAMES = frozenset({
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "SECURE_BUILDER_TOKEN", "SB_MODEL_KEY", "CI_JOB_TOKEN",
    "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "DOCKER_AUTH_CONFIG",
})
SECRET_PREFIXES = ("CI_JOB_JWT",)
SECRET_SUFFIXES = ("_TOKEN", "_KEY", "_SECRET", "_PASSWORD")
# A user name that only ever stands for a token, or a token-shaped user name, is a credential too.
TOKEN_USERS = ("gitlab-ci-token", "x-access-token", "x-token-auth", "oauth2", "oauth", "token")
URL_USERINFO = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://([^/\s@]+)@")
_TOKEN_SHAPED = re.compile(r"[A-Za-z0-9_-]{20,}")


def secret_name(name: str) -> bool:
    n = name.upper()
    return n in SECRET_NAMES or n.startswith(SECRET_PREFIXES) or n.endswith(SECRET_SUFFIXES)


def npm_config(name: str) -> bool:
    """npm reads any npm_config_* variable, in any case, as config: none reaches a scanner (gate run 3, N-01)."""
    return name.lower().startswith("npm_config_")


def carries_credential(value: str) -> bool:
    """A value holding a credential: core's secret pattern matches it, or it is a URL whose userinfo is one."""
    if SECRET.search(value):
        return True
    for userinfo in URL_USERINFO.findall(value):
        user, _, password = userinfo.partition(":")
        if password or user.lower() in TOKEN_USERS or _TOKEN_SHAPED.fullmatch(user):
            return True
    return False


def scanner_env(environ: Mapping[str, str] | None = None, withhold: Iterable[str] = ()) -> dict[str, str]:
    """This process's environment (or the given one) with every secret dropped, by name and by value.

    `withhold` adds names to drop, in any case: the Scan gate passes the config's sentinel.key_secret,
    the CI secret holding the model key, which may be called anything (gate run 3, N-02; the QA gate
    does the same with its withholding()).
    """
    source = os.environ if environ is None else environ
    held = frozenset(n.upper() for n in withhold if n)
    return {k: v for k, v in source.items()
            if k.upper() not in held and not secret_name(k) and not npm_config(k) and not carries_credential(v)}
