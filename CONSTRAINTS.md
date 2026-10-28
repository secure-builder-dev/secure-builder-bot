# Constraints

Last reviewed: 2026-10-14 by the maintainer

The quality bar for this repository, with numbers, checked mechanically. Agents read this before
writing code and never weaken it to make a change pass. Tightening is silent; loosening is loud:
`scripts/floor-guard.mjs` flags any lowered number, removed rule or new exception in the diff.

## Floor (always enforced, no setup required)

- No new suppression comments: `shellcheck disable`, `# noqa`, `# type: ignore`, `nosemgrep`, `gitleaks:allow`, `secrets-scan: allow`, `citations: allow`
- No unimplemented stubs: `TODO`, `FIXME`, `raise NotImplementedError`, an empty `catch`
- No skipped or deleted tests without a reason in the commit message: `_skip` in a bash suite, `pytest.mark.skip`, a deleted `*-test.sh`, an assertion removed from a test that stayed. The reason is a line `Test-removed: <path> — <reason>` in the commit that removes it
- No secrets in source
- No forbidden terms: the hashed denylist in `scripts/forbidden-terms.sha256`
- This file does not get weakened to make a change pass

Checked by `node scripts/floor-guard.mjs`, diff-scoped, at every edit. Exit 2 (could not run) is
never read as clean.

## Enforced with numbers

| Dimension | Rule | Checked by | Runs at |
|-----------|------|-----------|---------|
| Shell lint | Zero shellcheck findings on lines a change adds, any level | `scripts/lint-changed.sh` (shellcheck 0.10, `.shellcheckrc`) | every edit |
| Python lint | Zero ruff findings on lines a change adds | `scripts/lint-changed.sh` (ruff, `ruff.toml`: E F W B S UP) | every edit |
| Secrets | Zero gitleaks findings, reported redacted | `gitleaks detect --redact --no-banner` | every edit |
| Forbidden terms | Zero hits anywhere in the tree | `scripts/forbidden-terms.sh --all` | every edit |
| Self-tests | Every suite green, the constraint checks' own suite included | `make check-code`, `make gate-selftest`, `scripts/tests/constraints-test.sh` | task end, CI |
| Shell tests | Every new `.sh` under `engine/scripts/` or `scripts/` has a test that names it | `scripts/ratchet.sh` (the count below may not grow) | task end, CI |
| Python coverage | Changed lines ≥ 80% covered in every module's Python package (`*/securebuilderbot_*/`) | `make test` (pytest-cov writes lcov) + `scripts/coverage-changed.py --min 80` | task end, CI |
| Security: code | No high finding | `semgrep scan --config p/default --config p/bash --config p/python` | CI only (registry unreachable from some machines) |
| Security: deps | Nothing at high or above, once a manifest exists | `osv-scanner -r .` | CI only (osv.dev unreachable from some machines) |
| Architecture | Only the edges in `.boundaries` between script groups | `scripts/check-boundaries.sh` | task end, CI |

Why these numbers: zero on added lines is the number an agent can move, so it is held at zero. The
repo-wide totals were inherited and are ratchets below. 80% changed-line coverage is high enough to
force a test and low enough to allow a config line. "High or above" for the scanners is where the
signal stops being noise.

## Measured, not yet enforced

Recorded by `scripts/ratchet.sh`; `--record` rewrites a number that improved. A number that gets
worse fails the check.

| Metric | Today | Direction |
|--------|-------|-----------|
| shellcheck findings, all levels | 151 | must not grow |
| shellcheck findings, error or warning | 13 | must not grow |
| ruff findings | 9 | must not grow |
| shell scripts without a named test | 6 | must not grow |

## Where each check runs

| Tier | Command | What runs | Budget |
|------|---------|-----------|--------|
| every edit | `make check-fast` | floor guard, lint on added lines, gitleaks, forbidden terms | seconds |
| task end | `make check-task` | check-fast, then `make check-code` (the self-tests included), the constraints suite, ratchet, boundaries | under 90 s |
| CI and pre-PR | `make check-full` | check-task, then semgrep, osv-scanner, the doc checks | minutes |

A failed check blocks: the agent fixes its own output before handing work back. The full scan
(`make gate-scan`) and the gate (`make gate`) are separate and run before every pull request.

## Exceptions

| ID | Rule | Path | Reason | Owner | Expires |
|----|------|------|--------|-------|---------|

An exception has an owner and expires within 90 days. A new row is a loud event in the diff.
