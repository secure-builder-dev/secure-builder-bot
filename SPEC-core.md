# Spec: core

Module `core` of the capability map. Status: built on `epic/core`; the open questions below were decided during the build and are
confirmed by the human who merges it.

## Objective

`core` is what every other module stands on: it reads the one config file, resolves a profile
into concrete thresholds, runs the enabled gates in order and stops at the first red, decides
whether a change is light or deep, and writes the three outputs the PRD promises (a receipt an
assessor can read, a verdict a CI adapter can publish, a gate-log row the repo keeps). It knows no
platform and calls no network. The scanners, QA and Sentinel modules plug into one interface it
defines; the GitHub and GitLab adapters and the CLI call one entry point it exposes.

User stories, from the PRD:

- As a team lead, I write three lines in `.securebuilderbot.yml` and every enabled gate runs on
  my next pull request with the right thresholds for my impact level.
- As an assessor, I open one receipt per run and see what was checked, against which version of
  which standard, what was found, and what the tool did not assess.
- As a CI adapter, I get a machine-readable verdict per gate and one overall, and never have to
  parse prose.

Success looks like: `core/run run` on this repository, with `profile: il6` and
`gates: [scan]`, produces a receipt, a verdict and a gate-log row, and a bad config fails fast
with a line number.

## Tech Stack

- Python 3.12, standard library plus PyYAML 6 (the one dependency; see Open Questions)
- Bash 5 for the thin orchestration shims that call the migrated engine scripts until each is ported
- No framework, no network client, no database. State is files under `gate-records/`
- Tooling as `CONSTRAINTS.md` names it: ruff, shellcheck, pytest with pytest-cov, gitleaks

## Commands

```
Run the gates:      core/run run --base origin/main --head HEAD [--config .securebuilderbot.yml]
Validate config:    core/run config check [--config .securebuilderbot.yml]
Show a profile:     core/run profile show il6
Classify a range:   core/run classify --base origin/main --head HEAD [--why]
Scan verdict:       core/run scan-verdict [--results DIR] [--stamp]
Scan precondition:  core/run scan-precondition [--results DIR]
Through make:       make core ARGS="profile show il6"
Tests:              make test   (pytest core/tests with coverage to gate-records/state/core.lcov)
Lint:               ruff check core && shellcheck core/shims/*.sh
Every edit:         make check-fast
Task done:          make check-task
Before a PR:        make check-full
```

## Project Structure

```
core/
  securebuilderbot_core/
    __init__.py
    __main__.py        → the entry point behind `core/run` (argparse; the TS cli wraps this)
    config.py          → load and validate .securebuilderbot.yml; defaults from the profile
    profiles.py        → the none / il4 / il6 tables and `custom` merging
    gate.py            → the Gate protocol and GateResult (the interface other modules implement)
    runner.py          → order, stop on first red, timing, the run directory
    classify.py        → light or deep, by the paths a range touches (port of classify-range.sh)
    receipt.py         → receipt.json and receipt.md writers
    verdict.py         → verdict.json plus the one-line-per-gate block
    gatelog.py         → append a row to gate-records/gate-log.md; never blocks
    scangate.py        → the Scan gate: runs the shim, applies the verdict, writes its receipt
    precondition.py    → "the scan is green on this commit" (port of scan-precondition.sh)
  profiles/
    none.yml  il4.yml  il6.yml
  shims/
    scan.sh            → calls engine/scripts/scan/* until the scanners module replaces it
  tests/
    test_config.py  test_profiles.py  test_runner.py  test_classify.py  test_receipt.py
    test_verdict.py  test_gatelog.py  fixtures/
  README.md
```

Migrates from `engine/`: `scripts/gate/classify-range.sh` → `classify.py`;
`scripts/scan/gate-line.sh` → `verdict.py`; `scan-receipt.sh` stays with the scanners module,
because the scanner runners source it;
`scripts/gate/scan-precondition.sh` → the runner's "scan is green on this commit" check;
`templates/gate-records/` → the gate-log template. Each move is one task, with the engine's
self-test for that script ported alongside it, and the engine file deleted in the same commit.

## Interface: the Gate protocol

Every gate module (scanners, qa, sentinel) implements this and nothing else of core's internals.

```python
@dataclass(frozen=True)
class GateContext:
    repo: Path        # checkout root
    base: str         # git ref
    head: str         # git ref
    profile: Profile  # resolved thresholds, never the raw config
    depth: Literal["light", "deep"]
    run_dir: Path     # where this gate writes its files
    skip: tuple[str, ...] = ()  # parts of this gate the config turned off (scanner names for scan)


@dataclass(frozen=True)
class Finding:
    severity: Literal["blocking", "advisory"]
    rule_id: str          # control, STIG rule, CVE or scanner rule id
    message: str          # one sentence, what would fix it
    path: str | None = None
    line: int | None = None
    file: str | None = None  # evidence file under run_dir, if any


@dataclass(frozen=True)
class GateResult:
    gate: GateName
    status: Status
    reason: str = ""      # the one line that says why, when status is not pass
    findings: tuple[Finding, ...] = ()
    receipt: dict = field(default_factory=dict)  # this gate's section of the receipt


class Gate(Protocol):
    name: GateName

    def run(self, ctx: GateContext) -> GateResult: ...
```

`yellow` is a pass with an accepted risk applied or a profile-required check disabled. `not_run`
is a gate that was enabled but could not execute (tool missing, stale data past the profile's
limit, or a module not built yet: `not_built(name)`); the runner treats it as red, because a skip that reads as a pass is the failure the PRD
exists to prevent.

## Config and profiles

`.securebuilderbot.yml` is validated on every run: unknown key or bad value fails with the line
number. Three keys are required (`profile`, `gates`, `version`); everything else defaults from
the profile. Secret-shaped values are refused: a key named `*_key`, `*_secret` or `*_token` whose
value is not the name of a CI secret (letters, digits, underscores) fails validation.

Profiles are data files, not code. Each carries exactly the rows of the PRD's profile table:
baseline, STIG set, checklist blocks, scan fail-on, CVE-data staleness limit in days, coverage on
changed lines, whether mutation is required, accepted-risk expiry in days. `custom` is `il4` or
`il6` plus `add` and `remove` lists of control ids. A profile value disabled in the config
(`qa.mutation: off` at il4) is allowed, recorded, and surfaces as `yellow` on every run until
re-enabled.

## Runner

1. Load config, resolve profile, classify the range (`light` when no production code changed).
2. Create `gate-records/runs/<utc-timestamp>-<head-short-sha>/`.
3. For each enabled gate in the fixed order scan → qa → sentinel: build the context and call the
   gate's optional `prepare(ctx)`, all before any gate runs, so a gate can read the checkout before
   QA runs the pull request's code in it. Then, in the same order, call `run` with that context and
   write the gate's receipt section. Stop at the first `fail` or `not_run`.
4. Write `receipt.json`, `receipt.md`, `verdict.json`, the verdict block to stdout, and one row
   to `gate-records/gate-log.md`.
5. Exit 0 when every gate that ran passed or was yellow; 1 on any fail or not_run; 2 when the run
   itself could not start (bad config, not a git repo, no merge base). Exit 2 is never clean.

A docs-only range still runs `scan` (cheap) and skips the deep half of `sentinel`, as the PRD
says; which gates run is the config's call, how deep is the classifier's.

## Receipt

`receipt.json` is the contract; `receipt.md` is rendered from it. Top level: run id, timestamps,
base and head, profile name and the catalog version it resolves to, config file hash, depth, the
list of files sent to a model endpoint (empty unless sentinel ran), one section per gate as the
gate wrote it, controls in the baseline no gate assessed, accepted risks that applied with their
expiry dates. Nothing in a receipt is ever a secret value; the writer refuses a string that looks
like one (gitleaks rules, run in-process on the receipt before it is written).

## Code Style

Python: type hints everywhere, frozen dataclasses for data, no module-level state, no
`print` outside `__main__.py`, errors are exceptions with the path and line that caused them.

```python
def load_config(path: Path) -> Config:
    """Parse .securebuilderbot.yml. Unknown keys and bad values raise ConfigError with a line."""
    doc = _parse_yaml_with_lines(path)
    unknown = set(doc) - KNOWN_KEYS
    if unknown:
        key = sorted(unknown)[0]
        raise ConfigError(path, doc.line_of(key), f"unknown key {key!r}")
    gates = tuple(_gate(path, doc, g) for g in doc.get("gates", DEFAULT_GATES))
    return Config(profile=_profile(path, doc), gates=gates, version=_version(path, doc))
```

Bash shims: `set -uo pipefail`, every expansion quoted, arrays for lists, one job per script, the
WHY comment block at the top as the engine scripts have. Naming: `snake_case` in Python,
`kebab-case.sh` for scripts, `UPPER_SNAKE` for constants and environment variables.

## Testing Strategy

- pytest under `core/tests/`, one file per module, fixtures under `core/tests/fixtures/` (sample
  configs, a tiny git repo built in `tmp_path`, canned gate results). No mocking of the filesystem
  or git; tests run against real temporary repos.
- Coverage on changed lines ≥ 80% (`CONSTRAINTS.md`); the runner, config and receipt modules are
  the ones that fail loudly, so they are tested to their error paths: every `ConfigError` has a
  test that asserts the line number.
- A fake gate in the fixtures returns each of the four statuses so the runner's stop-on-red and
  exit codes are tested without a real scanner.
- Bash shims keep the engine's fixture-backed tests until the script they wrap is ported.
- `make check-task` must pass before a task is called done; it includes these tests once
  `pytest` is wired into `check-code` (first task).

## Boundaries

- **Always:** red test first, then green; `make check-fast` after every edit and `make check-task`
  before a task is done; every ConfigError carries a line number; receipts are written atomically
  (temp file, then rename); the engine file a task replaces is deleted in the same commit, with
  its self-test ported.
- **Ask first:** adding any dependency beyond PyYAML; changing a key name in
  `.securebuilderbot.yml` or a field in `GateResult` once another module uses it; changing a
  profile's numbers; editing `CONSTRAINTS.md`, `.boundaries` or a CI workflow; moving an engine
  script a module other than core owns.
- **Never:** a network call from core; reading `helm/values-*.yaml` or `*.tfvars`; writing a
  secret value anywhere; naming the platform the engine came from; a suppression comment to get
  past a check; pushing to `main`.

## Success Criteria

1. `core/run config check` on a file with an unknown key exits 2 and prints the key and its line number.
2. `core/run profile show il6` prints the High baseline's rows exactly as the PRD table has them; `il4` prints Moderate's; `none` prints no baseline.
3. `core/run classify` on a range touching only `docs/` says `light`; on a range touching `core/securebuilderbot_core/runner.py` says `deep`.
4. With a fake gate returning `fail`, `core/run run` exits 1, writes `verdict.json` with that gate failed and the later gates `not_run`, and appends one gate-log row.
5. With `gates: [scan]` and the scan shim, `core/run run` on this repository at HEAD produces `receipt.json`, `receipt.md` and `verdict.json`, and the receipt lists every scanner's version and database date.
6. A gate returning `not_run` makes the run exit 1 and the verdict say why; it never reads as a pass.
7. A config whose `sentinel.key_secret` value is not a CI-secret name is refused.
8. `make check-task` is green with core's tests included, and `pytest --cov` reports ≥ 80% on the lines this module added.
9. `engine/scripts/gate/classify-range.sh`, `engine/scripts/scan/gate-line.sh` and `scan-precondition.sh` no longer exist; their callers and self-tests run against the Python ports. `scan-receipt.sh` stays, owned by the scanners module, since every scanner runner sources it.
10. With `profile: il6`, a Grype or Trivy database older than 30 days, or one whose result file carries no date, fails the Scan gate with a `stale-data:<scanner>` finding; `profile: none` never judges age.

## Decisions taken during the build

- **PyYAML 6.0.2** is core's one runtime dependency, pinned in `core/requirements.txt`. Line
  numbers and duplicate-key detection come from its node API.
- **Run id** is `<utc-timestamp>-<head-short-sha>`, so a re-run on the same commit keeps both.
- **Receipt retention.** `gate-records/runs/` is gitignored. The CI workflow uploads it as an
  artifact; only the gate-log row is committed.
- **Profile numbers** are the PRD's table, checked against NIST SP 800-53 Rev 5 (catalog 5.2.0):
  Moderate has 287 controls and enhancements, High 370. `none` sets no CVE-data age limit,
  because the PRD names one only for il4 and il6.

## Changes outside core this epic needed

- The scanners scan the repository filesystem when it builds no image (Grype `dir:`, Trivy `fs`),
  so a repository without a Dockerfile is still scanned for vulnerable dependencies.
- npm-audit and ESLint report an empty scope, rather than a failure, when there is no npm app.
- Grype is pinned at v0.119.0. v0.87.0 still downloaded a database, built seven months earlier,
  because Anchore no longer publishes its schema; the age check above is what caught it.
- The control tools read Python. `verify-controls` and `mutate-controls` honour the `CONTROL_*`
  keys in `project.config.yaml`, which point them at `core/` and its pytest suite, and
  `docs/security/CONTROL-MANIFEST.md` names core's nine controls, each proven by mutation.
- Semgrep runs in `check-full` (its bash ruleset is `r/bash`; `p/bash` does not exist), and the
  three findings it raised in ported gate scripts are fixed.
- `.github/workflows/scan.yml` runs this repository's own Scan gate through `core/run run` at
  `profile: il6` on every push and pull request, and uploads the run directory.
