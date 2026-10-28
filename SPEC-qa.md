# Spec: qa

Module `qa` of the capability map. Status: built on `wip/qa`; the decisions below were taken
during the build and are confirmed by the human who merges it.

## Objective

`qa` is the second gate: do the tests prove the code, including the security controls? It runs
the five mechanical checks of PRD § The QA gate on the range core hands it, each a section of
the receipt with its evidence file, and it owns the control tools the engine shipped under
`engine/scripts/gate/` (derive, verify, mutate; the frontend mutation harness; the query-bounds
check) and their fixture tests. One adapter per test runner knows how to run a suite with an lcov
reporter; v1 is Node (Jest, Vitest) and Python (pytest). Sentinel will believe the manifest only
because this gate proved every row breaks a test.

User stories, from the PRD:

- As a team lead on Standard (Scan and QA), my pull request gets `Secure Builder / QA` with the
  one line that says why it failed, at the line it concerns.
- As an assessor, the receipt's QA section shows each check's result and the mutation table:
  control id, test file, red or green.
- As a user on first run, the gate drafts the control manifest from the guard-shaped functions it
  finds and asks me to confirm the rows, then refuses to run when a new one appears with no row.

Success looks like: `core/run run --base origin/main` on this repository with `gates: [scan, qa]`
runs the real pytest suite with coverage, the changed-line check at il6's 90, and the mutation of
every manifest row, and QA passes.

## Tech Stack

- Python 3.12, standard library only; core's PyYAML through core's config reader (no new dependency)
- Bash 5 for the control tools moved from the engine (`qa/scripts/`), unchanged in what they decide
- pytest and pytest-cov for this module's own tests and for the pytest adapter's lcov
- Tooling as `CONSTRAINTS.md` names it: ruff, shellcheck, gitleaks, the floor guard

## Commands

```
The gate, through core:   core/run run --base origin/main --head HEAD   (gates: [scan, qa] in .securebuilderbot.yml)
Control tools:            make verify-controls · make derive-controls · make mutate-controls ARGS="--since <rev>" · ARGS="--dry-run"
Draft a manifest:         bash qa/scripts/derive-controls.sh --draft docs/security/CONTROL-MANIFEST.draft.md
Frontend mutation:        make mutate-frontend · make check-frontend-mutations
Query bounds:             make query-bounds
Tests:                    make test   (pytest over every module; coverage to gate-records/state/core.lcov)
                          bash qa/tests/<name>-test.sh   (the control tools' fixture tests; make gate-selftest runs them all)
Changed-line coverage:    python3 scripts/coverage-changed.py --min 90
Every edit:               make check-fast
Task done:                make check-task
```

## Project Structure

```
qa/
  __init__.py                 → makes qa.tests a distinct package from core/tests when pytest runs both from the root
  securebuilderbot_qa/
    __init__.py               → GATE, the factory core looks up by name (runner.py:discover_gate)
    gate.py                   → QaGate: the five checks in order; receipt sections; status rules
    adapters/
      __init__.py             → TestRunner protocol, SuiteResult, parse_counts, run_logged, CommandRunner, detect_runners
      node.py                 → Jest and Vitest from package.json; npm test -- --coverage with the runner's lcov flag
      python.py               → pytest from pytest.ini / pyproject.toml / conftest.py / tests/; pytest-cov lcov into the run dir
    diff.py                   → changed files, added lines (a range, or the working tree), commits touching a path
    coverage_changed.py       → lcov → repo-relative hits; changed-line coverage; meets(threshold); test-path rule
    checks.py                 → added skips; routes added and their negative tests; a mocked database on an integration path
    controls.py               → runs derive/verify/mutate; parses their output (declared mode always mutates --since the base)
  scripts/                    → moved from engine/scripts/gate/ with history (git mv)
    _lib.sh  mutate-controls.sh  verify-controls.sh  derive-controls.sh  mutate-frontend.py
    check-frontend-mutations.sh  query-bounds.sh
  tests/
    conftest.py               → a real throwaway git repo; a fake npm on PATH
    test_adapters.py  test_coverage.py  test_checks.py  test_controls.py  test_gate.py
    fixtures/pyapp/           → the fixture Python project: a ten-line fake framework, require_user, require_owner,
                                 a route table of plain decorated functions, pytest tests, a manifest, project.config.yaml
    mutate-controls-test.sh  derive-controls-test.sh  verify-controls-test.sh  mutate-frontend-test.sh
    check-frontend-mutations-test.sh  query-bounds-test.sh
```

Moved from `engine/`: `scripts/gate/{mutate-controls,verify-controls,derive-controls,_lib}.sh`,
`mutate-frontend.py`, `check-frontend-mutations.sh`, `query-bounds.sh` → `qa/scripts/`;
`scripts/tests/{mutate-controls,derive-controls,mutate-frontend,check-frontend-mutations,query-bounds}-test.sh`
→ `qa/tests/`; the verify-controls section of `engine/scripts/gate/selftest.sh` →
`qa/tests/verify-controls-test.sh`. `repo-state.sh`, `legacy-inventory.sh`, `generate-truth.sh`
and `gate-proof.sh` stay in the engine and call into `qa/scripts/`.

## Interface: what core sees

`securebuilderbot_qa.GATE()` returns a `QaGate` with `name = "qa"` and `run(ctx) -> GateResult`
(the protocol in `SPEC-core.md`). The receipt section it returns:

```
checks:
  suite:           result, evidence, runners[{runner, app, command, passed, counts, log, error}], skips_added, errors
  coverage:        result, evidence, minimum, covered, executable, percent, lcov[]
  negative_tests:  result, evidence, routes, without_negative_test
  mocked_db:       result, evidence, sites
  mutation:        result, evidence, manifest, unregistered_guards, verify_failed, manifest_draft, derive, verify,
                   mutation (log, or why it was skipped), scope, rows, not_proven
mutation_table:    [{id, control, mutation, suite, verdict}]   — mutate-controls' table, every row
controls_assessed: ["SA-11", "SA-11(1)"] when the suite and the mutation both ran; [] otherwise
```

Findings carry `rule_id` `suite`, `skip`, `coverage`, `AC-3`, `mocked-db`, `unregistered-control`,
`verify-controls` or `SA-11`, the path and line where there is one, and the evidence file under
`qa/` in the run directory. Status: `fail` on any blocking finding; `yellow` when `qa.mutation:
false` and the profile requires mutation; `not_run` when no runner was detected, a runner could not
start, the suite wrote no lcov while production lines were added, `qa.manifest` names a path the
control tools do not read, or mutate-controls could not run; otherwise `pass`.

## Interface: the adapters

```python
class TestRunner(Protocol):
    runner: str; app: str
    def detect(self, repo: Path) -> bool: ...
    def run(self, repo: Path, changed_files: Sequence[str]) -> SuiteResult: ...   # passed, counts, log, lcov, lcov_root, error
    def coverage_lcov(self, repo: Path) -> Path: ...
```

`detect_runners(repo, log_dir)` returns one `NodeRunner` per `package.json` whose test script or
dev dependencies name Jest or Vitest (the script's word wins), plus `PytestRunner` when a marker
exists at the root. With `qa.test_command` other than `auto`, `CommandRunner` runs it once at the
root and coverage is read from the adapters' lcov paths or `coverage.lcov`, `coverage/lcov.info`,
`lcov.info` at the root.

## The five checks

1. **Suite green, no skip added.** Every runner's suite, with an lcov reporter. A red suite is a
   blocking `suite` finding. Lines the range added to test files that match the floor guard's
   skip patterns (`it.skip(`, `.only(`, `.todo(`, `xit(`, `fit(`, `@pytest.mark.skip/xfail`,
   `pytest.skip(`, `t.Skip(`) are blocking `skip` findings at their line unless a commit in the
   range touching the file names a ticket (`T-ABC-01`, `T-123`, `ABC-42`, `#123`) or the file is
   on `.constraintsignore`.
2. **Coverage on changed lines** ≥ `profile.qa.coverage_changed_lines`, over the lines the range
   added to production files (`.py .js .jsx .ts .tsx .mjs .cjs`, never a test path), against every
   adapter's lcov merged into one repo-relative map. A file no lcov mentions counts as uncovered.
3. **Negative tests for changed routes.** Route definitions on added lines (Express/Koa/Fastify
   `x.get('/p')`, FastAPI/Flask `@x.get('/p')` and `@x.route('/p')`, Django `path('p/')`,
   `@route('/p')`). Each needs a test *case* (a `def test_…` or `it(`/`test(` block) that references
   the route's path — a parameter matches any one segment — and asserts 401 or 403; a route with an
   id parameter also needs a case whose text names a cross-user denial (`user B`, `another user`,
   `not the owner`, …). Each gap is a blocking `AC-3` finding at the route's line.
4. **No mocked database on an integration path.** `jest.mock(` / `vi.mock(` / `mock.patch(` /
   `@patch(` of a module named like `db|database|prisma|knex|pg|sequelize|mongoose|sqlalchemy|
   typeorm|drizzle|mongo`, on an added line of a test under an inner `integration/`, `e2e/`, `api/`
   or `acceptance/` directory or a test that imports the app's server. `.constraintsignore` applies.
5. **Mutation of controls.** `derive-controls --list --draft <run>/qa/manifest-draft.md` (an
   UNREGISTERED guard is a blocking `unregistered-control` finding at its line; the draft is the
   evidence), then `verify-controls` (a FAIL row blocks), then `mutate-controls` — `--since <base>`
   when the manifest is byte-identical across the range, the full run when it changed — whose table
   is the receipt's `mutation_table`; every NOT PROVEN, manual or unlocatable row is a blocking
   `SA-11` finding. `qa.mutation: false` skips the mutation (not derive or verify) and is `yellow`
   when the profile requires it.

## Testing Strategy

- pytest under `qa/tests/`, one file per module; every case builds a real throwaway git repository;
  the node adapter runs against a fake `npm` on PATH that writes an lcov file; the gate runs the
  real pytest and the real control tools on the fixture project. No mocks of git or the filesystem.
- The control tools keep their fixture-backed bash tests, moved with them; `derive-controls-test.sh`
  gained the Python guard and draft cases, `mutate-controls-test.sh` the two-directory cases.
- Changed-line coverage of this module's Python: 93.9% at the last `scripts/coverage-changed.py
  --base epic/core --min 90`.

## Boundaries

- **Always:** red test first; `make check-fast` before every commit; the scripts' own semantics
  do not change (the gate wraps them); `not_run` whenever the gate could not do its job; every
  string the gate returns is plain text and never a secret-shaped value.
- **Ask first:** a new dependency; changing `GateResult` or `GateContext`; a `qa.*` config key;
  widening the control tools' manifest path.
- **Never:** a network call; writing to the user's branch; naming the platform the engine came
  from; a suppression comment; pushing.

## Success Criteria

1. **The fixture project through the gate** — `qa/tests/test_gate.py`: a green suite passes with
   every check `pass`, the mutation table proven and `SA-11`, `SA-11(1)` assessed; a route added
   without a 401/403 test fails with `AC-3` at `app/routes.py:13`; a `jest.mock('./db')` fixture
   in `api/test/integration/` fails with `mocked-db` at its line; a skip added in the range fails at
   `tests/check_routes.py:20` and passes once a commit names `T-QA-99`; three of four added lines
   covered fails at il6 (90) and passes at `none` (60); a manifest row that survives mutation fails
   with `SA-11` and the table shows `✗ NOT PROVEN`. Verified: 12 cases pass.
2. **The node adapter against a fake npm** — `qa/tests/test_adapters.py`: detection from
   `package.json` covers Jest and Vitest (and skips `node_modules`), the command carries the
   runner's lcov flag, the lcov file is found, a red run is not passed, a missing npm is an error.
   Verified: 14 cases pass.
3. **`derive-controls.sh --draft`** — `qa/tests/derive-controls-test.sh`: on a Python fixture it
   finds `HTTPException(status_code=403`, `abort(401)`, `PermissionDenied` and `Response(status=401)`
   guards, and the draft names each guard's function and the test file that mentions it (or says
   none does), numbered after the manifest's last id. Verified: 20 cases pass; `test_gate.py`
   also reads the draft the gate writes.
4. **This repository with `gates: [scan, qa]`** — `core/run run --base origin/main` at HEAD
   `08f8671` with a `gates: [qa]` config: QA PASS, 218 tests, 90.8% of the added production
   lines covered at il6's 90, every one of the 10 manifest rows proven in the receipt's mutation
   table, `controls_assessed` `["SA-11", "SA-11(1)"]` (run `20261023T142458Z-08f8671`). With the
   real config the run stops at Scan in this sandbox (ClamAV, Grype and Trivy cannot reach their
   databases here; run `20261023T142321Z-08f8671`) and QA is `not_run` behind it, as it should be;
   the `scan and qa` job in `.github/workflows/scan.yml` is where the full verdict is real.
5. **The move** — `engine/scripts/gate/` holds none of the seven moved scripts and
   `engine/scripts/tests/` none of the five moved tests (`git ls-files` shows them under `qa/`);
   `make check-task`, `make check-docs`, `make gate-selftest` and `make mutate-controls` green at
   the last commit (the exact lines are in the handback).

## Decisions taken during the build

- **The gate reads `.securebuilderbot.yml` itself** for `qa.test_command`, `qa.manifest` and
  `qa.mutation`: `GateContext` carries the profile, not the config, and changing it is core's call.
  A follow-up for core: a per-gate config section on the context.
- **Always `--since` the base** (2026-10-28, replacing "`--since` only when the manifest is
  unchanged"). mutate-controls compares each row's line with the list at the base, so a row added
  or edited in the range is re-proven with its implementation and proving-test changes; a harness
  change (`CONTROL_HARNESS_RE`) still re-proves every row, and the rows carried over say so in the
  table. The old rule re-proved every row on any edit to the list, which took this repository's own
  QA past an hour; the whole table, as criterion 4 recorded it, is `make mutate-controls`.
- **Several test directories.** `CONTROL_TEST_DIR` lists one per module, space-separated;
  `verify-controls` and `mutate-controls` look in each (`qa/scripts/_lib.sh:gate_test_files`).
  `project.config.yaml` now names both modules' packages and test directories, and its harness
  pattern covers each module's conftest and the file itself.
- **Per-case route matching.** A route reference and the assertion about it must sit in the same
  test case; file-level matching let any 403 in a file satisfy every route it named.
- **`.constraintsignore` applies to the skip and mocked-database checks.** A test that carries the
  patterns as data (the constraints suite, `test_checks.py`) is the floor guard's own false positive,
  answered with the same list.
- **A decorator-registered handler has no call site** to `verify-controls`, by its rules; the
  fixture names its controls as `require_*` functions the handler calls, which is the PRD's shape.
- **`qa/__init__.py`** exists so pytest imports `qa.tests` and `core`'s `tests` as different packages.
- **The lint on moved files.** `lint-changed` reads a rename as added lines, so the moved scripts
  and tests were made shellcheck- and ruff-clean on every line rather than exempted; the ratchet's
  ruff count fell from 16 to 13.

## Changes outside qa this build needed

- `Makefile`: `QA_SCRIPTS`/`QA_TESTS`, the six targets repointed, the selftest list.
- `.boundaries`: the `qa` group's edges; `scripts/check-boundaries.sh` lists the group.
- `scripts/ratchet.sh` counts `qa/scripts` and looks in `qa/tests`; `scripts/coverage-changed.py`
  imports the package and measures every module that has a package and a tests directory;
  `scripts/tests/constraints-test.sh` copies the package beside the script in its fixture.
- `core/securebuilderbot_core/classify.py`: `qa/` is gate tooling.
- `engine/scripts/gate-prompt.sh`: the mutator and tooling classes name `qa/scripts/`;
  `engine/scripts/gate/{repo-state,legacy-inventory,gate-proof,selftest,selftest-phase1}.sh`,
  `engine/scripts/docs/generate-truth.sh`, `engine/scripts/tests/gate-proof-test.sh` call into `qa/`.
- `.doc-paths-retired`, `docs/security/CONTROL-MANIFEST.md` (header and six rows),
  `docs/security/FRONTEND-MUTATIONS.md`, `engine/TRUTH.md`, `gate-records/gate-permanent-checks.md`
  and its template: the new paths.
- `project.config.yaml`: `CONTROL_SRC_ROOTS`, `CONTROL_TEST_DIR`, `CONTROL_HARNESS_RE` (values,
  not only comments: the qa rows cannot be verified or mutated otherwise).
- `.securebuilderbot.yml`: `gates: [scan, qa]`; `.github/workflows/scan.yml`: job `scan and qa`,
  dev requirements installed; `.constraintsignore`: the two files that carry every pattern.
- `gate-records/gate-log.md`: three rows from the dogfood runs.
