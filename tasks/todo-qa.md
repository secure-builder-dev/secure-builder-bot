# Tasks: qa

- [x] T1 Move the QA tooling out of `engine/` (git mv), every caller updated, all suites green
  - Verify: `make gate-selftest`, `make check-task`, `git ls-files engine/scripts/gate` holds none of the seven
- [x] T2 Proving tests in several directories (`CONTROL_TEST_DIR` lists each); `project.config.yaml` names both modules
  - Verify: mutate-controls-test.sh two-directory cases; `make verify-controls` 16 rows, 0 FAIL
- [x] T3 derive-controls: Python guard patterns, `--draft`
  - Verify: derive-controls-test.sh, 20 cases
- [x] T4 Adapters: protocol, Node (Jest, Vitest) against a fake npm, pytest with pytest-cov
  - Verify: test_adapters.py, 14 cases
- [x] T5 Changed-line coverage in the package; `scripts/coverage-changed.py` imports it
  - Verify: test_coverage.py; the constraints suite's coverage-changed cases
- [x] T6 The diff analyzers: skips, routes and negative tests, mocked database
  - Verify: test_checks.py
- [x] T7 The gate: five checks, receipt sections, status rules; the fixture project
  - Verify: test_gate.py, 12 cases (SPEC criterion 1)
- [x] T8 Dogfood: `gates: [scan, qa]`, the `scan and qa` CI job, `.constraintsignore` honoured
  - Verify: `core/run run --base origin/main` with `gates: [qa]`: QA PASS (SPEC criterion 4)
- [x] T9 Manifest rows CM-40..45 proven under mutation; spec, plan, todo, capability map, policy
  - Verify: `make mutate-controls`, `make check-task`, `make check-docs`
- Follow-ups, not this build: core could carry each gate's config section on `GateContext` ·
  the control tools read one manifest path (`qa.manifest` otherwise is `not_run`) · the cross-user
  rule is a text heuristic and a project may want to name its own test pattern · Go, Java and
  Kotlin adapters by contribution · the frontend mutation harness is still TypeScript-only ·
  `gate-prompt.sh`'s "controls touched" list still reads a web app's backend test directory only, not `CONTROL_TEST_DIR`
