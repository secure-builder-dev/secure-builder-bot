# Plan: qa

Implements `SPEC-qa.md` on branch `wip/qa`, from `epic/core`. The brief's order, kept: move the
tooling first so every suite is green before anything new exists; then the adapters, the pure
analyzers, the gate; dogfood; then the manifest rows and the records.

## Shape

- Package `qa/securebuilderbot_qa/`, found by core by name; tests in `qa/tests/`, measured by the
  changed-line coverage check (il6's 90 aimed for).
- The control tools move with `git mv` and keep their fixture tests; the gate wraps them and reads
  their output, never re-deciding what they decide.
- Every check is a pure function over what the range added (`diff.py`), so it is tested without a
  runner; the gate test runs the real runner and the real tools on a fixture project.

## Order

1. Move the QA tooling out of `engine/`; every caller follows; all suites green.
2. Proving tests in several directories (one per module), so the qa rows can be verified and mutated.
3. `derive-controls`: Python guard patterns and `--draft`.
4. Adapters: the protocol, Node (fake npm), pytest.
5. Changed-line coverage in the package; the script imports it.
6. The three diff analyzers.
7. The gate, on the fixture project.
8. Dogfood: `gates: [scan, qa]`, the CI job, the run on this repository.
9. Manifest rows CM-40..45 under mutation; spec, plan, todo, capability map, boundaries, policy.

## Risks

- The negative-test and mocked-database rules are text heuristics; they err toward a finding
  (a loud false refusal) rather than a silent pass, and `.constraintsignore` names the files that
  carry the patterns as data.
- `qa.manifest` other than `docs/security/CONTROL-MANIFEST.md` is `not_run`: the control tools read
  one path. Widening them is a follow-up.
- Locally the scan cannot pass in this sandbox, so the full `[scan, qa]` verdict is CI's.
