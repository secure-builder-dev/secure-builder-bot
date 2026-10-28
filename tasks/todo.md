# Tasks: core

- [x] T1 Skeleton: package, `__main__`, pytest config, `make core`, `make test` runs pytest, changed-line coverage script in check-task, CI installs requirements
  - Verify: `make test` runs an empty-but-real pytest suite; coverage script exits 0/1/2 as specified
- [x] T2 Profiles: none/il4/il6 data files, `custom`, baselines vendored from NIST OSCAL, `profile show`
  - Verify: SPEC criterion 2; baseline counts 287/370 asserted
- [x] T3 Config: load with line numbers, required keys, enums, secret-name rule, relaxations, `config check`
  - Verify: SPEC criteria 1 and 7
- [x] T4 Classify: Python port of classify-range.sh, `core/` is gate tooling, callers switched, bash test ported
  - Verify: SPEC criterion 3; the 16 ported cases
- [x] T5 Gate protocol, verdict, receipt, gate log, runner; scan verdict line ported with its fixture tests
  - Verify: SPEC criteria 4 and 6
- [x] T6 Scan gate shim with scanner versions and database dates; scan-precondition ported
  - Verify: SPEC criterion 5; the ported precondition cases
- [x] T7 Scanners: no npm app dir is an empty scope, a package.json without a lockfile still fails
  - Verify: scan-test-runner cases for both
- [ ] T8 Gate the range, fix findings, open the PR
  - [ ] F-01 (runs 1–2, blocking) The local scan ran 6/7: Grype's database hosts are refused by this
        sandbox's network policy. Passes when Grype runs locally (allow grype.anchore.io) or a human
        accepts the GitHub scan workflow's 7/7 as the scan of record for this range.
  - [x] F-02 (run 1) Secret-shaped text reached verdict.json and stdout — redacted at one point in the runner
  - [x] F-03 (run 1) No manifest rows for core's controls — nine rows, each proven by mutation; the control tools read Python
  - [x] B-01 (run 2) Scanner files in the uploaded run dir were not redacted — CM-10
  - Follow-ups, not this epic: N-03 derive-controls has no Python guard patterns · fail_on and
    medium_max_age_days are loaded but not enforced (run 1 N-03) · a profile downgrade in the PR's own
    config is not a relaxation (run 1 N-09) · actions pinned by tag, not SHA · PROOF-SET.md has no
    row for F-02 · FRONTEND-MUTATIONS.md holds template rows and there is no frontend/
  - Run 3 left non-blocking, as follow-ups: the YAML parser's own message and a secret-shaped key
    name can still be repeated in a ConfigError · redact_results skips files that are not UTF-8 ·
    the quoted-assignment secret shape never matches inside JSON · a redaction can leave a JSON
    report invalid (fails closed) · two triple-quoted strings on one line can open a block wrongly ·
    receipt.shown has no manifest row · floor-guard's fit( and .only( also refuse production code
    (fails closed) · an npm tree nested inside an app dir is not looked for · CONTROL_HARNESS_RE has
    no test of its own
