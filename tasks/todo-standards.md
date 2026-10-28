# Tasks: standards

- [x] T1 Move `engine/security/` and the nine scripts out of `engine/`; callers, classifier, ratchet, retired paths, the self-test sections; `gate.md` path rename in its own commit
  - Verify: `make verify-citations` 640 NIST + 27 OWASP + 33 of 84 STIG + 69 MASVS + 127 NIST-pub from the new location, as before the move; every suite green
- [x] T2 The Python API: `catalog`, `baseline`, `stigs`, `owasp`, `masvs`, `nist_pubs`, `versions`, `verify_citations`
  - Verify: SPEC criterion 2; the id pattern defect found by the spec's own example fixed and tested
- [x] T3 `standards/run` (`verify`, `versions`, `catalog`), `verify-citations.sh` as a wrapper; the eleven wrong enhancement citations corrected
  - Verify: the 55 self-test assertions pass against the wrapper; `--list-cited` and `--advisory` keep working
- [x] T4 Core's receipt carries `standards.catalog`
  - Verify: SPEC criterion 4
- [x] T5 The refresh: every upstream, `--dry-run`, `--offline DIR`, the changelog, the refusal (CM-31); the weekly workflow
  - Verify: SPEC criterion 3 against the three committed fixtures; the other upstreams against temporary repositories
- [x] T6 Manifest rows CM-30..36, `project.config.yaml` control roots, spec, plan, capability-map row
  - Verify: `make verify-controls`, `make mutate-controls` every row red; `make check-task`, `make check-docs` green
- Follow-ups, not this branch: `engine/SENTINEL-CHECKLIST.md` §86–90 still names `engine/security/checklists/` (a governance edit the lead makes) · `refresh-frameworks.sh` duplicates what `refresh.py` does without the `--adopt` pin semantics; retire it once the pin moves into the Python · the mutation tools' `CONTROL_TEST_DIR` is one directory · `receipt.md` does not render the `standards` section yet · the STIG index carries no severity, so `StigRule.severity` is None until the builder records it
