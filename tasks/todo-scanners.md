# Tasks: scanners

- [x] T0 lint-changed: a moved shell file's old lines are not this change's (test, then the fix)
  - Verify: constraints suite, the two new cases
- [x] T1 Move: scripts, fixtures, suite, scan.sh, gate.py, test_gate.py; `GATE` exported; core's shim fallback gone; every caller updated; nightly-scan.sh deleted
  - Verify: pytest, the scan suite, gate-selftest, verify-controls 0 FAIL, CM-05/CM-10 red under mutation, check-docs
- [x] T2 Scope: scan-scope.sh; hadolint, image-plan, checkov, npm-audit, eslint anywhere; run-pip-audit.sh pinned; Makefile and scan.sh wired; dispatch routes pip-audit
  - Verify: Group 17 of the bash suite (SPEC criterion 1)
- [x] T3 Policy: policy.py, accepted risks, scope.py; the gate scans any checkout; CM-21..CM-25
  - Verify: SPEC criterion 2 and 4; test_gate.py
- [x] T4 Receipts: exit codes from scan.sh, findings counts, the eighth scanner
  - Verify: test_the_receipt_lists_eight_scanners_with_exit_codes_and_counts
- [x] T5 The scanners image and pins.md; linted with the hadolint image; never in the bot's own plan
  - Verify: hadolint clean under .hadolint.yaml; image-plan prints nothing for the bot
- [x] T6 SCAN_ENGINE_<TOOL>; dependency policy § 4A.1; CI installs scanners/requirements.txt; capability-map row
- [x] T7 Spec, plan, todo; the local run at il6 (SPEC criterion 3: 6/7 + pip-audit, grype refused by the sandbox proxy); make check-task, check-docs, mutate-controls green; handback
  - Verify: the handback's check-task summary, mutate-controls 15/15 proven
