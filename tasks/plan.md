# Plan: core

Implements `SPEC-core.md` on branch `epic/core`. Open questions settled with the spec's own
proposals (recorded in the spec): PyYAML 6 is the one dependency; a run id is
`<utc-timestamp>-<short-sha>`; run directories are git-ignored and only the gate-log row is
committed; the profile numbers are the PRD's table, and the High and Moderate control counts were
checked against NIST's published OSCAL baselines (370 and 287, catalog 5.2.0).

## Shape

- Package `core/securebuilderbot_core/`, run as `make core ARGS="…"` (PYTHONPATH=core python3 -m
  securebuilderbot_core). Tests in `core/tests/`, run by `make test`, measured by changed-line
  coverage at task end.
- Profiles are data (`core/profiles/*.yml`); the baselines they name are vendored from NIST OSCAL
  as `engine/security/controls/nist-800-53r5-baselines.json` with the builder beside the other
  index builders.
- Four engine scripts become Python and are deleted: classify-range.sh, scan-precondition.sh,
  gate-line.sh. Their callers (gate-prompt.sh, gate-proof.sh, the Makefile) call the Python, and
  their bash tests move to pytest. `scan-receipt.sh` stays: every scanner runner sources it, so it
  belongs to the scanners module (spec amended).
- The scan gate is a shim over the engine scanners until the scanners module replaces it.

## Order

1. Skeleton, pytest wiring, changed-line coverage check, CI install.
2. Profiles and baselines.
3. Config.
4. Classify (port + tests) and callers switched.
5. Gate protocol, verdict (scan line port + tests), receipt, gate log, runner.
6. Scan gate shim and the scan-precondition port.
7. Scanners: an empty JS scope reads as "nothing in scope", not "did not run".
8. Gate: `make gate-scan`, `make gate`, fix findings, PR.

## Risks

- The scanners' scope is still `backend/` and `frontend/`; on this repository most scanners have
  nothing in scope. That is honest and named in the verdict; generalising scope is the scanners
  module.
- Profile-specific scan fail-on and CVE freshness are data in core and applied by the scanners
  module; core's scan verdict keeps the engine's rule (fixable High/Critical or malware blocks).
