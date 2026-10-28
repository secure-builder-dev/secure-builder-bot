# Plan: scanners

Implements `SPEC-scanners.md` on branch `wip/scanners` (base `epic/core`), in the order the module
brief gave, one commit per task, red test first.

## Shape

- Package `scanners/securebuilderbot_scanners/` exporting `GATE`; runners under
  `scanners/scripts/`; the bash suite stays bash under `scanners/tests/` beside the pytest file.
- One discovery helper for every runner (`scan-scope.sh`) and its Python mirror (`scope.py`), so
  the runners' scope and the gate's expectation are the same set.
- The policy is data from the profile (core) applied in `policy.py`; the manifest rows are the
  functions that decide (CM-21..CM-25).

## Order

1. Move everything out of `engine/scripts/scan/` and `core/` with `git mv`; every caller updated;
   every suite green before anything else changes. (A `lint-changed.sh` fix landed first: a
   `git mv` was read as a wholly added file.)
2. The whole-checkout scope, runner by runner, and the pip-audit runner with its pin.
3. The profile's policy in the gate; accepted risks; the gate scans any checkout.
4. Receipts: exit codes, counts, the eighth scanner (with 3).
5. The scanners image and `pins.md`.
6. Spec, plan, manifest rows, boundaries, dependency policy, CI install lines; the local run.

## Risks

- Grype cannot reach its database through this sandbox's proxy, so the bot's own scan here is
  7/8 at best; CI runs all eight. Said in the spec and the handback, not worked around.
- Core's verdict line counts seven; the gate counts eight. A core follow-up closes the gap.
