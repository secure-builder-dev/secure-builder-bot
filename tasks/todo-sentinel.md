# Tasks: sentinel

- [x] T1 The checklist as data: base, moderate and high YAML; `checklist.py`; every citation verified on load
  - Verify: test_checklist.py (the markdown twins, citations, items_for(il4), gaps(il6) = 339)
- [x] T2 Core config: `sentinel.endpoint`, `sentinel.model`, `sentinel.max_diff_bytes`, with line numbers
  - Verify: core/tests/test_config.py, the sentinel-keys cases
- [x] T3 The sanitizer: instruction-like lines removed and counted, the delimiter unforgeable, secrets redacted
  - Verify: test_sanitize.py
- [x] T4 The review request: the diff and the named files from the head, values files withheld, lockfiles as names and versions, the budget, QA's proof
  - Verify: test_inputs.py
- [x] T5 The answer schema: a fenced JSON block, validated by shape and against its request
  - Verify: test_schema.py
- [x] T6 The providers: Anthropic, OpenAI-compatible (self-hosted), the fake; the stdlib transport
  - Verify: test_providers.py (no network: a fake connection, a real one constructed and never opened)
- [x] T7 The review and the gate; `sentinel/` is gate tooling in core's classifier; the boundaries
  - Verify: test_review.py (SPEC criteria 2–5), core/tests/test_classify.py, check-boundaries
- [x] T8 The proof set: five cases, the replay, `make proofset` in `check-code`
  - Verify: `make proofset` 5/5; test_proofset.py, its negative cases included
- [x] T9 Dogfood: `.github/securebuilderbot-full.yml`, the `sentinel` job, `.securebuilderbot.yml` keeps scan and qa
  - Verify: test_dogfood.py; actionlint on scan.yml
- [x] T10 Manifest rows CM-50..CM-59; `CONTROL_*` keys; spec, plan, todo, capability map, policy
  - Verify: `make verify-controls` 0 FAIL; `make mutate-controls` every row proven; `make check-task`; `make check-docs`
- Follow-ups, not this build: core could carry the config path (or each gate's config section) on
  `GateContext`, retiring `SB_CONFIG` · the scan verdict on a light range (the PRD's "checklist and
  scan verdict") needs the scan gate's result on the context · a real-model replay of the proof set,
  run by a maintainer with a key before a release · `scripts/ratchet.sh` measures ruff over a fixed
  list of directories that does not include `sentinel` · the adapters could pass the PR title and
  body as `SB_PR_TITLE` / `SB_PR_BODY` (or `SB_PR_CONTEXT`), which the GitHub job here does itself
