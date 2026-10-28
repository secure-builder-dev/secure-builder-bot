# Plan: standards

Implements `SPEC-standards.md` on branch `wip/standards` (base `epic/core`). The module depends on
nothing: the standard library, the vendored indexes, and the builders that wrote them.

## Shape

- `standards/data/` is `engine/security/` moved with its history: the six JSON indexes, the guidance
  markdown, the profile checklists, the provider implementations, `FRAMEWORKS.md`.
- `standards/scripts/` holds the six index builders, `ingest-stig.py`, `refresh-frameworks.sh` (the
  manual, pin-respecting refresh) and `verify-citations.sh`, now a thin wrapper that lists the
  documents and hands them to the package.
- `standards/securebuilderbot_standards/`: `data.py` (the indexes as objects), `citations.py` (the
  verifier: one small decision per kind of citation, each a manifest row), `refresh.py` (the weekly
  refresh), `__main__.py` behind `standards/run`.
- Tests under `standards/tests/`: pytest for the package, `standards-selftest.sh` for the scripts
  (the seven sections that lived in the engine's self-test), offline fixtures generated from the
  vendored indexes by `fixtures/make-upstream.py`.
- Core's receipt gains `"standards": versions()` through one guarded import in `runner.py`.

## Order

1. Move everything out of `engine/` with `git mv`; every caller follows; all suites green before
   anything else changes. The boundaries edge and the gate agent's path each in their own commit.
2. The read API and the verifier as a function, red test first.
3. The command line and the wrapper; the receipt hook.
4. The refresh with offline fixtures; the weekly workflow.
5. Manifest rows, spec, plan, capability-map row; `make check-task`, `make check-docs`,
   `make mutate-controls` green.

## Risks

- The shell verifier's id pattern never judged an enhancement followed by punctuation; the port
  does, and the vendored documents had eleven wrong citations. Fixed in the documents, not hidden.
- Offline fixtures cannot carry the STIG redistribution or NIST's publication tree (git checkouts);
  those two sources are exercised from temporary repositories in the tests.
- The mutation tools read one test directory; a standards row names its test relative to
  `core/tests`.
