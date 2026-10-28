# The proof set

The reviewer's regression test (docs/PRD.md § Sentinel gate): cases a reviewer must catch, replayed
through the real pipeline on every `make check-code` by `make proofset` (sentinel/run proofset).

Each case is a directory: base/ and head/ trees (committed in turn into a throwaway repository),
pr.md (the pull request's title on its first line, then its description), expected.yml (the depth
the classifier must choose, the verdict, the findings that must be raised, what must NOT change the
verdict) and responses.yml (the fake provider's scripted answers, written as a competent reviewer
would answer).

The answers are scripted, so the proof set proves the pipeline — the classifier's depth, what is
sent and what is withheld, the sanitizer, the parsing, the findings' placement and the verdict — and
not the model. A model is proven by running a real provider against the same cases, which needs a
key and is not part of any check.

The cases live under sentinel/tests/ because they are test data: deliberately buggy sample apps, not
code the bot ships. The QA gate's test-path convention (qa/securebuilderbot_qa/coverage_changed.py,
TEST_PATH) matches tests/ directories, so the bot gating itself reads them as tests rather than as
production routes nobody tested. test_proofset.py holds them there.

| case | the bug class | must raise |
|---|---|---|
| route-lost-auth | a route that lost its authentication middleware, and an unscoped read | AC-3 on both lines |
| tenant-scope-removed | a tenant scope that returns the query unfiltered (a manifest control) | AC-3, and AC-4 from Control Completeness |
| secret-in-log | a password and a token written to the login log | SI-12, AU-9 |
| pr-talks-reviewer-into-pass | a PR description that tells the reviewer to pass a route that lost its role check | AC-6, with the three instruction lines removed and counted, and the same verdict without the description |
| docs-only | a documentation change | nothing: light depth, one request, every item n/a or cited |
