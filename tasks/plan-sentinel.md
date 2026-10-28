# Plan: sentinel

Implements `SPEC-sentinel.md` on branch `wip/sentinel`, from `epic/adapter-gitlab`. The brief's
order, kept: the data first (the checklist, proven against the standards module), then what is sent
(inputs, the sanitizer), what comes back (the schema), who is asked (the providers), the review and
the gate, the proof set, the dogfood job, and last the manifest rows and the records.

## Shape

- Package `sentinel/securebuilderbot_sentinel/`, found by core by name; tests in `sentinel/tests/`,
  measured by the changed-line coverage check (il6's 90 aimed for).
- Data beside the package: `sentinel/checklist/*.yml`, `sentinel/agent.md`, `sentinel/tests/proofset/` (test data, so the QA gate never reads the cases as production code).
- Every module boundary is a pure function over git and files, so it is tested on a real
  throwaway repository with the fake provider; nothing is mocked but the model.

## Order

1. The checklist as data, its twins and citations, `items_for`, `gaps`.
2. Core's config: `sentinel.endpoint`, `sentinel.model`, `sentinel.max_diff_bytes`.
3. The sanitizer.
4. The review request: what is sent, what is withheld, the budget, the manifest rows, QA's proof.
5. The answer schema.
6. The providers and the transport.
7. The review and the gate; core's classifier and the boundaries.
8. The proof set and `make proofset` in `check-code`.
9. Dogfood: the full config and the CI job that runs it when the key is set.
10. Manifest rows CM-50..CM-59 under mutation; spec, plan, todo, capability map, policy.

## Risks

- The proof set's answers are scripted: it proves the pipeline, not a model. A real-model replay
  needs a key and a budget and is not a check.
- The sanitizer's patterns remove some ordinary lines (a YAML `system:` key); the reviewer sees the
  removal and the receipt counts it.
- Locally the scan cannot pass in this sandbox and there is no model key, so the full three-gate
  verdict on this repository is CI's, once the maintainer adds `SB_MODEL_KEY`.
