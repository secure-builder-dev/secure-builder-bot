# Tasks: adapter-github

- [x] T1 Skeleton: package with exact pins, lockfile, tsconfig (strict), eslint (typescript-eslint + security), vitest with il6 coverage thresholds; `src/secrets.ts` ported from core as the first test
  - Verify: `npm test`, `npm run lint`, `npm run typecheck`, `npm audit` green
- [x] T2 Run directory and check runs: `src/run-dir.ts`, `src/checks.ts`; one check per gate present, conclusions, title, summary with the lineless findings (CM-62)
  - Verify: SPEC criterion 2, the check-run half
- [x] T3 Diff and comments: `src/diff.ts`, `src/comments.ts`; body shape, `shouldPost` (CM-60), stale detection
  - Verify: SPEC criterion 2, the comment half
- [x] T4 GitHub client over fetch and the fake: `src/github-api.ts`, `tests/fake-fetch.ts`
  - Verify: every endpoint used has a test against the fake
- [x] T5 Publisher and entry point: `src/publish.ts`, `src/main.ts`; refuse secrets (CM-61), dedupe, "Not found on", resolve, exit codes
  - Verify: SPEC criterion 2 end to end
- [x] T6 Setup PR: `src/templates.ts`, `src/setup-pr.ts`; config validated by `core/run config check`
  - Verify: SPEC criterion 3
- [x] T7 `action.yml`, `examples/secure-builder.yml`, Makefile loops, constraints workflow
  - Verify: SPEC criterion 4; `make test` and `make lint` run the package
- [x] T8 Spec, manifest rows (hand-proven), dependency policy, capability map; `make check-task`, `make check-docs`, `make mutate-controls`
  - Verify: SPEC criterion 1
