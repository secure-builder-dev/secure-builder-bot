# Plan: adapter-github

Implements `SPEC-adapter-github.md` on branch `wip/adapter-github`, base `epic/core`. The module is
the GitHub face of the bot: the composite Action that runs core, the publisher that turns a run
directory into check runs and review comments, and the setup pull request that enables the bot on
a repository (docs/PRD.md § The install experience, § Platforms, § What the user sees, § Security of
the bot itself).

## Shape

- An npm package `adapter-github/` (`@securebuilderbot/adapter-github`, private, ESM, Node 22),
  TypeScript under `src/`, vitest under `tests/`, exact pins, no runtime dependency: the GitHub API
  is a small typed client over global `fetch` (`src/github-api.ts`), injectable so every test runs
  against a fake fetch that records requests and returns canned responses.
- No build output. The Action runs `npm ci` then `npx tsx src/main.ts` from the bot's own checkout.
- The run directory core wrote (`gate-records/runs/<id>/`: `verdict.json`, `receipt.json`,
  `receipt.md`) is the only input the publisher reads; the fixtures under `tests/fixtures/` were
  produced by core's own runner with fake gates, so the shapes are core's, not hand-typed.
- Controls (CM-60..CM-62) are decision functions with a `mutate:` note each, proven by hand in the
  spec: the control tools index `core/` only until the QA module adds per-package roots.

## Order

1. Skeleton: package, pins, lockfile, tsconfig, eslint, vitest with coverage thresholds; the
   secret-shape port (`src/secrets.ts`) as the first red-then-green test.
2. The run directory and the check runs: read the three files, one check per gate present, the
   conclusion map, the title and summary; a gate that is off gets no check (CM-62).
3. The diff and the review comments: parse the pull request's patches, the comment body with the
   severity marker, `shouldPost` (CM-60), the stale-comment decision.
4. The GitHub client and the fake fetch: the handful of endpoints, pagination, GraphQL resolve.
5. The publisher: plan, refuse secrets (CM-61), post checks, dedupe, reply "Not found on <sha>",
   resolve, exit code; `src/main.ts` from the Action's environment.
6. The setup pull request: the two templates with a comment per line, `openSetupPr` over the Git
   Data API, update-never-duplicate; the produced config validated by `core/run config check`.
7. `action.yml` and `examples/secure-builder.yml`, pinned by SHA; the Makefile `test`/`lint` loops
   generalised; `npm ci` in the constraints workflow.
8. Spec, manifest rows with hand-proven mutations, dependency policy section, capability map row,
   `make check-task`, `make check-docs`, `make mutate-controls`.

## Risks

- The control tools (`verify-controls`, `mutate-controls`) read the roots `project.config.yaml`
  names, which are core's Python. Rows naming TypeScript are proven by hand and said so in the
  spec; per-package control roots belong to the QA module.
- npm 10 (what setup-node 22 ships) cannot resolve vitest 4.1's peer set from scratch, and every
  older vitest carries critical advisories. The lockfile is written by npm 12 and installed by
  `npm ci` under npm 10, which does not re-resolve; verified locally.
- The review-thread resolve is GraphQL only; when the token cannot, the reply alone stands.
