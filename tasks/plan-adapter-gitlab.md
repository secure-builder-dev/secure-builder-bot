# Plan: adapter-gitlab

Implements `SPEC-adapter-gitlab.md` on branch `wip/adapter-gitlab`, from `epic/core`. The module is
the GitLab CI/CD component and the merge request publisher (CAPABILITY-MAP.md); it depends on core
and on nothing else.

## Shape

- An npm package `adapter-gitlab/` (`@securebuilderbot/adapter-gitlab`, private, ESM, Node >= 22,
  exact pins), run with `npx tsx`, no `dist/`. vitest with lcov coverage, eslint flat config with
  typescript-eslint and eslint-plugin-security, strict tsconfig.
- The component is one YAML file, `templates/secure-builder.yml`, with a `spec: inputs:` block and
  one job that runs on merge request pipelines only. The token is a variable name in it, never a value.
- The publisher reads the run directory core wrote (`receipt.json`, `verdict.json`) and the CI
  variables, and talks to the GitLab REST API through one fetch-based client it is handed, so every
  test runs against an in-memory GitLab.
- The three controls the brief names are functions with manifest rows: dedupe before post (CM-70),
  secret refusal before any post (CM-71), the verdict note upsert (CM-72).

## Order

1. Scaffold and the component, with its test (parses, inputs, rules, artifacts, token by name).
2. The run directory reader and the markdown: verdict block, gate sections, severity markers.
3. Secret refusal: core's patterns ported, refusing a body before anything is sent.
4. The GitLab API client: notes, discussions, the merge request's diff refs, pagination.
5. The publisher: upsert the note, discussions with a position, dedupe, resolve what is gone.
6. The code quality report.
7. `main.ts`: environment and arguments to a run, exit codes.
8. `templates.ts` for the cli module's `init`.
9. Manifest rows, the control tools pointed at TypeScript as well, dependency policy, spec, map row.

## Risks

- No GitLab is reachable from this sandbox: the component is parsed and shape-tested, the publisher
  is tested against a fake fetch. The first real merge request is the integration test.
- `make test` and `make lint` iterate `backend frontend` until another builder generalises the
  loops; this module's scripts are run directly until then.
- The control tools index Python only today; the manifest rows for TypeScript controls need the
  roots in `project.config.yaml` widened (the last task) or they read as unwired.
