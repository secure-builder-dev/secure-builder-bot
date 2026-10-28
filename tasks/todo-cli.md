# Tasks: cli

- [x] T1 adapter-gitlab `setup-mr.ts`: include merge, MR body, project client, `openSetupMr` (create, update, never duplicate)
  - Verify: `adapter-gitlab/tests/setup-mr.test.ts`; `npm test`, lint, typecheck green in adapter-gitlab
- [x] T2 Scaffold `cli/`: package `securebuilderbot`, lockfile, tsconfig, eslint, vitest, bin stub, `--help`, `--version`
  - Verify: SPEC criterion 4; `npm test`, `npm run lint`, `npm run typecheck`, `npm audit` green
- [x] T3 `redactTokens` (CM-81) on every printed line and every file before it is written
- [x] T4 Platform from the remote, the three questions (flags, `--yes`, terminal), the implementation option
- [x] T5 `init` without a token: overwrite refusal (CM-80), files from the adapters' templates, include merge, local branch and commit, every write listed
  - Verify: SPEC criterion 2 (files, include once, refusal)
- [x] T6 `init` with a token: `openSetupPr`, `openSetupMr`; the token in no file and no output
  - Verify: SPEC criterion 2 (token)
- [x] T7 `run`: root, `python3`, `core/run`, `--base` fallback, verdict block, core's exit code, `--open`
  - Verify: SPEC criterion 3
- [x] T8 Manifest rows CM-80, CM-81, control tool keys, constraints workflow, dependency policy, capability map row, SPEC
  - Verify: `make check-task`, `make check-docs`, `make mutate-controls` green
