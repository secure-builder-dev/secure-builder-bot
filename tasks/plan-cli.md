# Plan: cli

Implements `SPEC-cli.md` on branch `wip/cli`, from `epic/adapter-gitlab` (the tip of the stack:
core, scanners, standards, qa, adapter-github and adapter-gitlab merged). The module is
`securebuilderbot init` and `securebuilderbot run` (CAPABILITY-MAP.md); it depends on core and on
both adapters, and on nothing else.

## Shape

- An npm package `cli/`, published name `securebuilderbot`, version 0.1.0, ESM, Node >= 22, exact
  pins, the same tooling as the adapters (strict tsconfig, vitest with v8 lcov coverage and the il6
  thresholds, eslint flat config with typescript-eslint type-aware and eslint-plugin-security, zero
  warnings). `tsx` is the one runtime dependency: `bin/securebuilderbot.js` loads `src/main.ts`
  through `tsx/esm/api`. No `dist/`.
- The adapters' templates and setup functions are imported by relative path
  (`../../adapter-github/src/templates.ts`), so the CLI writes byte for byte what the setup pull
  request writes. adapter-gitlab gains `src/setup-mr.ts`: the include merge into an existing
  `.gitlab-ci.yml`, the merge request body, a project-level REST client and `openSetupMr`.
- Every side effect is injected (`env`, `cwd`, `fetch`, the input stream, the two output sinks), so
  each test runs the real command against a temporary git repository and a fake fetch.
- The two controls the brief names: the overwrite refusal (CM-80) and the token redaction (CM-81),
  each a function with a manifest row and proven by `make mutate-controls`.

## Order

1. adapter-gitlab `setup-mr.ts`: `mergeInclude`, `setupMrBody`, `projectApi`, `openSetupMr`, with
   its test against a fake GitLab.
2. Scaffold `cli/`: package, lockfile, configs, the bin stub, `--help` and `--version`, exit codes.
3. `redactTokens` (CM-81): every printed line and every file before it is written.
4. Platform detection from the remote, the three questions (flags, `--yes`, the terminal), the
   implementation option and what it requires.
5. `init` without a token: the overwrite refusal (CM-80), both platforms' files, the include merge,
   the local branch and commit, the three commands, every write listed.
6. `init` with a token: the setup pull request through `openSetupPr`, the merge request through
   `openSetupMr`; a fake whose error echoes the token proves the redaction.
7. `run`: repository root, `python3`, `core/run` from the CLI's location or
   `SECUREBUILDERBOT_HOME`, `--base` fallback, the verdict block, core's exit code, `--open`.
8. Manifest rows, control tool keys, the constraints workflow, dependency policy, capability map
   row, spec; `make check-task`, `make check-docs`, `make mutate-controls`.

## Risks

- No GitHub or GitLab is reachable from here for a real setup PR: every request goes to a fake
  fetch. The first real `init` against a scratch repository is the integration test.
- Publishing to npm is not in scope: the package imports the adapters by relative path, which works
  from a checkout of this repository. A published package needs the adapters bundled or published
  beside it (a follow-up).
- The `.gitlab-ci.yml` merge edits YAML as text (no YAML package): it handles an absent file, a file
  without `include:`, and a block-sequence `include:`; any other `include:` shape is refused with
  the lines to add by hand, never guessed at.
