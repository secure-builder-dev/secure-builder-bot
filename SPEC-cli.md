# Spec: cli

Module `cli` of the capability map. Status: built on `wip/cli`, from `epic/adapter-gitlab`; the
decisions below were taken during the build and are confirmed by the human who merges it.

## Objective

`cli` is the bot from a terminal (docs/PRD.md § The install experience, § The one-command
alternative for either platform): `securebuilderbot init` sets a repository up, `securebuilderbot
run` runs the gates on it locally. It holds no gate logic and no template of its own: `init` writes
what the adapters' setup writes, from the adapters' own functions, and `run` is core's entry point
with the repository found and the arguments defaulted.

User stories, from the PRD:

- As a developer who would rather not click through a marketplace, I run `npx securebuilderbot
  init`, answer three questions (or pass `--yes`), and get the setup pull request on GitHub, or the
  merge request on GitLab, with the same files the app would write.
- As a developer, I run `securebuilderbot run` before pushing and see the verdict block my pull
  request will get, with core's exit code.
- As the bot's operator, the token `init` uses is read by name from the environment and never asked
  for, printed or written (§ Security of the bot itself).

## Tech Stack

- TypeScript 5.9 on Node 22, ESM, run from source with `tsx` (no `dist/`); strict tsconfig.
- vitest 4 with v8 lcov coverage and the il6 thresholds (90% lines, functions, statements; 80%
  branches) on `cli/src`; eslint 10 flat config with typescript-eslint (type-aware) and
  eslint-plugin-security, warnings failing the run.
- `tsx` is the one runtime dependency; the rest dev only. Exact pins, the same package set as
  adapter-gitlab's, every row in `docs/architecture/DEPENDENCY_POLICY.md` § 4D.
- No YAML package and no HTTP package: the adapters' fetch clients and core's PyYAML (through
  `core/run config check` in the tests) are enough.

## Commands

```
Install:          npm ci --prefix cli                       (CI: .github/workflows/constraints.yml)
Set a repo up:    node cli/bin/securebuilderbot.js init [--profile il4] [--gates scan,qa] [--sentinel off] [--yes]
                    [--platform github|gitlab] [--gitlab-group <group>] [--force]
Run the gates:    node cli/bin/securebuilderbot.js run [--base origin/main] [--head HEAD] [--config <file>] [--open]
Help, version:    node cli/bin/securebuilderbot.js --help · --version
Tests + coverage: cd cli && npm test           (vitest run --coverage → coverage/lcov.info)
Lint:             cd cli && npm run lint       (eslint . --max-warnings 0)
Typecheck:        cd cli && npm run typecheck
Advisories:       cd cli && npm audit
Through make:     make test · make lint        (every top-level package with node_modules)
Controls:         make verify-controls · make mutate-controls   (rows CM-80, CM-81)
```

`npx securebuilderbot` is the name the PRD gives; it works once the package is published (see
Follow-ups). From a checkout the bin is run with `node`, or linked with `npm link` in `cli/`.

## Project Structure

```
cli/
  package.json  package-lock.json  tsconfig.json  eslint.config.js  vitest.config.ts
  bin/securebuilderbot.js  → the command: tsx's tsImport loads src/main.ts
  src/
    main.ts      → argv to a command; --help, --version; every line through the redaction
    io.ts        → Io (env, cwd, sinks, terminal, fetch), Command, exit codes 0/1/2
    init.ts      → init: platform, answers, the overwrite refusal (CM-80), files, branch, commit, PR/MR
    run.ts       → run: root, python3, core/run, --base fallback, streaming, --open
    answers.ts   → the three questions: flags, --yes, the terminal; the implementation option
    platform.ts  → the origin remote → GitHub, GitLab or ask
    redact.ts    → redactTokens (CM-81), the token values, the refusing file writer
    git.ts       → git as a child process; GitError
  tests/
    main.test.ts  answers.test.ts  platform.test.ts  redact.test.ts  init.test.ts
    init-token.test.ts  run.test.ts   → the real commands on temporary repositories
    helpers.ts  fake-fetch.ts         → captured sinks, typed answers, temp repos, a recording fetch
adapter-gitlab/
  src/setup-mr.ts         → mergeInclude, setupMrBody, setupMrFiles, projectApi, openSetupMr (new)
  tests/setup-mr.test.ts
```

## Interfaces

**`securebuilderbot init`.**

1. The repository root (`git rev-parse --show-toplevel`; outside one, exit 2).
2. The platform: `--platform`, else the origin remote (`github.com` is GitHub, a host with `gitlab`
   in it is GitLab), else asked in the terminal; with `--yes` and no answer, exit 2 naming
   `--platform`.
3. The three answers, each from its flag, else the PRD's default with `--yes` (`il4`; `scan, qa`;
   sentinel `off`), else asked in the terminal (an empty line takes the default, three bad answers
   or a closed terminal exit 2). Nobody to ask and no `--yes`: exit 2 naming the missing flags. The
   options and the gates are adapter-github's (`validateAnswers`, `effectiveGates`): sentinel off
   removes `sentinel` from the gates, any other mode adds it, on both platforms.
4. The implementation option they imply, printed with what it requires: Light (scan only:
   nothing), Standard (qa: a test suite and `docs/security/CONTROL-MANIFEST.md`, which the QA gate
   drafts), Full (sentinel: a model key as the CI secret `SB_MODEL_KEY`); on GitLab also the
   publisher's `SECURE_BUILDER_TOKEN`; a warning when scan is off.
5. **CM-80**: an existing `.securebuilderbot.yml`, an existing workflow file `secure-builder.yml` in the user's `.github/workflows/`
   (GitHub), or a local `secure-builder/enable` branch the user is not on is refused without
   `--force`: exit 1, nothing written, the branch unchanged.
6. The files: GitHub, adapter-github's `setupFiles` (`configTemplate`, `workflowTemplate`); GitLab,
   adapter-gitlab's `configTemplate` and `includeSnippet` merged into `.gitlab-ci.yml` by
   `mergeInclude` (created when absent, appended when there is no `include:`, an entry added to a
   block-sequence `include:` at its indentation, unchanged when the component is already there, any
   other `include:` refused with the lines to add by hand: exit 1, nothing written). Without
   `--gitlab-group` the include carries `<group>` and init says to edit it.
7. **CM-81**: a file that would carry a token's value is refused before the first write (exit 1).
   An uncommitted change to `.securebuilderbot.yml`, the workflow file or `.gitlab-ci.yml`, untracked
   files included, is refused too, `--force` or not (exit 1): those files are committed on the setup
   branch, and an edit carried there would leave the user's branch (gate cli run 1, N-03).
   A setup file, or a directory above it, that is a symbolic link is refused the same way (CM-83):
   init never writes through a link, which could point outside the repository (N-04).
8. The files are written on the local branch `secure-builder/enable`, created from the default
   branch (`origin/HEAD`, else `origin/main`, `origin/master`, `main`, `master`; the current branch,
   said out loud, only when none exists) or reset to it with `--force`, never on the user's branch
   and never carrying its unmerged work (gate cli run 1, N-06). The existing `.gitlab-ci.yml`, the
   overwrite check and the link check read that branch's tree, and committed with the
   message "Enable Secure Builder" (only those paths; the user's hooks run).
9. With `GITHUB_TOKEN` or `GH_TOKEN` (GitHub) or `GITLAB_TOKEN` (GitLab) set and a repository in
   the origin remote: GitHub, `openSetupPr` over `GitHubClient`; GitLab, `openSetupMr` over
   `projectApi` (the project by its path). The token goes only to `api.github.com` (GITHUB_TOKEN,
   GH_TOKEN) or `gitlab.com` (GITLAB_TOKEN), or to the API the user names with `--github-api
   <https-url>` or `--gitlab-host <host>` (plain https, no credentials, checked before anything is
   written). A remote on any other host gets a line saying the token was not sent and the flag that
   would send it, then the commands to finish by hand (gate cli run 1, N-02). The adapter builds the remote branch from the
   default branch's head. A remote `secure-builder/enable` that already exists (on GitLab, also one an
   open merge request comes from) is refused without `--force`, through CM-80: exit 1, nothing
   pushed, and the message says to review it or run again with `--force`. With `--force` the adapter
   is asked again with `replaceBranch: true`, resets the branch and updates the open pull or merge
   request; it never opens a second. An API
   failure exits 2 and prints the commands to finish by hand; a body the GitLab adapter finds
   secret-shaped exits 1. Without a token: the three commands (`git push -u origin
   secure-builder/enable`, `gh pr create …` or `glab mr create …`, `git switch <previous>`).
10. Every write is listed at the end, under "Every write:", also after a failure.

**`securebuilderbot run`.** The root; `python3` on the PATH; `core/run` under `SECUREBUILDERBOT_HOME`
or the checkout the CLI is in (`cli/../core/run`); each missing is exit 2 with what to do. `--base`
defaults to `origin/main` when it resolves, else `main`; `--head` to `HEAD`; `--config` is resolved
from the working directory. Core runs at the root with the caller's environment, every line of its
output printed as it arrives; its exit code is the command's (any other code reads as 2). `--open`
prints the receipt's full path from core's `Receipt:` line. Nothing is published.

**Exit codes**, core's: 0 ok · 1 refused (a gate failed or did not run, an init refusal) · 2 could
not run (bad arguments, no repository, no platform, git or the API failed, core could not start).

**adapter-gitlab `setup-mr.ts`** (new): `mergeInclude(existing, snippet) → { content, changed }`
(throws `IncludeNotMergeable`), `setupMrBody(answers)`, `setupMrFiles(answers, existingCi,
{ group? })`, `projectApi({ apiV4Url, project, token, fetch? })` with `getProject`, `getFile`,
`createCommit`, `listOpenMergeRequests`, `createMergeRequest`, `updateMergeRequest` (PRIVATE-TOKEN
header only, every body through `refuseSecrets`, `GitLabApiError` naming status and path), and
`openSetupMr(api, answers, { group? }) → { branch, commit, mergeRequest, created, files }`: the
default branch from `GET /projects/:id`, create or update from `GET
/projects/:id/repository/files/:path?ref=`, one `POST /projects/:id/repository/commits` on
`secure-builder/enable` with `start_branch` and `force: true`, then `PUT` the open merge request
found by `GET /projects/:id/merge_requests?state=opened&source_branch=` or `POST` a new one.

## Testing Strategy

- vitest under `cli/tests/`, one file per source module, each command run through `main` against
  a temporary git repository (`tests/helpers.ts:tempRepo`) with its sinks captured; no module is
  mocked. The network is a recording fake fetch (`tests/fake-fetch.ts`) handed in through `Io`; the
  terminal is a stream of typed lines. Secret-shaped tokens are built at run time.
- The files init writes are compared with the adapters' template functions and validated with
  `core/run config check`; YAML merges are parsed with PyYAML in adapter-gitlab's test.
- `run` is tested against the real `core/run` of this checkout; a stand-in `core/run` covers stderr
  and an unexpected exit code.
- Coverage on `cli/src`: 99% of lines, thresholds enforced by `npm test`.

## Boundaries

- **Always:** red test first, then green; the files from the adapters' functions, never a copy;
  every printed line and every written file through the redaction; the setup on its own local
  branch; `make check-fast` before every commit.
- **Ask first:** a runtime dependency beyond tsx; a change to the three questions' options or
  defaults (they are the PRD's); a different setup branch name (both adapters share it).
- **Never:** a token prompted for, printed or written; a commit, push or edit on the user's
  current branch; a push at all (the commands are printed); a merge; anything scheduled; a
  suppression comment.

## Success Criteria

Each verified on `wip/cli` on 2026-10-23.

1. **`npm test`, `npm run lint`, `npm run typecheck`, `npm audit` green in `cli/`; `make
   check-task` green.** `npm test`: 68 tests in 7 files pass, coverage 99.18% lines, 96.41%
   branches, 100% functions; `npm run lint`: 0 problems at `--max-warnings 0`; `tsc --noEmit`:
   silent; `npm audit`: 0 vulnerabilities. `make test` prints `test: cli` and `make lint` prints
   `lint: cli` (the loops already find every package with `node_modules`; no Makefile change).
   adapter-gitlab: 103 tests pass, lint and typecheck clean. `make check-task` green at the last
   commit (summary lines in the handback).
2. **init** (`cli/tests/init.test.ts`, `cli/tests/init-token.test.ts`). In a temp repo with a
   github.com remote, `init --yes` writes `.securebuilderbot.yml` equal to adapter-github's
   `configTemplate` and the workflow `secure-builder.yml` in the user's `.github/workflows/` equal to `workflowTemplate` for
   `il4`, `[scan, qa]`, `off`, commits both on `secure-builder/enable` with `main` as parent, and
   `core/run config check` prints `config ok: profile il4 (287 controls) · gates scan, qa · version
   latest`. With a gitlab remote it writes adapter-gitlab's `configTemplate` and a `.gitlab-ci.yml`
   equal to `includeSnippet`; with an existing `.gitlab-ci.yml` it appends once, and a second run
   (with `--force`, as the first leaves the config behind) leaves the file byte for byte unchanged
   with one `include:`. A second `init` without `--force` exits 1, says `refused:
   .securebuilderbot.yml …`, and changes neither the file nor `HEAD`. With a fake fetch and
   `GITHUB_TOKEN` set to a `ghp_`-shaped value, the pull request is opened through `openSetupPr`
   (the blobs equal the templates; every request carries `Bearer <token>`), and the token appears
   in none of the output, none of the files and nothing in `git log -p --all`; when the fake's
   error message echoes the token, the output shows `[redacted]` in its place and the command
   exits 2. The same for GitLab with `GITLAB_TOKEN` (`PRIVATE-TOKEN` only). Also checked by hand
   through `bin/securebuilderbot.js` in a scratch repository.
3. **run** (`cli/tests/run.test.ts`). In a temp repo whose config is `gates: [qa]` and which has no
   test runner, `run` calls this checkout's `core/run run --base main --head HEAD` (no
   `origin/main`), prints `QA: NOT RUN — no test runner detected …`, `Overall: FAIL` and the
   `Receipt:` line, and exits 1, core's code; with `refs/remotes/origin/main` present the base is
   `origin/main`; `--open` prints an absolute path that exists; `SECUREBUILDERBOT_HOME` pointing at
   the checkout works the same, pointing at an empty directory exits 2; a bad config exits 2.
4. **`--help`** (`cli/tests/main.test.ts`) lists `init` and `run`, the three questions' flags
   (`--profile`, `--gates`, `--sentinel`) and `--yes`, `--force`, `--platform`, `--gitlab-group`,
   `--base`, `--head`, `--open`, the token variables and `SECUREBUILDERBOT_HOME`, and the exit
   codes; checked through the bin stub in a real process too.

**Controls, proven by mutation** (`docs/security/CONTROL-MANIFEST.md` § cli). `cli/src` is a
control root and `npm test --prefix cli` is part of the full-suite command, so `make
verify-controls` finds each row's call sites and `make mutate-controls` proves both. By hand first
(the mutation inserted as the first statement, `npx vitest run`, the file restored with `git
checkout`):

| id | mutation applied | result |
|---|---|---|
| CM-80 `overwriteRefusal` | `return null;` | 3 failed, 65 passed (`init.test.ts`: second init, existing workflow or branch, the unit test); after B-01, 5 failed, 67 passed (also `init-token.test.ts` ×2, the remote branch on GitHub and on GitLab) |
| CM-81 `redactTokens` | `return text;` | 6 failed, 62 passed (`init-token.test.ts` ×2: the echoed token, the file carrying it; `redact.test.ts` ×4) |

After each, 68 passed.

## Decisions taken during the build

- **The setup is committed on a local branch in both cases.** The brief asks for the files to be
  written and then, with a token, the pull request opened through the adapter; writing them into
  the user's current branch would edit a branch the bot never edits. So init always writes and
  commits on `secure-builder/enable`; with a token the adapter also builds the remote branch from
  the default branch's head (its own design), so the pull request carries the setup files and
  nothing else of the local tree. The local branch can be deleted once the pull request is open.
- **CM-80 covers what init would replace**: the config, the workflow file on GitHub, a local setup
  branch the user is not on (`--force` resets it with `git switch -C`), and the remote setup branch
  (gate cli run 1, B-01). Both adapters' setup functions take `replaceBranch`, default false, and
  refuse an existing branch before writing anything; init asks without it first, and only
  `overwriteRefusal` with `--force` lets it ask again with it. `.gitlab-ci.yml` is merged,
  not replaced, so it is not in the list; its own refusal is the merge's.
- **CM-81 is one function**, `redactTokens(text, tokens)`, over the values of `GITHUB_TOKEN`,
  `GH_TOKEN` and `GITLAB_TOKEN` (eight characters or more: no platform issues a shorter one, and a
  shorter value would redact ordinary words). `main` wraps the sinks once, so every line any command
  prints is redacted; `writeRedacted` refuses a file whose content would change; `init` checks
  every file before the first write so a refusal never leaves half a setup behind. The real path to
  the output is adapter-github's error, which carries the server's `message`.
- **Both platforms use adapter-github's three answers** (`action | self-hosted | off`) and its
  `effectiveGates`; adapter-gitlab's template accepts all three and is handed the computed gates,
  because on its own it does not add `sentinel` for a mode other than off.
- **The include merge is text, and refuses what it cannot do safely**, rather than add a YAML
  package: absent, no `include:`, a block sequence; an inline or mapping `include:` is refused with
  the lines to add. It lives in adapter-gitlab, since both the local file and the default branch's
  file (for the merge request) need it.
- **`--gitlab-group`** fills the component path; without it `includeSnippet`'s `<group>` placeholder
  is written and init prints a line saying to edit it.
- **`noPropertyAccessFromIndexSignature` is off** in `cli/tsconfig.json` (adapter-gitlab has it on):
  the CLI typechecks adapter-github's source, which is written without it.
- **`--yes` never asks**, the platform included: it is the non-interactive form.
- **The bin stub uses `tsx/esm/api`'s `tsImport`**, so the command needs no loader flag and no build.
- **`run` gives core the caller's environment** and streams its output line by line, through the
  redaction, rather than collect it: a scan takes minutes and the lines are the progress.

## What this sandbox could not do

- No real pull or merge request: every request in the tests goes to the recording fake. One manual
  run of the bin stub here picked up the sandbox's own `GITHUB_TOKEN` and made one real `GET` to
  the GitHub API for a placeholder repository, answered 401; nothing was created, the token was not
  printed, and the command exited 2 with the commands to finish by hand. The first real `init`
  against a scratch repository is the integration test.
- No GitLab is reachable: `openSetupMr` is tested against a fake GitLab.

## Changes outside cli/ this module needed

- `adapter-gitlab/src/setup-mr.ts` and `adapter-gitlab/tests/setup-mr.test.ts` (new): the adapter had
  only the merge request publisher, no setup.
- `project.config.yaml`: `cli/src` in `CONTROL_SRC_ROOTS`, `npm test --prefix cli` in
  `CONTROL_TEST_CMD`, the package's `package.json`, `package-lock.json`, `vitest.config.ts` and test
  helpers in `CONTROL_HARNESS_RE`.
- `docs/security/CONTROL-MANIFEST.md`: § cli, rows CM-80 and CM-81.
- `docs/architecture/DEPENDENCY_POLICY.md`: § 4D.
- `.github/workflows/constraints.yml`: `npm ci --prefix cli` before `make check-full`.
- `.boundaries`: informational edges `cli -> core`, `cli -> adapter-github`, `cli -> adapter-gitlab`
  (the checker's groups are shell and Python; `scripts/check-boundaries.sh` is unchanged).
- `CAPABILITY-MAP.md`: this module's Spec column.
- `tasks/plan-cli.md`, `tasks/todo-cli.md`.
- The Makefile is unchanged: its `test` and `lint` loops already run every package with
  `node_modules`.

## Follow-ups

- **Publishing.** The package imports the adapters by relative path, which needs a checkout of this
  repository. `npx securebuilderbot` from the registry needs the adapters bundled into the package
  (or published beside it) and `core/` found through `SECUREBUILDERBOT_HOME` or shipped with it;
  until then the name is reserved, `private` is not set and nothing is published.
- **An ambient token opens a pull request.** A developer whose shell exports `GITHUB_TOKEN` for
  something else gets the setup pull request opened. That is what the brief specifies; a `--local`
  flag that never uses a token would make it a choice.
- **adapter-gitlab's spec** names `src/templates.ts` as the cli's interface; `src/setup-mr.ts` is now
  the second, and `SPEC-adapter-gitlab.md` could say so.
- **Licenses.** `lightningcss` (MPL-2.0) and `minimatch` (BlueOak-1.0.0) are in all three Node
  lockfiles through vitest, dev only, and neither is in § 6.1's list; a maintainer's call.
- `init` pins `version: latest`; a `--release x.y.z` flag would pin the config, the workflow and the
  component together, which both adapters' templates already support.
