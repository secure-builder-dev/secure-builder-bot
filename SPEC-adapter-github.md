# Spec: adapter-github

Module `adapter-github` of the capability map. Status: built on `wip/adapter-github`, base
`epic/core`; the decisions below were taken during the build and are confirmed by the human who
merges it.

## Objective

`adapter-github` is the GitHub face of the bot (docs/PRD.md § The install experience, § Platforms,
§ What the user sees, § Security of the bot itself). Three things, and nothing of core's internals:

- **The Action** (`adapter-github/action.yml`): a composite action that runs core on the pull
  request's range from the bot's own checkout at the pinned ref, publishes, and uploads the run
  directory as the receipt artifact — each later step `if: always()`, so a red gate still publishes.
  Its `part` input splits that in two jobs (PRD § Configuration): `untrusted` runs only Scan and QA,
  refuses a model key, publishes nothing and uploads the one run core reported as the artifact
  `secure-builder-untrusted-run`; `trusted`, in the next job, downloads that artifact outside the
  checkout, runs core's trusted part on it (Sentinel and the verdict, Scan and QA carried as claims)
  and publishes. The workflow the setup writes uses the two parts; empty is one job, as before.
- **The publisher** (`adapter-github/src/publish.ts`, entry `adapter-github/src/main.ts`): the run
  directory core wrote becomes one check run per gate that ran, review comments on the diff lines
  the findings concern, within the noise budget, with a secrets refusal on everything it is about
  to post.
- **The setup pull request** (`adapter-github/src/setup-pr.ts`, `adapter-github/src/templates.ts`):
  the three answers become `.securebuilderbot.yml` with a comment above every line and the workflow
  file with the least permission the bot needs, on one branch and one pull request titled "Enable
  Secure Builder", updated and never duplicated.

User stories, from the PRD:

- As a team lead, I merge one pull request and from the next pull request on every gate I turned
  on reports as its own check, green, red or yellow, with the verdict on the check's page.
- As an author, each finding sits on the line it concerns with its severity, the rule it serves and
  one sentence on what would fix it; the bot never repeats itself and resolves its own comments
  when my next push fixes them.
- As an assessor, the receipt is attached to the run as an artifact, untouched.

## Tech Stack

- TypeScript 5.9 (strict, `NodeNext`, no emit) on Node 22, ESM. No runtime dependency: the GitHub
  API is a typed client over global `fetch`. The Action runs `npm ci` then `npx tsx src/main.ts`;
  there is no `dist/`.
- vitest with v8 coverage (il6 thresholds: 90% lines, functions and statements, 80% branches, on
  the whole package), ESLint flat config with typescript-eslint and eslint-plugin-security.
- Dev dependencies only, pinned exactly (docs/architecture/DEPENDENCY_POLICY.md § 4B); the lockfile
  is committed and written by npm 12 for the reason recorded there.

## Commands

```
Install:            cd adapter-github && npm ci
Tests + coverage:   npm test                (vitest run --coverage → coverage/lcov.info)
Lint:               npm run lint            (eslint .)
Typecheck:          npm run typecheck       (tsc --noEmit)
Audit:              npm audit               (0 findings on 2026-10-23)
Publish a run:      GITHUB_TOKEN=… GITHUB_REPOSITORY=owner/name GITHUB_SHA=… [GITHUB_EVENT_PATH=…] [SB_RUN_DIR=…] npx tsx src/main.ts
                    (SB_RUN_DIR unset: the newest untracked run whose receipt names the head; set but empty: exit 2)
Through make:       make test · make lint   (every top-level directory with a package.json and node_modules)
Every edit:         make check-fast
Task done:          make check-task
```

## Project Structure

```
adapter-github/
  action.yml               → the composite action (inputs version, base, python-version, token)
  examples/
    secure-builder.yml     → the workflow the setup pull request writes, for the default answers
  package.json  package-lock.json  tsconfig.json  eslint.config.js  vitest.config.ts
  src/
    main.ts                → the entry point: the Action's environment → publish → exit code
    publish.ts             → plan, refuse secrets (CM-61), post checks, comments, replies, resolves
    checks.ts              → one check per gate present (CM-62), conclusions, title, summary
    comments.ts            → comment body, shouldPost (CM-60), staleComments
    diff.ts                → the right-hand lines of the pull request's patches
    run-dir.ts             → read and validate verdict.json, receipt.json, receipt.md
    github-api.ts          → the typed client over fetch: REST, pagination, one GraphQL mutation
    secrets.ts             → the port of core's SECRET pattern
    templates.ts           → .securebuilderbot.yml, the workflow, the pull request body
    setup-pr.ts            → openSetupPr over the Git Data API
  tests/
    *.test.ts              → one file per source module, plus action.test.ts for the YAML
    fake-fetch.ts          → records every request, returns canned responses
    yaml.ts                → YAML through python3's PyYAML, so the package adds no parser
    fixtures/run-qa-fail/  run-qa-fixed/  run-qa-yellow/   → written by core's own runner
```

## Interfaces

**Input: the run directory** (`gate-records/runs/<id>/`), exactly as core writes it
(`core/securebuilderbot_core/runner.py`, `verdict.py`, `receipt.py`): `verdict.json` (`gates[]`
with `gate`, `status`, `reason`, finding counts), `receipt.json` (`run_id`, `head`, `gates.<name>`
with `findings[]` of `severity`, `rule_id`, `message`, `path`, `line`, `file`, and
`controls_assessed`), `receipt.md`. `readRunDir` validates the shapes and names the file that is
wrong. The fixtures were produced by running core's runner with fake gates, not typed by hand.

**Output: the pull request.**

- A check run named `Secure Builder / Scan`, `/ QA` or `/ Sentinel` per gate in `verdict.json`,
  on the pull request's head sha: `success` for pass, `failure` for fail **and** not_run,
  `neutral` for yellow; `title` is the gate's verdict line (`QA: FAIL — <reason>`); `summary` is
  the gate's section of `receipt.md`, the reason, the run id, `controls_assessed`, and the findings
  not placed on the diff. A gate the config turned off is absent from `verdict.json` and gets no
  check.
- A review comment per finding whose `path` and `line` the pull request changes (read from the
  pull request's file patches, right-hand side): `**BLOCKING** · \`rule\` · Secure Builder / QA —
  fails the check` or `_Advisory_ … — does not fail the check`, the message, `What would fix it:`
  one sentence by rule family, for Sentinel a line saying it comes from a cold reviewer with no
  build context, and an invisible marker so the bot's comments are its own whatever the login.
- Never a comment whose body and line match one the bot already posted (`shouldPost`); when an
  earlier comment's finding is gone on the new head, a reply `Not found on <sha>` and the thread
  resolved through GraphQL when the token can (the reply alone otherwise).
- Exit 0 when every gate passed or was yellow, 1 when any failed or did not run, 2 when nothing
  could be published (unreadable run directory, a secret-shaped string, a refused check run).

**The three answers** (`SetupAnswers`: `profile` none|il4|il6, `gates`, `sentinel`
action|self-hosted|off, optional `version`): `configTemplate`, `workflowTemplate`, `setupPrBody`,
`setupFiles`, `validateAnswers`, `effectiveGates` are exported for the `cli` module.
`openSetupPr(client, repo, answers)` returns the branch, commit, pull request and whether it
created or updated them.

**The client** (`GitHubClient`): `createCheckRun`, `listPullFiles`, `listReviewComments`,
`createReviewComment`, `replyToReviewComment`, `resolveThreadOfComment`, `getRepo`, `getRef`,
`getCommit`, `createBlob`, `createTree`, `createCommit`, `createRef`, `updateRef`, `listPulls`,
`createPull`, `updatePull`; `fetch`, `baseUrl` and `graphqlUrl` are injectable (GitHub Enterprise
Server through `GITHUB_API_URL` and `GITHUB_GRAPHQL_URL`). An error names the route and the
status, never the token.

**Environment the Action sets for `main.ts`:** `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_SHA`,
`GITHUB_EVENT_PATH` (the pull request number and head sha), `GITHUB_WORKSPACE` (where
`gate-records/runs/` is), `SB_RUN_DIR` (the run directory core reported on its own stdout, the last
`Receipt: gate-records/runs/<id>/receipt.md` line, passed from the core step through
`$GITHUB_OUTPUT`; empty when core reported none, which is exit 2), `SB_BOT_LOGIN` (default
`github-actions[bot]`). Whichever directory is named, it is published only when git does not track
it and its receipt's `head` is exactly the sha the checks are posted to; otherwise nothing is posted
and the exit is 2. Run by hand with `SB_RUN_DIR` unset, `main.ts` takes the newest-named directory
under `gate-records/runs/` that meets both conditions, and exits 2 when none does.

## Testing Strategy

- vitest, one file per module, every GitHub call against `tests/fake-fetch.ts`, which records
  method, path, query, headers and body and returns canned responses; no network, no mocking of
  the module under test.
- The run-directory fixtures come from core's runner (`core/securebuilderbot_core/runner.py`) with
  fake gates: scan pass; qa fail with two findings (one on `src/api/users.ts:42`, in the diff; one
  without a line); qa pass (the finding gone); qa yellow with an advisory.
- The produced `.securebuilderbot.yml` is written to a temporary directory and validated by
  `core/run config check` from the test; YAML is parsed through python3's PyYAML, which core
  already requires.
- Coverage thresholds are in `adapter-github/vitest.config.ts` and fail `npm test` when crossed.

## Boundaries

- **Always:** red test first, then green; `make check-fast` after every edit and `make check-task`
  before a task is done; every payload is checked for a secret-shaped string before anything is
  posted; a check run per gate that ran and none for one that is off; exact pins.
- **Ask first:** a runtime dependency; a new GitHub endpoint; a change to the comment body shape
  (it is the dedupe key: a change makes every earlier comment look new once).
- **Never:** a push, a merge or an edit to a user's branch (the Git Data API is used for the
  setup branch `secure-builder/enable` only); a secret value in a log, a check or a comment;
  naming the platform the engine came from; a suppression comment.

## Success Criteria

Each verified on `wip/adapter-github` on 2026-10-23.

1. **`npm test`, `npm run lint`, `npm run typecheck`, `npm audit` green; `make test` and
   `make lint` run them; `make check-task` green.** `npm test`: 68 tests in 8 files pass,
   coverage above the il6 thresholds; `npm run lint`: 0 problems; `npm run typecheck`: clean;
   `npm audit`: 0 vulnerabilities. `make test` prints `test: adapter-github` before `test: core
   (pytest)`, `make lint` prints `lint: adapter-github`. The last `make check-task` summary lines
   are in the handback.
2. **The publisher against the fixture and the fake** (`adapter-github/tests/publish.test.ts`):
   exactly two check runs (`Secure Builder / Scan` success, `Secure Builder / QA` failure, titles
   `Scan: PASS` and `QA: FAIL — 2 blocking findings…`); one review comment on
   `src/api/users.ts:42` beginning `**BLOCKING** · \`AC-3\``; the lineless SA-11 finding in the QA
   summary; a second run with the first run's comment listed posts nothing and replies nothing;
   with the `run-qa-fixed` fixture the earlier comment gets `Not found on <sha>` and its thread is
   resolved (two GraphQL calls); a finding whose message carries a `ghp_` token built at run time
   is refused: zero POST requests, exit 2, and the token never appears in the log.
3. **`openSetupPr` against the fake** (`adapter-github/tests/setup-pr.test.ts`): two blobs whose
   contents equal `configTemplate` and `workflowTemplate`, a tree on the default branch's tree, a
   commit with the default head as parent, `refs/heads/secure-builder/enable` created, the pull
   request "Enable Secure Builder" created with the body explaining the three answers and that
   the gates run on it too, under the config it adds; a second call with the branch and the pull request present
   force-updates the ref and rewrites the pull request, creating nothing. The config for `il4`,
   `[scan, qa]`, `off` is written to a temporary directory and `core/run config check` prints
   `config ok: profile il4 (287 controls) · gates scan, qa · version latest`, exit 0; the sentinel
   variant (`key_secret: SB_MODEL_KEY`) passes the same check.
4. **`action.yml` and the example workflow** (`adapter-github/tests/action.test.ts`): both parse;
   every third-party `uses:` is `actions/<name>@<40 hex> # vX.Y.Z` (setup-python v7.1.0,
   setup-node v7.1.0, upload-artifact v7.0.2, checkout v7.0.1; each SHA was fetched and confirmed a
   commit object); the example's permissions are exactly `contents: read`, `checks: write`,
   `pull-requests: write` and it equals `workflowTemplate` for the default answers. The bot's own
   step is `secure-builder-dev/secure-builder-bot/adapter-github@v0` as the brief names it: a
   commit of this repository cannot pin itself, and a user's gate behaviour changes only with a
   release (PRD § Staying current).

**Controls, proven by mutation** (docs/security/CONTROL-MANIFEST.md § adapter-github). When the
stack was assembled, the control tools learned a second extension (`CONTROL_SRC_EXT: py ts`) and
`project.config.yaml` lists `adapter-github/src` as a control root, with the full-suite command
running this package's vitest suite after pytest. `make verify-controls` finds each row's call
site and `make mutate-controls` proves all three (each RED under the full suite). Before that,
each was proven by hand, which is the record below: a one-line replacement, the suite run, the
file restored with `git checkout`:

| id | mutation applied | result |
|---|---|---|
| CM-60 `shouldPost` | body → `return true;` | 3 failed, 65 passed (`comments.test.ts` ×2, `publish.test.ts` "run again … posts nothing new") |
| CM-61 `refusal` | body → `return null;` | 2 failed, 66 passed (`publish.test.ts` secret refusal ×2) |
| CM-62 `gatesToPublish` | `if (g !== undefined) out.push(g);` → `out.push(g ?? { gate, status: 'pass', … });` | 7 failed, 61 passed (`checks.test.ts` ×2, `publish.test.ts` ×4, `main.test.ts` ×1) |

After each, `68 passed`.

## Decisions taken during the build

- **No octokit, no runtime dependency.** A 200-line client over `fetch` covers the eleven
  endpoints; the dependency policy's row count for a user's runner stays at zero.
- **Plan, refuse, post.** Every check payload and comment body is built before the first request;
  one secret-shaped string anywhere refuses the whole plan (exit 2, nothing posted) rather than
  posting the clean parts, because a partial publish hides the refusal.
- **The dedupe key is path, line and body.** GitHub clears `line` on an outdated comment and keeps
  `original_line`; both are read. The body carries no run id or sha, so it is stable across runs.
- **Resolve is GraphQL.** REST has no resolve endpoint; `resolveReviewThread` needs the thread id,
  found by the comment's `databaseId` among the first 100 threads with 100 comments each (enough
  for a pull request within the noise budget). A refusal reads as "not resolved" and the reply
  stands.
- **A re-run creates a new check run.** The noise budget is about comments; a fresh check run per
  run on the same head is GitHub's normal shape and keeps each run's verdict visible.
- **The event's head sha, not `GITHUB_SHA`.** On `pull_request` the latter is the merge commit;
  the checks belong on the head.
- **vitest 4.1.12 with a lockfile from npm 12.** Every older vitest carries critical advisories;
  npm 10 cannot resolve 4.1's peers from scratch but installs the lockfile with `npm ci`
  (verified, 0 audit findings). Recorded in docs/architecture/DEPENDENCY_POLICY.md § 4B.
- **Two security-plugin rules off by decision** in `adapter-github/eslint.config.js`
  (`detect-non-literal-fs-filename`, `detect-object-injection`), with the reason beside them; no
  disable comment anywhere.
- **The sentinel answer governs the gates list.** `off` removes `sentinel` from the gates, any
  other mode adds it, with a comment saying so; a config with scan off carries the PRD's warning.
- **Actions pinned at their current majors** (checkout v7, setup-python v7, setup-node v7,
  upload-artifact v7); GitHub-hosted runners carry the Node these need.

## What this sandbox could not do

- No GitHub Marketplace listing, no real pull request: every call is against the recording fake.
  The first real run is the lead's gate on this repository's own workflow.
- The `actions/*` repositories could not be read through the GitHub API from this session; their
  tag SHAs came from `git ls-remote` and each was fetched and confirmed a commit object.

## Changes outside adapter-github this module needed

- `Makefile`: the `test` and `lint` loops find every top-level directory with a `package.json`
  (and `node_modules`; the "lockfile but no node_modules in CI" rule kept) instead of naming
  `backend` and `frontend`.
- `.github/workflows/constraints.yml`: `npm ci --prefix adapter-github` before `make check-full`.
- `.gitignore`: `coverage/`.
- `.boundaries`: an informational edge `adapter-github -> core` (the checker's groups are shell and
  Python; the line records the dependency the capability map already states).
- `docs/security/CONTROL-MANIFEST.md`: the adapter's table, CM-60..CM-62.
- `docs/architecture/DEPENDENCY_POLICY.md`: § 4B for Node.
- `CAPABILITY-MAP.md`: this module's Spec column.

## Follow-ups

- **QA module:** a targeted run per language, so a TypeScript row names its vitest file and does
  not need the full suite (today its proving-test column is `-` for that reason).
- **cli module:** `securebuilderbot init` imports `templates.ts` and `setup-pr.ts`; the
  `SB_VERSION` the Action exports is for its receipt line.
- **scanners module:** `action.yml` installs `scanners/requirements.txt` when it exists.
- Review threads beyond the first 100, or 100 comments in a thread, are not searched for the
  resolve; the reply still lands.
- The check run's `summary` is truncated at GitHub's 65,535-character limit with a note; a very
  long receipt section is read in the artifact.
