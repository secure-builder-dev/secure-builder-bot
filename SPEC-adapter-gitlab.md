# Spec: adapter-gitlab

Module `adapter-gitlab` of the capability map. Status: built on `wip/adapter-gitlab`, from
`epic/core`; the decisions below were taken during the build and are confirmed by the human who
merges it.

## Objective

`adapter-gitlab` is how the bot runs on GitLab (docs/PRD.md § Platforms, the GitLab column): a
CI/CD component a user includes with one line, and a publisher that turns the run directory core
wrote into what a merge request shows — one note with the verdict block, one discussion per finding
on a diff line, the code quality widget, the receipt as a job artifact. It knows nothing about the
gates; it reads core's files and talks to GitLab's REST API, and nothing else.

User stories, from the PRD:

- As a team on GitLab, I add one `include:` line and the same three-line `.securebuilderbot.yml`,
  and every gate I turned on runs on my next merge request (§ The install experience).
- As an author, I see the verdict on the merge request and each finding on the line it concerns,
  with its severity and what would fix it, and nothing posted twice (§ What the user sees, § Noise
  budget).
- As the bot's operator, the component asks for nothing beyond the job token's scope, and the one
  token it needs is named, never written (§ Security of the bot itself).

Success looks like: a merge request pipeline that includes the component runs `core/run run`,
posts the note and the discussions, feeds the widget, and is red when any gate failed.

## Tech Stack

- TypeScript 5.9 on Node 22, ESM, run from source with `tsx` (no `dist/`); strict tsconfig
- vitest 4 with v8 lcov coverage; eslint 10 flat config with typescript-eslint (type-aware) and
  eslint-plugin-security, warnings failing the run
- A fetch-based GitLab API client, handed its `fetch` so every test runs against an in-memory GitLab
- The component is YAML; the tests parse it with PyYAML (core's one dependency) rather than add a
  YAML package
- Dependencies: `tsx` at run time; the rest dev only. Exact pins, every row in
  `docs/architecture/DEPENDENCY_POLICY.md` § 4C

## Commands

```
Install:          npm ci --prefix adapter-gitlab          (CI: .github/workflows/constraints.yml)
Tests + coverage: cd adapter-gitlab && npm test            (vitest run --coverage → coverage/lcov.info)
Lint:             cd adapter-gitlab && npm run lint        (eslint . --max-warnings 0)
Typecheck:        cd adapter-gitlab && npm run typecheck
Advisories:       cd adapter-gitlab && npm audit
Publish (CI):     npx tsx src/main.ts --project-dir "$CI_PROJECT_DIR" --report "$CI_PROJECT_DIR/gl-code-quality-report.json"
Controls:         make verify-controls · make mutate-controls   (rows CM-70..73)
Every edit:       make check-fast · Task done: make check-task · Docs: make check-docs
```

`make test` and `make lint` still iterate `backend frontend`; another builder is generalising those
loops to every directory with a `package.json`. Until that lands, this module's scripts are run
directly, as above.

## Project Structure

```
adapter-gitlab/
  package.json  package-lock.json  tsconfig.json  eslint.config.js  vitest.config.ts
  templates/
    secure-builder.yml   → the CI/CD component: spec: inputs:, one job on merge request pipelines
    README.md            → the include line, the three-question config, what the MR shows
  src/
    main.ts        → the command line: run directory + CI variables → one publish; exit 0/1/2
    publish.ts     → the note upsert, discussions with a position, dedupe, resolve what is gone
    gitlab-api.ts  → the REST API v4 client over an injectable fetch; every body through secrets.ts
    run-dir.ts     → receipt.json + verdict.json → one RunRecord; refuses what is not a run
    markdown.ts    → the verdict block, the note, a finding's body, severity markers, fix sentences
    secrets.ts     → core's secret patterns ported (+ GitLab's token shape); the refusal
    codequality.ts → gl-code-quality-report.json in the CodeClimate shape
    templates.ts   → the include snippet and the commented config, for the cli module's init
  tests/
    *.test.ts, fake-gitlab.ts (an in-memory merge request behind fetch), yaml.ts (PyYAML bridge)
    fixtures/run-dir/  → a run directory core itself produced: scan pass, qa fail with one lined
                         and one lineless finding
```

## Interfaces

**The component** (`templates/secure-builder.yml`). Inputs: `version` (`latest`), `base`
(`$CI_MERGE_REQUEST_DIFF_BASE_SHA`), `python_version` (`"3.12"`), `token_variable`
(`SECURE_BUILDER_TOKEN`: the NAME of the CI/CD variable holding a project access token with the
`api` scope). Both jobs clone the bot at the newest release tag `vX.Y.Z` (by version order, never
a branch; no tag is a refusal) for `latest`, or tag `v<x.y.z>` for a pin (`SECURE_BUILDER_SOURCE`
points an air-gapped install at a mirror). Three jobs, `rules:` merge request pipelines only:
`secure-builder` `pip install`s core's requirements and runs `core/run run --base <base> --head
$CI_COMMIT_SHA --part untrusted` (Scan and QA, which run the merge request's own code), its exit
code core's, and copies the one run core reported to `secure-builder-untrusted/`, which it uploads
(`when: always`); it declares no environment and is given no token or key.
`secure-builder-verdict` `needs:` it with its artifacts, runs `when: always`, declares the
environment `secure-builder-sentinel` that Sentinel's model key is scoped to, runs no merge request
code, and runs `core/run run … --part trusted --untrusted-run secure-builder-untrusted`: Sentinel and
the verdict, the gates job's run read as its claim. It uploads `gate-records/runs/`.
`secure-builder-publish` `needs:` the verdict job with its artifacts, runs `when: always` in the
`resource_group` `secure-builder/mr-$CI_MERGE_REQUEST_IID` (one publish at a time per merge
request), declares the
environment `secure-builder` (`action: prepare`) that the token's variable is scoped to (README),
installs Node 22 from the official tarball checked against its published checksum, `npm ci
--omit=dev`s the publisher and runs it; it runs no merge request code, and uploads
`gl-code-quality-report.json`, also as `reports: codequality:`. The token input is interpolated
exactly once, into the publish job's variable `SECURE_BUILDER_TOKEN_VARIABLE`; the publisher reads
`process.env[<that name>]` and nothing writes it. The component names no model key; the README scopes it to the verdict job's environment.

**The publisher** (`src/publish.ts`):

```ts
publish({ api: MergeRequestApi, run: RunRecord, headSha: string }): Promise<PublishOutcome>
// PublishOutcome: { note: { action: "created" | "updated", id }, discussions: { created, alreadyPosted, resolved }, lineless }
findVerdictNote(notes: Note[]): Note | undefined            // CM-72: the oldest non-system note with the marker
alreadyPosted(discussions, path, line, body): boolean       // CM-70: same path, line and body, by the bot
```

Every body, and the code quality report's content, is passed through `refuseSecrets` (CM-71)
before the report is written and before the first request; on a refusal no report is written and
nothing is sent. The API client refuses again per request. The note starts with `<!-- secure-builder:verdict -->`, a discussion
with `<!-- secure-builder:finding -->`; a discussion is the bot's when its first note carries the
marker and a position. A bot discussion whose finding is absent from this run gets the reply
`Not found on <sha>` and is resolved; a resolved one is left alone; a human's notes and discussions
are never touched.

**The client** (`src/gitlab-api.ts`): `mergeRequestApi({ apiV4Url, projectId, mergeRequestIid,
token, fetch? })` with `diffRefs`, `listNotes`, `createNote`, `updateNote`, `listDiscussions`,
`createDiscussion(body, position?)`, `replyToDiscussion`, `resolveDiscussion`. `PRIVATE-TOKEN`
header, JSON bodies, `per_page=100` following `x-next-page` for at most 50 pages; past that
the list is refused, never used partially. A failure is `GitLabApiError` with the
status and the path, never the response.

**The run record** (`src/run-dir.ts`): the shapes of `core/securebuilderbot_core/runner.py`'s
receipt and `verdict.py`'s verdict, read into `RunRecord { runId, base, head, branch, depth,
profile, relaxations, gates: GateRecord[], overall, exitCode }`. `selectRun(projectDir, sha,
named?)` picks the one run to publish: the one untracked run under `gate-records/runs` whose
receipt head is exactly `sha` (`CI_COMMIT_SHA`), or the one `--run-dir` names, held to the same
tests (`runRefusal`, CM-73: tracked by git, or another head, is refused). None, or more than one,
exits 1 naming each directory passed over and why.

**For the cli module** (`src/templates.ts`): `includeSnippet({ group?, version })` and
`configTemplate({ profile, gates, sentinel: "ci" | "action" | "self-hosted" | "off", version })`.

## Testing Strategy

- vitest under `adapter-gitlab/tests/`, one file per source module, against a run directory core
  produced and an in-memory GitLab (`fake-gitlab.ts`) that paginates and lists individual notes
  among the discussions as the real API does. No mocking of modules; the only fake is the
  network, injected as `fetch`.
- The component is parsed with PyYAML and its script lines with `bash -n`; the config templates
  are written to a temp dir and run through `core/run config check`.
- Secret shapes in tests are assembled from pieces, so no test file carries one.
- Coverage: 99% of lines in `src/` (`npm test` prints the table); the changed-line check in
  `make check-task` measures Python only today.
- The three manifest rows are proven by `make mutate-controls` (see Decisions) and were also proven
  by hand: with the mutation applied to the source (`alreadyPosted` → `return true`,
  `refuseSecrets` → `return`, `findVerdictNote` → `return undefined`) `npm test` goes red:
  CM-70 6 failures (5 in `publish.test.ts`, 1 in `main.test.ts`), CM-71 13 failures (10 in
  `secrets.test.ts`, 1 each in `gitlab-api.test.ts`, `publish.test.ts`, `main.test.ts`), CM-72
  3 failures (`publish.test.ts`); the tree restored, 89 pass again.

## Boundaries

- **Always:** red test first, then green; `make check-fast` before every commit; every body
  through the secret refusal before a request; the token only ever by the name of its variable;
  the bot's own notes found by marker, never by author or position alone; no `dist/`, no
  suppression comments, zero lint warnings.
- **Ask first:** a dependency beyond those in DEPENDENCY_POLICY.md § 4C; a change to the note or
  finding markers once a GitLab has them; a change to the component's input names; editing the
  Makefile loops (another builder's); a different clone source for the bot.
- **Never:** push to, merge into or edit a user's branch — the bot posts notes and discussions
  only; schedule anything in a user's repository; write a secret value to a file, log, note or
  artifact; import from `adapter-github/`; a presigned or floating anything.

## Success Criteria

1. `npm test`, `npm run lint`, `npm run typecheck`, `npm audit` green in `adapter-gitlab/` —
   verified: 89 tests pass with 99% line coverage; eslint reports 0 problems at `--max-warnings 0`;
   `tsc --noEmit` is silent; `npm audit` finds 0 vulnerabilities. `make check-task` green —
   verified at the last commit (the `test`/`lint` targets still skip this directory until the
   Makefile loops are generalised; the npm scripts were run directly, as above).
2. With the fixture run directory and a fake fetch — verified by `tests/publish.test.ts` and
   `tests/main.test.ts`: one note created with both gates' sections; one discussion with the
   position `{ position_type: text, base_sha, start_sha, head_sha, new_path, old_path, new_line: 117 }`
   from the merge request's diff refs; the lineless finding in the note and not in a discussion;
   a second run `PUT`s the same note and posts nothing else; a run where the finding is gone replies
   `Not found on <sha>` and `PUT`s `resolved: true`, once; a secret-shaped body makes `main` exit 2
   with zero requests sent; `tests/codequality.test.ts` validates the JSON against the shape with
   exactly one entry.
3. The component YAML — verified by `tests/component.test.ts`: parses as two documents, carries the
   `spec: inputs:` block with the four inputs and their defaults, the job's only rule is
   `$CI_PIPELINE_SOURCE == "merge_request_event"`, the token input is interpolated exactly once
   into a variable name, `$SECURE_BUILDER_TOKEN` is never expanded, and no script line writes a
   token anywhere. Not verified: the job against a real GitLab (none is reachable from here).
4. `configTemplate({ profile: "il6", gates: [scan, qa, sentinel], sentinel: "self-hosted" })` —
   verified by `tests/templates.test.ts`: written to a temp dir and passed to
   `core/run config check --config`, which prints `config ok: profile il6 (370 controls) · gates
   scan, qa, sentinel · version latest` and exits 0.

## Decisions taken during the build

- **The job installs Node from the official tarball**, checksum-verified against
  `SHASUMS256.txt`, on the `python:<version>` image, rather than a third-party image that ships
  both runtimes or a piped installer script. `python_version` stays an input as the brief names it.
- **The bot is cloned from GitHub by default**, `SECURE_BUILDER_SOURCE` overriding it for a mirror;
  `latest` is `main`, a pinned version is the tag `v<x.y.z>`. A component ref `@~latest` is what
  `includeSnippet` emits for `latest`, `@<x.y.z>` plus `inputs: version:` for a pin, so the
  component and the bot are pinned together.
- **Severity markers are text**, `**[BLOCKING]**` and `[advisory]`, visually distinct in GitLab's
  markdown without emoji. The code quality report maps blocking → `blocker`, advisory → `minor`;
  `major` is in the widget's vocabulary and unused.
- **Dedupe compares bodies trimmed**, exact otherwise: both sides are generated by the same code,
  and GitLab may trim trailing whitespace on storage.
- **The secret patterns gain `glpat-`**, GitLab's own token shape, on top of core's.
- **eslint 10.12.0, not the 9.x line**, which npm reports as no longer supported; the one rule off
  in the config is `security/detect-non-literal-fs-filename`, with the reason beside it: every fs
  call in the publisher takes the run directory named at run time.
- **The control tools cover TypeScript too.** `make verify-controls` indexes only the roots and
  extension `project.config.yaml` names, and `make mutate-controls` runs only its test command, so
  three TypeScript rows under Python-only keys read as unwired and unproven, and `make check-task`
  (which runs `verify-controls`) would be red. `qa/scripts/_lib.sh:gate_use_control_roots`
  now accepts several extensions in `CONTROL_SRC_EXT` (its own commit, governance), and
  `project.config.yaml` names both roots, `py ts`, and a test command that is both suites. The
  mutation tool's TypeScript mutations were already there; the by-hand proof above is the same
  result without the tool. This is the one change outside the brief's integration points, and the
  reason is that the brief's "`make check-task` green" could not otherwise hold with the rows the
  brief requires.

## Changes outside adapter-gitlab/ this module needed

- `.github/workflows/constraints.yml`: `npm ci --prefix adapter-gitlab` before `make check-full`.
- `.gitignore`: `coverage/`.
- `docs/security/CONTROL-MANIFEST.md`: rows CM-70, CM-71, CM-72 and the preamble on TypeScript rows.
- `docs/architecture/DEPENDENCY_POLICY.md`: § 4B, the Node dependencies.
- `CAPABILITY-MAP.md`: this module's Spec column.
- `project.config.yaml` and `qa/scripts/_lib.sh` (+ its self-test, `qa/tests/mutate-controls-test.sh`; the qa module moved both): the control tools on
  both languages, as above.
- `tasks/plan-adapter-gitlab.md`, `tasks/todo-adapter-gitlab.md`.
