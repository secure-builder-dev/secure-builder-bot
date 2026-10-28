# Spec: sentinel

Module `sentinel` of the capability map. Status: built on `wip/sentinel`; the decisions below were
taken during the build and are confirmed by the human who merges it.

## Objective

`sentinel` is the third gate: does the code keep every user in their lane, against the chosen
baseline? It is a cold reviewer with no build context. It reads the diff, the control manifest and
the profile's checklist, asks a model through the user's own key, and returns a verdict with a
citation or an N/A reason for every item. A light range gets the checklist pass. A deep range also
gets the Control Completeness review of each manifest control the diff touches, the adversarial
review and the edge-case hunt. It is the only part of the bot that reaches a model endpoint, and it
sends the diff and the files the checklist names, nothing else.

User stories, from the PRD:

- As a team lead on Full, my pull request gets `Secure Builder / Sentinel`, red on a blocking
  finding, with each finding on its diff line marked as coming from a cold reviewer.
- As an assessor, the receipt's Sentinel section names the provider and model, every request's size
  and the files it carried, each checklist item's answer, the Control Completeness blocks, and the
  baseline controls the reviewer did not assess.
- As a maintainer, a pull request whose description tries to talk the reviewer into a pass changes
  nothing. The lines are removed before any prompt is built, and the receipt counts them.

Success looks like: `make proofset` replays every case green through the real pipeline. And
`core/run run` with Sentinel on and no key is not_run, naming the variable, never a pass.

## Tech Stack

- Python 3.12, standard library only. The checklist is read with core's PyYAML; there is no new
  dependency and no vendor SDK. The providers call the endpoints over `http.client` and `ssl`.
- Markdown for the reviewer's agent definition (`sentinel/agent.md`). The two review skills are
  read as written from `engine/skills/` (see Decisions).
- pytest and pytest-cov for this module's tests. Tooling as `CONSTRAINTS.md` names it.

## Commands

```
The gate, through core:   core/run run --base origin/main --head HEAD --config <a config with sentinel in gates>
                          (SB_CONFIG names the same file for the gate; SB_MODEL_KEY, or the secret key_secret names, holds the key)
The proof set:            make proofset   ·   sentinel/run proofset [--case NAME]   (part of make check-code)
Tests:                    make test   (pytest over every module; sentinel/tests among them)
Control rows:             make verify-controls · make mutate-controls ARGS="--only CM-50,…,CM-59"
Every edit / task end:    make check-fast · make check-task · make check-docs
```

## Project Structure

```
sentinel/
  __init__.py                   → makes sentinel.tests its own package beside qa.tests and core/tests
  agent.md                      → the reviewer's agent definition: the system prompt of every request
  run                           → the module's command line (sentinel/run proofset), every package on the path
  checklist/
    base.yml moderate.yml high.yml   → every item of engine/SENTINEL-CHECKLIST.md and standards/data/checklists/IL6.md, word for word, with its controls
    control-completeness.yml    → the six questions, word for word from the checklist's table
  securebuilderbot_sentinel/
    __init__.py                 → GATE, the factory core looks up by name (runner.py:discover_gate)
    __main__.py                 → `proofset`
    checklist.py                → load_items, items_for(profile), gaps(profile, assessed), cc_questions; citations verified on load
    sanitize.py                 → is_instruction_like, sanitize_text, sanitize_diff, redact_secrets, data_block
    inputs.py                   → withheld, may_send, lock_packages, build_request → ReviewRequest
    schema.py                   → extract_json, validate, parse_checklist / parse_cc / parse_adversarial / parse_edge_case, SHAPES
    review.py                   → the four prompts, ask (one retry), review, place, findings_of, assessed
    gate.py                     → SentinelGate, without_key, missing_key, status_of
    replay.py                   → the proof set's replay
    providers/
      __init__.py               → Provider protocol, ProviderError, make_provider, DEFAULT_ANTHROPIC_MODEL
      http.py                   → post_json and connect: one POST, an HTTPS_PROXY tunnel, NO_PROXY
      _base.py                  → one retry on a busy endpoint; errors that name the status, never the key
      anthropic.py              → Messages API, anthropic-version 2023-06-01
      openai_compatible.py      → chat completions; the self-hosted provider is this with the user's base URL
      fake.py                   → scripted answers by request kind or prompt hash; every call recorded
  tests/
    conftest.py                 → a real throwaway git repository; the context core would build
    test_checklist.py test_sanitize.py test_inputs.py test_schema.py test_providers.py
    test_review.py test_proofset.py test_dogfood.py
    proofset/                   → test data under tests/, so the QA gate never counts the sample apps as production code
      README.md                 → what the proof set proves and what it does not
      <case>/base/ head/ pr.md expected.yml responses.yml   → five cases
```

## Interfaces

**What core sees.** `securebuilderbot_sentinel.GATE()` returns a `SentinelGate` with `name =
"sentinel"` and `run(ctx) -> GateResult`. Core's runner finds it by name. It builds `ctx` (the
merge base, the head, the profile, the depth from `classify` or `sentinel.depth`, and the run
directory `<run>/sentinel`), and stops before this gate when scan or QA did not pass.

**What the gate reads.**

- The config: the file named by `SB_CONFIG`, else `.securebuilderbot.yml` at the checkout root.
- The key: from the variable `sentinel.key_secret` names.
- The PR: `SB_PR_TITLE` and `SB_PR_BODY`, or a file named by `SB_PR_CONTEXT` (JSON with `title`
  and `body`, or Markdown with the title on its first line). Commit messages come from
  `git log base..head`.
- QA's proof: `<run>/qa/mutate-controls.log`, when QA ran in this run.

**Statuses.**

- `fail`: a blocking finding.
- `yellow`: the diff was over `sentinel.max_diff_bytes` and files were left out.
- `not_run`: no config, no key, an endpoint error, or an answer unreadable twice.
- `pass`: otherwise.

**Config keys added to core** (`core/securebuilderbot_core/config.py`):

- `sentinel.endpoint`: an http or https base URL with no credentials, query or fragment (a mirror
  or a self-hosted server).
- `sentinel.model`: a model id; the default is `claude-sonnet-5-5` for anthropic, and openai and
  self-hosted need one.
- `sentinel.max_diff_bytes`: a whole number of bytes, at least 1000; default 300000.

**The provider interface.** `complete(system: str, user: str, *, max_tokens: int) -> str`. A
failure raises `ProviderError`, whose message names the host or the HTTP status, never a header.
`make_provider(config.sentinel, key)` picks the provider:

- `anthropic`: the Messages API at `https://api.anthropic.com`, or the endpoint mirror.
- `openai`: chat completions at `https://api.openai.com`, or the endpoint.
- `self-hosted`: chat completions at the endpoint.

**The receipt section.**

- `provider` {name, model}, `depth`, `profile`, `checklist_blocks`, `items`.
- `requests` [{n, kind, attempt, bytes, files, answered}] and `sent_to_model_endpoint` (core lifts
  this to the top level).
- `checklist` [{id, answer, controls, evidence or reason, assessed}].
- `control_completeness` (a block per touched control, its text in the checklist's printed shape),
  `adversarial` {examined, findings}, `edge_case` {findings}.
- `sanitized_lines`, `redacted_secrets`, `not_sent`, `omitted_for_budget`, `named_files_missing`,
  `manifest_trust`, `notes`.
- `controls_assessed` and `controls_not_assessed`.

Every request and every answer is also kept under `<run>/sentinel/requests/` and `responses/`.

## How a review runs

1. **Inputs** (`inputs.py`), from git at the head only.
   - **The diff.** Each changed file's diff is sanitized, redacted and wrapped in a data block.
     Environment files, deployment values files, Terraform variables, key material and
     credentials files, and binaries are replaced by their path and a note. A lockfile is sent as
     its changed `name@version` lines only (package-lock, npm-shrinkwrap, go.sum, Cargo.lock,
     poetry.lock, uv.lock); any other lockfile format is withheld whole.
   - **The named files.** The manifest (`qa.manifest`), the config when it is inside the checkout,
     and each file an item of the profile `reads`. Each passes the same `may_send`.
   - **The budget.** The diff is cut by whole files at `sentinel.max_diff_bytes`, and the omitted
     files are listed.
   - **The manifest rows.** A row is touched when its implementation file changed or its row
     changed.
2. **Sanitizer** (`sanitize.py`). Each instruction-like line is replaced whole by `[removed:
   instruction-like text]` and counted. A diff line keeps its `+`, `-` or space prefix, and a hunk
   keeps its header, so line numbers hold. Matching runs on an NFKC-normalised copy with format
   characters dropped. A line carrying the data-block delimiter `<<<SB-` is removed too, so an input
   cannot close its own block. Secret-shaped strings are redacted by core's rule.
3. **Requests** (`review.py`). Each request is its own call, with `Request: <kind>` on the first
   line.
   - `checklist`: every item of the profile, with its controls and STIG rules.
   - `control_completeness`: the touched rows and the six questions; deep only, and only when a
     control is touched.
   - `adversarial` and `edge_case`: the two skills' text, the first with a JSON shape replacing its
     Markdown list, the second in its own JSON shape; deep only.
4. **Answers** (`schema.py`). The last fenced JSON block, validated against its schema and its
   request: every item answered exactly once, a citation with evidence, an N/A with a reason, a
   finding citing one of its item's controls, an adversarial finding citing an active NIST control,
   every touched control given its six answers. A failure is retried once, with the error quoted;
   a second failure is not_run.
5. **Verdict** (`gate.py`).
   - **Placement.** A finding keeps its line only when the diff that was sent shows it, and its path
     only when the file was sent. Each message ends with "(cold reviewer, no build context)".
   - **Control Completeness.** A question answered PASS, or left blank, is a blocking finding.
   - **Edge cases** are advisory findings, rule id `edge-case`.
   - **What counts as assessed.** `controls_assessed` holds the controls of items answered `cited`
     with evidence from a file that was sent, and nothing else.

## Testing Strategy

- pytest under `sentinel/tests/`. The fixtures are real temporary git repositories, never mocked.
  The model is the fake provider, scripted per request kind, and every call it receives is recorded,
  so a test asserts exactly what was sent.
- No test reaches the network. The HTTP transport is handed a fake connection. The real one is
  constructed in one test (an `HTTPSConnection` and its proxy tunnel) and never opened.
- The proof set replays five cases through the real gate. The replay is tested against broken
  copies of the cases: a missed finding, an extra one, a wrong depth or verdict, an instruction
  that reached the model, a verdict that moves without the PR description, and wrong counts. Each
  must be named, so a replay that compares nothing cannot pass.
- Coverage of the package: 98% of its lines. `make check-task` measures 93.4% of the lines this
  branch added, across every module.

## Boundaries

- **Always:** every input is data in a delimited block; every answer is validated before it is
  believed; not_run whenever the gate could not do its job; the key's name in a reason, never its
  value; the receipt lists exactly what was sent.
- **Ask first:** a new provider; a checklist item, a citation or a question (governance:
  `engine/GOVERNANCE.md`); widening what is sent; a new dependency.
- **Never:** a network call in a test; reading `.env*`, a values file, `*.tfvars` or a lockfile
  beyond names and versions; a key in a log, receipt, comment or file; a pass from an unreadable
  answer; editing a user's branch.

## Success Criteria

1. **Every checklist item's controls verify; il4 runs base and moderate only; `gaps(il6)` is long.**
   Verified by `test_checklist.py`. Every control and STIG id of all 36 items goes through
   `verify_citations`; a bad, withdrawn or unknown id is refused on load; and every markdown item
   has a YAML twin with the same text. `items_for(il4)` is 26 items, base and moderate. `gaps(il6)`
   is the High baseline minus the cited controls: **339 of 370**. The checklist cites 34 controls,
   31 of them in the High baseline. At il4 the gap is 265 of 287; `none` has no baseline and no gap.
2. **A request sends what it should and nothing else.** Verified by `test_review.py`, with the
   fake provider:
   - A light request is one `checklist` call carrying every item, the diff and the named files,
     and no Control Completeness question.
   - A deep request on a diff touching CM-02 sends the six questions for CM-02 only; CM-01 is
     nowhere in it.
   - `sent_to_model_endpoint` is the diff's files plus the manifest (plus the config when it is in
     the checkout).
   - An `.env` in the diff is replaced by its path and a note, and its value is in no request and
     no file under the run directory.
3. **An injection in the PR body is removed before the prompt is built, and counted.** Verified by
   `test_review.py`, `test_sanitize.py` and the `pr-talks-reviewer-into-pass` case: three lines
   removed, `sanitized_lines: 3`, none of their words sent, the same verdict without the
   description.
4. **A malformed answer is retried once, then not_run; a blocking finding fails.** Verified by
   `test_review.py`. A malformed answer gets one retry quoting the parse error, then not_run with
   "the reviewer's answer could not be read". A blocking finding is `fail`, and the finding carries
   its path, line, control id and the cold-reviewer suffix.
5. **No key is not_run naming the variable, and the key is never written.** Verified by
   `test_review.py`, and end to end in a clone: `core/run run` with Sentinel only and no
   `SB_MODEL_KEY` printed "Sentinel: NOT RUN — the model key is not set: the environment has no
   SB_MODEL_KEY …" and exited 1. A secret-shaped key, and a plain one, echoed back by the model in
   a finding and in evidence, appear in no file under the run directory and in no line of output
   (the run went through core's own runner).
6. **Everything replays and every check is green.** `make proofset` replays 5/5 cases green.
   `make check-task` is green (check-code: all 13 code checks passed, proofset among them),
   `make check-docs` is green, and `make mutate-controls` proves every row, CM-50..CM-59 among them.

## Decisions taken during the build

- **The checklist's markdown has no ids, and it is not edited here.** So the twin key is the text.
  Each YAML item carries its markdown bullet word for word, plus the file it came from; the test
  matches both ways. Ids are `B-nn`, `M-nn` and `H-nn` by block.
  - Base holds the code-level items, the ones OWASP speaks to.
  - Moderate holds the engineering-process items and the remaining "Also verify" lines.
  - High holds IL6.md's seven lines plus three items for the PRD's High topics that IL6.md has no
    line for: session lock, non-repudiation and covert channel. Cross-domain is IL6.md's CDS line.
- **STIG ids come from the redistributed index only.** The Application Security and Development
  STIG (APSC-DV) is not redistributed, so items cite application SRG rules the index carries,
  verified like the NIST ids.
- **`applies_when` is said to the reviewer, never used to skip an item.** A mechanical skip would
  need a detector for each tag, and a wrong one would be a silent hole.
- **What counts as assessed is narrower than the brief's minimum.** A control is assessed only
  when its item was answered `cited` with evidence from a file actually sent. A finding answer does
  not count, and neither does evidence citing a file the reviewer never saw.
- **The two review skills are read in place from `engine/skills/`, not moved.**
  `.claude/agents/gate.md` cites them there and may not be edited here.
- **The edge-case hunt keeps its own output shape, so its findings are advisory.** That shape has
  no severity and no control id, so its findings use rule id `edge-case`. The adversarial review
  gets a JSON shape (in place of its Markdown list) with severity and a NIST control.
- **The sanitizer's patterns are the brief's, with word boundaries and a normalised copy.**
  `approve_request()` and `systemctl` survive. A line like `system: x` in code is removed, and the
  reviewer sees it was. A false removal costs one line; a missed instruction can cost the verdict.
- **Secret-shaped strings are redacted before anything is sent** (core's rule), as well as before
  anything is written. The PRD forbids sending secrets, whoever committed them.
- **The transport is `http.client`, not `urllib.request`.** The URL comes from config, and ruff's
  S310 rule flags `urlopen` on such a URL; suppressing it is forbidden. `http.client` opens exactly
  the scheme it is given. `HTTPS_PROXY` is honoured through a CONNECT tunnel, and `NO_PROXY` by
  host suffix.
- **The Anthropic request has no `thinking` and no sampling parameters, and refusals are not
  rerouted.** Only `text` blocks are read. A `refusal` stop reason is a ProviderError (not_run).
  There is no server-side fallback, so the receipt's model is the model that answered.
  `max_tokens` is 16000.
- **The gate finds its config through `SB_CONFIG`.** `GateContext` carries no config path, so CI
  sets `SB_CONFIG` to the file it passes to `core/run run --config`; otherwise the root
  `.securebuilderbot.yml` is read. A follow-up below proposes core carry it.
- **A provider missing its endpoint or model is valid config, refused by the gate at run time.**
  The setup PR the adapters write says `provider: self-hosted` before the user has a server to
  name, so core does not refuse that file; the gate is not_run and names `sentinel.endpoint` or
  `sentinel.model`.
- **The dogfood job has no `continue-on-error`.** A red reviewer is a red check. The job runs only
  when `SB_MODEL_KEY` is set and says so in a notice when it is not. Fork PRs, which get no
  secrets, take the notice path.

## Changes outside sentinel/ this module needed

- `core/securebuilderbot_core/config.py` (+ `core/tests/test_config.py`): `sentinel.endpoint`,
  `sentinel.model` and `sentinel.max_diff_bytes`, each validated with its line number. An endpoint
  carrying credentials is refused without repeating it.
- `core/securebuilderbot_core/classify.py` (+ `test_classify.py`): `sentinel/` is gate tooling,
  always deep, as `core/`, `scanners/` and `qa/` are, so a change to the reviewer is reviewed with
  the full depth.
- `core/tests/test_runner.py`: the not-installed-module test marks sentinel not installed, as it
  already did the scanners, now that the module exists. One line added, no assertion changed.
- `scripts/check-boundaries.sh` and `.boundaries`: `sentinel` is a script group, with its edges to
  core, standards and qa, and core's edge to it, each with its reason.
- `Makefile`: `proofset`, appended to `CHECK_TARGETS` so `check-code` runs it.
- `project.config.yaml`: the package, the test directory and the conftest in the `CONTROL_*` keys.
- `docs/security/CONTROL-MANIFEST.md`: CM-50..CM-59, each proven by mutation.
- `.securebuilderbot.yml`: still `gates: [scan, qa]`; the comment says why.
- `.github/securebuilderbot-full.yml` and the `sentinel` job in `.github/workflows/scan.yml`: all
  three gates in CI. **The maintainer turns it on by adding `SB_MODEL_KEY` as a repository secret.**
- `docs/architecture/DEPENDENCY_POLICY.md`: a note that the module adds no dependency.
- `CAPABILITY-MAP.md`: this module's row names this spec.

## Not done here, and why

- **No real model has run the proof set.** That needs a key, and no test may touch the network. The
  scripted answers prove the pipeline, not the model; the README in the proof set says so.
- **Light depth is checklist only, not "checklist and scan verdict".** The scan gate's result is not
  on `GateContext`; when the scan failed, Sentinel never runs at all.
- **The proof set's fixture code is deliberately buggy.** It is not under a `tests/` directory, so
  CI's semgrep scans it. Its findings at ERROR severity, if any, could not be checked here, because
  the semgrep registry is unreachable from this sandbox.

## Gate run 1: what the cold reviewer found, and how each is closed

- **S-01, the key in the receipt.** A key stored with a trailing newline broke the Authorization
  header. The resulting ValueError, header and all, reached core's crash handler and every run file.
  Now:
  - the key is stripped;
  - a key with a control character, inner whitespace, a quote, a backslash or a non-ASCII character
    is not_run, naming the variable (CM-58);
  - every exception after the key is read becomes not_run, with the key scrubbed from its reason.
- **S-02, paths as an injection channel.**
  - Every author string printed into a prompt (a changed path, an omitted path, a touched manifest
    row) is JSON-quoted ASCII with its angle brackets escaped, and sits inside a data block.
  - The receipt counts the changed paths that needed it, as `unsafe_paths`.
- **S-03, environment and values files sent.** `withheld()` is case-insensitive and covers:
  - any `.env`, `*.env` and `.env.*`, and direnv's .envrc;
  - any `values*.y?ml`;
  - `*.tfstate*` and `*.tfvars*`;
  - credentials and secrets files: `credentials*.json`, `.git-credentials`, `.netrc`, `.npmrc`,
    `.pypirc`, `.pgpass`, `kubeconfig`, `*.kubeconfig`, `.docker/config.json`, `.kube/config`,
    `secrets*.y?ml`, and service-account key JSON;
  - key material.
- **S-04, a file named `*`.** Every git call that takes a path runs with `--literal-pathspecs`.
- **N-03, the pull request's own config.** When the config is in the checkout, its `sentinel` section
  (provider, endpoint, model, key_secret, depth, max_diff_bytes) is read at the base commit.
  - A change to it in the pull request is reported as `config_changed_by_pr` and as an advisory CM-3
    finding, and the base values are used.
  - A base without the config is not_run. The dogfood job therefore runs Sentinel only once
    `.github/securebuilderbot-full.yml` is on `main`.
- **N-04, plain http.** `sentinel.endpoint` must be https unless its host is loopback.
- **N-05, the CI job.** The sentinel job uses `persist-credentials: false`, installs every npm package
  from its lockfile, and reads `origin/main` from the full checkout.

Not changed, and left to a decision outside this module:
- the profile (and so the checklist) still comes from the head's config, as core resolves it for
  every gate;
- `qa.manifest` is still the head's.
