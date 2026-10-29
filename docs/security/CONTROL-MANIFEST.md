# Control Manifest

> Seeded into your project by `make sync-engine` on first sync and never overwritten after that. This file is yours: replace the placeholder rows with your project's controls.

**Purpose.** One row per security control, naming the code that implements it, the infrastructure
artifact it depends on, and the test that proves it. `qa/scripts/verify-controls.sh` checks every
row against the working tree at each gate.

**Why this exists.** A passing test proves a function behaves correctly. It does not prove anything
*calls* that function, and it does not prove the deployment artifact the control depends on still
exists in the repo. Both fail silently, and a diff-scoped gate cannot see either:

- A control can be written, reviewed, gated and fully unit-tested with **no production call site at
  all**. Its tests pass the entire time. Nothing in a per-story gate asks "does anything call this?"
- A Kubernetes artifact a control depends on — a NetworkPolicy, a shipper Deployment — can ship in
  one story and be deleted later by a commit outside the engine. The test file that reads it then
  throws at collection, taking every sibling test in that file down with it, and the suite reports
  one red file rather than fifteen unenforced controls.

**The rule this encodes:** a control is not finished when it is tested. It is finished when a line
of running code calls it, and that line has a name.

**Call sites are never read from this file.** The verifier recomputes them from the tree on every
run. A call site is a direct call (`verifyToken(req)`) **or** a by-reference wiring — the shape
Express middleware, ORM hooks and handler arrays actually use (`app.use(requireAuth)`,
`router.get('/x', requireRole, h)`, `hooks: { beforeFind: scopeTenant }`). Comment lines and
`import`/`export … from` lines are ignored — a symbol named only in a doc comment or an import is
not a call site, and that exact false positive is what lets a dead control look wired.
`make gate-selftest` proves each of these cases against a fixture.

---

## How to use it

- **At every gate.** `make verify-controls` runs from `make gate-state`. A `FAIL` is a finding for
  `gate-records/gate-permanent-checks.md` — it is *not* a fix for the epic under gate.
- **When a ticket adds a control.** Add its row in the same commit. Under the Sentinel checklist, a
  control-shaped diff with no manifest row is a blocking finding — without the row,
  `make verify-controls` and `make mutate-controls` have nothing to check and pass silently.
- **When a row FAILs.** Register it and open a retro task in the plan. Do not fold the
  fix into unrelated work — a control repair belongs on a task of its own, where the gate range
  that covers it says so.

Columns: `id` · `control` · `implementation (file:symbol)` · `required artifact` · `proving test` · `note`

- `implementation` — `path/to/file.ts:symbolName`. The verifier checks the symbol is defined there.
- `required artifact` — a deploy file the control depends on, or `-`.
- `proving test` — a glob relative to the test directory, or `-`.
- `note` — free text; `mutate:<kind>` (middleware|decision|scope|redact|noop) or `mutate:stmt=<code>` tells `make mutate-controls` how to break the control. A table cell cannot contain `|` — write `??` not `||`.

---

## Manifest

This repository's controls are the bot's own: Python under `core/securebuilderbot_core/` and
`scanners/securebuilderbot_scanners/`, `standards/securebuilderbot_standards/` and
`qa/securebuilderbot_qa/`, proved by pytest under `core/tests/`, `scanners/tests/`,
`standards/tests/` and `qa/tests/`. The `CONTROL_*` keys in `project.config.yaml` point both
tools at all four; a proving-test glob is looked for in every listed test directory.
CM-20..CM-27 are the scanners module's (CM-26 and CM-27 its keeping of the bot's secrets from the PR code a scanner runs), CM-30..CM-36 the standards module's, CM-40..CM-45 the
QA gate's own refusals, CM-46..CM-48 the QA gate's keeping of the bot's secrets from the user's code it runs and from what the run keeps.
The two adapters' controls are TypeScript, proved by vitest; their sections below say why
their proving-test column is `-`.
The template's web-app and IL6 deployment rows (token gate, tenant scope, audit store, banner,
egress) do not apply to a command-line tool with no server, and were removed rather than left as
placeholders that read as unfinished work.

| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-01 | A receipt never carries a secret-shaped string | `core/securebuilderbot_core/receipt.py:check_no_secrets` | - | `test_runner.py` | SC-28, SI-12 · mutate:noop |
| CM-02 | Gate output is redacted before anything is written | `core/securebuilderbot_core/receipt.py:redact` | - | `test_runner.py` | SI-12, F-02 · mutate:stmt=return text, 0 |
| CM-03 | A secret-shaped config key holds a CI secret name, never a value | `core/securebuilderbot_core/config.py:_check_secret_shaped` | - | `test_config.py` | IA-5(7) · mutate:noop |
| CM-04 | A partial scan is never a pass | `core/securebuilderbot_core/verdict.py:scan_verdict` | - | `test_verdict.py` | RA-5 · mutate:replace=blocking = dispatch.is_file() or ran < total ~> blocking = dispatch.is_file() |
| CM-05 | Stale CVE data fails the Scan gate | `scanners/securebuilderbot_scanners/gate.py:stale_databases` | - | `test_gate.py` | RA-5(2) · mutate:stmt=return {} |
| CM-06 | A gate handoff needs a green scan of this tree | `core/securebuilderbot_core/precondition.py:check` | - | `test_precondition.py` | RA-5, CA-7 · mutate:replace=if verdict != "PASS": ~> if False: |
| CM-07 | The run stops at the first gate that fails or does not run | `core/securebuilderbot_core/runner.py:run` | - | `test_runner.py` | CA-7 · mutate:replace=stopped = result.status in ("fail", "not_run") ~> stopped = False |
| CM-08 | A failed or unrun gate is never an overall pass | `core/securebuilderbot_core/verdict.py:overall` | - | `test_verdict.py` | CA-7 · mutate:replace=return "fail" ~> return "pass" |
| CM-09 | A range touching gate tooling or a control is reviewed deep | `core/securebuilderbot_core/classify.py:classify` | - | `test_classify.py` | CM-4 · mutate:replace=Classification("deep" if reasons else "light", ~> Classification("light", |
| CM-10 | Every file the scanners wrote is redacted before the run keeps it | `scanners/securebuilderbot_scanners/gate.py:redact_results` | - | `test_gate.py` | SI-12, B-01 · mutate:stmt=return {} |
| CM-11 | A pull request never loosens its own gate: the config in the target branch's tip governs the run (gates, profile, skipped scanners, the exceptions file, mutation, Sentinel), read by blob with replace refs ignored and never through a link; the pull request's own copy is validated and what it changes is reported and applies once merged; only a target with no config yet uses the pull request's copy; a config reached through a linked prefix outside the checkout is still the checkout's, and a directory inside the checkout that is a link is refused | `core/securebuilderbot_core/config.py:governing_config` | - | `test_governing.py` | CM-3, CM-5 · mutate:stmt=return Governing(config=head, source="pull request", changed=()) |
| CM-12 | The commit the config and every excusing list are read from is the target branch's tip (--config-ref, default --base), never the merge base the pull request chooses by branching from an older commit; a base that is the head itself, or a range that edits the CI workflow (.github/workflows, .github/actions, .gitlab-ci.yml, .gitlab), is a relaxation, never a clean pass | `core/securebuilderbot_core/__main__.py:_governing` | - | `test_governing.py` | CM-3, CM-5 · mutate:stmt=return governing_config(head, Path(_toplevel()), _git_out("merge-base", args.base, args.head)) |
| CM-92 | The verdict job reads the untrusted job's receipt only as one core wrote for this range: a regular file under the size cap, a `--part untrusted` run, the same head and merge base; anything else is every carried gate not running | `core/securebuilderbot_core/untrusted.py:_load` | - | `test_parts.py` | SI-10, SC-39 · PRD § Configuration · mutate:replace=if raw.get("head") != head or raw.get("base") != base: ~> if False: |
| CM-93 | Only Scan and QA are carried from the job that ran the pull request's code; a Sentinel result it reports is ignored and Sentinel runs in the verdict job | `core/securebuilderbot_core/untrusted.py:read_untrusted` | - | `test_parts.py` | SC-39, AC-6 · mutate:replace=wanted = [g for g in UNTRUSTED_GATES if g in enabled] ~> wanted = [g for g in ("scan", "qa", "sentinel") if g in enabled] |
| CM-94 | A carried gate's status is marked as that job's claim, and its controls are listed as claimed, never as assessed by the run that publishes | `core/securebuilderbot_core/untrusted.py:_result` | - | `test_parts.py` | CA-2, AU-10 · mutate:replace="controls_claimed": sorted(set(claimed)), "attested_by": ATTESTED} ~> "controls_assessed": claimed} |
| CM-95 | The untrusted part runs only the gates that run pull request code (Scan, QA); Sentinel, and the model key it reads, belong to the other part | `core/securebuilderbot_core/runner.py:run` | - | `test_parts.py` | SC-39, AC-6 · mutate:replace=and (part != "untrusted" or g in UNTRUSTED_GATES)) ~> ) |
| CM-99 | Every string carried from the job that ran the pull request's code is one redacted line: a newline cannot start another gate's section, and a secret-shaped one is never written | `core/securebuilderbot_core/untrusted.py:_text` | - | `test_parts.py` | SI-10, SI-12 · drafted-split review, B3, N1 · mutate:replace=return redact(" ".join(value.splitlines()))[0] ~> return value |
| CM-100 | The receipt renders every gate's reason and finding on one line, so text a gate quotes from the code under review never becomes a heading the publishers read as another gate's section | `core/securebuilderbot_core/receipt.py:_line` | - | `test_receipt.py` | SI-10 · drafted-split review, B3 · mutate:stmt=return str(text) |
| CM-21 | A CVE at or above the profile's fail-on severity, or a medium past its age limit at il6, blocks unless an accepted risk covers it | `scanners/securebuilderbot_scanners/policy.py:is_blocking` | - | `test_gate.py` | RA-5, SI-2 · mutate:stmt=return None |
| CM-22 | An accepted-risk entry past its expiry, or further out than the profile allows, covers nothing | `scanners/securebuilderbot_scanners/policy.py:entry_problem` | - | `test_gate.py` | CA-5, RA-5 · mutate:stmt=return None |
| CM-23 | A manifest in the checkout that no runner audited fails the Scan gate | `scanners/securebuilderbot_scanners/scope.py:unaudited_manifests` | - | `test_gate.py` | RA-5 · mutate:stmt=return [] |
| CM-24 | A scanner the verdict line does not count still fails the gate when it did not run | `scanners/securebuilderbot_scanners/gate.py:missing_extra_scanners` | - | `test_gate.py` | RA-5 · mutate:stmt=return [] |
| CM-25 | An applied accepted risk, or a scanner the config switched off, is yellow, never a pass | `scanners/securebuilderbot_scanners/gate.py:scan_status` | - | `test_gate.py` | CA-5 · mutate:replace=return "yellow" if applied or skipped else "pass" ~> return "pass" |
| CM-102 | A Wolfi package a Dockerfile installs that Wolfi stopped building, while it still builds a newer line of the same package, fails the Scan gate at that Dockerfile line | `scanners/securebuilderbot_scanners/gate.py:stale_wolfi_packages` | - | `test_gate.py` | SA-22, SI-2 · mutate:replace=if (now - built).days > WOLFI_STALE_DAYS and live: ~> if False: |
| CM-26 | The scanners are started with no secret in their environment, by name or by value | `scanners/securebuilderbot_scanners/environment.py:scanner_env` | - | `test_gate.py` | AC-6, SC-4 · the same rule as CM-46, written twice because scanners may not import qa; what one process can promise: PR code a scanner runs (a local requirement's setup.py, a JavaScript eslint config) can still read the gate process's environment from /proc/<pid>/environ · mutate:stmt=return dict(os.environ if environ is None else environ) |
| CM-27 | A variable whose value carries a credential (a URL with userinfo, or a secret-shaped string) is withheld from the scanners whatever its name | `scanners/securebuilderbot_scanners/environment.py:carries_credential` | - | `test_gate.py` | AC-6, SC-4 · the same rule as CM-47 · mutate:stmt=return False |
| CM-28 | An accepted-risk entry applies only when it is in the target branch tip's copy of the exceptions file the governing config names, read by blob and never through a link; an entry the pull request adds or changes is reported as pending and covers nothing until merged | `scanners/securebuilderbot_scanners/gate.py:accepted_risks_at_base` | - | `test_gate.py` | CA-5, CM-3 · mutate:stmt=p = ctx.repo / ScanConfig.accepted_risks; return p, "", [], (p.read_bytes() if p.is_file() else None) |
| CM-29 | The Checkov justification list and the npm-audit allowlist the scanners read are the target branch tip's copies, written into the run directory and named by CHECKOV_JUSTIFICATIONS and NPM_AUDIT_ALLOWLIST; a base with no list points the scanner at nothing, never at the checkout's copy or the bot's own; the scanners that read them run before any scanner that runs pull request code (the order is pinned by a test) | `scanners/securebuilderbot_scanners/gate.py:scanner_lists_at_base` | - | `test_gate.py` | CA-5, CM-3 · mutate:stmt=return {} |
| CM-20 | The Scan gate takes everything it reads from git (the exceptions file, both excusing lists) in prepare(), before any gate runs pull request code: git does not verify a loose object on read, and the scanners run pull request code as the job user; the exceptions load from the bytes held since then, written under a name chosen after the scanners finish | `scanners/securebuilderbot_scanners/gate.py:prepare` | - | `test_gate.py` | SI-7, CM-3 · mutate:stmt=return None |
| CM-30 | An unknown or withdrawn NIST control is never an acceptable citation | `standards/securebuilderbot_standards/citations.py:is_active_control` | - | `test_citations.py` | CA-2 · mutate:decision |
| CM-31 | A catalog revision that breaks a citation is not adopted by the refresh | `standards/securebuilderbot_standards/refresh.py:refuse_broken_citations` | - | `test_refresh.py` | CM-3, CM-6 · mutate:stmt=return [] |
| CM-32 | An OWASP id whose title moved between editions is refused | `standards/securebuilderbot_standards/citations.py:owasp_title_matches` | - | `test_citations.py` | CA-2 · mutate:decision |
| CM-33 | A STIG id on an indexed platform must be in the index | `standards/securebuilderbot_standards/citations.py:stig_rule_known` | - | `test_citations.py` | CA-2 · mutate:decision |
| CM-34 | A MASVS id must be in the pinned v2 catalog; v1 numbering is refused | `standards/securebuilderbot_standards/citations.py:masvs_id_current` | - | `test_citations.py` | CA-2 · mutate:decision |
| CM-35 | A NIST publication revision never published is refused | `standards/securebuilderbot_standards/citations.py:pub_revision_published` | - | `test_citations.py` | CA-2 · mutate:decision |
| CM-36 | The allow marker exempts one line, never the document | `standards/securebuilderbot_standards/citations.py:line_is_exempt` | - | `test_citations.py` | CA-2 · mutate:decision |
| CM-37 | A pull request that removes every row of the target branch's control list (deletes it, or leaves only its header) fails QA rather than dropping it to the drafted mode's yellow: both row counts are pinned in prepare(), the target branch's read by blob from its tree | `qa/securebuilderbot_qa/gate.py:_mutation` | - | `test_gate.py` | SA-11, CM-3 · drafted-mode review, B-1 · mutate:replace=if pinned.target_rows and not pinned.head_rows: ~> if False: |
| CM-68 | The control tools read the head commit's control list as QA pinned it by blob in prepare(), written out only after the suite has run, never the checkout's file: a pull request's tests cannot rewrite the list a mutation reads | `qa/securebuilderbot_qa/gate.py:_mutation` | - | `test_gate.py` | SA-11, CM-3, SI-7 · drafted-mode review round 2, B1 · what it does not claim: the suite still runs as the job user in the job that decides the verdict, so code it runs can still game a mutation (a test that fails whenever any source differs from git) · mutate:replace=listed.write_bytes(pinned.head_list) ~> listed.write_bytes((ctx.repo / controls.MANIFEST).read_bytes()) |
| CM-38 | Only the QA gate points a control tool at another list: an inherited CONTROL_MANIFEST is dropped before any tool starts, so a CI variable or pull request code cannot redirect mutate-controls to a forged list | `qa/securebuilderbot_qa/controls.py:run_tool` | - | `test_controls.py` | SA-11, CM-3 · mutate:replace=env.pop("CONTROL_MANIFEST", None) ~> None |
| CM-39 | A repository with no control rows (no list, or only its header) is never a clean QA pass: the drafted controls are sabotage-tested and the gate is yellow until a person confirms the draft, and yellow too with mutation off | `qa/securebuilderbot_qa/controls.py:rows_in` | - | `test_gate.py` | SA-11, CA-2 · PRD § The control manifest · mutate:stmt=return 1 |
| CM-14 | When the drafted mode inferred the control roots from the layout and the suite command they imply is red before any mutation (or none could be inferred), QA stays yellow and names the command and the key to set, never not_run and never a pass: an inference that did not fit is not the user's broken suite | `qa/securebuilderbot_qa/gate.py:_mutate_draft` | - | `test_gate.py` | SA-11, CA-2 · PRD § The control manifest · mutate:replace=if mutate.code == INFERRED_RED: ~> if False: |
| CM-40 | A skipped test added without a ticket reference is refused | `qa/securebuilderbot_qa/checks.py:added_skips` | - | `test_checks.py` | SA-11 · mutate:stmt=return [] |
| CM-41 | Coverage on the changed lines is held to the profile's threshold | `qa/securebuilderbot_qa/coverage_changed.py:meets` | - | `test_coverage.py` | SA-11 · mutate:stmt=return True |
| CM-42 | A route added without a negative test is refused | `qa/securebuilderbot_qa/checks.py:routes_without_negative_tests` | - | `test_checks.py` | SA-11, AC-3 · mutate:stmt=return [] |
| CM-43 | A mocked database on an integration path is refused | `qa/securebuilderbot_qa/checks.py:mocked_db_sites` | - | `test_checks.py` | SA-11 · mutate:stmt=return [] |
| CM-44 | A guard-shaped function with no manifest row is refused | `qa/securebuilderbot_qa/controls.py:unregistered_guards` | - | `test_controls.py` | SA-11, CM-3 · mutate:stmt=return [] |
| CM-45 | A manifest row the suite survives under mutation is refused | `qa/securebuilderbot_qa/controls.py:unproven_rows` | - | `test_controls.py` | SA-11(1) · mutate:stmt=return [] |
| CM-46 | The user's suite and the control tools are started with no secret in their environment, by name or by value | `qa/securebuilderbot_qa/adapters/__init__.py:user_env` | - | `test_adapters.py` | AC-6, SC-4 · what one process can promise: code running as the same user can still read the parent process's environment from /proc/<pid>/environ, and closing that needs the suite to run in a job that holds no secret, a design decision for the human · mutate:stmt=return dict(os.environ) |
| CM-47 | A variable whose value carries a credential (a URL with userinfo, or a secret-shaped string) is withheld whatever its name | `qa/securebuilderbot_qa/adapters/__init__.py:carries_credential` | - | `test_adapters.py` | AC-6, SC-4 · mutate:stmt=return False |
| CM-48 | Nothing the run keeps from the suite or the control tools carries a secret-shaped string | `qa/securebuilderbot_qa/adapters/__init__.py:keep_log` | - | `test_adapters.py` | SI-12, SC-28 · mutate:replace=cleaned, _ = redact(output) ~> cleaned = output |
| CM-49 | .constraintsignore, the list that excuses a skip or a mock as data, is the target branch tip's copy read by blob in prepare(); a list the pull request adds or edits excuses nothing until merged | `qa/securebuilderbot_qa/gate.py:_ignore_list` | - | `test_gate.py` | SA-11, CM-3 · mutate:stmt=return (ctx.repo / IGNORE_FILE).read_text() if (ctx.repo / IGNORE_FILE).is_file() else "" |


## Manifest — sentinel (Python)

The Sentinel gate's controls are Python under `sentinel/securebuilderbot_sentinel/`, proved by
pytest under `sentinel/tests/`; `project.config.yaml` lists both, so a row's proving test is named
by its bare file name as the Python rows above are. CM-50..CM-59, CM-90 and CM-91 are the sentinel module's.

| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-50 | An instruction-like line in the PR, the commits, the diff or a named file never reaches the model, nor does an instruction-like changed path, its words spaced or joined by _ - / or . (a numbered placeholder stands in every place it would appear, the diff's own header lines included) or manifest cell; each is counted in sanitized_lines | `sentinel/securebuilderbot_sentinel/sanitize.py:is_instruction_like` | - | `test_sanitize.py` | SI-10 · PRD § Security of the bot itself: prompt injection · gate run 2, B-02; gate run 3, N-02 · mutate:stmt=return False |
| CM-51 | The model key is never written to a receipt, a finding, a reason or an evidence file | `sentinel/securebuilderbot_sentinel/gate.py:without_key` | - | `test_review.py` | IA-5, SI-12 · mutate:scope |
| CM-52 | A model answer without its schema's shape is refused, never read | `sentinel/securebuilderbot_sentinel/schema.py:validate` | - | `test_schema.py` | SI-10 · mutate:noop |
| CM-53 | Only the diff and the named files are sent, never an environment, values, Terraform state or variables, credentials or key file, matched case-insensitively: any yaml/yml name containing values, .env followed by a separator or *.env.*, any name containing secret or credential, the credential dotfiles, and key extensions including .ppk, .p8 and .keytab; a source-code file is reviewed whatever its name | `sentinel/securebuilderbot_sentinel/inputs.py:may_send` | - | `test_inputs.py` | AC-4 · PRD § No code leaves the user's CI · gate run 2, B-03 · mutate:decision |
| CM-54 | Every checklist item and every touched control is answered exactly once | `sentinel/securebuilderbot_sentinel/schema.py:_exactly_once` | - | `test_schema.py` | CA-2 · mutate:stmt=return None |
| CM-55 | A finding keeps its path and line only when the diff that was sent shows them | `sentinel/securebuilderbot_sentinel/review.py:place` | - | `test_review.py` | CA-2 · mutate:stmt=return path, line |
| CM-56 | A control is assessed only when its item was cited with evidence from a file that was sent | `sentinel/securebuilderbot_sentinel/review.py:assessed` | - | `test_review.py` | CA-2 · PRD § What a profile does not do · mutate:stmt=return {c for i in req.items for c in i.controls} |
| CM-57 | A blocking finding fails the Sentinel gate, and a diff cut to the budget is yellow at best | `sentinel/securebuilderbot_sentinel/gate.py:status_of` | - | `test_review.py` | CA-7 · mutate:replace=if blocking: ~> if False: |
| CM-58 | No model key, or one with a control character, space, quote or non-ASCII character, is not_run naming the variable, never a pass or a crash | `sentinel/securebuilderbot_sentinel/gate.py:missing_key` | - | `test_review.py` | IA-5, CA-7 · mutate:stmt=return None |
| CM-59 | A checklist citing an unknown or withdrawn control, or an unknown STIG rule, never loads | `sentinel/securebuilderbot_sentinel/checklist.py:_verify` | - | `test_checklist.py` | CA-2 · mutate:noop |
| CM-90 | Every author string that reaches a prompt (a path, a manifest cell) is encoded so it can carry no newline, control character or delimiter | `sentinel/securebuilderbot_sentinel/sanitize.py:quote` | - | `test_review.py` | SI-10 · gate run 1, S-02 · mutate:scope |
| CM-91 | Sentinel's provider, endpoint, model, key_secret and depth come from the config at the range's base, never the head: read by blob from the base commit's tree with refs/replace ignored, a symlinked config refused, and read before any gate runs the pull request's code; the provider that sends them, with every module its request path loads, and the reviewer's instructions (agent.md, both skills, the Control Completeness questions) are loaded from the bot's install at the same moment | `sentinel/securebuilderbot_sentinel/gate.py:_configs` | - | `test_review.py` | CM-3, SC-8 · gate run 1, N-03; gate run 2, B-01; gate run 3, B-01 · what one process can promise: everything is captured when core's run starts, so code the CI ran before core (an install step) is outside the capture; the blob read and the refusals still hold against it, but git's object store itself is trusted, and code running as this user could rewrite a stored object in place. Outside the claim too: a Python module, or a file of the interpreter's own installation, that Sentinel did not load in prepare and that is first loaded later, including the standards indexes' presence checks and the TLS trust store read per request. The full fix is to run Sentinel in a job where no pull request code ran, a design decision for the human · mutate:replace=return replace(ctx.config if ctx.config is not None else head, sentinel=base.sentinel), changed, rel, "" ~> return head, changed, rel, "" |

## Manifest — adapter-github (TypeScript)

The adapter's controls are TypeScript under `adapter-github/src/`, proved by vitest under
`adapter-github/tests/`. `project.config.yaml` lists the package as a control root and `ts` as a
control extension, so both tools prove these rows on every gate. Their proving-test column is
`-` on purpose: a row's targeted run is pytest, which would exit non-zero on a `.ts` file and read
as a proof, so each mutation runs the full suite, whose command runs this package's vitest suite
after pytest. The vitest files that prove each row are named in its note.

| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-60 | A comment already posted on a line is never posted again (noise budget) | `adapter-github/src/comments.ts:shouldPost` | - | - | PRD § Noise budget; no NIST control claimed · proving tests comments.test.ts, publish.test.ts · mutate:decision |
| CM-61 | Nothing is posted when any check title, summary or comment body is secret-shaped | `adapter-github/src/publish.ts:refusal` | - | - | SI-12 (the port of core's CM-01 to the bot's own output) · proving test publish.test.ts · mutate:stmt=return null |
| CM-62 | A gate the config turned off gets no check at all, never a green one | `adapter-github/src/checks.ts:gatesToPublish` | - | - | CA-7 · proving tests checks.test.ts, publish.test.ts · mutate:replace=if (g !== undefined) out.push(g); ~> out.push(g ?? { gate, status: 'pass', reason: '', blocking_findings: 0, advisory_findings: 0 }); |
| CM-63 | A run is published only to the head its receipt names: a receipt for any other sha is refused and nothing is posted | `adapter-github/src/publish.ts:publish` | - | - | SI-7 (the published verdict is the one core wrote for this head; a commit cannot know its own sha) · proving tests publish.test.ts, main.test.ts · mutate:replace=if (run.receipt.head !== headSha) { ~> if (false) { |
| CM-64 | A run directory git tracks is never published, whether discovered or named by SB_RUN_DIR: the pull request committed it, core did not write it | `adapter-github/src/run-dir.ts:isTrackedByGit` | - | - | SI-7 · proving test main.test.ts · mutate:stmt=return false |
| CM-65 | A gate that passed on a run with a relaxation (a scanner or mutation off, the CI workflow edited, a base that is the head) is published neutral with the relaxations in its summary, never as success | `adapter-github/src/checks.ts:planCheckRuns` | - | - | CA-7 · docs/PRD.md § Configuration (a yellow note on every PR check) · proving test checks.test.ts · mutate:replace=gate.status === 'pass' && run.verdict.relaxations.length ? 'neutral' : conclusionFor(gate.status) ~> conclusionFor(gate.status) |
| CM-66 | The publisher posts nothing when the pull request now targets another branch than the one the run read its rules from: a re-run of a job from before a retarget replays the old base_ref, and its checks would become the newest on the head | `adapter-github/src/main.ts:baseMoved` | - | - | CM-3, SI-7 · proving test main.test.ts · mutate:stmt=return null |
| CM-67 | The setup pull request adds the drafted control list only where the default branch has none: a list the team keeps is never replaced | `adapter-github/src/setup-pr.ts:openSetupPr` | - | - | CM-3 · proving test setup-pr.test.ts · mutate:replace=if (!(await client.fileExists(f.path, base))) files.push(f); ~> files.push(f); |
| CM-96 | The job that runs the pull request's code has read access and no secret, whatever the answers; the write token and the model key go to the verdict job alone | `adapter-github/src/templates.ts:workflowTemplate` | - | - | SC-39, AC-6 · PRD § Configuration · proving tests setup-pr.test.ts, action.test.ts · mutate:replace='    permissions: { contents: read }', ~> '    permissions: { contents: read, checks: write }', |
| CM-97 | A check for a gate the job that ran the pull request's code reported says so first, and lists that job's controls as claimed, not assessed | `adapter-github/src/checks.ts:summaryFor` | - | - | CA-2, AU-10 · proving test checks.test.ts · mutate:replace=if (receipt?.attested_by) parts.push( ~> if (false) parts.push( |

## Manifest — adapter-gitlab (TypeScript)

The adapter's controls are TypeScript under `adapter-gitlab/src/`, proved by vitest under
`adapter-gitlab/tests/`, and proven on every gate the same way as adapter-github's: a control
root and the `ts` extension in `project.config.yaml`, the full suite running the package's
vitest suite, the vitest file named in each note.

| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-70 | A finding is never posted twice on the same line: same path, line and body by the bot is skipped | `adapter-gitlab/src/publish.ts:alreadyPosted` | - | - | SI-12 · `adapter-gitlab/tests/publish.test.ts` · mutate:decision |
| CM-71 | No body that carries a secret-shaped string is ever sent to GitLab, and no code quality report carrying one is written for the merge request widget | `adapter-gitlab/src/secrets.ts:refuseSecrets` | - | - | SC-28, SI-12 · `adapter-gitlab/tests/secrets.test.ts`, `publish.test.ts`, `main.test.ts`, `codequality.test.ts` · mutate:noop |
| CM-72 | The verdict note is edited in place, never posted a second time | `adapter-gitlab/src/publish.ts:findVerdictNote` | - | - | SI-12 · `adapter-gitlab/tests/publish.test.ts` · mutate:stmt=return undefined |
| CM-73 | Only a run core wrote for the published commit is published: a run directory tracked by git, or one whose receipt head is another commit, is refused | `adapter-gitlab/src/run-dir.ts:runRefusal` | - | - | SI-7, SI-12 · `adapter-gitlab/tests/run-dir.test.ts`, `main.test.ts` · mutate:stmt=return null |
| CM-74 | A request that carries the GitLab token never follows a redirect: a 3xx is an error, so the token never reaches the host or scheme a `Location` names | `adapter-gitlab/src/gitlab-api.ts:tokenRequest` | - | - | gate cli run 3, B-01; SC-8, IA-5(7) · `adapter-gitlab/tests/gitlab-api.test.ts`, `setup-mr.test.ts` · mutate:stmt=return { method, headers: { "PRIVATE-TOKEN": token, Accept: "application/json" } } |
| CM-75 | The setup merge request adds the drafted control list only where the default branch has none: a list the team keeps is never replaced | `adapter-gitlab/src/setup-mr.ts:openSetupMr` | - | - | CM-3 · proving test setup-mr.test.ts · mutate:replace=if ((await api.getFile(f.path, base)) === null) files.push(f); ~> files.push(f); |
| CM-98 | The verdict note marks a gate the job that ran the merge request's code reported, and lists that job's controls as claimed, not assessed | `adapter-gitlab/src/markdown.ts:section` | - | - | CA-2, AU-10 · proving test markdown.test.ts · mutate:replace=if (g.attestedBy) out.push( ~> if (false) out.push( |
| CM-101 | The one verdict note renders every gate's reason, verdict line and finding on one line, so no gate's text starts another gate's section | `adapter-gitlab/src/markdown.ts:verdictBlock` | - | - | SI-10 · drafted-split review, B3 · proving test markdown.test.ts · mutate:replace=${oneLine(g.reason)}` : "")); ~> ${g.reason}` : "")); |

## Manifest — cli (TypeScript)

The CLI's controls are TypeScript under `cli/src/`, proved by vitest under `cli/tests/`, and proven
on every gate the same way as the adapters': a control root and the `ts` extension in
`project.config.yaml`, the full suite running the package's vitest suite after the others, the
vitest files named in each note.

| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-80 | init never overwrites an existing `.securebuilderbot.yml`, workflow file or setup branch without --force, the remote setup branch included (a person may have pushed edits to it): it exits 1, overwrites nothing and pushes nothing | `cli/src/init.ts:overwriteRefusal` | - | - | PRD § Configuration (the file is the user's); no NIST control claimed · proving tests init.test.ts, init-token.test.ts · mutate:stmt=return null |
| CM-81 | The value of a token from the environment never reaches a printed line or a written file: lines are redacted, a file that would carry one is refused | `cli/src/redact.ts:redactTokens` | - | - | SI-12, IA-5(7) (the CLI's counterpart of core's CM-02) · proving tests redact.test.ts, init-token.test.ts · mutate:stmt=return text |
| CM-82 | init never commits a setup file with uncommitted changes (staged, unstaged or untracked) onto its own branch, `--force` or not: it exits 1 and writes nothing | `cli/src/init.ts:uncommittedSetupFiles` | - | - | gate cli run 1, N-03; no NIST control claimed · proving test init.test.ts · mutate:stmt=return [] |
| CM-83 | init never writes through a symbolic link: a setup file, or a directory above it, that is a link is refused whatever --force says (exit 1, nothing written) | `cli/src/init.ts:symlinkOnPath` | - | - | gate cli run 1, N-04; no NIST control claimed · proving test init.test.ts · mutate:stmt=return null |
| CM-84 | init sends GITHUB_TOKEN only to api.github.com and GITLAB_TOKEN only to gitlab.com, and to another host only when the user names it with --github-api or --gitlab-host (plain https, no credentials or query); the origin remote alone never decides where a token goes | `cli/src/init.ts:tokenDestination` | - | - | gate cli run 1, N-02 (run 2, B-02); SC-8, IA-5(7) · proving test init-token.test.ts · mutate:stmt=return "https://" + remote.host + "/api/v4" |
| CM-85 | An error nothing in the CLI expected is reported by its kind only, never its message, which may quote a server's reply and so part of a token | `cli/src/main.ts:unexpectedLine` | - | - | gate cli run 2, N-04 (run 3, B-02); SI-11, IA-5(7) · proving test init-token.test.ts · mutate:stmt=return "securebuilderbot " + command + ": " + String(e) |
| CM-86 | When the setup pull or merge request cannot be opened, init names the status and the request, never the server's or fetch's words: no reply message, body slice, JSON.parse error or fetch error message is repeated | `cli/src/init.ts:openFailure` | - | - | gate cli run 2, N-04, run 3, N-01 and run 4, B-01 (run 3, B-02); SI-11, IA-5(7) · proving test init-token.test.ts · mutate:stmt=return e instanceof Error ? new CouldNotOpen("could not open: " + e.message) : null |
| CM-87 | init prints the message of its own errors only; any other error goes to main, which names its kind | `cli/src/init.ts:ownMessage` | - | - | gate cli run 2, N-04 (run 3, B-02); SI-11 · proving test init-token.test.ts · mutate:stmt=return e instanceof Error ? e.message : String(e) |
| CM-88 | A platform token from the environment that holds whitespace or a control character is refused before any request (exit 2): fetch quotes such a header value trimmed, which full-value redaction cannot match | `cli/src/init.ts:tokenFor` | - | - | gate cli run 4, B-01; SI-11, IA-5(7) · proving test init-token.test.ts · mutate:stmt=return (platform === "github" ? env["GITHUB_TOKEN"] ?? env["GH_TOKEN"] : env["GITLAB_TOKEN"]) || undefined |
| CM-89 | init drafts a control list only with QA on and no list kept in the working tree or the tree the setup starts from, so it never replaces the team's own | `cli/src/init.ts:runInit` | - | - | CM-3 · proving test init.test.ts · mutate:replace=effectiveGates(setup).includes("qa") && !existsSync(path.join(root, MANIFEST_PATH)) && fileAt(root, source, MANIFEST_PATH) === null ~> effectiveGates(setup).includes("qa") |
| CM-13 | init never overwrites a project.config.yaml the team keeps: one in the working tree or the tree the setup starts from (a link counts, lstat not existsSync) gets the inferred CONTROL_* lines printed for a person to add, and nothing is written there | `cli/src/init.ts:keptConfig` | - | - | CM-3 · proving test init.test.ts · mutate:stmt=return false |
