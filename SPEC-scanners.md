# Spec: scanners

Module `scanners` of the capability map. Status: built on `wip/scanners` (base `epic/core`); the
decisions below were taken during the build and are confirmed by the human who merges it.

## Objective

`scanners` is the Scan gate: the eight scanner wrappers and their pins, the whole-checkout scope
they share, the CVE-freshness check, the per-scanner receipts, and the profile's policy over what
the scanners found. It implements core's `Gate` protocol and nothing else of core's internals;
core finds it by name (`securebuilderbot_scanners.GATE`). It knows no platform and reaches no
model endpoint; the only network it uses is the scanners' own feeds (CVE databases, the npm and
PyPI advisory services), read live at run time as the PRD requires.

User stories, from the PRD:

- As a team lead, every PR gets the Scan gate with nothing to install: the eight scanners ship
  pinned inside the bot, and the profile I picked decides what blocks.
- As an assessor, the receipt tells me, per scanner, the version, the database date, what it
  examined, its exit code and how many findings it had; and which accepted risks applied, with
  their expiry.
- As a developer, a CVE the gate blocks on names the package, the version, the fix and the
  result file, and the one thing that lifts it: an upgrade or an accepted-risk entry with a
  reason and an expiry.

Success looks like: `core/run run` at `profile: il6` on any checkout runs all eight scanners
against the whole tree and fails on any critical or high CVE no accepted risk covers.

## Tech Stack

- Bash 5 for the runners (one per scanner), the shared scope and receipt helpers, the dispatch
  generator and the image plan; the fixture-backed bash suite stays bash
- Python 3.12 for the gate, the policy and the scope mirror, standard library plus PyYAML (core's
  dependency); pip-audit 2.10.1 is the module's one Python dependency, a tool, pinned
- The five container scanners run as pinned images (`scanners/scripts/tool-versions.env`) or as
  host binaries (`SCAN_ENGINE`), one tool at a time if need be (`SCAN_ENGINE_<TOOL>`)
- `scanners/Dockerfile`: the bot and the eight scanners in one image, built by CI

## Commands

```
The scan (results in gate-records/scan/latest):   make scan        make scan-lite    make gate-scan
One runner:                 bash scanners/scripts/run-<scanner>.sh      (SCAN_RESULTS_DIR, PROJECT_ROOT)
The gate on a range:        core/run run --base origin/main --head HEAD   (gates: [scan] in .securebuilderbot.yml)
Another checkout:           PROJECT_ROOT=/path/to/checkout bash scanners/scan.sh
Tests:                      make test (pytest, scanners/tests/test_gate.py) · bash scanners/tests/scan-test-runner.sh
Engine:                     SCAN_ENGINE=auto|container|native · SCAN_ENGINE_TRIVY=native (one tool)
The image:                  docker build -f scanners/Dockerfile -t securebuilderbot .
                            docker run --rm -v "$PWD:/src" securebuilderbot run --base origin/main
Lint the image's Dockerfile:  docker run --rm -i -v "$PWD/.hadolint.yaml:/.hadolint.yaml:ro" hadolint/hadolint:v2.12.0-alpine hadolint --config /.hadolint.yaml - < scanners/Dockerfile
Every edit:                 make check-fast      Task done: make check-task      Docs: make check-docs
```

## Project Structure

```
scanners/
  securebuilderbot_scanners/
    __init__.py          → GATE = ScanGate (what core's runner looks up)
    gate.py              → the Scan gate: runs scan.sh, reads the results, applies the policy, writes the receipt
    policy.py            → CVE records from every result file; the fail-on, medium-age and accepted-risk rules
    scope.py             → the checkout's manifests, the runners' prune list mirrored; unaudited_manifests
  scan.sh                → the runners in order into one results directory; records each exit code
  scripts/
    tool-versions.env    → every pin (five image tags, the pip-audit version)
    tool-runner.sh       → container or native per tool; count_json
    scan-scope.sh        → whole-checkout discovery with one prune list (every runner sources it)
    scan-receipt.sh      → scan_begin / scan_ran / scan_none: what each runner asserts it examined
    scan-track.sh        → web or android (the android paths are unchanged)
    run-hadolint.sh run-checkov.sh run-clamav.sh run-grype.sh run-trivy.sh
    run-npm-audit.sh run-eslint.sh run-pip-audit.sh
    generate-dispatch.sh → dispatch.md (fixable work) and poam-candidates.md, as before, plus pip-audit
    image-plan.sh build-images.sh pull-images.sh image-age-guard.sh checkov-decide.sh scan-severity.sh
  fixtures/              → canned result sets the suites read (each now carries pip-audit.json)
  tests/
    scan-test-runner.sh  → the bash suite (320 cases)
    test_gate.py         → the gate, the policy, the scope, the receipt (pytest)
  Dockerfile             → the scanners image
  pins.md                → tags today, digests next, the release workflow
  local-scan-setup.md    → running the scan on a workstation
  requirements.txt       → pip-audit==2.10.1
```

Moved from `engine/scripts/scan/` and `core/` with `git mv`; `engine/scripts/scan/` no longer
exists and `.doc-paths-retired` names every old path. `nightly-scan.sh` was deleted: nothing
referenced it and the bot schedules nothing.

## Interfaces

**Into core.** `ScanGate.run(ctx: GateContext) -> GateResult` (SPEC-core.md § Interface). The
gate scans `ctx.repo` (any checkout: `PROJECT_ROOT` reaches every runner), honours `ctx.skip`,
and reads the profile's `scan.fail_on`, `scan.medium_max_age_days`, `scan.cve_data_max_age_days`
and `accepted_risk_expiry_days`. `GateResult.status` is `fail` on any blocking finding, `yellow`
when an accepted risk applied, `pass` otherwise, `not_run` when the scan could not start.
Findings carry the CVE id as `rule_id`, the package, version, fix and scanner in the message,
and the result file as `file`; a scanner that did not run is `scanner:<name>`; an unusable
accepted-risk entry is `accepted-risk:<id>`; a manifest no runner audited is `unaudited:<path>`;
stale CVE data is `stale-data:<scanner>`; a Wolfi line left behind is `stale-package:<package>`, at its Dockerfile line; everything else fixable in `dispatch.md` keeps its own
rule id (a hadolint code, a checkov check, `eslint`, `SECRET`, `MISCONFIG`, `malware`).

**The receipt section** (`receipt.scanners`, one entry per scanner, nine of them): `version`
(the pinned tag or the pip-audit pin; "the project's own" for npm and eslint), `image`,
`database` (the CVE database's own date, ClamAV's signature age, "live … at scan time" for the
registry audits, "n/a — rule-based" for the linters, "n/a — nothing in scope" when the runner
declared an empty scope), `examined` (the runner's own receipt line), `exit_code` (as
`scan.sh` recorded it; "not recorded" when the shim did not start it) and `findings` (a count
from the result file). Beside it: `line` (core's verdict line, unchanged), `stale`, `policy`
(the profile's numbers and the blocking/advisory CVE counts), `accepted_risks_applied`
(id, package, expires, reason), `redacted`, and `controls_assessed` (RA-5 when a vulnerability
scanner ran, SI-3 when ClamAV ran, nothing else claimed).

**Accepted risks.** `docs/security/accepted-risks.yml` (the path `scan.accepted_risks` names in
the checkout's `.securebuilderbot.yml`; the default when it has none): a list, or `entries:`,
of `{id, reason, expires: YYYY-MM-DD, scope?}`. `id` is a CVE, GHSA or PYSEC id and matches a
finding by id or alias; `scope` narrows it to a package name or a result file. An entry is
usable only with an id, a reason and a date neither past nor further out than the profile's
`accepted_risk_expiry_days`; otherwise it is itself a blocking finding and covers nothing.

**The runners' contract** (unchanged from the engine): a result file per run, `scan_begin`
first, `scan_ran` or `scan_none` last and only on a success path, exit 0/1 for the decision and
"did not run" for anything unparseable; `scan.sh` adds `scanners-exit` (name and exit code).
`run-pip-audit.sh` writes `pip-audit.json` (`apps`, `blocking` = a fix exists, `reported` = no
fix) and takes `PIP_AUDIT_CMD` (default `python3 -m pip_audit`).
`run-wolfi-freshness.sh` reads every `apk add` in a Dockerfile stage built `FROM` a Wolfi or
Chainguard image, looks each package up in Wolfi's APKINDEX (`WOLFI_INDEX_URL`, or a local
`WOLFI_INDEX_FILE`) and writes `wolfi-freshness.json`: each install's Dockerfile and line, its last
build date, and the newer numbered lines of the same package (`nodejs-24` for `nodejs-22`) with
theirs. It decides nothing; the gate's `stale_wolfi_packages` blocks an install last built over
`WOLFI_STALE_DAYS` (45) ago while a newer line was built within them (CM-102). An index that cannot
be read is the scanner not running; no Wolfi Dockerfile is nothing in scope.

## Scope

Every runner discovers its targets anywhere under the checkout through `scan-scope.sh`, pruning
`node_modules`, `.git`, `dist`, `build`, `vendor`, `.venv`, `venv`, the bot's own
`scanners/fixtures` and whatever git ignores: Dockerfiles (hadolint, and `image-plan.sh` for the
image scans: every Dockerfile is an image named by its directory and built from it, except the
bot's own), chart roots, terraform trees and Kubernetes manifests (checkov), every
`package.json` directory (npm audit needs its lockfile; eslint runs the app's own `lint` script
when it starts with eslint and lists the app as unlinted otherwise), every `requirements*.txt`
and every `pyproject.toml` without one (pip-audit). Nothing is stray: a manifest that was found
is audited or the scan fails by name, and the gate holds the runners to it (`scope.py`, CM-23).
Only a checkout with no manifest at all is an empty scope, declared and named in the verdict.
The android track's paths are as they were.

## Policy

`policy.cves_from_results` reads Grype, Trivy (with `PublishedDate`), npm audit and pip-audit
into one record per CVE and package, the best-rated scanner's word, a date from whichever
carries one; a pip-audit finding another scanner also reported, by id or alias and package,
takes that scanner's rating. `policy.is_blocking` (CM-21): a CVE whose severity is in the
profile's `fail_on` blocks, fix available or not; at il6 a medium published more than
`medium_max_age_days` ago blocks, and one with no published date in any result file cannot be
shown young and blocks too; a CVE no scanner rated (pip-audit emits none) blocks at every
profile; an npm advisory `npm audit --omit=dev` proved outside the production tree stays
advisory (DEPENDENCY_POLICY rule 7 as amended). A blocking CVE an accepted risk covers becomes
advisory and turns the run yellow (CM-25). `dispatch.md` keeps its fixable list as it was; its
CVE items are the policy's, its other items (a Dockerfile error, a checkov check, an eslint
message, a secret) block as before.

## Code Style

As core's: type hints, frozen dataclasses, no module-level state, errors with a path. Bash as the
engine's: `set -uo pipefail`, every expansion quoted, a WHY block at the top, a named test for
every script (the ratchet counts the ones without).

## Testing Strategy

- `scanners/tests/scan-test-runner.sh`: the engine's fixture-backed suite, moved whole, plus
  Group 17 for the scope (fake tools on `PATH`, scratch git checkouts): a Dockerfile outside
  `backend/`, the image plan, checkov's three target kinds, a `tools/site/` app audited and
  linted, every branch of `run-pip-audit.sh` with a fake binary, the per-tool engine override,
  dispatch routing for pip-audit.
- `scanners/tests/test_gate.py`: the gate through a fake `scan.sh` that lays down a fixture and
  the real dispatch; the policy per profile; accepted risks valid, expired, too far, malformed,
  scoped; the eight-scanner receipt; the eighth scanner missing; unaudited manifests; the stale-
  data and redaction cases moved with the file.
- Mutation: CM-05, CM-10, CM-21, CM-22, CM-23, CM-24, CM-25 each go red under
  `make mutate-controls` (the rows name the proving test relatively, `../../scanners/tests/…`).
- Changed-line coverage: 94.8% on the module's Python at the last `make check-task`.

## Boundaries

- **Always:** red test first; `make check-fast` before every commit; a runner that cannot do its
  job leaves no receipt; an empty scope is declared, never inferred; every pin lives in
  `tool-versions.env`.
- **Ask first:** a new scanner; a change to the policy's numbers (they are the profile's); a new
  prune rule; adding pip-audit to core's `SCANNERS` tuple and `scan.skip` names (a core change).
- **Never:** a network call from the gate itself; a scan that reads as clean when a scanner did
  not run; the bot's own image built by the bot's own scan; a suppression comment.

## Success Criteria

1. `make test` and `make check-task` green; the scan bash suite green with the new cases.
   **Verified:** `make check-task` at the end of the build (output in the handback); the bash
   suite 320 passed, 0 failed, 3 skipped (the three skips are environmental: no `android/`, no
   live results directory, no nightly workflow). Group 17 holds a `package.json` in `tools/site/`
   audited and linted (not stray, not "nothing in scope"), a `requirements.txt` and a
   `pyproject.toml` anywhere audited by a faked pip-audit (and `vendor/` pruned), and a Dockerfile
   under `svc/api/` linted (a gitignored one and one under `node_modules` not).
2. `scanners/tests/test_gate.py`: at il4 a high CVE with no accepted risk → `fail`, blocking
   finding `CVE-2026-1111` naming libx@1.0 and `scan/results/trivy.json`; accepted with a valid
   expiry → `yellow`, `accepted_risks_applied` lists it; expired → `fail` with both the CVE and
   `accepted-risk:CVE-2026-1111`; at il6 a medium 40 days old → `fail`, 10 days old → `pass`
   with an advisory; at `none` a high → not blocking, a critical → blocking. Stale-database
   handling unchanged: its six cases moved with the file and pass. **Verified:** pytest, 201 passed.
3. `core/run run` on this repository at `profile: il6`, `gates: [scan]`. **Verified** on the
   build's own sandbox (`SCAN_ENGINE_TRIVY=native SSL_CERT_FILE=… core/run run --base epic/core`,
   run `20261023T144046Z-5d762b7`): `Scan: FAIL — a scanner the gate counts did not run; 6/7
   scanners ran (did not run: grype) (nothing in scope: checkov npm-audit eslint) · 0 fixable`.
   Grype is the one scanner that did not run: its database hosts are refused by this sandbox's
   egress proxy (the core epic recorded the same gap); trivy reached its feed natively, the rest
   ran in their pinned images. The receipt lists eight scanners with exit codes and counts:
   hadolint `ran 1 Dockerfile(s)` (the scanners image, exit 0), checkov `none` (no IaC), clamav
   `ran Scanned files: 374` (signatures 5 days old), grype `did not run` (exit 1), trivy `ran
   repository filesystem` (database updated 2026-10-23), npm-audit and eslint `none` (no
   package.json), pip-audit 2.10.1 `ran 3 manifest(s)` (`core/requirements.txt`,
   `core/requirements-dev.txt`, `scanners/requirements.txt`), 0 CVEs blocking or advisory,
   `controls_assessed` RA-5 and SI-3; the one blocking finding is `scanner:grype`. The GitHub
   `scan` workflow, where every feed is reachable, runs all eight.
4. `make verify-controls`: 15 controls, 0 FAIL. `make mutate-controls`: every row proven,
   including CM-21 (fail-on policy), CM-22 (accepted-risk expiry), CM-23 (unaudited manifests),
   CM-24 (the eighth scanner) and CM-25 (yellow, never pass). **Verified:** the run at the end of
   the build, in the handback.
5. `engine/scripts/scan/` no longer exists (`git ls-files engine/scripts/scan` is empty);
   `make check-docs` green: all three documentation checks pass. **Verified.**

## Decisions taken during the build

- **The verdict line stays at seven; the gate counts eight.** Core's `SCANNERS` tuple and
  `scan.skip` names are core's; the brief said the line gains nothing new, so pip-audit is
  accounted for by the gate (`missing_extra_scanners`, CM-24) and listed in the receipt. Adding
  it to core's line and to `scan.skip` is a core change, proposed as a follow-up.
- **The gate scans any checkout.** The engine's gate refused a repository other than the bot's
  own because the runners located the project from their own path; every runner now honours
  `PROJECT_ROOT`, `scan.sh` passes `ctx.repo`, and the scanners image mounts the checkout at
  `/src`. The "only the checkout it is installed in" refusal is gone.
- **Accepted risks are read from the checkout's own config.** `GateContext` carries no config
  path and changing it is a core decision, so the gate loads `.securebuilderbot.yml` at the
  checkout root for `scan.accepted_risks` and falls back to the default path. Tests pass the
  path to `ScanGate(accepted_risks=…)`.
- **npm's own allowlist is not an accepted risk.** The gate judges every advisory by the profile;
  an entry in `docs/security/npm-audit-allowlist.yaml` lifts the runner's exit code (so
  `dispatch.md` stays as it was) but not the gate's verdict. One mechanism, one file. Merging the
  two lists is a follow-up.
- **Unrated is blocking.** pip-audit rates nothing; a vulnerability no other scanner rated blocks
  at every profile rather than passing as "unknown", and the message says why.
- **A medium with no published date blocks at il6.** The age rule cannot be shown satisfied, so
  the conservative side is taken; Trivy carries the date for almost everything.
- **Image contexts are the Dockerfile's directory.** The engine special-cased `frontend/` to
  build from the repo root; the convention now is the directory, and a pipeline file that names
  contexts still wins when present.
- **pip-audit runs natively on every engine.** There is no separate image for it; the scanners
  image installs the pin, CI installs `scanners/requirements.txt`, and the runner refuses any
  other version.
- **eslint without a lint script is "unlinted", not a crash.** The bot has no ruleset of its own
  yet; an app the project itself does not lint is listed by name, and a checkout where no app has
  one is a declared empty scope.
- **`SCAN_ENGINE_<TOOL>`** exists because this build's sandbox could run trivy only natively and
  the rest only in containers; it is small, per tool, and tested.
- **The scanners image takes its binaries from the pinned images** (`COPY --from`), so there is one
  list of pins; Node by checksum, checkov and pip-audit from PyPI at the pinned versions.

## Changes outside the module

- `core/securebuilderbot_core/runner.py`: the scan shim fallback is gone; a missing gate module
  is `not_built`. `core/securebuilderbot_core/__main__.py`: the stamp's CVE-age check imports
  the scanners module by name and stamps FAIL without it. `core/securebuilderbot_core/classify.py`:
  `scanners/` is gate tooling (deep). `core/tests/test_runner.py`, `core/tests/test_verdict.py`
  (fixture path, the stamp test).
- `Makefile` (`SCAN_SCRIPTS`, `gate-selftest`, `scan`, `scan-lite`, `gate-scan`, `audit`),
  `.boundaries` and `scripts/check-boundaries.sh` (group `scanners`), `scripts/ratchet.sh`,
  `scripts/lint-changed.sh` (a `git mv` is not a wholly added file; with a test),
  `scripts/tests/constraints-test.sh`, `.gitignore`, `.doc-paths-retired`, `.hadolint.yaml`
  (comment), `project.config.yaml` (`CONTROL_SRC_ROOTS`, `CONTROL_HARNESS_RE`),
  `docs/security/CONTROL-MANIFEST.md` (CM-05, CM-10 moved; CM-21..CM-25),
  `docs/security/npm-audit-allowlist.yaml` (comment), `docs/architecture/DEPENDENCY_POLICY.md`
  (§ 4A.1), `.github/workflows/scan.yml` and `constraints.yml` (the pip-audit install),
  `CAPABILITY-MAP.md` (this row).

## Follow-ups

- Core: add `pip-audit` to `verdict.SCANNERS` and `config.SCANNERS` so the line counts eight and
  `scan.skip: [pip-audit]` is accepted.
- The release workflow: digests beside tags in `tool-versions.env` (`scanners/pins.md`).
- One accepted-risk list: fold the npm allowlist and checkov justifications into
  `accepted-risks.yml`, or have the gate read them.
- A `.dockerignore` for the image build (`COPY . /bot` copies `.git` and `gate-records/`).
- cargo audit and govulncheck as the ecosystem audits for Rust and Go (PRD § Scan gate).
