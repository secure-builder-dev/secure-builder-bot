# Quality gate

**What it answers:** do the tests prove the code in this range? It runs once per epic on
`main..HEAD` of the epic branch, in a clean context, as Part 1 of `.claude/agents/gate.md`. A
**re-gate** (`make gate-prompt --regate`) runs on the range since the last gate-log row's head and
does only what that range requires — the prompt lists the steps mechanically from `git diff`. The
full `main..HEAD` gate is the epic's first row and is not repeated; a green re-gate on the fixes is
what the merge waits for.
Thresholds below are set at project start and do not drift per epic. A change to them is a rulebook
change: its own commit, and the human reads the diff (`engine/GOVERNANCE.md`).

## Criteria

### 1. The suite passes, whole

`make test` exits 0. No `it.skip` / `xit` / `@Disabled` introduced in the range unless the ticket
says why. The suite runs three times when the test harness changed in the range, otherwise once
(three if that run fails); one failure is a failure.

### 2. Coverage on the range

Measured by Jest/nyc (web) or JaCoCo (Android) on the files changed in the range — not the
project average. Skipped when the range changes no production code; the record says so.

| Layer | Minimum line coverage |
|---|---|
| Service layer | 80% |
| Repository layer | 80% |
| Route handlers | 70% |
| Middleware | 80% |

Frontend coverage, on a project that has a frontend app, is measured by Vitest
(`@vitest/coverage-v8`) on the same range basis; a project with no frontend records it N/A:

| Scope | Minimum |
|---|---|
| Every frontend file in the range — lines | 90% |
| A frontend file in the range with **8 or more** branches — branches | 75% |
| The range as a whole — branches | 85% |

Branches are held to a lower bar than lines, and per-file only above 8 branches, because a v8 branch
percentage is unstable on a small denominator: a file with 3 branches reads 66% on one miss, and a
per-file branch floor would fail on files that are fully tested. The aggregate row is what actually
holds the line; the per-file row catches a large file left half-covered.

What may be excluded from the frontend measurement: the application entry point (it calls
`createRoot` at module scope and cannot be imported without mounting the app), test scaffolding, and
type-only files. **Vendored UI output is not excludable** — generated component code the project
ships is code the project owns, and ownership rather than authorship sets the standard. The list
lives in the project's Vitest config under `coverage.exclude`; a change to that list is a change to
this threshold and needs the same sign-off.

A file in the range below its floor is blocking unless the ticket names the file and says why — the
same escape §1 already allows for an `it.skip`. A statement that is genuinely unreachable under
jsdom is named in the project's gate records, with its reason, rather than exempted here.

`make mutate-frontend` runs alongside `make mutate-controls`: it breaks each row of
`docs/security/FRONTEND-MUTATIONS.md` on purpose and the frontend suite must go red. A `NOT PROVEN`
row is blocking. Coverage says how much code runs under test; this says whether a test would notice
it changing, and they are different questions.

### 3. Negative tests, per route

For every route added or changed in the range: a test asserting **401 without a token**. For every
record-scoped route: **user A cannot read or mutate user B's record**. For any endpoint that
deactivates or demotes a user: **the last admin cannot be**. Enumerate routes from
`docs/truth/api.md` (`make docs`) and name the test that covers each. A route with none is blocking.
If the range adds or changes no routes — a plugin-only epic on the android track, say — this
section has nothing to enumerate. Say that in the verdict rather than passing a section with zero
items in silence: a gate that checked nothing and a gate that checked everything must not read
the same.

### 4. No mocked database on integration paths

Tests that exercise repositories or services hit the test database (`backend/src/test/db.ts`),
not a mocked client. A mocked DB behind a control's test is blocking — it proves the mock.

### 5. Mutation check — the proof the tests are real

`make mutate-controls`: every row in `docs/security/CONTROL-MANIFEST.md` is broken on purpose
(middleware → `next()`, decision → `return true`, scoping → pass-through, redaction → identity)
and the suite must go **red**. At the gate, `--since <base of the range>` (the last gated head on a
re-gate) mutates only rows whose implementation or proving test changed, plus every row added to or
edited in the manifest since then (all rows when the harness changed); an unchanged row is cited,
by name, to the gate-log row that last ran it on this code — or it is run.

**There is no nightly** (2026-10-12). `.github/workflows/nightly-proof.yml` used to mutate every row
against `main` each night, and a red night was a finding against `main` with its own ticket. It was
red on every night it fired and then lost its runner to the account's Actions allowance; the engine
no longer schedules it (the file stays for `workflow_dispatch`, and a project may run no GitHub
Actions at all — T-ENGINE-18). So the only citation for an unchanged row is a gate-log row that ran
it on this code. `FRONTEND-MUTATIONS.md` rows never had a nightly to cite — the one night it ran
recorded `0 proven, 58 NOT PROVEN` for the frontend half (T-CSMVIEW-07): run `make mutate-frontend`,
or the gate says plainly that they were not proven.
A control that stays green is not proven and is blocking. Rows the
script cannot locate are reported for a human. This replaces commit-order evidence: a red commit
proved a test failed once; this proves it would fail today.

### 6. Done-when

For each ticket in the range, `done_when` is demonstrably true from a test or from `make dev`.
A ticket in review whose `done_when` has no proving test is a finding (not blocking) and is named.

### 7. Mechanical (`make check` already ran in CI)

lint and typecheck exit 0; no stray `console.log` / debug output in production paths.

## Android track additions (`APP_TRACK=android`)

ktlint zero violations · Detekt zero issues at `error` · JaCoCo meets the table above.

## Output

The verdict block and gate-log row format are in `.claude/agents/gate.md`. Every blocking
finding becomes a retro ticket in `planning/tickets/` on the same branch; the next run gets its own
row.

## Not this gate

Secrets, auth ordering, RBAC correctness, SQL injection, ADR compliance, dependency policy,
platform surface — the security gate (`engine/SENTINEL-CHECKLIST.md`). The quality gate asks one thing:
**did the tests prove the code?**
