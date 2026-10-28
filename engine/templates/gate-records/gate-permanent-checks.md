# Gate Permanent-Checks Register — TEMPLATE

> **This is the engine template.** Copy it once into the project's gate output directory:
> ```
> cp gate-records/gate-permanent-checks.md gate-records/gate-permanent-checks.md
> ```
> `planning/` is project-owned and never synced, so your register is never overwritten.

**Purpose.** The inverse of `gate-accepted-findings.md`. That file records what the project decided
to **tolerate**. This one records what it decided to **permanently check** — and, separately, which
accepted risks are carrying a compensating control that must actually exist.

**Why this exists.** A gate system that does not learn from findings re-earns them. Without this
file, a severe finding can be detected, correctly understood, consciously dispositioned — and leave
behind nothing that would ever catch it again.

The failure mode is specific and it is not hypothetical: a risk is found, an agent or reviewer
writes out the exact attack path, a mitigation is *named* as what would make accepting it safe, the
User accepts on that basis — and then the mitigation is never built, while the decision is recorded
only in a sprint handoff document that scrolls out of view. Gates run afterward. None re-surface it,
because gates are stateless and read only the diff. Weeks later an outside reviewer finds it and
rates it critical.

The disposition can be entirely defensible and the outcome still bad, because the *record* was not
durable and the compensating control was never verified. **Table B exists so that cannot recur.**

---

## How gates use this file

1. **Table A is read at gate start.** Each row names a finding class and the mechanism that now
   catches it. If a row's mechanism is missing or broken, that is a blocking finding — the check
   itself has regressed.
2. **Table B is read at gate start and at every release decision.** Any row whose *proof* column is
   not satisfied is reported **every run, without exception**, until it is. An accepted risk with an
   unbuilt compensating control is not an accepted risk — it is an open one with paperwork.
3. **Rows are added by the User**, or by an agent transcribing a User decision. An agent may not
   accept its own finding — that is self-approval.

---

## Table A — Permanent checks

Every P0/P1 finding, from any source (gate, incident, peer review, external audit), becomes a row
here **before its fix commits**: the finding class, the mechanism that now catches it, and where
that mechanism lives.

The rows below ship with the engine because the mechanisms do. Add your project's own beneath them.

| id | finding class it catches | mechanism | lives in | status |
|---|---|---|---|---|
| PC-01 | Control implemented and tested but never called by production code | manifest call-site recomputation | `qa/scripts/verify-controls.sh` | **ACTIVE** |
| PC-02 | Deploy artifact a control depends on deleted after its story closed | manifest `required artifact` column | `qa/scripts/verify-controls.sh` | **ACTIVE** |
| PC-03 | CI jobs removed or gutted outside the engine | `ci_lines` / `ci_jobs` / `ci runs tests` delta | `engine/scripts/gate/repo-state.sh` | **ACTIVE** |
| PC-04 | Baseline suite rot accumulating while per-story gates stay green | `suite run T/P/F` delta recorded every gate | `engine/scripts/gate/repo-state.sh` | **ACTIVE** |
| PC-05 | Test file doing file I/O at module scope — throws at collection, silently voids every sibling test | `collection-risk files` count | `engine/scripts/gate/repo-state.sh` | **ACTIVE** |
| PC-06 | Redaction / sanitisation guard inspecting only the top level of an object | Control Completeness Q1 | `CLAUDE.md` §Control Completeness | **ACTIVE** |
| PC-07 | Two write paths to the same state, guard on only one | Control Completeness Q2 | `CLAUDE.md` §Control Completeness | **ACTIVE** |
| PC-08 | Framework entry points a hook does not cover | Control Completeness Q3 | `CLAUDE.md` §Control Completeness | **ACTIVE** |
| PC-09 | Verification that checks some claims and silently omits others | Control Completeness Q4 | `CLAUDE.md` §Control Completeness | **ACTIVE** |
| PC-10 | Validation schema written but never mounted, or not strict | Control Completeness Q6 | `CLAUDE.md` §Control Completeness | **ACTIVE** |
| PC-11 | Code merged from a branch outside the engine with no gate | Inbound Code lifecycle rule | `CLAUDE.md` §Inbound Code | **ACTIVE** |

---

## Table B — Accepted risks and their compensating controls

A risk is only *accepted* when **all four** middle columns are satisfied. A row with an unbuilt or
unproven compensating control is reported at every gate until it is built.

| id | risk | attack path | compensating control | proof it exists | re-review trigger | status |
|---|---|---|---|---|---|---|
| AR-01 | _(example — replace)_ | _What an attacker actually does, concretely. If you cannot write this, you do not yet understand the risk well enough to accept it._ | _What makes accepting it safe._ | _The test or check name, and evidence it runs. "We'll be careful" is not proof._ | _The event that forces re-review — a deploy to a shared environment, a new client, an epic close._ | OPEN / ACCEPTED |

**Note on `status`.** `ACCEPTED` requires a satisfied *proof* column. Anything else is `OPEN`,
regardless of how well-reasoned the original decision was.
