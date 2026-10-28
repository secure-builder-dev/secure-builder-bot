# The truth

Two kinds of document describe this system. **The plan** is hand-written: the PRD, the API
contract, the schema draft. It says what we intend. **The truth** is generated from the code
and never edited by hand. It says what exists, and it cannot go stale because nothing has to
remember to update it.

Everything under `docs/truth/` is the truth. Do not edit it; regenerate it.

## What the truth contains, per track

**Web track** (`APP_TRACK=web`)

| file | what it is | where it comes from |
|---|---|---|
| `docs/truth/api.md` | every HTTP route the backend registers: method, path, the middleware chain in order, and `file:line` | a static scan of `backend/src/**` for `router.get(...)`, `app.post(...)` and friends, with mount prefixes resolved through `app.use('/api', router)` and imports |
| `docs/truth/schema.md` | every table with its columns | `pg_dump --schema-only` when `DATABASE_URL` is set and reachable; otherwise the migrations (raw SQL, Knex, Prisma, Sequelize) |
| `docs/truth/schema.sql` | the DDL the table list was derived from | the same source; absent when there is no SQL to show |

**Android track** (`APP_TRACK=android`)

The backend is shared, so `api.md` and `schema.md` are generated exactly as above. In addition:

| file | what it is | where it comes from |
|---|---|---|
| `docs/truth/app-api.md` | every backend call the app makes: method, path, `Interface.function`, `file:line` | Retrofit annotations (`@GET`, `@POST`, `@HTTP(...)`) and Ktor client calls (`client.get("...")`) under `android/` |

**Out of scope, on both tracks.** Anything that is hand-written on both sides has no truth to
generate and is not compared: UI flows, screen designs, MDM configuration, deployment values,
prose in the PRD. Those live in the walkthrough and are reviewed by people.

Each generated file starts with a line naming the script, the commit and the date it was
generated from. A route whose mount point could not be resolved is shown as `<mount?>/path`
rather than guessed.

## When it is generated

- **After every epic.** `/close-epic` diffs `docs/truth/` across the epic and asks, for every route or
  column that changed, whether an ADR or a walkthrough section explains it.
- **In CI**, on every push, so a stale committed copy is caught the same day.
- **At brownfield onboarding**, before anything is planned. On an existing codebase the truth
  is the starting point; the PRD is written against it, not the other way round.

## Why there is no drift report

Until 2026-10-03 a hand-written `API_CONTRACT.md` and `DB_SCHEMA_v2.md` were the plan, and
`make drift` compared them to this truth at every epic close. In practice the code moved first and the
documents followed, so most drift lines ended as "edit the document to match code that was already
gated" — a second description of one API, maintained by hand. ADR-112 retired both documents and the
report. The truth is the only description of what the API and schema *are*; the PRD, the ADRs and each
epic's walkthrough say what they *should* be.

## Commands

```sh
# generate the truth (always exits 0; prints "truth: N routes, M tables (source: static|pg_dump)")
engine/scripts/docs/generate-truth.sh
DATABASE_URL=postgres://... engine/scripts/docs/generate-truth.sh     # prefer the live schema

# do the tests prove the controls? break each one, expect red (see CONTROL-MANIFEST.md)
qa/scripts/mutate-controls.sh --dry-run           # show each mutation, run nothing
qa/scripts/mutate-controls.sh                     # run the suite once per control
qa/scripts/mutate-controls.sh --only CM-01,CM-05

# regression test for all of the above (throwaway fixture repo, no node needed)
engine/scripts/gate/selftest-phase1.sh
```
