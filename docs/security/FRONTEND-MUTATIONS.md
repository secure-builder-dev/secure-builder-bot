# Frontend Mutation Manifest

> Seeded into your project by `make sync-engine` on first sync and never overwritten after that.
> This file is yours: replace the placeholder rows below with your frontend's behaviours, and
> raise the floor in `qa/scripts/check-frontend-mutations.sh` (or set `FM_FLOOR`) as you
> add them. A project with no frontend deletes the rows and sets the floor to 0.

**Purpose.** One row per frontend behaviour whose test must have teeth. `make mutate-frontend`
breaks each one on purpose and requires the suite to go **red**. A mutation the suite survives is a
behaviour with no test that would notice it changing — a blocking finding at the epic gate.

**Why this exists, and why it is separate from `CONTROL-MANIFEST.md`.** That manifest and
`make mutate-controls` cover `backend/src/` only: every row points at backend code, and the harness's
default suite command is the backend's. The frontend had no equivalent, and the
evidence that one was needed came from a real frontend-coverage pass: a request helper read **100%
lines with zero tests**, and two of five defect sites sat in files at 96% and 97% statements whose
tests all passed both before and after the fix, because not one asserted a date.

Line and branch coverage measure **reach**. This file measures **strength**. They are different
numbers and the difference is where defects live.

## How a row works

| column | meaning |
|---|---|
| `id` | stable identifier, referenced from gate rows and tickets |
| `file` | path under `frontend/` |
| `from` | the exact source text to replace. **Must occur exactly once in the file** — the harness fails the row rather than guessing |
| `to` | what to replace it with |
| `proves` | the behaviour that stops working, in one line — what a reviewer reads when the row goes GREEN |

Backticks around `from` and `to` are stripped; a literal backtick inside them is written `` \` ``.

**Cells are single-line.** There is no newline escape: a `\n` written in a cell would be inserted into
the source as the two characters `\` and `n`, which produces a syntax error — and a syntax error makes
the suite go red, so the row would report **proven** without any test having caught anything. The
harness refuses such a row rather than grading it. A mutation that needs to span lines belongs as a
single-line replacement that is still valid TypeScript, which every row here is.

## How to use it

- **At every gate.** `make mutate-frontend` alongside `make mutate-controls`. A `NOT PROVEN` row is a
  finding, not a fix for whatever story is in flight.
- **When a story adds a frontend guard.** Add its row in the same commit as the test.
- **A row cannot quietly disappear.** `make check` runs `qa/scripts/check-frontend-mutations.sh`, which
  fails if the row count drops below a floor committed in the script, if an id repeats, or if an id
  between FM-01 and the highest present is neither a row nor declared removed. To remove a row
  deliberately, add `**FM-nn removed <YYYY-MM-DD> — <reason>.**` under **Removed rows** below and
  lower the floor in the same commit — the shape `CONTROL-MANIFEST.md` uses for CM-18. Ids are
  stable identifiers cited from gate rows and tickets, so they are never renumbered and a gap is not
  an error. The check catches a row *disappearing*; a row **weakened in place** — a `to` that no
  longer breaks the behaviour — is invisible to it and is T-078.
- **When a row is UNLOCATABLE.** The source moved. Fix the row — do not delete it. A deleted row is
  an unproven behaviour with no record that it was ever proven.
- **Rows are never deleted to make the harness pass.** Deleting a row is a governance-visible act:
  it removes a standing proof. If a behaviour genuinely no longer exists, the row goes in the same
  commit that removes it, and the commit says so.

---

## Rows

| id | file | from | to | proves |
|---|---|---|---|---|
| FM-01 | src/lib/api.ts | `?? '/api'` | `?? ''` | PLACEHOLDER — replace with one of your own. Requests fall back to the `/api` prefix when no runtime or build config supplies one; without it every call goes to the document root. |
| FM-02 | src/components/ProtectedRoute.tsx | `if (isLoading) return null;` | `if (false) return null;` | PLACEHOLDER — replace with one of your own. A protected page renders nothing while auth is still resolving, so protected content cannot flash to a signed-out visitor. |
| FM-03 | src/lib/storage.ts | `parsed.every((v) => typeof v === 'string')` | `true` | PLACEHOLDER — replace with one of your own. A value read from browser storage is validated before it is trusted, so one bad write cannot break the page that reads it. |

## Removed rows

Nothing has been removed yet. A deliberate removal is recorded here as
`**FM-nn removed <YYYY-MM-DD> — <reason>.**`, with the floor in
`qa/scripts/check-frontend-mutations.sh` lowered in the same commit. Ids are never reused.
