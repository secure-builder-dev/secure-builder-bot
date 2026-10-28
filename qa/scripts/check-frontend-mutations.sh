#!/usr/bin/env bash
# Integrity of docs/security/FRONTEND-MUTATIONS.md — the deletion detector.
#
# WHY. QG-FE-001/GOV-010 made that manifest gate policy: `make mutate-frontend` requires every row to
# go RED, and a NOT PROVEN row is blocking. But nothing read the file itself, so the cheapest way
# past a failing row was to delete it — after which the gate is green, the guard is gone, and no step
# anywhere reports it. That is the same shape as T-057 (an exemption list nothing watched), and the
# same answer: a check inside `make check`, so it runs on every push.
#
# WHAT IT CANNOT SEE. A row *weakened in place* — a `to` mutant that no longer breaks the behaviour,
# or a `from` re-anchored to a line nobody asserts. That needs the harness to grade the mutation
# itself and is T-078. This check is about rows disappearing, nothing more.
#
# HOW A REMOVAL IS RECORDED. Ids are stable identifiers cited from gate rows and tickets, so they are
# never renumbered and a gap is not an error. A deliberate removal is declared in the manifest's
# "Removed rows" section in the shape CONTROL-MANIFEST.md already uses for CM-18:
#
#     **FM-07 removed 2026-09-26 — reason.**
#
# and the floor below is lowered in the same commit. Both edits are visible in review, which is the
# point: the check does not prevent removal, it prevents a *silent* one.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST="${FM_MANIFEST:-$ROOT/docs/security/FRONTEND-MUTATIONS.md}"

# The committed floor. Raise it in the same commit that adds rows; lower it only alongside a
# "Removed rows" entry.
FLOOR="${FM_FLOOR:-3}"

fail() { printf 'check-frontend-mutations: %s\n' "$1" >&2; exit 1; }

[ -f "$MANIFEST" ] || fail "manifest not found: $MANIFEST"

ids="$(grep -oE '^\| FM-[0-9]+' "$MANIFEST" | sed 's/^| //' || true)"
count="$(printf '%s\n' "$ids" | grep -c 'FM-' || true)"

[ "$count" -ge "$FLOOR" ] || fail "$count rows, floor is $FLOOR — a row was removed. Record it under 'Removed rows' and lower the floor in the same commit, or restore it."

dupes="$(printf '%s\n' "$ids" | sort | uniq -d)"
[ -z "$dupes" ] || fail "duplicate row id(s): $(printf '%s' "$dupes" | tr '\n' ' ')— ids are stable identifiers cited from gate rows and tickets"

# Every id from FM-01 to the highest present must be a row, or declared removed.
max="$(printf '%s\n' "$ids" | sed 's/FM-//' | sort -n | tail -1)"
missing=""
for n in $(seq 1 "$max"); do
  id="$(printf 'FM-%02d' "$n")"
  grep -qx "$id" <<<"$ids" && continue
  grep -qE "^\*\*${id} removed [0-9]{4}-[0-9]{2}-[0-9]{2} — .+\*\*" "$MANIFEST" && continue
  missing="$missing $id"
done
[ -z "$missing" ] || fail "id(s) neither present nor recorded as removed:$missing — add '**<id> removed <YYYY-MM-DD> — <reason>.**' under 'Removed rows'"

printf 'check-frontend-mutations: %d rows, floor %d, no gaps unaccounted for\n' "$count" "$FLOOR"
