#!/usr/bin/env bash
# selftest-phase1.sh — fixture-backed regression test for the Phase 1 tooling:
#   engine/scripts/docs/generate-truth.sh,
#   qa/scripts/mutate-controls.sh (dry-run only — no node/jest needed).
#
# Builds a throwaway git repo shaped like a small Express + Knex backend with a hand-written
# plan (contract, schema doc, PRD) that deliberately disagrees with the code, and asserts each
# script's answer. Run it after touching any of the three scripts.
#
# USAGE   engine/scripts/gate/selftest-phase1.sh        (or: make gate-selftest-phase1)
# EXIT    0 = all assertions hold · 1 = at least one failed

set -uo pipefail
GATE_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCS_DIR="$(cd "$GATE_DIR/../docs" && pwd)"
QA_DIR="$(cd "$GATE_DIR/../../../qa/scripts" && pwd)"
FX="$(mktemp -d)"; trap 'rm -rf "$FX"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }
assert_eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected [$3] got [$2]"; }
assert_has() { if grep -qF -- "$3" <<<"$2"; then ok "$1"; else bad "$1" "output lacks [$3]"; fi; }
assert_not() { if grep -qF -- "$3" <<<"$2"; then bad "$1" "output contains [$3]"; else ok "$1"; fi; }

# ── fixture ───────────────────────────────────────────────────────────────────
cd "$FX" && git init -q && git config user.email t@t && git config user.name t
mkdir -p backend/src/routes backend/src/middleware backend/src/hooks backend/migrations docs/architecture docs/security
cat > backend/src/app.ts <<'TS'
import express from "express";
import { router } from "./routes";
import { requireAuth } from "./middleware/auth";
import { health } from "./health";
const app = express();
app.use(requireAuth);
app.use('/api', router);
app.get('/health', health);
export default app;
TS
cat > backend/src/routes/index.ts <<'TS'
import { Router } from "express";
import { requireRole } from "../middleware/auth";
import { list, get, remove } from "./users.controller";
export const router = Router();
router.get('/users', requireRole('admin'), list);
router.get('/users/:id', get);
router.delete(
  '/users/:id',
  requireRole('admin'),
  async (req, res) => { res.json(await remove(req.params.id)); }
);
TS
cat > backend/src/middleware/auth.ts <<'TS'
import { Request, Response, NextFunction } from "express";

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.headers.authorization) { res.status(401).end(); return; }
  next();
}

export const requireRole = (role: string) => (req: Request, res: Response, next: NextFunction) => {
  if ((req as any).user.role !== role) { res.status(403).end(); return; }
  next();
};

export function canEdit(user: { id: string }, doc: { owner_id: string }): boolean {
  return user.id === doc.owner_id;
}
TS
cat > backend/src/hooks/scope.ts <<'TS'
export function scopeTenant(opts: { where?: object }, tenant: string) {
  opts.where = { ...(opts.where || {}), tenant_id: tenant };
}
TS
cat > backend/migrations/001_init.ts <<'TS'
import { Knex } from "knex";
export async function up(knex: Knex) {
  await knex.schema.createTable('users', (table) => {
    table.uuid('id').primary();
    table.string('email').notNullable();
    table.timestamps(true, true);
  });
  await knex.schema.createTable('documents', (t) => {
    t.uuid('id').primary();
    t.uuid('owner_id').references('users.id');
    t.specificType('tags', 'text[]');
  });
}
export async function down(knex: Knex) { await knex.schema.dropTable('documents'); await knex.schema.dropTable('users'); }
TS
cat > docs/architecture/API_CONTRACT.md <<'MD'
# API Contract
All endpoints are prefixed `/api`.
### `GET /api/users`
### `GET /api/users/{id}`
### `DELETE /api/users/{id}`
### `PATCH /api/users/{id}`
MD
cat > docs/architecture/DB_SCHEMA_v2.md <<'MD'
# Schema
## Tables
### users
```sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ
);
```
### <!-- Primary data table -->
```sql
-- CREATE TABLE <entity> ( ... );
```
### documents
```sql
CREATE TABLE documents (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id),
  tags TEXT[]
);
```
### audit_logs
```sql
CREATE TABLE audit_logs (id UUID PRIMARY KEY, action TEXT);
```
## Indexes
| Index | Table | Columns |
|---|---|---|
| `idx_users_email` | `users` | `email` |
MD
cat > docs/PRD.md <<'MD'
# PRD
## Requirements
The system SHALL let an Admin list Users and remove a User.
The system SHALL store Documents owned by Users; each Document carries tags.
The system SHALL send Notifications when a Document changes; Notifications are batched; unread Notifications are counted.
The system SHALL NOT store passwords.
MD
cat > docs/security/CONTROL-MANIFEST.md <<'MD'
| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-01 | token gate | `backend/src/middleware/auth.ts:requireAuth` | - | `auth.test.ts` | authN |
| CM-02 | tenant scope | `backend/src/hooks/scope.ts:scopeTenant` | - | - | authZ |
| CM-04 | edit decision | `backend/src/middleware/auth.ts:canEdit` | - | - | authZ |
| CM-99 | placeholder | `<path>:<symbol>` | - | `<glob>` | ignored |
MD
git add -A && git commit -qm "fixture"

echo "── generate-truth ──"
out=$(bash "$DOCS_DIR/generate-truth.sh"); rc=$?
assert_eq  "exit 0"                                        "$rc" 0
assert_has "summary counts 4 routes / 2 tables, static"    "$out" "truth: 4 routes, 2 tables (source: static)"
api=$(cat docs/truth/api.md); schema=$(cat docs/truth/schema.md)
assert_has "header line stamped"                           "$api" "<!-- generated by engine/scripts/docs/generate-truth.sh @"
assert_has "app.use('/api', router) prefix resolved via import" "$api" "| GET | \`/api/users\` | requireRole('admin'), list | backend/src/routes/index.ts:5 |"
assert_has "multi-line registration, inline handler"       "$api" "| DELETE | \`/api/users/:id\` | requireRole('admin'), (inline) | backend/src/routes/index.ts:7 |"
assert_has "app-level route has no prefix"                 "$api" "| GET | \`/health\` | health | backend/src/app.ts:8 |"
assert_has "knex createTable + timestamps parsed"          "$schema" "| users | id:uuid, email:string, created_at:timestamp, updated_at:timestamp | backend/migrations/001_init.ts |"
assert_has "knex specificType parsed"                      "$schema" "| documents | id:uuid, owner_id:uuid, tags:text[] | backend/migrations/001_init.ts |"
assert_has "schema header names the source"                "$schema" "**Source: static**"
[ -f docs/truth/schema.sql ] && bad "no schema.sql when there is no raw SQL" "schema.sql exists" || ok "no schema.sql when there is no raw SQL"
untracked=$(git status --porcelain | grep -v '^?? docs/truth/' || true)
assert_eq  "writes nothing outside docs/truth/"            "$untracked" ""

echo "── mutate-controls --dry-run ──"
out=$(bash "$QA_DIR/mutate-controls.sh" --dry-run); rc=$?
assert_eq  "dry-run exits 0 when every control is locatable" "$rc" 0
assert_has "middleware: return next(); inside requireAuth body" "$out" "  +    5    if (true as boolean) return next();"
assert_has "…directly after the opening brace line"        "$out" "       3  export function requireAuth(req: Request, res: Response, next: NextFunction): void {"
cm01=$(printf '%s\n' "$out" | awk '/^CM-01 /{p=1} /^CM-02 /{p=0} p')
assert_not "…not before the function"                      "$cm01" "  +    3"
assert_not "…not inside the nested res.status() call"      "$cm01" "  +    6"
assert_has "decision: return true; inside canEdit"         "$out" "  +   15    if (true as boolean) return true;"
assert_has "scope hook on options → return;"               "$out" "  +    3    if (true as boolean) return;"
assert_has "table row for CM-01"                           "$out" "| CM-01 | token gate | middleware → \`return next();\` | — | dry-run |"
assert_has "table row for CM-04"                           "$out" "| CM-04 | edit decision | decision → \`return true;\` | — | dry-run |"
assert_has "placeholder row ignored"                       "$out" "1 placeholder row(s) ignored"
assert_not "kotlin-less repo: no manual rows"              "$out" "manual"
assert_eq  "dry-run leaves the tree untouched"             "$(git status --porcelain | grep -v '^?? docs/truth/' || true)" ""
out=$(bash "$QA_DIR/mutate-controls.sh" --dry-run --only CM-04)
assert_not "--only filters rows"                           "$out" "CM-01"
# slim (T-SLIM-04): the two new kinds. escalate rewrites the caller as admin; replace swaps one literal.
printf '| CM-06 | edit decision, escalated | `backend/src/middleware/auth.ts:canEdit` | - | - | mutate:escalate |\n' >> docs/security/CONTROL-MANIFEST.md
printf '| CM-07 | edit decision, replaced | `backend/src/middleware/auth.ts:canEdit` | - | - | mutate:replace=user.id ~> doc.owner_id |\n' >> docs/security/CONTROL-MANIFEST.md
out=$(bash "$QA_DIR/mutate-controls.sh" --dry-run --only CM-06,CM-07); rc=$?
assert_eq  "escalate and replace are locatable"            "$rc" 0
assert_has "escalate rewrites the user parameter"          "$out" "if (true as boolean) user = { ...user, role: 'admin' } as any;"
assert_has "replace swaps the literal in place"            "$out" "doc.owner_id === doc.owner_id"
printf '| CM-08 | no such text | `backend/src/middleware/auth.ts:canEdit` | - | - | mutate:replace=nowhere in this file ~> x |\n' >> docs/security/CONTROL-MANIFEST.md
out=$(bash "$QA_DIR/mutate-controls.sh" --dry-run --only CM-08); rc=$?
assert_eq  "replace text not found → exit 1"               "$rc" 1
assert_has "…and says so"                                  "$out" "replace text not found"
git checkout -q -- docs/security/CONTROL-MANIFEST.md
# T-ENGINE-17: a guard that is a module-scope constant is defined ABOVE the function that reads it.
# The old 200-line forward window never looked there, so such a control was `manual` for ever.
base=$(git rev-parse HEAD)
printf 'const ELIGIBLE = ["SGT", "SSG"];\nexport function isEligible(rank: string): boolean {\n  return ELIGIBLE.includes(rank);\n}\n' >> backend/src/middleware/auth.ts
printf '| CM-10 | eligibility list | `backend/src/middleware/auth.ts:isEligible` | - | - | mutate:replace="SGT" ~> "PVT" |\n' >> docs/security/CONTROL-MANIFEST.md
git add -A && git -c user.email=t@t -c user.name=t commit -qm "module-scope guard"
out=$(bash "$QA_DIR/mutate-controls.sh" --dry-run --only CM-10); rc=$?
assert_eq  "a literal above the definition is locatable (module-scope constant)" "$rc" 0
assert_has "…and the mutation lands on the constant line"  "$out" 'const ELIGIBLE = ["PVT", "SSG"];'
assert_not "…not reported as manual"                       "$out" "manual"
git reset -q --hard "$base"
# a control that cannot be mutated automatically is named and fails the run
printf '| CM-05 | ghost | `backend/src/hooks/scope.ts:nothingHere` | - | - | x |\n' >> docs/security/CONTROL-MANIFEST.md
out=$(bash "$QA_DIR/mutate-controls.sh" --dry-run); rc=$?
assert_eq  "unlocatable symbol → exit 1"                   "$rc" 1
assert_has "…and is named"                                 "$out" "MANUAL / UNLOCATABLE: CM-05"
git checkout -q -- docs/security/CONTROL-MANIFEST.md

echo "── mutate-controls (real run, fake suite) ──"
# a "suite" that goes red only when requireAuth is mutated: proves CM-01, not CM-02/CM-04,
# and proves the file is restored afterwards
out=$(MUTATE_TEST_CMD='! grep -q "mutate-controls: middleware" backend/src/middleware/auth.ts' bash "$QA_DIR/mutate-controls.sh"); rc=$?
assert_eq  "exit 1 when any control is not proven"         "$rc" 1
assert_has "baseline runs first"                           "$out" "baseline (unmutated) … GREEN"
assert_has "CM-01 proven"                                  "$out" "| RED | ✓ proven |"
assert_has "CM-04 not proven"                              "$out" "| GREEN | ✗ NOT PROVEN |"
assert_has "not-proven ids named"                          "$out" "NOT PROVEN: CM-02 CM-04"
assert_eq  "every file restored after the run"             "$(git status --porcelain | grep -v '^?? docs/truth/' || true)" ""
out=$(MUTATE_TEST_CMD='false' bash "$QA_DIR/mutate-controls.sh"); rc=$?
assert_eq  "red baseline aborts with exit 1"               "$rc" 1
assert_has "…and says why"                                 "$out" "already red before any mutation"

echo "── mutate-controls: own proving test first (targeted) ──"
base=$(git rev-parse HEAD)
mkdir -p backend/src/__tests__ && printf 'test("auth", () => {});\n' > backend/src/__tests__/auth.test.ts
git add -A && git -c user.email=t@t -c user.name=t commit -qm "proving test"
# the full suite never notices anything; CM-01's own test does — so CM-01 is proven by the targeted run
TGT="$(mktemp)"
out=$(MUTATE_TEST_CMD='true' MUTATE_TARGET_CMD='echo {tests} > "'"$TGT"'"; ! grep -q "mutate-controls: middleware" backend/src/middleware/auth.ts' bash "$QA_DIR/mutate-controls.sh"); rc=$?
assert_has "CM-01 proven by its own test"                  "$out" "| RED (own test) | ✓ proven |"
assert_eq  "only the named proving test was run"           "$(cat "$TGT")" "backend/src/__tests__/auth.test.ts"
assert_has "rows with no proving test still use the full suite" "$out" "NOT PROVEN: CM-02 CM-04"
assert_has "the summary counts targeted rows"              "$out" "1 run against their own test first (0 needed the full suite)"
# the named test misses the mutation; another test in the full suite catches it — still proven, and said so
out=$(MUTATE_TEST_CMD='! grep -q "mutate-controls: middleware" backend/src/middleware/auth.ts' MUTATE_TARGET_CMD='true {tests}' bash "$QA_DIR/mutate-controls.sh"); rc=$?
assert_has "own test green → full suite decides"           "$out" "| RED (full suite) | ✓ proven — by another test; the named proving test missed it |"
assert_has "…and the fallback is counted"                  "$out" "1 run against their own test first (1 needed the full suite)"
# a targeted run that hangs is cut off, reported, and the run moves on
out=$(MUTATE_TEST_CMD='true' MUTATE_TARGET_TIMEOUT=1 MUTATE_TARGET_CMD='sleep 5; : {tests}' bash "$QA_DIR/mutate-controls.sh"); rc=$?
assert_eq  "a timeout is not proven → exit 1"              "$rc" 1
assert_has "…reported as TIMED OUT"                        "$out" "TIMED OUT: CM-01"
assert_has "…and the next rows still ran"                  "$out" "| CM-04 | edit decision |"
assert_eq  "every file restored after targeted runs"       "$(git status --porcelain | grep -v '^?? docs/truth/' || true)" ""
rm -f "$TGT"
git reset -q --hard "$base"

echo "── mutate-controls --since: a row added since the base is always re-proven (T-SLIM-14) ──"
base=$(git rev-parse HEAD)
printf '| CM-09 | registered later, code untouched | `backend/src/middleware/auth.ts:canEdit` | - | - | x |\n' >> docs/security/CONTROL-MANIFEST.md
git add docs/security/CONTROL-MANIFEST.md && git -c user.email=t@t -c user.name=t commit -qm "register CM-09"
out=$(bash "$QA_DIR/mutate-controls.sh" --dry-run --since "$base"); rc=$?
assert_eq  "--since exits 0"                               "$rc" 0
assert_has "CM-09 is mutated although its file did not change" "$out" "| CM-09 | registered later, code untouched | decision → \`return true;\` | — | dry-run |"
assert_has "CM-01 existed at the base and is unchanged"    "$out" "| CM-01 | token gate | — | — | ○ unchanged since"
git reset -q --hard "$base"
# T-SLIM-15: the same id, re-pointed at another proving test, neither file touched — re-proven.
awk -F'|' -v OFS='|' '/^\| CM-01 /{$6=" `repointed.test.ts` "}1' docs/security/CONTROL-MANIFEST.md > "$FX/.m" && mv "$FX/.m" docs/security/CONTROL-MANIFEST.md
git add docs/security/CONTROL-MANIFEST.md && git -c user.email=t@t -c user.name=t commit -qm "re-point CM-01"
out=$(bash "$QA_DIR/mutate-controls.sh" --dry-run --since "$base"); rc=$?
assert_eq  "--since exits 0 after a re-point"              "$rc" 0
assert_has "CM-01 re-pointed since the base is mutated (T-SLIM-15)" "$out" "| CM-01 | token gate | middleware → \`return next();\` | — | dry-run |"
assert_has "CM-04 untouched is still unchanged"            "$out" "| CM-04 | edit decision | — | — | ○ unchanged since"
git reset -q --hard "$base"

echo "── empty repo ──"
E="$(mktemp -d)"; ( cd "$E" && git init -q && out=$(bash "$DOCS_DIR/generate-truth.sh"); rc=$?
  printf '%s\n%s\n' "$rc" "$out" ) > "$FX/.empty"; rm -rf "$E"
assert_eq  "no backend: exit 0"                            "$(sed -n 1p "$FX/.empty")" 0
assert_has "no backend: says so"                           "$(cat "$FX/.empty")" "no backend source found"
assert_has "no backend: summary still printed"             "$(cat "$FX/.empty")" "truth: 0 routes, 0 tables (source: static)"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
