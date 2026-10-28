# Sentinel gate checklist

Moved verbatim from `CLAUDE.md` (Phase 0, 2026-09-16). The gate (`.claude/agents/gate.md`, Part 2) runs this checklist on the epic range `main..epic/<name>`. "Story" below reads as "the range under review"; a control-shaped diff is one that touches authentication, authorization, scoping, audit, redaction, cryptography or input validation.


**SECURITY_TIER context variable:** This project's security tier is read from `SECURITY_TIER` in `project.config.yaml` (value `IL4` or `IL6`). It is a design-time deployment target set at project initialization, not a runtime feature flag. When `SECURITY_TIER=IL6`, the additional gate block below is enforced; when `SECURITY_TIER=IL4`, the IL6 block is informational only. If `SECURITY_TIER` is `UNSET`, the project is not initialized — Sentinel returns a blocking finding and the gate cannot pass.

- No hardcoded secrets or credentials anywhere — no fallback/default values in config files or env var definitions
- All endpoints require valid Keycloak token (except OAuth callback)
- Auth middleware registered before all route handlers — no route can be reached without passing through it
- Negative auth test required: every endpoint asserts 401 when called without a token
- RBAC scoping enforced per the project's PRD — every role lane the PRD defines is enforced at the API layer, not the frontend
- Negative RBAC tests required: user A cannot read or mutate user B's records; no role can mutate records or fields it does not own
- Last-admin guard present on any endpoint that deactivates or demotes a user — enforced at API layer, not frontend only
- SQL injection prevented — parameterized queries only
- Soft-delete / archive filters (e.g. `deleted_at`, `archived_at`) applied on all active-record queries where the schema defines them
- Custom Express error handler wired globally — no stack traces, internal messages, DB errors, file paths, or storage keys in any API response
- File uploads, if any, use in-memory storage — no disk writes on backend pods
- All new dependencies present in `docs/architecture/DEPENDENCY_POLICY.md`
- All project-specific invariants listed under **Key Architecture Constraints** are enforced (computed-field write guards, route-specific transaction isolation, storage/auth patterns, etc.) — see that section for this project's list
- **Control manifest row present** — `make derive-controls` reports 0 unregistered guards (the code is the list); a diff that creates or modifies a security control has a corresponding row in `docs/security/CONTROL-MANIFEST.md` in the same commit, and `make verify-controls` resolves that row (implementation present, production call site recomputed and non-zero, required artifact present, proving test present). A control-shaped diff with no manifest row is a **blocking** finding.
- **Control Completeness Review run** — if the diff is control-shaped (auth, authz, audit, redaction, crypto, scoping), the six-question block below is answered **in prose** and included in the Sentinel report. An unanswered question, or one answered "PASS", is a **blocking** finding.
- **Pre-flight deltas named** — every delta `make gate-state` reports is named in the gate-log row: reviewed here if this range caused it, one sentence if it did not. No ticket for a non-blocking delta. **Control decay is blocking** whatever caused it.
- **Rulebook changes in their own commit** — a diff touching `CLAUDE.md`, `.claude/`, or gate-deciding `engine/` files lands in a commit that changes nothing else, so the human can read all of it. Mixed with other changes: blocking (`engine/GOVERNANCE.md` rule 1).

**Also verify** — carried from the two-gate era's security-gate definition, which the merge into
`.claude/agents/gate.md` first dropped. Each traces to a guard, a middleware or a test; "it probably
doesn't" is not verification.

- Input validated at every API boundary; reserved and computed fields refused on a generic `PUT` and
  changed only through their dedicated endpoints; computed columns never written
- Reads go through the views the schema defines; check-and-set paths hold `SELECT FOR UPDATE`
- No presigned object-store URLs (API-proxied streaming); error responses carry codes only
- No server-side token store or session table; frontend tokens in memory, never localStorage/sessionStorage
- No PII, tokens or secrets in logs (NS-02, NS-03)
- No route or UI offered to a role that cannot use it (NS-13); no role-escalation path except the
  admin-only user-management endpoint (NS-15)
- No plaintext secrets in Helm values, ConfigMaps or image env; the image scan not disabled (NS-17, NS-18)
- CORS matches the platform rule
- Every project-specific SHALL NOT in `docs/PRD.md` traced to its guard — if the PRD defines none, say so

### Control Completeness Review (Sentinel — control-shaped diffs only)

The Sentinel checklist above asks whether a control **exists**. That question has a known blind
spot: a control can exist, be correctly implemented, be thoroughly tested, pass its gate — and have
an edge its author never walked to. A yes/no checklist cannot find those, because the honest answer
to *"is tenant scoping enforced?"* is **yes**.

**Trigger.** The diff creates or modifies authentication, authorization, audit, redaction,
cryptography, or scoping code. Roughly one story in four. Otherwise this section is skipped
entirely — it is not a default, and running it on every story turns it into a rubber stamp.

**These are answered in prose, not ticked.** A question that can be answered "PASS" has not been
asked. Q3 and Q4 in particular require Sentinel to *write the list*; the enumeration is the
mechanism, not the verdict.

| # | question | the defect class it catches |
|---|---|---|
| Q1 | Does the guard recurse into nested objects and arrays, or does it inspect only top-level keys? | A redaction/sanitisation pass that checks the keys of the outer object and copies nested values by reference — writing secrets or PII into a store that cannot be corrected. |
| Q2 | Is there a second write path to this same state, and is the guard present on **both**? | A privilege ceiling enforced on `POST` but not `PATCH` (or create-vs-bulk-create), so the restricted operation is reachable in two steps. |
| Q3 | Which framework entry points does this hook **not** cover? List them. | ORM lifecycle hooks that bind a subset of operations — e.g. a `beforeFind` that does not fire for `count`/`sum`/aggregate, and binds only the root model so joined includes go unscoped. |
| Q4 | What does this verification **not** verify? List it. | A token check that validates issuer and signature but not audience, algorithm, or token type — so a credential minted for a different client of the same realm is accepted. |
| Q5 | Name the production call site — file and line. | A control that is implemented and tested but never invoked. If you cannot name the calling line, the control is not finished. |
| Q6 | If it rejects input: is the schema strict, and is it actually mounted? | Validation schemas written, exported, and imported by nothing; or schemas that pass unknown keys through, leaving mass-assignment defence to repository discipline. |

Sentinel emits one block per control touched:

```
CONTROL COMPLETENESS — <file>:<symbol>
  Q1 recursion    : <answer or N/A>
  Q2 write paths  : <answer or N/A>
  Q3 entry points : <enumerated list or N/A>
  Q4 not-verified : <enumerated list or N/A>
  Q5 call site    : <file:line>
  Q6 strict/mount : <answer or N/A>
  → <BLOCKING finding | clear>
```

**Why this is separate from the checklist above.** The checklist catches *absence* — a control that
is not there. This catches *incompleteness* — a control that is there and stops early. Mechanical
checks are cheap and never decay, so add them liberally; reasoning checks like this one cost real
gate time and rot if applied broadly. Keep the trigger narrow and the questions few.

---

### IL6 Additional Gate Checks — `standards/data/checklists/IL6.md` (read it when `SECURITY_TIER=IL6`)

### Android Track Gate Checks — `standards/data/checklists/android.md` (read it when `APP_TRACK=android`)

### Tactical Provider Infrastructure Checks — `standards/data/checklists/tactical.md` (read it when `PROVIDER=tactical`)

Sentinel ends every gate check with a formal verdict:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GATE VERDICT: [PASS / FAIL] | SECURITY_TIER: [IL4 / IL6] | run #[n] | range [base]..[head] | depth [deep / light]
Suite: [T]/[P]/[F]   Coverage: [PASS/FAIL/N/A]   Negative tests: [n]/[n]   Mutation: [proven]/[rows]   Unregistered guards: [n]
CM: [PASS/FAIL]   CC: [n blocks / skipped]   AR/EH: [run / skipped]   DP: [run / N/A]   Proof set: [n/n / N/A]
Platform surface: [n files: names / none]
Scan: [PASS/FAIL] — [n]/7 scanners · [n] fixable · [n] POAM candidate(s)
Open findings: [n]   Blocking findings: [n]  (tickets: T-…)
Doc findings: [n] — never blocking, ticketed not fixed here (tickets: T-… or none)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

