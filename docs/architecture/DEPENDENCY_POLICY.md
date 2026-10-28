## About This Document

**Purpose:** Authoritative reference for all package decisions. Every dependency addition, upgrade, or removal must be reviewed against this document. Sentinel enforces compliance on every story gate check.

**Workflow role:** Sentinel owns this. Amelia reads before adding any new package. Tori checks during refinement that no new dependencies are introduced without DP review. New teams: complete §3 and §4 approved lists before Sprint 1 begins.

**How to fill in:** For each section, add packages to the approved list as they pass Sentinel DP review. Never add a package directly to `package.json` without first adding it to this document.

---

---
project: <APP_NAME>
owner: Sentinel (Security & Architecture Gatekeeper)
status: active
lastUpdated: <DATE>
---

# Dependency Policy

Authoritative reference for all package decisions in <APP_NAME>. Every dependency addition, upgrade, or removal must be reviewed against this document. Sentinel enforces compliance on every story gate check.

---

## 1 — Policy Overview

### 1.1 Rules

1. **No unapproved package enters the codebase.** Adding a dependency not on the approved list is a gate failure. Submit for review first.
2. **No GPL or AGPL licensed packages in production bundles.** IL4 deployment constraint.
3. **No packages with unresolved critical or high CVEs** unless POAM-allowlisted per §5.
4. **No managed BaaS client SDKs** (Supabase, Firebase, etc.) — self-hosted backend only.
5. **Packages pinned to minor version ranges** (`^major.minor.x`). Floating majors (`*`, `latest`) are prohibited in `package.json`.
6. **`package-lock.json` is committed and must match `package.json`** exactly. PRs that modify `package.json` without a matching lock file update are blocked.
7. **devDependencies are not exempt** from license or CVE policy — they run in CI and on developer machines.

**Governance citations:**
- **SI-2 (Flaw Remediation)** — Rule 3: prohibiting packages with unresolved critical/high CVEs implements SI-2's requirement to identify and correct system flaws within organizationally defined timeframes.
- **SR-5 (Acquisition Strategies, Tools, and Methods)** — Rule 2: GPL/AGPL prohibition restricts acquisition to licenses compatible with government purpose rights under 48 CFR § 227.7103, reducing supply chain risk from copyleft license obligations.

### 1.2 Adding a New Dependency

Before adding any package:

1. Check the approved list in §3 or §4 — if it's there, proceed
2. If not listed: open a dependency review in the PR description with:
   - Package name and version
   - Purpose — what problem it solves, why an existing approved package doesn't cover it
   - License — confirm not GPL/AGPL
   - CVE status — run `npm audit` and confirm no critical/high findings
   - Weekly downloads and maintenance status (abandoned packages are blocked)
3. Sentinel reviews the addition as part of `GC` or `DP` gate check
4. Once approved, Sentinel adds it to this document

**Governance citations:**
- **SR-3 (Supply Chain Controls and Processes)** — the dependency review process (steps 1–4) establishes the supply chain inspection required before any new component enters the codebase.
- **SR-5 (Acquisition Strategies, Tools, and Methods)** — the CVE status and license checks (step 2) are the acquisition strategy mechanisms that reduce supply chain risk for each evaluated dependency.

### 1.3 Removing a Dependency

Removals do not require pre-approval but must be reflected in this document at next `DP` review. Unused packages are a CVE surface — remove promptly.

---

## Governance Authority

This policy implements the supply chain and flaw remediation control families of NIST SP 800-53 Rev 5 as required for IL4 deployments under the DoD Cloud Computing SRG v1r4. The primary control families this document implements are:

- **SI — System and Information Integrity:** Flaw remediation (SI-2, SI-2(2)) — all CVE prohibition and scanning requirements trace to this family.
- **SR — Supply Chain Risk Management:** Supply chain risk management plan (SR-2), supply chain controls and processes (SR-3), acquisition strategies and methods (SR-5), and component authenticity (SR-11) — the approved dependency list and review process are this project's application-layer SCRM artifact.
- **CM — Configuration Management:** Configuration change control (CM-3), access restrictions for change (CM-5), configuration settings (CM-6), and software usage restrictions (CM-10) — package pinning, lock file requirements, and license controls satisfy these families.

---

## 2 — Prohibited Packages

These packages are **blocked unconditionally**. A PR containing any of these is an automatic gate failure.

| Package | Reason |
|---|---|
| Any `@supabase/*` package | Architecture violation — self-hosted backend only |
| AI-scaffolder tagging packages (e.g. `lovable-tagger`) | Scaffolding-only artifacts — no place in a deployed build |
| Any package with GPL-2.0, GPL-3.0, AGPL-3.0 license | IL4 license constraint |
| Any package with an unresolved critical CVE | Unless POAM-allowlisted per §5 |
| `@aws-sdk/s3-request-presigner` | Presigned URL generation — prohibited by ADR-006. Documents are API-proxied only. |
| `cors` | CORS middleware — The IL4 hosting platform does not allow CORS. Same-domain ALB routing (ADR-015) makes this package both unnecessary and a misconfiguration risk. |
| `@types/cors` | Type definitions for prohibited `cors` package — prohibited by association. |

---

## 3 — Frontend Approved Dependencies

### 3.1 Runtime Dependencies

<!-- Add packages as they pass Sentinel DP review. Format:
| `package-name` | `^version` | License | Purpose | ✅ Approved — Sentinel DP review [story] [date] |
-->

| Package | Version Range | License | Purpose | Status |
|---|---|---|---|---|
| `react` | `^18.3.x` | MIT | UI framework | ✅ Pre-approved |
| `react-dom` | `^18.3.x` | MIT | DOM rendering | ✅ Pre-approved |
| `react-router-dom` | `^6.x` | MIT | Client-side routing | ⚠️ **Avoid** — open moderate CVEs GHSA-wrjc-x8rr-h8h6 / GHSA-337j-9hxr-rhxg in the 6.x line; approve `^7.18+` through Sentinel DP review when routing is needed |
| `@tanstack/react-query` | `^5.x` | MIT | Server state management | ✅ Pre-approved |
| `react-hook-form` | `^7.x` | MIT | Form state management | ✅ Pre-approved |
| `@hookform/resolvers` | `^3.x` | MIT | Zod integration for forms | ✅ Pre-approved |
| `zod` | `^3.x` | MIT | Schema validation | ✅ Pre-approved |
| `axios` | `^1.x` | MIT | HTTP client | ✅ Pre-approved |
| `date-fns` | `^3.x` | MIT | Date manipulation | ✅ Pre-approved |
| `clsx` | `^2.x` | MIT | Conditional classnames | ✅ Pre-approved |
| `tailwind-merge` | `^2.x` | MIT | Tailwind class merging | ✅ Pre-approved |
| `tailwindcss-animate` | `^1.x` | MIT | Animation utilities | ✅ Pre-approved |
| `class-variance-authority` | `^0.7.x` | Apache-2.0 | Component variant API | ✅ Pre-approved |
| `lucide-react` | `^0.x` | ISC | Icon library | ✅ Pre-approved |
| `sonner` | `^1.x` | MIT | Toast notifications | ✅ Pre-approved |
| `next-themes` | `^0.3.x` | MIT | Theme switching | ✅ Pre-approved |
| `@radix-ui/*` | Latest | MIT | Shadcn UI primitives | ✅ Pre-approved (all) |
| `react-oidc-context` | `^3.x` | MIT | React context layer for PKCE OAuth2 / OIDC (ADR-014) | ✅ Pre-approved |
| `oidc-client-ts` | `^3.x` | Apache-2.0 | Standards-based OIDC/OAuth2 engine (ADR-014) | ✅ Pre-approved |

### 3.2 Frontend Dev Dependencies

| Package | Version Range | License | Purpose | Status |
|---|---|---|---|---|
| `vite` | `^7.x` | MIT | Build tool (vitest ^4 requires vite ^6 or ^7) | ✅ Pre-approved |
| `@vitejs/plugin-react-swc` | `^4.x` | MIT | React SWC transform (the ^4 line supports vite 7) | ✅ Pre-approved |
| `typescript` | `^5.x` | Apache-2.0 | Type system | ✅ Pre-approved |
| `tailwindcss` | `^3.x` | MIT | CSS framework | ✅ Pre-approved |
| `autoprefixer` | `^10.x` | MIT | PostCSS plugin | ✅ Pre-approved |
| `postcss` | `^8.x` | MIT | CSS transforms | ✅ Pre-approved |
| `eslint` | `^9.x` | MIT | Linter — flat config (`eslint.config.js`), not `.eslintrc.*` | ✅ Pre-approved |
| `eslint-plugin-react-hooks` | `^5.x` | MIT | React hooks lint rules | ✅ Pre-approved |
| `eslint-plugin-react-refresh` | `^0.4.x` | MIT | HMR lint rules | ✅ Pre-approved |
| `@eslint/js` | `^9.x` | MIT | ESLint JS config | ✅ Pre-approved |
| `typescript-eslint` | `^8.x` | MIT | TS ESLint rules | ✅ Pre-approved |
| `globals` | `^15.x` | MIT | ESLint globals | ✅ Pre-approved |
| `@types/react` | `^18.x` | MIT | React types | ✅ Pre-approved |
| `@types/react-dom` | `^18.x` | MIT | React DOM types | ✅ Pre-approved |
| `@types/node` | `^22.x` | MIT | Node types | ✅ Pre-approved |
| `@tailwindcss/typography` | `^0.5.x` | MIT | Typography plugin | ✅ Pre-approved |
| `vitest` | `^4.x` | MIT | Vite-native test runner for frontend unit/hook tests | ✅ Pre-approved |
| `jsdom` | `^29.x` | MIT | DOM environment for vitest | ✅ Pre-approved |
| `@testing-library/react` | `^16.x` | MIT | React hook and component testing utilities | ✅ Pre-approved |
| `@testing-library/dom` | `^10.x` | MIT | Required peer of `@testing-library/react` 16 | ✅ Pre-approved |
| `@testing-library/jest-dom` | `^6.x` | MIT | Custom DOM matchers for vitest assertions | ✅ Pre-approved |
| `@testing-library/user-event` | `^14.x` | MIT | Simulates real user interactions in tests | ✅ Pre-approved |
| `msw` | `^2.x` | MIT | Mock Service Worker — intercepts API calls in tests (node adapter, no disk write) | ✅ Pre-approved |

---

## 4 — Backend Approved Dependencies

### 4.3 npm Overrides (transitive CVE mitigations)

<!-- Document all npm overrides here with justification. -->

| Override | Pinned To | Reason | Added |
|---|---|---|---|

### 4.1 Backend Runtime Dependencies

| Package | Version Range | License | Purpose | Status |
|---|---|---|---|---|
| `express` | `^4.x` | MIT | Web framework | ✅ Pre-approved |
| `knex` | `^3.x` | MIT | SQL query builder | ✅ Pre-approved |
| `pg` | `^8.x` | MIT | PostgreSQL driver | ✅ Pre-approved |
| `openid-client` | `^5.x` | MIT | Keycloak OIDC / JWKS — Issuer discovery | ✅ Pre-approved |
| `jose` | `^4.x` | MIT | JWT verification + JWKS remote keyset (stateless Bearer token validation) | ✅ Pre-approved |
| `express-rate-limit` | `^7.x` | MIT | Per-IP and per-user request rate limiting | ✅ Pre-approved |
| `@aws-sdk/client-s3` | `^3.x` | Apache-2.0 | S3 GovCloud operations | ✅ Pre-approved |
| `multer` | `^1.x` | MIT | Multipart file upload buffer | ✅ Pre-approved |
| `express-validator` | `^7.x` | MIT | Input validation | ✅ Pre-approved |
| `winston` | `^3.x` | MIT | JSON structured logging | ✅ Pre-approved |
| `helmet` | `^7.x` | MIT | Security headers middleware | ✅ Pre-approved |
| `cors` | any | — | CORS middleware | ❌ **PROHIBITED.** The IL4 hosting platform does not support CORS. Same-domain ALB routing (ADR-015) eliminates any CORS requirement. Installing this package is an automatic Sentinel gate failure. |
| `dotenv` | `^16.x` | BSD-2-Clause | Local env vars | ✅ Pre-approved |
| `uuid` | `^14.x` | MIT | UUID generation (if needed) | ✅ Pre-approved |
| `zod` | `^3.x` | MIT | Request body validation | ✅ Pre-approved |

### 4.2 Backend Dev / Test Dependencies

| Package | Version Range | License | Purpose | Status |
|---|---|---|---|---|
| `jest` | `^29.x` | MIT | Test runner | ✅ Pre-approved |
| `ts-jest` | `^29.x` | MIT | TypeScript Jest transform | ✅ Pre-approved |
| `supertest` | `^6.x` | MIT | HTTP integration testing | ✅ Pre-approved |
| `testcontainers` | `^10.x` | MIT | Real PostgreSQL in tests | ✅ Pre-approved |
| `@types/express` | `^4.x` | MIT | Express types | ✅ Pre-approved |
| `@types/jest` | `^29.x` | MIT | Jest types | ✅ Pre-approved |
| `@types/multer` | `^1.x` | MIT | Multer types | ✅ Pre-approved |
| `@types/cors` | any | — | Types for prohibited `cors` package | ❌ **PROHIBITED** |
| `@types/supertest` | `^6.x` | MIT | Supertest types | ✅ Pre-approved |
| `typescript` | `^5.x` | Apache-2.0 | Type system | ✅ Pre-approved |
| `ts-node` | `^10.x` | MIT | TypeScript execution | ✅ Pre-approved |
| `nodemon` | `^3.x` | MIT | Dev server reload | ✅ Pre-approved |
| `eslint` | `^9.x` | MIT | Linter | ✅ Pre-approved |
| `typescript-eslint` | `^8.x` | MIT | TS lint rules | ✅ Pre-approved |

---

## 4A — core (Python) Approved Dependencies

`core/` is the bot's own runner, in Python 3.12. Pins are exact, in `core/requirements.txt` and
`core/requirements-dev.txt`; a change to either is a dependency change the gate reviews.

| Package | Version | License | Purpose | Status |
|---|---|---|---|---|
| `PyYAML` | `==6.0.2` | MIT | Reads `.securebuilderbot.yml` with line numbers (runtime, the only one) | ✅ Approved — Sentinel DP review, core epic run 1, 2026-10-15 |
| `pytest` | `==9.1.1` | MIT | Test runner (dev only) | ✅ Approved — Sentinel DP review, core epic run 1, 2026-10-15 |
| `pytest-cov` | `==7.1.0` | MIT | Changed-line coverage (dev only) | ✅ Approved — Sentinel DP review, core epic run 1, 2026-10-15 |

Transitive, dev only: `coverage` (Apache-2.0), `pluggy` (MIT), `iniconfig` (MIT), `packaging`
(Apache-2.0 or BSD-2-Clause). None is GPL or AGPL.

The `qa` module (`qa/`, Python 3.12) adds no dependency: its gate and adapters are standard
library, its tests run on the same pytest and pytest-cov pins, and its control tools are bash.
The pytest adapter runs a gated repository's own pytest-cov, which is that repository's dependency.

The `sentinel` module (`sentinel/`, Python 3.12) adds no dependency either: its providers call
the model endpoints over the standard library's `http.client` and `ssl` (no vendor SDK), its
checklist is read with core's PyYAML, and its tests run on the same pytest and pytest-cov pins.

### 4A.1 — scanners (Python)

`scanners/` runs the eight scanners; its one Python dependency is the ecosystem audit for Python
apps, pinned in `scanners/requirements.txt` and, for the runner's version check, in
`scanners/scripts/tool-versions.env` (`SCAN_PIP_AUDIT_VERSION`). The CI workflows and the scanners
image install it; `run-pip-audit.sh` refuses any other version.

| Package | Version | License | Purpose | Status |
|---|---|---|---|---|
| `pip-audit` | `==2.10.1` | Apache-2.0 | The ecosystem audit for Python apps (`run-pip-audit.sh`), reading PyPI's advisory feed at run time | ✅ Approved — scanners epic, 2026-10-23 (Sentinel DP review at the epic gate) |

Transitive, runtime of the scanner only: `cyclonedx-python-lib` (Apache-2.0), `pip-api`
(Apache-2.0), `pip-requirements-parser` (MIT), `requests` (Apache-2.0), `rich` (MIT),
`CacheControl` (Apache-2.0), `platformdirs` (MIT), `packaging` (Apache-2.0 or BSD-2-Clause),
`toml`/`tomli`/`tomli-w` (MIT). None is GPL or AGPL. The scanner binaries the module pins (hadolint,
checkov, ClamAV, Grype, Trivy) are tools the bot runs, not packages it imports; their pins are
`scanners/scripts/tool-versions.env` and `scanners/pins.md`.

## 4B — adapter-github (Node) Approved Dependencies

`adapter-github/` is the GitHub face of the bot, TypeScript on Node 22, with **no runtime
dependency**: the GitHub API is a small typed client over the platform's `fetch`
(`adapter-github/src/github-api.ts`), so nothing ships to a user's runner beyond the bot itself.
Every package below is a dev dependency, pinned exactly in `adapter-github/package.json`; the
lockfile `adapter-github/package-lock.json` is committed and `npm ci` installs it. A change to
either is a dependency change the gate reviews. `npm audit` on the tree: 0 findings
(2026-10-23). Every package in the tree is MIT, Apache-2.0, BSD, ISC, BlueOak-1.0.0 (jackspeak,
path-scurry) or Python-2.0 (argparse); none is GPL, LGPL or AGPL.

| Package | Version | License | Purpose | Status |
|---|---|---|---|---|
| `typescript` | `5.9.3` | Apache-2.0 | The type system (`tsc --noEmit` is the typecheck) | ✅ Approved — adapter-github, 2026-10-23 |
| `tsx` | `4.23.15` | MIT | Runs `src/main.ts` in the Action without a build step | ✅ Approved — adapter-github, 2026-10-23 |
| `vitest` | `4.1.12` | MIT | Test runner | ✅ Approved — adapter-github, 2026-10-23 |
| `@vitest/coverage-v8` | `4.1.12` | MIT | Coverage with the il6 thresholds, lcov to `coverage/lcov.info` | ✅ Approved — adapter-github, 2026-10-23 |
| `eslint` | `9.39.5` | MIT | Linter, flat config | ✅ Approved — adapter-github, 2026-10-23 |
| `typescript-eslint` | `8.72.0` | MIT | TypeScript lint rules and parser | ✅ Approved — adapter-github, 2026-10-23 |
| `eslint-plugin-security` | `4.2.0` | Apache-2.0 | Security lint rules (two off by decision, reasons in `adapter-github/eslint.config.js`) | ✅ Approved — adapter-github, 2026-10-23 |
| `@types/node` | `22.20.5` | MIT | Node 22 types | ✅ Approved — adapter-github, 2026-10-23 |

**Why vitest 4.1.12 and a lockfile written by npm 12.** Every vitest below 4.1.11 carries
GHSA-82fw-gwwq-j7x9 and GHSA-qxg6-89mg-rqv8 (critical, `@vitest/mocker`), which this policy
blocks even in a dev dependency. npm 10.9 (what `actions/setup-node` ships with Node 22) crashes
resolving vitest 4.1's peer set from scratch (`Cannot read properties of null (reading
'edgesOut')`); it installs the committed lockfile with `npm ci` without re-resolving. The lockfile
was therefore written with `npx npm@12.2.1 install --package-lock-only` and verified with npm 10's
`npm ci` and `npm audit` (0 findings). Regenerate it the same way after a pin changes.

## 4C — adapter-gitlab (Node) Approved Dependencies

`adapter-gitlab/` is the GitLab CI/CD component and merge request publisher, TypeScript on Node 22,
run with `npx tsx` and never built. Pins are exact (stricter than §1.1 rule 5, on purpose: the bot
is a security tool and a floating minor is a change nobody reviewed), in `adapter-gitlab/package.json`
with its committed lockfile; `npm audit` reports no advisory at any level as of 2026-10-23.

| Package | Version | License | Purpose | Status |
|---|---|---|---|---|
| `tsx` | `4.23.15` | MIT | Runs the publisher from source in the CI job (the one runtime dependency) | ✅ Approved — adapter-gitlab build, 2026-10-23 |
| `typescript` | `5.9.3` | Apache-2.0 | Type checking, `strict` (dev only) | ✅ Approved — adapter-gitlab build, 2026-10-23 |
| `vitest` | `4.1.12` | MIT | Test runner (dev only) | ✅ Approved — adapter-gitlab build, 2026-10-23 |
| `@vitest/coverage-v8` | `4.1.12` | MIT | lcov coverage for the changed-line check (dev only) | ✅ Approved — adapter-gitlab build, 2026-10-23 |
| `eslint` | `10.12.0` | MIT | Linter, flat config, zero warnings (dev only; the 9.x line is end of life) | ✅ Approved — adapter-gitlab build, 2026-10-23 |
| `typescript-eslint` | `8.72.0` | MIT | Type-aware lint rules (dev only) | ✅ Approved — adapter-gitlab build, 2026-10-23 |
| `eslint-plugin-security` | `4.2.0` | Apache-2.0 | Security lint rules (dev only) | ✅ Approved — adapter-gitlab build, 2026-10-23 |
| `@types/node` | `22.20.5` | MIT | Node 22 types (dev only) | ✅ Approved — adapter-gitlab build, 2026-10-23 |

Transitive: `esbuild` and `get-tsconfig` under tsx (MIT); vite, rollup and the vitest workspace
under vitest (MIT); `@typescript-eslint/*` (MIT); `safe-regex` under the security plugin (MIT).
The lockfile carries no GPL, LGPL or AGPL package (checked over every `license` field).

<!-- cli module -->
## 4D — cli (Node) Approved Dependencies

`cli/` is the npm package `securebuilderbot` (`securebuilderbot init`, `securebuilderbot run`),
TypeScript on Node 22, run from source through `tsx` (the one runtime dependency: the bin stub
loads `src/main.ts` with `tsx/esm/api`); it imports the two adapters' source by relative path, so
it adds no package of theirs. Exact pins in `cli/package.json`; the lockfile `cli/package-lock.json`
was written with `npx npm@12.2.1 install --package-lock-only` (the reason is in § 4B) and installs
with `npm ci`. Its package set is the same as adapter-gitlab's, version for version. `npm audit`:
0 vulnerabilities (2026-10-23).

| Package | Version | License | Purpose | Status |
|---|---|---|---|---|
| `tsx` | `4.23.15` | MIT | Runs `src/main.ts` from the bin stub without a build step (the one runtime dependency) | ✅ Approved — cli build, 2026-10-23 |
| `typescript` | `5.9.3` | Apache-2.0 | Type checking, `strict` (dev only) | ✅ Approved — cli build, 2026-10-23 |
| `vitest` | `4.1.12` | MIT | Test runner (dev only) | ✅ Approved — cli build, 2026-10-23 |
| `@vitest/coverage-v8` | `4.1.12` | MIT | Coverage with the il6 thresholds, lcov (dev only) | ✅ Approved — cli build, 2026-10-23 |
| `eslint` | `10.12.0` | MIT | Linter, flat config, zero warnings (dev only) | ✅ Approved — cli build, 2026-10-23 |
| `typescript-eslint` | `8.72.0` | MIT | Type-aware lint rules (dev only) | ✅ Approved — cli build, 2026-10-23 |
| `eslint-plugin-security` | `4.2.0` | Apache-2.0 | Security lint rules (dev only; one rule off, reason in `cli/eslint.config.js`) | ✅ Approved — cli build, 2026-10-23 |
| `@types/node` | `22.20.5` | MIT | Node 22 types (dev only) | ✅ Approved — cli build, 2026-10-23 |

Every `license` field in the lockfile is MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC,
BlueOak-1.0.0 (`minimatch`) or MPL-2.0 (`lightningcss` and its platform binaries, an optional
dependency of vite under vitest, dev only, never shipped or modified); none is GPL, LGPL or AGPL.
§ 6.1 lists neither BlueOak-1.0.0 nor MPL-2.0; both arrive through the same vitest tree as § 4B
and § 4C, and are recorded here for the maintainer's review rather than read as approved.

## 5 — Vulnerability Threshold Policy

### 5.1 Severity Thresholds

| Severity | Action | Timeline |
|---|---|---|
| **Critical** | Block — do not ship. Update or replace package immediately. If no fix exists, initiate POAM. | 0 days |
| **High** | Block — update or replace before merge. If no fix exists, initiate POAM within 24 hours. | 24 hours |
| **Medium** | Flag — document in PR. Update at next scheduled dependency maintenance cycle. | Next sprint |
| **Low** | Log — tracked but non-blocking. | Next quarterly review |

**Governance citations:**
- **SI-2 (Flaw Remediation)** — severity thresholds and response timelines implement SI-2's requirement to install security-relevant updates within organizationally defined time periods (0 days for critical, 24 hours for high).
- **SI-2(2) (Automated Flaw Remediation Status)** — pipeline `npm audit` enforcement of these thresholds is the automated mechanism required by SI-2(2) to determine the current state of flaw remediation across the system.

### 5.2 POAM Process for Unresolvable CVEs

If a critical or high CVE has no available patch and the package cannot be replaced:

1. Document the finding in the project's POAM allowlist (format per the platform team's guidance)
2. Submit a Change Request to the platform team to add to the scanner allowlist
3. Set a remediation target date (max 90 days for high; max 30 days for critical)
4. Review at each sprint — close the POAM entry when a fix is available and applied

**Governance citation:**
- **CA-5 (Plan of Action and Milestones)** — entries in the project's POAM allowlist and the associated platform team Change Request are the plan of action and milestone tracking required by CA-5 (a formal RMF artifact per NIST SP 800-37) to document accepted risk with scheduled remediation dates.

### 5.3 Scanning

`npm audit` runs as part of the `quality:lint` CI stage. PRs with critical or high findings that are not POAM-allowlisted are blocked from merge.

**Governance citations:**
- **SI-2 (Flaw Remediation)** — `npm audit` in the `quality:lint` CI stage is the automated flaw identification and reporting mechanism that satisfies SI-2's scanning requirement.
- **SR-11 (Component Authenticity)** — Anchore container scanning evaluates package provenance alongside CVE findings, contributing to the component authenticity verification required by SR-11.

---

## 6 — License Policy

### 6.1 Approved Licenses

| License | Approved | Notes |
|---|---|---|
| MIT | ✅ Yes | |
| Apache-2.0 | ✅ Yes | |
| BSD-2-Clause | ✅ Yes | |
| BSD-3-Clause | ✅ Yes | |
| ISC | ✅ Yes | |
| CC0-1.0 | ✅ Yes | |

### 6.2 Prohibited Licenses

| License | Status | Reason |
|---|---|---|
| GPL-2.0 | ❌ Prohibited | Copyleft — IL4 deployment constraint |
| GPL-3.0 | ❌ Prohibited | Copyleft — IL4 deployment constraint |
| AGPL-3.0 | ❌ Prohibited | Strong copyleft — IL4 deployment constraint |
| LGPL-2.1 | ⚠️ Review required | Weak copyleft — permitted only with explicit legal review |
| LGPL-3.0 | ⚠️ Review required | Same |
| Unknown / Unlicensed | ❌ Prohibited | No license = all rights reserved |
| Custom / Proprietary | ⚠️ Review required | Case-by-case — submit for Sentinel + legal review |

**Governance citations:**
- **SR-5 (Acquisition Strategies, Tools, and Methods)** — the approved license list (§6.1) is an acquisition strategy control restricting package selection to licenses compatible with government purpose rights and IL4 deployment constraints.
- **SR-3 (Supply Chain Controls and Processes)** — license review as part of the §1.2 dependency addition process constitutes a supply chain inspection step, ensuring components comply with contractual and legal obligations before entering the codebase.

---

## 7 — Pre-Sprint-1 Dependency Audit

<!-- Before Sprint 1: verify that no prohibited packages are present in package.json.
Common items to check:
- Any BaaS client SDKs (e.g. `@supabase/*`) → remove
- Any scaffolding-only packages (e.g. `lovable-tagger`) → remove
- Any packages with GPL/AGPL licenses → remove
- Any packages with known critical CVEs → update or replace
Add completed items to the gate log after Sentinel review.
-->

| # | Check | Action | Owner |
|---|---|---|---|
| 1 | Verify no prohibited packages in `package.json` | Audit and remove | Amelia |

---

## Cross-Reference

For the authoritative mapping of all Sentinel gate checks to NIST SP 800-53 Rev 5 control IDs, see `standards/data/controls/CONTROLS-MAPPING.md`.

---

*Owned by Sentinel. All dependency additions require gate approval. Violations are blocking findings.*
