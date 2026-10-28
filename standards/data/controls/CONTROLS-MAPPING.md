## About This Document

**Purpose:** Maps every Sentinel gate check to the NIST SP 800-53 Rev 5 control family and control IDs it is grounded in, so a reader can see why each check exists and find the related control. A navigation aid — see "What this document is not" below.

**Workflow role:** Sentinel reads it to confirm its checks are grounded in controls rather than in someone's preference. An SSP author may use it to locate which gate check happens to exercise a control; what goes in the SSP, and the evidence cited there, remain theirs and the platform's.

**How to fill in:** Rows 1–20 are framework-level gate checks applicable to all projects. Rows 9–13 and 15 are project-specific placeholders (view-only reads, state-field mutation paths, `SELECT FOR UPDATE`) drawn from Key Architecture Constraints — replace them with your application's equivalent data-access patterns and database constraints.

---

# Controls Mapping — Sentinel Gate Checks → NIST SP 800-53 Rev 5

**Scope:** Maps every Sentinel gate checklist item in `engine/SENTINEL-CHECKLIST.md` to its NIST SP 800-53 Rev 5 control family and control ID(s), plus an OWASP reference where the mapping is unambiguous.
**References:** NIST SP 800-53 Rev 5 (2020); IL4-baseline.md; IL6-delta.md; OWASP Top 10 for Web Application Security **2025 edition**; OWASP Top 10 for LLM Applications **2025 edition**. Editions are named because the numbering moves between them, and both are verified mechanically by `make verify-citations` against `controls/owasp-index.json`.
**Last updated:** 2026-09-19

---

## What this document is not

This engine produces **development records** — the gate log, Sentinel's verdict history, the
findings register, the governance changelog. They exist so a human can see what was reviewed, what
was found, and what became a ticket, and so each retro can turn a finding into a standing check.

**They are not accreditation evidence, and this table is not an ATO artifact.** The platform owns
the ATO package and the artifacts in it. Where a control requires evidence, a human may cite this
engine's output as an input to what they write; the engine's records are never the submission. The
same boundary the control documents already draw for the RMF process (see `IL6-delta.md`,
`providers/aws/IL6-implementation.md`, `controls/CDS-guidance.md`) applies to the records too.

The practical consequence, which the gate follows: **a missing or unwritten record never blocks
development.** It is a finding that opens a ticket. A gate check blocks only when skipping it would
leave another check verifying nothing.

---

## How to Read This Table

- **Gate Check** — the exact label used in the Sentinel checklist (`engine/SENTINEL-CHECKLIST.md`).
- **Primary Controls** — the 800-53 control IDs most directly satisfied by this check.
- **Supporting Controls** — controls that are partially satisfied or whose requirements this check contributes to.
- **Baseline** — `IL4` means the check is active for both IL4 and IL6. `IL6` means the check is only active when `SECURITY_TIER=IL6`.
- **OWASP** — the OWASP Top 10 for Web Application Security **2025** category the check speaks to. Left **blank** where more than one category could reasonably claim it; a blank means "not confidently mapped", never "not covered".

---

## Sentinel Gate Checks — IL4 Baseline (Always Active)

| # | Gate Check Label | Primary Controls | Supporting Controls | Baseline | OWASP |
|---|---|---|---|---|---|
| 1 | No hardcoded secrets or credentials — no fallback/default values in config or env definitions | IA-5 (Authenticator Management), CM-6 (Configuration Settings) | SA-3 (System Development Life Cycle), CM-3 (Change Control) | IL4 | A02 Security Misconfiguration |
| 2 | All endpoints require valid Keycloak token (except OAuth callback) | IA-2 (Identification and Authentication), AC-3 (Access Enforcement) | AC-6 (Least Privilege) | IL4 | A07 Authentication Failures |
| 3 | Auth middleware registered before all route handlers — no route reachable without auth | AC-3 (Access Enforcement), SA-8 (Security and Privacy Engineering Principles) | IA-2 | IL4 | A01 Broken Access Control |
| 4 | Negative auth test required: every endpoint asserts 401 without a token | CA-2 (Control Assessments), SA-11 (Developer Testing) | SA-11(1) (Static Code Analysis) | IL4 | A07 Authentication Failures |
| 5 | RBAC scoping enforced per the project's PRD RBAC table — every role lane (e.g. `admin` / `editor` / `user`) enforced at the API layer | AC-2 (Account Management), AC-3 (Access Enforcement) | AC-6 (Least Privilege), AC-6(1), AC-6(10) | IL4 | A01 Broken Access Control |
| 6 | Negative RBAC tests: user A cannot read/mutate user B's records; `user` role cannot access or mutate records they do not own | AC-3 (Access Enforcement), AC-4 (Information Flow Enforcement) | CA-2(2), SA-11 | IL4 | A01 Broken Access Control |
| 7 | Last-admin guard on endpoints that deactivate or demote a user — enforced at API layer | AC-2 (Account Management), AC-5 (Separation of Duties) | AC-6(2) | IL4 | A01 Broken Access Control |
| 8 | SQL injection prevented — parameterized queries only | SI-10 (Information Input Validation) | SA-11, CA-2 | IL4 | A05 Injection |
| 9 | Application reads query a protected database view, not base tables directly — the view enforces row-level access policy | AC-3 (Access Enforcement), SA-8 (Security and Privacy Engineering Principles) | CM-5 (Access Restrictions for Change) | IL4 | A01 Broken Access Control |
| 10 | State-field mutations only via dedicated PATCH endpoints | CM-5 (Access Restrictions for Change), AC-3 (Access Enforcement) | SI-10 | IL4 | A01 Broken Access Control |
| 11 | `PUT /:id` rejects state fields in body | CM-5 (Access Restrictions for Change), SI-10 (Information Input Validation) | SA-8 | IL4 |  |
| 12 | Concurrent state-mutation endpoints use `SELECT FOR UPDATE` transactions (record the pattern in the project's ADR-LOG) | AC-3 (Access Enforcement), SI-10 (Information Input Validation) | SC-5 (Denial-of-service Protection) | IL4 |  |
| 13 | Concurrent status-transition endpoints use `SELECT FOR UPDATE` transactions (record the pattern in the project's ADR-LOG) | AC-3 (Access Enforcement), SI-10 (Information Input Validation) | SC-5 | IL4 |  |
| 14 | Soft-delete / archive filters (e.g. `deleted_at`, `archived_at`) on all active-record queries where the schema defines them | AC-3 (Access Enforcement), SI-12 (Information Management and Retention) | CM-5 | IL4 | A01 Broken Access Control |
| 15 | Computed/generated database columns never written by application code — database enforces immutability of generated fields | CM-5 (Access Restrictions for Change), SA-8 (Security and Privacy Engineering Principles) | SI-10 | IL4 |  |
| 16 | Custom Express error handler wired globally — no stack traces, internal messages, DB errors, file paths, or object-store keys in any API response | SI-11 (Error Handling) | SC-28 (Protection of Information at Rest — indirect: prevents path disclosure) | IL4 | A02 Security Misconfiguration |
| 17 | File uploads use in-memory storage — no disk writes on backend pods | SC-28 (Protection of Information at Rest), CM-6 (Configuration Settings) | SI-12 | IL4 |  |
| 18 | No presigned object-store URLs generated — file downloads are API-proxied only (record in the project's ADR-LOG) | AC-3 (Access Enforcement), SC-8 (Transmission Confidentiality) | SC-8(1) | IL4 | A01 Broken Access Control |
| 19 | No server-side token storage, session tables, or session middleware | IA-5 (Authenticator Management), SC-23 (Session Authenticity) | SC-28 | IL4 | A07 Authentication Failures |
| 20 | All new dependencies present in `docs/architecture/DEPENDENCY_POLICY.md` | SR-3 (Supply Chain Controls and Processes), CM-3 (Configuration Change Control) | SR-5 (Acquisition Strategies), SR-11 (Component Authenticity), RA-3(1) (Supply Chain Risk Assessment) | IL4 | A03 Software Supply Chain Failures |

---

## Sentinel Gate Checks — IL6 Additional Block (Active When SECURITY_TIER=IL6)

| # | Gate Check Label | Primary Controls | Supporting Controls | Baseline | OWASP |
|---|---|---|---|---|---|
| IL6-1 | FIPS 140-3 validated crypto libraries only — no MD5, SHA-1, RC4, or non-FIPS-validated TLS ciphers | IA-7 (Cryptographic Module Authentication), SC-13 (Cryptographic Protection) | SC-8(1) | IL6 | A04 Cryptographic Failures |
| IL6-2 | All API responses include classification banner header per applicable classification guide | SC-16 (Transmission of Security and Privacy Attributes) | SI-12, ICD 710 (CAPCO) | IL6 |  |
| IL6-3 | No unclassified external calls at runtime — no public npm registries, CDNs, or third-party endpoints | SC-7(8) (Boundary Protection — managed interface) | SA-9(2) | IL6 |  |
| IL6-4 | Audit logs written to tamper-evident, append-only store not writable by the application process | AU-9(2) (Store on Separate Physical Systems or Components) | AU-9(3), AU-9(4), AU-10 | IL6 | A09 Security Logging and Alerting Failures |
| IL6-5 | CDS integration points documented and not bypassed (see `CDS-guidance.md`) | SC-16(1) (Transmission — validate security attributes on import) | CA-3, DoD CC SRG §6.6 | IL6 |  |
| IL6-6 | Personnel clearance level not stored in application DB — delegated to identity provider | IA-4 (Identifier Management), AC-2 (Account Management) | IA-12, PS-3 | IL6 |  |
| IL6-7 | FIPS 140-3 module list verified — all cryptographic operations use NIST-validated modules only | SC-13 (Cryptographic Protection), IA-7 (Cryptographic Module Authentication) | CNSSP-15 | IL6 | A04 Cryptographic Failures |

---

## Android Track Gate Checks → Controls (active when `APP_TRACK=android`)

When `APP_TRACK=android`, Sentinel replaces the web-track container / Node.js / PostgreSQL items
with these. The `SECURITY_TIER` overlay applies on top. STIG IDs are **not** duplicated here — they
live in `standards/data/providers/android/STIG-checklist.md`, which also carries the standing
caveat that STIG IDs must be verified against the DISA STIG Viewer before use in a formal
assessment.

**The mobile baseline is OWASP MASVS v2, not the DISA Mobile Application STIG.** The mobile STIG is
CUI-marked and published behind DoD PKI; these are not CUI workstations, so it cannot enter this
repository, and no redistributor carries it either. That is a documented boundary, not an open gap —
the same line the Agent Security Rules draw around POAMs and platform scan artifacts. MASVS ships a
machine-readable catalogue, so unlike a mobile STIG ID, every `MASVS-*` ID below is checked on every
push by `make verify-citations`. MASVS is an industry standard and **not a DoD authority**: it
grounds these checks, it does not accredit them. A `—` means no MASVS control fits — left blank
rather than guessed, the same rule as the OWASP column.

**Additional references:** OWASP MASVS v2 (`standards/data/controls/masvs-index.json`);
NIST SP 800-163 Rev 1; NIST SP 800-124 Rev 2.

| # | Gate Check Label | Primary Controls | Supporting Controls | OWASP | MASVS |
|---|---|---|---|---|---|
| AND-1 | All network calls use TLS 1.2 minimum, 1.3 preferred — no cleartext HTTP | SC-8 (Transmission Confidentiality and Integrity), SC-8(1) | SC-13 | A04 Cryptographic Failures | MASVS-NETWORK-1 |
| AND-2 | No sensitive data written to Android external storage — internal app storage only | SC-28 (Protection of Information at Rest) | AC-3 | A01 Broken Access Control | MASVS-STORAGE-1 |
| AND-3 | No sensitive data logged via `Log.d` / `Log.v` / `Log.i` — no PII, tokens or credentials in logcat | AU-3 (Content of Audit Records), SI-11 (Error Handling) | SC-28 | A09 Security Logging and Alerting Failures | MASVS-STORAGE-2 |
| AND-4 | Authentication token stored in Android KeyStore — not SharedPreferences or local files | IA-5 (Authenticator Management), SC-28 | SC-12 (Key Establishment and Management) | A04 Cryptographic Failures | MASVS-CRYPTO-2 |
| AND-5 | Backend API calls carry `Authorization: Bearer <token>`; no unauthenticated endpoint reachable from the app | IA-2 (Identification and Authentication), AC-3 (Access Enforcement) | — | A07 Authentication Failures | MASVS-AUTH-1 |
| AND-6 | Certificate pinning evaluated; justified absence accepted (government CA chain may make it redundant) | SC-8(1) | SC-17 (Public Key Infrastructure Certificates) |  | MASVS-NETWORK-2 |
| AND-7 | No hardcoded credentials, API keys or base URLs in source — injected via build config or secure storage | IA-5, CM-6 (Configuration Settings) | — | A02 Security Misconfiguration | MASVS-STORAGE-1 |
| AND-8 | Exported components (`Activity`, `Service`, `BroadcastReceiver`) minimised; each one justified in the report | CM-7 (Least Functionality), AC-3 | AC-6 | A01 Broken Access Control | MASVS-PLATFORM-1 |
| AND-9 | `minSdkVersion` documented and justified — must support TLS enforcement and KeyStore availability | CM-2 (Baseline Configuration), CM-6 | — |  | MASVS-CODE-1 |
| AND-10 | `APP_TYPE=atak` only: plugin manifest declares a minimum ATAK version at or above the required floor | CM-2 (Baseline Configuration) | CM-6 |  | — |

---

## Tactical Provider Checks → Controls (active when `PROVIDER=tactical`)

When `PROVIDER=tactical`, these substitute for the cloud infrastructure checks (managed secrets,
registry, Helm, Terraform, cloud IAM). Application-layer checks are unchanged and remain mandatory
regardless of provider. Grounded in ADR-023 and `standards/data/providers/tactical/`; open gaps
OG-6a through OG-6e are recorded there as accepted-risk items, not findings.

These checks confirm that something is **documented by the deploying team**. The documents and the
authorisation they record belong to that team and their ISSO, not to this engine.

| # | Gate Check Label | Primary Controls | Supporting Controls |
|---|---|---|---|
| TAC-1 | TLS termination documented at the server / reverse-proxy layer; cipher suite ≥ TLS 1.2 | SC-8, SC-8(1) | SC-13 |
| TAC-2 | No plaintext secrets in provisioning scripts, environment files or tracked configuration | IA-5, CM-6 | SC-28 |
| TAC-3 | Audit log destination documented, satisfying the 365-day retention requirement | AU-2 (Event Logging), AU-11 (Audit Record Retention) | AU-4, AU-9 |
| TAC-4 | Data-at-rest encryption documented for the database volume and persistent storage (LUKS or equivalent) | SC-28, SC-28(1) | SC-13 |
| TAC-5 | Network firewall rules documented — only required ports open; no management ports exposed to the client network segment | SC-7 (Boundary Protection), SC-7(5) | CM-7 |
| TAC-6 | OS and runtime packages current — no critical/high CVEs in deployed packages at deployment time | SI-2 (Flaw Remediation), RA-5 (Vulnerability Monitoring) | SI-2(2) |
| TAC-7 | Deployment authorisation documented — evidence of ISSO/AO approval for this application on this network | CA-6 (Authorization) | — |

---

## Assurance and Lifecycle Checks → Controls

The checks below were added after 2026-05-01. They are not application behaviours — they are how
the engine keeps its own checks honest.

**Read the control IDs here as grounding, not as satisfaction.** Each names the control that
motivates the check; none of them is a control this engine satisfies on a project's behalf.

The **Blocking?** column follows one rule: *a finding blocks only if skipping it would leave
another check verifying nothing.* Everything else is a finding that opens a retro ticket.

| Gate Check Label | Primary Controls | Supporting | Blocking? | Notes |
|---|---|---|---|---|
| Control-manifest row present, and `make verify-controls` resolves it | CM-3 (Configuration Change Control), CM-5 (Access Restrictions for Change), SA-11 | CA-7 | **blocks** | Without the row, `verify-controls` and `mutate-controls` have nothing to check and pass silently. Call sites are recomputed from the tree every run, never read from the manifest. |
| Control Completeness Review answered in prose (control-shaped ranges only) | SA-8 (Security and Privacy Engineering Principles), SA-11 | CA-2 | **blocks** | The checklist catches a control that is *absent*; this catches one that is *present and stops early*. A question answered "PASS" has not been asked. |
| Pre-flight deltas named (`make gate-state`) | CA-7 (Continuous Monitoring) | CM-6 | named in the gate-log row; control decay **blocks** | A delta from outside the range gets one sentence, not a ticket. The probe itself never remediates and never blocks. |
| Rulebook changes in their own commit (`engine/GOVERNANCE.md`) | CM-3, CM-5, AC-5 (Separation of Duties) | SA-10 (Developer Configuration Management) | **blocks** when mixed with other changes | The accountable control is the human reading that commit's diff; the AI gate cannot be the backstop for a change to its own rules. |
| Platform-surface report — filenames, counts, key presence, never values | CM-2 (Baseline Configuration), CM-3 | CM-6 | listed in the verdict; the human's merge is the consent | Reporting is not a write. Silence about the frozen surface is a protocol violation, not deference. |
| Legacy inventory (`make legacy-inventory`) | CA-7, RA-3 (Risk Assessment) | — | reported | Which source files no gate has ever read. Each disposition is a human decision. |
| Findings-become-checks; permanent-checks register | CA-7 | — | reported | Table B rows whose compensating control is unbuilt are reported every run until built. This register is engine-internal; the project's actual POA&M is the platform artifact (see `docs/architecture/DEPENDENCY_POLICY.md`). |
| LLM06 — excessive agency (agent write boundaries) | AC-3, AC-6 (Least Privilege), CM-5 | SA-8 | **blocks** for an unconsented write | No agent merges or pushes to main, or edits `docs/PRD.md` outside a planning session; platform-file changes are named in the verdict for the human. Sentinel itself writes only `gate-records/` and `planning/tickets/`. |
| Negative user stories NS-01..NS-18, plus every project-specific SHALL NOT in `docs/PRD.md` | traced individually into the AC / SI / SC / IA rows above | — | **blocks** | Listed under "Also verify" in `engine/SENTINEL-CHECKLIST.md`. Each must trace to a specific guard, middleware or test — "it probably doesn't" is not verification. |

---

## Quality Gate Checks → Controls

The quality gate asks whether the tests prove the code. These checks are not security controls in the traditional sense but contribute to the assurance of security controls by ensuring that security-relevant tests exist, run, and would fail if the control stopped working.

| Check | Contributing Controls | Notes |
|---|---|---|
| Test coverage ≥ defined threshold (per `engine/QUALITY_GATE.md`) | CA-2 (Control Assessments), SA-11 (Developer Testing) | Coverage ensures security-relevant code paths are exercised |
| `make mutate-controls` — every row in `docs/security/CONTROL-MANIFEST.md` is broken on purpose and the suite must go red | SA-11 (Developer Testing), SA-11(1) | Supersedes the TDD red-phase commit artifact, removed 2026-09-16. A red phase proved a test failed once, before the code existed; mutation proves the tests still depend on the control today, and re-proves it every gate. A control that survives mutation is `NOT PROVEN` and blocking. Supporting: CA-2(2), CM-5 |
| Full test suite passes before Sentinel review | SA-11(1), CA-2(2) | Failing suite = unverified behavior = Sentinel gate invalid |
| Negative auth test present for every new endpoint | CA-2(2), SA-11 | Directly maps to Sentinel check #4 above |
| Negative RBAC test present | CA-2(2), SA-11 | Directly maps to Sentinel check #6 above |

---

## Control Families Not Directly Mapped to Gate Checks

The following control families are required at IL4 but are not implemented by application-layer gate checks. They are inherited from the hosting platform ATO, addressed at the organizational/operational level, or implemented by Keycloak/infrastructure:

| Family | Primary Implementation Mechanism |
|---|---|
| AT — Awareness and Training | Organizational policy; personnel training records |
| CP — Contingency Planning | Hosting platform ATO; backup and recovery procedures |
| IR — Incident Response | Platform SOC; organizational IR procedures |
| MA — Maintenance | Hosting platform ATO; infrastructure team |
| MP — Media Protection | Hosting platform ATO; data center physical controls |
| PE — Physical and Environmental | Platform data center controls; inherited ATO |
| PL — Planning | SSP; organizational planning artifacts |
| PM — Program Management | Organizational; ISSM/ISSO roles |
| PS — Personnel Security | Organizational personnel security; CAC vetting |
| RA — Risk Assessment | ATO/RMF; POAM process (DEPENDENCY_POLICY.md §5.2) |
| CA (partial) — ATO/authorization activities | ATO process; organizational |

---

## OWASP Top 10 for LLM Applications — what this engine enforces

The engine is itself an agent system, so this list applies to the engine as much as to anything it
builds. Recorded here so that what is *not* covered is visible rather than merely absent.

| ID | Category | Status | Where |
|---|---|---|---|
| LLM01 | Prompt Injection | **not covered** | No check treats repository content — issue text, dependency READMEs, fetched documentation — as untrusted input to an agent. See Known gaps. |
| LLM02 | Sensitive Information Disclosure | enforced | Agent Security Rules in `CLAUDE.md`: never read `helm/values-*.yaml` or any `*.tfvars`; never echo account IDs, ARNs, security group IDs, endpoints, bucket names or client secrets. The platform-surface report is filenames, counts and key presence — never values. |
| LLM05 | Improper Output Handling | **not covered** | No check constrains how agent output is consumed downstream. |
| LLM06 | Excessive Agency | enforced | Step 13 of `.claude/agents/gate.md` (platform surface and agent write boundaries), the human merge, and the `git push` / `git merge` / `gh pr merge` guard in `engine/scripts/guard-main.sh`. |
| LLM08 | Vector and Embedding Weaknesses | **N/A** | No retrieval-augmented generation, no vector store, no embedding pipeline anywhere in the engine. Re-open if one is introduced. |
| LLM10 | Unbounded Consumption | **not covered** | No resource ceiling on agent sessions or gate runs. |

---

## Known Gaps

Documented so a future decision has somewhere to land. **None of these is a rule.** Adding one to
the Sentinel checklist is a rulebook change: its own commit, and the User reads the diff (`engine/GOVERNANCE.md`).

| Gap | Control it would speak to | Proposed disposition |
|---|---|---|
| **Audit event generation at IL4.** Nothing verifies the application *emits* an audit record for a privileged action — a role change, a deactivation, a denied authorisation. `IL4-baseline.md` marks AU-2 and AU-12 as satisfied by application logging middleware, and AC-6(9) likewise; audit only becomes a checked item at IL6, and there it checks the store rather than emission. | AU-2, AU-12, AC-6(9) | A **product requirement, not an engine rule.** A project that needs it states it in `docs/PRD.md`, where the existing machinery — PRD requirements and Key Architecture Constraints — already enforces it at the gate. Retention and protection of those records (AU-4, AU-9, AU-11) belong to the platform. |
| **SSRF / outbound request validation.** No check at IL4. The IL6 item "no unclassified external calls at runtime" is a network boundary rule, not validation of a request built from user input. Under the 2025 OWASP list SSRF no longer stands alone — it was folded into A01 Broken Access Control — so the gap now sits inside a category the engine otherwise covers well, which makes it easier to miss, not less real. | SC-7, SI-10 | Open. Best carried as a project-specific Key Architecture Constraint wherever the application makes outbound calls influenced by user input. |
| **Rate limiting and anti-automation.** Absent. SC-5 appears only as a supporting control on the transaction-isolation rows, which is a different concern. | SC-5 | Open. Frequently satisfied at the platform ingress — confirm inheritance before adding an application-layer check. |
| **Framework edition currency — DISA STIGs only.** NIST, both OWASP lists and OWASP MASVS are now pinned, vendored and verified mechanically (`make verify-citations`, `make refresh-frameworks`). The OS and platform STIGs are indexed through ComplianceAsCode, a redistributor rather than DISA. What remains unverifiable is anything DISA publishes only behind DoD PKI — the Application Security and Development STIG (`APSC-DV-*`) and the Mobile Application STIG. | CM-6, CA-7 | **Partly closed 2026-09-19.** The Android track's mobile grounding moved to OWASP MASVS v2, which is machine-verified; the Mobile Application STIG is recorded as a scope boundary (CUI-marked, not a CUI workstation) rather than a gap. The remaining `APSC-DV-*` citations still need a CAC-enabled human or a redistributor that carries that STIG. |
| **A10:2025 Mishandling of Exceptional Conditions has no mapped check.** New in the 2025 list. Row 16 (global error handler, no stack traces or DB errors in responses) is the obvious candidate and is currently mapped to A02 Security Misconfiguration. | SI-11 | Open — a mapping judgment, not a renumbering, so it is a human call rather than something the index can settle. |
| **Prompt injection from untrusted repository content** (LLM01 above). | SI-10 | Open. The cold-window wall stops build rationalisation reaching the reviewer; it does not treat repository content as untrusted input. |

---

## Notes on Using This Mapping

1. **SSP cross-reference:** an SSP author may use this table to find which gate check exercises a given control. What the SSP names as the implementing mechanism, and what it cites as evidence, is the author's call and the platform's to supply — this table is a finding aid, not a source of either.

2. **Records, not evidence.** The gate log (`gate-records/gate-log.md`) and Sentinel's verdict history record what the engine reviewed, what it found, and what became a ticket. They are development records. They are **not** accreditation evidence for SA-11, CA-2 or any other control, and nothing here should be submitted as such — see "What this document is not" above.

3. **Inherited controls:** Controls implemented by the hosting platform, Keycloak, or AWS/Azure infrastructure are documented as "inherited" in the SSP. The platform ATO serves as the inheritance source. Application teams do not re-implement these controls but must confirm inheritance in the SSP.

4. **Tailoring:** This mapping reflects the baseline control set. ATO-specific tailoring (additions or exclusions) is documented in the SSP tailoring statement and does not modify this document.
