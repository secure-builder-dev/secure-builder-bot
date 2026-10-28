## About This Document

**Purpose:** Android track IL6 implementation guide for `SECURITY_TIER=IL6 | PROVIDER=tactical` deployments — maps IL6 High-baseline controls to the Android/ATAK application layer.

**Workflow role:** Frank reads before implementing Android security controls; Sentinel references when running Android + IL6 gate checks; Amelia reads for security-relevant implementation constraints.

**How to fill in:** Replace `<APP_PACKAGE_NAME>` and `<NAMESPACE>` placeholders with your project's values. Review ATAK-specific sections only when `APP_TYPE=atak`.

---

# Android Track IL6 Implementation Guide

**Deployment target:** Classified perimeter network (SECRET-level) — `SECURITY_TIER=IL6 | PROVIDER=tactical`
**Application track:** `APP_TRACK=android` — Kotlin/MVVM native Android app (ATAK plugin or standalone)
**Impact level:** IL6 — data up to SECRET; full NIST SP 800-53 Rev 5 High baseline in force
**Control baseline:** `standards/data/controls/IL4-baseline.md` + `standards/data/controls/IL6-delta.md`
**Last updated:** 2026-05-05

> **NETWORK CONSTRAINT — READ FIRST:** IL6 deployments handle data classified up to SECRET and require a classified network (NSS — National Security System). Deployers must complete an Authority to Operate (ATO) under the Risk Management Framework (RMF) for NSS with DCSA, NSA, or DoD Component oversight as applicable. This document maps the IL6 delta control requirements to Android-specific implementations. It does not perform or substitute for the RMF process.

> **OG-4 OPEN GAP:** ATAK WatchTower distribution support on classified (SIPR/IL6) networks is an open gap pending TAK Product Center confirmation. Until OG-4 is resolved, `ATAK_PLUGIN=true, SECURITY_TIER=IL6` distributions use a manual handoff process — server admin downloads signed APK from the CI artifact store and uploads to WatchTower, or deploys via MDM on the classified network. This document covers both paths.

> **PRIMARY CONFIG:** `APP_TRACK=android | SECURITY_TIER=IL6 | PROVIDER=tactical` is this team's confirmed primary configuration. This document is an implementation guide, not a placeholder — it documents what IL6 requires on Android and where team-specific decisions are still pending (carried as open gaps).

This document covers only the **delta** above the IL4 baseline (`IL4-implementation.md`). All IL4 controls remain fully in force at IL6. Read this document in conjunction with `IL4-implementation.md`.

---

## Reference Sources

| Source | What it covers | Where to find it |
|---|---|---|
| NIST SP 800-53 Rev 5 | High baseline control catalog — full High requirements, including enhancements not in Moderate | `csrc.nist.gov/pubs/sp/800/53/r5/upd1/final` |
| `standards/data/controls/IL6-delta.md` | Cloud-agnostic IL6 High delta — all High-baseline additions and escalations above Moderate | This repo |
| CNSSI 1253 | NSS security categorization and control selection for classified systems | Organizational access via NSS/ISSO channels |
| ICD 503 | Intelligence Community Directive 503 — IT systems security risk management for IC environments | IC community access |
| DoD CC SRG v1r4 | IL6 requirements; C2S/SC2S references; classified network isolation requirements | `public.cyber.mil` → search "Cloud Computing SRG" |
| OWASP MASVS v2 | Mobile application security baseline; applies unchanged at IL6. The Android track's verifiable grounding — the DISA Mobile Application STIG is CUI-marked and out of scope for this repo, see `providers/android/STIG-checklist.md` | [github.com/OWASP/masvs](https://github.com/OWASP/masvs); vendored at `standards/data/controls/masvs-index.json` |
| NIST SP 800-157 | Guidelines for Derived PIV Credentials — relevant for derived CAC authentication on classified networks | `csrc.nist.gov/pubs/sp/800/157/final` (OG-1 reference) |
| `standards/data/controls/CDS-guidance.md` | Cross-domain solution scope boundary — what a deployer must procure separately if CDS is needed | This repo |

---

## IL6 Delta — Access Control

| Control ID | Type | IL6 Requirement | Android / Backend Implementation | How to Verify |
|---|---|---|---|---|
| AC-2(3) | Enhancement | Disable accounts automatically after ≤ 35 days of inactivity (NSS requirement). | Keycloak inactivity policy configured for 35-day automatic account disable. Application user management honors Keycloak account state. | Keycloak admin console → Realm Settings → Sessions confirms inactivity timeout ≤ 35 days. Test with an inactive account — API call returns HTTP 401. |
| AC-2(5) | Enhancement | Require session logout after defined inactivity period. | Keycloak session timeout tightened for IL6 (shorter than IL4 TTL). Android app handles session expiry and re-initiates auth. | Keycloak session timeout value confirmed at deploy time. Android app tested for session expiry handling. |
| AC-3(7) | Enhancement | Enforce role-to-clearance binding. Personnel clearance level must not be stored in the application database — delegated entirely to the identity provider. | Application DB does not store clearance level fields. Keycloak and organizational IdP are the authoritative source for clearance. | `grep -rn "clearance\|classification_level" backend/src/` returns no storage references. DB schema contains no clearance-level columns. |
| AC-6(2) | Enhancement | Privileged users must use non-privileged accounts for non-privileged functions. | Admin role users have separate administrative and operational accounts, managed in Keycloak. Application enforces role separation at the RBAC layer. | Keycloak admin UI confirms separate admin and user accounts for privileged personnel. |
| AC-10 | New at High | Limit concurrent sessions per account. | Keycloak session limit per user configured. Android app handles session conflict gracefully (new session invalidates old). | Keycloak admin console → Sessions shows session limit enforced. Attempt concurrent sessions from two devices — older session invalidated. |
| AC-17(2) | Enhancement | Protect remote access sessions using FIPS 140-3 validated cryptographic mechanisms. | All Android-to-backend TLS uses FIPS 140-3 validated cipher suites on the classified network. See FIPS 140-3 section below. | TLS session cipher suite confirmed via network capture — only FIPS 140-3 approved algorithms. |

---

## IL6 Delta — Audit and Accountability

> **AU-9(2) requirement (new at High):** Audit logs must be written to a store not accessible or writable by the application process. On the tactical provider, this means the log destination is separate from the application runtime — not a local file the application can overwrite. See OG-6d and `standards/data/providers/tactical/` (F-ATAK-005) for the tactical provider log destination implementation.

| Control ID | Type | IL6 Requirement | Android / Backend Implementation | How to Verify |
|---|---|---|---|---|
| AU-9(2) | Enhancement | Store audit logs in a component not accessible by the application process. Tamper-evident, append-only store required. | Backend audit logs routed to a separate log destination — not a file the application process writes directly. Tactical provider log approach documented per ADR-023 / F-ATAK-005. **[OG-6d TBD]** Specific log destination pending F-ATAK-005. | Application process does not have write access to the audit log destination. Log tampering requires out-of-band administrative access. |
| AU-9(3) | Enhancement | Implement cryptographic protection for audit information. | Audit log destination implements integrity protection (hash chaining, WORM storage, or equivalent). **[OG-6d TBD]** Specific mechanism documented in F-ATAK-005. | Audit log integrity mechanism documented. Test: attempt to modify a log entry — mechanism detects or prevents modification. |
| AU-10 | New at High | Non-repudiation — bind identity of originator to information; verify on demand. | Backend: every audit record includes `keycloak_id` (from validated JWT). Keycloak issues signed tokens — identity binding is cryptographically verifiable. Android: API calls include JWT; `keycloak_id` logged server-side. | Audit log entry includes `keycloak_id` for every mutating operation. Token signature verifiable against Keycloak JWKS. |
| AU-14 | New at High | Session audit capability — capture and log content of user sessions; support review. | Backend logs all API requests per session (via `request_id` correlation). Android session events (login, logout, token refresh) logged at INFO level without sensitive data. | Session activity reconstructable from backend logs using `request_id` correlation. `keycloak_id` links session to user identity. |

---

## IL6 Delta — Cryptographic Requirements (FIPS 140-3)

> **FIPS 140-3 escalation (IA-7, SC-13 at High):** At IL6 for NSS, FIPS 140-2 is not sufficient — FIPS 140-3 validated modules are required. This applies to all security-relevant cryptographic operations.

| Control ID | Type | IL6 Requirement | Android / Backend Implementation | How to Verify |
|---|---|---|---|---|
| IA-7 (escalated) | Escalation | FIPS 140-3 validated cryptographic modules only. | Android: AOSP BoringSSL version running on the classified network device must be FIPS 140-3 validated. Verify the specific Android platform version used on classified devices has a FIPS 140-3 validated BoringSSL module. Confirm with device/MDM vendor. | NIST CMVP validation certificate for BoringSSL version on deployed devices. No custom TrustManager or `SSLSocketFactory` implementations that bypass the platform. |
| SC-13 (escalated) | Escalation | FIPS 140-3 modules for all cryptographic operations — no MD5, SHA-1, RC4, non-FIPS TLS ciphers. | Android: No MD5, SHA-1, or RC4 in any security-relevant usage. TLS cipher suite restricted to FIPS-approved algorithms. Backend: same constraint applies to all cryptographic operations. | Android: `grep -rn "MD5\|SHA1\|RC4\|DES" app/src/` — no security-relevant usages. Backend: TLS configuration lists only FIPS 140-3 approved cipher suites. |
| IA-5(6) | Enhancement | Protect authenticators commensurate with classified data access. | Android authentication token stored in hardware-backed Android KeyStore where available. Devices used for IL6 access must support hardware-backed KeyStore (Android 9+ with StrongBox or TEE). | Android: `KeyInfo.isInsideSecureHardware()` returns `true` for keys used in authentication on classified devices. MDM confirms enrolled devices meet hardware KeyStore requirement. |
| SC-12 | — | APK signing key stored with classified-grade protection. **[OG-3 TBD]** Signing CA/key format pending TAK team confirmation. | Signing keystore file protected with hardware-backed storage or HSM on the CI infrastructure. Key access restricted to pipeline identity. No signing key material committed to source. | `git log --all -- "*.jks" "*.keystore" "*.p12"` returns no results. CI pipeline signing step uses secure variable injection. |

---

## IL6 Delta — Classification Banner Requirement

> **SC-16 / ICD 710 requirement (new at High):** All API responses must include a classification banner header per the applicable classification guide and CAPCO marking requirements.

| Requirement | Implementation | How to Verify |
|---|---|---|
| All API responses include classification banner header | Backend middleware adds classification header (e.g., `X-Classification: SECRET//YOUR-MARKINGS`) to every response. Header value matches the classification of the data served — at minimum the system's baseline classification. CAPCO-compliant marking required. | `curl -I https://<BACKEND_ENDPOINT>/api/health` — confirm classification header present on every response. Header value reviewed by security officer for CAPCO compliance. |
| Android app surfaces classification banner | Android app displays classification banner on every screen that presents data from the backend API. Banner text matches the API response header. | UI review: every data-displaying screen shows classification banner. Banner persists — not dismissable. |

---

## IL6 Delta — Network Isolation (No Unclassified External Calls)

> **SC-7(8) / DoD CC SRG §5.4 requirement:** No unclassified external calls at runtime — no public npm registries, CDNs, package managers, or third-party endpoints reachable from the running application on the classified network.

| Requirement | Implementation | How to Verify |
|---|---|---|
| No unclassified external calls at runtime | Android app backend API is the only external endpoint the app calls. No analytics SDKs, no public CDN resources, no third-party telemetry. All Gradle dependencies resolved from mirrored/local repository on the classified network (no live Maven Central or Google Maven access at runtime). Backend makes no outbound calls to public internet services at runtime. | Android: network traffic capture during operation — only calls to `<BACKEND_BASE_URL>`. No DNS lookups to public domains. Backend: `netstat` / `ss -tnp` during operation — no established connections to public internet addresses. |
| Build-time vs. runtime isolation | Gradle dependency resolution occurs at CI build time on the classified network against a local mirror. The built APK artifact does not make any dependency resolution calls at runtime. | APK analyzed for embedded URLs — only `<BACKEND_BASE_URL>` and Keycloak endpoint present. No public package registry URLs. |

---

## IL6 Delta — Personnel Clearance Delegation

| Requirement | Implementation | How to Verify |
|---|---|---|
| Personnel clearance level not stored in application database | Application DB schema contains no clearance-level columns (`clearance_level`, `classification_access`, etc.). Keycloak and organizational IdP are the sole authoritative sources for personnel clearance. Application derives access rights from Keycloak-issued JWT role claims only (`admin`/`editor`/`user`). | DB schema review: no clearance-related columns. `grep -rn "clearance" backend/src/` — no storage operations. Keycloak token claims reviewed — role only, no clearance level. |

---

## IL6 Delta — Audit Log Tamper Evidence

> Addressed in AU-9(2) and AU-9(3) above. Summarized here for Sentinel gate cross-reference.

The audit log destination must be:
1. Not writable by the application process
2. Append-only or WORM-protected
3. Cryptographically integrity-protected (hash chaining or equivalent)
4. Retained for ≥ 365 days

**[OG-6d TBD]** Specific log destination and integrity mechanism documented in `standards/data/providers/tactical/` (F-ATAK-005).

---

## IL6 Delta — Incident Response (Spillage)

| Control ID | Type | IL6 Requirement | Android / Backend Implementation |
|---|---|---|---|
| IR-9 | New at High | Information spillage response procedures required. | Organizational incident response plan must include a spillage procedure for classified data. Application teams coordinate with the unit ISSO. Application does not implement spillage response automation — this is an operational requirement. |
| IR-9(2–4) (was IR-9(1–4); (1) withdrawn in Rev 5, incorporated into IR-9) | New at High | Spillage notification, training, post-spill operations, and exposure safeguards. | Organizational/operational. Application teams complete spillage response training per unit requirement. |

---

## Open Gaps Summary (IL6 Specific)

| ID | Gap | Status | Blocking? |
|---|---|---|---|
| OG-1 | Authentication method (PKCE vs. mTLS with derived CAC credentials) | Pending TAK team + identity platform team | Not blocking — outcome requirements fixed |
| OG-3 | APK signing CA/key format (org-managed vs. DoD PKI-issued) | Pending TAK team | Not blocking — signing required regardless |
| OG-4 | WatchTower on classified network (`ATAK_PLUGIN=true`) | Pending TAK Product Center | Not blocking — manual handoff documented as interim |
| OG-6b | Secrets management on tactical provider | Pending team decision | Not blocking — no hardcoded secrets is the enforced outcome |
| OG-6c | TLS CA for classified network | Pending unit IT | Not blocking — TLS enforcement required |
| OG-6d | Audit log destination and integrity mechanism | F-ATAK-005 documents | Not blocking — AU requirements are fixed |

When gaps are resolved, the responsible story author appends a resolution note to the gap entry in ADR-022 and updates this document. Sentinel gate runs treat documented open gaps as accepted risk items, not findings, until remediation.
