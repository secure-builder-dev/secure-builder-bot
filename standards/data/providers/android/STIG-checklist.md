## About This Document

**Purpose:** Android Mobile Application STIG verification checklist covering the Kotlin/MVVM app layer for the Android track.

**Workflow role:** Frank reads and executes before marking Android-lane stories complete; Sentinel confirms checklist completion at gate; Amelia references for TDD test requirements on security-relevant behaviors.

**How to fill in:** Work through all items before gate submission. Mark any item N/A with a written justification (e.g., certificate pinning may be N/A with documented rationale for government CA chain deployments).

---

# Android Mobile Application STIG Checklist

**Lane:** Frank (pipeline and gate STIG verification reference)
**Scope:** `APP_TRACK=android` — Kotlin/MVVM native Android app, ATAK plugin or standalone. Covers Android client layer. Backend API layer checks remain in the web-track STIG checklists (`providers/aws/STIG-checklist.md` Sections 3–4) — reference those, do not duplicate.
**References:** **OWASP MASVS v2** (the verifiable mobile baseline — see the scope note below); DISA Application Security and Development STIG V5R3; NIST SP 800-163 Rev 1; NIST SP 800-124 Rev 2
**Last updated:** 2026-09-19

> **Scope note — why the DISA Mobile Application STIG is not the baseline here.** It is CUI-marked
> and published behind DoD PKI at `cyber.mil`, and these are not CUI workstations, so it cannot enter
> this repository at all. That is a deliberate boundary, the same one the Agent Security Rules draw
> around POAMs and platform scan artifacts — not a gap waiting to be filled. ComplianceAsCode, which
> redistributes the OS STIGs the other tracks cite, carries no mobile content either, so nothing
> could ever verify a mobile STIG ID written here.
>
> **OWASP MASVS v2 is the baseline instead, because it can actually be checked.** MASVS ships a
> machine-readable catalogue (`OWASP_MASVS.yaml`) in the project's own repository, so every
> `MASVS-*` ID in the tables below is verified on every push by `make verify-citations` against
> `standards/data/controls/masvs-index.json`. MASVS is an industry standard, **not a DoD
> authority** — it grounds these items, it does not accredit them. Where an assessment needs the
> Mobile Application STIG, that is a CAC-holder's task on a CUI workstation, outside this engine.

> **STIG ID note:** `APSC-DV-*` IDs reference the DISA Application Security and Development STIG,
> current as of this document date. Items labeled `[Framework-derived]` have no direct DISA STIG ID
> and derive from NIST SP 800-163 Rev 1, NIST SP 800-124 Rev 2, DoD CC SRG v1r4, or ADR-022
> architectural decisions. Verify current STIG IDs against the DISA STIG Viewer
> (`public.cyber.mil/stigs/`) before use in formal audit assessments.

Quality-gate verification: every item names a MASVS control **and** either a published STIG ID or its
derivation source (`[Framework-derived]` with the source reference). No percentage threshold on STIG
IDs: no platform STIG is published for this track's surface, so those items derive from the SRGs and
NIST. The MASVS column is the mechanically verified one — `make verify-citations` resolves every
`MASVS-*` ID against the pinned catalogue and fails on an ID that does not exist there or on a
superseded `MSTG-*` (MASVS v1) ID. A `—` in that column means no MASVS control fits; it is left
blank rather than guessed.

---

## Reference Sources

| Source | What it covers | Where to find it |
|---|---|---|
| **OWASP MASVS v2** | **The mobile baseline for this checklist — 24 controls in 8 groups. Verified mechanically.** | [github.com/OWASP/masvs](https://github.com/OWASP/masvs) — `OWASP_MASVS.yaml`; vendored at `standards/data/controls/masvs-index.json` |
| OWASP MASTG | Test procedures behind each MASVS control — how to actually verify one | [mas.owasp.org/MASTG](https://mas.owasp.org/MASTG/) |
| DISA STIG Viewer (free JAR) | Load and search STIG packages; look up Application Security and Development STIG IDs | `public.cyber.mil/stigs/srg-stig-tools/` |
| DISA Mobile Application STIG | **Out of scope here — CUI-marked, behind DoD PKI. See the scope note above.** Needed only for a formal assessment, on a CUI workstation. | `public.cyber.mil/stigs/downloads/` |
| DISA Application Security and Development STIG V5R3 | Source for APSC-DV-XXXXXX items — application-layer security requirements | `public.cyber.mil/stigs/downloads/` → search "Application Security and Development" |
| NIST SP 800-163 Rev 1 | Mobile app security vetting methodology — source for `[Framework-derived]` vetting items | `csrc.nist.gov/pubs/sp/800/163/r1/final` |
| NIST SP 800-124 Rev 2 | Mobile device management and security baseline — source for device-level `[Framework-derived]` items | `csrc.nist.gov/pubs/sp/800/124/r2/final` |
| Android developer security documentation | Android KeyStore, Network Security Config, permissions model, exported components | `developer.android.com/security` |
| CIS Android Benchmark | CIS-derived hardening items for Android | `cisecurity.org/benchmark/android` (free after registration) |

---

## Section 1 — Transport Security

Sources: OWASP MASVS v2 (`MASVS-NETWORK`); DISA Application Security and Development STIG (APSC-DV items)

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 1.1 | APSC-DV-002000 | MASVS-NETWORK-1 | Application must implement DoD-approved encryption for all data in transit | All network calls use HTTPS (TLS 1.2 minimum; TLS 1.3 preferred). No cleartext HTTP permitted for any production endpoint. |
| 1.2 | [Framework-derived — NIST 800-124 §4.1] | MASVS-NETWORK-1 | Android Network Security Configuration must prohibit cleartext traffic | `network_security_config.xml` contains `<base-config cleartextTrafficPermitted="false">` or equivalent per-domain config. `AndroidManifest.xml` references this config via `android:networkSecurityConfig`. |
| 1.3 | [Framework-derived — NIST 800-163 §4.3] | MASVS-NETWORK-1 | TLS version minimum enforced at the client | TLS 1.0 and 1.1 not accepted. AOSP platform TLS version negotiation produces TLS 1.2+ on all connections. Verify via `openssl s_client` or network capture that server and client agree on TLS 1.2 minimum. |
| 1.4 | APSC-DV-002000 | MASVS-NETWORK-1 | No custom TrustManager that bypasses certificate chain validation | No `X509TrustManager` implementation that accepts all certificates (`checkServerTrusted` is a no-op or always-pass). Code review: `grep -rn "checkServerTrusted\|TrustAllCerts\|ALLOW_ALL_HOSTNAME_VERIFIER" app/src/` returns no results in production code. |
| 1.5 | [Framework-derived — ADR-022] | MASVS-NETWORK-2 | Certificate pinning evaluated; absence justified if not implemented | If certificate pinning is not implemented, a documented justification is present in the Sentinel gate report (e.g., "government CA chain on classified network makes pinning operationally unmanageable — CA chain validation is the primary control"). Sentinel accepts justified absence. |
| 1.6 | APSC-DV-001160 | MASVS-NETWORK-2 | Application must use a DoD-approved CA for TLS | Trust anchor for backend TLS connections is the unit/organizational CA or DoD PKI CA. No public CAs not on the approved list trusted for backend connections. `network_security_config.xml` restricts trust anchors to organizational CA bundle for production domains. |

---

## Section 2 — Data Storage

Sources: OWASP MASVS v2 (`MASVS-STORAGE`, `MASVS-CRYPTO`); NIST SP 800-163 Rev 1

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 2.1 | [Framework-derived — NIST 800-163 §4.2] | MASVS-STORAGE-1 | No sensitive data written to Android external storage | No `Environment.getExternalStorageDirectory()`, `MediaStore`, or `ACTION_OPEN_DOCUMENT_TREE` writes that contain CUI or credential data. Code review: `grep -rn "getExternalStorage\|WRITE_EXTERNAL_STORAGE" app/src/` — any matches are for non-sensitive media only and justified. |
| 2.2 | [Framework-derived — NIST 800-124 §5.1] | MASVS-STORAGE-1 | Sensitive data stored in Android internal app storage only | App-generated files containing CUI stored in `context.getFilesDir()` or equivalent internal storage path. Internal storage is protected by Android's app sandbox (not accessible to other apps without root). |
| 2.3 | APSC-DV-002240 | MASVS-STORAGE-1 | No sensitive data in Android SharedPreferences in plaintext | Authentication tokens, API keys, and credentials not stored in `SharedPreferences`. `grep -rn "SharedPreferences" app/src/` — any usage is for non-sensitive UI preferences only. |
| 2.4 | [Framework-derived — NIST 800-163 §4.2] | MASVS-CRYPTO-2, MASVS-STORAGE-1 | Authentication tokens stored in Android KeyStore | `KeyStore.getInstance("AndroidKeyStore")` used for all key and token storage operations requiring security. No token or key material stored in `SharedPreferences`, local files, or Room/SQLite without encryption. Hardware-backed KeyStore used where available (Android 9+ with StrongBox or TEE). |
| 2.5 | [Framework-derived — NIST 800-163 §4.4] | MASVS-STORAGE-2 | No sensitive data in app backups | `android:allowBackup="false"` in `AndroidManifest.xml`, or `android:fullBackupContent` explicitly excludes directories containing sensitive data. Backup is disabled or selectively configured to exclude CUI. |
| 2.6 | [Framework-derived — NIST 800-124 §5.2] | MASVS-STORAGE-2 | Sensitive data cleared from memory when no longer needed | Long-lived sensitive data (decrypted keys, tokens) is zeroed or reassigned after use. `char[]` or `ByteArray` used instead of `String` for passwords where feasible (strings are immutable and GC-dependent). |

---

## Section 3 — Authentication and Credential Management

Sources: OWASP MASVS v2 (`MASVS-AUTH`); NIST SP 800-157 (OG-1 reference)

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 3.1 | APSC-DV-000460 | MASVS-AUTH-1 | Application must enforce approved authorizations for all access | Every API call includes `Authorization: Bearer <token>`. No endpoint reachable from the app without a valid token. Backend auth middleware verified (web-track STIG Sections 3–4 apply to backend). |
| 3.2 | [Framework-derived — ADR-022 Sentinel check] | MASVS-CRYPTO-2 | Authentication token stored in Android KeyStore — not SharedPreferences or local files | `KeyStore.getInstance("AndroidKeyStore")` used for token key storage. Code review and dynamic analysis confirm no token in `SharedPreferences`, local files, or logcat. |
| 3.3 | [Framework-derived — OG-1 / NIST 800-157] | MASVS-AUTH-1 | Authentication method choice documented | Auth acquisition method (PKCE vs. mTLS with derived CAC credentials) documented in project-level ADR amendment once OG-1 is resolved. Sentinel accepts documented open gap until resolved; outcome requirement (token in KeyStore, no unauthenticated calls) is enforced regardless. |
| 3.4 | [Framework-derived — NIST 800-163 §4.1] | MASVS-STORAGE-1 | No hardcoded credentials, API keys, or base URLs in source | `grep -rn "http[s]\?://\|password\|apiKey\|secret" app/src/` — no production credentials or hardcoded base URLs. Values injected via `BuildConfig` fields from CI variables. `BuildConfig.java` is generated at build time and not committed to source. |
| 3.5 | APSC-DV-002560 | MASVS-AUTH-1 | CSRF protection for state-mutating operations | PKCE OAuth2 flow (or mTLS — OG-1) provides CSRF protection. All state-mutating API calls use `Authorization: Bearer <token>` — no cookie-based session. |
| 3.6 | [Framework-derived — NIST 800-124 §4.3] | MASVS-AUTH-1 | Re-authentication required after session timeout | App handles session expiry gracefully — user is redirected to auth flow when token expires. Expired token is cleared from KeyStore before new token is stored. |
| 3.7 | [Framework-derived — NIST 800-124 §5.1] | MASVS-AUTH-1 | App does not implement its own password management | No local password storage or password validation in the app. Authentication delegated entirely to Keycloak. |

---

## Section 4 — Input Validation

Sources: OWASP MASVS v2 (`MASVS-CODE-4`); DISA Application Security and Development STIG V5R3

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 4.1 | APSC-DV-001900 | MASVS-CODE-4 | Application must validate all inputs before processing | All user inputs validated for data type, length, and format before API submission. Invalid inputs produce a user-facing validation error, not a raw backend error. |
| 4.2 | APSC-DV-002540 | — (backend) | Application must prevent SQL injection (backend) | Backend uses parameterized queries for all SQL. No string interpolation of user input. Referenced from `providers/aws/STIG-checklist.md` Section 3 — not duplicated here. |
| 4.3 | [Framework-derived — NIST 800-163 §4.5] | MASVS-PLATFORM-1, MASVS-CODE-4 | Deep link / intent input validated | If the app handles Android deep links or explicit intents from other apps, all intent extras validated before use. Intent data not trusted as authoritative without validation. `grep -rn "getIntent().getData\|getStringExtra" app/src/` — all callers validate before use. |
| 4.4 | APSC-DV-001900 | MASVS-CODE-4 | Maximum input length enforced on all text fields | Text input fields enforce `android:maxLength` attribute or equivalent runtime validation. Prevents buffer overflows and oversized payload submission. |

---

## Section 5 — Logging

Sources: OWASP MASVS v2 (`MASVS-STORAGE-2`, `MASVS-RESILIENCE`); DISA Application Security and Development STIG V5R3

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 5.1 | APSC-DV-002200 | MASVS-STORAGE-2 | No sensitive data in Android logcat | `Log.d`, `Log.v`, `Log.i`, `Log.w`, `Log.e` calls do not include PII, authentication tokens, credentials, or classified data. `grep -rn "Log\.\(d\|v\|i\|w\|e\)" app/src/` — reviewed; no sensitive data in log messages. |
| 5.2 | [Framework-derived — NIST 800-163 §4.6] | MASVS-STORAGE-2 | Debug logging disabled in release builds | `BuildConfig.DEBUG` is `false` in release builds. Verbose logging guarded with `if (BuildConfig.DEBUG)` checks. Release APK does not produce `Log.d` or `Log.v` output for normal operations. |
| 5.3 | APSC-DV-002440 | MASVS-RESILIENCE-4 | No debug features in production build | `android:debuggable="false"` in release build (set by Gradle release build type). `android:testOnly="false"` in release manifest. `apksigner verify --verbose <app.apk>` confirms `debuggable` is not set. |
| 5.4 | APSC-DV-001380 | MASVS-STORAGE-2 | Error messages do not expose sensitive internal information | Error messages displayed to the user are generic — no stack traces, internal exception details, server addresses, or DB messages. `Timber` or equivalent logging library used with release tree that strips stack traces from user-facing messages. |
| 5.5 | [Framework-derived — ADR-022 Sentinel check] | MASVS-STORAGE-2 | No credentials or tokens in logcat under any condition | Crash reporting and logging frameworks (if used) configured to redact authentication headers and token values. `grep -rn "access_token\|Bearer\|Authorization" app/src/` — no log calls that include these values. |

---

## Section 6 — Exported Android Components

Sources: OWASP MASVS v2 (`MASVS-PLATFORM-1`); Android developer documentation

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 6.1 | [Framework-derived — ADR-022 Sentinel check] | MASVS-PLATFORM-1 | Exported Android components minimized | Every `Activity`, `Service`, `BroadcastReceiver`, or `ContentProvider` with `android:exported="true"` is justified in the Sentinel gate report. Components that do not need to receive intents from other apps set `android:exported="false"`. |
| 6.2 | [Framework-derived — NIST 800-163 §4.5] | MASVS-PLATFORM-1 | Exported components protected with permissions where required | Exported components that handle sensitive operations declare `android:permission` requiring a signature-level or custom permission. No exported component accepts unauthenticated data from untrusted sources without validation. |
| 6.3 | [Framework-derived — Android developer security] | MASVS-PLATFORM-1 | Intent filters do not expose sensitive functionality | Activity intent filters for deep links and custom schemes validated (Section 4.3). No exported Activity with an intent filter processes authentication data without validation. |
| 6.4 | [Framework-derived — NIST 800-163 §4.5] | MASVS-PLATFORM-1 | Implicit broadcasts handled defensively | `BroadcastReceiver` components that handle implicit broadcasts validate the sending package and data before acting. No security decision made based solely on an unprotected broadcast. |

---

## Section 7 — Minimum SDK Version

Sources: OWASP MASVS v2 (`MASVS-CODE-1`); NIST SP 800-124 Rev 2; Android developer documentation

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 7.1 | [Framework-derived — NIST 800-124 §4.2] | MASVS-CODE-1 | `minSdkVersion` documented and justified | `minSdkVersion` value in `build.gradle` is documented in the Sentinel gate report with justification. Justification must confirm the minimum version supports: Android KeyStore availability (API 18+), hardware-backed KeyStore where required (API 28+ for StrongBox), and TLS enforcement. |
| 7.2 | [Framework-derived — ADR-022 Sentinel check] | MASVS-CODE-1 | `minSdkVersion` supports TLS enforcement | Chosen `minSdkVersion` supports Android Network Security Configuration (`network_security_config.xml` requires API 24+) or the equivalent TLS enforcement mechanism for the chosen min SDK. If `minSdkVersion < 24`, `OkHttpClient` or equivalent is configured to enforce TLS 1.2 programmatically. |
| 7.3 | [Framework-derived — NIST 800-124 §5.1] | MASVS-CRYPTO-2 | `minSdkVersion` supports hardware-backed KeyStore (IL6 requirement) | For `SECURITY_TIER=IL6`, enrolled devices must support hardware-backed Android KeyStore. Minimum device requirement documented. MDM enrollment policy enforces minimum device capability. |
| 7.4 | [Framework-derived — NIST 800-124 §4.2] | MASVS-CODE-1 | Target SDK version kept current | `targetSdkVersion` is within 2 major versions of the current Android release. Outdated target SDK disables modern security enforcements (scoped storage, permission restrictions). `build.gradle` `targetSdkVersion` reviewed. |

---

## Section 8 — APK Integrity and Distribution

Sources: OWASP MASVS v2 (`MASVS-RESILIENCE`, `MASVS-CRYPTO-2`); NIST SP 800-163 Rev 1

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 8.1 | APSC-DV-002440 | MASVS-RESILIENCE-4 | Release APK not debuggable | `apksigner verify --verbose <app.apk>` shows `debuggable` is NOT set. `android:debuggable` not present or `false` in release manifest. |
| 8.2 | [Framework-derived — ADR-022 Sentinel check / OG-3] | MASVS-RESILIENCE-2 | APK signed with documented signing key | `apksigner verify --print-certs <app.apk>` shows valid signature. Signing key provenance documented (org-managed keystore or DoD PKI-issued — **[OG-3 TBD]**). |
| 8.3 | [Framework-derived — NIST 800-163 §4.1] | MASVS-RESILIENCE-2 | APK signature uses v2 or v3 scheme | `apksigner verify --verbose <app.apk>` confirms `Verified using v2 scheme: true` or `v3 scheme: true`. v1-only signing is insufficient — v2/v3 block post-signing modification of APK zip entries. |
| 8.4 | [Framework-derived — ADR-022 Sentinel check] | MASVS-CRYPTO-2 | Signing key not committed to source control | `git log --all -- "*.jks" "*.keystore" "*.p12" "*.pfx"` returns no results. `.gitignore` excludes keystore file patterns. |
| 8.5 | [Framework-derived — NIST 800-163 §4.1] | — | APK distribution channel verified | Distribution via WatchTower (if `ATAK_PLUGIN=true`) or MDM (if `ATAK_PLUGIN=false`). No distribution via public app stores or unauthenticated file shares. |
| 8.6 | [Framework-derived — NIST 800-124 §5.3] | MASVS-RESILIENCE-3 | ProGuard / R8 obfuscation enabled for release builds | Release build configuration enables R8/ProGuard (`minifyEnabled true`). Obfuscation does not replace security controls but reduces attack surface from reverse engineering. `build.gradle` release build type confirms `minifyEnabled true`. |

---

## Section 9 — ATAK Plugin Conditionals (`ATAK_PLUGIN=true` only)

The items in this section apply only when `ATAK_PLUGIN=true`. Skip this section for standalone Android apps (`ATAK_PLUGIN=false`).

Sources: OWASP MASVS v2 (`MASVS-PLATFORM-1`, `MASVS-CODE-3`, `MASVS-RESILIENCE-2`); ATAK SDK documentation; ADR-022

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 9.1 | [Framework-derived — ADR-022 Sentinel check] | — | ATAK plugin manifest declares minimum ATAK version ≥ 5.6 | `plugin.xml` or equivalent ATAK plugin manifest declares `minAtak` (or equivalent attribute) ≥ `5.6`. Sentinel verifies this attribute is present and meets the minimum. |
| 9.2 | [Framework-derived — ADR-022] | MASVS-CODE-3 | TAK SDK sourced from official TAK Product Center channels | `build.gradle` references the TAK Product Center Maven repository (documented internal URL). No public Maven mirror for TAK SDK. Repository URL documented in `DEPENDENCY_POLICY.md`. |
| 9.3 | [Framework-derived — ADR-022] | MASVS-PLATFORM-1 | Plugin inter-process communication secured | Communication between the ATAK plugin and ATAK host process via TAK SDK APIs only. No custom IPC that bypasses ATAK sandboxing or exposes sensitive data to other plugins. Plugin intent handling validates input (Section 6 applies). |
| 9.4 | [Framework-derived — ADR-022 / OG-3] | MASVS-RESILIENCE-2 | APK signed for WatchTower validation | Signed APK compatible with WatchTower distribution validation requirements. Signing authority documented — **[OG-3 TBD]** pending TAK team confirmation of WatchTower signing requirements. |
| 9.5 | [Framework-derived — ADR-022 / OG-2] | — | WatchTower upload process documented | WatchTower distribution uses documented manual handoff process (server admin downloads signed APK from CI artifact store and uploads to WatchTower). Automated WatchTower API upload pending OG-2 resolution. |

---

## Section 10 — IL6-Specific Android Checks (`SECURITY_TIER=IL6`)

The items in this section supplement all preceding sections when `SECURITY_TIER=IL6`. IL4 items remain fully in force.

Sources: OWASP MASVS v2 (`MASVS-CRYPTO`, `MASVS-NETWORK-1`, `MASVS-PLATFORM-3`); CNSSI 1253; ICD 503; `standards/data/controls/IL6-delta.md`; `IL6-implementation.md`

| Item | STIG ID | MASVS | Check Description | Pass Criterion |
|---|---|---|---|---|
| 10.1 | [Framework-derived — SC-13 High] | MASVS-CRYPTO-1 | FIPS 140-3 validated cryptography only — no MD5, SHA-1, RC4 | `grep -rn "MD5\|SHA1\|SHA-1\|RC4\|DES\|3DES" app/src/` — no security-relevant usages. AOSP BoringSSL module on deployed device has NIST CMVP validation certificate at FIPS 140-3 level. |
| 10.2 | [Framework-derived — SC-16 / ICD 710] | MASVS-PLATFORM-3 | Classification banner displayed on all screens showing classified data | Every screen that renders data returned from the backend API displays a classification banner consistent with the API response `X-Classification` header. Banner not dismissable. |
| 10.3 | [Framework-derived — SC-7(8)] | MASVS-NETWORK-1 | No unclassified external calls at runtime | Network traffic capture during operation — only calls to `<BACKEND_BASE_URL>` on the classified network. No DNS lookups or connections to public internet addresses. |
| 10.4 | [Framework-derived — IA-5(6) High] | MASVS-CRYPTO-2 | Hardware-backed Android KeyStore required | `KeyInfo.isInsideSecureHardware()` returns `true` for authentication keys. MDM enrollment policy enforces hardware-backed KeyStore (Android 9+ with StrongBox or TEE). Documented device minimum for IL6 deployments. |
| 10.5 | [Framework-derived — AU-9(2) High] | MASVS-STORAGE-1 | No sensitive data cached on device beyond session | Authentication tokens and classified data not persisted beyond the active session. App clears KeyStore entries on logout. No classified content written to device storage that persists after session end. |

---

## Applying This Checklist in the Pipeline

Frank-lane pipeline verification steps reference this checklist by section and item number in pipeline step comments. Example:

```yaml
# STIG ref: Section 8.1, 8.2, 8.3 — APK signing verification
- name: verify-apk-signature
  run: |
    apksigner verify --verbose --print-certs build/outputs/apk/release/app-release.apk
```

**Backend STIG items:** Node.js (Section 3) and PostgreSQL (Section 4) items from `providers/aws/STIG-checklist.md` apply to the backend API layer of Android track projects. Reference those items — do not duplicate them here.
