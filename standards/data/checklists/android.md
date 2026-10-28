# Sentinel checklist block — active when `APP_TRACK=android`

Moved out of `engine/SENTINEL-CHECKLIST.md` on 2026-10-03 (T-SLIM-06) so a project where this block
is off does not load it on every gate. The gate reads this file when `project.config.yaml` turns it on.

#### Android Track Gate Checks (active when APP_TRACK=android)

When `APP_TRACK=android`, Sentinel replaces the web-track container/Node.js/PostgreSQL STIG items with the following **MASVS-grounded** checks. `SECURITY_TIER` overlay (IL4/IL6) applies on top. Each check is grounded in **OWASP MASVS v2**, NIST SP 800-163 Rev 1, NIST SP 800-124 Rev 2, and `standards/data/providers/android/STIG-checklist.md` (created by F-ATAK-002). **The DISA Mobile Application STIG is out of scope for this repository — CUI-marked and published behind DoD PKI; see that checklist's scope note.**

- All network calls use TLS 1.2 minimum; TLS 1.3 preferred — no cleartext HTTP permitted
- No sensitive data written to Android external storage — internal app storage only
- No sensitive data logged via `Log.d` / `Log.v` / `Log.i` — no PII, tokens, or credentials in logcat
- Authentication token stored in Android KeyStore — not in SharedPreferences or local files
- Backend API calls include `Authorization: Bearer <token>` header — no unauthenticated endpoints reachable from app
- Certificate pinning evaluated — if not implemented, documented justification required (government CA chain may make pinning redundant; Sentinel accepts justified absence)
- No hardcoded credentials, API keys, or base URLs in source — all injected via build config or secure storage
- Exported Android components (`Activity`, `Service`, `BroadcastReceiver`) minimized — each exported component requires justification in Sentinel report
- `minSdkVersion` documented and justified — version must support TLS enforcement and KeyStore availability
- **APP_TYPE=atak only:** ATAK plugin manifest declares minimum ATAK version — must match or exceed `5.6`
