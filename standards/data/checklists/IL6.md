# Sentinel checklist block — active when `SECURITY_TIER=IL6`

Moved out of `engine/SENTINEL-CHECKLIST.md` on 2026-10-03 (T-SLIM-06) so a project where this block
is off does not load it on every gate. The gate reads this file when `project.config.yaml` turns it on.

#### IL6 Additional Gate Checks (active when SECURITY_TIER=IL6)

Each check references `standards/data/controls/IL6-delta.md` for the NIST 800-53 High control IDs that ground the requirement. CDS check (item 5) is only applicable if the deployment includes a CDS integration boundary — projects without CDS may mark this N/A with justification.

- FIPS 140-3 validated crypto libraries only — no MD5, SHA-1, RC4, or non-FIPS-validated TLS ciphers
- All API responses include classification banner header per applicable classification guide
- No unclassified external calls at runtime — no public npm registries, CDNs, or third-party endpoints
- Audit logs written to tamper-evident, append-only store not writable by the application process
- CDS integration points documented and not bypassed (see `standards/data/controls/CDS-guidance.md`)
- Personnel clearance level not stored in application DB — delegated to identity provider
- FIPS 140-3 module list verified: all cryptographic operations use NIST-validated modules only
