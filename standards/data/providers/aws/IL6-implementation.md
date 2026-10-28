## About This Document

**Purpose:** AWS C2S/SC2S IL6 delta above the IL4 baseline — maps HIGH-baseline-only control requirements to classified AWS region implementation. Read in conjunction with `IL4-implementation.md` (all IL4 controls remain in force).

**Workflow role:** Frank reads before implementing the AWS classified track; Sentinel references when running IL6 gate checks; read alongside `IL4-implementation.md`.

**How to fill in:** Replace all `<PLACEHOLDER>` values with your C2S/SC2S deployment values. This document supplements `IL4-implementation.md` — use both together. Never commit real ARNs or classified endpoints.

---

# AWS C2S/SC2S IL6 Implementation Guide

> **IMPORTANT DISCLAIMER — READ BEFORE USING THIS DOCUMENT**
>
> This document describes the AWS classified cloud deployment boundary for applications targeting IL6 (data up to SECRET). It covers the control delta above IL4 as implemented on AWS Commercial Cloud Services (C2S) and Secret Commercial Cloud Services (SC2S).
>
> **This is not a complete C2S/SC2S accreditation guide.** It does not replace the Authority to Operate (ATO) process, the Risk Management Framework (RMF) for National Security Systems, or NSA/DCSA/DoD Component AO oversight. Obtaining C2S or SC2S access requires a separate NSS-specific onboarding process not covered by this document. Treating this document as a complete classified deployment guide is a misuse and could result in deploying data on an inappropriately accredited platform.
>
> See the section "C2S/SC2S Access Requirements" below before proceeding.

**Deployment target:** AWS C2S (`us-iso-east-1`) or SC2S (`us-isob-east-1`)
**Impact level:** IL6 — data up to SECRET (Classified National Security Information)
**Control baseline:** `standards/data/controls/IL4-baseline.md` (full IL4 controls remain in force) + `standards/data/controls/IL6-delta.md` (delta above IL4)
**Last updated:** 2026-05-04

IL4 controls documented in `providers/aws/IL4-implementation.md` remain in force at IL6. This document covers only the IL6 delta requirements and the classified-region-specific implementation changes.

---

## Reference Sources

Use these to cross-reference IL6 control requirements, verify C2S/SC2S access procedures, or check FIPS 140-3 module validation.

| Source | What it covers | Where to find it |
|---|---|---|
| DoD Cloud Computing SRG v1r4 | IL6 definition; C2S/SC2S authorization; NSS network requirements; Appendix A authorized offerings | `public.cyber.mil` → search "Cloud Computing SRG" |
| NIST SP 800-53 Rev 5 High Baseline | High-impact control additions above Moderate — used in `IL6-delta.md` | `csrc.nist.gov/pubs/sp/800/53/r5/upd1/final` |
| `standards/data/controls/IL6-delta.md` | Cloud-agnostic IL6 delta above IL4 — the source this doc implements for AWS | Local to this repo |
| `providers/aws/IL4-implementation.md` | Full IL4 control mapping — all IL4 controls remain in force at IL6 | Local to this repo |
| NIST CMVP — FIPS 140-3 validated modules | Verify which crypto libraries are FIPS 140-3 validated (required at IL6, not just 140-2) | `csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search` |
| AWS C2S / SC2S information | C2S (`us-iso-east-1`) and SC2S (`us-isob-east-1`) region access requirements and service availability | Contact your DoD Component CIO or AWS classified team; not publicly documented |
| NCDSMO BAPL | Baseline Approved Products List for cross-domain solutions (CDS) — required for IL6 CDS integration boundaries | `ncdsmo.nsa.gov` (NSA NCDSMO; requires cleared access) |
| CNSS Policy 11 | NSS information classification and handling — governs what data requires IL6 | `cnss.gov/CNSS/issuances/Policies.cfm` |
| AWS GovCloud FIPS endpoints reference | FIPS endpoint URLs for GovCloud services; applies equally to C2S where service is available | `docs.aws.amazon.com/general/latest/gr/rande.html#govcloud` |
| DISA STIG Viewer + STIG packages | Verify any STIG IDs referenced when extending the STIG checklist for IL6 | `public.cyber.mil/stigs/downloads/` |

---

## C2S/SC2S Access Requirements

Access to the AWS classified regions (C2S: `us-iso-east-1`; SC2S: `us-isob-east-1`) is not available through standard AWS commercial enrollment. The following prerequisites must be completed independently of any application deployment:

1. **NSS ATO**: The application must have or be pursuing an ATO under the Risk Management Framework (RMF) for National Security Systems. The AO must be a designated NSS AO (DCSA, NSA, or applicable DoD Component).
2. **C2S/SC2S enrollment**: The deploying organization must complete the IC/DoD C2S or SC2S enrollment process through the appropriate government contracting and vetting channels. This is a government-controlled procurement process — there is no self-service enrollment.
3. **Cleared personnel**: All personnel with access to the C2S/SC2S environment must hold a security clearance at or above the classification level of the data being processed (SECRET for SC2S).
4. **Classified network connectivity**: C2S/SC2S is accessible only from NSS-classified networks. No access is possible from unclassified networks. Deployers require appropriate SIPR/JWICS connectivity.

**Refer your AO and contracting officer** for the current C2S/SC2S enrollment procedures. This framework does not cover, expedite, or substitute for that process.

---

## IL6 Delta — Control Implementation

The following sections cover only controls that are new, escalated, or have materially different implementation requirements at IL6 relative to the IL4 baseline. All IL4 controls from `IL4-implementation.md` remain in force.

---

### FIPS 140-3 Cryptographic Requirements

IL6 escalates the cryptographic module requirement from FIPS 140-2 (IL4) to FIPS 140-3 only.

| Requirement | C2S/SC2S Implementation | How to Verify |
|---|---|---|
| IA-7 / SC-13: FIPS 140-3 validated modules only | AWS C2S/SC2S regions use FIPS 140-3 validated endpoints. Node.js must use the OpenSSL FIPS 3.0 provider (`OPENSSL_CONF` pointing to a FIPS 3.0 module config). No MD5, SHA-1, RC4, or DES in any cryptographic operation. | `node -e "const c = require('crypto'); console.log(c.getFips())"` — must return `1`. `openssl list -providers` confirms `fips` provider active. `openssl version -a` confirms OpenSSL 3.x with FIPS module. |
| TLS cipher suite restriction | ALB on C2S/SC2S enforces FIPS 140-3 cipher suite policy. TLS 1.3 preferred; TLS 1.2 allowed; TLS 1.0/1.1 prohibited. No RC4, DES, 3DES, EXPORT, NULL ciphers. | `openssl s_client -connect <APP_ENDPOINT>:443 -tls1` — expect connection failure. `aws elbv2 describe-listeners` confirms FIPS cipher policy. |
| KMS keys | C2S/SC2S KMS uses FIPS 140-3 validated HSMs for all key operations. All KMS key usage (S3 SSE-KMS, RDS, EBS) automatically satisfies this requirement. | No additional configuration needed — C2S/SC2S KMS is inherently FIPS 140-3. Confirm application does not use non-KMS cryptographic operations for data protection. |
| FIPS module list verification | Deployment verification step confirms FIPS 140-3 module list. Confirmed modules: OpenSSL 3.x FIPS provider, AWS KMS (region-validated), ACM (region-validated). Document any additional crypto operations and their module validation status. | Pipeline step runs `openssl list -providers | grep fips` and exits non-zero if FIPS provider absent. |

---

### Classification Banner Header

ICD 710 and CAPCO marking requirements mandate that API responses carry a classification banner.

| Requirement | C2S/SC2S Implementation | How to Verify |
|---|---|---|
| SC-16 / SC-8(2): Classification banner in all API responses | Express middleware adds `X-Classification` response header to all API responses. Header value per applicable classification guide: `UNCLASSIFIED` for test/dev, `SECRET` for SECRET data, etc. The header value is a deployment-time configuration injected via ExternalSecret CRD from Secrets Manager key `<APP_NAME>/il6/classification-banner`. | `curl -I https://<APP_ENDPOINT>/api/health` — confirm `X-Classification` header present on all responses including errors. Verify middleware is registered before routes in `app.ts`. |
| Banner on error responses | Global error handler injects the classification banner header before returning any error response. | Trigger a 500; confirm `X-Classification` present in response headers. |
| Banner not hardcoded | Classification label injected via environment variable `CLASSIFICATION_BANNER` — never a string literal in source code. | `grep -r "SECRET\|UNCLASSIFIED" backend/src/` — confirm no hardcoded classification strings; only env var references. |

---

### Network Isolation — No Unclassified External Calls at Runtime

IL6 requires that no unclassified external network calls occur at runtime. The classified network environment enforces this at the boundary, but the application must also be architected to respect it.

| Requirement | C2S/SC2S Implementation | How to Verify |
|---|---|---|
| SA-9(2) / SC-7(8): No public registry, CDN, or third-party endpoint calls at runtime | All npm dependencies bundled in the container image at build time — no runtime `require` of network-fetched modules. Keycloak JWKS keys cached locally with periodic refresh from classified-network Keycloak instance only. No public OCSP or CRL endpoints — FIPS PKI uses C2S/SC2S internal CA. ECR is C2S/SC2S region-local — no public ECR endpoint used. | Network policy (Kubernetes NetworkPolicy or CNI) permits only explicitly allowlisted internal destinations. `kubectl describe networkpolicy` — confirm default-deny egress with explicit allow list. |
| Air-gapped npm registry | Build environment uses an internal, air-gapped npm registry mirror (e.g., Nexus or Artifactory deployed on classified network). No `registry.npmjs.org` calls at build time. | Build log — confirm no outbound connections to `registry.npmjs.org`. `npm config get registry` in build container confirms internal registry URL. |
| Keycloak JWKS local cache | JWKS keys fetched from classified-network Keycloak at startup and refreshed on 24-hour interval. Cache is in-memory only — no disk persistence. | Confirm `JWKS_URI` environment variable points to classified-network Keycloak hostname (not a public domain). Verify application starts successfully without external network access in a network-isolated test. |
| C2S/SC2S service endpoints only | AWS SDK configured with `useFipsEndpoint: true` and explicit endpoint overrides for C2S/SC2S service URLs (where endpoint URL differs from commercial GovCloud). Secrets Manager, S3, KMS endpoint URLs are C2S/SC2S region-specific. | `aws sts get-caller-identity` from within the pod — confirm response comes from `us-iso-east-1` or `us-isob-east-1` STS endpoint. |

---

### Audit Logs — Tamper-Evident Append-Only Store

AU-9(2) at IL6 requires audit logs in a system component not writable by the application process.

| Requirement | C2S/SC2S Implementation | How to Verify |
|---|---|---|
| AU-9(2): Application process cannot write to audit log store | Winston logs to stdout only. EKS Fluentd/Fluent Bit DaemonSet ships logs to CloudWatch Logs. Application IRSA role explicitly denies `logs:PutLogEvents` — only the DaemonSet service account has that permission. | `aws iam get-role-policy --role-name <APP_IRSA_ROLE>` — confirm explicit deny on `logs:PutLogEvents`. Confirm DaemonSet service account has a separate IRSA role with only `logs:PutLogEvents` scoped to the audit log group. |
| Append-only log group | CloudWatch Log Group has resource-based policy: `Deny` for `logs:DeleteLogGroup`, `logs:DeleteLogStream`, `logs:DeleteRetentionPolicy` for all principals except `<SECURITY_OPS_ROLE_ARN>`. | `aws logs describe-resource-policies` — confirm denial policy exists. Attempt `aws logs delete-log-stream` with application role credentials — expect `AccessDenied`. |
| Cryptographic protection of audit records | CloudWatch log data encryption with C2S/SC2S KMS key `<AUDIT_KMS_KEY_ARN>`. Log export to S3 encrypted with separate KMS key. | `aws logs describe-log-groups` — confirm `kmsKeyId` is set to `<AUDIT_KMS_KEY_ARN>`. |

---

### Personnel Clearance — Not in Application DB

| Requirement | C2S/SC2S Implementation | How to Verify |
|---|---|---|
| Personnel clearance level not stored in application DB | The `users` table stores only `keycloak_id`, `role` (application RBAC: `admin`/`editor`/`user`), and display fields. Security clearance level is not a column in the application schema. | `docs/truth/schema.md` — confirm no `clearance_level`, `clearance_date`, or equivalent column in `users` table. `SELECT column_name FROM information_schema.columns WHERE table_name = 'users'` — confirm no clearance column. |
| Clearance enforcement delegated to IdP | Keycloak on classified network enforces clearance-based access via CAC/PIV attribute mapping. Application role is orthogonal to clearance level — an `admin` role does not confer clearance. | Keycloak client configuration confirms SCI/clearance attributes are not passed to the application JWT. Application JWT payload contains only `role`, `sub`, and standard OIDC claims. |

---

### Access Control — IL6 Enhancements

| Control ID | Requirement | C2S/SC2S Implementation | How to Verify |
|---|---|---|---|
| AC-2(3) | Disable accounts after 35-day inactivity (NSS requirement) | Keycloak inactivity policy configured: accounts not accessed within 35 days are disabled. Admin must re-enable with supervisor attestation. | Keycloak admin console → Realm Settings → Sessions — confirm `SSO Session Idle` and account inactivity policy. |
| AC-10 | Limit concurrent sessions | Keycloak `userSessions` limit set to `<MAX_CONCURRENT_SESSIONS>` per user. | Keycloak → Client → `<APP_NAME>-app` → `Limit login attempts` — confirm session limit configured. |
| AC-17(2) | Remote access: FIPS 140-3 TLS only | All remote administrative access (kubectl, bastion) uses TLS 1.2+ with FIPS 140-3 cipher suites. SSM Session Manager sessions on C2S/SC2S use FIPS endpoints. | `aws ssm start-session` uses `ssm.<AWS_REGION>.amazonaws.com` classified endpoint. TLS inspection confirms FIPS cipher suite. |

---

### Incident Response — Spillage

IL6 adds spillage response procedures not present at IL4. These are operational/organizational — not application-layer code requirements.

| Control ID | Requirement | Implementation |
|---|---|---|
| IR-9 | Information spillage response | Spillage response procedures documented and exercised. Classified incident response team on call. Contact `<SPILLAGE_RESPONSE_POC>` for spillage events. |
| IR-9(2–4) (was IR-9(1–4); (1) withdrawn in Rev 5, incorporated into IR-9) | Spillage notification, training, post-spill operations, exposure response | Documented in organizational incident response plan. Application teams confirm awareness in onboarding. |

**Application team responsibility:** If the application logs or processes data that is later determined to be above the authorized classification level, immediately contact `<SPILLAGE_RESPONSE_POC>` and the AO. Do not attempt to delete logs — that is a tampering violation. Follow the organizational spillage response plan.

---

## CDS Integration Boundary

If the IL6 deployment includes integration with a Cross-Domain Solution (CDS) — for example, passing data from SECRET to UNCLASSIFIED networks — the following applies:

- CDS components must be procured from the NCDSMO Baseline Approved Product List (BAPL). The framework does not bundle or implement a CDS.
- CDS integration points must be documented in `standards/data/controls/CDS-guidance.md` and must not be bypassed.
- The Sentinel IL6 gate verifies that `CDS-guidance.md` describes any CDS boundary present in the deployment and that no data path skips the CDS.
- If this deployment does not include a CDS integration boundary, mark this item N/A with justification in the Sentinel gate report.

---

## Placeholder Reference

| Placeholder | Description |
|---|---|
| `<APP_ENDPOINT>` | Classified network hostname/IP of the application's ALB |
| `<APP_IRSA_ROLE>` | Name of the application pod's IRSA IAM role |
| `<AUDIT_KMS_KEY_ARN>` | ARN of the KMS key used to encrypt CloudWatch audit log group |
| `<SECURITY_OPS_ROLE_ARN>` | ARN of the security operations IAM role |
| `<MAX_CONCURRENT_SESSIONS>` | Maximum concurrent Keycloak sessions per user (NSS-defined) |
| `<SPILLAGE_RESPONSE_POC>` | Name/contact for classified data spillage response |
| `<AWS_REGION>` | C2S (`us-iso-east-1`) or SC2S (`us-isob-east-1`) region identifier |
