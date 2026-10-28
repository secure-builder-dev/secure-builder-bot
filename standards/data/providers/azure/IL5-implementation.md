## About This Document

**Purpose:** Azure Government Secret (IL5) delta controls above the IL4 baseline for deployments targeting FIPS 199 Moderate at IL5 — the maximum impact level available on the Azure platform.

**Workflow role:** Frank reads before implementing the Azure Government Secret track; Sentinel references when running IL5-specific gate checks; Winston reads when designing IL5 architecture.

**How to fill in:** No customization required for framework controls. Replace `<NAMESPACE>` and other deployment-specific placeholders with your project's values before running Sentinel checks.

---

# Azure Government Secret IL5 Implementation Guide

**Deployment target:** Azure Government Secret (`usdodcentral` or `usdodeast`)
**Impact level:** IL5 — data up to SECRET, FIPS 199 Moderate (SECRET-level classified)
**Control baseline:** `standards/data/controls/IL4-baseline.md` (IL4 baseline carried forward) + IL5 overlay requirements
**IL ceiling for Azure track:** IL5. This is the maximum impact level achievable on the Azure Government commercial and Secret offerings.
**Last updated:** 2026-05-04

---

## ⚠ IL6 CEILING NOTICE — REQUIRED READING BEFORE DEPLOYMENT

**Azure does not reach IL6 under the DoD Cloud Computing Security Requirements Guide (CC SRG).**

IL6 (SECRET-level data with NSS network requirements) requires deployment on classified cloud infrastructure that is **not** the Azure Government commercial or Secret offering. Specifically:

- **IL6 requires:** Cloud infrastructure operating on a classified network (e.g., C2S or SC2S for AWS; JWICS-connected classified infrastructure for other providers). These are NSS-specific classified cloud environments governed by the Intelligence Community and DISA, not commercial FedRAMP-authorized platforms.
- **Azure Government Secret** is authorized for **SECRET-level classified data** at **IL5** under DoD CC SRG v1r4. It is **not** authorized for IL6. The SRG impact level ceiling for Azure Government Secret is explicitly IL5.
- **Consequence of misclassification:** Deploying IL6-level data (data requiring processing on a classified network per CNSS policy) on Azure Government Secret is an unauthorized classification-level spillage. This document does not authorize such deployment.

**If your requirement is IL6:** See `providers/aws/IL6-implementation.md` (AWS C2S/SC2S) and ADR-020 (Alternatives Considered section — Azure IL6 support explicitly rejected). Contact the authorizing official and NSS network authority before selecting a cloud provider for IL6 deployments.

**Reference:** ADR-020 — "Azure's DoD classified track reaches IL5 (Azure Government Secret). IL6 under the DoD CC SRG requires NSS-specific infrastructure that is not the Azure Government commercial offering."

---

## Reference Sources

Use these to cross-reference IL5 requirements, verify Azure Government Secret service availability, or check FIPS and personnel clearance requirements.

| Source | What it covers | Where to find it |
|---|---|---|
| DoD Cloud Computing SRG v1r4 | IL5 definition; Azure Government Secret authorization; why IL6 is not available on Azure (Appendix A) | `public.cyber.mil` → search "Cloud Computing SRG" |
| NIST SP 800-53 Rev 5 | Authoritative control catalog; Moderate baseline (IL4 carried forward at IL5) | `csrc.nist.gov/pubs/sp/800/53/r5/upd1/final` |
| `providers/azure/IL4-implementation.md` | Full IL4 control mapping — all IL4 controls remain in force at IL5 | Local to this repo |
| `standards/data/controls/IL6-delta.md` | Cloud-agnostic High-baseline additions (informational reference; IL6 is not available on Azure — see ceiling notice) | Local to this repo |
| Azure Government Secret (DoD IL5) documentation | Services available in DoD IL5 regions (`usdodcentral`, `usdodeast`); differs from commercial Azure Government | `learn.microsoft.com/en-us/azure/azure-government/documentation-government-impact-level-5` |
| Microsoft DoD IL5 compliance page | Azure Government Secret FedRAMP High + DoD IL5 authorization scope; downloadable audit evidence | `learn.microsoft.com/en-us/azure/compliance/offerings/offering-dod-il5` |
| Azure AD Government Conditional Access | CAC/PIV enforcement, MFA policies, compliant device requirements | `learn.microsoft.com/en-us/azure/active-directory/conditional-access/` |
| NIST CMVP — FIPS 140-2 validated modules | Verify cryptographic modules in use are FIPS 140-2 validated (IL5 requirement; IL6 escalates to 140-3) | `csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search` |
| Azure immutable blob storage documentation | WORM policy configuration for tamper-evident audit log archival | `learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview` |
| Azure Key Vault purge protection | Prevents deletion of secrets and keys — required for IL5 data boundary controls | `learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview` |
| FedRAMP Marketplace — Azure Government | P-ATO documentation; inherited vs. customer-responsible controls for IL5 deployment | `marketplace.fedramp.gov` → search "Microsoft Azure Government" |

---

## Scope and Applicability

This document describes the additional controls and configuration differences that apply when operating at IL5 on Azure Government Secret above the IL4 baseline documented in `IL4-implementation.md`. All IL4 controls carry forward at IL5 — this document addresses only the delta.

**IL5 deployment differences from IL4:**
1. Deployment target is Azure Government Secret (`usdodcentral`/`usdodeast`) — not the Azure Government commercial regions.
2. FIPS 140-2 validated cryptographic modules required (same requirement as IL4; IL5 does not escalate to FIPS 140-3 on the Azure track — that escalation applies to IL6 only).
3. Personnel clearance integration: SECRET-cleared users only; clearance level delegated to the Azure AD Government identity provider and the organizational IdP — never stored in the application database.
4. Network boundary: Azure Government Secret is an air-gapped or restricted network environment; all Azure service endpoints are `.usgovclouddataapi.net` equivalents for the Secret environment. Public internet connectivity is not assumed.
5. Classification banner: All API responses must include a classification banner header when operating at or above IL5.

---

## IL5 Delta — Additional Controls and Configuration Changes

### Classification Banner Requirement (IL5)

| Requirement | Configuration | How to Verify |
|---|---|---|
| All API responses include classification marking header | Express response middleware adds `X-Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY` (or appropriate marking per deployment classification guide) to every response before sending. Banner content is configurable via environment variable `CLASSIFICATION_BANNER`. | `curl -I https://<APP_ENDPOINT>/api/health` — confirm `X-Classification` header present on every response. Environment variable `CLASSIFICATION_BANNER` set in Key Vault secret and injected via External Secrets Operator. |

> **Note:** The specific classification marking (e.g., `SECRET//NOFORN`, `UNCLASSIFIED//CUI`) is determined by the data classification of the information the system processes and the applicable classification authority. The application middleware must support runtime configuration of the banner text. **This document does not determine the classification marking — the Authorizing Official and system owner determine the appropriate marking based on the data processed.**

---

### IA — Identification and Authentication (IL5 Delta)

| Control ID | Control Name | Azure Government Secret Configuration | How to Verify |
|---|---|---|---|
| IA-2(1), IA-2(2) | MFA for All Accounts | Azure Government Secret environment enforces CAC/PIV authentication for all users (no username/password fallback). Keycloak is configured to reject authentication flows that do not present a valid DoD CAC. Azure AD Government Conditional Access policy: `Require compliant device` + `Require multifactor authentication` for all cloud app access. | Verify Keycloak does not offer password authentication flow. Azure AD Conditional Access policy export — confirm `grantControls.builtInControls` includes both `mfa` and `compliantDevice`. |
| IA-4 | Identifier Management | User identifiers sourced from the organizational IdP (CAC-derived UPN). `keycloak_id` is the FK stored in the application DB — **personnel clearance level is not stored in the application database**. Clearance validation is delegated entirely to the Azure AD Government identity provider and the organizational IdP. | `SELECT column_name FROM information_schema.columns WHERE table_name = 'users';` — confirm no `clearance_level`, `clearance_date`, or similar clearance columns in the schema. |

---

### Personnel Clearance Integration Boundary

At IL5, only SECRET-cleared personnel may be provisioned accounts in the system. The application enforces this at the identity provider layer, not the application layer:

- **Azure AD Government** enforces clearance-gated group membership. Only users in the `<SECRET_CLEARED_GROUP_ID>` Azure AD group are provisioned Keycloak accounts.
- **Keycloak** is configured with an Azure AD identity provider that maps group membership to application roles. Users not in the cleared group are blocked at the IdP layer before reaching the application.
- **The application does not perform clearance checks.** It authenticates the JWT token and enforces RBAC (`admin`/`editor`/`user`) only. Clearance validation is a pre-condition enforced by the identity chain, not a runtime responsibility of the application.

| Item | Configuration |
|---|---|
| Clearance enforcement point | Azure AD Government group membership (`<SECRET_CLEARED_GROUP_ID>`) — managed by the organizational IdP |
| Application clearance storage | **None** — clearance level never stored in application DB or JWT claims used for routing |
| Keycloak IdP group mapping | Azure AD group → Keycloak role mapping. Non-cleared users receive no Keycloak role and cannot access the application. |
| Verify | `SELECT * FROM users LIMIT 5;` — confirm no clearance-related columns. Azure AD group membership report — confirm only SECRET-cleared users in application group. |

---

### SC — System and Communications Protection (IL5 Delta)

| Control ID | Control Name | Azure Government Secret Configuration | How to Verify |
|---|---|---|---|
| SC-7 | Boundary Protection | In the Azure Government Secret environment, connectivity is restricted to the classified network boundary. No public internet egress from node subnet. Image pulls from ACR occur over the classified network only — ACR is deployed in the Secret region. | Verify no NAT Gateway routes to public internet. `az network route-table show --name <ROUTE_TABLE_NAME> --resource-group <RESOURCE_GROUP>` — confirm no `0.0.0.0/0` → Internet routes. |
| SC-8(1) | Transmission Cryptographic Protection | Application Gateway TLS policy: minimum TLS 1.2 using FIPS 140-2 validated cipher suites. All intra-cluster traffic TLS-encrypted. No HTTP-only endpoints. | Application Gateway TLS policy check (same as IL4). Verify no HTTP listeners. |
| SC-12 | Cryptographic Key Management | Key Vault in Azure Government Secret region. Key Vault configured with `enableRbacAuthorization: true` and purge protection. CMK for all storage encryption. | `az keyvault show --name <KEY_VAULT_NAME> --query '{rbac:properties.enableRbacAuthorization,purge:properties.enablePurgeProtection}'` — both `true`. |

---

### AU — Audit and Accountability (IL5 Delta)

| Control ID | Control Name | Azure Government Secret Configuration | How to Verify |
|---|---|---|---|
| AU-9 | Protection of Audit Information | Log Analytics Workspace in the classified region has both a `CanNotDelete` resource lock and a `ReadOnly` lock on the workspace resource (write access only via designated security ops principal). Immutable storage policy on the archive storage account. | `az lock list --resource <WORKSPACE_RESOURCE_ID>` — confirm both `CanNotDelete` and `ReadOnly` locks present. |
| AU-11 | Audit Record Retention | Log retention: minimum 365 days active in Log Analytics; immutable archive storage at `<AUDIT_ARCHIVE_STORAGE_ACCOUNT>` with time-based WORM policy configured for minimum 365-day lock. | `az storage container immutability-policy show --account-name <AUDIT_ARCHIVE_STORAGE_ACCOUNT> --container-name <AUDIT_CONTAINER>` — confirm `immutabilityPeriodSinceCreationInDays` ≥ 365. |

---

## Inherited Controls (IL5)

All inherited controls from the IL4 table carry forward at IL5. Additionally:

| Family | Inherited From |
|---|---|
| PE — Physical and Environmental | Azure Government Secret data center physical controls (classified facility) |
| PS — Personnel Security | Organizational personnel security and SECRET clearance adjudication |
| IR — Incident Response | Azure Government Secret MSRC incident response + organizational SOC for classified incidents |

---

## IL5 Deployment Prerequisites (Azure Government Secret)

In addition to the IL4 prerequisite services, the following are required for IL5:

- Azure Government Secret region access (requires DoD sponsorship and ATO for the classified environment)
- ACR deployed in the Secret region (not Azure Government commercial ACR)
- Key Vault in the Secret region
- Log Analytics Workspace in the Secret region
- Application Gateway in the Secret region
- All Kubernetes manifests, Helm chart values, and pipeline secrets reference Secret-region endpoints — no references to commercial Azure Government endpoints (`*.usgovcloudapi.net`)
- Classification banner middleware active (`CLASSIFICATION_BANNER` environment variable set per the applicable classification guide)

---

## Placeholder Reference (IL5 Additions)

The following placeholders are in addition to those documented in `IL4-implementation.md`.

| Placeholder | Description |
|---|---|
| `<SECRET_CLEARED_GROUP_ID>` | Azure AD group object ID for SECRET-cleared application users |
| `<ROUTE_TABLE_NAME>` | Route table name for AKS node subnet (Secret region) |
| `<AUDIT_CONTAINER>` | Blob container name for audit log archival with WORM policy |
| `CLASSIFICATION_BANNER` | Environment variable name for the classification banner text value |
