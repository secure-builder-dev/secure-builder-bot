## About This Document

**Purpose:** Maps each IL4 control baseline item to its Azure Government implementation — identifies which Azure service satisfies each control and how to verify it.

**Workflow role:** Frank reads before implementing the Azure Government deployment; Sentinel references when running IL4 gate checks; Winston reads when designing Azure architecture.

**How to fill in:** Replace all `<PLACEHOLDER>` values (cluster name, resource group, Key Vault name, namespace) with your project's actual resource names. Never commit real subscription IDs or service principal credentials.

---

# Azure Government IL4 Implementation Guide

**Deployment target:** Azure Government (`usgovarizona` or `usgovvirginia`)
**Impact level:** IL4 — data up to CUI, FIPS 199 Moderate
**Control baseline:** `standards/data/controls/IL4-baseline.md` (cloud-agnostic source)
**IL ceiling for Azure track:** IL5 (Azure Government Secret). This document covers IL4. See `IL5-implementation.md` for the IL5 layer.
**Last updated:** 2026-05-04

> **Azure track ceiling notice:** The Azure Government commercial offering reaches IL5 (Azure Government Secret — SECRET-level classified). Azure does **not** reach IL6 under the DoD CC SRG. IL6 requires NSS-specific classified cloud infrastructure (C2S/SC2S or equivalent) that is not available on Azure Government. If your deployment requirement is IL6, see `providers/aws/IL6-implementation.md` and ADR-020.

This document maps each IL4 control from the cloud-agnostic baseline to its Azure Government implementation. Each entry identifies the Azure service or configuration that satisfies the control and includes a "how to verify" step. Controls addressed entirely at the organizational or Azure platform ATO level are noted as inherited.

**Prerequisite services assumed deployed:**
- Azure Key Vault (Government region)
- Azure Workload Identity (federated pod identity for AKS — uses OIDC federation between AKS and Azure AD)
- Azure Container Registry (ACR) with Microsoft Defender for Containers enabled
- AKS cluster in Azure Government region with OIDC issuer enabled
- Azure Monitor + Log Analytics Workspace configured
- Azure Policy for AKS (Azure Policy add-on installed)
- Azure Active Directory Government as identity provider (Keycloak federated to AAD Gov)

---

## Reference Sources

Use these to cross-reference control mappings, verify Azure service configuration options, or check DoD authorization status for Azure Government.

| Source | What it covers | Where to find it |
|---|---|---|
| NIST SP 800-53 Rev 5 | Authoritative control catalog — AC, AU, CM, IA, SC, SI, SR families used throughout this doc | `csrc.nist.gov/pubs/sp/800/53/r5/upd1/final` (PDF + spreadsheet) |
| DoD Cloud Computing SRG v1r4 | IL4/IL5 definitions; Azure Government IL4 authorization; Appendix A lists authorized cloud offerings | `public.cyber.mil` → search "Cloud Computing SRG" |
| Azure Government documentation hub | Azure Government region service availability, compliance scope, and configuration differences from commercial Azure | `learn.microsoft.com/en-us/azure/azure-government/` |
| Azure Government compliance portal | FedRAMP High, DoD IL2/IL4/IL5 authorizations; downloadable audit reports and compliance documents | `learn.microsoft.com/en-us/azure/compliance/` → "Azure Government" filter |
| Azure Key Vault documentation | Secret management, RBAC authorization, purge protection, rotation policy configuration | `learn.microsoft.com/en-us/azure/key-vault/` |
| Azure Workload Identity documentation | OIDC federation setup between AKS and Azure AD; service account annotation patterns | `learn.microsoft.com/en-us/azure/aks/workload-identity-overview` |
| Azure AKS security concepts | Private cluster, RBAC, network policy, Azure Policy add-on, node pool hardening | `learn.microsoft.com/en-us/azure/aks/concepts-security` |
| Azure Container Registry documentation | Private endpoints, Defender for Containers, geo-replication, content trust | `learn.microsoft.com/en-us/azure/container-registry/` |
| Azure Monitor + Log Analytics | Workspace retention, resource locks, diagnostic settings for AKS | `learn.microsoft.com/en-us/azure/azure-monitor/` |
| Azure CLI reference (`az` commands) | Verify exact parameter names and query paths used in "How to Verify" column | `learn.microsoft.com/en-us/cli/azure/` |
| Microsoft Defender for Containers | Scanning configuration, Security Center API gate integration | `learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction` |
| FedRAMP Marketplace — Azure Government | FedRAMP High P-ATO; inherited controls list for Azure Government | `marketplace.fedramp.gov` → search "Microsoft Azure Government" |
| DISA STIG Viewer + STIG packages | Verify CNTR-K8, APSC-DV, PGS9 STIG IDs used in `STIG-checklist.md` | `public.cyber.mil/stigs/downloads/` |
| CIS Azure AKS Benchmark v1.4 | Source for `[Framework-derived]` AKS-specific items in the STIG checklist | `cisecurity.org/benchmark/kubernetes` (free after registration) |

---

## AC — Access Control

| Control ID | Control Name | Azure Service / Configuration | How to Verify |
|---|---|---|---|
| AC-2 | Account Management | Azure AD Government manages application user lifecycle. AKS uses Azure RBAC with scoped role assignments per namespace — no shared cluster-admin bindings for application service accounts. Workload Identity federates pod identity to a scoped Azure AD application registration. | `az role assignment list --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>` — confirm only expected role assignments exist. Azure AD admin portal confirms no orphaned accounts or guest accounts with elevated access. |
| AC-2(1) | Automated Account Management | Azure AD event-driven lifecycle workflows (Entitlement Management) deactivate accounts on separation signal. Key Vault access policies and RBAC are reviewed quarterly. | Verify Azure AD lifecycle workflow is active in Entitlement Management. `az keyvault role assignment list --hsm-name <KEY_VAULT_NAME>` — confirm no stale assignments. |
| AC-3 | Access Enforcement | Keycloak RBAC (`admin`/`editor`/`user`) enforced in Express middleware before route handlers. AKS RBAC (`ClusterRole`/`RoleBinding`) restricts pod-to-pod and pod-to-API-server access. Azure Application Gateway routes only to the application namespace ingress. | Run `curl -s <internal-endpoint>` without `Authorization` header — expect HTTP 401. `kubectl get rolebindings -A` — confirm only expected service account bindings exist. |
| AC-6 | Least Privilege | Workload Identity managed identity policy scoped to specific Azure Blob Storage container and Key Vault secrets only — no `*` resource in any role assignment. AKS service account bound to workload identity federation via annotation `azure.workload.identity/client-id`. | `az role assignment list --assignee <MANAGED_IDENTITY_CLIENT_ID>` — confirm no wildcard scope. `kubectl describe serviceaccount <APP_NAME>-backend -n <NAMESPACE>` — confirm workload identity annotation present. |
| AC-6(1) | Authorize Security Functions | Admin-only Keycloak roles required for user management endpoints. ACR push access restricted to the pipeline service principal only — no application runtime write access to ACR. | Attempt user-management API call with `editor` token — expect HTTP 403. Confirm only `<PIPELINE_SP_OBJECT_ID>` has `AcrPush` role on the ACR resource. |
| AC-12 | Session Termination | Stateless JWT tokens; no server-side session. Token expiry enforced in Express middleware via JWKS validation. Keycloak token TTL configured at `<TOKEN_TTL_SECONDS>`. | Replay an expired token — expect HTTP 401. Confirm no session tables in PostgreSQL schema. |
| AC-17 | Remote Access | AKS API server endpoint is private (`enablePrivateCluster: true`). Kubectl access requires Azure Bastion with CAC authentication or Azure AD Privileged Identity Management (PIM) with MFA. | `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'apiServerAccessProfile.enablePrivateCluster'` — expect `true`. |

---

## AU — Audit and Accountability

| Control ID | Control Name | Azure Service / Configuration | How to Verify |
|---|---|---|---|
| AU-2 | Event Logging | AKS control plane diagnostic settings ship audit logs (kube-apiserver, kube-audit, kube-scheduler) to Log Analytics Workspace. Winston middleware logs all HTTP requests with method, path, status, response time, and `keycloak_id`. Azure Monitor ingests logs from container stdout/stderr. | `az monitor diagnostic-settings list --resource <AKS_RESOURCE_ID>` — confirm `kube-audit` category enabled and destination is Log Analytics Workspace. Verify Winston log format in application logs. |
| AU-3 | Content of Audit Records | Winston log format: `{ timestamp, method, path, status, duration_ms, keycloak_id, request_id }`. No PII, no full request bodies, no response bodies in logs. | Trigger a request; verify log entry in Log Analytics — confirm no PII fields. `az monitor log-analytics query --workspace <WORKSPACE_ID> --analytics-query 'ContainerLog | limit 10'` — review log shape. |
| AU-4 | Audit Log Storage Capacity | Log Analytics Workspace retention set to 365 days minimum. Data export to Azure Storage Account configured for long-term archival. | `az monitor log-analytics workspace show --workspace-name <WORKSPACE_NAME> --resource-group <RESOURCE_GROUP> --query 'retentionInDays'` — confirm ≥ 365. |
| AU-9 | Protection of Audit Information | Log Analytics Workspace has a resource lock (`CanNotDelete`) applied. Application managed identity does not have `Microsoft.OperationalInsights/workspaces/write` or delete permissions. | `az lock list --resource-group <RESOURCE_GROUP>` — confirm `CanNotDelete` lock on workspace. Confirm application managed identity role assignment does not include Log Analytics Contributor or higher. |
| AU-9(4) | Access by Subset of Privileged Users | Log Analytics management operations restricted to `<SECURITY_OPS_PRINCIPAL_ID>` via scoped RBAC. | Confirm application managed identity role is limited to `Log Analytics Reader` (or send-only) — not `Log Analytics Contributor`. |
| AU-11 | Audit Record Retention | Log Analytics Workspace retention: 365 days. Log export to Azure Storage Account (immutable blob storage with time-based retention lock) for archival at `<AUDIT_ARCHIVE_STORAGE_ACCOUNT>/<AUDIT_CONTAINER>/`. | `az storage blob service-properties show --account-name <AUDIT_ARCHIVE_STORAGE_ACCOUNT>` — confirm immutable policy enabled. |
| AU-12 | Audit Record Generation | Winston middleware registered as first Express middleware before route handlers. All requests generate an audit record regardless of outcome. AKS diagnostic logs capture all kube-apiserver audit events. | Deploy a request that triggers a 404 — confirm log entry exists in Log Analytics. Verify middleware order in `app.ts`. |

---

## CM — Configuration Management

| Control ID | Control Name | Azure Service / Configuration | How to Verify |
|---|---|---|---|
| CM-2 | Baseline Configuration | Helm chart defines the complete AKS baseline. All pod specs pinned to digest-tagged images from ACR. GitOps (Flux or ArgoCD) tracks the chart version in the application Git repository. | `helm history <RELEASE_NAME>` — confirm version pinned. `kubectl get pods -o jsonpath='{.items[*].spec.containers[*].image}'` — confirm digest-tagged images from `<ACR_NAME>.azurecr.us`. |
| CM-3 | Configuration Change Control | All Helm chart changes require PR + Sentinel gate review. Direct `kubectl apply` to production namespace blocked by Azure Policy admission webhook. | Attempt `kubectl apply` without PR — confirm admission webhook rejects. `git log docs/architecture/` confirms ADR audit trail. |
| CM-6 | Configuration Settings | All application secrets injected via External Secrets Operator (ESO) pulling from Azure Key Vault using Workload Identity. No secrets in Helm values files — only `secretKeyRef` references to the ExternalSecret-created Kubernetes Secret. ExternalSecret spec: `spec.dataFrom.extract.key: <APP_NAME>/<ENV>/app-secrets` in Key Vault. | `kubectl get externalsecrets -n <NAMESPACE>` — confirm sync status `SecretSynced`. `kubectl get secret <APP_NAME>-app-secrets -o yaml` — confirm no plaintext secrets in Helm values. `az keyvault secret list --vault-name <KEY_VAULT_NAME>` — confirm expected secrets present. |
| CM-7 | Least Functionality | AKS nodes use minimal Azure Linux (Mariner) or Ubuntu AKS-optimized image. No SSH daemon on nodes — Azure Bastion or `az aks command invoke` used for break-glass access only. Node security group allows only Application Gateway → pod traffic on port 3000. | `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'agentPoolProfiles[*].osSKU'` — confirm minimal OS. `az network nsg rule list --nsg-name <NODE_NSG_NAME> --resource-group <RESOURCE_GROUP>` — confirm no port 22 inbound rule. |
| CM-8 | System Component Inventory | SBOM generated per build (CycloneDX format) stored as ACR artifact annotation or in the pipeline artifact store. Microsoft Defender for Containers scans every image on push to ACR. | `az acr manifest show-metadata --registry <ACR_NAME> --name <IMAGE_NAME>` — confirm SBOM annotation present. Azure Security Center — Container registry recommendations — confirm no unresolved critical findings. |

---

## IA — Identification and Authentication

| Control ID | Control Name | Azure Service / Configuration | How to Verify |
|---|---|---|---|
| IA-2 | Identification and Authentication | Keycloak federated to the organizational CAC/PIV IdP via Azure AD Government. All application users authenticated via Keycloak PKCE OAuth2 flow. AKS cluster authentication via Azure AD integration — `kubelogin` with AAD Government. | `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'aadProfile'` — confirm AAD integration enabled. Attempt login without CAC — confirm Keycloak rejects. |
| IA-2(1), IA-2(2) | MFA for Privileged and Non-Privileged Accounts | Keycloak enforces MFA (CAC) for all users. Azure AD Conditional Access policy requires MFA for Azure portal and CLI access. | Keycloak admin console → Authentication → Required Actions confirms CONFIGURE_TOTP or CAC required. Azure AD Conditional Access — confirm policy targeting all users requires MFA. |
| IA-5 | Authenticator Management | Azure Key Vault stores all application credentials (DB password, signing keys, ACR pull credentials). External Secrets Operator (with Workload Identity) syncs secrets to Kubernetes Secrets on a defined resync interval. No secrets in environment variable definitions or config maps. | `az keyvault secret list --vault-name <KEY_VAULT_NAME>` — confirm all app secrets present with `<APP_NAME>/` prefix. `kubectl get configmap -n <NAMESPACE> -o yaml` — confirm no embedded secret values. |
| IA-7 | Cryptographic Module Authentication | Azure Government endpoints use FIPS 140-2 validated modules at IL4. TLS connections use FIPS-compliant cipher suites enforced at Application Gateway (TLS policy `AppGwSslPolicy20220101`). | `az network application-gateway ssl-policy show --gateway-name <APP_GW_NAME> --resource-group <RESOURCE_GROUP>` — confirm FIPS-compliant TLS policy. Verify no non-FIPS cipher suites in the policy. |

---

## MA — Maintenance

| Control ID | Control Name | Azure Service / Configuration | How to Verify |
|---|---|---|---|
| MA-4 | Nonlocal Maintenance | AKS node access via Azure Bastion only. No SSH key pairs deployed on nodes (SSH disabled in node pool config). Azure Bastion sessions require Azure AD MFA. Session activity logged to Log Analytics. | `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'agentPoolProfiles[*].nodeTaints'` — confirm SSH not enabled. `az network bastion list --resource-group <RESOURCE_GROUP>` — confirm Bastion deployed in management subnet. |

---

## MP — Media Protection

| Control ID | Control Name | Azure Service / Configuration | How to Verify |
|---|---|---|---|
| MP-2 | Media Access | Azure Blob Storage container policy restricts access to the application managed identity only. Public blob access disabled at storage account level (`allowBlobPublicAccess: false`). Storage account firewall restricts access to AKS subnet only. | `az storage account show --name <STORAGE_ACCOUNT_NAME> --resource-group <RESOURCE_GROUP> --query 'allowBlobPublicAccess'` — expect `false`. `az storage account network-rule list --account-name <STORAGE_ACCOUNT_NAME>` — confirm AKS subnet is the only allowed virtual network. |
| MP-6 | Media Sanitization | Azure Blob object deletion uses server-side deletion. Storage account key rotation revokes access. Customer-managed key (CMK) via Key Vault — key deletion revokes access to all encrypted blobs. | Confirm storage lifecycle policy does not retain soft-deleted blobs beyond retention window. Key Vault CMK deletion is access-protected by Key Vault RBAC. |

---

## SC — System and Communications Protection

| Control ID | Control Name | Azure Service / Configuration | How to Verify |
|---|---|---|---|
| SC-7 | Boundary Protection | Single Azure Application Gateway ingress point in public subnet. AKS nodes in private subnet — no direct internet access. Azure Firewall or NAT Gateway for egress only (image pulls from ACR during build). Network Security Group blocks all non-Application-Gateway inbound traffic to node subnet. | `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'networkProfile'` — confirm private cluster. Confirm NAT Gateway is the only egress path from node subnet. |
| SC-8(1) | Transmission Cryptographic Protection | Application Gateway HTTPS listener enforces FIPS-compliant TLS policy (`AppGwSslPolicy20220101`, minimum TLS 1.2). Internal pod-to-pod traffic uses Kubernetes-native TLS (cert-manager with `<INTERNAL_CA>` issuer). | `az network application-gateway frontend-port list --gateway-name <APP_GW_NAME> --resource-group <RESOURCE_GROUP>` — confirm HTTPS frontend configured. Verify no HTTP-only listeners in Application Gateway rules. |
| SC-12 | Cryptographic Key Management | Azure Blob Storage uses Customer-Managed Key (CMK) from Key Vault for SSE. Key Vault is configured with soft-delete and purge protection enabled. Annual key rotation enforced via Key Vault rotation policy. | `az keyvault show --name <KEY_VAULT_NAME> --resource-group <RESOURCE_GROUP> --query '{softDelete:properties.enableSoftDelete, purgeProtection:properties.enablePurgeProtection}'` — expect both `true`. `az storage account show --name <STORAGE_ACCOUNT_NAME> --query 'encryption'` — confirm Key Vault CMK. |
| SC-13 | Cryptographic Protection | Azure Government region uses FIPS 140-2 validated cryptographic modules for all Azure service API calls at IL4. Application Gateway enforces TLS 1.2 minimum. Node.js application uses standard TLS without downgrading cipher suites. | Application Gateway TLS policy check above. Confirm no `--ssl-version=tlsv1` or deprecated cipher flags in Node.js startup. |
| SC-17 | PKI Certificates | TLS certificates issued by `<INTERNAL_CA>` via cert-manager with an Azure AD-integrated issuer, or from `<APP_GW_CERT_ARN>` via Key Vault certificate reference. | `kubectl get certificate -n <NAMESPACE>` — confirm cert-manager issued cert is READY. `az keyvault certificate show --vault-name <KEY_VAULT_NAME> --name <CERT_NAME>` — confirm certificate present and active. |
| SC-28 | Protection of Information at Rest | Azure Blob objects encrypted with SSE using CMK from Key Vault. Azure Database for PostgreSQL Flexible Server encrypted at rest with CMK. AKS OS disks encrypted with Azure Disk Encryption or platform-managed key (CMK preferred for IL4). No temporary disk writes — Multer configured for memory storage only. | `az storage account show --name <STORAGE_ACCOUNT_NAME> --query 'encryption.keySource'` — confirm `Microsoft.Keyvault`. `az postgres flexible-server show --name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --query 'dataEncryption'` — confirm CMK encryption. |

---

## SI — System and Information Integrity

| Control ID | Control Name | Azure Service / Configuration | How to Verify |
|---|---|---|---|
| SI-2 | Flaw Remediation | `npm audit` runs in pipeline as blocking gate step. Microsoft Defender for Containers scans every ACR image on push — critical/high findings block pipeline via Azure Security Center API gate. | Azure Security Center — Container registry recommendations — confirm no unresolved critical findings for deployed image. Pipeline log confirms `npm audit --audit-level=high` passes. |
| SI-3 | Malicious Code Protection | Base images pulled from ACR (populated from approved sources — no public Docker Hub). Defender for Containers scans every image in ACR; zero critical/high findings required. ACR geo-redundancy disabled for Government regions (use single-region ACR). | Azure Security Center — Defender for Containers recommendations — confirm image scan passed. `az acr repository show --name <ACR_NAME> --repository <REPO_NAME>` — confirm image present. |
| SI-7 | Software Integrity | Container images signed with Cosign (signing key in Key Vault `<COSIGN_KEY_SECRET_NAME>`). AKS admission controller (Ratify with Gatekeeper or Kyverno) enforces signature verification before pod scheduling. | `cosign verify --key azurekms://<KEY_VAULT_URI>/keys/<COSIGN_KEY_NAME> <IMAGE_DIGEST>` passes. Attempt deploy of unsigned image — confirm admission webhook rejects. |
| SI-7(1) | Integrity Checks | CycloneDX SBOM generated per build; stored as ACR image attestation. Attestation verified by Cosign. | `cosign verify-attestation --type cyclonedx --key azurekms://<KEY_VAULT_URI>/keys/<COSIGN_KEY_NAME> <IMAGE_DIGEST>` passes. |
| SI-10 | Information Input Validation | Knex parameterized queries for all SQL — no string interpolation. Express-validator validates all request bodies. `zod` schema validation on API inputs. | Code review: `grep -r "knex.raw" backend/src/` — confirm no raw SQL with user inputs. |
| SI-11 | Error Handling | Express global error handler returns generic `{ error: "Internal server error" }` with no stack trace, DB message, storage key, or file path. | Trigger a 500 intentionally; confirm response body contains no stack trace or internal path. |

---

## SR — Supply Chain Risk Management

| Control ID | Control Name | Azure Service / Configuration | How to Verify |
|---|---|---|---|
| SR-3 | Supply Chain Controls | Base images sourced from approved registries and pushed to ACR. Defender for Containers verifies provenance and absence of critical/high CVEs. `npm audit` + `DEPENDENCY_POLICY.md` gates supply chain at application layer. SBOM generated and stored per build. | `az acr repository show-manifests --name <ACR_NAME> --repository <REPO_NAME>` — confirm images present. SBOM artifact present in pipeline artifact store after each build. |
| SR-5 | Acquisition Strategies | All npm packages vetted against `docs/architecture/DEPENDENCY_POLICY.md`. Approved list managed by Sentinel gate. GPL/AGPL licenses blocked. | `npm audit --audit-level=moderate` passes. Review `DEPENDENCY_POLICY.md` approved lists match `package.json`. |
| SR-11 | Component Authenticity | Pipeline validates base image provenance before build. Cosign container signing prevents post-build image substitution. ACR content trust enforced via admission controller. | Pipeline log confirms base image provenance check passed. `cosign verify` passes for deployed image. |

---

## Inherited Controls

The following control families are inherited from the Azure Government platform ATO and require no application-layer implementation. Application teams confirm inheritance in the System Security Plan.

| Family | Inherited From |
|---|---|
| PE — Physical and Environmental Protection | Azure Government FedRAMP High data center physical controls |
| CP — Contingency Planning (infrastructure layer) | Azure Government platform backup and recovery procedures |
| PL — Planning | ATO / organizational policies |
| PS — Personnel Security | Organizational personnel vetting and separation procedures |
| IR — Incident Response (organizational layer) | Azure Government MSRC incident response procedures |
| MA — Maintenance (physical layer) | Azure Government physical maintenance controls |

---

## Placeholder Reference

The following placeholders appear in this document and must be replaced with actual values at deployment time. Never commit real infrastructure values to this repo.

| Placeholder | Description |
|---|---|
| `<SUBSCRIPTION_ID>` | Azure subscription ID |
| `<TENANT_ID>` | Azure AD tenant ID |
| `<RESOURCE_GROUP>` | Resource group containing the application resources |
| `<CLUSTER_NAME>` | AKS cluster name |
| `<NAMESPACE>` | Kubernetes namespace for the application |
| `<ACR_NAME>` | Azure Container Registry name |
| `<KEY_VAULT_NAME>` | Azure Key Vault name |
| `<KEY_VAULT_URI>` | Azure Key Vault URI (e.g., `https://<name>.vault.usgovcloudapi.net`) |
| `<APP_GW_NAME>` | Azure Application Gateway name |
| `<APP_GW_CERT_ARN>` | Key Vault certificate reference for Application Gateway TLS |
| `<WORKSPACE_ID>` | Log Analytics Workspace ID |
| `<WORKSPACE_NAME>` | Log Analytics Workspace name |
| `<STORAGE_ACCOUNT_NAME>` | Azure Storage Account for document storage |
| `<AUDIT_ARCHIVE_STORAGE_ACCOUNT>` | Azure Storage Account for long-term audit log archival |
| `<AUDIT_CONTAINER>` | Blob container name for audit log archival |
| `<POSTGRES_SERVER_NAME>` | Azure Database for PostgreSQL Flexible Server name |
| `<MANAGED_IDENTITY_CLIENT_ID>` | Client ID of the application managed identity |
| `<PIPELINE_SP_OBJECT_ID>` | Object ID of the pipeline service principal |
| `<SECURITY_OPS_PRINCIPAL_ID>` | Object ID of the security operations principal |
| `<NODE_NSG_NAME>` | Network Security Group name for AKS node subnet |
| `<INTERNAL_CA>` | Internal CA name/description |
| `<COSIGN_KEY_SECRET_NAME>` | Key Vault secret/key name for Cosign signing key |
| `<COSIGN_KEY_NAME>` | Key Vault key name for Cosign (azurekms reference) |
| `<TOKEN_TTL_SECONDS>` | Keycloak access token TTL (seconds) |
