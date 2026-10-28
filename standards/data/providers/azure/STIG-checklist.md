## About This Document

**Purpose:** AKS/ACR/Node.js/PostgreSQL STIG verification checklist for the Azure Government deployment track.

**Workflow role:** Frank reads and executes before marking deployment-lane stories complete; Sentinel confirms checklist completion at gate.

**How to fill in:** Work through sections 1–4 top-to-bottom at first deployment. Re-run Section 4 (PostgreSQL) for each schema-change story. Mark any non-applicable item N/A with justification.

---

# Azure / AKS / Container / Node.js / PostgreSQL STIG Checklist

**Lane:** Frank (pipeline STIG verification reference)
**Scope:** Azure Government deployment using AKS, containerized Node.js, and Azure Database for PostgreSQL Flexible Server. Items apply equally to Azure Government Secret (IL5) deployments unless noted.
**References:** DISA Kubernetes STIG V1R11; DISA Application Security and Development STIG V5R3; DISA PostgreSQL 9.x STIG V2R4; CIS Azure AKS Benchmark v1.4; CIS Microsoft Azure Foundations Benchmark v2.0
**Last updated:** 2026-05-04

> **STIG ID note:** STIG IDs reference DISA STIG content current as of this document date. Verify item applicability and exact IDs against the current DISA STIG Viewer (`public.cyber.mil/stigs/`) before use in formal audit assessments. Items labeled `[Framework-derived]` have no direct DISA STIG ID and derive from DoD CC SRG v1r4, CIS benchmark items, or Azure Government platform requirements.

Quality-gate verification: every item names either a published STIG ID or its derivation source (`[Framework-derived]` with the source reference). No percentage threshold: no platform STIG is published for this track's surface, so the items derive from the SRGs and NIST rather than from a STIG. `make verify-citations` checks every published ID that is cited.

## Reference Sources

Use these to verify STIG IDs, look up current STIG content, or check CIS benchmark items for AKS.

| Source | What it covers | Where to find it |
|---|---|---|
| DISA STIG Viewer (free JAR) | Load and search all STIG packages; look up CNTR-K8, APSC-DV, PGS9 IDs | `public.cyber.mil/stigs/srg-stig-tools/` |
| DISA Kubernetes STIG V1R11 | Source for all CNTR-K8-XXXXXX items in Sections 1 and 2 | `public.cyber.mil/stigs/downloads/` → search "Kubernetes" |
| DISA Application Security and Development STIG V5R3 | Source for all APSC-DV-XXXXXX items in Sections 2 and 3 | `public.cyber.mil/stigs/downloads/` → search "Application Security and Development" |
| DISA PostgreSQL 9.x STIG V2R4 | Source for all PGS9-00-XXXXXX items in Section 4 (compatible with PostgreSQL 14/15/16) | `public.cyber.mil/stigs/downloads/` → search "PostgreSQL" |
| CIS Azure AKS Benchmark v1.4 | Source for `[Framework-derived]` AKS-specific items in Section 1 | `cisecurity.org/benchmark/kubernetes` (free after registration) |
| CIS Microsoft Azure Foundations Benchmark v2.0 | Source for `[Framework-derived]` Azure resource configuration items (ACR, Key Vault, storage) | `cisecurity.org/benchmark/azure` (free after registration) |
| Azure AKS security hardening docs | Canonical Microsoft guidance for AKS hardening items — cross-reference Section 1 verify steps | `learn.microsoft.com/en-us/azure/aks/security-hardened-vm-host-image` |
| Azure Container Registry security docs | Canonical Microsoft guidance for ACR access control and scanning — cross-reference Section 2 | `learn.microsoft.com/en-us/azure/container-registry/container-registry-intro` |
| Azure Database for PostgreSQL Flexible Server parameters | Canonical parameter names and allowed values — cross-reference Section 4 verify steps | `learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters` |
| DoD Cloud Computing SRG v1r4 §5.7 | Trusted container provenance requirement grounding Section 2 `[Framework-derived]` items | `public.cyber.mil` → search "Cloud Computing SRG" |
| `providers/aws/STIG-checklist.md` Section 3 | Node.js runtime STIG items — referenced by Section 3 of this checklist, not duplicated | Local to this repo |

> **Node.js runtime STIG items (Section 3):** See `providers/aws/STIG-checklist.md` Section 3. All Node.js runtime hardening items apply identically to the Azure track — the runtime is Node.js regardless of cloud provider. Reference those items directly rather than duplicating them here.
>
> **PostgreSQL STIG items (Section 4):** This section contains the full set of DISA PostgreSQL STIG items adapted for Azure Database for PostgreSQL Flexible Server. Verification commands use `az postgres flexible-server` CLI syntax.

---

## Section 1 — AKS Cluster Hardening

Sources: DISA Kubernetes STIG V1R11 (CNTR-K8-XXXXXX); CIS Azure AKS Benchmark v1.4

| STIG ID | Check Description | Pass Criterion |
|---|---|---|
| CNTR-K8-000010 | Kubernetes API server must have anonymous authentication disabled | AKS managed control plane disables anonymous auth by default. `kubectl get --as=system:anonymous pods` returns `Forbidden`. `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'enableRbac'` returns `true`. |
| CNTR-K8-000020 | Kubernetes API server must not use basic authentication | AKS managed control plane does not support basic authentication. `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'aadProfile'` returns non-null AAD profile confirming AAD-only authentication. |
| CNTR-K8-000030 | Kubernetes API server must not use token file–based authentication | AKS does not allow `--token-auth-file` on the managed control plane. `kubelogin` with AAD is the only authentication mechanism — no static token files. |
| CNTR-K8-000100 | Kubernetes secrets must not be stored as environment variables | `kubectl get pods -o jsonpath='{..env}'` returns no inline secret values. All secrets injected via `secretKeyRef` from ExternalSecret-created Kubernetes Secrets sourced from Key Vault via Workload Identity. |
| CNTR-K8-000150 | Kubernetes API server must enable audit logging | AKS diagnostic settings ship `kube-audit` and `kube-audit-admin` log categories to Log Analytics Workspace. `az monitor diagnostic-settings list --resource <AKS_RESOURCE_ID>` — confirm `kube-audit` category enabled with Log Analytics destination. |
| CNTR-K8-000160 | Kubernetes audit log must have a maximum size configured | AKS audit log sizing managed by Azure. Log Analytics Workspace daily cap configured. `az monitor log-analytics workspace show --workspace-name <WORKSPACE_NAME> --resource-group <RESOURCE_GROUP> --query 'workspaceCapping'` — confirm daily cap configured and alert on cap approach set. |
| CNTR-K8-000170 | Kubernetes audit log must have a maximum age configured | Log Analytics Workspace retention ≥ 30 days minimum (365 days required for AU-11). `az monitor log-analytics workspace show --workspace-name <WORKSPACE_NAME> --resource-group <RESOURCE_GROUP> --query 'retentionInDays'` — confirm ≥ 365. |
| CNTR-K8-000180 | Kubernetes audit log must have a maximum backup count configured | Log Analytics archival export to Azure Storage Account with immutable blob storage configured. `az storage container immutability-policy show --account-name <AUDIT_ARCHIVE_STORAGE_ACCOUNT> --container-name <AUDIT_CONTAINER>` — confirm policy present with ≥ 365 day retention lock. |
| CNTR-K8-000200 | Kubernetes API server must use RBAC authorization mode | AKS has RBAC enabled and Azure RBAC integration enforced. `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'enableRbac'` — expect `true`. `kubectl auth can-i --list --as=system:serviceaccount:default:default` returns only expected permissions. |
| CNTR-K8-000250 | Default Kubernetes service account must not be used for API operations | All application pods use a named service account annotated with `azure.workload.identity/client-id: <MANAGED_IDENTITY_CLIENT_ID>`. `kubectl get pods -o jsonpath='{..serviceAccountName}'` returns no `default` service accounts in application namespaces. |
| CNTR-K8-000260 | Kubernetes must not automatically mount service account tokens on Pods that do not need API access | Application pods that do not call the Kubernetes API set `automountServiceAccountToken: false` in the pod spec. `kubectl get pods -n <NAMESPACE> -o json | jq '.items[] | select(.spec.automountServiceAccountToken != false)'` — returns no application pods that should not have API access. |
| CNTR-K8-000270 | Kubernetes API server must have the PodSecurity admission controller enabled | AKS 1.25+: PodSecurity admission enabled. Application namespace labeled `pod-security.kubernetes.io/enforce: restricted` or `baseline`. `kubectl get namespace <NAMESPACE> --show-labels` — confirm label present. |
| CNTR-K8-000290 | Kubernetes API server must have the NodeRestriction admission plugin enabled | AKS managed control plane enables NodeRestriction by default. Verify admission plugins via AKS control plane configuration: NodeRestriction is present in the managed control plane admission chain. |
| CNTR-K8-000310 | Kubernetes pods must not run as root | Pod security context: `runAsNonRoot: true`, `runAsUser: <NON_ROOT_UID>`. `securityContext.allowPrivilegeEscalation: false` on all containers. `kubectl get pods -n <NAMESPACE> -o json | jq '.items[].spec.containers[].securityContext'` — confirm `runAsNonRoot: true` on all containers. |
| CNTR-K8-000330 | Kubernetes must not allow privileged containers | No pod spec has `privileged: true`. PodSecurity admission and Azure Policy built-in `Do not allow privileged containers in Kubernetes cluster` assigned. `az policy assignment list --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>` — confirm policy assigned. |
| CNTR-K8-000340 | Containers must not share the host process ID namespace | Pod spec does not contain `hostPID: true`. `kubectl get pods -A -o json | jq '.items[] | select(.spec.hostPID==true)'` returns empty. |
| CNTR-K8-000350 | Containers must not share the host network namespace | Pod spec does not contain `hostNetwork: true`. Azure Policy built-in `Kubernetes cluster pods should not use host network` assigned and compliant. `kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true)'` returns empty in application namespaces. |
| CNTR-K8-000360 | Containers must not share the host IPC namespace | Pod spec does not contain `hostIPC: true`. `kubectl get pods -A -o json | jq '.items[] | select(.spec.hostIPC==true)'` returns empty. |
| CNTR-K8-000380 | Kubernetes kubelet must not allow anonymous authentication | AKS node pools use `--anonymous-auth=false` on managed kubelet by default. `az aks nodepool show --cluster-name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --name <NODEPOOL_NAME> --query 'kubeletConfig'` — confirm anonymous auth disabled. |
| CNTR-K8-000390 | Kubernetes API server must not have the insecure-port flag set | AKS managed control plane does not expose the insecure port (port 8080). No `--insecure-port` flag in managed control plane. Verify: `curl http://<KUBE_APISERVER_IP>:8080/api` from within the cluster fails with connection refused. |
| CNTR-K8-000400 | Kubernetes API server must have the AlwaysPullImages admission plugin enabled | Configure via `az aks update` with `--enable-alwayspullimages` (AKS 1.27+). Alternatively enforce via Azure Policy `Ensure image registries are configured for Kubernetes cluster`. Verify admission plugin is active. |
| CNTR-K8-000435 | Containers must drop all Linux capabilities not explicitly required | Pod spec `securityContext.capabilities.drop: ["ALL"]`. Required capabilities added back individually. No `NET_ADMIN`, `SYS_ADMIN`, or `SYS_PTRACE` unless justified. Azure Policy built-in `Kubernetes cluster containers should only use allowed capabilities` assigned. |
| CNTR-K8-000440 | Kubernetes must have network policies defined for all application namespaces | AKS configured with `--network-policy azure` or `--network-policy calico`. `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'networkProfile.networkPolicy'` — confirm non-null. `kubectl get networkpolicy -A` — all application namespaces have default-deny ingress and egress policy. |
| [Framework-derived] | AKS nodes use managed identities only — no service principal with client secret | `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'identity.type'` — expect `UserAssigned` or `SystemAssigned`. No service principal with client secret credential in any node or control plane configuration. |
| [Framework-derived] | AKS node pool OS disk encrypted with Customer-Managed Key | Node pool OS disk encrypted with Azure Disk Encryption Set referencing Key Vault CMK (`--disk-encryption-set-id`). `az disk-encryption-set show --name <ENCRYPTION_SET_NAME> --resource-group <RESOURCE_GROUP>` — confirm Key Vault CMK present and active. |
| [Framework-derived] | RBAC — no wildcard resource permissions in application service account roles | `kubectl get clusterrolebindings,rolebindings -A -o yaml | grep '"*"'` returns no results in application namespaces. Azure Policy built-in `Kubernetes cluster should not grant CLUSTER_ADMIN to service accounts` assigned. |
| [Framework-derived] | AKS API server endpoint is private | `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'apiServerAccessProfile.enablePrivateCluster'` returns `true`. No public API server DNS name resolvable from outside the VNet. |
| [Framework-derived] | Azure Policy add-on enabled on AKS cluster | `az aks show --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP> --query 'addonProfiles.azurepolicy.enabled'` returns `true`. Azure Policy compliance dashboard — AKS-scoped policies assigned and reporting compliance state. |

---

## Section 2 — ACR Container Image Hardening

Sources: DISA Application Security and Development STIG V5R3 (APSC-DV-XXXXXX); DISA Kubernetes STIG V1R11 (CNTR-K8-XXXXXX); Azure Container Registry + Defender for Containers requirements

| STIG ID | Check Description | Pass Criterion |
|---|---|---|
| APSC-DV-000100 | Application must not use packages with unresolved critical CVEs | `npm audit --audit-level=critical` exits 0. Microsoft Defender for Containers scans every ACR image on push — critical findings surface in Azure Security Center. Pipeline gate checks Security Center API and blocks if critical findings exist. No CRITICAL findings on deployed image. |
| APSC-DV-001120 | Application must not run as root — container must not run as root | Container user is non-root (`USER <NON_ROOT_UID>` in Dockerfile). Pod spec `securityContext.runAsNonRoot: true`. `kubectl exec <POD> -- id` returns `uid=<NON_ROOT_UID>` (not uid=0). |
| APSC-DV-001160 | Application must use a DoD-approved CA for TLS | Container trusts only `<INTERNAL_CA>` issued certificates. No public CAs not on the Azure Government approved list in the container trust store. |
| APSC-DV-001740 | Application must have vulnerability scanning performed | Defender for Containers scans every image pushed to ACR (enabled: `az security pricing show --name ContainerRegistry` — expect `pricingTier: Standard`). Pipeline blocks if scan has critical findings. Azure Security Center — Container registry recommendations — confirm no unresolved critical findings for the deployed image digest. |
| APSC-DV-002000 | Application must implement DoD-approved encryption for data in transit | All container outbound connections (to PostgreSQL, to Azure APIs, to Key Vault) use TLS 1.2+. No `http://` scheme for any external connection from the container. `DATABASE_URL` includes `?sslmode=verify-full`. Azure SDK calls use HTTPS endpoints only. |
| APSC-DV-002240 | Application must not contain SUID or SGID binaries | `find / -perm /6000 -type f` in the container returns no results or only expected system binaries. Dockerfile explicitly removes SUID binaries: `RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true`. |
| APSC-DV-002440 | Application must not expose administrative interfaces in production | No debug endpoints (`/debug`, Node.js inspector port 9229) exposed. `kubectl get svc -n <NAMESPACE>` — no service exposes port 9229. Azure NSG — confirm no rule exposes port 9229 externally. |
| APSC-DV-002460 | Application error messages must not reveal sensitive information | Error responses contain no stack traces, file paths, DB messages, or storage keys. Verified during Sentinel gate check and manual testing. |
| CNTR-K8-000190 | Container image versions must use immutable references | Images deployed using digest references (`<ACR_NAME>.azurecr.us/<REPO>@sha256:<DIGEST>`) — not mutable tags. Azure Policy or Kyverno policy rejects mutable-tag deployments. `kubectl get pods -o jsonpath='{.items[*].spec.containers[*].image}'` — confirm all images use `@sha256:` digest notation. |
| CNTR-K8-000340 | Container must not use host PID namespace — image spec check | Dockerfile and pod spec contain no `hostPID: true`. Admission controller rejects. `kubectl get pods -n <NAMESPACE> -o json | jq '.items[] | select(.spec.hostPID==true)'` returns empty. |
| CNTR-K8-000350 | Container must not use host network namespace — image spec check | Pod template for this image never sets `hostNetwork: true`. Azure Policy built-in `Kubernetes cluster pods should not use host network` enforced and compliant. |
| CNTR-K8-000425 | Container images must be cryptographically verified before deployment | `cosign verify --key azurekms://<KEY_VAULT_URI>/keys/<COSIGN_KEY_NAME> <IMAGE_DIGEST>` exits 0. AKS admission controller (Ratify with Gatekeeper or Kyverno with Cosign verifier) rejects unsigned images. Signing step is non-optional in pipeline — any image in the ACR production repository without a valid Cosign signature indicates a pipeline bypass and must be investigated. |
| [Framework-derived] | ACR public access disabled | `az acr show --name <ACR_NAME> --resource-group <RESOURCE_GROUP> --query 'publicNetworkAccess'` returns `Disabled`. ACR accessible only from AKS subnet via Private Endpoint or service endpoint. |
| [Framework-derived] | ACR private endpoint configured — no public registry access | `az acr private-endpoint-connection list --registry-name <ACR_NAME> --resource-group <RESOURCE_GROUP>` — confirm private endpoint connection present and `Approved`. Private DNS zone `privatelink.azurecr.us` linked to AKS VNet — all ACR traffic flows privately. |
| [Framework-derived] | Container root filesystem is read-only where possible | Pod spec `securityContext.readOnlyRootFilesystem: true`. Writable paths mounted as `emptyDir` volumes only. `kubectl exec <POD> -- touch /test` returns `Permission denied`. |
| [Framework-derived] | Multi-stage Docker build — final image contains no build tooling | Dockerfile uses multi-stage build; final stage copies only compiled output. `docker run <IMAGE> which gcc` returns command not found. |

---

## Section 3 — Node.js Runtime Hardening (Azure Track Reference)

**These items apply identically to the Azure track. Reference `providers/aws/STIG-checklist.md` Section 3 directly — do not duplicate here.**

All Node.js runtime STIG items (APSC-DV-000460, APSC-DV-001380, APSC-DV-001900, APSC-DV-002000, APSC-DV-002200, APSC-DV-002440, APSC-DV-002540, APSC-DV-002560, APSC-DV-002590, APSC-DV-003300, and `[Framework-derived]` items for `npm audit`, dependency pinning, and memory-only storage) apply to the Azure track without modification. The runtime is Node.js regardless of cloud provider — the STIG requirements are identical.

Frank-lane verification must check these items using `providers/aws/STIG-checklist.md` Section 3 as the authoritative list.

---

## Section 4 — PostgreSQL Hardening (Azure Database for PostgreSQL Flexible Server)

> **Citations superseded.** These items cited the PostgreSQL 9 STIG (`PGS9-*`), which reached
> end of life in 2021 and is not redistributed by ComplianceAsCode, so nothing could verify them.
> The requirement text is unchanged and sound; the identifiers are retained in parentheses as
> historical pointers. Refreshing them against a current PostgreSQL STIG needs STIG Viewer access.

Sources: DISA PostgreSQL 9.x Security Technical Implementation Guide V2R4 (PGS9-00-XXXXXX). Items adapted for Azure Database for PostgreSQL Flexible Server (PostgreSQL 14/15/16 compatible). Items labeled `[Framework-derived]` apply Azure-specific deployment constraints with no direct DISA STIG ID.

> **Azure Flexible Server note:** Several PostgreSQL configuration parameters are set via the Azure portal or CLI (`az postgres flexible-server parameter set`) rather than by editing `postgresql.conf` directly. Verification commands below use both `az` CLI and `psql` queries where applicable. The application user `<APP_DB_USER>` is a service account with scoped permissions only — Azure Flexible Server's `azure_pg_admin` built-in role is the nearest equivalent to the PostgreSQL superuser role and must be treated with equivalent restriction.

| STIG ID | Check Description | Pass Criterion |
|---|---|---|
| [Framework-derived] (was PGS9-00-000100) | PostgreSQL must limit the number of concurrent connections | `max_connections` set to defined limit. `az postgres flexible-server parameter show --server-name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --name max_connections` — returns configured value. No single role has unrestricted connection slots; `<APP_DB_USER>` has `CONNECTION LIMIT <N>` set. |
| [Framework-derived] (was PGS9-00-000150) | PostgreSQL must run using a non-privileged OS account | Azure Flexible Server manages the PostgreSQL process — the underlying OS process runs as a non-privileged managed service account. Application connects as `<APP_DB_USER>` which is not the Azure managed admin account. Verify: `<APP_DB_USER>` cannot perform OS-level operations. |
| [Framework-derived] (was PGS9-00-000200) | PostgreSQL must produce audit records | `pgaudit` extension enabled on Flexible Server. `az postgres flexible-server parameter show --server-name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --name pgaudit.log` — confirm non-null log categories (at minimum `DDL`). Audit logs shipped to Log Analytics Workspace. |
| [Framework-derived] (was PGS9-00-000300) | PostgreSQL must generate audit records for privilege escalation events | `log_statement = 'ddl'` captures `GRANT`, `REVOKE`, `ALTER ROLE`. `az postgres flexible-server parameter show --server-name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --name log_statement` — expect `ddl` or `all`. |
| [Framework-derived] (was PGS9-00-000500) | PostgreSQL must use FIPS-validated cryptographic modules for authentication | `ssl = on`. Azure Flexible Server enforces TLS by default. `ssl_min_protocol_version` set to `TLSv1.2`. `ssl_ciphers` restricted to FIPS-approved suites. `az postgres flexible-server show --name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --query 'sslEnforcement'` — expect `Enabled`. |
| [Framework-derived] (was PGS9-00-000600) | PostgreSQL superuser access must be restricted to authorized accounts | Azure Flexible Server's `azure_pg_admin` role is the equivalent of superuser — no application account should have this role. Application connects as `<APP_DB_USER>`. `SELECT rolname FROM pg_roles WHERE rolsuper = true;` returns only the internal postgres system account. Verify `<APP_DB_USER>` is not a member of `azure_pg_admin`. |
| [Framework-derived] (was PGS9-00-000900) | PostgreSQL must log all connection attempts | `log_connections = on`. `az postgres flexible-server parameter show --server-name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --name log_connections` — expect `on`. Application connection errors appear in Log Analytics. |
| [Framework-derived] (was PGS9-00-001000) | PostgreSQL must enforce access restrictions to protect data | `<APP_DB_USER>` granted only `SELECT`, `INSERT`, `UPDATE`, `DELETE` on required tables and views. No `GRANT ALL`. `\dp` in `psql` confirms minimal privileges. Migration role `<MIGRATION_DB_USER>` has DDL rights; app role does not. |
| [Framework-derived] (was PGS9-00-001700) | PostgreSQL must generate audit records for failed logon attempts | `log_connections = on` and `log_line_prefix` includes timestamp and client IP. Failed authentication attempts generate a log entry visible in Log Analytics. Verify by attempting connection with invalid credentials and checking Log Analytics query results. |
| [Framework-derived] (was PGS9-00-002700) | PostgreSQL must use encrypted connections | Azure Flexible Server: `ssl_enforcement_enabled: true` enforced at the Azure resource layer. Application `DATABASE_URL` includes `?sslmode=verify-full`. `az postgres flexible-server show --name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --query 'sslEnforcement'` — expect `Enabled`. |
| [Framework-derived] (was PGS9-00-003100) | PostgreSQL must implement separation of duties through role assignment | Separate roles: `<APP_DB_USER>` for DML only; `<MIGRATION_DB_USER>` for DDL. No single role combines DML and schema-change access at runtime. Migration credentials are not present in the running pod environment variables. |
| [Framework-derived] (was PGS9-00-003800) | PostgreSQL must protect the confidentiality and integrity of transmitted information | `ssl_min_protocol_version = TLSv1.2`. `az postgres flexible-server parameter show --server-name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --name ssl_min_protocol_version` — expect `TLSv1.2`. No `host` (unencrypted) entries for remote connections — Azure Flexible Server requires TLS for all non-local connections. |
| [Framework-derived] (was PGS9-00-004200) | PostgreSQL audit log information must be protected from unauthorized access | Log Analytics Workspace receives Flexible Server audit logs. Workspace has `CanNotDelete` resource lock. Application managed identity does not have `Microsoft.OperationalInsights/workspaces/write` permissions. `az lock list --resource <WORKSPACE_RESOURCE_ID>` — confirm lock present. |
| [Framework-derived] (was PGS9-00-005100) | PostgreSQL must have unnecessary extensions disabled | `SELECT name FROM pg_available_extensions WHERE installed_version IS NOT NULL;` returns only required extensions. `pgaudit` is installed; no `dblink`, `postgres_fdw`, `plpython`, or other unused extensions. `az postgres flexible-server show --name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --query 'storageProfile'` — note installed extensions. |
| [Framework-derived] (was PGS9-00-005300) | PostgreSQL must require authentication for all database connections | Azure Flexible Server does not allow `trust` authentication for remote connections. All connections require `scram-sha-256` (managed by Azure). `az postgres flexible-server show --name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --query 'authConfig'` — confirm AAD and password auth configured; no trust. |
| [Framework-derived] (was PGS9-00-005600) | PostgreSQL must implement cryptographic mechanisms to prevent unauthorized disclosure of data at rest | Azure Flexible Server encrypted at rest with Customer-Managed Key (CMK) from Key Vault. `az postgres flexible-server show --name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --query 'dataEncryption'` — expect `keyType: AzureKeyVault` with Key Vault reference populated. |
| [Framework-derived] | Azure Flexible Server VNet integration — no public network access | `az postgres flexible-server show --name <POSTGRES_SERVER_NAME> --resource-group <RESOURCE_GROUP> --query '{public:network.publicNetworkAccess, delegatedSubnet:network.delegatedSubnetResourceId}'` — confirm `publicNetworkAccess: Disabled` and delegated subnet present. All application connections route through the private VNet. |
| [Framework-derived] | Microsoft Defender for open-source relational databases enabled | `az security pricing show --name OpenSourceRelationalDatabases` — expect `pricingTier: Standard`. Defender for Databases alerts on anomalous access patterns, potential SQL injection, and unusual client activity for the Flexible Server instance. Verify no active Defender alerts in Azure Security Center for this server. |

---

## Applying This Checklist in the Pipeline

Frank-lane pipeline verification steps must reference this checklist by section and STIG ID in pipeline step comments. Example:

```yaml
# STIG ref: CNTR-K8-000310, CNTR-K8-000435 — non-root pod, capabilities dropped (AKS)
- name: verify-pod-security-context
  run: |
    kubectl get pods -n $NAMESPACE -o json \
      | jq '.items[].spec.containers[].securityContext | select(.privileged == true)' \
      | wc -l | grep -q '^0$'
```

For Node.js runtime items, reference `providers/aws/STIG-checklist.md` by section and STIG ID:

```yaml
# STIG ref: APSC-DV-002540 (providers/aws/STIG-checklist.md Section 3) — SQL injection prevention
- name: verify-parameterized-queries
  run: |
    grep -rn "knex\.raw" backend/src/ | grep -v "?" && exit 1 || exit 0
```

For Azure Database for PostgreSQL Flexible Server items, use `az` CLI verification:

```yaml
# STIG ref: [Framework-derived] (was PGS9-00-002700) — encrypted connections required
- name: verify-postgres-ssl-enforcement
  run: |
    az postgres flexible-server show \
      --name $POSTGRES_SERVER_NAME \
      --resource-group $RESOURCE_GROUP \
      --query 'sslEnforcement' -o tsv | grep -q 'Enabled'
```
