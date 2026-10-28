## About This Document

**Purpose:** EKS/container/Node.js/PostgreSQL STIG verification checklist for AWS GovCloud and C2S/SC2S deployments (Frank lane).

**Workflow role:** Frank reads and executes before marking deployment-lane stories complete; Sentinel confirms checklist completion at gate.

**How to fill in:** Work through sections 1–4 at first deployment. Replace `<PLACEHOLDER>` values with your cluster's resource names. Section 4 `[Framework-derived]` rows for view and flag mutation patterns must be updated to match your application schema.

---

# AWS / EKS / Container / Node.js / PostgreSQL STIG Checklist

**Lane:** Frank (pipeline STIG verification reference)
**Scope:** AWS GovCloud (`us-gov-east-1`) deployment using EKS, containerized Node.js, and self-hosted PostgreSQL on EKS. Items apply equally to C2S/SC2S IL6 deployments unless noted.
**References:** DISA Kubernetes STIG V1R11; DISA Application Security and Development STIG V5R3; DISA PostgreSQL 9.x STIG V2R4; CIS Amazon EKS Benchmark v1.4.0
**Last updated:** 2026-05-04

> **STIG ID note:** STIG IDs reference DISA STIG content current as of this document date. Verify item applicability and exact IDs against the current DISA STIG Viewer (`public.cyber.mil/stigs/`) before use in formal audit assessments. Items labeled `[Framework-derived]` have no direct DISA STIG ID and derive from DoD CC SRG v1r4, CIS benchmark items, Chainguard/Wolfi platform requirements, or hosting platform constraints.

Quality-gate verification: every item names either a published STIG ID or its derivation source (`[Framework-derived]` with the source reference). No percentage threshold: no platform STIG is published for this track's surface, so the items derive from the SRGs and NIST rather than from a STIG. `make verify-citations` checks every published ID that is cited.

**For Azure-specific items:** F-003 extends this checklist.

## Reference Sources

Use these to verify STIG IDs, look up current STIG content, or check CIS benchmark items.

| Source | What it covers | Where to find it |
|---|---|---|
| DISA STIG Viewer (free JAR) | Load and search all STIG packages below; look up CNTR-K8, APSC-DV, PGS9 IDs | `public.cyber.mil/stigs/srg-stig-tools/` |
| DISA Kubernetes STIG V1R11 | Source for all CNTR-K8-XXXXXX items in Sections 1 and 2 | `public.cyber.mil/stigs/downloads/` → search "Kubernetes" |
| DISA Application Security and Development STIG V5R3 | Source for all APSC-DV-XXXXXX items in Sections 2 and 3 | `public.cyber.mil/stigs/downloads/` → search "Application Security and Development" |
| DISA PostgreSQL 9.x STIG V2R4 | Source for all PGS9-00-XXXXXX items in Section 4 (compatible with PostgreSQL 14/15/16) | `public.cyber.mil/stigs/downloads/` → search "PostgreSQL" |
| CIS Amazon EKS Benchmark v1.4 | Source for `[Framework-derived]` EKS-specific items in Section 1 | `cisecurity.org/benchmark/kubernetes` (free after registration) |
| Chainguard image catalog | Base image CVE status and SBOM; confirms which images are hardened against Section 2 items | `cgr.dev/chainguard/` (public); `images.chainguard.dev` for detailed CVE/SBOM reports |
| DoD Cloud Computing SRG v1r4 §5.7 | Trusted container provenance requirement grounding Section 2 `[Framework-derived]` items | `public.cyber.mil` → search "Cloud Computing SRG" | The Node.js (Section 3) and PostgreSQL (Section 4) sections below apply identically to the Azure track — reference these items rather than duplicating them in `providers/azure/STIG-checklist.md`.

---

## Section 1 — EKS Cluster Hardening

Sources: DISA Kubernetes STIG V1R11 (CNTR-K8-XXXXXX); CIS Amazon EKS Benchmark v1.4.0

| STIG ID | Check Description | Pass Criterion |
|---|---|---|
| CNTR-K8-000010 | Kubernetes API server must have anonymous authentication disabled | `kube-apiserver` started with `--anonymous-auth=false`. `kubectl get --as=system:anonymous pods` returns `Forbidden`. |
| CNTR-K8-000020 | Kubernetes API server must not use basic authentication | No `--basic-auth-file` flag in API server manifest. `aws eks describe-cluster` confirms no basic auth config. |
| CNTR-K8-000030 | Kubernetes API server must not use token file–based authentication | No `--token-auth-file` flag in API server manifest. |
| CNTR-K8-000100 | Kubernetes secrets must not be stored as environment variables | `kubectl get pods -o jsonpath='{..env}'` returns no inline secret values. All secrets injected via `secretKeyRef` from ExternalSecret-created Kubernetes Secrets only. |
| CNTR-K8-000150 | Kubernetes API server must enable audit logging | EKS control plane logging: `api`, `audit`, `authenticator` all enabled. `aws eks describe-cluster --query 'cluster.logging.clusterLogging[?enabled]'` confirms. |
| CNTR-K8-000160 | Kubernetes audit log must have a maximum size configured | `--audit-log-maxsize` set to ≥ 100 (MB). |
| CNTR-K8-000170 | Kubernetes audit log must have a maximum age configured | `--audit-log-maxage` set to ≥ 30 (days). |
| CNTR-K8-000180 | Kubernetes audit log must have a maximum backup count | `--audit-log-maxbackup` set to ≥ 10. |
| CNTR-K8-000200 | Kubernetes API server must use RBAC authorization mode | `--authorization-mode` includes `RBAC`. `kubectl auth can-i --list --as=system:serviceaccount:default:default` returns only expected permissions. |
| CNTR-K8-000250 | Default Kubernetes service account must not be used for API operations | All application pods use a named service account with a scoped IRSA role. `kubectl get pods -o jsonpath='{..serviceAccountName}'` returns no `default` service accounts in application namespaces. |
| CNTR-K8-000270 | Kubernetes API server must have the PodSecurity admission controller enabled | EKS 1.25+: PodSecurity admission enabled; namespace labeled `pod-security.kubernetes.io/enforce: restricted` or `baseline`. |
| CNTR-K8-000290 | Kubernetes API server must have the NodeRestriction admission plugin enabled | `--enable-admission-plugins` includes `NodeRestriction`. EKS managed control plane enables by default. |
| CNTR-K8-000310 | Kubernetes pods must not run as root | Pod security context: `runAsNonRoot: true`, `runAsUser: <NON_ROOT_UID>`. `securityContext.allowPrivilegeEscalation: false` on all containers. |
| CNTR-K8-000330 | Kubernetes must not allow privileged containers | No pod spec has `privileged: true`. PodSecurity admission blocks privileged containers. `kubectl create pod test --image=<IMAGE> --privileged` is rejected. |
| CNTR-K8-000340 | Containers must not share the host process ID namespace | Pod spec does not contain `hostPID: true`. Verify: `kubectl get pods -A -o json | jq '.items[] | select(.spec.hostPID==true)'` returns empty. |
| CNTR-K8-000350 | Containers must not share the host network namespace | Pod spec does not contain `hostNetwork: true`. Verify: `kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true)'` returns empty in application namespaces. |
| CNTR-K8-000360 | Containers must not share the host IPC namespace | Pod spec does not contain `hostIPC: true`. Verify: `kubectl get pods -A -o json | jq '.items[] | select(.spec.hostIPC==true)'` returns empty. |
| CNTR-K8-000380 | Kubernetes kubelet must not allow anonymous authentication | EKS node group kubelet configured with `--anonymous-auth=false`. |
| CNTR-K8-000400 | Kubernetes API server must have the AlwaysPullImages admission plugin enabled | `--enable-admission-plugins` includes `AlwaysPullImages`. Prevents cached, potentially modified images from running. |
| CNTR-K8-000435 | Containers must drop all Linux capabilities not explicitly required | Pod spec `securityContext.capabilities.drop: ["ALL"]`. Required capabilities added back individually. No `NET_ADMIN`, `SYS_ADMIN`, or `SYS_PTRACE` unless justified and documented. |
| CNTR-K8-000440 | Kubernetes must have network policies defined for all application namespaces | `kubectl get networkpolicy -A` — all application namespaces have at least a default-deny egress and ingress policy. Namespaces without a network policy produce a pipeline check failure. |
| [Framework-derived] | EKS nodes use IMDSv2 only | EC2 launch template for node group sets `HttpTokens: required` (IMDSv2). `curl http://169.254.169.254/latest/meta-data/ --max-time 2` from a pod returns `401` (requires token). |
| [Framework-derived] | EKS node groups do not use over-privileged IAM roles | Node group instance profile scoped to `AmazonEKSWorkerNodePolicy`, `AmazonEC2ContainerRegistryReadOnly`, `AmazonEKS_CNI_Policy`. No `AdministratorAccess` or `PowerUserAccess`. |
| [Framework-derived] | RBAC — no wildcard resource permissions in application service account roles | `kubectl get clusterrolebindings,rolebindings -A -o yaml | grep '"*"'` returns no results in application namespaces. |
| [Framework-derived] | EKS API server endpoint is private | `aws eks describe-cluster --query 'cluster.resourcesVpcConfig.endpointPublicAccess'` returns `false`. |

---

## Section 2 — Container Image Hardening

Sources: DISA Application Security and Development STIG V5R3 (APSC-DV-XXXXXX); DISA Kubernetes STIG V1R11 (CNTR-K8-XXXXXX); ADR-034 approved registry policy (Chainguard primary, supersedes ADR-021)

| STIG ID | Check Description | Pass Criterion |
|---|---|---|
| APSC-DV-000100 | Application must not use packages with unresolved critical CVEs | `npm audit --audit-level=critical` exits 0. Anchore policy gate: CRITICAL findings are blocking. ECR enhanced scanning: no CRITICAL findings on deployed image. |
| APSC-DV-001120 | Application must separate privileged and non-privileged functionality — container must not run as root | Container user is non-root (`USER <NON_ROOT_UID>` in Dockerfile). Pod spec `securityContext.runAsNonRoot: true`. `kubectl exec <POD> -- id` returns `uid=<NON_ROOT_UID>` (not uid=0). |
| APSC-DV-001160 | Application must use a DoD-approved CA for TLS | Container trusts only `<INTERNAL_CA>` (ACM Private CA in GovCloud) or the platform-approved CA bundle. No public CAs not on the approved list. |
| APSC-DV-001740 | Application must have vulnerability scanning performed | Anchore Enterprise (or Anchore CLI) scans every image pushed to ECR. Pipeline blocks push if scan fails. `aws ecr describe-image-scan-findings` — `findingSeverityCounts.CRITICAL` = 0. |
| APSC-DV-002240 | Application must not contain SUID or SGID binaries | `find / -perm /6000 -type f` in the container returns no results or only expected system binaries. Chainguard Wolfi images strip SUID bits by default as part of the distroless/minimal build philosophy. |
| APSC-DV-002440 | Application must not expose administrative interfaces in production | No debug endpoints (`/debug`, Node.js inspector port 9229) exposed. `kubectl get svc -n <NAMESPACE>` — no service exposes port 9229. |
| APSC-DV-002460 | Application error messages must not reveal sensitive information | Error responses contain no stack traces, file paths, DB messages, or S3 keys. Verified during Sentinel gate check. |
| CNTR-K8-000190 | Container image versions must use immutable references | Images deployed using digest references (`<IMAGE>@sha256:<DIGEST>`) — not mutable tags (`:latest` or equivalent). Kyverno or OPA Gatekeeper policy rejects mutable-tag deployments. |
| CNTR-K8-000340 | Container must not use host PID namespace (image spec check) | Dockerfile and pod spec contain no `hostPID: true`. Confirmed at image review and admission control. |
| CNTR-K8-000350 | Container must not use host network namespace (image spec check) | Pod template for this image never sets `hostNetwork: true`. Admission controller rejects. |
| CNTR-K8-000425 | Container images must be cryptographically verified before deployment | `cosign verify --key <COSIGN_PUBLIC_KEY_REF> <IMAGE_DIGEST>` exits 0. EKS admission controller (Connaisseur or Kyverno) rejects unsigned images at deploy time. |
| [Framework-derived] | Base image sourced from an approved registry | `FROM` instruction references a registry listed in `docs/security/approved-registries.yaml`. Chainguard (`cgr.dev`) is the primary base image source per ADR-034 (supersedes ADR-021); Any other registry on the approved list is a documented fallback only. Pipeline provenance gate validates the registry against the approved list, not a single hardcoded prefix. |
| [Framework-derived] | Container root filesystem is read-only where possible | Pod spec `securityContext.readOnlyRootFilesystem: true`. Writable paths mounted as `emptyDir` volumes only. `kubectl exec <POD> -- touch /test` returns `Permission denied`. |
| [Framework-derived] | Multi-stage Docker build — final image contains no build tooling | Dockerfile uses multi-stage build; final stage copies only compiled output. `docker run <IMAGE> which gcc` returns command not found. |
| [Framework-derived] | Container image signed before push to ECR — no pipeline bypass | Signing step is non-optional in pipeline. Any image reaching the ECR production repository without a valid Cosign signature indicates a pipeline bypass and must be investigated. |

---

## Section 3 — Node.js Runtime Hardening

Sources: DISA Application Security and Development STIG V5R3; OWASP Node.js Security Cheat Sheet; IL4 platform application requirements. No DISA STIG targets Node.js specifically — items reference the closest applicable APSC-DV control or are labeled `[Framework-derived]`.

| STIG ID | Check Description | Pass Criterion |
|---|---|---|
| APSC-DV-000460 | Application must enforce approved authorizations for logical access | Express auth middleware registered before all route handlers. Every request passes through auth check before any route handler. `grep -n "authMiddleware\|requireAuth" backend/src/app.ts` confirms global middleware registration. |
| APSC-DV-001380 | Application must generate error messages that provide required information for investigation | Error responses include an error code or correlation ID sufficient for log lookup without exposing sensitive server details. `request_id` included in 4xx/5xx responses for correlation. |
| APSC-DV-001900 | Application must validate all inputs | All request bodies validated with `zod` schema or `express-validator` before processing. `PUT`/`POST`/`PATCH` endpoints return 400 for invalid input. |
| APSC-DV-002000 | Application must implement DoD-approved encryption for data in transit | All outbound connections use TLS 1.2+. AWS SDK configured with `useFipsEndpoint: true`. No `http://` scheme for any external connection. |
| APSC-DV-002200 | Application must protect audit record content from unauthorized disclosure | Winston log format does not include request bodies, response bodies, `Authorization` headers, passwords, or raw SQL parameters. Verified by log sampling in staging. |
| APSC-DV-002440 | Application must not include debug or test features in production | `NODE_ENV=production` in container environment. Node.js inspector port not in pod spec. `app.set('env', 'production')` disables Express stack traces. |
| APSC-DV-002540 | Application must prevent SQL injection | All database queries use Knex parameterized query builder. `grep -rn "knex\.raw" backend/src/` — any occurrences use `?` binding syntax only; no string interpolation of user input. |
| APSC-DV-002560 | Application must protect against Cross-Site Request Forgery | PKCE OAuth2 flow provides CSRF protection for auth endpoints. All state-mutating API endpoints require `Authorization: Bearer <token>` — no cookie-based session. |
| APSC-DV-002590 | Application must implement required security headers | Helmet middleware configured with: `contentSecurityPolicy`, `hsts`, `noSniff`, `frameguard`, `xssFilter`. `curl -I https://<APP_ENDPOINT>/api/health` confirms `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options` present. |
| APSC-DV-003300 | Application must protect against denial-of-service attacks | `express-rate-limit` configured with per-IP limit for unauthenticated endpoints and per-user limit for authenticated endpoints. ALB WAF rules configured for additional volume protection. |
| [Framework-derived] | No `npm audit` critical or high findings at deploy time | `npm audit --audit-level=high` exits 0 in pipeline. Blocking gate — deploy fails if exit code non-zero. |
| [Framework-derived] | Dependency versions pinned in `package.json` | No `*` or `latest` version specifiers. `package-lock.json` committed and matches `package.json`. `grep -E '"\*"|"latest"' package.json` returns no results. |
| [Framework-derived] | Memory storage only — no disk writes on backend pods | Multer configured `storage: multer.memoryStorage()`. No `fs.writeFile` or `fs.createWriteStream` in production code. `grep -rn "writeFile\|createWriteStream" backend/src/` returns no results. |

---

## Section 4 — PostgreSQL Hardening (Self-Hosted on EKS)

> **Citations superseded.** These items cited the PostgreSQL 9 STIG (`PGS9-*`), which reached
> end of life in 2021 and is not redistributed by ComplianceAsCode, so nothing could verify them.
> The requirement text is unchanged and sound; the identifiers are retained in parentheses as
> historical pointers. Refreshing them against a current PostgreSQL STIG needs STIG Viewer access.

Sources: DISA PostgreSQL 9.x Security Technical Implementation Guide V2R4 (PGS9-00-XXXXXX). PostgreSQL 14/15/16 STIG items are substantially compatible. Items labeled `[Framework-derived]` apply PostgreSQL STIG intent to newer versions or EKS-specific deployment patterns.

| STIG ID | Check Description | Pass Criterion |
|---|---|---|
| [Framework-derived] (was PGS9-00-000100) | PostgreSQL must limit the number of concurrent connections | `max_connections` set to defined limit. No single role has unrestricted connection slots. `SHOW max_connections;` returns configured value. |
| [Framework-derived] (was PGS9-00-000150) | PostgreSQL must run using a non-privileged OS account | PostgreSQL process runs as `postgres` OS user (uid ≠ 0). Pod spec `runAsUser: 999` (or appropriate non-root UID). `ps aux | grep postgres` confirms non-root UID. |
| [Framework-derived] (was PGS9-00-000200) | PostgreSQL must produce audit records | `log_connections = on`, `log_disconnections = on`, `log_duration = on`, `log_statement = 'ddl'` (at minimum). `SHOW log_connections;` returns `on`. |
| [Framework-derived] (was PGS9-00-000300) | PostgreSQL must generate audit records for privilege escalation events | `log_statement = 'ddl'` captures `GRANT`, `REVOKE`, `ALTER ROLE`. Confirmed in `postgresql.conf`. |
| [Framework-derived] (was PGS9-00-000500) | PostgreSQL must use FIPS-validated cryptographic modules for authentication | `ssl = on`. TLS certificate from `<INTERNAL_CA>`. `ssl_ciphers` restricted to FIPS-approved ciphers only (no RC4, DES, 3DES, EXPORT). `SELECT ssl_cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();` returns approved cipher. |
| [Framework-derived] (was PGS9-00-000600) | PostgreSQL superuser access must be restricted to authorized OS accounts | `SELECT rolname FROM pg_roles WHERE rolsuper = true;` returns only `postgres` (system account). Application connects as `<APP_DB_USER>` with no `SUPERUSER`, `CREATEROLE`, or `CREATEDB`. |
| [Framework-derived] (was PGS9-00-000900) | PostgreSQL must log all connection attempts | `log_connections = on`. Application connection errors appear in PostgreSQL log. |
| [Framework-derived] (was PGS9-00-001000) | PostgreSQL must enforce access restrictions to protect data | Application user `<APP_DB_USER>` granted only `SELECT`, `INSERT`, `UPDATE`, `DELETE` on required tables and views. No `GRANT ALL`. `\dp` confirms minimal privileges. |
| [Framework-derived] (was PGS9-00-001700) | PostgreSQL must generate audit records for failed logon attempts | `log_connections = on` and `log_line_prefix` includes timestamp and IP. Failed authentication attempts generate a log entry. Verify by attempting connection with invalid credentials and checking log. |
| [Framework-derived] (was PGS9-00-002700) | PostgreSQL must use encrypted connections | `ssl = on`, `ssl_cert_file` and `ssl_key_file` configured. `pg_hba.conf` requires `hostssl` for all non-local connections. Application `DATABASE_URL` includes `?sslmode=verify-full`. |
| [Framework-derived] (was PGS9-00-003100) | PostgreSQL must implement separation of duties through role assignment | Separate roles: application role (`<APP_DB_USER>`) for DML only; migration role (`<MIGRATION_DB_USER>`) for DDL. No single role combines DML and schema-change access at runtime. |
| [Framework-derived] (was PGS9-00-003800) | PostgreSQL must protect the confidentiality and integrity of transmitted information | `ssl = on` with `ssl_min_protocol_version = 'TLSv1.2'`. `pg_hba.conf` contains no `host` (unencrypted) entries for remote connections. |
| [Framework-derived] (was PGS9-00-004200) | PostgreSQL audit log information must be protected from unauthorized access | CloudWatch Log Group for PostgreSQL logs has resource-based policy denying deletion to the application IRSA role. Only `<SECURITY_OPS_ROLE_ARN>` may delete or modify log retention settings. |
| [Framework-derived] (was PGS9-00-005100) | PostgreSQL must have unnecessary extensions disabled | `SELECT name FROM pg_available_extensions WHERE installed_version IS NOT NULL;` returns only required extensions. No `dblink`, `postgres_fdw`, `plpython`, or other unused extension installed. |
| [Framework-derived] (was PGS9-00-005300) | PostgreSQL must require authentication for all database connections | `pg_hba.conf` contains no `trust` method for remote connections. All remote connections use `scram-sha-256` authentication. Local `postgres` system user uses `peer`. |
| [Framework-derived] (was PGS9-00-005600) | PostgreSQL must implement cryptographic mechanisms to prevent unauthorized disclosure of data at rest | EBS volume for PostgreSQL pod encrypted with `<NODE_EBS_KMS_KEY_ARN>`. `pg_crypto` extension used for any application-layer encryption of sensitive fields, if applicable. |
| [Framework-derived] | Application reads from a protected database view, not base tables directly — view enforces soft-delete and any archive filter the schema defines | `grep -rn "FROM <BASE_TABLE_NAME>\b" backend/src/` returns no results. All active-record queries use the view, which enforces `deleted_at IS NULL AND archived_at IS NULL`. |
| [Framework-derived] | `SELECT FOR UPDATE` used for state-mutation transactions (record the pattern in the project's ADR-LOG) | Concurrent state-mutation race condition prevented — each flag mutation is wrapped in a `BEGIN` / `SELECT ... FOR UPDATE` / `UPDATE` / `COMMIT` transaction. `grep -rn "SELECT FOR UPDATE" backend/src/` confirms presence in mutation handlers. |
| [Framework-derived] | Database migration role is separate from application runtime role and revoked after migration | `<MIGRATION_DB_USER>` holds DDL rights. `<APP_DB_USER>` does not have `CREATE TABLE`, `ALTER TABLE`, or `DROP TABLE`. Migration credentials are not present in running pod environment variables. |

---

## Applying This Checklist in the Pipeline

Frank-lane pipeline verification steps must reference this checklist by section and STIG ID in pipeline step comments. Example:

```yaml
# STIG ref: CNTR-K8-000310, CNTR-K8-000435 — non-root pod, capabilities dropped
- name: verify-pod-security-context
  run: |
    kubectl get pods -n $NAMESPACE -o json \
      | jq '.items[].spec.containers[].securityContext | select(.privileged == true)' \
      | wc -l | grep -q '^0$'
```

**F-003 extension note:** When extending this checklist for Azure in `providers/azure/STIG-checklist.md`, Node.js (Section 3) and PostgreSQL (Section 4) items apply identically — reference them here rather than duplicating. Azure STIG checklist covers AKS cluster hardening (Section 1 equivalent) and ACR image security (Section 2 equivalent) only.
