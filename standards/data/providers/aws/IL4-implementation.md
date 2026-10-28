## About This Document

**Purpose:** Maps each IL4 control baseline item to its AWS GovCloud (`us-gov-east-1`) implementation — identifies which AWS service satisfies each control and how to verify it.

**Workflow role:** Frank reads before implementing the AWS GovCloud deployment; Sentinel references when running IL4 gate checks; Winston reads when designing AWS architecture.

**How to fill in:** Replace all `<PLACEHOLDER>` values (cluster name, namespace, IAM role names, S3 bucket, KMS key ARNs) with your project's actual resource names. Never commit real ARNs — store in team-managed secrets.

---

# AWS GovCloud IL4 Implementation Guide

**Deployment target:** AWS GovCloud (`us-gov-east-1`)
**Impact level:** IL4 — data up to CUI, FIPS 199 Moderate
**Control baseline:** `standards/data/controls/IL4-baseline.md` (cloud-agnostic source)
**Last updated:** 2026-05-04

This document maps each IL4 control from the cloud-agnostic baseline to its AWS GovCloud implementation. Each entry identifies the AWS service or configuration that satisfies the control and includes a "how to verify" step. Controls addressed entirely at the organizational or hosting platform ATO level are noted as inherited.

**Prerequisite services assumed deployed:**
- AWS Secrets Manager (GovCloud region)
- External Secrets Operator (ESO) installed in cluster with ExternalSecret CRD
- Registry pull credentials in Secrets Manager only if a fallback registry needs them; Chainguard is public and needs none (ADR-034, supersedes ADR-021)
- EKS cluster in `us-gov-east-1` with IRSA enabled
- Amazon ECR (GovCloud) for application image hosting
- Amazon S3 GovCloud with default SSE-KMS enabled
- AWS ALB Ingress Controller with TLS termination
- Anchore Enterprise or Anchore CLI in pipeline

---

## Reference Sources

Use these to cross-reference control mappings, verify STIG IDs, or look up AWS service configuration options.

| Source | What it covers | Where to find it |
|---|---|---|
| NIST SP 800-53 Rev 5 | Authoritative control catalog — AC, AU, CM, IA, SC, SI, SR families used throughout this doc | `csrc.nist.gov/pubs/sp/800/53/r5/upd1/final` (PDF + spreadsheet) |
| DoD Cloud Computing SRG v1r4 | IL4/IL5/IL6 definitions; AWS GovCloud authorization at IL4; C2S/SC2S at IL6; Appendix A lists authorized cloud offerings | `public.cyber.mil` → search "Cloud Computing SRG" |
| AWS GovCloud Developer Guide | GovCloud region (`us-gov-east-1`) service availability and compliance scope | `docs.aws.amazon.com/govcloud-us/latest/UserGuide/` |
| AWS Secrets Manager docs | ExternalSecret CRD patterns, rotation config, cross-account access | `docs.aws.amazon.com/secretsmanager/latest/userguide/` |
| AWS EKS Best Practices Guide | IRSA setup, pod security, network policy, node IAM roles | `aws.github.io/aws-eks-best-practices/` |
| AWS IAM Reference | IRSA trust policy structure, resource-scoped policy patterns | `docs.aws.amazon.com/IAM/latest/UserGuide/` |
| Amazon EKS FIPS endpoints | `useFipsEndpoint: true` SDK config; FIPS-validated service endpoints in GovCloud | `docs.aws.amazon.com/sdkref/latest/guide/feature-endpoints.html` |
| ALB FIPS TLS policy reference | `ELBSecurityPolicy-FIPS-TLS-1-2-Ext-2023-05` cipher suite list | `docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html` |
| AWS KMS GovCloud key management | Customer-managed key rotation, key policies, GovCloud KMS availability | `docs.aws.amazon.com/kms/latest/developerguide/` |
| DISA STIG Viewer + STIG packages | Verify CNTR-K8, APSC-DV, PGS9 STIG IDs used in `STIG-checklist.md` | `public.cyber.mil/stigs/downloads/` |
| CIS Amazon EKS Benchmark v1.4 | CIS-derived items in STIG checklist Section 1 labeled `[Framework-derived]` | `cisecurity.org/benchmark/kubernetes` (free after registration) |
| Chainguard image catalog (primary) | Pre-hardened base images, per-image CVE status and SBOM | `cgr.dev/chainguard/` (public); `images.chainguard.dev` for CVE/SBOM detail |
| FedRAMP Marketplace — AWS GovCloud | FedRAMP High P-ATO documentation; inherited controls list | `marketplace.fedramp.gov` → search "AWS GovCloud" |

---

## AC — Access Control

| Control ID | Control Name | AWS Service / Configuration | How to Verify |
|---|---|---|---|
| AC-2 | Account Management | IAM roles scoped per service; Keycloak manages application user lifecycle. EKS node IAM roles use IRSA — no shared EC2 instance profiles. | `aws iam list-roles --path-prefix /eks/` returns only expected service roles. Keycloak admin UI confirms no orphaned accounts. |
| AC-2(1) | Automated Account Management | Keycloak event hooks deactivate accounts on the organizational IdP termination signal. IAM access key rotation enforced via IAM password/key policy. | Verify Keycloak user sync job logs. `aws iam generate-credential-report` — confirm no keys older than 90 days. |
| AC-3 | Access Enforcement | Keycloak RBAC (`admin`/`editor`/`user`) enforced in Express middleware before route handlers. EKS RBAC (`ClusterRole`/`RoleBinding`) restricts pod-to-pod access. ALB target group forwards only to the application namespace. | Run `curl -s <internal-endpoint>` without `Authorization` header — expect HTTP 401. Verify `kubectl get rolebindings -A` contains only expected service accounts. |
| AC-6 | Least Privilege | IRSA IAM role policy scoped to specific S3 bucket ARN and KMS key ARN only. No `*` resource in any application IAM policy. EKS service account bound to IRSA role via annotation. | `aws iam get-role-policy --role-name <APP_IRSA_ROLE>` — confirm no wildcard resource. `kubectl describe serviceaccount <APP_NAME>-backend -n <NAMESPACE>` — confirm IRSA annotation present. |
| AC-6(1) | Authorize Security Functions | Admin-only Keycloak roles required for user management endpoints. IAM policy for ECR push restricted to pipeline IAM role only. | Attempt user-management API call with `editor` token — expect HTTP 403. Confirm only `<PIPELINE_ROLE_ARN>` has `ecr:PutImage` in IAM policy. |
| AC-12 | Session Termination | Stateless JWT tokens; no server-side session. Token expiry enforced in Express middleware via `jose` JWKS validation. Keycloak token TTL configured at `<TOKEN_TTL_SECONDS>`. | Replay an expired token — expect HTTP 401. Confirm no session tables in PostgreSQL schema. |
| AC-17 | Remote Access | EKS API endpoint is private (`endpointPublicAccess: false`). Kubectl access requires bastion with CAC authentication or AWS SSO with MFA. | `aws eks describe-cluster --name <CLUSTER_NAME> --query 'cluster.resourcesVpcConfig.endpointPublicAccess'` — expect `false`. |

---

## AU — Audit and Accountability

| Control ID | Control Name | AWS Service / Configuration | How to Verify |
|---|---|---|---|
| AU-2 | Event Logging | EKS control plane audit logs enabled (API server, authenticator, scheduler). Winston middleware logs all HTTP requests with method, path, status, response time, and `keycloak_id`. CloudTrail enabled in `us-gov-east-1` for AWS API calls. | `aws eks describe-cluster --name <CLUSTER_NAME> --query 'cluster.logging'` — confirm `api`, `audit`, `authenticator` enabled. CloudTrail console confirms trail active in GovCloud region. |
| AU-3 | Content of Audit Records | Winston log format: `{ timestamp, method, path, status, duration_ms, keycloak_id, request_id }`. No PII, no full request bodies, no response bodies in logs. | Trigger a request; verify log entry in CloudWatch Logs — confirm no PII fields. |
| AU-4 | Audit Log Storage Capacity | CloudWatch Log Group retention set to 365 days minimum. Log Group storage quota monitored via CloudWatch alarm. | `aws logs describe-log-groups --log-group-name-prefix /aws/eks/<CLUSTER_NAME>` — confirm retention policy ≥ 365. |
| AU-9 | Protection of Audit Information | CloudWatch Log Group has resource-based policy denying log deletion to application IAM role. Only designated security-ops role can delete log streams. | `aws logs describe-resource-policies` — confirm application role lacks `logs:DeleteLogStream`. |
| AU-9(4) | Access by Subset of Privileged Users | CloudWatch Logs access restricted to `<SECURITY_OPS_ROLE_ARN>` for management actions. | Confirm application IRSA role policy does not include `logs:DeleteLog*` or `logs:PutRetentionPolicy`. |
| AU-11 | Audit Record Retention | CloudWatch Log Group retention: 365 days (1 year). EKS audit log S3 export configured for archival at `<AUDIT_ARCHIVE_BUCKET>/<CLUSTER_NAME>/`. | `aws logs describe-log-groups` — confirm `retentionInDays: 365`. S3 bucket lifecycle policy confirms objects retained minimum 365 days. |
| AU-12 | Audit Record Generation | Winston middleware registered as first Express middleware before route handlers. All requests generate an audit record regardless of outcome. | Deploy a request that triggers a 404 — confirm log entry exists. Verify middleware order in `app.ts`. |

---

## CM — Configuration Management

| Control ID | Control Name | AWS Service / Configuration | How to Verify |
|---|---|---|---|
| CM-2 | Baseline Configuration | Helm chart defines the complete EKS baseline. All pod specs pinned to digest-tagged images from an approved registry (Chainguard primary per ADR-034, which supersedes ADR-021; other approved registries as fallback). HelmRelease in Flux/ArgoCD tracks the chart version. | `helm history <RELEASE_NAME>` — confirm version pinned. `kubectl get pods -o jsonpath='{.items[*].spec.containers[*].image}'` — confirm digest-tagged images. `grep FROM Dockerfile` — confirm registry is on the approved list in `docs/security/approved-registries.yaml`. |
| CM-3 | Configuration Change Control | All Helm chart changes require PR + Sentinel gate review. Direct `kubectl apply` to production namespace blocked by OPA/Gatekeeper admission policy. | Attempt `kubectl apply` without PR — confirm admission webhook rejects. `git log docs/architecture/` confirms ADR audit trail. |
| CM-6 | Configuration Settings | All application secrets injected via ExternalSecret CRD pulling from AWS Secrets Manager. No secrets in Helm values files — only `secretKeyRef` references to the ExternalSecret-created Kubernetes Secret. Sample ExternalSecret: `spec.dataFrom.extract.key: <APP_NAME>/<ENV>/app-secrets`. | `kubectl get externalsecrets -n <NAMESPACE>` — confirm sync status `SecretSynced`. `kubectl get secret <APP_NAME>-app-secrets -o yaml` — confirm no plaintext secrets in Helm values. |
| CM-7 | Least Functionality | EKS nodes use minimal Amazon Linux 2 optimized AMI. No SSH daemon on nodes — Systems Manager Session Manager used for break-glass access only. Node security group allows only ALB → pod traffic on port 3000. | `aws ec2 describe-security-groups --group-ids <NODE_SG_ID>` — confirm no port 22 ingress rule. `aws ssm describe-instance-information` confirms SSM agent registered. |
| CM-8 | System Component Inventory | SBOM generated per build (CycloneDX format) stored as ECR image artifact annotation. ECR image scanning enabled — scan on push. | `aws ecr describe-image-scan-findings --repository-name <REPO_NAME> --image-id imageTag=<TAG>` — confirm scan findings present. Verify SBOM artifact in pipeline artifacts store. |

---

## IA — Identification and Authentication

| Control ID | Control Name | AWS Service / Configuration | How to Verify |
|---|---|---|---|
| IA-2 | Identification and Authentication | Keycloak federated to the organizational CAC/PIV IdP. All application users authenticated via Keycloak PKCE OAuth2 flow. EKS cluster authentication via AWS IAM + `aws-auth` ConfigMap — no local kubeconfig credentials. | `kubectl get configmap aws-auth -n kube-system` — confirm only expected IAM roles and users. Attempt login without CAC — confirm Keycloak rejects. |
| IA-2(1), IA-2(2) | MFA for Privileged and Non-Privileged Accounts | Keycloak enforces MFA (CAC) for all users. AWS SSO enforces MFA for IAM console access. | Keycloak admin console → Authentication → Required Actions confirms CONFIGURE_TOTP or CAC required. |
| IA-5 | Authenticator Management | Secrets Manager stores all application credentials (DB password, signing keys, approved registry pull secret). ExternalSecret CRD rotates secrets on 24-hour resync. No secrets in environment variable definitions or config maps. | `aws secretsmanager list-secrets --filter Key=name,Values=<APP_NAME>/` — confirm all app secrets present. `kubectl get configmap -n <NAMESPACE> -o yaml` — confirm no embedded secret values. |
| IA-7 | Cryptographic Module Authentication | AWS GovCloud endpoints use FIPS 140-2 validated modules. AWS SDK configured with `useFipsEndpoint: true`. All TLS connections use FIPS-compliant cipher suites at ALB (policy `ELBSecurityPolicy-FIPS-TLS-1-2-Ext-2023-05`). | `aws elbv2 describe-load-balancers` → describe listeners → confirm FIPS security policy on HTTPS listener. Verify `useFipsEndpoint: true` in AWS SDK client initialization. |

---

## MA — Maintenance

| Control ID | Control Name | AWS Service / Configuration | How to Verify |
|---|---|---|---|
| MA-4 | Nonlocal Maintenance | EKS node access via AWS Systems Manager Session Manager only. No SSH key pairs deployed on nodes. Session Manager sessions require IAM role with MFA. Session logs shipped to CloudWatch Logs and S3. | `aws ec2 describe-key-pairs` — confirm no key pairs associated with node launch template. `aws ssm get-document --name SSM-SessionManagerRunShell` — confirm log destination configured. |

---

## MP — Media Protection

| Control ID | Control Name | AWS Service / Configuration | How to Verify |
|---|---|---|---|
| MP-2 | Media Access | S3 GovCloud bucket policy denies access except from IRSA role. Block Public Access enabled on all buckets. Bucket ACLs disabled (`ObjectOwnership: BucketOwnerEnforced`). | `aws s3api get-bucket-policy --bucket <APP_DOCS_BUCKET>` — confirm explicit deny for non-IRSA principals. `aws s3api get-public-access-block --bucket <APP_DOCS_BUCKET>` — confirm all four block settings true. |
| MP-6 | Media Sanitization | S3 object deletion uses server-side deletion (no custom key wiping needed — SSE-KMS key deletion revokes access). RDS volume deletion includes snapshot deletion and key revocation. | Confirm S3 lifecycle policy does not retain deleted objects. RDS deletion protection disabled only via IAM-gated action. |

---

## SC — System and Communications Protection

| Control ID | Control Name | AWS Service / Configuration | How to Verify |
|---|---|---|---|
| SC-7 | Boundary Protection | Single ALB ingress point in public subnet. EKS nodes in private subnets — no direct internet access. NAT Gateway for egress only (image pulls from approved registry during build). Network ACL blocks all non-ALB inbound traffic to node subnets. | `aws ec2 describe-subnets --filters Name=tag:kubernetes.io/role/internal-elb,Values=1` — confirm node subnets are private. Confirm NAT Gateway is the only egress path from node subnets. |
| SC-8(1) | Transmission Cryptographic Protection | ALB HTTPS listener enforces `ELBSecurityPolicy-FIPS-TLS-1-2-Ext-2023-05`. Internal pod-to-pod traffic uses Kubernetes-native TLS (cert-manager + Let's Encrypt GovCloud CA or `<INTERNAL_CA>`). | `aws elbv2 describe-listeners` — confirm HTTPS with FIPS policy. Verify no HTTP-only endpoints in ALB rules. |
| SC-12 | Cryptographic Key Management | S3 SSE-KMS: customer-managed KMS key `<APP_KMS_KEY_ARN>` in `us-gov-east-1`. Key policy restricts usage to IRSA role and `<BACKUP_ROLE_ARN>`. Annual key rotation enabled. | `aws kms describe-key --key-id <APP_KMS_KEY_ID> --query 'KeyMetadata.KeyRotationStatus'` — expect enabled. `aws kms get-key-policy` — confirm no wildcard principals. |
| SC-13 | Cryptographic Protection | AWS GovCloud region uses FIPS 140-2 validated cryptographic modules for all AWS service API calls. Node.js application uses `node:crypto` (OpenSSL FIPS module) in GovCloud. ALB enforces TLS 1.2 minimum. | Confirm Node.js built with `--openssl-fips` or application uses `crypto.getFips()` returning 1. ALB security policy FIPS check above. |
| SC-17 | PKI Certificates | TLS certificates issued by `<INTERNAL_CA_ARN>` via ACM Private CA (GovCloud). Certificate pinning for Keycloak JWKS endpoint. | `aws acm list-certificates --certificate-statuses ISSUED` — confirm active cert for app domain. `kubectl get certificate -n <NAMESPACE>` — confirm cert-manager issued cert. |
| SC-28 | Protection of Information at Rest | S3 objects encrypted with SSE-KMS (`aws:kms`) using customer-managed key. RDS PostgreSQL encrypted at rest with `<RDS_KMS_KEY_ARN>`. EBS volumes for EKS nodes encrypted with `<NODE_EBS_KMS_KEY_ARN>`. No temporary disk writes — Multer configured for memory storage only. | `aws s3api get-bucket-encryption --bucket <APP_DOCS_BUCKET>` — confirm SSE-KMS. `aws rds describe-db-instances --query 'DBInstances[*].StorageEncrypted'` — expect true. |

---

## SI — System and Information Integrity

| Control ID | Control Name | AWS Service / Configuration | How to Verify |
|---|---|---|---|
| SI-2 | Flaw Remediation | `npm audit` runs in pipeline as blocking gate step. ECR image scanning (enhanced scanning via Inspector) runs on every push. Critical/high findings block pipeline. | `aws ecr describe-image-scan-findings --repository-name <REPO_NAME>` — confirm findings below critical threshold. Pipeline log confirms `npm audit --audit-level=high` passes. |
| SI-3 | Malicious Code Protection | Base images pulled from an approved registry (Chainguard `cgr.dev` primary per ADR-034, which supersedes ADR-021; other registries are documented fallbacks requiring written justification and platform team sign-off). Anchore Enterprise scans every image in pipeline before push to ECR — zero critical/high findings required regardless of registry source. | Pipeline log confirms Anchore scan passed with zero critical/high findings. `grep FROM Dockerfile` — confirm registry is in `docs/security/approved-registries.yaml`. |
| SI-7 | Software Integrity | Container images signed with Cosign (signing key in Secrets Manager `<APP_NAME>/pipeline/cosign-key`). EKS admission controller (Connaisseur or Kyverno) enforces signature verification before pod scheduling. | `cosign verify --key <PUBLIC_KEY_REF> <IMAGE_DIGEST>` passes. Attempt deploy of unsigned image — confirm admission webhook rejects. |
| SI-7(1) | Integrity Checks | CycloneDX SBOM generated per build; stored as ECR image annotation. Attestation verified by Cosign. | `cosign verify-attestation --type cyclonedx --key <PUBLIC_KEY_REF> <IMAGE_DIGEST>` passes. |
| SI-10 | Information Input Validation | Knex parameterized queries for all SQL — no string interpolation. Express-validator validates all request bodies. `zod` schema validation on API inputs. | Code review: `grep -r "knex.raw" backend/src/` — confirm no raw SQL with user inputs. `grep -r "query\|raw\(" backend/src/` confirms parameterized calls only. |
| SI-11 | Error Handling | Express global error handler returns generic `{ error: "Internal server error" }` with no stack trace, DB message, S3 key, or file path. | Trigger a 500 intentionally; confirm response body contains no stack trace or internal path. |

---

## SR — Supply Chain Risk Management

| Control ID | Control Name | AWS Service / Configuration | How to Verify |
|---|---|---|---|
| SR-3 | Supply Chain Controls | Base images from approved registry (Chainguard primary per ADR-034, supersedes ADR-021; other approved registries as fallback). Anchore scans verify provenance and absence of critical/high CVEs. `npm audit` + `DEPENDENCY_POLICY.md` gates supply chain at application layer. SBOM generated and stored per build. | `grep FROM Dockerfile` — registry in approved list. SBOM artifact present in pipeline artifact store after each build. |
| SR-5 | Acquisition Strategies | All npm packages vetted against `docs/architecture/DEPENDENCY_POLICY.md`. Approved list managed by Sentinel gate. GPL/AGPL licenses blocked. | `npm audit --audit-level=moderate` passes. Review `DEPENDENCY_POLICY.md` approved lists match `package.json`. |
| SR-11 | Component Authenticity | Pipeline verifies base image digest against `docs/security/approved-registries.yaml` before build. Cosign container signing prevents post-build image substitution. | Pipeline log confirms approved-registry digest check passed. `cosign verify` passes for deployed image. |

---

## Inherited Controls

The following control families are inherited from the IL4 hosting platform ATO and require no application-layer implementation. Application teams confirm inheritance in the System Security Plan.

| Family | Inherited From |
|---|---|
| PE — Physical and Environmental Protection | IL4 hosting platform data center controls |
| CP — Contingency Planning (infrastructure layer) | Hosting platform backup and recovery procedures |
| PL — Planning | ATO / organizational policies |
| PS — Personnel Security | Organizational personnel vetting and separation procedures |
| IR — Incident Response (organizational layer) | Platform SOC incident response procedures |
| MA — Maintenance (physical layer) | Hosting platform physical maintenance controls |

---

## Placeholder Reference

The following placeholders appear in this document and must be replaced with actual values at deployment time. Never commit real infrastructure values to this repo.

| Placeholder | Description |
|---|---|
| `<CLUSTER_NAME>` | EKS cluster name |
| `<NAMESPACE>` | Kubernetes namespace for the application |
| `<APP_IRSA_ROLE>` | Name of the IRSA IAM role for the application pod |
| `<PIPELINE_ROLE_ARN>` | ARN of the IAM role used by the CI/CD pipeline |
| `<APP_DOCS_BUCKET>` | S3 bucket name for application document storage |
| `<APP_KMS_KEY_ARN>` | ARN of the customer-managed KMS key for S3 encryption |
| `<APP_KMS_KEY_ID>` | Key ID of the KMS key (short form) |
| `<RDS_KMS_KEY_ARN>` | ARN of the KMS key for RDS encryption |
| `<NODE_EBS_KMS_KEY_ARN>` | ARN of the KMS key for EKS node EBS volume encryption |
| `<NODE_SG_ID>` | Security group ID for EKS worker nodes |
| `<SECURITY_OPS_ROLE_ARN>` | ARN of the security operations IAM role |
| `<BACKUP_ROLE_ARN>` | ARN of the backup/restore IAM role |
| `<INTERNAL_CA_ARN>` | ACM Private CA ARN for internal TLS certificates |
| `<INTERNAL_CA>` | Internal CA name/description |
| `<AUDIT_ARCHIVE_BUCKET>` | S3 bucket for long-term audit log archival |
| `<TOKEN_TTL_SECONDS>` | Keycloak access token TTL (seconds) |
