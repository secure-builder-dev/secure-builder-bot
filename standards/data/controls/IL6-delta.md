## About This Document

**Purpose:** NIST SP 800-53 High delta controls that activate above the IL4 Moderate baseline when `SECURITY_TIER=IL6` — documents only the *additions and overrides*, not repeated IL4 controls.

**Workflow role:** Sentinel references when running IL6 gate checks; Winston reads when designing IL6-specific architecture; Frank reads before writing IL6 provider implementation files.

**How to fill in:** No customization required — activate by setting `SECURITY_TIER=IL6` at initialization. Add rows only if your ATO requires High-baseline-specific tailoring beyond this delta.

---

# IL6 Control Delta — NIST SP 800-53 Rev 5 High (Above IL4 Moderate Baseline)

**Scope:** Cloud-agnostic. Documents only the DELTA — controls that are added at the High baseline or where High requirements are materially more restrictive than Moderate. Read in conjunction with `IL4-baseline.md`; IL4 Moderate controls remain in force at IL6. This document does not repeat IL4 controls.
**References:** NIST SP 800-53 Rev 5 (2020), DoD CC SRG v1r4, FIPS 199 High, CNSSI 1253, ICD 503.
**Last updated:** 2026-05-01

**Network constraint:** IL6 deployments handle data classified up to SECRET and require a classified network (NSS — National Security System). Deployers must complete an Authority to Operate (ATO) under the Risk Management Framework (RMF) for NSS with DCSA, NSA, or DoD Component oversight as applicable. The framework documents the control requirements; it does not perform or substitute for the RMF process.

For provider-specific IL6 implementation guidance, see `providers/aws/IL6-implementation.md`.

---

## How to Read This Document

Each entry below is one of:

- **New control at High** — exists in the 800-53 High baseline but not the Moderate baseline; must be added.
- **Enhancement required at High** — control exists at Moderate but High requires an additional enhancement (noted with the enhancement number).
- **Requirement escalation** — same control number exists at both levels, but the High parameter is materially more stringent (e.g., shorter timeframe, larger scope, higher assurance level).

---

## AC — Access Control (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| AC-2(3) | Enhancement at High | Disable accounts automatically after defined inactivity period (typically 35 days for NSS). Moderate only requires periodic review. | — (Keycloak inactivity policy; verified at deploy time) |
| AC-2(5) | Enhancement at High | Require logout when inactive for defined period. | — (Keycloak session timeout tightened for IL6) |
| AC-2(11) | Enhancement at High | Enforce usage conditions for access accounts (time-of-day, location, device). | — (Keycloak conditional access rules) |
| AC-2(12) | Enhancement at High | Monitor and report atypical usage of system accounts. | — (SIEM/monitoring; IL6 hosting platform) |
| AC-3(7) | Enhancement at High | Enforce role-based access control. | rbac-scoping-correct (IL6 adds explicit role-to-clearance binding) |
| AC-4(21) | Enhancement at High | Separate information flows logically or physically using defined mechanisms. | — (network segmentation; classified network isolation) |
| AC-6(2) | Enhancement at High | Require privileged users to use non-privileged accounts for non-privileged functions. | — (separate admin and user accounts) |
| AC-6(5) | Enhancement at High | Restrict privileged access to explicitly authorized personnel. | — (access control list; personnel vetting) |
| AC-7(2) | Enhancement at High | Purge or wipe information from mobile devices after defined consecutive failed logon attempts. | — (N/A — mobile use prohibited on classified network) |
| AC-10 | New at High | Limit concurrent sessions per account by type. | — (Keycloak session limit configuration) |
| AC-17(2) | Enhancement at High | Protect remote access sessions using cryptographic mechanisms. | — (TLS 1.2+ mandatory; FIPS 140-3 cipher suites only at IL6) |

---

## AU — Audit and Accountability (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| AU-3(2) (withdrawn in Rev 5, incorporated into PL-9) | Enhancement at High | Centralize management of audit record content. | — (centralized log aggregation required; application-generated logs routed to tamper-evident store) | <!-- citations: allow -->
| AU-6(1) | Enhancement at High | Employ automated mechanisms to integrate audit review, analysis, and reporting. | — (SIEM integration; IL6 hosting platform) |
| AU-6(3) | Enhancement at High | Correlate audit records from different repositories. | — (centralized logging with correlation ID) |
| AU-6(5) | Enhancement at High | Integrate analysis with vulnerability scanning information. | — (platform SIEM) |
| AU-6(6) | Enhancement at High | Correlate audit records with information from physical access monitoring. | — (IL6 hosting platform) |
| AU-9(2) | Enhancement at High | Store audit records in a system component not accessible by the application process. | audit-logs-tamper-evident-append-only |
| AU-9(3) | Enhancement at High | Implement cryptographic protection for audit information. | — (tamper-evident log store) |
| AU-10 | New at High | Provide non-repudiation protection — bind identity of originator to information; verify on demand. | — (keycloak_id in every audit record; signed tokens) |
| AU-12(1) | Enhancement at High | Compile audit records from multiple system components into a system-wide audit trail. | — (centralized logging; correlation ID) |
| AU-12(3) | Enhancement at High | Allow designated personnel to change the level of auditing based on risk. | — (log level configuration; operational) |
| AU-14 | New at High | Session audit — provide capability to capture, record, and log content of user sessions; review. | — (session activity logging; classified network requirement) |

---

## CA — Assessment, Authorization, and Monitoring (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| CA-2(2) | Enhancement at High | Include as part of control assessments: announced or unannounced in-depth assessments. | — (ATO/RMF NSS process) |
| CA-7(4) | Enhancement at High | Include risk monitoring in continuous monitoring strategy. | — (IL6 platform continuous monitoring) |
| CA-8 | New at High | Penetration testing — conduct adversarial testing at defined frequency. | — (ATO requirement; not application-layer) |
| CA-8(1) | New at High | Employ independent penetration test team. | — (ATO requirement) |

---

## CM — Configuration Management (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| CM-2(7) | Enhancement at High | Issue organization-defined systems, components, or devices with approved configurations to individuals. | — (device control; organizational) |
| CM-3(2) | Enhancement at High | Test, validate, and document changes to system before implementation. | — (pipeline; staging environment gate) |
| CM-3(6) | Enhancement at High | Implement cryptographic mechanisms to detect unauthorized changes to software, firmware, and information. | — (container signing; SBOM; base-image provenance — F-002) |
| CM-5(1) | Enhancement at High | Document system changes; retain records for defined period. | — (git history; pipeline audit logs) |
| CM-5(3) (withdrawn in Rev 5, no replacement named) | Enhancement at High | Prevent installation of software without verification of trust. | — (base-image provenance gate; container signing — F-002) | <!-- citations: allow -->
| CM-7(5) | Enhancement at High | Maintain and enforce allowlist of authorized software. | — (approved-registry allowlist per `docs/security/approved-registries.yaml`; approved dependency list) |
| CM-8(2) | Enhancement at High | Maintain currency, completeness, accuracy, and availability of system component inventory. | — (SBOM — F-002; Helm chart inventory) |
| CM-8(3) | Enhancement at High | Detect unauthorized components using automated mechanisms. | — (base-image provenance gate; Anchore; SBOM) |
| CM-12 | New at High | Information location — identify and document where information is processed and stored. | — (S3 bucket data map; PostgreSQL schema; ATO artifact) |
| CM-14 | New at High | Signed components — prevent installation of unsigned components. | — (container signing; base-image provenance gate — F-002) |

---

## IA — Identification and Authentication (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| IA-2(6) | Enhancement at High | Implement MFA using separate devices. Physical authenticator required for privileged access on classified systems. | — (CAC/PIV required; Keycloak configuration) |
| IA-3(1) | Enhancement at High | Authenticate device connections using bidirectional authentication. | — (mTLS for service-to-service on classified network) |
| IA-5(2) | Enhancement at High | For PKI-based authentication: validate certificates; map identity to account; implement local caching with expiration. | — (JWKS local caching already in place; FIPS 140-3 key management at IL6) |
| IA-5(6) | Enhancement at High | Protect authenticators commensurate with the information they are authorized to access. | — (HSM-backed key storage at IL6) |
| IA-5(8) | Enhancement at High | Implement strategy for managing authenticators when individuals have multiple accounts. | — (organizational/Keycloak) |
| IA-7 | Escalation at High | Cryptographic module authentication: use FIPS 140-3 validated modules only. At Moderate, FIPS 140-2 is acceptable. | fips-140-3-crypto-only |
| IA-8(6) | Enhancement at High | Disassociate user attributes after session completion. | — (stateless JWT; no server-side session) |
| IA-9 | New at High | Service identification and authentication — uniquely identify and authenticate services before connections. | — (service-to-service mTLS; IAM/workload identity) |
| IA-12 | New at High | Identity proofing — require identity proofing at defined assurance levels. | — (personnel clearance; CAC vetting; organizational) |

---

## IR — Incident Response (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| IR-3(2) | Enhancement at High | Coordinate incident response testing with organizational elements responsible for related plans. | — (classified network IR coordination; operational) |
| IR-4(1) | Enhancement at High | Implement automated mechanisms to support incident handling. | — (SIEM automation; IL6 hosting platform) |
| IR-6(1) | Enhancement at High | Report incidents using automated mechanisms. | — (automated incident reporting; platform SOC) |
| IR-9 | New at High | Information spillage response — respond to spillage of classified information. | — (operational; classified incident response procedures required) |
| IR-9(1) (withdrawn in Rev 5, incorporated into IR-9) | New at High | Responsible personnel notified of spillage. | — (operational) | <!-- citations: allow -->
| IR-9(2) | New at High | Training — provide spillage response training. | — (organizational) |
| IR-9(3) | New at High | Post-spill operations — implement procedures to ensure personnel not involved in spillage activities are not impacted. | — (operational) |
| IR-9(4) | New at High | Exposure to unauthorized personnel — employ security safeguards if information is exposed. | — (operational) |

---

## PL — Planning (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| PL-2(3) (withdrawn in Rev 5, incorporated into PL-2) | Enhancement at High | Plan reviews — review and update SSP on defined frequency and upon significant changes. | — (ATO/RMF; operational) | <!-- citations: allow -->

---

## RA — Risk Assessment (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| RA-3(2) | Enhancement at High | Integrate risk assessment results and risk management decisions into organizational operations. | — (ATO/RMF integration) |
| RA-5(1) (withdrawn in Rev 5, incorporated into RA-5) | Enhancement at High | Update vulnerabilities scanned using organization-managed repositories. | — (Anchore; air-gapped NVD mirror on classified network) | <!-- citations: allow -->
| RA-5(4) | Enhancement at High | Determine what information about the system is discoverable by adversaries; take corrective action. | — (adversarial assessment; pen test — CA-8) |
| RA-5(5) | Enhancement at High | Implement privileged access for vulnerability scanning. | — (scanner access control; platform) |
| RA-10 | New at High | Threat hunting — proactively search for indicators of compromise and adversarial TTPs. | — (platform SOC threat hunting) |

---

## SA — System and Services Acquisition (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| SA-8(19) | Enhancement at High | Implement trusted computing using hardware roots of trust. | — (platform TPM; classified hardware requirement) |
| SA-9(2) | Enhancement at High | Establish restrictions on disclosure of information to external service providers. | — (classified network isolation; no unclassified external calls at runtime) |
| SA-11(2) | Enhancement at High | Perform threat and vulnerability analyses; exploit testing of software. | — (penetration test; adversarial review) |
| SA-11(8) | Enhancement at High | Dynamic code analysis — employ dynamic code analysis tools. | — (DAST in pipeline — `dast:sandbox` baseline job; classified equivalent for IL6) |

---

## SC — System and Communications Protection (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| SC-3(1) | Enhancement at High | Security function isolation — hardware separation. | — (classified hardware; trusted execution environment) |
| SC-5(1) | Enhancement at High | Restrict ability to limit DoS attack effects to address volume-based, protocol, and application-based attacks. | — (WAF; ALB rate limiting; network-layer IL6 protections) |
| SC-7(8) | Enhancement at High | Route all traffic through managed interface (prevent split tunneling). | no-unclassified-external-calls-at-runtime |
| SC-7(18) | Enhancement at High | Fail secure — prevent information from being transmitted during failure. | — (fail-closed circuit breakers; classified network) |
| SC-7(21) | Enhancement at High | Isolation of system components. | — (network segmentation; pod isolation) |
| SC-8(2) | Enhancement at High | Pre/post transmission handling — maintain security level of information. | — (classification banner in API responses) |
| SC-10 | New at High | Network disconnect — terminate connections after defined period of inactivity. | — (ALB idle timeout; classified network session control) |
| SC-13 | Escalation at High | Cryptographic protection escalates: FIPS 140-3 validated modules required (FIPS 140-2 not sufficient at IL6 for NSS). | fips-140-3-crypto-only |
| SC-16 | New at High | Transmission of security attributes — associate security attributes with information exchanged between systems. | classification-banner-header |
| SC-16(1) | New at High | Validate security attributes upon import. | — (CDS integration boundary — see CDS-guidance.md) |
| SC-28(2) | Enhancement at High | Offline storage — remove data from online storage and store offline. | — (operational; backup and recovery procedures) |
| SC-34 | New at High | Non-modifiable executable programs — use non-modifiable firmware/software at load time. | — (read-only container filesystem; immutable image) |
| SC-39(2) | Enhancement at High | Separate processing domains to support isolation. | — (hardware-level separation on classified hardware) |
| SC-45 | New at High | System time synchronization — synchronize internal clocks. | — (NTP from classified network time source) |
| SC-51 | New at High | Hardware-based protection — implement hardware mechanisms for protection. | — (TPM; classified hardware platform) |

---

## SI — System and Information Integrity (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| SI-2(1) (withdrawn in Rev 5, incorporated into PL-9) | Enhancement at High | Centrally manage flaw remediation process. | — (centralized patch management; classified network) | <!-- citations: allow -->
| SI-3(2) (withdrawn in Rev 5, incorporated into SI-3) | Enhancement at High | Automatically update malicious code protection mechanisms. | — (air-gapped AV update process on classified network) | <!-- citations: allow -->
| SI-4(1) | Enhancement at High | Connect and configure system monitoring tools to centralized monitoring infrastructure. | — (SIEM; platform SOC) |
| SI-4(4) | Enhancement at High | Inbound and outbound communications traffic monitoring. | — (DLP; classified network boundary monitoring) |
| SI-4(5) | Enhancement at High | Alert when system attack indicators occur. | — (SIEM alerting; platform SOC) |
| SI-4(11) | Enhancement at High | Analyze communications traffic anomalies. | — (network analytics; classified network) |
| SI-4(20) | Enhancement at High | Privileged user monitoring — implement additional monitoring for privileged accounts. | — (enhanced audit for admin actions) |
| SI-4(22) | Enhancement at High | Unauthorized network services — detect and alert for network services not authorized. | — (network allowlist; classified network boundary) |
| SI-4(25) | Enhancement at High | Optimize network traffic analysis. | — (IL6 hosting platform) |
| SI-6 | New at High | Security and privacy function verification — verify correct operation of security and privacy functions. | — (startup integrity checks; operational testing) |
| SI-7(2) | Enhancement at High | Code authentication — implement cryptographic mechanisms to detect unauthorized changes to software. | — (container signing; SBOM; approved-registry provenance) |
| SI-7(5) | Enhancement at High | Automated response — automatically shut down system when integrity violations detected. | — (fail-closed circuit breakers) |
| SI-7(9) | Enhancement at High | Verify boot process — verify integrity of boot process. | — (secure boot; classified hardware) |
| SI-7(14) (withdrawn in Rev 5, no replacement named) | Enhancement at High | Binary or machine executable code from unknown sources prohibited. | — (base-image provenance gate; allowlisted images only) | <!-- citations: allow -->
| SI-12(1) | Enhancement at High | Limit PII processing and use to authorized purpose. | — (data minimization; keycloak_id only in logs) |
| SI-23 | New at High | Information fragmentation — fragment and distribute information across multiple systems or components. | — (classified data handling; operational) |

---

## SR — Supply Chain Risk Management (High Delta)

| Control ID | Type | High Requirement (Delta from Moderate) | Sentinel IL6 Check |
|---|---|---|---|
| SR-4(3) | Enhancement at High | Penetration testing and analysis of supply chain elements. | — (adversarial supply chain assessment) |
| SR-6(1) | Enhancement at High | Testing and analysis of supply chain elements at every post-reseller tier. | — (base-image provenance across tiers; SBOM attestation) |
| SR-9 | New at High | Tamper resistance and detection — implement tamper protection mechanisms. | — (hardware tamper detection; classified hardware) |
| SR-9(1) | New at High | Multiple stages of system development and production to detect tampering. | — (multi-stage pipeline signing; SBOM attestation) |

---

## IL6-Specific Application-Layer Requirements (Not in 800-53 Families Above)

These requirements derive from ICD 503, CNSSI 1253, and DoD CC SRG v1r4 for NSS/classified systems and apply at the application layer:

| Requirement | Source | Sentinel IL6 Check |
|---|---|---|
| All API responses must include a classification banner header per the applicable classification guide. | ICD 710; CAPCO marking requirements | classification-banner-header |
| No unclassified external calls at runtime — no public npm registries, CDNs, or third-party endpoints reachable from the running application. | DoD CC SRG §5.4; NSS network isolation | no-unclassified-external-calls-at-runtime |
| Personnel clearance level must not be stored in the application database — delegated entirely to the identity provider. | DoD personnel security policy; least-privilege | personnel-clearance-not-in-app-db |
| FIPS 140-3 module list must be verified — all cryptographic operations use NIST-validated modules only. | CNSSP-15; DoD CC SRG crypto requirements | fips-140-3-module-list-verified |
| CDS integration points must be documented and not bypassed (see `CDS-guidance.md`). | NCDSMO; DoD CC SRG §6.6 | cds-integration-boundary-documented |
| Audit logs must be written to a tamper-evident, append-only store not writable by the application process. | ICD 503 §3.6; AU-9(2) | audit-logs-tamper-evident-append-only |
