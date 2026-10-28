## About This Document

**Purpose:** Cloud-agnostic control baseline for IL4 deployments — defines *what* must be controlled at the NIST SP 800-53 Rev 5 Moderate + DoD CC SRG v1r4 level, independent of cloud provider.

**Workflow role:** Winston reads before designing architecture; Sentinel references when auditing gate checks against control IDs; Frank reads before writing provider implementation files.

**How to fill in:** No customization required. Add new rows only if your ATO requires tailored controls beyond the baseline. Provider-specific *how* is in `providers/<provider>/IL4-implementation.md`.

---

# IL4 Control Baseline — NIST SP 800-53 Rev 5 Moderate

**Scope:** Cloud-agnostic. Applies to any deployment targeting IL4 (data up to CUI, FIPS 199 Moderate impact level) regardless of cloud provider.
**References:** NIST SP 800-53 Rev 5 (2020), DoD CC SRG v1r4, FIPS 199, FIPS 200.
**Last updated:** 2026-05-01

This document lists the NIST SP 800-53 Rev 5 Moderate baseline controls most directly applicable to containerized web application deployments. Controls are grouped by family. Where a Sentinel gate check directly implements a control, the check label is noted in the **Sentinel Check** column. Controls with no direct Sentinel check are still required — they are addressed at the infrastructure, operational, or organizational level.

For the mapping of Sentinel checklist items → control IDs, see `CONTROLS-MAPPING.md`. For provider-specific implementation guidance, see `providers/`.

---

## AC — Access Control

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| AC-2 | Account Management | Manage accounts (creation, modification, disabling, removal). Enforce account types; review accounts periodically. | RBAC-correct; last-admin-guard |
| AC-2(1) | Account Management — Automated System Account Management | Automate account management for creation, modification, disabling, removal. | — (Keycloak handles provisioning) |
| AC-3 | Access Enforcement | Enforce approved authorizations for access to system resources per access control policy. | auth-middleware-first; negative-auth-test; rbac-negative-tests; view-reads; state-PATCH-only; no-presigned-urls |
| AC-4 | Information Flow Enforcement | Enforce approved authorizations for controlling information flow between interconnected systems. | rbac-negative-tests |
| AC-5 | Separation of Duties | Separate duties of individuals; document separation; implement access control to enforce separation. | last-admin-guard |
| AC-6 | Least Privilege | Employ least privilege for accounts and processes. | rbac-scoping-correct |
| AC-6(1) | Least Privilege — Authorize Access to Security Functions | Explicitly authorize access to security-relevant functions. | rbac-scoping-correct |
| AC-6(9) | Least Privilege — Log Use of Privileged Functions | Log the use of privileged functions. | — (audit logging) |
| AC-6(10) | Least Privilege — Prohibit Non-Privileged Users from Executing Privileged Functions | Prevent non-privileged users from executing privileged functions. | rbac-scoping-correct |
| AC-7 | Unsuccessful Logon Attempts | Enforce limit on consecutive invalid logon attempts; lock account/node for specified period. | — (Keycloak enforces) |
| AC-8 | System Use Notification | Display system use notification message before granting access. | — (Keycloak login page) |
| AC-11 | Device Lock | Prevent access to the system by initiating a session lock after inactivity. | — (frontend/Keycloak) |
| AC-12 | Session Termination | Automatically terminate session after defined conditions. | no-server-side-token-storage |
| AC-17 | Remote Access | Establish and document usage restrictions and implementation guidance for remote access. | — (VPN/network layer) |
| AC-18 | Wireless Access | Establish usage restrictions and implementation guidance for wireless access. | — (network layer) |
| AC-19 | Access Control for Mobile Devices | Establish usage restrictions for mobile devices. | — (organizational policy) |
| AC-20 | Use of External Systems | Establish terms and conditions for authorized individuals using external systems. | — (organizational policy) |
| AC-22 | Publicly Accessible Content | Designate authorized individuals; train users; review content; remove non-public information. | — (organizational policy) |

---

## AU — Audit and Accountability

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| AU-1 | Policy and Procedures | Develop, document, and disseminate audit and accountability policy. | — (this document) |
| AU-2 | Event Logging | Identify events for logging: logon/logoff, access to security-relevant resources, object access, admin privilege use, failed access attempts. | — (Winston logging middleware) |
| AU-3 | Content of Audit Records | Audit records contain: date/time, event type, subject identity, outcome, source/destination. No PII in logs — method, path, status, response time, keycloak_id only. | no-PII-logging |
| AU-3(1) | Content of Audit Records — Additional Audit Information | Include additional information: session ID, process ID. | — (request correlation ID) |
| AU-4 | Audit Log Storage Capacity | Allocate sufficient storage for audit logs. | — (infrastructure) |
| AU-5 | Response to Audit Logging Process Failures | Alert on audit logging failures; take action (shutdown, overwrite oldest records). | — (infrastructure monitoring) |
| AU-6 | Audit Record Review, Analysis, and Reporting | Review and analyze audit records periodically; report findings. | — (operational) |
| AU-8 | Time Stamps | Use internal clocks for audit record timestamps; record UTC. | — (Node.js/PostgreSQL default) |
| AU-9 | Protection of Audit Information | Protect audit information and tools from unauthorized modification and deletion. | — (infrastructure) |
| AU-9(4) | Protection of Audit Information — Access by Subset of Privileged Users | Authorize access to management of audit logging to explicit subset of privileged users. | — (infrastructure RBAC) |
| AU-11 | Audit Record Retention | Retain audit records for 90 days online, 1 year total. | — (infrastructure/operational) |
| AU-12 | Audit Record Generation | Provide audit record generation at system components; allow designated roles to select which events are audited. | — (Winston logging middleware) |

---

## CA — Assessment, Authorization, and Monitoring

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| CA-1 | Policy and Procedures | Develop, document, and disseminate CA policy. | — |
| CA-2 | Control Assessments | Assess controls periodically; produce assessment reports; provide results to authorizing officials. | negative-auth-test; rbac-negative-tests |
| CA-2(1) | Control Assessments — Independent Assessors | Employ independent assessors for control assessments. | — (ATO process) |
| CA-3 | Information Exchange | Approve and document system interconnections. | — (network/infrastructure) |
| CA-5 | Plan of Action and Milestones | Develop POAM; update based on assessment findings. | — (POAM process per DEPENDENCY_POLICY.md §5.2) |
| CA-6 | Authorization | Assign senior official as authorizing official; authorize system before operations; update authorization. | — (ATO) |
| CA-7 | Continuous Monitoring | Implement continuous monitoring strategy. | — (platform pipeline + Anchore) |
| CA-9 | Internal System Connections | Authorize internal connections; document interfaces. | — (architecture docs) |

---

## CM — Configuration Management

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| CM-1 | Policy and Procedures | Develop, document, and disseminate CM policy. | — |
| CM-2 | Baseline Configuration | Develop, document, and maintain baseline configurations. | — (Helm chart; Dockerfile) |
| CM-2(2) | Baseline Configuration — Automation Support | Maintain baseline configuration using automated mechanisms. | — (pipeline) |
| CM-3 | Configuration Change Control | Document, approve, implement, and document changes to the system. | dependencies-in-policy |
| CM-4 | Impact Analyses | Analyze changes for security impact before implementation. | — (PR review; Sentinel gate) |
| CM-5 | Access Restrictions for Change | Define, document, approve, and enforce access restrictions for changes. | state-PATCH-only; PUT-rejects-state-fields; generated-columns-never-written |
| CM-6 | Configuration Settings | Establish and document configuration settings; enforce; identify deviations. | no-hardcoded-secrets; multer-memory-storage |
| CM-7 | Least Functionality | Configure to provide only essential capabilities; prohibit or restrict use of functions not required. | — (Helm; network policy) |
| CM-7(1) | Least Functionality — Periodic Review | Review system periodically to identify and eliminate unnecessary functions. | — (operational) |
| CM-7(2) | Least Functionality — Prevent Program Execution | Prevent execution of programs not authorized. | — (container hardening) |
| CM-8 | System Component Inventory | Develop and document inventory of system components. | — (Helm; SBOM — F-002) |
| CM-10 | Software Usage Restrictions | Use software in accordance with contracts and copyright laws. | dependencies-in-policy (license column) |
| CM-11 | User-Installed Software | Govern and monitor user-installed software. | — (immutable containers) |

---

## IA — Identification and Authentication

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| IA-1 | Policy and Procedures | Develop, document, and disseminate IA policy. | — |
| IA-2 | Identification and Authentication — Organizational Users | Uniquely identify and authenticate organizational users. | all-endpoints-require-token |
| IA-2(1) | IA — Organizational Users — MFA for Privileged Accounts | Implement MFA for privileged accounts. | — (Keycloak MFA configuration) |
| IA-2(2) | IA — Organizational Users — MFA for Non-Privileged Accounts | Implement MFA for non-privileged accounts. | — (Keycloak MFA configuration) |
| IA-2(8) | IA — Replay-Resistant Authentication | Implement replay-resistant authentication for network access to privileged accounts. | — (Keycloak PKCE OAuth2; short-lived JWTs) |
| IA-2(12) | IA — Acceptance of PIV Credentials | Accept and electronically verify PIV credentials. | — (Keycloak CAC/PIV integration) |
| IA-3 | Device Identification and Authentication | Uniquely identify and authenticate devices before establishing connections. | — (network/infrastructure) |
| IA-4 | Identifier Management | Manage system identifiers by receiving authorization, selecting identifiers, assigning identifiers, preventing reuse. | — (Keycloak manages user IDs; keycloak_id as FK in DB) |
| IA-5 | Authenticator Management | Manage authenticators: initial distribution, minimum/maximum lifetime, reuse restrictions, strength. | no-hardcoded-secrets; no-server-side-token-storage |
| IA-5(1) | Authenticator Management — Password-Based Authentication | Enforce minimum password complexity and change requirements. | — (Keycloak password policy) |
| IA-6 | Authentication Feedback | Obscure feedback of authentication information during authentication. | — (Keycloak login UI) |
| IA-7 | Cryptographic Module Authentication | Implement cryptographically based mechanisms to authenticate to cryptographic modules. | — (FIPS 140-2 at IL4; FIPS 140-3 at IL6) |
| IA-8 | Identification and Authentication — Non-Organizational Users | Uniquely identify and authenticate non-organizational users. | — (N/A — only org users) |
| IA-11 | Re-Authentication | Require re-authentication when defined conditions occur. | — (Keycloak session timeout) |

---

## IR — Incident Response

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| IR-1 | Policy and Procedures | Develop, document, and disseminate IR policy. | — |
| IR-2 | Incident Response Training | Provide incident response training. | — (organizational) |
| IR-3 | Incident Response Testing | Test incident response capability. | — (operational) |
| IR-4 | Incident Handling | Implement incident handling capability; coordinate with contingency plan. | — (operational) |
| IR-5 | Incident Monitoring | Track and document incidents. | — (operational) |
| IR-6 | Incident Reporting | Report incidents to designated authorities. | — (platform team) |
| IR-8 | Incident Response Plan | Develop and distribute incident response plan. | — (organizational) |

---

## MA — Maintenance

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| MA-2 | Controlled Maintenance | Schedule, perform, document, and review records of maintenance on system components. | — (infrastructure/operational) |
| MA-4 | Nonlocal Maintenance | Approve and monitor nonlocal maintenance; require MFA for remote sessions. | — (infrastructure) |
| MA-5 | Maintenance Personnel | Establish a process for maintenance personnel authorization. | — (organizational) |

---

## MP — Media Protection

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| MP-2 | Media Access | Restrict access to digital and non-digital media to authorized individuals. | — (S3 GovCloud access control via IAM) |
| MP-3 | Media Marking | Mark removable media with CUI markings. | — (operational) |
| MP-6 | Media Sanitization | Sanitize digital media before disposal or reuse. | — (operational/infrastructure) |
| MP-7 | Media Use | Restrict or prohibit the use of removable media. | — (infrastructure/organizational) |

---

## PE — Physical and Environmental Protection

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| PE-2 | Physical Access Authorizations | Develop and maintain list of individuals with authorized physical access. | — (data center: hosting platform physical controls) |
| PE-3 | Physical Access Control | Enforce physical access authorizations at entry/exit points. | — (hosting platform) |
| PE-6 | Monitoring Physical Access | Monitor physical access to facilities. | — (hosting platform) |
| PE-8 | Visitor Access Records | Maintain visitor access records for defined period. | — (hosting platform) |
| PE-12 | Emergency Lighting | Employ and maintain automatic emergency lighting. | — (hosting platform) |
| PE-13 | Fire Protection | Employ and maintain fire suppression and detection devices. | — (hosting platform) |
| PE-14 | Environmental Controls | Maintain temperature and humidity levels within defined ranges. | — (hosting platform) |
| PE-15 | Water Damage Protection | Protect system from water damage with master shutoff valves. | — (hosting platform) |
| PE-16 | Delivery and Removal | Authorize and control delivery and removal of hardware. | — (hosting platform) |

---

## PL — Planning

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| PL-1 | Policy and Procedures | Develop, document, and disseminate planning policy. | — |
| PL-2 | System Security and Privacy Plans | Develop and document SSP. | — (ATO artifact) |
| PL-4 | Rules of Behavior | Establish rules of behavior; acknowledgment required before access. | — (organizational) |
| PL-8 | Security and Privacy Architectures | Develop security and privacy architectures. | — (ADR-LOG.md; this document set) |
| PL-10 | Baseline Selection | Select a control baseline. | — (this document) |
| PL-11 | Baseline Tailoring | Tailor selected control baseline. | — (ATO tailoring) |

---

## PS — Personnel Security

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| PS-3 | Personnel Screening | Screen individuals before authorizing access. | — (organizational) |
| PS-4 | Personnel Termination | Terminate access upon separation; conduct exit interviews. | — (Keycloak account deactivation) |
| PS-5 | Personnel Transfer | Review and reissue authorizations following transfer. | — (Keycloak; user management API) |
| PS-6 | Access Agreements | Develop and maintain access agreements; review periodically. | — (organizational) |

---

## RA — Risk Assessment

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| RA-1 | Policy and Procedures | Develop, document, and disseminate RA policy. | — |
| RA-2 | Security Categorization | Categorize the system; document results in SSP. | — (IL4, FIPS 199 Moderate) |
| RA-3 | Risk Assessment | Conduct risk assessment; document results; review periodically. | — (ATO process) |
| RA-3(1) | Risk Assessment — Supply Chain Risk Assessment | Conduct supply chain risk assessment. | dependencies-in-policy |
| RA-5 | Vulnerability Monitoring and Scanning | Scan for vulnerabilities; analyze reports; remediate within defined timeframes. | — (Anchore; npm audit in pipeline) |
| RA-5(2) | Vulnerability Monitoring and Scanning — Update Vulnerabilities Scanned | Update vulnerabilities being scanned. | — (Anchore DB updated in pipeline) |
| RA-5(11) | Vulnerability Monitoring and Scanning — Public Disclosure Program | Establish a public vulnerability disclosure program. | — (organizational) |
| RA-7 | Risk Response | Respond to findings from risk assessments. | — (POAM per DEPENDENCY_POLICY.md §5.2) |

---

## SA — System and Services Acquisition

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| SA-1 | Policy and Procedures | Develop, document, and disseminate SA policy. | — |
| SA-2 | Allocation of Resources | Determine information security requirements; include in capital planning. | — |
| SA-3 | System Development Life Cycle | Acquire and manage system using SDLC with security considerations. | — (BMAD agent workflow; TDD protocol) |
| SA-4 | Acquisition Process | Include security requirements in acquisition contracts. | — (approved-registry base images per ADR-034; IL4 platform requirements) |
| SA-4(9) | Acquisition — Functions/Ports/Protocols/Services in Use | Require developer to document functions, ports, protocols, and services. | — (`docs/truth/api.md`, generated) |
| SA-5 | System Documentation | Obtain and protect documentation for the system. | — (docs/ folder) |
| SA-8 | Security and Privacy Engineering Principles | Apply security and privacy engineering principles in system development. | auth-middleware-first; view-reads; generated-columns-never-written |
| SA-9 | External System Services | Require external service providers to comply with security requirements. | — (hosting platform services; Keycloak; S3 GovCloud) |
| SA-10 | Developer Configuration Management | Require configuration management for system development. | — (git; Helm; pipeline) |
| SA-11 | Developer Testing and Evaluation | Require developer to employ security assessment plans; test coverage analysis. | negative-auth-test; rbac-negative-tests |
| SA-11(1) | Developer Testing — Static Code Analysis | Require static code analysis tools. | — (ESLint; TypeScript compiler) |
| SA-15 | Development Process, Standards, and Tools | Require development process compliant with security standards. | — (BMAD TDD protocol; Sentinel gate) |
| SA-17 | Developer Security and Privacy Architecture and Design | Require developer to produce security architecture. | — (ADR-LOG.md; CLAUDE.md architecture constraints) |

---

## SC — System and Communications Protection

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| SC-1 | Policy and Procedures | Develop, document, and disseminate SC policy. | — |
| SC-3 | Security Function Isolation | Isolate security functions from non-security functions. | — (Express middleware chain ordering) |
| SC-4 | Information in Shared System Resources | Prevent unauthorized transfer via shared resources. | — (containerization; namespace isolation) |
| SC-5 | Denial of Service Protection | Protect against or limit effects of DoS attacks. | — (express-rate-limit; ALB WAF) |
| SC-7 | Boundary Protection | Monitor and control communications at external boundaries. | — (platform ALB; network policy) |
| SC-7(3) | Boundary Protection — Access Points | Limit number of external network connections. | — (single ALB ingress point) |
| SC-8 | Transmission Confidentiality and Integrity | Implement cryptographic protections for transmissions. | no-presigned-S3-URLs (all transfers API-proxied over TLS) |
| SC-8(1) | Transmission — Cryptographic Protection | Implement cryptographic mechanisms to prevent unauthorized disclosure during transmission. | — (TLS 1.2+ enforced at ALB) |
| SC-12 | Cryptographic Key Establishment and Management | Establish and manage cryptographic keys. | — (AWS KMS / Key Vault) |
| SC-13 | Cryptographic Protection | Employ cryptographic uses and types of cryptography required for each use. | — (FIPS 140-2 validated modules at IL4) |
| SC-17 | Public Key Infrastructure Certificates | Issue PKI certificates under appropriate policy. | — (platform TLS certificates) |
| SC-18 | Mobile Code | Establish usage restrictions and implementation guidance for mobile code. | — (CSP headers via Helmet) |
| SC-20 | Secure Name/Address Resolution Service — Authoritative Source | Provide additional data origin and integrity verification artifacts. | — (platform internal DNS) |
| SC-21 | Secure Name/Address Resolution Service — Recursive or Caching Resolver | Request and perform data origin and integrity verification. | — (platform DNS) |
| SC-22 | Architecture and Provisioning for Name/Address Resolution Service | Provide fault-tolerant name/address resolution. | — (hosting platform) |
| SC-23 | Session Authenticity | Protect the authenticity of communication sessions. | no-server-side-token-storage; Keycloak PKCE |
| SC-28 | Protection of Information at Rest | Implement cryptographic protections for information at rest. | multer-memory-storage (no disk write); S3 SSE-KMS at provider layer |
| SC-28(1) | Protection of Information at Rest — Cryptographic Protection | Implement cryptographic mechanisms to prevent unauthorized disclosure. | — (S3 SSE-KMS; RDS encrypted EBS) |
| SC-39 | Process Isolation | Maintain a separate execution domain for each process. | — (container isolation; EKS pod isolation) |

---

## SI — System and Information Integrity

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| SI-1 | Policy and Procedures | Develop, document, and disseminate SI policy. | — |
| SI-2 | Flaw Remediation | Identify, report, and correct flaws; test remediation; incorporate corrections. | — (npm audit; Anchore; POAM) |
| SI-2(2) | Flaw Remediation — Automated Flaw Remediation Status | Determine remediation status using automated mechanisms. | — (pipeline npm audit; Anchore) |
| SI-3 | Malicious Code Protection | Implement malicious code protection at entry/exit points. | — (Anchore container scanning; base-image provenance) |
| SI-4 | System Monitoring | Monitor system for unauthorized access, use, and malicious code. | — (hosting platform monitoring) |
| SI-5 | Security Alerts, Advisories, and Directives | Receive security alerts from designated sources; generate internal alerts. | — (CISA alerts; npm audit advisory feed) |
| SI-7 | Software, Firmware, and Information Integrity | Employ integrity verification tools. | — (container image signing — F-002 pipeline gap) |
| SI-7(1) | Software Integrity — Integrity Checks | Perform integrity checks of software at startup, access, or periodically. | — (container signing; SBOM — F-002) |
| SI-10 | Information Input Validation | Check information inputs for accuracy, completeness, validity, and authenticity. | sql-injection-parameterized; PUT-rejects-state-fields |
| SI-11 | Error Handling | Generate error messages that provide necessary information and do not reveal sensitive information. | custom-error-handler-no-stack-traces |
| SI-12 | Information Management and Retention | Manage and retain information within system and output from system in accordance with policy. | deleted-at-archived-at-filters |
| SI-16 | Memory Protection | Implement protection measures for memory. | — (container hardening; Node.js memory limits) |

---

## SR — Supply Chain Risk Management

| Control ID | Control Name | Moderate Requirement | Sentinel Check |
|---|---|---|---|
| SR-1 | Policy and Procedures | Develop, document, and disseminate SR policy. | — |
| SR-2 | Supply Chain Risk Management Plan | Develop supply chain risk management plan. | — (DEPENDENCY_POLICY.md is the application-layer SCRM artifact) |
| SR-3 | Supply Chain Controls and Processes | Establish supply chain processes; inspect system components. | dependencies-in-policy (Rev 5 incorporated the withdrawn SA-12 here — citations: allow); provenance gate; SBOM |
| SR-5 | Acquisition Strategies, Tools, and Methods | Employ acquisition strategies to reduce supply chain risk. | — (Chainguard primary base-image source per ADR-034, other approved registries a documented fallback; approved dependency list) |
| SR-8 | Notification Agreements | Establish agreements to be notified of breaches. | — (organizational) |
| SR-10 | Inspection of Systems or Components | Inspect systems or components using defined inspection techniques. | — (`make scan` — Grype, Trivy, Checkov, Hadolint; platform pipeline scanning) |
| SR-11 | Component Authenticity | Employ anti-counterfeit measures. | — (approved-registry provenance gate per ADR-034; container signing) |
| SR-11(1) | Component Authenticity — Anti-Counterfeit Training | Train personnel in anti-counterfeit policies and procedures. | — (organizational) |
| SR-11(2) | Component Authenticity — Configuration Control for Component Service/Repair | Use configuration control to maintain component authenticity after service/repair. | — (immutable containers; no in-place patching) |

---

## Notes on Applicability

**Physical and Environmental (PE) controls** — met entirely by the IL4 hosting platform (its data center) and not directly in scope for application-layer implementation. Application teams confirm PE controls are inherited from the platform ATO.

**Planning (PL), Personnel Security (PS), Program Management (PM)** — met at the organizational/ATO level. Application teams document inherited controls in the System Security Plan.

**IL4 FIPS 140-2 cryptographic requirement** — at IL4, NIST requires FIPS 140-2 (or newer) validated cryptographic modules for all security-relevant cryptographic operations. At IL6, this requirement escalates to FIPS 140-3. See `IL6-delta.md` for the escalation details.
