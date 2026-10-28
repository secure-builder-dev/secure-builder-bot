## About This Document

**Purpose:** Defines the framework's CDS scope boundary — what the framework does not provide regarding cross-domain data transfer and what a deployer must procure separately.

**Workflow role:** Sentinel reads when checking IL6-5 (CDS integration points documented and not bypassed); any agent must read before asserting cross-domain capability.

**How to fill in:** No customization required — this document defines a fixed framework boundary. If your deployment includes a CDS integration point, document it in your architecture ADRs and reference this file.

---

# Cross-Domain Solution (CDS) Guidance

**Scope:** Defines the CDS scope boundary for this framework. Documents what the framework does not provide, what a deployer must procure separately, and where the framework's IL6 mode ends and where a CDS begins.
**References:** DoD CC SRG v1r4 §6.6; NIST SP 800-53 Rev 5 SC-16, SC-16(1); NCDSMO BAPL; CNSSI 1253; ICD 503.
**Last updated:** 2026-05-01

---

## What Is a Cross-Domain Solution?

A cross-domain solution (CDS) is a controlled interface that provides the ability to manually and/or automatically access and/or transfer information between different security domains. CDS components:

- Are accredited under the Risk Management Framework (RMF) for National Security Systems (NSS).
- Must appear on the **NSA Baseline Approved Product List (BAPL)**, maintained by the National Cross Domain Strategy and Management Office (NCDSMO).
- Require a **Connection Approval Process (CAP)** before any classified-to-unclassified connection is permitted.
- Are a **hardware and software procurement**, not a software configuration. A deployer cannot build a CDS from open-source components or configure one from an application framework.

---

## Framework Scope Boundary

**This framework does not implement, bundle, simulate, or approximate a CDS.**

The framework's IL6 mode documents the application-layer requirements for a system operating on a classified network (SECRET and below). It does not create, manage, or operate any connection between classified and unclassified domains.

| Capability | In Framework? | Notes |
|---|---|---|
| Application running entirely on classified network (no cross-domain data flow) | Yes | IL6 mode; `SECURITY_TIER=IL6` |
| NIST 800-53 High control documentation | Yes | `IL6-delta.md` |
| Application-layer classification banner in API responses | Yes | IL6 Sentinel gate check IL6-2 |
| Data flowing FROM a classified system TO an unclassified system | **No** | Requires a procured, BAPL-listed CDS |
| Data flowing FROM an unclassified system TO a classified system | **No** | Requires a procured, BAPL-listed CDS |
| Automated guard or filter between domains | **No** | BAPL product required |
| CDS audit trail | **No** | CDS product audit, not application audit |
| CDS configuration, management, or operation | **No** | NCDSMO-governed process |

---

## Where the Framework Ends — Integration Boundary

If a deployer's architecture requires data to move between a classified network (SECRET) and an unclassified network (CUI/NIPRNet), the CDS integration boundary is:

```
┌──────────────────────────────────────────────┐
│  Classified Network (SECRET)                  │
│                                               │
│  Application (IL6 mode, SECURITY_TIER=IL6)   │
│    └── writes to / reads from CDS interface   │
│          ▲ THIS IS WHERE THE FRAMEWORK ENDS   │
│          │                                    │
│  ┌───────┴──────────────────────────────┐     │
│  │  CDS (BAPL-listed; CAP-approved)     │     │  ← Deployer must procure
│  │  Hardware guard / filter / transfer  │     │
│  └──────────────────────────────────────┘     │
│          │                                    │
└──────────┼────────────────────────────────────┘
           │  (cross-domain transfer)
┌──────────┴────────────────────────────────────┐
│  Unclassified Network (NIPRNet / CUI)          │
│                                               │
│  Receiving System (IL4 or lower)              │
└──────────────────────────────────────────────┘
```

The framework's IL6 Sentinel gate check `IL6-5` (CDS integration points documented and not bypassed) verifies that:

1. Any interface point in the application code that is designed to send or receive data across a domain boundary is explicitly documented in the architecture.
2. No application code attempts to perform a cross-domain transfer without routing through the CDS.
3. The CDS is not bypassed by writing directly to shared storage, shared databases, or shared network paths that cross domain boundaries.

---

## What a Deployer Must Procure Separately

If the application architecture requires a cross-domain data flow:

| Step | Action | Authority |
|---|---|---|
| 1. Identify CDS requirement | Determine the data types, direction, and transfer frequency | Mission owner / system architect |
| 2. Select BAPL product | Search the NCDSMO Baseline Approved Product List for an approved CDS appropriate to the data type and volume | NCDSMO BAPL (restricted access — CAC required) |
| 3. Connection Approval Process | Submit CAP request to NCDSMO; include system architecture, data flow diagrams, and risk acceptance | NCDSMO / Component CIO |
| 4. ATO integration | Integrate CDS into the system ATO; document inheritance of CDS controls | ISSO / ISSM |
| 5. Operational deployment | Deploy CDS hardware/software per vendor guidance and NCDSMO accreditation conditions | Infrastructure team |
| 6. Ongoing accreditation | Maintain CDS accreditation; re-submit CAP when architecture changes | ISSO / NCDSMO |

---

## Misuse Warning

**Treating the framework's IL6 mode as a complete classified deployment solution without a properly procured and accredited CDS is a misuse of this framework and a security violation.**

Specifically:

- Configuring `SECURITY_TIER=IL6` does not authorize a cross-domain connection.
- The IL6 Sentinel gate checks are application-layer assurance measures. They do not substitute for NCDSMO CAP approval.
- Running an IL6-mode application on a classified network and connecting it to an unclassified network without a BAPL-listed CDS in between is a data spillage event and a reportable security incident under DoD policy.
- The classification banner header (IL6 Sentinel gate check IL6-2) is a labeling mechanism, not a data transfer control. Adding a banner to an API response does not protect data that is transmitted to an unauthorized domain.

---

## IL5 Note (Azure Track)

The Azure Government Secret (IL5) track of this framework does not involve classified data at the SECRET level. IL5 handles controlled unclassified information (CUI) at the highest sensitivity tier on the Azure platform. CDS requirements apply when SECRET data must cross domains — this is outside the Azure track ceiling. The Azure IL5 deployment is not connected to classified networks and does not require a CDS.

If a future Azure deployment requires SECRET-level data processing, it is outside the framework's Azure track and requires NSS-specific infrastructure and NCDSMO approval. See `providers/azure/IL5-implementation.md` for the Azure ceiling.

---

## References

- NCDSMO: National Cross Domain Strategy and Management Office — manages the BAPL and CAP process.
- BAPL: Baseline Approved Product List — the authoritative list of NSA-approved CDS components.
- DoD CC SRG v1r4 §6.6: Cross-Domain Solutions — requirements for CDS in cloud environments.
- NIST SP 800-53 Rev 5 SC-16 and SC-16(1): Transmission of Security Attributes; validation on import.
- ICD 503: Intelligence Community Information Technology Systems Security Risk Management, Certification, and Accreditation.
- CNSSI 1253: Security Categorization and Control Selection for NSS.
