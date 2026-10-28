## About This Document

**Purpose:** Index and orientation guide for the security documentation tree.

**Workflow role:** All agents read before touching any security-related file. Sentinel uses it to navigate to the relevant provider track.

**How to fill in:** Update the provider track table to reflect your project's active tracks (set at initialization via APP_TRACK/SECURITY_TIER/PROVIDER). Mark inactive tracks as N/A.

---

# Framework Security Documentation

This folder implements the two-layer security architecture defined in **ADR-020** (accepted 2026-05-01, extended by ADR-022 and ADR-023).

## Scope — what this engine's records are, and are not

The engine produces **development records**: the gate log, Sentinel's verdict history, the findings
register, the legacy inventory, the governance changelog. They exist so a human can see what was
reviewed, what was found, and what became a ticket, and so each retro can turn a finding into a
standing check.

They are **not accreditation evidence**. The platform owns the ATO package and the artifacts in it.
Where a control requires evidence, a human may cite this engine's output as an input to what they
write; the engine's records are never the submission. The documents in this folder describe control
*requirements* and how a provider satisfies them — they do not perform, replace, or stand in for the
RMF process, as `controls/IL6-delta.md` and `providers/aws/IL6-implementation.md` already state.

One practical consequence, and the gate follows it: **a missing or unwritten record never blocks
development.** It is a finding that opens a ticket. A gate check blocks only when skipping it would
leave another check verifying nothing — a missing control-manifest row blocks because
`make verify-controls` and `make mutate-controls` would then have nothing to check; an
undispositioned pre-flight delta does not.

## Layer 1 — Cloud-Agnostic Control Baseline (`controls/`)

Defines *what* must be controlled, independent of any cloud provider. Organized by impact level:

| File | Scope |
|---|---|
| `controls/IL4-baseline.md` | NIST SP 800-53 Rev 5 Moderate controls for IL4 deployments (CUI, FIPS 199 Moderate) |
| `controls/IL6-delta.md` | NIST SP 800-53 Rev 5 High additions/overrides above the IL4 Moderate baseline (up to SECRET; classified network required) |
| `controls/CONTROLS-MAPPING.md` | Every security-gate check and quality-gate item mapped to its NIST 800-53 Rev 5 control ID, with OWASP references, the Android and Tactical blocks, and a named list of known gaps |
| `controls/CDS-guidance.md` | Cross-domain solution scope boundary — what the framework does not provide and what a deployer must procure separately |

## Layer 2 — Provider-Specific Implementation (`providers/`)

Maps Layer 1 controls to *how* they are satisfied on each supported deployment provider. Three providers are recognized: `aws`, `azure`, and `tactical`.

| Path | Scope |
|---|---|
| `providers/aws/IL4-implementation.md` | AWS GovCloud (`us-gov-east-1`) IL4 implementation |
| `providers/aws/IL6-implementation.md` | AWS C2S/SC2S IL6 classified deployment boundary |
| `providers/aws/STIG-checklist.md` | EKS, container, Node.js, PostgreSQL STIG items for the Frank lane |
| `providers/azure/IL4-implementation.md` | Azure Government IL4 implementation |
| `providers/azure/IL5-implementation.md` | Azure Government Secret IL5 implementation (Azure ceiling — Azure does not reach IL6) |
| `providers/azure/STIG-checklist.md` | AKS, container, Node.js, PostgreSQL STIG items for the Frank lane |
| `providers/android/IL6-implementation.md` | Android track IL6 implementation guide — primary config `IL6|tactical`; no IL4 android deployments on this team (F-ATAK-002) |
| `providers/android/STIG-checklist.md` | Android STIG items for the Frank and Sentinel lanes (F-ATAK-002) |
| `providers/tactical/IL4-implementation.md` | Tactical (self-owned perimeter network) IL4 implementation — no cloud IaC, no managed K8s (F-ATAK-005) |
| `providers/tactical/STIG-checklist.md` | Tactical provider STIG items for the Frank and Sentinel lanes (F-ATAK-005) |

## Impact Level Ceiling by Provider

| Provider | Maximum Impact Level | Authorization Basis |
|---|---|---|
| AWS GovCloud | IL4 | FedRAMP High P-ATO (inherited) |
| AWS C2S / SC2S | IL6 | NSS classified cloud authorization |
| Azure Government | IL4 | FedRAMP High (inherited) |
| Azure Government Secret | IL5 (ceiling — Azure does not reach IL6 under DoD CC SRG) | DoD IL5 PA |
| Tactical (classified perimeter network) | IL6 | Android-only on this team — classified network, team-owned server; no cloud provider. See ADR-023 and ADR-026. |

## Project Initialization

Projects are initialized via a guided decision tree (ADR-026). See `CLAUDE.md → Project Initialization Variables` for the full tree. Summary:

| Profile | `APP_TRACK` | `SECURITY_TIER` | `PROVIDER` | `APP_TYPE` |
|---|---|---|---|---|
| Web — IL4 on AWS | `web` | `IL4` | `aws` | N/A |
| Web — IL4 on Azure | `web` | `IL4` | `azure` | N/A |
| Web — IL6 on AWS | `web` | `IL6` | `aws` | N/A |
| Web — IL6 on Azure | `web` | `IL6` | `azure` | N/A |
| Android — NATIVE | `android` | `IL6` | `tactical` | `native` |
| Android — ATAK plugin | `android` | `IL6` | `tactical` | `atak` |

Android always = IL6 + tactical. There is no Android + cloud provider combination on this team (ADR-025, ADR-026). There is no web + tactical combination on this team (ADR-026).

`tactical` provider: no Terraform, no Kubernetes, no Helm, no cloud-managed secrets — all replaced by team-selected self-managed equivalents. See ADR-023 for full specification and open gaps.

> **Reference IDs.** `F-*` story IDs and `OG-*` open-gap IDs cited in these documents are engine-build references (the stories that created the engine itself), not your project's stories.
