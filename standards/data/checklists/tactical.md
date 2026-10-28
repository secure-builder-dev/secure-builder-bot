# Sentinel checklist block — active when `PROVIDER=tactical`

Moved out of `engine/SENTINEL-CHECKLIST.md` on 2026-10-03 (T-SLIM-06) so a project where this block
is off does not load it on every gate. The gate reads this file when `project.config.yaml` turns it on.

#### Tactical Provider Infrastructure Checks (active when PROVIDER=tactical)

When `PROVIDER=tactical`, Sentinel substitutes the following checks in place of the cloud-specific infrastructure checks (Secrets Manager, hardened container registry, Helm, Terraform, cloud IAM). Application-layer checks (auth, SQL injection, RBAC, parameterized queries, etc.) are unchanged and remain mandatory regardless of provider. These checks are grounded in ADR-023 and `standards/data/providers/tactical/` (created by F-ATAK-005); open gaps OG-6a through OG-6e are treated as accepted risk items, not findings, until remediated.

- TLS termination documented at the server/reverse-proxy layer — confirm cipher suite ≥ TLS 1.2 minimum
- No plaintext secrets in provisioning scripts, environment files, or configuration tracked by the repo — secrets injected via team-selected mechanism at runtime
- Audit log destination documented and satisfies AU-2/AU-11 retention requirement (365 days minimum)
- Data at rest encryption documented for database volume and any persistent storage (LUKS or equivalent)
- Network firewall rules documented — only required ports open; no management ports (SSH, RDP) exposed to the Android client network segment
- OS and runtime packages current — no critical/high CVEs in deployed OS packages at deployment time
- Deployment authorization documented — evidence of ISSO/AO approval for this application on this network

Sentinel records the scan verdict with `make scan-verdict` before writing this block. The scan
itself runs BEFORE the gate, not inside it — `make gate-prompt` refuses a handoff whose tree is not
scanned green on this commit — so by the time Sentinel reads it there is a verdict to transcribe,
not a scan to run. A scanner that did not run is a FAIL: a partial scan reporting no findings is
indistinguishable from a clean one.
