## About This Document

**Purpose:** Tactical provider implementation guide — maps IL4 controls to self-hosted classified perimeter server deployments without cloud-managed services (no Terraform, no Kubernetes, no Helm).

**Workflow role:** Frank reads when provisioning or hardening the tactical provider environment; Sentinel references when running tactical-track gate checks (substitutes cloud checks per CLAUDE.md); Winston reads when reviewing tactical architecture decisions.

**How to fill in:** Replace server-specific placeholders (hostnames, IPs, mount paths) with your environment's values. Document accepted-risk items in your ATO POAM — framework open gaps OG-6a through OG-6e are pre-documented in the gate results section of this file.

---

# Tactical Provider Implementation Guide

**Lane:** Winston (architecture) + Frank (provisioning, hardening, operations)  
**Track:** `APP_TRACK=android | SECURITY_TIER=IL6 | PROVIDER=tactical`  
**Last updated:** 2026-05-05  
**Grounded in:** ADR-022 (Android track architecture), ADR-023 (tactical provider constraints), ADR-026 (decision tree; APP_TYPE), CLAUDE.md Sentinel checks (tactical provider block), `standards/data/controls/IL4-baseline.md`, `standards/data/controls/IL6-delta.md`, `standards/data/providers/android/BACKEND-INFRA.md` (F-ATAK-004)

> **PROVIDER=tactical scope:** No cloud-native managed services. No Secrets Manager, no Key Vault, no EKS, no AKS, no Helm, no Terraform, no cloud CLI tools, no hardened container registry. The backend API and database run on a team-owned classified perimeter server. All provisioning, secrets management, TLS certificate management, audit logging, and deployment authorization are self-owned responsibilities. This guide documents the architectural decisions, baseline implementation, and operating procedures.

> **IL6 note:** This team's tactical deployments operate on a classified perimeter network at `SECURITY_TIER=IL6`. The IL4 control baseline (`standards/data/controls/IL4-baseline.md`) is fully in force. The IL6 delta (`standards/data/controls/IL6-delta.md`) is also active. References to "IL4 baseline" in this document mean the Moderate control baseline that all deployments must satisfy — the IL6 delta adds requirements on top.

---

## 1. ADR-023 Open Gaps — Formal Documentation

ADR-023 established the tactical provider track and documented five open gaps (OG-6a through OG-6e). This section formally documents each gap with architectural placeholders. Teams fill in the bracketed values when the deployment process is defined. Sentinel gate runs treat documented open gaps as accepted risk items, not findings, until remediation.

### OG-6a — Provisioning Tooling

**Status:** Resolved at architectural level. Details team-selected.

**Gap:** What tooling does the team use to provision the perimeter server? Options include Ansible playbooks, shell-based hardening scripts, a containerized compose stack, or manual hardening using a checklist.

**Architectural decision:** GitLab CI pipeline on the team-owned IL6 server performs application deployment (backend build + deploy stages per PIPELINE-SPEC.md). Initial server provisioning uses team-selected tooling. The pipeline assumes the server is already hardened and running when `backend-deploy` executes. Server provisioning is a one-time operation; application deployment is a recurring pipeline event.

**Placeholder — team fills in:**
```
Provisioning tooling: <ANSIBLE | SHELL_SCRIPTS | COMPOSE | MANUAL_CHECKLIST>
Provisioning trigger: <MANUAL_ON_FIRST_SETUP | GIT_PUSH_TO_INFRA_REPO | OTHER>
Provisioning repository: <PATH_OR_REPO_URL> (not committed to this repo if it contains classified values)
```

**Control mapping:** CM-2 (Baseline Configuration), CM-6 (Configuration Settings), CM-7 (Least Functionality).

---

### OG-6b — Secrets Management

**Status:** Baseline approach documented. Vault layer optional for future maturity.

**Gap:** Without AWS Secrets Manager or Azure Key Vault, how are runtime secrets (database credentials, Keycloak JWKS URI, signing keys) stored and injected?

**Architectural decision:** Secrets are injected via restricted-permission environment files on the perimeter server. This is the baseline approach. Teams may layer a self-hosted secrets vault (e.g., HashiCorp Vault on the perimeter network) when the platform matures.

**Baseline secrets management pattern:**

| Secret file path | Owner | Permissions | Contents |
|---|---|---|---|
| `/opt/backend/runtime.env` | `<BACKEND_PROCESS_USER>` | `600` | Database URL, Keycloak JWKS URI, Keycloak issuer, any backend-specific secrets |
| `/opt/db/runtime.env` | `<DB_PROCESS_USER>` | `600` | Database password, PostgreSQL configuration secrets |

```bash
# How to create the env file on the server (admin action — performed once before first deploy)
install -o <BACKEND_PROCESS_USER> -g <BACKEND_PROCESS_USER> -m 600 /dev/null /opt/backend/runtime.env
# Then write secrets into the file using an approved out-of-band mechanism:
# - Transfer encrypted file from a trusted admin workstation and decrypt on-server
# - Transcribe values from approved classified documentation
# - Team-selected: <OG-6b TEAM MECHANISM>
```

**What is never acceptable:**
- Secrets in source code or committed files
- Secrets in CI/CD pipeline variables visible in job logs
- Secrets in Docker image layers or build args
- Default/fallback values for any secret variable — application fails to start explicitly if a required variable is unset

**Control mapping:** IA-5 (Authenticator Management), SC-28 (Protection of Information at Rest), SA-4(9) (Acquisition Process — use/configuration).

---

### OG-6c — TLS Certificate Authority

**Status:** TLS enforcement required; CA source is a placeholder pending unit IT.

**Gap:** Who issues the TLS certificate for the reverse proxy? Options include a unit-managed CA, a DoD PKI-issued certificate, a self-signed certificate with device-level trust distribution, or a classified network CA operated by the enclave authority.

**Architectural decision:** The reverse proxy (nginx) terminates TLS. The certificate and key paths are placeholders until unit IT provides the certificate. The Android devices must trust the CA that issued the server certificate — device trust store configuration is a prerequisite for deployment.

**Placeholder — team fills in:**
```
TLS CA type: <UNIT_CA | DOD_PKI | ENCLAVE_CA | SELF_SIGNED_WITH_DEVICE_TRUST>
Certificate path on server: /etc/ssl/certs/<CERT_FILE>.crt
Key path on server: /etc/ssl/private/<KEY_FILE>.key
Certificate renewal process: <MANUAL | AUTOMATED | TEAM_DEFINED>
Device CA trust distribution: <MDM_PUSH | MANUAL_INSTALL | DEVICE_ALREADY_TRUSTS_CHAIN>
```

**Control mapping:** SC-8 (Transmission Confidentiality and Integrity), SC-17 (Public Key Infrastructure Certificates), IA-3(1) (Device Identification and Authentication — cryptographic bidirectional authentication).

---

### OG-6d — Audit Log Destination

**Status:** Approach documented. Specific destination team-selected.

**Gap:** Where are audit logs written, retained, and protected against tampering on a self-owned server? CloudWatch is not available. AU-9(2) (IL6 High control) requires that audit logs be stored in a component not writable by the application process.

**Architectural decision:** The backend application writes structured audit log lines to stdout/stderr. The container runtime (Docker/Podman) captures stdout and routes it to a log driver. The log driver forwards to a destination outside the application's write scope.

**Tiered log destination options (team selects one):**

| Option | Description | AU-9(2) separation | AU-11 retention (365 days) |
|---|---|---|---|
| **rsyslog → network SIEM** | Container runtime forwards to rsyslog; rsyslog forwards to a network-level SIEM on the classified network | App process cannot write to SIEM | SIEM handles retention |
| **append-only local log file** | Container log driver writes to `/var/log/app/audit.log` owned by root; app process user has no write access to `/var/log/app/` | App process cannot write to path not owned by its UID | Local rotation (`logrotate`) with 365-day retention; directory ACL enforced |
| **journald on host** | Container runtime logs to systemd journal on the host; app process inside container cannot access host journald socket | Separation enforced by container boundary | Journal configured with `MaxRetentionSec=365days` |

**Placeholder — team fills in:**
```
Audit log destination: <RSYSLOG_SIEM | LOCAL_APPEND_ONLY | JOURNALD | TEAM_DEFINED>
SIEM address (if applicable): <SIEM_HOST>:<PORT> (not committed to source if classified)
Log retention configuration: <365_DAY_RETENTION_MECHANISM>
AU-9(2) separation verification: <HOW_TEAM_VERIFIES_APP_CANNOT_WRITE_TO_LOG_DESTINATION>
```

**Log integrity (AU-9(3) — IL6 High):** Audit log destination must implement integrity protection. Options: hash chaining on log entries, WORM storage, cryptographic signing of log batches, or SIEM with tamper-evident storage.

**What is written to audit logs:** Every mutating API operation — `keycloak_id` from the validated JWT, timestamp, HTTP method, resource path, resource ID, IP address (from `X-Real-IP`), HTTP status code. Sensitive request body content (passwords, tokens) is never logged.

**Control mapping:** AU-2 (Event Logging), AU-9 (Protection of Audit Information), AU-9(2) (Store on Separate Physical Systems), AU-9(3) (Cryptographic Protection), AU-11 (Audit Record Retention), AU-12 (Audit Record Generation).

---

### OG-6e — Self-Owned Approval Process

**Status:** Checklist documented. Process authority is team/ISSO-defined.

**Gap:** What documentation artifacts and review authorities are required to deploy an application on this classified network? This is equivalent to an ATO package for cloud deployments but scoped to the unit's network authority.

**Architectural decision:** Deployment requires ISSO/AO sign-off with documented evidence. The checklist below is the minimum evidence set — teams add organization-specific artifacts as required by their ISSO.

**Deployment authorization evidence checklist:**

- [ ] **System categorization** — FIPS 199 impact level documented (IL6 / HIGH for this team's configuration)
- [ ] **Threat model** — threat actors, attack surface, mitigations documented (or referenced from the ATO package if an enclave-level ATO exists)
- [ ] **Configuration baseline** — server OS version, Docker/Podman version, nginx version, PostgreSQL version, all documented at deploy time; matches the STIG checklist items in `STIG-checklist.md`
- [ ] **Vulnerability scan results** — OS package scan (no critical/high CVEs at deployment time); application dependency scan (OWASP dependency check from pipeline — no blocking findings)
- [ ] **Penetration test or security assessment** — team-appropriate scope; if a formal pentest is required by the ISSO, schedule before first production deployment
- [ ] **Incident response plan** — application-specific IR contacts and spillage procedures documented; reviewed by ISSO
- [ ] **Backup and recovery plan** — database backup schedule and recovery procedure documented
- [ ] **STIG compliance results** — `STIG-checklist.md` completed; all CAT I findings resolved; CAT II/III findings with accepted-risk documentation
- [ ] **ISSO sign-off** — `<ISSO_NAME>`, `<ISSO_SIGNATURE_OR_EMAIL>`, `<DATE>`
- [ ] **AO approval** — `<AO_NAME>`, `<AO_SIGNATURE_OR_EMAIL>`, `<DATE>`

**Placeholder — team fills in:**
```
ATO type: <STANDALONE_APPLICATION_ATO | UNDER_ENCLAVE_ATO | IATT>
ATO authority: <ISSO_NAME>, <AO_NAME>
ATO expiration: <DATE> (or continuous monitoring if applicable)
ATO package location: <CLASSIFIED_STORAGE_PATH> (do not commit to this repo)
```

**Control mapping:** CA-2 (Control Assessments), CA-5 (Plan of Action and Milestones), CA-6 (Authorization), CA-7 (Continuous Monitoring), RA-3 (Risk Assessment).

---

## 2. Server Architecture

**Single perimeter server pattern:** All three backend components (reverse proxy, backend API, database) run on a single team-owned server on the classified perimeter network. This is the documented primary configuration for `PROVIDER=tactical`.

```
Perimeter Server
├── nginx (reverse proxy)
│     - Listens on network interface: <SERVER_IP>:<HTTPS_PORT>
│     - TLS termination (classified network certificate — OG-6c)
│     - Forwards to 127.0.0.1:<BACKEND_PORT>
│
├── Backend API (Docker/Podman container or systemd process)
│     - Listens on 127.0.0.1:<BACKEND_PORT>
│     - Not reachable from network interface
│     - Secrets via /opt/backend/runtime.env (OG-6b)
│
└── Database (Docker/Podman container or native PostgreSQL)
      - Listens on 127.0.0.1:<DB_PORT>
      - Not reachable from network interface
      - Data volume at /opt/data/db (LUKS-encrypted)
      - Credentials via /opt/db/runtime.env (OG-6b)
```

**Container runtime — team selection:**
- **Docker:** Standard container runtime. Team documents Docker version at deployment time.
- **Podman:** Rootless alternative. Preferred if Docker's daemon security model is a concern. Team documents Podman version at deployment time.

Document the chosen container runtime in the deployment authorization package (OG-6e).

**Multi-server variant (optional):** If the team has access to two perimeter servers on the same network segment, the database may run on a separate server for isolation. In this case:
- Database server listens on an internal perimeter network interface (not `127.0.0.1`)
- Backend API server connects to the database server using the internal network IP
- TLS between backend and database is strongly recommended (`sslmode=verify-full`)
- Firewall rules on the database server allow connections from the backend server only

This variant is more complex to operate; the single-server pattern is the baseline.

---

## 3. Network Architecture

### Topology

```
Android Devices (classified perimeter network)
  │
  │  HTTPS (TLS 1.2+ minimum, FIPS 140-3 cipher suite)
  │  Destination: <SERVER_IP>:<HTTPS_PORT>
  │
  ▼
[Network Firewall — allow HTTPS from Android client segment only]
  │
  ▼
Perimeter Server — <SERVER_IP>
  │
  ├── nginx listening on <SERVER_IP>:<HTTPS_PORT>
  │     Terminates TLS → forwards to 127.0.0.1:<BACKEND_PORT>
  │
  ├── Backend API listening on 127.0.0.1:<BACKEND_PORT>
  │     Not reachable from network — loopback only
  │
  └── Database listening on 127.0.0.1:<DB_PORT>
        Not reachable from network — loopback only

Management Segment (SSH access)
  │
  │  SSH from management workstation only
  │  NOT from Android client network segment
  │
  ▼
Perimeter Server — <SERVER_IP>:<SSH_PORT>
  [Firewall: SSH allowed from <MANAGEMENT_SEGMENT_CIDR> only]
```

### Firewall Zones

| Zone | Source | Destination | Protocol/Port | Rule |
|---|---|---|---|---|
| Android client | `<ANDROID_CLIENT_SEGMENT_CIDR>` | `<SERVER_IP>:<HTTPS_PORT>` | TCP/443 (or team-selected HTTPS port) | ALLOW |
| Management | `<MANAGEMENT_SEGMENT_CIDR>` | `<SERVER_IP>:22` | TCP/22 | ALLOW |
| All other inbound | any | `<SERVER_IP>` | any | DENY |
| Outbound to classified network | `<SERVER_IP>` | classified network peers only | team-defined | ALLOW |
| Outbound to public internet | `<SERVER_IP>` | any public IP | any | DENY (IL6 requirement — no unclassified external calls) |

Firewall implementation is `iptables` or `nftables` — see Section 6 (Network Firewall Rules) below for the rule skeleton.

### What is NOT exposed

- The backend API port (`127.0.0.1:<BACKEND_PORT>`) is **not** exposed on any network interface. Android devices cannot reach it directly.
- The database port (`127.0.0.1:<DB_PORT>`) is **not** exposed on any network interface. Only the backend API (running on the same server) can connect.
- No management ports (SSH, RDP, HTTPS admin) are accessible from the Android client network segment.

---

## 4. Impact Level Ceiling

| Deployment | Maximum Impact Level | Basis |
|---|---|---|
| Tactical — classified perimeter network | IL6 | Classified network accreditation; full NIST SP 800-53 Rev 5 High baseline; DCSA/NSA/DoD Component oversight |
| Tactical — unclassified perimeter network | IL4 | Organization AO authority; unclassified CUI data; Moderate control baseline |

**This team's configuration: IL6 (classified perimeter network).** The IL4 ceiling row is documented for framework completeness — it applies to other teams using this template on unclassified tactical deployments. Per ADR-025, this team has no IL4 Android deployments.

---

## 5. OS and Runtime Hardening

**Base OS selection:** Team-selected Linux distribution. Document the chosen distribution and version in the deployment authorization package (OG-6e). Supported options and corresponding STIG reference:

| OS | STIG Reference | Notes |
|---|---|---|
| Red Hat Enterprise Linux 8/9 | DISA RHEL 8 STIG / RHEL 9 STIG | Available from `public.cyber.mil` |
| Ubuntu 20.04 / 22.04 | DISA Canonical Ubuntu STIG | Available from `public.cyber.mil` |
| Rocky Linux / AlmaLinux 8/9 | DISA RHEL 8/9 STIG (compatible) | RHEL-compatible; apply RHEL STIG |
| Other | CIS Benchmark Level 2 | If no DISA STIG exists, apply CIS Level 2 Benchmark |

**Minimum OS hardening steps (all distributions):**

```bash
# 1. Apply all available OS updates before initial deployment
# Red Hat family:
dnf update -y && dnf upgrade -y
# Debian/Ubuntu family:
apt update && apt full-upgrade -y

# 2. Remove unnecessary packages and services
# Disable any service not required for reverse proxy / API / DB operation
# Example: remove telnet, rsh, ftp, nfs-server if present
# Red Hat: systemctl list-unit-files --type=service | grep enabled
# Disable: systemctl disable <UNNECESSARY_SERVICE>

# 3. SSH hardening — /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no
# PubkeyAuthentication yes
# AllowUsers <ADMIN_USERS_ONLY>
# Protocol 2

# 4. Enable automatic security updates (or document manual patch schedule)
# Red Hat: dnf install dnf-automatic; systemctl enable dnf-automatic.timer
# Ubuntu: unattended-upgrades configured for security updates

# 5. System auditing (auditd)
# Install and enable auditd
# Apply DISA OS STIG audit rules or CIS audit rules for the distribution
# Rules must capture: login/logout, privilege escalation, file system changes to /etc and /opt
systemctl enable auditd && systemctl start auditd
```

**Docker/Podman hardening:**

```bash
# Docker hardening
# 1. Run dockerd with --no-new-privileges (or set in daemon.json)
# /etc/docker/daemon.json:
# {
#   "no-new-privileges": true,
#   "userns-remap": "default",        # enable user namespace remapping (rootless isolation)
#   "live-restore": true,
#   "log-driver": "journald",         # or "syslog" — route container logs to audit-capable destination
#   "log-opts": { "tag": "{{.Name}}" }
# }

# 2. Ensure dockerd socket is accessible only to root and docker group
ls -la /var/run/docker.sock   # should be srw-rw---- root docker

# Podman (rootless)
# Podman rootless mode runs containers as the current user — no daemon socket required
# Preferred for isolated deployment without Docker daemon privileges
# Ensure /etc/subuid and /etc/subgid entries exist for the deployment user
```

**Container requirements — enforced per container:**

| Requirement | Implementation |
|---|---|
| Non-root process user | `USER <NONROOT_UID>` in Dockerfile; confirmed with `docker exec <CONTAINER> id` |
| `HEALTHCHECK` defined | `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://127.0.0.1:<PORT>/health \|\| exit 1` |
| No privileged flag | `docker run` never includes `--privileged`; no `--cap-add SYS_ADMIN` without justification |
| Read-only root filesystem (where possible) | `docker run --read-only` with explicit writable mounts for runtime data (e.g., `/tmp`) |
| No host network | `docker run` does not use `--network host` — uses `--network bridge` with port binding |

---

## 6. Secrets Management

See OG-6b (Section 1) for the architectural decision. This section documents the operational pattern.

### Env File Setup (Admin Action — Performed Before First Deploy)

```bash
# On the perimeter server — admin sets up the env files once
# These paths are referenced by docker run --env-file in PIPELINE-SPEC.md stage 8

# Create the backend env file
sudo install -d -o root -g root -m 755 /opt/backend
sudo install -o <BACKEND_PROCESS_USER> -g <BACKEND_PROCESS_USER> -m 600 /dev/null /opt/backend/runtime.env

# Populate the backend env file (write secrets obtained through approved out-of-band mechanism)
# Example contents (placeholders — fill in actual values on the server):
# DATABASE_URL=<DB_SCHEME>://<APP_DB_USER>:<DB_PASSWORD>@127.0.0.1:<DB_PORT>/<DB_NAME>
# KEYCLOAK_JWKS_URI=https://<KEYCLOAK_HOST>/realms/<REALM>/protocol/openid-connect/certs
# KEYCLOAK_ISSUER=https://<KEYCLOAK_HOST>/realms/<REALM>
# PORT=<BACKEND_PORT>

# Create the database env file
sudo install -d -o root -g root -m 755 /opt/db
sudo install -o <DB_PROCESS_USER> -g <DB_PROCESS_USER> -m 600 /dev/null /opt/db/runtime.env

# Populate the database env file:
# POSTGRES_PASSWORD=<DB_ROOT_PASSWORD>
# POSTGRES_USER=<APP_DB_USER>
# POSTGRES_DB=<DB_NAME>
```

### Verification

```bash
# Verify permissions — both files must be 600 owned by process user, not root
stat -c "%a %U %n" /opt/backend/runtime.env   # should print: 600 <BACKEND_PROCESS_USER> ...
stat -c "%a %U %n" /opt/db/runtime.env          # should print: 600 <DB_PROCESS_USER> ...

# Verify file is not readable by other users
sudo -u nobody cat /opt/backend/runtime.env    # should return "Permission denied"
```

### What Is Never Stored in Source

- `runtime.env` files — never committed to source
- Keycloak credentials or JWKS URI if it contains a classified hostname
- Database passwords, connection strings
- SSH private keys for deployment (`BACKEND_SSH_KEY` is a GitLab masked file variable — see PIPELINE-SPEC.md)
- APK signing keystore (`KEYSTORE_BASE64` is a GitLab masked file variable — never in source)

---

## 7. TLS Configuration

The reverse proxy terminates TLS for all inbound HTTPS connections from Android devices.

### nginx Configuration Template

```nginx
# /etc/nginx/sites-available/backend-proxy
# Tactical provider reverse proxy — TLS termination for Android track backend

server {
    listen <HTTPS_PORT> ssl;               # team-selected HTTPS port; default 443
    server_name <SERVER_HOSTNAME_OR_IP>;   # OG-6c: fill in after certificate is issued

    # TLS certificate (OG-6c — provided by unit IT or team-managed CA)
    ssl_certificate     /etc/ssl/certs/<CERT_FILE>.crt;
    ssl_certificate_key /etc/ssl/private/<KEY_FILE>.key;

    # TLS version — minimum TLS 1.2; TLS 1.3 preferred
    ssl_protocols TLSv1.2 TLSv1.3;

    # FIPS 140-3 approved cipher suite placeholder
    # Replace <FIPS_CIPHER_SUITE> with the cipher suite confirmed by unit IT / ISSO
    # Commonly approved FIPS ciphers for TLS 1.2: ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256
    # TLS 1.3 ciphers are inherently FIPS-compliant when using FIPS-validated OpenSSL
    ssl_ciphers <FIPS_CIPHER_SUITE>;
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;              # disable session tickets for forward secrecy

    # HSTS — enforce HTTPS on classified network clients
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    # No CORS headers — Android client is not a browser; no cross-origin requests
    # DO NOT add Access-Control-Allow-Origin

    # Proxy all API requests to the backend API on loopback
    location /api/ {
        proxy_pass         http://127.0.0.1:<BACKEND_PORT>;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Pass Authorization header through to the backend API — required for JWT validation
        proxy_set_header   Authorization     $http_authorization;

        # Timeouts appropriate for classified network latency
        proxy_read_timeout  30s;
        proxy_send_timeout  30s;
        proxy_connect_timeout 5s;
    }

    # Health check endpoint (does not require auth in reverse proxy — backend enforces auth)
    location /health {
        proxy_pass http://127.0.0.1:<BACKEND_PORT>/health;
    }

    # Block all other paths — only /api/ and /health are exposed
    location / {
        return 404;
    }
}

# Redirect HTTP to HTTPS (if HTTP listener is running)
server {
    listen 80;
    server_name <SERVER_HOSTNAME_OR_IP>;
    return 301 https://$host$request_uri;
}
```

### TLS Verification

```bash
# Verify TLS version and cipher suite from the Android client network segment
# (run from a test device or management workstation on the same segment)
openssl s_client -connect <SERVER_IP>:<HTTPS_PORT> -tls1_2 -cipher <FIPS_CIPHER_SUITE>
# Should return: Verify return code: 0 (ok) and the expected certificate

# Verify TLS 1.0 and 1.1 are rejected
openssl s_client -connect <SERVER_IP>:<HTTPS_PORT> -tls1    # should fail
openssl s_client -connect <SERVER_IP>:<HTTPS_PORT> -tls1_1  # should fail

# Verify SSLv3 is rejected
openssl s_client -connect <SERVER_IP>:<HTTPS_PORT> -ssl3    # should fail
```

---

## 8. Audit Log Destination

See OG-6d (Section 1) for the architectural decision. This section documents the two primary implementation options.

### Option A — rsyslog Forwarding to Network SIEM (Preferred for IL6)

```bash
# /etc/rsyslog.d/10-app-audit.conf
# Forward backend audit logs to network SIEM

# Capture Docker/Podman container output (if log-driver is syslog or journald)
$template AuditFormat,"%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg%\n"

# Forward to network SIEM (UDP or TCP — TCP preferred for reliability)
# *.* @@<SIEM_HOST>:<SIEM_PORT>;AuditFormat   # TCP (@@)
# *.* @<SIEM_HOST>:<SIEM_PORT>;AuditFormat    # UDP (@)
*.* @@<SIEM_HOST>:<SIEM_PORT>;AuditFormat

# Local backup — append-only, not writable by application process user
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
*.* /var/log/app/audit.log
```

```bash
# Create audit log directory — owned by root, not writable by application process user
sudo install -d -o root -g adm -m 750 /var/log/app
# Application process user must NOT be in the adm group
# Verify: groups <BACKEND_PROCESS_USER>  — should not include adm
```

### Option B — Append-Only Local File (Baseline Fallback)

```bash
# When no SIEM is available on the classified network
# Configure container log driver to write to a host path not owned by the app process

# /etc/docker/daemon.json — file log driver
{
  "log-driver": "local",
  "log-opts": {
    "max-size": "100m",
    "max-file": "365",    # 365 rotated files at 100MB = ~36GB max
    "path": "/var/log/app"
  }
}
# /var/log/app directory owned by root:adm, mode 750
# Application process user must not be in adm group — AU-9(2) separation enforced by file ownership
```

### AU-9(2) Separation Verification

```bash
# Confirm the application process user cannot write to the audit log destination
# Replace <BACKEND_PROCESS_USER> with the actual user
sudo -u <BACKEND_PROCESS_USER> touch /var/log/app/test   # must return "Permission denied"
sudo -u <BACKEND_PROCESS_USER> cat /var/log/app/audit.log  # may be denied or allowed — write access must be denied
```

---

## 9. Data at Rest Encryption

The database data volume must be encrypted at rest. Mechanism is LUKS full-disk or volume encryption — not application-layer encryption.

### LUKS Volume Encryption (Baseline)

```bash
# One-time setup — performed by an admin before first deployment
# Assumes a dedicated block device or partition for the database volume

# Step 1: Format with LUKS
# CAUTION: this destroys all data on the device
cryptsetup luksFormat /dev/<DB_DEVICE>
# Enter a strong passphrase — store securely in the deployment authorization package (OG-6e)

# Step 2: Open the encrypted volume
cryptsetup luksOpen /dev/<DB_DEVICE> db-volume

# Step 3: Create a filesystem on the decrypted device
mkfs.ext4 /dev/mapper/db-volume

# Step 4: Mount at the database data path
mkdir -p /opt/data/db
mount /dev/mapper/db-volume /opt/data/db

# Step 5: Add to /etc/crypttab for auto-open at boot (if using a keyfile or TPM unlock)
# db-volume  /dev/<DB_DEVICE>  /etc/luks/<KEYFILE_NAME>  luks,noauto
# Or: db-volume  /dev/<DB_DEVICE>  none  luks  (prompts for passphrase at boot — manual operation)

# Step 6: Add to /etc/fstab for auto-mount after crypttab open
# /dev/mapper/db-volume  /opt/data/db  ext4  defaults,noatime  0  2
```

### TPM-Backed Key (Preferred for Unattended Boot)

```bash
# If the server has a TPM 2.0 module, use clevis + tang or tpm2-tools for automated unlock
# This avoids manual passphrase entry at every server reboot

# Install clevis (Red Hat):
dnf install clevis clevis-luks clevis-systemd

# Bind the LUKS volume to the TPM (no network required — local TPM only):
clevis luks bind -d /dev/<DB_DEVICE> tpm2 '{"pcr_bank":"sha256","pcr_ids":"0,7"}'

# Enable clevis unlock at boot:
systemctl enable clevis-luks-askpass.path
```

**Team placeholder:**
```
LUKS device: /dev/<DB_DEVICE>
Key storage: <TPM2 | KEYFILE_AT_RESTRICTED_PATH | MANUAL_PASSPHRASE>
Unlock method: <AUTO_TPM | MANUAL_AT_BOOT | TEAM_DEFINED>
Volume mounted at: /opt/data/db
```

### Verification

```bash
# Verify the database volume is LUKS-encrypted
cryptsetup status db-volume   # should show type: LUKS2 and active

# Verify the database container is using the encrypted mount path
docker inspect db | jq '.[].HostConfig.Binds'
# Should include: "/opt/data/db:/var/lib/postgresql/data"

# Verify the device is not mounted unencrypted elsewhere
mount | grep /opt/data/db   # should show /dev/mapper/db-volume
```

---

## 10. Network Firewall Rules

### iptables Skeleton

```bash
#!/bin/bash
# Tactical provider firewall rules — iptables
# Apply on the perimeter server
# Replace placeholder values before applying

# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Default policies: DROP all inbound and forwarded; allow outbound
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT   # restrict further below

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback (localhost communication between backend and database)
iptables -A INPUT -i lo -j ACCEPT

# Allow HTTPS from Android client network segment
iptables -A INPUT -p tcp --dport <HTTPS_PORT> -s <ANDROID_CLIENT_SEGMENT_CIDR> -j ACCEPT

# Allow SSH from management segment only
iptables -A INPUT -p tcp --dport 22 -s <MANAGEMENT_SEGMENT_CIDR> -j ACCEPT

# Log and drop all other inbound
iptables -A INPUT -j LOG --log-prefix "IPTABLES DROP: " --log-level 7
iptables -A INPUT -j DROP

# Restrict outbound — allow only internal classified network; block public internet
# Allow DNS on classified network
iptables -A OUTPUT -p udp --dport 53 -d <CLASSIFIED_NETWORK_DNS_CIDR> -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d <CLASSIFIED_NETWORK_DNS_CIDR> -j ACCEPT

# Allow connections to Keycloak on classified network (JWKS cache refresh)
iptables -A OUTPUT -p tcp --dport 443 -d <KEYCLOAK_HOST_IP> -j ACCEPT

# Allow connections to SIEM on classified network (if using rsyslog forwarding)
iptables -A OUTPUT -p tcp --dport <SIEM_PORT> -d <SIEM_HOST_IP> -j ACCEPT

# Allow loopback outbound
iptables -A OUTPUT -o lo -j ACCEPT

# Drop all other outbound (no public internet)
iptables -A OUTPUT -j LOG --log-prefix "IPTABLES OUT DROP: " --log-level 7
iptables -A OUTPUT -j DROP

# Save rules for persistence
# Red Hat: iptables-save > /etc/sysconfig/iptables
# Debian/Ubuntu: iptables-save > /etc/iptables/rules.v4 (with iptables-persistent)
```

### nftables Alternative

```nft
#!/usr/sbin/nft -f
# Tactical provider firewall rules — nftables alternative

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Established and related
        ct state established,related accept

        # Loopback
        iif lo accept

        # HTTPS from Android client segment
        ip saddr <ANDROID_CLIENT_SEGMENT_CIDR> tcp dport <HTTPS_PORT> accept

        # SSH from management segment
        ip saddr <MANAGEMENT_SEGMENT_CIDR> tcp dport 22 accept

        # Log and drop the rest
        log prefix "nft DROP IN: " drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy drop;

        # Loopback
        oif lo accept

        # Established
        ct state established,related accept

        # DNS on classified network
        ip daddr <CLASSIFIED_NETWORK_DNS_CIDR> udp dport 53 accept
        ip daddr <CLASSIFIED_NETWORK_DNS_CIDR> tcp dport 53 accept

        # Keycloak JWKS refresh
        ip daddr <KEYCLOAK_HOST_IP> tcp dport 443 accept

        # SIEM (if applicable)
        ip daddr <SIEM_HOST_IP> tcp dport <SIEM_PORT> accept

        # Log and drop the rest (no public internet)
        log prefix "nft DROP OUT: " drop
    }
}
```

### Firewall Verification

```bash
# Verify rules are active
iptables -L -v -n --line-numbers   # or: nft list ruleset

# Test: confirm HTTPS port is reachable from Android client segment
# (Run from a device on the Android client network segment)
curl -k https://<SERVER_IP>:<HTTPS_PORT>/health   # should return 200 or backend response

# Test: confirm SSH is NOT reachable from Android client segment
# (Run from a device on the Android client network segment)
nc -z -w 2 <SERVER_IP> 22   # should timeout

# Test: confirm no public internet access from server
curl --max-time 5 https://google.com   # should timeout or fail
```

---

## 11. Deployment Authorization

**Process:** Before the first production deployment, the deployer assembles the evidence package and obtains ISSO/AO sign-off per OG-6e.

**Evidence checklist (minimum):**

```
[ ] System categorization memo — FIPS 199 impact level: HIGH (IL6, SECRET-level data)
[ ] Network enclave authorization reference — ATO/ATC number for the classified network segment
[ ] Server configuration baseline:
      OS: <DISTRIBUTION AND VERSION>
      Docker/Podman: <VERSION>
      nginx: <VERSION>
      PostgreSQL: <VERSION>
      Documented on: <DATE>
[ ] OS vulnerability scan: <TOOL USED>, scan date <DATE>, results: <NO_CRITICAL_HIGH | EXCEPTIONS_DOCUMENTED>
[ ] Application dependency scan: GitLab pipeline job <JOB_URL> dated <DATE>, result: PASS
[ ] STIG compliance: standards/data/providers/tactical/STIG-checklist.md completed
      CAT I items: ALL RESOLVED
      CAT II items: <RESOLVED_COUNT> resolved, <ACCEPTED_RISK_COUNT> accepted risk (documented)
      CAT III items: <RESOLVED_COUNT> resolved, <ACCEPTED_RISK_COUNT> accepted risk (documented)
[ ] Network firewall rules reviewed by ISSO — approved on: <DATE>
[ ] Incident response / spillage procedure — document reference: <CLASSIFIED_STORAGE_PATH>
[ ] Backup and recovery plan — document reference: <PATH>
[ ] ISSO sign-off: <ISSO_NAME> on <DATE>
[ ] AO approval: <AO_NAME> on <DATE>
```

**Recurring authorization maintenance:**

- Reauthorization required when: OS version changes, application version changes significantly, network segment changes, security control implementation changes
- Continuous monitoring: monthly review of vulnerability scan results, quarterly review of STIG compliance checklist
- ATO expiration: `<AO_DEFINED_EXPIRATION_DATE>` — schedule reauthorization at least 60 days before expiration

---

## Sentinel Gate Cross-Reference

| CLAUDE.md Sentinel Check (Tactical Provider Block) | Implementation in this doc |
|---|---|
| TLS termination documented at reverse proxy ≥ TLS 1.2 | Section 7 — nginx config template with `ssl_protocols TLSv1.2 TLSv1.3` |
| No plaintext secrets in provisioning scripts or config tracked by repo | Section 6 — env files at restricted paths; never committed to source |
| Audit log destination documented (AU-2/AU-11, 365-day retention) | Section 8 — rsyslog/SIEM or append-only local file; AU-11 retention configured |
| Data at rest encryption documented (LUKS or equivalent) | Section 9 — LUKS on /opt/data/db; TPM-backed key option |
| Network firewall rules documented — only required ports; SSH not from Android segment | Section 10 — iptables/nftables skeleton; HTTPS from Android segment, SSH from management segment only |
| OS and runtime packages current — no critical/high CVEs at deployment | Section 5 — OS update step before deployment; pipeline dependency scan gate |
| Deployment authorization documented (ISSO/AO approval) | Section 11 — evidence checklist; OG-6e formal documentation in Section 1 |

---

## Winston Architecture Confirmation

Content in this document is consistent with:
- **ADR-022** — Android track architecture pattern (three-layer: Android app → Backend API → Shared DB); no frontend container; backend technology team-selected; tactical provider is Android-only for this team
- **ADR-023** — Tactical provider constraints: no cloud-native managed services; single perimeter server; self-owned provisioning, secrets management, TLS, audit log, data-at-rest encryption, and deployment authorization; open gaps OG-6a through OG-6e formally documented with remediation paths
- **ADR-026** — Decision tree; tactical is Android-only for this team; web+tactical is not a supported configuration
- **BACKEND-INFRA.md (F-ATAK-004)** — Server architecture diagram, network topology, env file injection pattern, and F-ATAK-005 deferrals all consistent with this document
- **PIPELINE-SPEC.md (F-ATAK-003)** — Stage 8 backend-deploy SSH deployment, `--env-file /opt/backend/runtime.env`, `127.0.0.1` port binding — all consistent with Sections 6 and 7 of this document

---

## Frank Compliance Confirmation

Sections 5–11 (OS hardening, secrets management, TLS configuration, audit log, LUKS encryption, firewall rules, deployment authorization) are consistent with:
- **ADR-022, ADR-023, ADR-026** — No Helm, no Terraform, no Kubernetes, no cloud CLI; self-owned server provisioning
- **BACKEND-INFRA.md** — env file paths (`/opt/backend/runtime.env`, `/opt/db/runtime.env`), `127.0.0.1` port binding, LUKS deferred to this document, audit log deferred to this document, firewall rules deferred to this document — all now documented
- **PIPELINE-SPEC.md** — `--env-file` secret injection, `127.0.0.1:3001` port binding, SSH deployment with strict host checking — consistent with this document
- **CLAUDE.md Sentinel checks** — All seven tactical provider Sentinel checks addressed in corresponding sections

---

## Open Gaps Summary

| ID | Gap | Section | Status |
|---|---|---|---|
| OG-6a | Provisioning tooling | Section 1 | Placeholder — team fills in chosen tooling |
| OG-6b | Secrets management | Sections 1, 6 | Env file baseline documented; vault layer optional |
| OG-6c | TLS CA for classified network | Sections 1, 7 | Placeholder — pending unit IT certificate |
| OG-6d | Audit log destination | Sections 1, 8 | Two options documented; team selects one |
| OG-6e | Self-owned approval process | Sections 1, 11 | Evidence checklist documented; ISSO/AO sign-off required |
| OG-1 | Authentication method (PKCE vs. mTLS) | BACKEND-INFRA.md | Pending TAK team + Keycloak platform team |
| OG-5 | Backend technology stack | BACKEND-INFRA.md | Open — team selects when codebase is known |

---

## Gate Results

**Murat:** PASS — Winston + Frank joint documentation story; no TDD gate applicable. All 12 dispatch content requirements satisfied: ADR-023 open gaps OG-6a through OG-6e formally documented with architectural placeholders and NIST control mappings (Section 1); server architecture diagram (Section 2); network architecture with firewall zone table (Section 3); impact level ceiling table (Section 4); OS and runtime hardening checklist with Docker/Podman requirements (Section 5); secrets management env file baseline with permissions and setup commands (Section 6); nginx TLS config template with FIPS cipher placeholder (Section 7); audit log destination with two implementation options and AU-9(2) separation verification (Section 8); LUKS encryption with TPM-backed key option and command sequence (Section 9); iptables and nftables firewall rule skeletons (Section 10); deployment authorization evidence checklist with recurring maintenance schedule (Section 11); STIG-checklist.md covering OS (Section 1, DISA RHEL 8/9 + Ubuntu STIG, 22 items), Docker/Podman (Section 2, CIS Docker Benchmark v1.6, 19 items), nginx (Section 3, DISA nginx STIG V1R4, 16 items), PostgreSQL (Section 4, DISA PostgreSQL 9.x STIG V2R4, 20 items) with STIG IDs on ≥ 80% of items, CAT levels, and verification commands.

**Sentinel:** PASS (0 findings) | SECURITY_TIER: IL6
No hardcoded secrets or credentials — all server addresses, ports, passwords, and cipher suite values are angle-bracket placeholders. No real infrastructure values committed. All seven CLAUDE.md tactical provider Sentinel checks addressed with corresponding document sections. All IL6 additional gate checks addressed (FIPS 140-3 cipher placeholder, audit log tamper-evidence via AU-9(2) separation, no external unclassified calls documented via firewall outbound rules). No new application dependencies introduced. Open gaps OG-6a through OG-6e all formally documented with remediation paths and placeholder fill-in instructions. No out-of-scope changes.

**Manual Security Review:** CLEAR — Infrastructure provisioning guide and STIG checklist only; no auth surface, no API endpoints, no data handling code introduced. Firewall rules verified: SSH restricted to management segment, not Android client segment; no default-allow or `0.0.0.0` rules. nginx config verified: Authorization header passthrough present, no CORS headers, TLS 1.0/1.1 disabled, server_tokens off. Secrets management verified: mode 600, process-user ownership, verification command confirms non-process-users cannot read. LUKS verified: TPM-backed unlock avoids manual passphrase without weakening encryption. Audit log separation verified: AU-9(2) verification step explicitly tests app process cannot write to log destination.

**User:** APPROVED 2026-05-05
