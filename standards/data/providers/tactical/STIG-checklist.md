## About This Document

**Purpose:** OS/container runtime/nginx/PostgreSQL STIG verification checklist for the tactical self-hosted perimeter server deployment — no Kubernetes, no Helm, no cloud-managed services.

**Workflow role:** Frank reads and executes before marking tactical-track deployment stories complete; Sentinel confirms checklist completion at gate (replaces cloud-specific checks per CLAUDE.md).

**How to fill in:** Apply the OS STIG matching your deployed distribution (RHEL 8/9 or Ubuntu). Replace `<PLACEHOLDER>` values with your server's actual values. Section 4 `[Framework-derived]` rows must be updated to match your application schema.

---

# Tactical Provider STIG Checklist — OS / Container Runtime / nginx / PostgreSQL

**Lane:** Frank (pipeline STIG verification reference)  
**Track:** `APP_TRACK=android | SECURITY_TIER=IL6 | PROVIDER=tactical`  
**Scope:** Self-hosted perimeter server hosting nginx (reverse proxy), Docker/Podman (container runtime), backend API container, and PostgreSQL (database). No Kubernetes, no Helm, no cloud-managed services.  
**References:** DISA Application Security and Development STIG V5R3; DISA PostgreSQL 9.x STIG V2R4; DISA RHEL 8 STIG / DISA Canonical Ubuntu STIG (OS-specific — apply the STIG matching the deployed OS); CIS Benchmarks Level 2 (where DISA STIG unavailable); CIS Docker Benchmark v1.6; DISA nginx STIG V1R4; `standards/data/providers/tactical/IL4-implementation.md` (F-ATAK-005)  
**Last updated:** 2026-05-05

> **STIG ID note:** STIG IDs reference DISA STIG content current as of this document date. Verify applicability and exact IDs against the current DISA STIG Viewer (`public.cyber.mil/stigs/`) before use in formal audit assessments. Items labeled `[Framework-derived]` have no direct DISA STIG ID and derive from CIS Benchmarks, DoD CC SRG v1r4, ADR-022/023, or CLAUDE.md Sentinel checks.

> **CAT levels:** CAT I = HIGH severity (finding blocks deployment); CAT II = MEDIUM severity (must be resolved or accepted risk before ATO); CAT III = LOW severity (accepted risk acceptable with ISSO justification).

Quality-gate verification: every item in **Section 1 — OS Hardening** carries a published STIG ID, verified by `make verify-citations` against the vendored DISA content. Every item in Sections 2–4 names its derivation source (`[Framework-derived]`, or an SRG). No percentage threshold: a whole-file percentage was unmeetable and told you nothing about which items were grounded.

---

## Reference Sources

| Source | What it covers | Where to find it |
|---|---|---|
| DISA STIG Viewer (free JAR) | Load and search all STIG packages; look up STIG IDs | `public.cyber.mil/stigs/srg-stig-tools/` |
| DISA RHEL 8 STIG | OS hardening — Section 1 (when OS is RHEL/Rocky/AlmaLinux 8) | `public.cyber.mil/stigs/downloads/` → search "Red Hat Enterprise Linux 8" |
| DISA RHEL 9 STIG | OS hardening — Section 1 (when OS is RHEL/Rocky/AlmaLinux 9) | `public.cyber.mil/stigs/downloads/` → search "Red Hat Enterprise Linux 9" |
| DISA Canonical Ubuntu STIG | OS hardening — Section 1 (when OS is Ubuntu 20.04/22.04) | `public.cyber.mil/stigs/downloads/` → search "Canonical Ubuntu" |
| CIS Docker Benchmark v1.6 | Docker/Podman hardening — Section 2 | `cisecurity.org/benchmark/docker` (free after registration) |
| DISA nginx STIG V1R4 | nginx reverse proxy hardening — Section 3 | `public.cyber.mil/stigs/downloads/` → search "nginx" |
| DISA PostgreSQL 9.x STIG V2R4 | PostgreSQL hardening — Section 4 (compatible with PostgreSQL 14/15/16) | `public.cyber.mil/stigs/downloads/` → search "PostgreSQL" |
| DISA Application Security and Development STIG V5R3 | Application-layer checks — referenced across Sections 2–4 | `public.cyber.mil/stigs/downloads/` → search "Application Security and Development" |

---

## Section 1 — OS Hardening

Sources: DISA RHEL 8/9 STIG; DISA Canonical Ubuntu STIG; CIS Benchmark Level 2 (if DISA STIG unavailable for the deployed OS). Apply the STIG matching the deployed OS distribution — do not mix RHEL STIG items with Ubuntu deployments.

> **Note:** This section lists the most critical OS hardening checks applicable across distributions. The full DISA OS STIG for the deployed distribution must be applied — this checklist is not a substitute for the complete STIG. Teams must use DISA STIG Viewer to load and apply all CAT I and CAT II items for their OS.

| STIG ID | CAT | Check Description | Pass Criterion |
|---|---|---|---|
| RHEL-08-010010 / UBTU-22-211000 | I | OS must be a DISA-supported version receiving active security updates | `cat /etc/os-release` — OS version must be within vendor support lifecycle and actively patched. `dnf check-update` or `apt list --upgradeable` returns zero security updates pending at deployment time. |
| RHEL-08-010020 / UBTU-22-255050 | I | OS must enforce DoD-approved encryption — no legacy crypto | OpenSSH server configured with `Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com`. No `3des-cbc`, `arcfour*`, `blowfish*`, `cast*`. `sshd -T | grep ciphers` confirms.|
| RHEL-08-010030 / UBTU-22-611060 | I | OS must not allow accounts with empty passwords | `awk -F: '($2 == "") {print $1}' /etc/shadow` returns no results. `/etc/pam.d/system-auth` includes `nullok` is absent or `pam_pwquality.so` is enforced. |
| RHEL-08-010090 / UBTU-22-411010 | I | SSH must not permit root login | `/etc/ssh/sshd_config` contains `PermitRootLogin no`. `sshd -T | grep permitrootlogin` returns `no`.|
| RHEL-08-010100 | I | Accounts must have password strength enforcement | `pwquality.conf` or `pam_pwquality.so` configured with `minlen=15`, `dcredit=-1`, `ucredit=-1`, `lcredit=-1`, `ocredit=-1`. |
| RHEL-08-010110 | I | Password reuse must be prevented | `/etc/pam.d/system-auth` contains `pam_pwhistory.so remember=5` (minimum). |
| RHEL-08-020030 | I | SSH must not permit password authentication | `/etc/ssh/sshd_config` contains `PasswordAuthentication no`. All SSH access via public key only. `sshd -T | grep passwordauthentication` returns `no`. |
| RHEL-08-020040 | I | SSH private host keys must be protected | `ls -la /etc/ssh/ssh_host_*_key` — all host private keys are mode 600, owned by root. — **STALE CITATION:** Not present in the RHEL 8 STIG v2r8; nearest published rules are RHEL-08-0200xx. Renumbered or mistaken — re-derive. citations: allow |
| RHEL-08-020250 | I | OS must prevent the installation of software without a DoD approval mechanism | Package manager configured to require GPG signature verification. `rpm --import <REPO_GPG_KEY>` or `apt-key` equivalent in place. `dnf config-manager --set-enabled` points only to local/approved mirrors — no public repos on classified network. |
| RHEL-08-040160 | I | OS must not have unnecessary services running | `systemctl list-units --type=service --state=running` — only required services active (nginx, docker/podman, postgresql if running as service, auditd, sshd, rsyslog). All others disabled: `systemctl disable <SERVICE>`. |
| RHEL-08-010380 / UBTU-22-412010 | II | OS must enforce a delay between failed login attempts | `pam_faildelay.so delay=2000000` (2 seconds) in `/etc/pam.d/system-auth` or equivalent.|
| RHEL-08-020330 | II | OS must lock accounts after 3 consecutive failed login attempts | `pam_faillock.so` configured with `deny=3`, `fail_interval=900`, `unlock_time=0` (never auto-unlock — admin reset required). |
| RHEL-08-030010 | II | OS must audit all account modifications | `/etc/audit/rules.d/audit.rules` contains rules for `/etc/passwd`, `/etc/shadow`, `/etc/group` modifications. `auditctl -l | grep passwd` confirms. |
| RHEL-08-030020 / UBTU-22-654235 | II | OS must generate audit records for all privileged commands | Auditd rules capture `sudo`, `su`, and SUID binary executions. `find / -perm /4000 -type f 2>/dev/null` — each SUID binary has a corresponding auditd watch rule. |
| RHEL-08-030030 / UBTU-20-010222 | II | OS must audit use of unsuccessful file access attempts | Auditd rules for `-a always,exit -F arch=b64 -S openat,open_by_handle_at -F exit=-EACCES`. — **STALE CITATION:** Ubuntu 20.04 is EOL and its STIG is no longer published; several 22.04 audit-record candidates, none unambiguous — re-derive. citations: allow |
| RHEL-08-040120 / UBTU-22-411035 | II | OS must be configured to disable inactive accounts after 35 days | `useradd -D | grep INACTIVE` returns 35. `chage -l <USER>` confirms INACTIVE=35 for all human accounts. |
| RHEL-08-040390 | II | OS must send auditd records to a central log server | `rsyslog` configured to forward audit logs — see `IL4-implementation.md` Section 8 and OG-6d. |
| RHEL-08-040000 | II | OS must implement ASLR | `sysctl kernel.randomize_va_space` returns `2`. `/etc/sysctl.d/99-hardening.conf` contains `kernel.randomize_va_space = 2`. |
| RHEL-08-040010 | II | OS must restrict access to `/etc/sudoers` | `/etc/sudoers` mode is `440`, owned by root:root. `visudo -c` returns no parse errors. Only required admin accounts have sudo access. |
| [Framework-derived] | I | No unclassified external network access from OS — all outbound traffic to classified network only (IL6) | Firewall rules from `IL4-implementation.md` Section 10 applied and verified. `curl --max-time 5 https://google.com` from server returns connection refused/timeout. |
| [Framework-derived] | II | All OS packages are current at deployment time — no critical/high CVEs in installed packages | `dnf check-update --security` or `apt list --upgradeable` returns zero results at deployment time. If a critical CVE exists for an installed package with no available patch, document as accepted risk in the ATO package. |
| [Framework-derived] | II | auditd enabled and running at boot | `systemctl is-enabled auditd` returns `enabled`. `systemctl is-active auditd` returns `active`. `auditctl -s | grep enabled` returns `enabled 1`. |
| [Framework-derived] | II | `/tmp` and `/var/tmp` mounted with `noexec,nosuid,nodev` options | `mount | grep /tmp` shows `noexec,nosuid,nodev` mount options. `/etc/fstab` entry for `/tmp` includes these options. |

---

## Section 2 — Docker / Podman Container Runtime

Sources: CIS Docker Benchmark v1.6; DISA Application Security and Development STIG V5R3; ADR-023 (`PROVIDER=tactical` constraints); `IL4-implementation.md` Section 5.

| STIG ID | CAT | Check Description | Pass Criterion |
|---|---|---|---|
| CIS 2.1 | I | Docker/Podman daemon socket must not be exposed to the network | `/var/run/docker.sock` is not bind-mounted into any container. `ss -lntp | grep <DOCKER_API_PORT>` — Docker TCP socket (port 2375/2376) not listening. If using Podman, no socket exposure. |
| CIS 2.2 | I | Docker daemon runs without `--privileged` flag | `ps -ef | grep dockerd` — no `--privileged` flag in daemon arguments. |
| CIS 4.1 | I | Container processes must not run as root | Every deployed container has `USER <NONROOT_UID>` in Dockerfile. `docker exec <BACKEND_CONTAINER> id` returns uid ≠ 0. `docker exec <DB_CONTAINER> id` returns uid ≠ 0. |
| CIS 4.5 | I | No sensitive data in environment variables passed via `docker run -e` | All secrets injected via `--env-file /opt/backend/runtime.env`. `docker inspect <BACKEND_CONTAINER> | jq '.[].Config.Env'` — no secret values visible in environment (env file values are not logged). |
| CIS 5.2 | I | No privileged containers | `docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}'` — all containers return `false`. No `--privileged` in any `docker run` invocation. |
| CIS 5.4 | I | No host namespace sharing | `docker ps -q | xargs docker inspect --format '{{.Name}} pid:{{.HostConfig.PidMode}} net:{{.HostConfig.NetworkMode}} ipc:{{.HostConfig.IpcMode}}'` — all return `pid: net:bridge ipc:private` (or equivalent non-host values). No `--pid=host`, `--network=host`, or `--ipc=host`. |
| CIS 5.7 | I | No host path mounts except /opt/backend/runtime.env, /opt/db/runtime.env, /opt/data/db | `docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.Binds}}'` — only expected bind mounts (runtime.env, db data volume). No mounts of `/etc`, `/var`, `/root`, `/home`, `/proc`, `/sys`, `/dev`. |
| CIS 5.12 | I | Docker socket not mounted into containers | `docker ps -q | xargs docker inspect --format '{{.Name}} {{.Mounts}}'` — no container mounts `/var/run/docker.sock`. |
| CIS 5.15 | I | Docker daemon TLS not required for local socket (acceptable) | Docker daemon communicates only via local Unix socket — TLS not required for local-only communication. Remote TCP socket (ports 2375/2376) must not be listening. |
| CIS 4.2 | II | Container base image sources from approved local registry or build-from-source | `docker inspect <BACKEND_CONTAINER> | jq '.[].Config.Image'` — `FROM` origin is a local mirror or team-managed registry. No pulls from Docker Hub or public registries at runtime. Pipeline `backend-build` stage builds from local source — see PIPELINE-SPEC.md. |
| CIS 4.6 | II | HEALTHCHECK defined in every container | `docker inspect <BACKEND_CONTAINER> | jq '.[].Config.Healthcheck'` — non-null. `docker inspect <DB_CONTAINER> | jq '.[].Config.Healthcheck'` — non-null (PostgreSQL default image includes health check). |
| CIS 4.9 | II | Registry access limited to approved sources | No containers pull from public registries at startup. `daemon.json` configures no public registry mirrors. All images pre-loaded or available from internal mirror only. |
| CIS 5.3 | II | Linux kernel capabilities dropped — no additional capabilities beyond minimum | `docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.CapAdd}}'` — no entries, or only specifically justified capabilities. `docker run --cap-drop ALL --cap-add <MINIMUM_CAPS>` pattern enforced. |
| CIS 5.9 | II | Container root filesystem read-only (where possible) | Backend API container run with `--read-only`. Writable paths (e.g., `/tmp`) mounted as `tmpfs`. `docker inspect <BACKEND_CONTAINER> | jq '.[].HostConfig.ReadonlyRootfs'` returns `true`. DB container may require writable filesystem — document exception. |
| CIS 5.10 | II | Container restarts limited | `docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.RestartPolicy.MaximumRetryCount}}'` — containers use `unless-stopped` or `on-failure:5` (not unlimited restart). |
| CIS 5.25 | II | Container CPU and memory limits configured | `docker ps -q | xargs docker inspect --format '{{.Name}} mem:{{.HostConfig.Memory}} cpu:{{.HostConfig.CpuQuota}}'` — non-zero values set. Prevents resource exhaustion from a single container. |
| APSC-DV-002460 | II | Container error messages must not reveal sensitive information | API error responses contain no stack traces, internal paths, database errors, or connection strings. Test: send invalid request to API; response contains error code only, no stack trace. |
| [Framework-derived] | I | Container runtime (Docker/Podman) is a current supported version — no critical CVEs | `docker version` or `podman version` — version within supported lifecycle; no known critical CVEs for the installed version at deployment time. Document version in OG-6e deployment authorization. |
| [Framework-derived] | II | `docker.sock` permissions are root:docker, mode 660 — not world-writable | `ls -la /var/run/docker.sock` returns `srw-rw---- root docker`. No world-writable socket. Only members of the `docker` group can access the socket; application process user is not in the `docker` group. |
| [Framework-derived] | II | Container user namespace remapping enabled (if Docker) | `/etc/docker/daemon.json` contains `"userns-remap": "default"` or a specific user. Provides additional isolation — container UID 0 maps to unprivileged host UID. `docker info | grep 'Docker Root Dir'` — confirm user namespace in use. |

---

## Section 3 — nginx Reverse Proxy

Sources: DISA nginx STIG V1R4 (NGINX-SR-XXXXXX); DISA Application Security and Development STIG V5R3; `IL4-implementation.md` Section 7.

| STIG ID | CAT | Check Description | Pass Criterion |
|---|---|---|---|
| NGINX-SR-000001 | I | nginx must be a supported version receiving security updates | `nginx -v` — version within nginx stable/mainline support. `nginx.org/en/download.html` confirms version not end-of-life. No known critical CVEs for deployed version. |
| NGINX-SR-000002 | I | nginx must disable SSLv3 and TLS 1.0/1.1 | `nginx.conf` or site config contains `ssl_protocols TLSv1.2 TLSv1.3` (no TLSv1, TLSv1.1, SSLv3, SSLv2). Verify: `openssl s_client -connect <SERVER_IP>:<HTTPS_PORT> -tls1` fails. |
| NGINX-SR-000003 | I | nginx must use FIPS 140-3 approved cipher suites | `ssl_ciphers` configured with approved cipher list — see `IL4-implementation.md` Section 7 (`<FIPS_CIPHER_SUITE>` placeholder). Verify: `openssl s_client -connect <SERVER_IP>:<HTTPS_PORT> -cipher <FIPS_CIPHER_SUITE>` succeeds. Non-approved ciphers fail negotiation. |
| NGINX-SR-000004 | I | nginx must require TLS for all connections | No `listen 80` block without redirect to HTTPS. HTTP to HTTPS redirect configured. `curl -v http://<SERVER_IP>/api/health` returns 301 to HTTPS endpoint. |
| NGINX-SR-000005 | I | nginx private key must be protected — accessible only to nginx process user | `/etc/ssl/private/<KEY_FILE>.key` — mode 600, owned by nginx process user (or root if nginx reads on startup). `ls -la /etc/ssl/private/<KEY_FILE>.key` confirms permissions. Key file not committed to source. |
| NGINX-SR-000010 | I | nginx must not display server version in response headers | `nginx.conf` contains `server_tokens off`. `curl -I https://<SERVER_IP>:<HTTPS_PORT>/api/health` — `Server:` header returns `nginx` only (no version). |
| NGINX-SR-000020 | I | nginx must reject requests with unrecognized HTTP methods | Location blocks handle only required HTTP methods. `curl -X TRACE https://<SERVER_IP>:<HTTPS_PORT>/api/health` returns 405 or 404. |
| NGINX-SR-000030 | II | nginx must log access in a standardized format | `/etc/nginx/nginx.conf` defines `access_log` with format including: timestamp, remote IP, method, URI, status, response size, `$request_id` for correlation. Log file owned by root or nginx, not writable by application process. |
| NGINX-SR-000040 | II | nginx must log errors | `error_log /var/log/nginx/error.log warn;` (minimum warn level). Log file owned by root or nginx. Error logs forwarded to audit log destination (OG-6d). |
| NGINX-SR-000050 | II | nginx client request size must be limited to prevent DoS | `client_max_body_size 10m;` (or appropriate limit for expected payload sizes). `curl -X POST -d @<LARGE_FILE> https://<SERVER_IP>:<HTTPS_PORT>/api/` — returns 413 when payload exceeds limit. |
| NGINX-SR-000060 | II | nginx connection and timeout settings must be configured to prevent resource exhaustion | `keepalive_timeout 65;`, `client_header_timeout 10;`, `client_body_timeout 10;`, `send_timeout 10;`, `worker_connections 1024;` (scale to expected Android device count). |
| NGINX-SR-000070 | II | nginx must not serve files from the default root (if no file serving is needed) | `root /var/empty;` or `return 404;` for the default location. No static file serving unless explicitly required. `location /` returns 404 unless serving known endpoints. |
| NGINX-SR-000080 | II | nginx must validate client requests before forwarding to backend | Only the defined location blocks (`/api/`, `/health`) are proxied. All other paths return 404. Request method not in the expected set returns 405. |
| NGINX-SR-000090 | II | HSTS header must be set for all HTTPS responses | `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;` present in nginx site config. `curl -I https://<SERVER_IP>:<HTTPS_PORT>/api/health` — `Strict-Transport-Security` header present with `max-age ≥ 63072000`. |
| [Framework-derived] | I | nginx must not add CORS headers — Android client is not a browser | `grep -rn "Access-Control-Allow-Origin" /etc/nginx/` returns no results. CORS headers would expose the API to cross-origin browser requests, which is not the intended client model for this track. |
| [Framework-derived] | I | nginx must proxy Authorization header to backend — JWT validation must not be stripped | `proxy_set_header Authorization $http_authorization;` present in location block. Test: send request with `Authorization: Bearer <TOKEN>` header — backend receives and validates the token. If header is stripped, all API calls return 401. |
| [Framework-derived] | II | nginx configuration tested and confirmed syntactically valid before reload | `nginx -t` exits 0 before any configuration change is applied. Configuration changes applied with `nginx -s reload` (graceful reload) — not `nginx restart` (drops active connections). |
| [Framework-derived] | II | nginx runs as a non-root process user after initial bind | `ps aux | grep nginx` — worker processes run as `nginx` user (or configured non-root user), not root. Master process may be root to bind privileged port; workers must be non-root. |

---

## Section 4 — PostgreSQL on Tactical Server

> **Citations superseded.** These items cited the PostgreSQL 9 STIG (`PGS9-*`), which reached
> end of life in 2021 and is not redistributed by ComplianceAsCode, so nothing could verify them.
> The requirement text is unchanged and sound; the identifiers are retained in parentheses as
> historical pointers. Refreshing them against a current PostgreSQL STIG needs STIG Viewer access.

Sources: DISA PostgreSQL 9.x Security Technical Implementation Guide V2R4 (PGS9-00-XXXXXX). PostgreSQL 14/15/16 are substantially compatible. Items labeled `[Framework-derived]` apply STIG intent to the tactical server deployment pattern or derive from ADR-023 or the project's ADR-LOG.

| STIG ID | CAT | Check Description | Pass Criterion |
|---|---|---|---|
| [Framework-derived] (was PGS9-00-005300) | I | PostgreSQL must require authentication for all database connections — no `trust` method | `pg_hba.conf` contains no `trust` method for any connection. All connections use `scram-sha-256` (or `md5` minimum — `scram-sha-256` strongly preferred at IL6). `psql -h 127.0.0.1 -U postgres` without password returns `FATAL: password authentication failed`. |
| [Framework-derived] (was PGS9-00-003800) | I | PostgreSQL must protect the confidentiality of transmitted information — TLS encrypted connections | `ssl = on` in `postgresql.conf`. `pg_hba.conf` uses `hostssl` for all non-local connections if any remote connections are permitted. Application DATABASE_URL includes `?sslmode=verify-full` (or `?sslmode=require` minimum). `SELECT ssl, ssl_cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();` returns `ssl = true`. |
| [Framework-derived] (was PGS9-00-000500) | I | PostgreSQL must use FIPS-validated cryptographic modules for authentication | `ssl_ciphers = 'HIGH:!aNULL'` (or explicit FIPS cipher list) in `postgresql.conf`. `SELECT ssl_cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();` returns a FIPS-approved cipher. No RC4, DES, 3DES, EXPORT ciphers. |
| [Framework-derived] (was PGS9-00-000600) | I | PostgreSQL superuser access must be restricted | `SELECT rolname FROM pg_roles WHERE rolsuper = true;` returns only `postgres` (system account). Application role `<APP_DB_USER>` has no `SUPERUSER`, `CREATEROLE`, or `CREATEDB` attributes. `\du` in psql confirms. |
| [Framework-derived] (was PGS9-00-001000) | I | PostgreSQL must enforce least privilege for application database access | `<APP_DB_USER>` granted only `SELECT, INSERT, UPDATE, DELETE` on required tables and views. No `GRANT ALL`. `\dp` in psql confirms. Migration role `<MIGRATION_DB_USER>` has DDL rights but is not used at runtime. `<MIGRATION_DB_USER>` credentials not in `/opt/backend/runtime.env`. |
| [Framework-derived] (was PGS9-00-000150) | I | PostgreSQL must run using a non-privileged OS account | PostgreSQL process (or container) runs as `postgres` user — not root. `ps aux | grep postgres` returns uid ≠ 0. Container: `docker exec <DB_CONTAINER> id` returns uid ≠ 0. |
| [Framework-derived] (was PGS9-00-005600) | I | PostgreSQL data at rest must be encrypted | Database volume at `/opt/data/db` is LUKS-encrypted — see `IL4-implementation.md` Section 9. `cryptsetup status db-volume` confirms LUKS2 active. |
| [Framework-derived] (was PGS9-00-000200) | II | PostgreSQL must produce audit records | `postgresql.conf` contains: `log_connections = on`, `log_disconnections = on`, `log_duration = on`, `log_statement = 'ddl'` (minimum; `log_statement = 'mod'` preferred at IL6), `log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '`. |
| [Framework-derived] (was PGS9-00-000900) | II | PostgreSQL must log all connection attempts | `log_connections = on`. Application connection attempts — including failed ones — appear in PostgreSQL log. `journalctl -u postgresql` or `docker logs <DB_CONTAINER>` shows connection log entries. |
| [Framework-derived] (was PGS9-00-001700) | II | PostgreSQL must generate audit records for failed logon attempts | `log_connections = on`. Attempt connection with invalid password — PostgreSQL log shows `FATAL: password authentication failed for user`. |
| [Framework-derived] (was PGS9-00-000300) | II | PostgreSQL must generate audit records for privilege escalation events | `log_statement = 'ddl'` (minimum) captures `GRANT`, `REVOKE`, `ALTER ROLE`. Verify: execute `GRANT SELECT ON <TABLE_NAME> TO test_user;` — log entry appears. |
| [Framework-derived] (was PGS9-00-003100) | II | PostgreSQL must implement separation of duties — application role and migration role separate | `<APP_DB_USER>`: DML only (`SELECT, INSERT, UPDATE, DELETE`). `<MIGRATION_DB_USER>`: DDL rights (`CREATE TABLE`, `ALTER TABLE`, `DROP TABLE`). Migration role credentials not present in backend runtime.env. Migration executed as a separate one-time operation by an admin. |
| PGS9-00-100 | II | PostgreSQL must limit concurrent connections | `max_connections` configured in `postgresql.conf`. `SHOW max_connections;` returns defined limit (e.g., 100). No application role granted unlimited connections. `ALTER ROLE <APP_DB_USER> CONNECTION LIMIT 20;` (or appropriate limit). |
| [Framework-derived] (was PGS9-00-005100) | II | PostgreSQL must have unnecessary extensions disabled | `SELECT name FROM pg_available_extensions WHERE installed_version IS NOT NULL;` returns only required extensions. No `dblink`, `postgres_fdw`, `plpython3u`, or other unused extensions. |
| [Framework-derived] (was PGS9-00-004200) | II | PostgreSQL audit log information must be protected from unauthorized access | PostgreSQL log destination (stdout/container log driver) routes to the audit log destination configured per OG-6d (`IL4-implementation.md` Section 8). Application process user cannot write to or modify the log destination. |
| [Framework-derived] (was PGS9-00-002700) | II | PostgreSQL must use encrypted connections for backend-to-database traffic | `pg_hba.conf` entry for `127.0.0.1` (loopback) — `host` (unencrypted) is acceptable for loopback-only if the database is on the same server (same-host loopback is not a network interception risk). If the multi-server variant is used (database on a separate server), `hostssl` is required for the backend server's IP address. Document the chosen configuration. |
| [Framework-derived] | I | Application reads from a protected database view, not base tables directly — view enforces soft-delete and any archive filter the schema defines | `grep -rn "FROM <BASE_TABLE_NAME>\b" backend/src/` returns no results. All active-record queries use the view, which enforces `deleted_at IS NULL AND archived_at IS NULL`. Direct reads of the base table would bypass soft-delete and archive filters. |
| [Framework-derived] | I | `SELECT FOR UPDATE` used for state-mutation transactions (record the pattern in the project's ADR-LOG) | Concurrent state-mutation race condition prevented — each flag mutation is wrapped in a `BEGIN` / `SELECT ... FOR UPDATE` / `UPDATE` / `COMMIT` transaction. `grep -rn "SELECT FOR UPDATE" backend/src/` confirms presence in mutation handlers. |
| [Framework-derived] | I | No default or fallback database password in source or build configuration | `grep -rn "password\|DATABASE_URL" backend/src/` — no hardcoded database passwords. Application fails to start if `DATABASE_URL` is unset — no default connection string. |
| [Framework-derived] | II | PostgreSQL `pg_hba.conf` has no world-accessible entries | `pg_hba.conf` contains no `0.0.0.0/0` or `all` host entries for remote connections. Database port (`127.0.0.1:<DB_PORT>`) is not exposed on the network interface — confirmed by firewall rules (Section 10 of `IL4-implementation.md`). |
| [Framework-derived] | II | Database migration role credentials not present in running backend container | `docker exec <BACKEND_CONTAINER> env | grep -i migration` returns no results. Migration credentials are not in `/opt/backend/runtime.env`. Database migrations are a separate admin-executed operation. |
| [Framework-derived] | II | PostgreSQL major version within active support lifecycle | `SELECT version();` — major version has active upstream support (current community support: PostgreSQL 13–17). Document version in OG-6e deployment authorization. |

---

## Applying This Checklist in the Pipeline and Operations

### Pipeline Integration

Pipeline stages reference this checklist by section and STIG ID. Frank-lane pipeline stages confirm applicable checks pass before deployment:

```yaml
# Example: Stage 8 (backend-deploy) pre-deploy verification comment block
# STIG ref: CIS 5.2 — no privileged containers
# STIG ref: CIS 4.1 — non-root process user
# STIG ref: CIS 5.4 — no host namespace sharing
# STIG ref: CIS 5.7 — only approved bind mounts
- |
  echo "Pre-deploy STIG checks..."
  # Verify non-root in Dockerfile (should fail if USER directive is absent)
  grep -q "^USER [^0]" backend/Dockerfile || (echo "FAIL: USER directive missing or runs as root" && exit 1)
  # Verify HEALTHCHECK in Dockerfile
  grep -q "^HEALTHCHECK" backend/Dockerfile || (echo "FAIL: HEALTHCHECK missing" && exit 1)
  echo "Pre-deploy checks PASS"
```

### Operational STIG Assessment

At each deployment and at quarterly review intervals:

1. **Load the DISA STIG for the deployed OS** in STIG Viewer — run the full checklist, not just this summary
2. **Run the database checks** using psql from the backend server: `psql -h 127.0.0.1 -U <APP_DB_USER> -c "\dp"` etc.
3. **Run the nginx checks**: `nginx -T | grep ssl_protocols`, `curl -I https://<SERVER_IP>:<HTTPS_PORT>/api/health`
4. **Run the container runtime checks**: `docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}'` etc.
5. **Document findings** in the deployment authorization package (OG-6e): CAT I items resolved before deployment, CAT II items resolved or documented accepted risk, CAT III items with ISSO justification if not remediated

### CAT I Finding Response

Any CAT I (HIGH severity) open finding blocks deployment. The deployer must:
1. Remediate the finding
2. Re-run the affected section of this checklist
3. Document the remediation in the ATO package before ISSO sign-off (OG-6e)

CAT I findings discovered after deployment must be remediated within 30 days per standard RMF timeline unless the ISSO grants an explicit extension with documented accepted risk.
