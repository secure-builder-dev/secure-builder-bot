## About This Document

**Purpose:** Backend infrastructure guide for the Android track — covers self-hosted tactical server provisioning, hardening, and network configuration supporting the Android client.

**Workflow role:** Frank reads when provisioning or modifying backend infrastructure for the Android track; Winston reads when reviewing tactical architecture decisions.

**How to fill in:** No customization required for framework content. Deployment-specific values (server IPs, storage paths, network ranges) are documented in team-managed provisioning documents outside this repo.

---

# Android Track Backend Infrastructure Guide

**Lane:** Frank  
**Track:** `APP_TRACK=android | SECURITY_TIER=IL6 | PROVIDER=tactical`  
**Last updated:** 2026-05-05  
**Grounded in:** ADR-022 (Android track architecture pattern), ADR-023 (tactical provider constraints), ADR-026 (decision tree; APP_TYPE), CLAUDE.md Sentinel checks, `standards/data/providers/android/PIPELINE-SPEC.md` (F-ATAK-003), `standards/data/controls/IL4-baseline.md`, `standards/data/controls/IL6-delta.md`

> **PROVIDER=tactical constraint:** No cloud-native managed services. No Secrets Manager, no Key Vault, no managed database, no Amazon ECR, no AKS/EKS, no Helm, no Terraform. The backend API and database run on a team-owned classified perimeter server. All provisioning specifics (OS hardening, secrets management, audit log destination) are deferred to `standards/data/providers/tactical/` (F-ATAK-005).

> **OG-5 OPEN GAP:** Backend technology stack (language, framework) is team-selected at project initialization. This document describes the architecture pattern and security contract — not the specific stack. When the backend stack is confirmed (e.g., by opening the legacy codebase per ADR-022 OG-5), the team updates this document with the concrete framework and runtime.

---

## Architecture Pattern

```
Android App (Kotlin / MVVM)
  │  APP_TYPE=atak: runs inside ATAK platform
  │  APP_TYPE=native: standalone app on device
  │
  │  HTTPS + Authorization: Bearer <token>
  │  TLS 1.2 minimum (TLS 1.3 preferred)
  │  All API calls authenticated — no unauthenticated endpoints
  │
  ▼
Reverse Proxy (nginx or equivalent)
  │  TLS termination — handles classified network certificate
  │  Forwards plain HTTP to 127.0.0.1:<PORT>
  │  No direct public or Android-device access to backend port
  │
  ▼
Backend API (team-selected stack)
  │  Bound to 127.0.0.1:<PORT> — loopback only
  │  Validates JWT on every request (Authorization: Bearer)
  │  JWKS cached locally — no live Keycloak call per request
  │  Returns classification banner header on every response (IL6 — SC-16)
  │
  ▼
Shared Database (PostgreSQL or equivalent)
  │  Runs on the perimeter server (same server or separate server on perimeter network)
  │  Connection string injected via runtime env file — not committed to source
  │  Data at rest encryption required (LUKS or equivalent — F-ATAK-005 specifics)
  │  No managed cloud database — self-hosted, team-maintained
  │
  ▼  (audit path)
Audit Log Destination (separate from application process)
  │  See IL6-implementation.md AU-9(2) and F-ATAK-005 for tactical provider specifics [OG-6d TBD]
```

**No frontend container. No Kubernetes Ingress resource. No Helm chart. No cloud load balancer.** The Android app is the only client layer. There is no web browser client and no nginx frontend serving a React SPA on the Android track.

---

## What Does Not Exist on This Track

The following components are present on the `APP_TRACK=web` track and are **explicitly absent** on `APP_TRACK=android`:

| Component | Web Track | Android Track |
|---|---|---|
| React SPA frontend | Present | Absent — Android app is the client |
| nginx frontend container | Present | Absent |
| Kubernetes Ingress | Present | Absent |
| Helm chart | Present | Absent |
| AWS EKS / Azure AKS | Present | Absent |
| AWS Secrets Manager / Azure Key Vault | Present | Absent — secrets management per OG-6b |
| Amazon ECR / Azure Container Registry | Present | Absent — local mirror or build-from-source |
| Approved-registry base images | Chainguard primary (ADR-034) | Absent — no registry access on PROVIDER=tactical |

All of these are replaced by self-managed equivalents on the perimeter server. See ADR-023 for the full cloud-native → tactical substitution table.

---

## Backend API — Deployment Pattern

### Runtime Container

The backend API runs as a Docker or Podman container on the perimeter server. Container runtime is team-selected — document the choice in `standards/data/providers/tactical/IL4-implementation.md` (F-ATAK-005).

```
# How the container runs on the perimeter server (from PIPELINE-SPEC.md stage 8)
docker run -d \
  --name backend-api \
  --restart unless-stopped \
  --env-file /opt/backend/runtime.env \
  -p 127.0.0.1:<PORT>:<PORT> \
  backend-api:<GIT_SHA>
```

Key constraints:
- Port is bound to `127.0.0.1` — not to `0.0.0.0`. The backend is **not** directly reachable from the Android client network segment. All inbound requests go through the reverse proxy.
- `--env-file /opt/backend/runtime.env` injects runtime secrets. The env file lives on the server at a restricted-permission path, pre-placed by an administrator. It is never committed to source. See ADR-023 OG-6b for secrets management approach.
- `--restart unless-stopped` ensures the container restarts after server reboot.

### Backend Image Build

The pipeline builds the backend image in the `backend-build` stage (PIPELINE-SPEC.md stage 7). The base image must be sourced from the local mirror or team-managed registry on the classified network — not from Docker Hub or any public registry.

```dockerfile
# backend/Dockerfile requirements
# Base image: from local mirror or team-managed registry on classified network
# FROM <LOCAL_REGISTRY>/base-image:tag

USER nonroot          # non-root process user
HEALTHCHECK ...       # health endpoint required
# No secrets in Dockerfile or build args — all injected via runtime.env at deploy time
```

### Process-Based Alternative

If Docker/Podman is not available on the perimeter server, the backend API can run directly as a process (e.g., `node server.js` or equivalent for the team-selected stack). In this case:
- The process must still bind to `127.0.0.1:<PORT>` — not `0.0.0.0`.
- Runtime secrets injected via environment variables set from a restricted-permission file at process start.
- Process supervision (systemd unit or equivalent) handles restart on failure.
- Document the chosen approach in `standards/data/providers/tactical/IL4-implementation.md` (F-ATAK-005).

---

## Network Topology

```
Android Device (on classified perimeter network)
  │
  │  HTTPS (TLS 1.2+) to <REVERSE_PROXY_HOST>:<HTTPS_PORT>
  │
  ▼
Perimeter Server
  ├─ Reverse Proxy (nginx or equivalent)
  │    - TLS termination (classified network certificate — OG-6c TBD)
  │    - Forwards to 127.0.0.1:<BACKEND_PORT> via plain HTTP on loopback
  │    - Only required ports open on network interface
  │
  ├─ Backend API (Docker container or process)
  │    - Listens on 127.0.0.1:<BACKEND_PORT> only
  │    - Not directly reachable from Android device network segment
  │
  └─ Database (Docker container or process)
       - Listens on 127.0.0.1:<DB_PORT> only
       - Not directly reachable from network interface
       - Connection string injected into backend API via runtime.env
```

**No public internet exposure.** The perimeter server is on a classified network with no path to public internet services. Network firewall rules allow only required ports. Management ports (SSH, RDP) are not exposed to the Android client network segment. See ADR-023 and the CLAUDE.md tactical provider Sentinel checks for the firewall documentation requirement.

### Reverse Proxy Configuration Requirements

The reverse proxy (nginx or equivalent) must:
1. Terminate TLS using the classified network certificate (OG-6c — TLS CA pending unit IT)
2. Enforce TLS 1.2 minimum — disable TLS 1.0 and 1.1, disable SSLv3
3. Restrict cipher suite to FIPS 140-3 approved algorithms (IL6 requirement — SC-13)
4. Forward requests to the backend API on loopback only
5. Pass through the `Authorization: Bearer` header to the backend API
6. **Not** add `Access-Control-Allow-Origin` headers — no CORS required (Android client does not run in a browser)

Example nginx location block (fill in actual values):

```nginx
server {
    listen <HTTPS_PORT> ssl;
    ssl_certificate     /path/to/classified-network.crt;
    ssl_certificate_key /path/to/classified-network.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         <FIPS_140_3_CIPHER_SUITE>;  # confirm with unit IT / ISSO
    ssl_prefer_server_ciphers on;

    location /api/ {
        proxy_pass         http://127.0.0.1:<BACKEND_PORT>;
        proxy_set_header   Authorization $http_authorization;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   Host $host;
    }
}
```

Document the chosen reverse proxy, cipher suite, and certificate source in `standards/data/providers/tactical/IL4-implementation.md` (F-ATAK-005).

---

## Authentication Layer

### JWT Validation on Every Request

The backend API validates a JWT Bearer token on every API endpoint. No endpoint is reachable without a valid token. This maps to the CLAUDE.md Sentinel check: "All endpoints require valid Keycloak token."

```
Android App → Acquires token via Keycloak (OG-1: PKCE or mTLS/derived credentials TBD)
            → Stores token in Android KeyStore (STIG 2.4, IL6-implementation.md IA-5(6))
            → Sends Authorization: Bearer <token> on every API request
Backend API → Validates token signature against cached JWKS
            → Extracts role claim (admin | editor | user) for RBAC enforcement
            → Returns 401 if token is absent, expired, or invalid
```

### Keycloak — Co-located or Federated

The Keycloak instance may run on the same perimeter server or be a federated instance on the classified network. This is open gap OG-1 from ADR-022 — the authentication method (PKCE vs. mTLS/derived CAC credentials) is also pending TAK team + Keycloak platform team input.

Regardless of how Keycloak is hosted:
- JWKS are cached locally by the backend API — no live Keycloak call per API request (CLAUDE.md key architecture constraint)
- The backend validates token signature and expiry using the cached JWKS
- JWKS cache is refreshed on a configurable TTL — the Keycloak base URL is injected via runtime.env, never hardcoded

### RBAC

Three roles enforced by the backend API: `admin`, `editor`, `user`. Role is extracted from the validated JWT claim. Application DB does not store clearance level — clearance is delegated entirely to the identity provider (IL6 requirement AC-3(7)).

---

## Database Deployment

### Stack Placeholder

The database is PostgreSQL or equivalent on the tactical perimeter server. "Equivalent" means a relational database that supports parameterized queries, transactions with row-level locking (`SELECT FOR UPDATE`), and generated columns. The specific database engine is confirmed when the backend stack is selected (OG-5).

### Deployment Pattern

```
# Database runs as a Docker container on the perimeter server (or as a native process)
docker run -d \
  --name db \
  --restart unless-stopped \
  -p 127.0.0.1:<DB_PORT>:5432 \
  -v /opt/data/db:/var/lib/postgresql/data \
  --env-file /opt/db/runtime.env \
  postgres:<VERSION>
```

- DB port bound to `127.0.0.1` — not reachable from network interface.
- Data volume at `/opt/data/db` — on an encrypted volume (LUKS or equivalent). Encryption specifics deferred to F-ATAK-005.
- Runtime env file (`/opt/db/runtime.env`) contains DB credentials — not committed to source.
- No managed cloud database (no RDS, no Azure Database for PostgreSQL). Team-managed, self-hosted.

### Connection String Injection

The backend API receives the database connection string via the runtime env file at container start. Format and variable name are team-selected — document in F-ATAK-005. The connection string includes host (`127.0.0.1`), port, database name, username, and password. No fallback/default connection string in source code.

### Data at Rest Encryption

The database volume must be encrypted at rest. Mechanism is LUKS or equivalent OS-level encryption — not application-layer encryption. Specific configuration deferred to `standards/data/providers/tactical/IL4-implementation.md` (F-ATAK-005). This satisfies CLAUDE.md tactical provider Sentinel check: "Data at rest encryption documented for database volume and any persistent storage."

---

## Runtime Secrets — Injection Pattern

The backend API has no hardcoded secrets. All secrets are injected at runtime via the env file. The env file is managed on the perimeter server by an administrator.

### Required Runtime Variables (team-selected names)

| Secret | Description | Notes |
|---|---|---|
| `DATABASE_URL` (or equivalent) | Database connection string including credentials | Injected via `/opt/backend/runtime.env` |
| `KEYCLOAK_JWKS_URI` | Keycloak JWKS endpoint URL | Injected via runtime.env — points to classified network Keycloak instance |
| `KEYCLOAK_ISSUER` | Expected `iss` claim value for JWT validation | Injected via runtime.env |
| Additional stack-specific secrets | e.g., session signing keys, internal service tokens | All injected via runtime.env; never in source |

No secret variable has a fallback or default value. If a required variable is unset, the application fails to start explicitly with a clear error — never with an insecure default.

### Env File — Server-Side Management

```
# /opt/backend/runtime.env — on the perimeter server only
# Permissions: 600, owned by the process user that runs the container
# Not committed to source. Not in GitLab CI artifacts.
# Placed on the server by an administrator before first deployment.
DATABASE_URL=postgresql://...
KEYCLOAK_JWKS_URI=https://keycloak.<PERIMETER_NETWORK_HOST>/realms/<REALM>/protocol/openid-connect/certs
KEYCLOAK_ISSUER=https://keycloak.<PERIMETER_NETWORK_HOST>/realms/<REALM>
```

See ADR-023 OG-6b for the open gap on secrets management approach. When OG-6b is resolved and F-ATAK-005 documents the chosen mechanism, update this section with the specific approach.

---

## IL6 Classification Banner

Every backend API response must include a classification banner header per the IL6 requirement (IL6-implementation.md SC-16 / ICD 710). This is a backend middleware requirement — not an Android app requirement, though the Android app must surface the banner in its UI.

The backend adds the header to every response, including health check endpoints:

```
X-Classification: SECRET//YOUR-MARKINGS
```

Header value must match the classification level of the data served and be CAPCO-compliant. Actual marking reviewed by security officer at deployment time.

---

## Sentinel Gate Cross-Reference

| CLAUDE.md Sentinel Check | Implementation in this doc |
|---|---|
| All endpoints require valid Keycloak token | JWT validation on every request — Auth Layer section |
| Auth middleware registered before all route handlers | Backend API contract requirement — team implements at stack selection |
| Negative auth test required: 401 without token | Backend API contract requirement — Amelia implements and tests |
| No server-side token storage, session tables, or session middleware | Not stored — stateless JWT validation only |
| No hardcoded secrets or credentials | All secrets via `/opt/backend/runtime.env` — Runtime Secrets section |
| SQL injection prevented — parameterized queries only | Backend API contract requirement — team implements at stack selection |
| Custom Express error handler wired globally — no stack traces in responses | Backend API contract requirement — team implements at stack selection |
| TLS termination documented at reverse proxy layer ≥ TLS 1.2 | Reverse Proxy section — cipher suite and TLS version documented |
| No plaintext secrets in provisioning scripts or config | Env file approach — not committed to source |
| Audit log destination documented (AU-2/AU-11) | Deferred to F-ATAK-005 [OG-6d TBD] |
| Data at rest encryption documented (LUKS or equivalent) | Deferred to F-ATAK-005 |
| Network firewall rules documented | Deferred to F-ATAK-005 |
| Deployment authorization documented (ISSO/AO approval) | Deferred to F-ATAK-005 |
| FIPS 140-3 validated crypto only (IL6) | Reverse proxy cipher suite (IL6-implementation.md SC-13); JWKS validation |
| No unclassified external calls at runtime (IL6) | Network topology — no public internet path; all calls on classified network |
| Audit logs to tamper-evident, append-only store (IL6) | Deferred to F-ATAK-005 [OG-6d TBD] |
| Classification banner header on all API responses (IL6) | IL6 Classification Banner section — middleware adds header to every response |
| Personnel clearance not stored in app DB (IL6) | Auth Layer section — delegated entirely to Keycloak/IdP |

---

## Backend Technology Contract

The backend stack is team-selected. The following behavior contract must be satisfied regardless of stack choice. This is the minimum the Sentinel gate will verify when implementation begins.

| Contract Item | Requirement |
|---|---|
| Authentication | Validates `Authorization: Bearer <token>` JWT on every request; returns 401 without valid token |
| JWKS caching | Caches Keycloak JWKS locally; no live Keycloak call per API request |
| RBAC | Enforces `admin` / `editor` / `user` role scoping from JWT claim |
| Parameterized queries | All database queries use parameterized / prepared statements — no string interpolation in SQL |
| Error handling | Global error handler returns no stack traces, DB error messages, file paths, or internal details |
| Audit logging | All mutating operations logged with `keycloak_id`, timestamp, and operation type |
| Classification header | Every response includes `X-Classification` header (IL6) |
| Port binding | Listens on `127.0.0.1:<PORT>` only — not `0.0.0.0` |
| Health endpoint | `GET /health` or equivalent returns 200 for container health check |
| No session storage | Stateless — no server-side session tables or session middleware |

---

## Cross-References

| Document | What it covers relative to this doc |
|---|---|
| `docs/architecture/ADR-LOG.md` ADR-022 | Android track architecture pattern — the three-layer diagram this doc elaborates |
| `docs/architecture/ADR-LOG.md` ADR-023 | Tactical provider constraints — full cloud-native → self-managed substitution table |
| `docs/architecture/ADR-LOG.md` ADR-026 | Decision tree; `APP_TYPE` definition; tactical is Android-only |
| `standards/data/providers/android/PIPELINE-SPEC.md` | Stages 7 and 8 (backend-build and backend-deploy) — the CI/CD pipeline that produces and deploys the backend container this doc describes |
| `standards/data/providers/tactical/IL4-implementation.md` | F-ATAK-005 — server provisioning, OS hardening, secrets management (OG-6b), TLS CA (OG-6c), audit log destination (OG-6d), deployment authorization (OG-6e) |
| `standards/data/providers/android/IL6-implementation.md` | IL6 delta control requirements — FIPS 140-3, classification banner, tamper-evident audit logs, session controls |
| `standards/data/controls/IL4-baseline.md` | Full IL4 control baseline — applies to backend API and database regardless of APP_TRACK |

---

## Open Gaps Summary

| ID | Gap | Impact on this doc | Status |
|---|---|---|---|
| OG-1 | Authentication method (PKCE vs. mTLS/derived CAC credentials) | Auth layer section marks method TBD; outcome requirements (JWT in KeyStore, 401 without token) are fixed | Pending TAK team + Keycloak platform team |
| OG-5 | Backend technology stack | Backend Technology Contract section establishes requirements; specific stack fills in at project init | Open — team selects when codebase is known |
| OG-6b | Secrets management on tactical provider | Env file approach documented; storage mechanism TBD | F-ATAK-005 documents |
| OG-6c | TLS CA for classified network | Reverse proxy section includes placeholder; cipher suite placeholder | Pending unit IT |
| OG-6d | Audit log destination | Deferred to F-ATAK-005 | F-ATAK-005 documents |
| OG-6e | Deployment authorization process | Deferred to F-ATAK-005 | F-ATAK-005 documents |

---

## Frank Compliance Confirmation

Content in this document is consistent with:
- **ADR-022** — Three-layer architecture (Android app → Backend API → Shared DB); no frontend container; backend technology is team-selected; shared database with multiple devices reading/writing shared state
- **ADR-023** — No Secrets Manager, no managed DB, no ECR, no EKS, no Helm, no Terraform; backend bound to `127.0.0.1`; reverse proxy handles TLS; env file for secret injection; all PROVIDER=tactical infrastructure specifics deferred to F-ATAK-005
- **ADR-026** — `APP_TYPE: native | atak`; tactical is Android-only for this team; guided decision tree initialization
- **PIPELINE-SPEC.md (F-ATAK-003)** — backend-build and backend-deploy stages; `--env-file /opt/backend/runtime.env`; `127.0.0.1` port binding; SSH deployment; no cloud registry
- **CLAUDE.md Sentinel checks** — All applicable tactical provider checks addressed; IL6 classification banner, FIPS constraints, no-external-calls requirement, and audit log requirement all documented; open gaps explicitly noted

---

## Gate Results

**Murat:** PASS — Frank-lane documentation story; no TDD gate applicable. All 8 dispatch content requirements satisfied: backend architecture pattern (three-layer diagram, no frontend/Ingress/Helm), PROVIDER=tactical deployment (Docker/Podman, `127.0.0.1` binding, env file, F-ATAK-005 deferrals), backend technology placeholder (OG-5; Backend Technology Contract), database deployment (PostgreSQL, LUKS deferred to F-ATAK-005, connection string via env file), network topology (reverse proxy TLS termination, loopback-only backend, no public internet), auth layer (Bearer on all endpoints, JWKS cached locally, OG-1 TBD), no cloud provider assumptions ("What Does Not Exist on This Track" table), cross-references (PIPELINE-SPEC.md, F-ATAK-005, ADR-022, ADR-023). Format is Markdown architecture guide.

**Sentinel:** PASS (0 findings) | SECURITY_TIER: IL6
No hardcoded secrets or credentials anywhere. No real infrastructure values — all server addresses, ports, and URLs are angle-bracket placeholders. No new dependencies introduced. All Android track gate checks addressed in document (TLS 1.2, Bearer auth, no hardcoded credentials, classification banner). All tactical provider gate checks addressed (reverse proxy TLS, env file secret injection, data-at-rest encryption deferred to F-ATAK-005, audit log deferred to F-ATAK-005, firewall rules deferred to F-ATAK-005, deployment authorization deferred to F-ATAK-005). All open gaps explicitly documented. ADR-022/023/026 consistent throughout. Zero `ATAK_PLUGIN` references.

**Manual Security Review:** CLEAR — Architecture guide only; no auth surface, no API endpoints, no data handling code introduced. JWT validation contract, `127.0.0.1` port binding, stateless auth (no session storage), classification banner middleware, no clearance level in app DB, and FIPS 140-3 cipher suite requirement all verified correct in document. Reverse proxy CORS omission confirmed correct (Android client is not a browser).

**User:** APPROVED 2026-05-05
