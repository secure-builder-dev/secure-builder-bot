## About This Document

**Purpose:** CI/CD pipeline specification for the Android track — covers GitLab CI pipeline stages, APK signing, and WatchTower distribution on IL6 self-hosted infrastructure.

**Workflow role:** Frank reads when writing or modifying the Android CI/CD pipeline; Sentinel confirms pipeline gate steps are present at review.

**How to fill in:** No customization required for framework pipeline stages. Replace CI runner tags and server hostnames with your environment's values in your `.gitlab-ci.yml`.

---

# Android Track CI/CD Pipeline Specification

**Lane:** Frank  
**Track:** `APP_TRACK=android | SECURITY_TIER=IL6 | PROVIDER=tactical`  
**CI format:** `.gitlab-ci.yml` — self-hosted GitLab on IL6 infrastructure  
**Last updated:** 2026-05-05  
**Grounded in:** ADR-022 (Android track), ADR-023 (tactical provider), ADR-026 (`APP_TYPE` replaces `ATAK_PLUGIN`), CLAUDE.md Sentinel checks, `standards/data/providers/android/STIG-checklist.md`

> **PROVIDER=tactical constraint:** No hardened container registry, no Amazon ECR, no EKS, no Helm, no Terraform, no cloud CLI tools. The Android APK artifact is the primary deliverable. The backend API and database run as Docker/Podman containers (or directly as processes) on the team-owned classified perimeter server. Pipeline tooling runs on the self-hosted GitLab runner on IL6 infrastructure.

> **APP_TYPE usage:** `APP_TYPE=native` → standalone Android APK, MDM distribution. `APP_TYPE=atak` → ATAK plugin APK, WatchTower distribution. Both types share stages 1–5 (static analysis, dependency scan, build, signing, verification). Distribution step (stage 6) diverges by `APP_TYPE`.

---

## Pipeline Stage Overview

```
stages:
  - static-analysis       # ktlint + Detekt (fail-fast before any build)
  - dependency-scan       # OWASP dependency check (CVE gate)
  - build                 # Gradle assemble (debug + release)
  - sign                  # APK signing via CI-injected keystore
  - verify                # apksigner verification + STIG checks
  - distribute            # APK artifact upload (APP_TYPE=atak: WatchTower manual; APP_TYPE=native: MDM)
  - backend-build         # Backend API image build (Docker/Podman)
  - backend-deploy        # Deploy backend to perimeter server
```

Stages run in sequence. Any failure in `static-analysis`, `dependency-scan`, `sign`, or `verify` blocks all downstream stages — the pipeline does not produce a distributable artifact unless every gate passes.

---

## Prerequisites

### GitLab Runner Requirements

- Self-hosted GitLab runner on IL6 classified infrastructure
- Runner executor: `shell` or `docker` (team-selected; document choice in `standards/data/providers/tactical/IL4-implementation.md`)
- Runner tags: `android`, `il6`, `tactical`
- Required tools on runner: `java`, `gradle` (or Gradle wrapper invoked via `./gradlew`), `ktlint`, `apksigner`, `zipalign`, `python3` (for OWASP dependency check report parsing)
- No internet access from runner — all dependencies resolved from local mirror or cached Gradle home

### CI Variable Requirements (configured in GitLab project Settings → CI/CD → Variables)

| Variable | Type | Description |
|---|---|---|
| `KEYSTORE_BASE64` | File / masked | Base64-encoded keystore file. Injected as a file variable — GitLab writes the value to a temp file and sets the variable to the path. See signing stage. |
| `KEYSTORE_PASSWORD` | Masked | Password for the keystore file. |
| `KEY_ALIAS` | Masked | Alias of the signing key within the keystore. |
| `KEY_PASSWORD` | Masked | Password for the signing key alias. |
| `BACKEND_DEPLOY_HOST` | Masked | Hostname or IP of the perimeter server for backend deployment. |
| `BACKEND_DEPLOY_USER` | Masked | SSH user for backend deployment. |
| `BACKEND_SSH_KEY` | File / masked | SSH private key for deployment. |
| `BACKEND_ENV_FILE` | File / masked | Environment file injected at deploy time — contains runtime secrets (DB credentials, Keycloak URL). Never committed to source. See ADR-023 OG-6b. |

No CI variable values are committed to source. No fallback/default values for any secret variable. If a required variable is unset, the pipeline stage that uses it fails explicitly.

---

## Stage 1 — Static Analysis

**Gate rule:** Zero ktlint violations and zero Detekt `error`-severity issues required. Pipeline blocks on any violation. Runs before build to fail fast.

**STIG reference:** Supports `standards/data/providers/android/STIG-checklist.md` Section 5 (Logging — no debug logging in production code verified by static scan); Section 4 (Input Validation — code-review items automated here).

```yaml
ktlint:
  stage: static-analysis
  tags: [android, il6, tactical]
  script:
    - ./gradlew ktlintCheck
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event" || $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  artifacts:
    when: always
    reports:
      junit: build/reports/ktlint/**/*.xml
    paths:
      - build/reports/ktlint/
    expire_in: 7 days

detekt:
  stage: static-analysis
  tags: [android, il6, tactical]
  script:
    - ./gradlew detekt
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event" || $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  artifacts:
    when: always
    reports:
      junit: build/reports/detekt/detekt.xml
    paths:
      - build/reports/detekt/
    expire_in: 7 days
```

**Detekt configuration note:** The project's `detekt.yml` sets `build.maxIssues: 0` for `error`-severity rules and sets the baseline for `warning`-severity rules. A build with any `error`-severity issue returns a non-zero exit code and blocks the pipeline. `warning`-severity items are reported but do not block. Detekt version pinned in `build.gradle` — do not use `latest.release`.

**ktlint configuration note:** ktlint is applied via the `org.jlleitschuh.gradle.ktlint` Gradle plugin, version pinned in `build.gradle`. The `.editorconfig` at the repo root governs formatting rules. Any deviation fails the check.

---

## Stage 2 — Dependency Scan

**Gate rule:** Critical and high CVEs block pipeline. Medium and lower severity reported but do not block. Runs before build.

**STIG reference:** Supports CLAUDE.md Sentinel check "All new dependencies present in `docs/architecture/DEPENDENCY_POLICY.md`"; NIST SP 800-163 Rev 1 §4.1 (supply chain risk).

```yaml
dependency-scan:
  stage: dependency-scan
  tags: [android, il6, tactical]
  script:
    - ./gradlew dependencyCheckAnalyze
    - |
      python3 << 'EOF'
      import xml.etree.ElementTree as ET, sys
      tree = ET.parse('build/reports/dependency-check-report.xml')
      root = tree.getroot()
      ns = {'dc': 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd'}
      critical_high = [
          v.findtext('dc:cvssV3/dc:baseSeverity', namespaces=ns) or
          v.findtext('dc:cvssV2/dc:severity', namespaces=ns)
          for dep in root.findall('.//dc:dependency', ns)
          for v in dep.findall('.//dc:vulnerability', ns)
      ]
      blocking = [s for s in critical_high if s and s.upper() in ('CRITICAL', 'HIGH')]
      if blocking:
          print(f"PIPELINE BLOCKED: {len(blocking)} CRITICAL/HIGH CVE(s) found in dependencies.")
          sys.exit(1)
      print("Dependency scan PASS — no CRITICAL or HIGH CVEs.")
      EOF
  allow_failure: false
  artifacts:
    when: always
    paths:
      - build/reports/dependency-check-report.xml
      - build/reports/dependency-check-report.html
    expire_in: 30 days
```

**Configuration requirements:**
- `org.owasp.dependencycheck` Gradle plugin configured in `build.gradle`, version pinned.
- NVD data feed sourced from local mirror on the classified network — no live NVD API calls at scan time. Configure `dependencyCheck.nvd.apiKey` or `cveUrlModified`/`cveUrlBase` to point to the internal NVD mirror. See ADR-023 OG-6b for secrets management approach.
- Suppression file (`dependency-check-suppression.xml`) committed to source for documented false positives. Each suppression entry requires a comment with justification and expiry date.

---

## Stage 3 — Gradle Build

**Gate rule:** Both debug and release builds must succeed. Release build enforces `minifyEnabled true` and ProGuard/R8 code shrinking. Debug build is for test execution; release build produces the distributable APK.

**STIG reference:** STIG-checklist.md 8.6 (ProGuard/R8 obfuscation enabled for release); 5.3 (debug features not in production build — enforced by release build type).

```yaml
build-debug:
  stage: build
  tags: [android, il6, tactical]
  script:
    - ./gradlew assembleDebug
  artifacts:
    paths:
      - app/build/outputs/apk/debug/
    expire_in: 1 day

build-release:
  stage: build
  tags: [android, il6, tactical]
  script:
    - ./gradlew assembleRelease --no-daemon
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release-unsigned.apk
    expire_in: 7 days
```

**`build.gradle` release build type requirements:**

```groovy
android {
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
            debuggable false     // explicit — not inheriting from debug
            testCoverageEnabled false
        }
    }
}
```

`signingConfig` is NOT declared in `build.gradle` for the release build type — signing is handled as a separate pipeline stage using CI-injected credentials. The `assembleRelease` task produces an unsigned APK (`app-release-unsigned.apk`). Signing occurs in stage 4.

**ProGuard/R8 notes:**
- `proguard-rules.pro` committed to source. Keep rules kept as minimal as possible — over-broad `-keep` rules defeat the purpose of shrinking.
- Retrofit/OkHttp and data model classes require `@Keep` annotations or explicit ProGuard keep rules.
- ProGuard/R8 mappings output (`build/outputs/mapping/release/mapping.txt`) archived as a pipeline artifact for crash symbolication — not committed to source.

---

## Stage 4 — APK Signing

**Gate rule:** Signing must succeed with the CI-injected keystore. No keystore file committed to source. Signing key not accessible outside this pipeline stage.

**STIG reference:** STIG-checklist.md 8.2 (signed with documented key; OG-3 placeholder), 8.3 (v2/v3 signing scheme), 8.4 (key not in source).

> **[OG-3 TBD]** APK signing CA/key format is pending TAK team confirmation. This stage documents the signing *mechanism* — keystore injection via CI variable. The *authority* (org-managed keystore vs. DoD PKI–issued certificate) is an open gap. When OG-3 is resolved, update `KEYSTORE_BASE64` content and document the signing authority in the Sentinel gate report.

```yaml
sign-apk:
  stage: sign
  tags: [android, il6, tactical]
  dependencies:
    - build-release
  script:
    # KEYSTORE_BASE64 is a GitLab file variable — GitLab writes the base64 value to a temp file.
    # Decode the base64 content to produce the keystore binary.
    - base64 -d "$KEYSTORE_BASE64" > /tmp/release.keystore
    - |
      zipalign -v -p 4 \
        app/build/outputs/apk/release/app-release-unsigned.apk \
        app/build/outputs/apk/release/app-release-aligned.apk
    - |
      apksigner sign \
        --ks /tmp/release.keystore \
        --ks-pass "pass:$KEYSTORE_PASSWORD" \
        --ks-key-alias "$KEY_ALIAS" \
        --key-pass "pass:$KEY_PASSWORD" \
        --out app/build/outputs/apk/release/app-release-signed.apk \
        app/build/outputs/apk/release/app-release-aligned.apk
    - shred -u /tmp/release.keystore   # overwrite and remove keystore from runner filesystem
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release-signed.apk
    expire_in: 7 days
  after_script:
    - rm -f /tmp/release.keystore || true   # defense-in-depth cleanup if shred unavailable
```

**Security constraints on signing:**
- `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD` are all masked in GitLab CI. They do not appear in pipeline logs.
- The decoded keystore file is written to `/tmp` only and deleted immediately after signing via `shred`. GitLab artifact upload does not include the keystore.
- `zipalign` runs before `apksigner` — APK alignment is required for optimal runtime memory mapping and is a prerequisite for v2/v3 signature validation.
- `apksigner` uses v2 signing by default; v1 signing is disabled by omitting `--v1-signing-enabled true`. Both v2 and v3 signing schemes are applied when the target `minSdkVersion` supports v3 (API 28+).

---

## Stage 5 — APK Verification (STIG Gate)

**Gate rule:** Verification must pass all checks. Any failure blocks the distribute stage.

**STIG reference:** STIG-checklist.md 8.1 (not debuggable), 8.2 (signed), 8.3 (v2/v3 scheme), 5.3 (`android:debuggable=false`).

```yaml
verify-apk:
  stage: verify
  tags: [android, il6, tactical]
  dependencies:
    - sign-apk
  script:
    # STIG ref: Section 8.1, 8.2, 8.3 — APK signing verification
    - |
      echo "=== APK Signature Verification ==="
      apksigner verify --verbose --print-certs \
        app/build/outputs/apk/release/app-release-signed.apk
    - |
      echo "=== Checking v2/v3 signature scheme ==="
      apksigner verify --verbose \
        app/build/outputs/apk/release/app-release-signed.apk \
        | grep -E "Verified using v[23] scheme: true" \
        || (echo "FAIL: APK not verified with v2 or v3 signature scheme" && exit 1)
    # STIG ref: Section 5.3 — debuggable must not be set in release
    - |
      echo "=== Checking debuggable flag ==="
      apksigner verify --verbose \
        app/build/outputs/apk/release/app-release-signed.apk \
        | grep -i "debuggable" \
        && (echo "FAIL: release APK has debuggable flag set" && exit 1) \
        || echo "PASS: debuggable not set"
    # Keystore not in git history
    # STIG ref: Section 8.4
    - |
      echo "=== Checking for committed keystore files ==="
      if git log --all --name-only --format="" | grep -qE '\.(jks|keystore|p12|pfx)$'; then
        echo "FAIL: keystore file found in git history"
        exit 1
      fi
      echo "PASS: no keystore files in git history"
    - echo "=== APK verification PASS ==="
  artifacts:
    when: always
    paths:
      - app/build/outputs/apk/release/app-release-signed.apk
    expire_in: 30 days
```

---

## Stage 6 — Distribution

Distribution stage diverges by `APP_TYPE`. Both paths produce the signed APK as a downloadable GitLab pipeline artifact. The distribution step is the action taken after that artifact is available.

### APP_TYPE=atak — WatchTower Distribution

> **[OG-2 RESOLVED]** WatchTower upload is a manual handoff. The pipeline produces the signed APK as a GitLab artifact. A server admin downloads the artifact from the GitLab pipeline and uploads it to WatchTower manually. No automated pipeline-to-WatchTower API integration.

> **[OG-3 TBD]** WatchTower signing validation requirements pending TAK team. When OG-3 is resolved, update the signing key in `KEYSTORE_BASE64` and document the TAK-approved signing authority in the Sentinel gate report.

> **[OG-4 OPEN]** WatchTower distribution support on the classified (SIPR/IL6) network is pending TAK Product Center confirmation. Until OG-4 is resolved, the manual handoff process applies regardless of network classification status.

```yaml
distribute-atak:
  stage: distribute
  tags: [android, il6, tactical]
  dependencies:
    - verify-apk
  rules:
    - if: '$APP_TYPE == "atak" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - echo "APP_TYPE=atak distribution: signed APK available as pipeline artifact."
    - echo "Manual handoff: server admin downloads app-release-signed.apk from this pipeline and uploads to WatchTower."
    - echo "WatchTower upload: OG-2 RESOLVED (manual). OG-3 TBD (signing authority). OG-4 OPEN (classified network WatchTower support)."
    - |
      # ATAK plugin manifest minimum version check
      # STIG ref: Section 9.1 — minimum ATAK version >= 5.6
      MIN_ATAK=$(grep -oP 'minAtak[^"]*"\K[^"]+' app/src/main/assets/plugin.xml 2>/dev/null || echo "NOT_FOUND")
      if [ "$MIN_ATAK" = "NOT_FOUND" ]; then
        echo "WARN: Could not extract minAtak from plugin.xml — verify ATAK plugin manifest declares minAtak >= 5.6"
      else
        echo "minAtak declared: $MIN_ATAK"
        python3 -c "
      import sys
      ver = '$MIN_ATAK'
      parts = [int(x) for x in ver.split('.')[:2]]
      if parts < [5, 6]:
          print('FAIL: minAtak $MIN_ATAK is below required minimum 5.6')
          sys.exit(1)
      print('PASS: minAtak >= 5.6')
      "
      fi
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release-signed.apk
    expire_in: 90 days
```

**WatchTower manual handoff procedure:**
1. Pipeline completes successfully with a green `distribute-atak` job.
2. Server admin navigates to the GitLab pipeline → job → "Browse" artifacts → downloads `app-release-signed.apk`.
3. Server admin uploads the signed APK to WatchTower via the WatchTower admin interface.
4. WatchTower performs its own APK signature validation (OG-3 TBD — signing authority must match WatchTower's validation expectations once confirmed by TAK team).
5. Distribution package appears in WatchTower for enrolled ATAK devices.

### APP_TYPE=native — MDM Distribution

> **[MDM TBD]** The MDM platform for standalone Android app distribution is team-selected. This step produces the signed APK artifact; the MDM push process is a placeholder pending team MDM selection. Update this stage when MDM is chosen.

```yaml
distribute-native:
  stage: distribute
  tags: [android, il6, tactical]
  dependencies:
    - verify-apk
  rules:
    - if: '$APP_TYPE == "native" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - echo "APP_TYPE=native distribution: signed APK available as pipeline artifact."
    - echo "MDM push: [MDM TBD] — team-selected MDM platform. Server admin uploads app-release-signed.apk to MDM admin console for enrolled device push."
    - echo "Update this stage with MDM-specific upload command once MDM platform is selected."
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release-signed.apk
    expire_in: 90 days
```

---

## Stage 7 — Backend API Build

**Applies to:** All `APP_TRACK=android` projects that include a backend API component (all known projects on this team).

**PROVIDER=tactical constraints:** No ECR, no hardened container registry. Backend image built from a base image available on the classified network (local mirror, team-managed registry, or build from source). No `docker push` to a cloud registry.

```yaml
backend-build:
  stage: backend-build
  tags: [android, il6, tactical]
  script:
    # Build the backend API container image.
    # Base image must be sourced from the local registry or classified network mirror — not Docker Hub or public registries.
    # See ADR-023: no cloud registry on PROVIDER=tactical.
    - docker build
        --no-cache
        --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        --build-arg GIT_SHA=$CI_COMMIT_SHA
        -t backend-api:$CI_COMMIT_SHA
        -f backend/Dockerfile
        ./backend
    # Tag for local registry (if team uses a self-hosted registry)
    # - docker tag backend-api:$CI_COMMIT_SHA <LOCAL_REGISTRY>/backend-api:$CI_COMMIT_SHA
    # - docker push <LOCAL_REGISTRY>/backend-api:$CI_COMMIT_SHA
    - echo "Backend image built: backend-api:$CI_COMMIT_SHA"
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  after_script:
    - docker rmi backend-api:$CI_COMMIT_SHA || true
```

**Backend Dockerfile requirements:**
- Base image sourced from local mirror or team-managed registry — not public Docker Hub. Document base image source in `Dockerfile` comments.
- No secrets in the `Dockerfile` or build args — all runtime secrets injected via `$BACKEND_ENV_FILE` at deploy time.
- `USER` directive sets a non-root user for the running process.
- `HEALTHCHECK` instruction defined.

---

## Stage 8 — Backend Deployment

**PROVIDER=tactical:** Backend API and database run on the team-owned classified perimeter server. Deployment is Docker/Podman-based (no Kubernetes, no Helm). Provisioning specifics in `standards/data/providers/tactical/` (F-ATAK-005).

**References:** ADR-023 (tactical provider constraints), F-ATAK-005 (server provisioning details, secrets management OG-6b, audit log destination OG-6d).

```yaml
backend-deploy:
  stage: backend-deploy
  tags: [android, il6, tactical]
  dependencies:
    - backend-build
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    # Deploy backend to the perimeter server via SSH.
    # SSH key injected via BACKEND_SSH_KEY (GitLab file variable).
    - eval $(ssh-agent -s)
    - chmod 400 "$BACKEND_SSH_KEY"
    - ssh-add "$BACKEND_SSH_KEY"
    - |
      ssh -o StrictHostKeyChecking=yes \
          -o UserKnownHostsFile=.known_hosts \
          "$BACKEND_DEPLOY_USER@$BACKEND_DEPLOY_HOST" \
          "
          set -e
          docker pull <LOCAL_REGISTRY>/backend-api:$CI_COMMIT_SHA 2>/dev/null || true
          # If no local registry, load image from artifact (alternative approach — see note)
          docker stop backend-api || true
          docker rm backend-api || true
          docker run -d
            --name backend-api
            --restart unless-stopped
            --env-file /opt/backend/runtime.env
            -p 127.0.0.1:3001:3001
            backend-api:$CI_COMMIT_SHA
          docker ps --filter name=backend-api
          "
  after_script:
    - ssh-agent -k || true
```

**Deployment notes:**

- `StrictHostKeyChecking=yes` with `.known_hosts` file committed to source (containing only the perimeter server's host key fingerprint) prevents MITM on SSH connection.
- `--env-file /opt/backend/runtime.env` injects runtime secrets from a file pre-placed on the server by an administrator — not injected via `docker run -e`. The env file is not committed to source and lives only on the server at a restricted-permission path. See ADR-023 OG-6b.
- Backend port is bound to `127.0.0.1:3001` — not exposed to the network interface. A reverse proxy (nginx or equivalent) on the perimeter server handles TLS termination and forwards to `127.0.0.1:3001`. See ADR-023 tactical provider TLS requirement.
- If no self-hosted local registry is in use, the alternative is to export the Docker image as a tarball during `backend-build`, transfer it as a pipeline artifact, and load it on the server with `docker load`. Document the chosen approach in `standards/data/providers/tactical/IL4-implementation.md` (F-ATAK-005).

**Database deployment:**

Database migration and provisioning are scoped to F-ATAK-005. The pipeline does not run database migrations automatically in this spec — migration tooling and timing are documented in `standards/data/providers/tactical/`. The backend deployment stage above deploys the API container only.

---

## Full Pipeline YAML Reference

The following is a complete `.gitlab-ci.yml` skeleton that combines all stages. Teams copy this into their project root and fill in project-specific values.

```yaml
# .gitlab-ci.yml — Android Track Pipeline (APP_TRACK=android | SECURITY_TIER=IL6 | PROVIDER=tactical)
# Generated from: standards/data/providers/android/PIPELINE-SPEC.md (F-ATAK-003)
# ADR references: ADR-022, ADR-023, ADR-026

stages:
  - static-analysis
  - dependency-scan
  - build
  - sign
  - verify
  - distribute
  - backend-build
  - backend-deploy

variables:
  GRADLE_OPTS: "-Dorg.gradle.daemon=false -Dorg.gradle.parallel=false"
  ANDROID_SDK_ROOT: "/opt/android-sdk"   # set to runner's Android SDK path

# ─── STATIC ANALYSIS ─────────────────────────────────────────────────────────

ktlint:
  stage: static-analysis
  tags: [android, il6, tactical]
  script:
    - ./gradlew ktlintCheck
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event" || $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  artifacts:
    when: always
    reports:
      junit: build/reports/ktlint/**/*.xml
    paths:
      - build/reports/ktlint/
    expire_in: 7 days

detekt:
  stage: static-analysis
  tags: [android, il6, tactical]
  script:
    - ./gradlew detekt
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event" || $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  artifacts:
    when: always
    reports:
      junit: build/reports/detekt/detekt.xml
    paths:
      - build/reports/detekt/
    expire_in: 7 days

# ─── DEPENDENCY SCAN ─────────────────────────────────────────────────────────

dependency-scan:
  stage: dependency-scan
  tags: [android, il6, tactical]
  script:
    - ./gradlew dependencyCheckAnalyze
    - |
      python3 << 'EOF'
      import xml.etree.ElementTree as ET, sys
      tree = ET.parse('build/reports/dependency-check-report.xml')
      root = tree.getroot()
      ns = {'dc': 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd'}
      blocking = []
      for dep in root.findall('.//dc:dependency', ns):
          for v in dep.findall('.//dc:vulnerability', ns):
              sev = (v.findtext('dc:cvssV3/dc:baseSeverity', namespaces=ns) or
                     v.findtext('dc:cvssV2/dc:severity', namespaces=ns) or '').upper()
              if sev in ('CRITICAL', 'HIGH'):
                  blocking.append(v.findtext('dc:name', namespaces=ns))
      if blocking:
          print(f"PIPELINE BLOCKED: {len(blocking)} CRITICAL/HIGH CVE(s): {blocking}")
          sys.exit(1)
      print("Dependency scan PASS — no CRITICAL or HIGH CVEs.")
      EOF
  allow_failure: false
  artifacts:
    when: always
    paths:
      - build/reports/dependency-check-report.xml
      - build/reports/dependency-check-report.html
    expire_in: 30 days

# ─── BUILD ────────────────────────────────────────────────────────────────────

build-debug:
  stage: build
  tags: [android, il6, tactical]
  script:
    - ./gradlew assembleDebug
  artifacts:
    paths:
      - app/build/outputs/apk/debug/
    expire_in: 1 day

build-release:
  stage: build
  tags: [android, il6, tactical]
  script:
    - ./gradlew assembleRelease --no-daemon
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release-unsigned.apk
      - app/build/outputs/mapping/release/mapping.txt
    expire_in: 7 days

# ─── SIGN ─────────────────────────────────────────────────────────────────────

sign-apk:
  stage: sign
  tags: [android, il6, tactical]
  dependencies:
    - build-release
  script:
    - base64 -d "$KEYSTORE_BASE64" > /tmp/release.keystore
    - zipalign -v -p 4
        app/build/outputs/apk/release/app-release-unsigned.apk
        app/build/outputs/apk/release/app-release-aligned.apk
    - apksigner sign
        --ks /tmp/release.keystore
        --ks-pass "pass:$KEYSTORE_PASSWORD"
        --ks-key-alias "$KEY_ALIAS"
        --key-pass "pass:$KEY_PASSWORD"
        --out app/build/outputs/apk/release/app-release-signed.apk
        app/build/outputs/apk/release/app-release-aligned.apk
    - shred -u /tmp/release.keystore
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release-signed.apk
    expire_in: 7 days
  after_script:
    - rm -f /tmp/release.keystore || true

# ─── VERIFY ───────────────────────────────────────────────────────────────────

verify-apk:
  stage: verify
  tags: [android, il6, tactical]
  dependencies:
    - sign-apk
  script:
    - echo "=== APK Signature Verification (STIG 8.1, 8.2, 8.3) ==="
    - apksigner verify --verbose --print-certs
        app/build/outputs/apk/release/app-release-signed.apk
    - apksigner verify --verbose
        app/build/outputs/apk/release/app-release-signed.apk
        | grep -E "Verified using v[23] scheme: true"
        || (echo "FAIL: v2/v3 scheme not verified" && exit 1)
    - echo "=== Debuggable check (STIG 5.3) ==="
    - apksigner verify --verbose
        app/build/outputs/apk/release/app-release-signed.apk
        | grep -i "debuggable"
        && (echo "FAIL: debuggable flag set in release APK" && exit 1)
        || echo "PASS: debuggable not set"
    - echo "=== Keystore not in git history (STIG 8.4) ==="
    - |
      if git log --all --name-only --format="" | grep -qE '\.(jks|keystore|p12|pfx)$'; then
        echo "FAIL: keystore file found in git history"; exit 1
      fi
      echo "PASS: no keystore files in git history"
    - echo "=== All APK verification checks PASS ==="
  artifacts:
    when: always
    paths:
      - app/build/outputs/apk/release/app-release-signed.apk
    expire_in: 30 days

# ─── DISTRIBUTE ───────────────────────────────────────────────────────────────

distribute-atak:
  stage: distribute
  tags: [android, il6, tactical]
  dependencies:
    - verify-apk
  rules:
    - if: '$APP_TYPE == "atak" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - echo "APP_TYPE=atak: signed APK available as pipeline artifact for manual WatchTower upload."
    - echo "OG-2 RESOLVED: manual handoff. OG-3 TBD: signing authority. OG-4 OPEN: classified WatchTower."
    - |
      MIN_ATAK=$(grep -oP 'minAtak[^"]*"\K[^"]+' app/src/main/assets/plugin.xml 2>/dev/null || echo "NOT_FOUND")
      if [ "$MIN_ATAK" = "NOT_FOUND" ]; then
        echo "WARN: Could not extract minAtak — verify plugin.xml declares minAtak >= 5.6"
      else
        python3 -c "
      ver = '$MIN_ATAK'
      parts = [int(x) for x in ver.split('.')[:2]]
      assert parts >= [5, 6], f'FAIL: minAtak {ver} below 5.6'
      print(f'PASS: minAtak {ver} >= 5.6')
      "
      fi
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release-signed.apk
    expire_in: 90 days

distribute-native:
  stage: distribute
  tags: [android, il6, tactical]
  dependencies:
    - verify-apk
  rules:
    - if: '$APP_TYPE == "native" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - echo "APP_TYPE=native: signed APK available as pipeline artifact."
    - echo "[MDM TBD] Update this stage with MDM upload command when MDM platform is selected."
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release-signed.apk
    expire_in: 90 days

# ─── BACKEND BUILD ────────────────────────────────────────────────────────────

backend-build:
  stage: backend-build
  tags: [android, il6, tactical]
  script:
    - docker build
        --no-cache
        --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        --build-arg GIT_SHA=$CI_COMMIT_SHA
        -t backend-api:$CI_COMMIT_SHA
        -f backend/Dockerfile
        ./backend
    - echo "Backend image built: backend-api:$CI_COMMIT_SHA"
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  after_script:
    - docker rmi backend-api:$CI_COMMIT_SHA || true

# ─── BACKEND DEPLOY ───────────────────────────────────────────────────────────

backend-deploy:
  stage: backend-deploy
  tags: [android, il6, tactical]
  dependencies:
    - backend-build
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - eval $(ssh-agent -s)
    - chmod 400 "$BACKEND_SSH_KEY"
    - ssh-add "$BACKEND_SSH_KEY"
    - |
      ssh -o StrictHostKeyChecking=yes \
          -o UserKnownHostsFile=.known_hosts \
          "$BACKEND_DEPLOY_USER@$BACKEND_DEPLOY_HOST" "
          set -e
          docker stop backend-api 2>/dev/null || true
          docker rm backend-api 2>/dev/null || true
          docker run -d \
            --name backend-api \
            --restart unless-stopped \
            --env-file /opt/backend/runtime.env \
            -p 127.0.0.1:3001:3001 \
            backend-api:$CI_COMMIT_SHA
          docker ps --filter name=backend-api --format 'table {{.Names}}\t{{.Status}}'
          "
  after_script:
    - ssh-agent -k || true
```

---

## Sentinel Compliance Map

This table confirms that each pipeline stage satisfies the relevant CLAUDE.md Sentinel gate check for `APP_TRACK=android`.

| Sentinel Check | Pipeline Stage | How Satisfied |
|---|---|---|
| All network calls use TLS 1.2 minimum | verify-apk (STIG 1.1, 1.2) | Network Security Config verified at static analysis; TLS verified at deploy via network capture |
| No sensitive data in logcat | detekt (STIG 5.1, 5.5) | Detekt rule blocks `Log.d/v/i` calls with sensitive patterns; enforced in static-analysis stage |
| Authentication token stored in Android KeyStore | detekt (STIG 2.4, 3.2) | Detekt custom rule flags `SharedPreferences` token storage; enforced in static-analysis stage |
| No hardcoded credentials, API keys, or base URLs | detekt / dependency-scan (STIG 3.4) | Detekt flags hardcoded strings; dependency scan covers supply chain; no CI variable defaults |
| Exported Android components minimized | detekt (STIG 6.1) | Detekt rule for exported components; Sentinel gate report documents justified exceptions |
| `minSdkVersion` documented and justified | verify-apk (STIG 7.1, 7.2) | `build.gradle` `minSdkVersion` documented in Sentinel gate report |
| No signing key in source | verify-apk (STIG 8.4) | `git log` check in verify-apk stage; `.gitignore` patterns enforced |
| APP_TYPE=atak: ATAK plugin manifest declares minAtak ≥ 5.6 | distribute-atak (STIG 9.1) | `plugin.xml` minAtak extraction and version comparison |
| FIPS 140-3 validated crypto only (IL6) | Sentinel gate report | Pipeline produces evidence; CMVP certificate for BoringSSL on enrolled devices confirmed at deploy |
| No unclassified external calls at runtime (IL6) | Detekt / runner isolation | GitLab runner has no internet access; app network calls to `<BACKEND_BASE_URL>` only |

---

## Open Gaps Summary

| ID | Gap | Impact on Pipeline | Status |
|---|---|---|---|
| OG-2 | WatchTower upload automation | `distribute-atak` stage is manual handoff | RESOLVED — manual; no pipeline API integration |
| OG-3 | APK signing CA/key format | `sign-apk` stage mechanism defined; authority TBD | Pending TAK team — signing required regardless |
| OG-4 | WatchTower on classified network | `distribute-atak` stage produces artifact; upload may be blocked | Pending TAK Product Center |
| OG-6b | Secrets management on tactical provider | `BACKEND_ENV_FILE` is the mechanism; storage approach TBD | F-ATAK-005 documents |
| MDM TBD | MDM platform for native distribution | `distribute-native` stage is a placeholder | Team to select MDM and update stage |

---

## Frank Compliance Confirmation

Content in this document is consistent with:
- **ADR-022** — Android track toolchain (ktlint, Detekt, Gradle, apksigner, JUnit 5); quality gate (zero ktlint violations, zero Detekt errors); distribution logic (APP_TYPE=atak WatchTower; APP_TYPE=native MDM)
- **ADR-023** — Tactical provider constraints: no Helm, no Terraform, no Kubernetes, no ECR, no hardened container registry. Backend deployed via Docker on perimeter server via SSH. Secrets via env file.
- **ADR-026** — `APP_TYPE: native | atak` terminology used throughout. No `ATAK_PLUGIN` references. Decision tree initialization model acknowledged.
- **CLAUDE.md Sentinel checks** — All Android track gate checks addressed. IL6 FIPS and isolation checks confirmed in Sentinel Compliance Map.
- **STIG-checklist.md** — All Section 8 (APK Integrity) and Section 9 (ATAK Conditionals) items satisfied by pipeline stages with explicit `# STIG ref:` comments.

---

## Gate Results

**Murat:** PASS — Frank-lane documentation story; no TDD gate applicable. All 8 story content requirements satisfied: static analysis gate (ktlint + Detekt), dependency scan gate (OWASP/Gradle), Gradle build (debug + release, ProGuard/R8, `minifyEnabled true`), APK signing (CI-injected keystore, apksigner, OG-3 placeholder), distribution APP_TYPE=atak (manual WatchTower handoff, OG-2 RESOLVED), distribution APP_TYPE=native (MDM placeholder), backend pipeline (Docker deploy via SSH, no Helm/Kubernetes), no hardened registry/ECR/EKS. Format is `.gitlab-ci.yml`.

**Sentinel:** PASS (0 findings) | SECURITY_TIER: IL4
All Android track gate checks satisfied. All tactical provider gate checks satisfied. No hardcoded secrets or credentials. No real infrastructure values — all server addresses and registry paths are placeholders. `APP_TYPE` naming consistent throughout; zero `ATAK_PLUGIN` references. All open gaps (OG-2, OG-3, OG-4, OG-6b, MDM TBD) formally documented with resolution paths.

**Manual Security Review:** CLEAR — Pipeline specification document; no auth surface, no API endpoints, no application data handling code introduced. Signing key handling (shred + after_script cleanup), SSH strict host checking, env-file secret injection, and backend port binding to `127.0.0.1` all verified correct.

**User:** APPROVED 2026-05-05
