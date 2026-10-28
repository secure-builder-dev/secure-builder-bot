## About This Document

**Purpose:** Instructions for running the local compliance scan pipeline (Grype, Trivy, Checkov, Hadolint, ClamAV) on a developer workstation.

**Workflow role:** Amelia and Frank reference when setting up local scan tooling. Use `make scan` or `make scan-lite` as the primary interface — this doc explains what those targets do under the hood.

**How to fill in:** Tool versions live in `scanners/scripts/tool-versions.env` and should match what the deployment pipeline uses. Nothing here needs registry credentials.

---

# Local Compliance Scan Setup

Operational guide for running the local compliance scan pipeline. This is a pre-pipeline scan layer — it runs locally on demand to catch fixable issues before they hit the platform's compliance gate.

---

## Prerequisites

**Docker. Nothing else.** The scanners run as pinned containers declared in
`scanners/scripts/tool-versions.env`, so `make scan` behaves the same on a new laptop, a CI
runner and a cloud session. There is no install step.

```bash
make scan        # the compliance scan
make scan-lite   # static only, no Docker
```

The first run pulls the scanner images; later runs reuse them, and the Grype and Trivy
vulnerability databases persist in named Docker volumes — still refreshed on every run, just not
re-downloaded whole.

To change a tool version, edit `tool-versions.env`. Nothing else needs touching.

**Before an accreditation run,** replace the tags there with digests so a scan is exactly
reproducible — *except ClamAV*, which must stay on a moving tag. Grype and Trivy fetch their
vulnerability data at run time, so pinning them says nothing about data freshness. ClamAV's
signatures ship inside the image, so a digest pin freezes them permanently. `run-clamav.sh`
pulls a fresh image automatically when its signatures pass 7 days; a digest pin makes that
impossible and the scan starts refusing to run.

### Running against host binaries instead

`SCAN_ENGINE=native` uses locally installed CLIs and skips Docker. Optional — use it if you
already have the tools, or where Docker is unavailable.

<details>
<summary>Native install (optional)</summary>

### macOS (Homebrew)

```bash
brew install hadolint
pip install checkov
brew install clamav
brew install grype
brew install trivy
```

After installing ClamAV, initialize the signature database:

```bash
sudo freshclam
```

### Linux (Debian/Ubuntu)

```bash
# hadolint
wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
chmod +x /usr/local/bin/hadolint

# checkov
pip install checkov

# clamav
sudo apt install clamav clamav-freshclam
sudo freshclam

# grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# trivy
sudo apt install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install trivy
```

</details>

---

## Base Images

**Chainguard (`cgr.dev/chainguard/wolfi-base`) is the base image source.** ADR-034, superseding
ADR-021. It is public, so nothing here needs a registry account, and its minimal CVE footprint is
most of why scan results stay readable.

Every Dockerfile in this repo is already `FROM chainguard/wolfi-base:latest`. There is nothing to
configure.

**Any other approved registry is a documented fallback only** — permitted when Chainguard lacks
a required image, with written justification and platform sign-off. It is not a second supported
option to choose between; ADR-034 made it the exception. If a project ever takes one that needs
credentials, the `docker login` goes before the build, in `scanners/scripts/build-images.sh`.

**Scanning never needs registry credentials.** Grype and Trivy read images that are already built
and present locally, so every layer they read is on disk. Credentials matter only for pulling a
base — `docker build --pull` — which is a build concern, not a scan one.

## Running Scans

### Static scans only (no credentials required)

```bash
make scan-lite
```

Runs hadolint, Checkov, ClamAV, `npm audit` (over all dependencies of every app dir; needs the
network, not node_modules) and eslint (each app's own config, `--max-warnings 0`; needs
node_modules). No Docker access required. Safe to run on any machine.

### Full scan (all seven scanners)

```bash
make scan
```

Requires Docker running. It builds the images first (`--pull --no-cache`, so the scan measures the
current tree rather than a cached layer) and then scans them. No registry credentials. The seven
scanners are hadolint, Checkov, ClamAV, Grype, Trivy, `npm audit` (`run-npm-audit.sh`) and eslint
(`run-eslint.sh`), the last two added 2026-09-23; the scan verdict (`core/run scan-verdict`) fails the verdict when any of them
produced no result.

### Image scans only

```bash
make scan-images
```

Runs Grype and Trivy only, against locally built images. No registry credentials.

### Android track (`APP_TRACK=android`)

The same seven scanners, the same verdict, different scopes. A plugin ships as an APK, so there is
no image to scan and no npm app dir to audit (2026-10-07):

- **Grype and Trivy scan `android/` as a filesystem** (`grype dir:android`, `trivy fs android`
  with the vuln, secret and misconfig scanners). Trivy reads the dependency tree from
  `gradle.lockfile`; Syft catalogs the jars and poms it finds. **Commit a `gradle.lockfile`**
  (`./gradlew dependencies --write-locks`) or the Gradle dependencies are not scanned, and the
  runner says so in its receipt.
- **`npm audit` and eslint declare an empty scope** (`NOT APPLICABLE`, a `none` receipt), the way
  hadolint does on a repo with no Dockerfiles. The verdict counts them as ran and names them under
  "nothing in scope". Kotlin lint is `make lint` (ktlint, detekt), not a gate scanner yet.
- **Dispatch routes a filesystem result by either scanner's word**, not the image rule's
  intersection: Trivy and Syft catalog different things in a tree, so demanding both would mean a
  Gradle CVE never counts. A fix available blocks with the Gradle remedy; no fix is a POAM
  candidate; a secret or a failed misconfiguration check in the tree blocks.

The track comes from `APP_TRACK` in `project.config.yaml`, or is inferred from a Gradle wrapper
or Kotlin source when it is `UNSET`; `SCAN_TRACK=android|web` overrides (`scan-track.sh`).

### Re-run dispatch generation

```bash
make scan-dispatch
```

Re-generates `dispatch.md` from the most recent scan results without re-running any scanners. Useful after reviewing results manually.

---

## Reading the Dispatch Report

After a scan, results are written to `gate-records/scan/latest/` (gitignored):

| File | Purpose |
|---|---|
| `hadolint.json` / `hadolint.log` | Dockerfile findings |
| `checkov.json` / `checkov.log` | Helm / Terraform policy findings |
| `clamav.log` | Malware scan output |
| `grype.json` / `grype.log` | Image CVE findings (Grype) |
| `trivy.json` / `trivy.log` | Image CVE findings (Trivy) |
| `discrepancy.log` | CVEs found by only one scanner (excluded from dispatch) |
| `poam-candidates.md` | CVEs with no fix, or in the base image layer |
| `dispatch.md` | Self-healing agent dispatch — paste into a new Claude Code session |

### Triggering agent remediation

If `dispatch.md` was written, open it and paste its full contents into a new Claude Code session. Bob will dispatch Amelia (npm CVE fixes) and Frank (Dockerfile/Helm fixes). User must approve before anything is committed.

### POAM candidates

Findings in `poam-candidates.md` cannot be auto-remediated. Follow `engine/agent-cve-poam-guidelines.md` to submit a Change Request to the platform team.

---

## No scheduled scan

The bot schedules nothing, here or in a repository it gates (PRD § Staying current): the scan runs
before every gate (`make gate-scan`) and on every push and pull request through the bot's own
workflow. The engine's nightly wrapper and its `scan-history.log` were dropped with the move into
`scanners/`; a scan that nobody reads is not a control.

---

## Signature Freshness

ClamAV will refuse to scan if its virus database is more than 7 days old. If you see:

```
[clamav] STALE SIGNATURES — database is N days old (max 7). Run: freshclam
```

Update the database:

```bash
sudo freshclam
```

---

## POAM Process

See `engine/agent-cve-poam-guidelines.md` for the full POAM submission workflow. In summary:

1. Review `gate-records/scan/latest/poam-candidates.md`
2. For each finding, draft POAM language (CVE ID, reason not fixable, mitigation)
3. Submit a Change Request to the platform team
4. Add the CVE to the project's POAM allowlist once the platform team acknowledges
