# scanners/Dockerfile — the scanners image: the bot and its eight scanners, pinned, in one image.
#
# WHY THIS EXISTS
#   A CI job (the GitHub Action, the GitLab component) needs every scanner the Scan gate runs,
#   at the version the bot pinned, with no install step on the runner. This image carries the bot
#   (core/, scanners/, the gate scripts) and the tools, and runs the gate natively inside it:
#   SCAN_ENGINE=native, so no Docker socket is needed where the image runs.
#
# PINS
#   The container scanners come from the very images scanners/scripts/tool-versions.env names, by
#   COPY --from, so there is one list of pins and this file cannot drift from it. checkov and
#   pip-audit are installed from PyPI at the same versions; Node 22 by checksum. ClamAV is the
#   distribution's package: its signatures refresh at run time (freshclam), never by this build.
#   Pinning by digest rather than tag is scanners/pins.md; the release workflow will do it.
#
# BUILD   docker build -f scanners/Dockerfile -t securebuilderbot .      (context: the repo root)
# RUN     docker run --rm -v "$PWD:/src" securebuilderbot run --base origin/main --head HEAD
#         The checkout is mounted at /src, the working directory; PROJECT_ROOT follows it.
#   This file cannot be built where containers have no network (the sandbox the bot was built
#   in); it is linted there (hadolint) and built by CI. The bot's own scan never builds it:
#   scanners/scripts/image-plan.sh leaves it out of the plan on purpose.

FROM hadolint/hadolint:v2.12.0-alpine AS hadolint
FROM anchore/grype:v0.119.0 AS grype
FROM aquasec/trivy:0.58.2 AS trivy

FROM python:3.12-slim

ARG NODE_VERSION=22.12.0
ARG NODE_SHA256=22982235e1b71fa8850f82edd09cdae7e3f32df1764a9ec298c72d25ef2c164f
ARG CHECKOV_VERSION=3.2.334
ARG PIP_AUDIT_VERSION=2.10.1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# git for the range the gate reads; jq for every runner; clamav for the daemonless clamscan and
# freshclam; ca-certificates and curl for the feeds and the Node tarball; xz for that tarball.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git jq xz-utils clamav clamav-freshclam \
 && rm -rf /var/lib/apt/lists/*

COPY --from=hadolint /bin/hadolint /usr/local/bin/hadolint
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" -o /tmp/node.tar.xz \
 && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --exclude='*/CHANGELOG.md' --exclude='*/README.md' \
 && rm -f /tmp/node.tar.xz

# The bot's own Python dependencies and the two PyPI-installed scanners, all pinned.
COPY core/requirements.txt /bot/core/requirements.txt
COPY scanners/requirements.txt /bot/scanners/requirements.txt
RUN pip install --no-cache-dir -r /bot/core/requirements.txt -r /bot/scanners/requirements.txt \
    "checkov==${CHECKOV_VERSION}" "pip-audit==${PIP_AUDIT_VERSION}"

COPY . /bot

ENV SCAN_ENGINE=native \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# The gate runs as an unprivileged user, never root: a scanner that a hostile file exploits gets
# that user's rights inside the container, not root's. It owns what has to be written at run time
# (ClamAV's signature directory for freshclam, its home for the Grype and Trivy caches, /src when
# nothing is mounted), and git trusts the mounted checkout, whose owner is the host's uid.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin scanner \
 && mkdir -p /var/lib/clamav /src \
 && chown -R scanner:scanner /var/lib/clamav /src \
 && git config --system --add safe.directory '*'
USER scanner

WORKDIR /src
ENTRYPOINT ["/bot/core/run"]
CMD ["--help"]
