# Scanner pins

Every scanner the Scan gate runs is pinned in one place, `scanners/scripts/tool-versions.env`:
the five container images (hadolint, checkov, clamav, grype, trivy) by tag, and pip-audit by
version (the same pin in `scanners/requirements.txt`, which the CI workflows and the scanners
image install; `run-pip-audit.sh` refuses any other version). `scanners/Dockerfile` takes its
hadolint, grype and trivy binaries from those same images by `COPY --from`, so the image cannot
drift from the file. npm audit and eslint are the project's own (the npm the runner finds, the
app's own eslint); the bot pins neither, and the receipt says so.

## Tags today, digests next

A tag is a moving pointer: `anchore/grype:v0.119.0` names whatever the registry holds under that
tag at pull time, which is reproducible in practice and not by construction. The PRD's supply-chain
rule (§ Security of the bot itself) is a pin by digest, so a scan is exactly repeatable and a
re-published tag cannot change what ran. To pin an image by digest:

```
docker buildx imagetools inspect anchore/grype:v0.119.0 --format '{{.Manifest.Digest}}'
# → sha256:…
SCAN_IMAGE_GRYPE="${SCAN_IMAGE_GRYPE:-anchore/grype:v0.119.0@sha256:…}"
```

A `tag@sha256:…` reference keeps the tag readable and makes the digest the thing that is pulled;
`pull-images.sh`, `tool-runner.sh` and the Dockerfile's `COPY --from` all accept it unchanged. The
bash suite already asserts every image carries a tag or a digest, and `scangate` records whatever
the file says as the scanner's version in the receipt.

**ClamAV stays on a moving tag** (`clamav/clamav:stable`) by decision, recorded in
`tool-versions.env`: its signatures ship inside the image and refresh through freshclam, and a
digest pin would freeze the baked signatures while the volume they seed drifts. The daemonless
`clamscan` in the scanners image is the distribution's package for the same reason.

## The release workflow (follow-up)

The weekly refresh the PRD describes (§ Staying current) is the bot's own workflow, not anything in
a user's repository: it checks each scanner's upstream for a new release, rewrites the tag **and
its digest** here, runs the self-tests and the proof set against the pinned fixtures, and opens a
release PR. Until it exists, the pins move by hand, in a commit of their own, and the gate's
self-test is the check that the new version still reads the fixtures the same way.
