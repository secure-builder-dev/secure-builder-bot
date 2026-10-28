#!/usr/bin/env bash
# tool-runner.sh — run a scanner without requiring it to be installed.
#
# WHY THIS EXISTS
#   Every runner opened with `command -v <tool> || exit 1`, so `make scan` only worked on a machine
#   where somebody had run five separate installs — two package managers, a curl-to-shell, and an
#   apt repo. The practical effect is that the scan runs on the one workstation that was set up for
#   it. Everywhere else — a new laptop, a fresh CI runner, a cloud session — it exits 1 at the first
#   scanner and the pipeline is a no-op nobody notices, because "NOT INSTALLED" and "no findings"
#   both leave the tree looking clean.
#
#   The scanners all publish images. Running them as pinned containers means the scan behaves the
#   same everywhere and a tool version is a one-line edit in tool-versions.env rather than a request
#   that everybody re-run brew.
#
#   This changes HOW a tool is invoked and nothing about what is scanned or how it is judged. The
#   image plan, the stale-image guard and every severity threshold are untouched.
#
# ENGINE  SCAN_ENGINE=auto       (default) containers when Docker works, host binaries otherwise
#         SCAN_ENGINE=container  containers only; fail when Docker is unusable
#         SCAN_ENGINE=native     host binaries only — the behaviour before this file existed
#         SCAN_ENGINE_<TOOL>     one tool on the other engine (SCAN_ENGINE_TRIVY=native): a host with
#                                one scanner installed and the rest in containers. Per tool, never
#                                inherited by the others; anything but container|native is ignored.
#
# USAGE   sourced by the run-*.sh scripts, immediately after RESULTS_DIR is set:
#           . "$SCRIPT_DIR/tool-runner.sh"
#         then call tool_hadolint / tool_checkov / tool_clamscan / tool_grype / tool_trivy
#         in place of the bare binary. Paths passed to them are RELATIVE to the project root.

_TR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$_TR_DIR/../.." && pwd)}"
# shellcheck source=tool-versions.env
. "$_TR_DIR/tool-versions.env"

SCAN_ENGINE="${SCAN_ENGINE:-auto}"
_tr_engine=""

scan_engine() {
  if [ -z "$_tr_engine" ]; then
    case "$SCAN_ENGINE" in
      container) _tr_engine=container ;;
      native)    _tr_engine=native ;;
      auto|"")   if docker info >/dev/null 2>&1; then _tr_engine=container; else _tr_engine=native; fi ;;
      *) echo "[scan] SCAN_ENGINE='$SCAN_ENGINE' is not auto|container|native" >&2; return 2 ;;
    esac
  fi
  echo "$_tr_engine"
}

# scan_engine_for <tool or binary> — the engine this one tool runs on: its own override, else the global.
scan_engine_for() {
  local name="$1" v
  [ "$name" = clamscan ] || [ "$name" = freshclam ] && name=clamav
  v="$(printenv "SCAN_ENGINE_$(printf '%s' "$name" | tr '[:lower:]-' '[:upper:]_')" 2>/dev/null || true)"
  case "$v" in container|native) printf '%s' "$v" ;; *) scan_engine ;; esac
}

# have_tool <binary> — can this scanner run at all under the engine resolved for it?
have_tool() {
  if [ "$(scan_engine_for "$1")" = container ]; then docker info >/dev/null 2>&1
  else command -v "$1" >/dev/null 2>&1; fi
}

# tool_missing <label> <binary> — the message a runner prints before exiting 1.
tool_missing() {
  if [ "$(scan_engine_for "$2")" = container ]; then
    echo "[$1] Docker is not usable, so the pinned $1 image cannot run."
    echo "[$1]   Start Docker, or SCAN_ENGINE=native with $2 installed (scanners/local-scan-setup.md)."
  else
    echo "[$1] NOT INSTALLED — SCAN_ENGINE=native and '$2' is not on PATH."
    echo "[$1]   Install it (scanners/local-scan-setup.md), or unset SCAN_ENGINE to use containers."
  fi
}

# Run as the invoking user on Linux so nothing a container writes lands root-owned.
_tr_user() { [ "$(uname -s)" = Linux ] && printf -- '--user %s:%s' "$(id -u)" "$(id -g)"; }

# ClamAV has no arm64 image, so on an arm64 host Docker prepends a platform-mismatch WARNING to the
# command's own output — where the signature-freshness guard parses it as a version line, finds no
# build date, and blocks the scan as UNVERIFIED. Requesting the platform removes the warning. A
# no-op on amd64, and empty SCAN_PLATFORM_CLAMAV opts out. See tool-versions.env.
_tr_clamav_platform() {
  [ -n "${SCAN_PLATFORM_CLAMAV:-}" ] && printf -- '--platform %s' "$SCAN_PLATFORM_CLAMAV"
}

# ── The bot's own scanner config ─────────────────────────────────────────────
# own_config_args <tool> — the flags that make <tool> read the bot's config (scanners/scan-config)
# and nothing in the checkout, one per line. Read them with a while-read loop (no mapfile: macOS bash 3.2).
#
# WHY THIS EXISTS
#   The runners cd into the checkout, and Grype (.grype.yaml, .grype/config.yaml), Trivy
#   (.trivyignore, trivy.yaml, trivy-secret.yaml) and hadolint (.hadolint.yaml) each read their own
#   config from the working directory when no other is named. A file the checkout carries could then
#   drop a CVE or a rule before the Scan gate saw it, with no expiry (CM-22), no yellow verdict
#   (CM-25) and nothing in the receipt — the accepted-risk control bypassed by one dotfile (gate
#   run 1, B-5; hadolint N-11). Naming a file always wins over the search, for all three tools; an
#   accepted risk goes only through the Scan gate's accepted-risks file. Under the container engine
#   the directory is mounted read-only at /scan-config, so the same files are read either way.
_TR_CONFIG_DIR="$(cd "$_TR_DIR/../scan-config" 2>/dev/null && pwd)"
scan_config_path() {   # scan_config_path <tool> <file> — where <tool> sees the bot's <file> under its engine
  if [ "$(scan_engine_for "$1")" = container ]; then printf '/scan-config/%s' "$2"; else printf '%s/%s' "$_TR_CONFIG_DIR" "$2"; fi
}
# trivy_cache_dir — Trivy's own default, named outright, so no config file can move it (gate run 2, B-7).
# Under the container engine that is the cache volume; natively, TRIVY_CACHE_DIR or the user cache dir.
trivy_cache_dir() {
  if [ "$(scan_engine_for trivy)" = container ]; then printf '/root/.cache/trivy'
  else printf '%s' "${TRIVY_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/trivy}"; fi
}
# `trivy` is the global flags, which every call takes — `version` too, since the database date is read
# through it: until gate run 2 (B-7) `trivy version` named no config, so a trivy.yaml in the checkout
# could point it at a cache whose metadata says 2099 and fake the date CM-05 judges. `trivy-scan` adds
# the flags only a scan subcommand accepts.
own_config_args() {
  case "$1" in
    grype)    printf '%s\n' --config "$(scan_config_path grype grype.yaml)" ;;
    trivy)    printf '%s\n' --config "$(scan_config_path trivy trivy.yaml)" --cache-dir "$(trivy_cache_dir)" ;;
    trivy-scan) own_config_args trivy
              printf '%s\n' --ignorefile "$(scan_config_path trivy trivyignore)" --secret-config "$(scan_config_path trivy trivy-secret.yaml)" ;;
    # --disable-ignore-pragma: a `# hadolint ignore=DL…` line in the checkout's Dockerfile dropped a
    # rule with no expiry and nothing in the receipt (gate run 2, N-02). Rules change in scan-config.
    hadolint) printf '%s\n' --config "$(scan_config_path hadolint hadolint.yaml)" --disable-ignore-pragma ;;
    # checkov also reads .checkov.yaml from its working directory and from a directory it is given,
    # and --config-file does not displace either: run-checkov.sh runs it over a copy that has none.
    checkov)  printf '%s\n' --config-file "$(scan_config_path checkov checkov.yaml)" ;;
  esac
}

# ── Result parsing ───────────────────────────────────────────────────────────
# count_json <file> <jq-filter> <label> — read a count out of a scanner's JSON, or FAIL LOUDLY.
#
# WHY THIS EXISTS
#   Every runner used to read its count as `jq ... 2>/dev/null || echo "0"`. jq fails when the
#   scanner did not produce parseable output — it crashed, the image would not pull, the file is
#   empty. The `|| echo "0"` then turned that into "0 findings", and a zero-finding scan reports
#   PASS. So a scanner that never ran was indistinguishable from a clean one, which is the exact
#   defect this pipeline exists to prevent; hadolint did precisely this on an arm64 machine whose
#   hadolint image had not been pulled. Finding F-22.
#
#   run-hadolint.sh additionally redirects the tool's stderr into the JSON file (2>&1), so a
#   failed run writes docker's error text where the findings should be. That is why this checks
#   parseability rather than only emptiness.
#
# Prints the count on success. On failure prints why, to stderr, and returns 2 — never a number.
count_json() {
  local file="$1" filter="$2" label="$3" n
  if [ ! -s "$file" ]; then
    echo "[$label] FAIL — $file is empty or missing. The scanner did not run." >&2
    return 2
  fi
  if ! n=$(jq -e "$filter" "$file" 2>/dev/null); then
    echo "[$label] FAIL — $file is not parseable JSON. The scanner did not complete." >&2
    echo "[$label]   $file begins: $(head -c 160 "$file" | tr '\n' ' ')" >&2
    # Move it out of the way rather than leave it for the verdict to count. Until 2026-09-24 this
    # guard fired, the runner exited 2, and the unreadable file stayed in the results directory —
    # where the scan verdict (core/run scan-verdict) counted the scanner as having run, so a broken scanner read as 7/7 PASS.
    # gate-line validates independently now; this is the other half, and it keeps the evidence:
    # `.unparseable` is for a human to read, and no scanner, dispatcher or verdict looks at it.
    mv -f "$file" "$file.unparseable" 2>/dev/null \
      && echo "[$label]   moved aside to $file.unparseable — the results directory now shows this scanner as not run" >&2
    return 2
  fi
  case "$n" in (''|*[!0-9]*) echo "[$label] FAIL — expected a count, got '$n'." >&2; return 2 ;; esac
  printf '%s' "$n"
}

# ── Per-tool wrappers ────────────────────────────────────────────────────────
# Mount needs differ per tool, so each gets its own wrapper rather than one call with flags.
# Under the container engine the project is always mounted read-only at /src, and /src is the
# working directory — which is why callers pass relative paths.

tool_hadolint() {
  if [ "$(scan_engine_for hadolint)" = native ]; then hadolint "$@"; else
    # shellcheck disable=SC2046
    docker run --rm $(_tr_user) -v "$PROJECT_ROOT:/src:ro" -v "$_TR_CONFIG_DIR:/scan-config:ro" -w /src \
      --entrypoint hadolint "$SCAN_IMAGE_HADOLINT" "$@"
  fi
}

tool_checkov() {
  if [ "$(scan_engine_for checkov)" = native ]; then checkov "$@"; else
    # shellcheck disable=SC2046
    docker run --rm $(_tr_user) -v "$PROJECT_ROOT:/src:ro" -v "$_TR_CONFIG_DIR:/scan-config:ro" -w /src \
      --entrypoint checkov "$SCAN_IMAGE_CHECKOV" "$@"
  fi
}

# ClamAV's signature database lives in a named volume shared by every clamav invocation here.
# freshclam and clamscan are separate `docker run` calls, so without a volume an update is thrown
# away by --rm before the scan ever sees it. Docker also seeds a new named volume from the image's
# own /var/lib/clamav, so the database baked into the image is the starting point and freshclam
# fetches deltas rather than ~250MB on a cold start.
#
# Once the volume exists it shadows the image's baked database, which means `docker pull` no longer
# refreshes signatures — freshclam is the only thing that does. That is deliberate. Two competing
# refresh mechanisms is how one of them quietly stops working and nobody notices, which is the same
# shape as the bug this whole file exists to prevent.
_TR_CLAMAV_DB_VOLUME="${SCAN_CLAMAV_DB_VOLUME:-scan-clamav-db}"

# tool_clamscan <host-target> [args...]
# The target is mounted at /scan rather than derived from the project root, because the EICAR test
# points SCAN_DIR_OVERRIDE at a temp directory outside the repo.
tool_clamscan() {
  local target="$1"; shift
  if [ "$(scan_engine_for clamav)" = native ]; then clamscan "$@" "$target"; else
    # No --entrypoint and no --user here, unlike the other scanners. The ClamAV image is
    # s6-overlay based: its entrypoint is /init, which prepares the signature database and the
    # permissions clamscan needs, then execs the command. Passing clamscan as the command and
    # letting /init run is the usage the image documents for a one-off scan.
    #
    # This is NOT what caused the exit 125 seen in CI on 2026-09-19 — that was an image tag that
    # does not exist (see tool-versions.env), so docker never got as far as starting a container.
    # Two rounds went into the wrong cause because the docker error was written to clamav.log and
    # nothing ever printed it; run-clamav.sh now tails that log on a scan error.
    # shellcheck disable=SC2046
    docker run --rm $(_tr_clamav_platform) -v "$target:/scan:ro" -v "$_TR_CLAMAV_DB_VOLUME:/var/lib/clamav" \
      "$SCAN_IMAGE_CLAMAV" clamscan "$@" /scan
  fi
}

# tool_freshclam [args...] — update the signature database in place.
# This is what makes the staleness guard satisfiable: signatures reach current independently of
# when the image was built, so the threshold is a real deadline rather than a bet on the image
# publisher's rebuild cadence.
tool_freshclam() {
  if [ "$(scan_engine_for clamav)" = native ]; then freshclam "$@"; else
    # shellcheck disable=SC2046
    docker run --rm $(_tr_clamav_platform) -v "$_TR_CLAMAV_DB_VOLUME:/var/lib/clamav" \
      "$SCAN_IMAGE_CLAMAV" freshclam "$@"
  fi
}

# The image scanners read locally built images, so they need the Docker socket. The named cache
# volume keeps the vulnerability database between runs — it is still refreshed on every run, this
# only avoids re-downloading all of it each time.
#
# The project is also mounted read-only at /src, as it is for the static scanners: on the android
# track these two scan the filesystem (`grype dir:android`, `trivy fs android`) instead of an
# image, and a relative path has to resolve inside the container (2026-10-07, android scan profile).
tool_grype() {
  if [ "$(scan_engine_for grype)" = native ]; then grype "$@"; else
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$PROJECT_ROOT:/src:ro" -v "$_TR_CONFIG_DIR:/scan-config:ro" -w /src \
      -v scan-grype-cache:/.cache "$SCAN_IMAGE_GRYPE" "$@"
  fi
}

tool_trivy() {
  if [ "$(scan_engine_for trivy)" = native ]; then trivy "$@"; else
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$PROJECT_ROOT:/src:ro" -v "$_TR_CONFIG_DIR:/scan-config:ro" -w /src \
      -v scan-trivy-cache:/root/.cache "$SCAN_IMAGE_TRIVY" "$@"
  fi
}
