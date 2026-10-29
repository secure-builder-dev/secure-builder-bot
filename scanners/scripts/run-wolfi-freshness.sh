#!/usr/bin/env bash
# run-wolfi-freshness.sh — for every Wolfi package a Dockerfile installs, its last build date in
# Wolfi's package index and every newer line of the same package, as a gate scanner with the same
# contract as the runners beside it: a result file per run, a receipt, "did not run" never "clean".
#
# WHY THIS EXISTS
#   Wolfi ships one package per release line (nodejs-22, nodejs-24) and stops building a line when
#   upstream retires it. A Dockerfile that installs nodejs-22 keeps building and keeps scanning
#   clean for weeks after its last build: no CVE is filed against a version nobody rebuilds yet.
#   The first project the bot gated sat on nodejs-22 last built Aug 7 while nodejs-24 was built
#   Oct 21. This runner records the facts; the Scan gate (stale_wolfi_packages) decides.
#
# INPUTS   every Dockerfile in scope (scan-scope.sh) whose stage is FROM a wolfi or chainguard image
# OUTPUTS  $RESULTS_DIR/wolfi-freshness.json   {index, packages: [{package, dockerfile, line,
#                                              in_index, last_build, newer: [{package, last_build}]}]}
# ENV      WOLFI_INDEX_URL  (default the x86_64 APKINDEX; an air-gapped install points it at a mirror)
#          WOLFI_INDEX_FILE (a local APKINDEX.tar.gz instead of a download; the tests use it)
# EXIT     0 = recorded, or nothing in scope · 1 = the scanner did not run
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
RESULTS_DIR="${SCAN_RESULTS_DIR:-$PROJECT_ROOT/gate-records/scan/latest}"
INDEX_URL="${WOLFI_INDEX_URL:-https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz}"
# shellcheck source=scan-receipt.sh
. "$SCRIPT_DIR/scan-receipt.sh"
scan_begin wolfi-freshness
# shellcheck source=scan-scope.sh
. "$SCRIPT_DIR/scan-scope.sh"
mkdir -p "$RESULTS_DIR"
OUT="$RESULTS_DIR/wolfi-freshness.json"; rm -f "$OUT"
cd "$PROJECT_ROOT" || exit 1

wanted="$(scan_targets "$PROJECT_ROOT" -name Dockerfile -o -name 'Dockerfile.*' | python3 -I -c '
import re, sys
for path in sys.stdin.read().splitlines():
    wolfi, start, joined = False, 0, ""
    for n, line in enumerate(open(path, errors="replace"), 1):
        start, joined = (start or n), joined + line.rstrip("\n").rstrip("\\") + " "
        if line.rstrip("\n").endswith("\\"):
            continue  # a continued instruction is read whole, and reported at its first line
        if m := re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)", joined, re.I):
            wolfi = bool(re.search(r"wolfi|chainguard", m.group(1), re.I))
        elif wolfi:
            for m in re.finditer(r"\bapk\s+add\b([^;&|]*)", joined):  # the packages end at the next shell operator
                for word in m.group(1).split():
                    if re.fullmatch(r"[a-z0-9][a-z0-9._+-]*(=\S+)?", word):
                        print(word.split("=")[0], path, start)
        start, joined = 0, ""
')"
if [ -z "$wanted" ]; then
  printf '{"index": null, "packages": []}\n' > "$OUT"
  scan_none wolfi-freshness "no Dockerfile installs a Wolfi package"
  exit 0
fi

index="${WOLFI_INDEX_FILE:-}"
if [ -z "$index" ]; then
  index="$(mktemp)"; trap 'rm -f "$index"' EXIT
  if ! curl -fsSL --max-time 120 -o "$index" "$INDEX_URL"; then
    echo "[wolfi-freshness] FAIL — could not download $INDEX_URL. The scanner did not run."; exit 1
  fi
fi

if ! printf '%s\n' "$wanted" | python3 -I -c '
import json, re, sys, tarfile, datetime
index, url, out = sys.argv[1:4]
built = {}
with tarfile.open(index) as tar:
    text = tar.extractfile("APKINDEX").read().decode(errors="replace")
for rec in text.split("\n\n"):
    f = dict(line.split(":", 1) for line in rec.splitlines() if len(line) > 2 and line[1] == ":")
    if "P" in f and f.get("t", "").isdigit():
        built[f["P"]] = max(built.get(f["P"], 0), int(f["t"]))
iso = lambda t: datetime.datetime.fromtimestamp(t, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
packages = []
for row in sys.stdin.read().splitlines():
    name, path, line = row.split(" ")
    stem, _, num = name.rpartition("-")
    newer = sorted(((int(m.group(1)), p) for p in built if (m := re.fullmatch(re.escape(stem) + r"-(\d+)", p))
                    and num.isdigit() and int(m.group(1)) > int(num)))
    packages.append({"package": name, "dockerfile": path, "line": int(line), "in_index": name in built,
                     "last_build": iso(built[name]) if name in built else None,
                     "newer": [{"package": p, "last_build": iso(built[p])} for _, p in newer]})
json.dump({"index": url, "packages": packages}, open(out, "w"), indent=1)
' "$index" "${WOLFI_INDEX_FILE:-$INDEX_URL}" "$OUT"; then
  rm -f "$OUT"
  echo "[wolfi-freshness] FAIL — $INDEX_URL is not a readable APKINDEX. The scanner did not run."; exit 1
fi
n="$(printf '%s\n' "$wanted" | wc -l | tr -d ' ')"
scan_ran wolfi-freshness "$n Wolfi package install(s) against ${WOLFI_INDEX_FILE:-$INDEX_URL}"
echo "[wolfi-freshness] Complete — $n install(s) checked. Results: $OUT"
exit 0
