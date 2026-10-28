#!/usr/bin/env bash
# check-doc-paths.sh — every repo path mentioned in a Markdown file must exist.
#
# Scans tracked *.md files (plus CLAUDE.md, Makefile) for backtick-quoted paths and markdown
# link targets that look like repo-relative paths, and reports the ones that do not resolve.
# Skips URLs, <placeholders>, globs, paths with {templating}, and paths the doc itself says are
# created later. Exit 1 if anything is broken. Run before committing a move.
#
# USAGE   engine/scripts/check-doc-paths.sh [--engine] [--all] [--exclude=<regex>]...
#         --exclude  skip scanned files matching this extended regex (repeatable). A project
#                    may also list patterns in .doc-paths-ignore at the repo root.
#         --engine  also scan engine/*.md — only meaningful in the engine repo itself; a downstream
#                   project's engine/ docs legitimately mention tracks it does not have. The engine
#                   repo sets it via Makefile.project. --all additionally scans engine/skills/.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1
ALL=0; ENGINE=0
for a in "$@"; do case "$a" in --all) ALL=1 ;; --engine) ENGINE=1 ;; esac; done

# Known top-level roots a repo path can start with. Anything else in backticks is prose/code.
# Directory roots: a mention is only a path if a '/' follows. Without this, a backticked mention of
# a track or config VALUE (`android`, which is also a real top-level dir on that track) reads as a
# missing directory — finding F-5.
DIR_ROOTS='engine|docs|planning|gate-records|backend|frontend|android|helm|terraform|docker|scripts|\.claude|\.github|\.githooks'
# File roots: match exactly, no separator follows.
FILE_ROOTS='CLAUDE\.md|README\.md|Makefile|project\.config\.yaml|\.gitlab-ci\.yml|\.gitignore|docker-compose[A-Za-z0-9_.-]*\.yml|\.env[A-Za-z0-9_.-]*|\.hadolint\.yaml'

# Not scanned: generated truth files, BMAD's own skill/config trees (upstream docs) and the structure proposal
# (a record of the old→new move; its old paths are the point).
files=$(git ls-files '*.md' CLAUDE.md Makefile | grep -vE '^engine/|^docs/truth/|^docs/proposals/(structure-proposal|afk-decision-log)\.md$')
[ "$ENGINE" -eq 1 ] && files=$(git ls-files '*.md' CLAUDE.md Makefile | grep -vE '^engine/(skills|templates)/|^docs/truth/|^docs/proposals/(structure-proposal|afk-decision-log)\.md$')
[ "$ALL" -eq 1 ] && files=$(git ls-files '*.md' CLAUDE.md Makefile)

# Paths that are supposed to be absent from the template: created per project, per clone, or by
# a later phase: env files, scan output, platform values files, project-authored lists, generated
# truth, planning output, per-user settings.
# From the engine's first project (2026-10-03, T-ENGINE-04 / GOV-027). The planning clause below used to
# read `planning/(onboard\.json|epics/|tickets/)`, which skipped every path under those two trees
# BEFORE the existence test — so this checker could neither confirm nor deny that any planning path
# resolved. Measured 2026-10-02: 194 files were deleted from `planning/epics/_archive/` and
# `planning/tickets/` and `make check-doc-paths` reported "all repo paths in docs resolve" — green
# because it never looked — while the project's own handover notes cited that command as the way to
# verify such a deletion was safe.
#
# In a PROJECT, `planning/epics/<slug>/` and `planning/tickets/` exist as soon as the project is
# planned, so a path inside them that does not resolve is a real broken reference. In the ENGINE
# repo they legitimately do not exist, so the wider exemption is kept there and only there (--engine).
# `planning/onboard.json` stays exempt everywhere: `make onboard` writes it, and it is gitignored.
PLANNING_ABSENT='planning/onboard\.json$'
[ "$ENGINE" -eq 1 ] && PLANNING_ABSENT='planning/(onboard\.json|epics/|tickets/)'
EXPECTED_ABSENT='^(\.env([./]|$)|gate-records/scan(/|$)|helm/|terraform/|\.gitlab-ci\.yml$|docs/security/(providers/[^/]+/)?approved-(registries|image-digests)\.yaml$|docs/security/PROOF-SET\.md$|docs/truth(/|$)|'"$PLANNING_ABSENT"'|\.claude/settings\.json$|backend/\.env|frontend/\.env|Makefile\.project$|gate-records/LEGACY-INVENTORY\.md$|android/app/|backend/src/(middleware|repositories|routes|services)/)'

# F-4: optional project-level ignore list. One extended regex per line; '#' comments and blank
# lines skipped. Matched against the scanned FILE path, so a project can exclude an archived docs
# tree (old planning records whose paths were correct when written) without falsifying history.
# slim (T-SLIM-06): a third transition, beside archived tickets and archived epics below. A path
# deleted ON PURPOSE is listed in .doc-paths-retired — one extended regex per line, each with a comment
# naming the ticket that retired it. The ADR log, gate logs and review guides cite those paths
# correctly as of when they were written, and rewriting them would falsify the record; exempting
# whole files would blind the check to everything else in them. A retired path is resolved by name,
# so every other broken path in the same file is still reported.
RETIRED_FILE=".doc-paths-retired"
retired_re=""
if [ -f "$RETIRED_FILE" ]; then
  retired_re=$(sed -E 's/[[:space:]]+#.*$//' "$RETIRED_FILE" | grep -vE '^[[:space:]]*(#|$)' | paste -sd'|' -)
fi

IGNORE_FILE=".doc-paths-ignore"
ignore_re=""
if [ -f "$IGNORE_FILE" ]; then
  ignore_re=$(grep -vE '^[[:space:]]*(#|$)' "$IGNORE_FILE" | paste -sd'|' -)
fi
for a in "$@"; do case "$a" in --exclude=*) e="${a#--exclude=}"; ignore_re="${ignore_re:+$ignore_re|}$e" ;; esac; done
if [ -n "$ignore_re" ]; then
  files=$(printf '%s\n' "$files" | grep -vE "$ignore_re" || true)
fi

TMP="$(mktemp -u)"
while IFS= read -r f; do
  # backtick paths + markdown link targets, one per line, with line numbers
  grep -noE '`[^` ]+`|\]\([^) ]+\)' "$f" 2>/dev/null \
  | sed -E 's/^([0-9]+):`?\]?\(?([^`)]*)`?\)?$/\1 \2/' \
  | while read -r ln p; do
      p="${p#./}"
      case "$p" in
        http*|mailto:*|\#*|*'<'*|*'>'*|*'{'*|*'*'*|*'|'*|*'$'*|*'='*|*' '*) continue ;;
      esac
      p="${p%%#*}"; p="${p%/}"; p="${p%:*}"   # strip anchors, trailing slash, :line suffixes
      [ -z "$p" ] && continue
      grep -qE "^($DIR_ROOTS)/|^($FILE_ROOTS)$" <<<"$p" || continue
      # ADR identifiers (docs/architecture/ADR-014) are references, not files — F-5.
      grep -qE 'ADR-[0-9]+$' <<<"$p" && continue
      grep -qE "$EXPECTED_ABSENT" <<<"$p" && continue
      # A gitignored path is a per-clone local file (docker-compose.dev.yml, .env, scan output).
      # It exists on a developer's disk but is never checked out in CI, so a filesystem test alone
      # passes locally and fails in CI — the worst failure mode a check can have. Same category as
      # the .env entries in EXPECTED_ABSENT, handled generally here. Finding F-8.
      # Try the bare path and the directory form. A directory-only ignore rule ("gate-records/state/")
      # does NOT match a path git cannot classify as a directory, and in CI the directory does not
      # exist — so the bare test passes locally, where it does exist, and fails on the runner. The
      # trailing slash tells git to treat it as a directory regardless of what is on disk. F-8b.
      { git check-ignore -q "$p" || git check-ignore -q "$p/"; } 2>/dev/null && continue
      [ -e "$p" ] && continue
      [ -n "$retired_re" ] && grep -qE "^(${retired_re})$" <<<"$p" && continue
      # From the engine's first project (2026-10-03, T-ENGINE-16). A finished epic's tickets are
      # COLLAPSED into one ledger under planning/tickets/_archive/ and the individual files are
      # deleted; git keeps their full text. An epic folder is retired to planning/epics/_archive/
      # the same way. Gate logs, the governance changelog and the proposals all cite those paths by
      # name, correctly, at the moment they were written — so every close-epic turned this check red
      # and the reflex was to add another blanket file exemption, which re-blinds the check that
      # T-ENGINE-04 had just restored. Three were added in one afternoon that way.
      #
      # So resolve the two transitions instead of exempting the files that mention them. A missing
      # ticket file is fine IF its id appears in a ledger; a missing epic folder is fine IF the
      # archive holds it. Anything else is still a real broken reference and is still reported.
      case "$p" in
        planning/tickets/*T-*.md)
          _tid="$(basename "$p" | sed -E 's/^(T-[A-Za-z0-9]+-[0-9]+).*/\1/')"
          if [ -n "$_tid" ] && grep -qRE "^\| ?$_tid ?\|" planning/tickets/_archive/ 2>/dev/null; then continue; fi
          ;;
        planning/epics/*)
          _slug="${p#planning/epics/}"; _slug="${_slug%%/*}"
          [ -n "$_slug" ] && [ -e "planning/epics/_archive/$_slug" ] && continue
          ;;
      esac
      # relative to the doc's own directory?
      [ -e "$(dirname "$f")/$p" ] && continue
      printf '  %s:%s  %s\n' "$f" "$ln" "$p"; echo BROKEN >> "$TMP"
    done
done <<< "$files"
[ -f "$TMP" ] && { n=$(wc -l < "$TMP"); echo "── $n broken path(s)"; rm -f "$TMP"; exit 1; }
echo "check-doc-paths: all repo paths in docs resolve"
