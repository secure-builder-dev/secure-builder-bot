#!/usr/bin/env bash
# gate-launch.sh — `make gate`: produce the handoff and start the one gate on it, in a clean context.
#
# WHY THIS EXISTS
#   The gate used to be a prompt printed for a human to paste into a new window. The window was only
#   ever there to give the reviewer an empty context, and a subagent starts empty. This runs
#   gate-prompt.sh (which still refuses on main, on an empty range, past the re-gate cap and before a
#   green scan) and hands its output — nothing else — to the `gate` agent in a non-interactive
#   Claude Code session.
#
#   Without the `claude` CLI on PATH it prints the handoff and says how to give it to the `gate`
#   subagent from an interactive session. Same text either way; nobody types into it.
#
# USAGE   gate-launch.sh [--checkpoint] [--regate]
#           GATE_PERMISSION_MODE  default acceptEdits (the gate writes its row and tickets)
#           GATE_DRY=1            print the command instead of running it
# EXIT    gate-prompt's refusal code, or the gate session's exit code

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1
PROMPT="$(bash "$HERE/gate-prompt.sh" "$@")" || exit $?
if ! command -v claude >/dev/null 2>&1; then
  printf '%s\n\n' "$PROMPT"
  echo "make gate: no \`claude\` CLI on PATH. In a Claude Code session, ask it to run the \`gate\` subagent"
  echo "           with the handoff above as its whole prompt — nothing from the build conversation."
  exit 0
fi
cmd=(claude -p --agent gate --permission-mode "${GATE_PERMISSION_MODE:-acceptEdits}" --allowedTools "Bash Read Grep Glob Edit Write Skill")
if [ "${GATE_DRY:-0}" = "1" ]; then printf '%q ' "${cmd[@]}"; printf '<handoff: %s lines>\n' "$(printf '%s\n' "$PROMPT" | wc -l | tr -d ' ')"; exit 0; fi
printf '%s\n' "$PROMPT" | "${cmd[@]}"
