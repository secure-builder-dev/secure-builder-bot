#!/usr/bin/env bash
# Point git at the tracked hooks so the forbidden-terms check runs before every commit.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
echo "hooks installed: core.hooksPath = .githooks"
