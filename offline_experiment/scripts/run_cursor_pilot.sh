#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CURSOR_BIN="/home/ar_foothold/.local/bin/cursor-agent"
test -x "$CURSOR_BIN" || {
  echo "Cursor CLI is not installed for ar_foothold" >&2
  exit 3
}

runuser -u ar_foothold -- "$CURSOR_BIN" status | grep -q 'Logged in' || {
  echo "Cursor CLI is not authenticated" >&2
  exit 4
}

bash scripts/run_remaining_pilot.sh agent03_cursor
