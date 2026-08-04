#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 7 ]; then
  cat <<'USAGE'
Usage:
  bash scripts/collect_session.sh SESSION_ID OPERATOR_TYPE SCENARIO_FAMILY CONDITION OUTCOME AGENT_MODEL HUMAN_OPERATOR -- COMMAND [ARGS...]

Examples:
  bash scripts/collect_session.sh s001 agent suid_sgid_abuse primary success api_frontier "" -- bash -lc 'id; ls /etc >/dev/null'
  bash scripts/collect_session.sh h001 human suid_sgid_abuse primary success "" h00 -- bash

This wrapper records authorized lab commands with strace and stores metadata.
It does not provide or run exploit logic by itself.
USAGE
  exit 2
fi

SESSION_ID="$1"
OPERATOR_TYPE="$2"
SCENARIO_FAMILY="$3"
CONDITION="$4"
OUTCOME="$5"
AGENT_MODEL="$6"
HUMAN_OPERATOR="$7"
shift 7

if [ "${1:-}" != "--" ]; then
  echo "Expected -- before command" >&2
  exit 2
fi
shift

if [ "$#" -lt 1 ]; then
  echo "Missing command to trace" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW_DIR="$ROOT_DIR/data/raw"
TRACE_DIR="$RAW_DIR/strace"
META_DIR="$RAW_DIR/session_metadata"
LOG_DIR="$RAW_DIR/agent_logs"
mkdir -p "$TRACE_DIR" "$META_DIR" "$LOG_DIR"

META_PATH="$META_DIR/${SESSION_ID}.json"
TRACE_PATH="$TRACE_DIR/${SESSION_ID}.strace"
LOG_PATH="$LOG_DIR/${SESSION_ID}.log"

cat > "$META_PATH" <<META
{
  "session_id": "$SESSION_ID",
  "operator_type": "$OPERATOR_TYPE",
  "scenario_family": "$SCENARIO_FAMILY",
  "condition": "$CONDITION",
  "outcome": "$OUTCOME",
  "agent_model": "$AGENT_MODEL",
  "agent_cli_version": "${AGENT_CLI_VERSION:-}",
  "agent_requested_model": "${AGENT_REQUESTED_MODEL:-}",
  "agent_execution_mode": "${AGENT_EXECUTION_MODE:-}",
  "human_operator": "$HUMAN_OPERATOR",
  "study_phase": "${STUDY_PHASE:-pilot}",
  "protocol_version": "${PROTOCOL_VERSION:-}",
  "scenario_variant": "${SCENARIO_VARIANT:-default}",
  "participant_skill": "${PARTICIPANT_SKILL:-}",
  "site_id": "${SITE_ID:-local_wsl}",
  "trial_index": "${TRIAL_INDEX:-}",
  "schedule_row_id": "${SCHEDULE_ROW_ID:-}",
  "campaign_id": "${CAMPAIGN_ID:-}",
  "attack_pattern": "${ATTACK_PATTERN:-}",
  "campaign_stage": "${CAMPAIGN_STAGE:-}",
  "trigger_state": "${TRIGGER_STATE:-}",
  "expected_protected_change": "${EXPECTED_PROTECTED_CHANGE:-}",
  "scenario_fixture_root": "${AUTONOMOUS_ROOT_SCENARIO:-}",
  "fixture_generator_sha256": "${FIXTURE_GENERATOR_SHA256:-}"
}
META

echo "[collect_session] session=$SESSION_ID trace=$TRACE_PATH"
set +e
strace -f -ttt \
  -e trace=%process,%file,%creds,capget,capset \
  -o "$TRACE_PATH" \
  -- "$@" >"$LOG_PATH" 2>&1
session_rc=$?
set -e

if [ "$session_rc" -eq 0 ]; then
  final_outcome="success"
elif [ "$session_rc" -eq 124 ]; then
  final_outcome="timeout"
else
  final_outcome="failure"
fi

python3 - "$META_PATH" "$final_outcome" "$session_rc" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
metadata = json.loads(path.read_text(encoding="utf-8"))
metadata["outcome"] = sys.argv[2]
metadata["session_exit_code"] = int(sys.argv[3])
path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "[collect_session] done outcome=$final_outcome exit_code=$session_rc"
exit "$session_rc"
