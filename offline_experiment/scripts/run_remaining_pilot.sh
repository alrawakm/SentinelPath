#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK="${1:-agent01_codex}"
LOG_DIR="$ROOT_DIR/results/batch_logs"
mkdir -p "$LOG_DIR"

run_if_missing() {
  local pattern="$1"
  local condition="$2"
  local trial="$3"
  local campaign_id="${pattern}_${condition}_${FRAMEWORK}_$(printf '%03d' "$trial")"
  local expected_stages=1
  if [ "$pattern" = "staged" ]; then
    expected_stages=3
  fi

  local present
  present="$(find "$ROOT_DIR/results/session_outcomes" -maxdepth 1 -type f \
    -name "${campaign_id}_stage*.json" 2>/dev/null | wc -l)"
  if [ "$present" -eq "$expected_stages" ]; then
    echo "SKIP complete $campaign_id"
    return
  fi
  if [ "$present" -ne 0 ]; then
    echo "ERROR partial campaign $campaign_id has $present/$expected_stages outcomes" >&2
    return 1
  fi

  echo "START $campaign_id $(date --iso-8601=seconds)"
  "$ROOT_DIR/scripts/run_campaign.sh" \
    "$FRAMEWORK" "$pattern" "$condition" "$trial" pilot \
    >"$LOG_DIR/${campaign_id}.stdout.log" \
    2>"$LOG_DIR/${campaign_id}.stderr.log"
  echo "DONE $campaign_id $(date --iso-8601=seconds)"
}

for trial in 1 2 3; do
  run_if_missing staged staged_attack "$trial"
  run_if_missing staged matched_control "$trial"
  run_if_missing trigger trigger_satisfied "$trial"
  run_if_missing trigger trigger_unsatisfied "$trial"
  run_if_missing trigger matched_control "$trial"
done

python3 "$ROOT_DIR/scripts/analyze_new_experiment.py"
echo "PILOT COMPLETE $FRAMEWORK $(date --iso-8601=seconds)"
