#!/usr/bin/env bash
set -euo pipefail

ROOT="/tmp/sentinelpath_bpf_trials"
if [[ "$(realpath -m "$ROOT")" != "/tmp/sentinelpath_bpf_trials" ]]; then
  echo "unsafe trial path" >&2
  exit 2
fi
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
rm -rf "$ROOT"
mkdir -p "$ROOT/results"
TARGET="$ROOT/protected.json"
OTHER="$ROOT/unrelated.json"
LOG="$ROOT/events.jsonl"
PIN="/sys/fs/bpf/sentinelpath_config"
CSV="$ROOT/results/trial_metrics.csv"
printf '{"role":"viewer"}\n' > "$TARGET"
printf '{"role":"viewer"}\n' > "$OTHER"
printf 'condition,trial,iterations,allowed,denied,total_ns,ns_per_operation\n' > "$CSV"

append_trial() {
  local condition="$1"
  local trial="$2"
  shift 2
  local row
  row="$("$@" | tail -n 1)"
  printf '%s,%s,%s\n' "$condition" "$trial" "$row" >> "$CSV"
}

./io_benchmark "$OTHER" 1000 write >/dev/null
./io_benchmark "$OTHER" 1000 read >/dev/null
for trial in $(seq 1 30); do
  append_trial baseline_write "$trial" ./io_benchmark "$OTHER" 5000 write
  append_trial baseline_read "$trial" ./io_benchmark "$OTHER" 5000 read
done

rm -f "$PIN"
./sentinelpath_loader sentinelpath.bpf.o "$TARGET" "$LOG" "$PIN" &
LOADER_PID=$!
cleanup() {
  kill "$LOADER_PID" 2>/dev/null || true
  wait "$LOADER_PID" 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 100); do
  if [[ -e "$PIN" ]] && grep -q '"event":"monitor_start"' "$LOG" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
kill -0 "$LOADER_PID"

for trial in $(seq 1 30); do
  append_trial monitored_unrelated_write "$trial" \
    ./io_benchmark "$OTHER" 5000 write
  append_trial protected_read "$trial" \
    ./io_benchmark "$TARGET" 5000 read
  append_trial protected_unauthorized_write "$trial" \
    ./io_benchmark "$TARGET" 1000 write
  append_trial protected_authorized_write "$trial" \
    ./sentinelpath_run "$PIN" ./io_benchmark "$TARGET" 1000 write
done

kill "$LOADER_PID"
wait "$LOADER_PID" || true
trap - EXIT
cp "$LOG" "$ROOT/results/events.jsonl"
cp "$CSV" ./trial_metrics.csv
cp "$LOG" ./trial_events.jsonl
cat "$CSV"
