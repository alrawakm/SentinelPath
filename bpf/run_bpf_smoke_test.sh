#!/usr/bin/env bash
set -euo pipefail

ROOT="/tmp/sentinelpath_bpf_smoke"
EXPECTED="/tmp/sentinelpath_bpf_smoke"
if ! mountpoint -q /sys/fs/bpf; then
  mount -t bpf bpf /sys/fs/bpf
fi
if [[ "$(realpath -m "$ROOT")" != "$EXPECTED" ]]; then
  echo "unsafe temporary path" >&2
  exit 2
fi
rm -rf "$ROOT"
mkdir -p "$ROOT"
TARGET="$ROOT/access_control.json"
LOG="$ROOT/events.jsonl"
PIN="/sys/fs/bpf/sentinelpath_config"
printf '{"service_role":"viewer","debug_capability":false}\n' > "$TARGET"
if [[ "$PIN" != "/sys/fs/bpf/sentinelpath_config" ]]; then
  echo "unsafe BPF pin path" >&2
  exit 2
fi
rm -f "$PIN"

./sentinelpath_loader sentinelpath.bpf.o "$TARGET" "$LOG" "$PIN" &
LOADER_PID=$!
cleanup() {
  kill "$LOADER_PID" 2>/dev/null || true
  wait "$LOADER_PID" 2>/dev/null || true
  if [[ -f "$LOG" ]]; then
    echo "--- SentinelPath failure log ---" >&2
    cat "$LOG" >&2
  fi
}
trap cleanup EXIT
for _ in $(seq 1 100); do
  if [[ -e "$PIN" ]] && grep -q '"event":"monitor_start"' "$LOG" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
[[ -e "$PIN" ]]
kill -0 "$LOADER_PID"
grep -q '"event":"monitor_start"' "$LOG"

if printf '{"service_role":"administrator"}\n' > "$TARGET" 2>/dev/null; then
  echo "unauthorized write unexpectedly succeeded" >&2
  exit 1
fi
grep -q '"service_role":"viewer"' "$TARGET"

./sentinelpath_run "$PIN" sh -c \
  "printf '%s\n' '{\"service_role\":\"administrator\",\"debug_capability\":true}' > '$TARGET'"
grep -q '"service_role":"administrator"' "$TARGET"

if rm "$TARGET" 2>/dev/null; then
  echo "unauthorized unlink unexpectedly succeeded" >&2
  exit 1
fi

kill "$LOADER_PID"
wait "$LOADER_PID" || true
trap - EXIT
grep -q '"decision":"deny"' "$LOG"
grep -q '"decision":"allow"' "$LOG"
cat "$LOG"
