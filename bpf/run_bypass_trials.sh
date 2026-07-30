#!/usr/bin/env bash
set -euo pipefail

ROOT="/tmp/sentinelpath_bypass_trials"
if [[ "$(realpath -m "$ROOT")" != "/tmp/sentinelpath_bypass_trials" ]]; then
  echo "unsafe trial path" >&2
  exit 2
fi
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
rm -rf "$ROOT"
mkdir -p "$ROOT"
TARGET="$ROOT/protected.json"
OTHER="$ROOT/unrelated.json"
LOG="$ROOT/events.jsonl"
PIN="/sys/fs/bpf/sentinelpath_config"
OUT="./bypass_trials.csv"
printf '{"role":"viewer"}\n' > "$TARGET"
printf '{"role":"viewer"}\n' > "$OTHER"
ln -s "$TARGET" "$ROOT/symlink.json"
ln "$TARGET" "$ROOT/hardlink.json"

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

printf 'case,attempts,expected,correct,incorrect\n' > "$OUT"
measure_denial() {
  local name="$1"
  shift
  local correct=0
  local incorrect=0
  for _ in $(seq 1 100); do
    if "$@" 2>/dev/null; then
      incorrect=$((incorrect + 1))
    else
      correct=$((correct + 1))
    fi
  done
  printf '%s,100,deny,%d,%d\n' "$name" "$correct" "$incorrect" >> "$OUT"
}

measure_denial direct_write sh -c "printf X > '$TARGET'"
measure_denial symlink_write sh -c "printf X > '$ROOT/symlink.json'"
measure_denial hardlink_write sh -c "printf X > '$ROOT/hardlink.json'"
measure_denial rename_away mv "$TARGET" "$ROOT/moved.json"
measure_denial unlink rm "$TARGET"

correct=0
incorrect=0
for _ in $(seq 1 100); do
  printf '{"role":"replacement"}\n' > "$ROOT/replacement.json"
  if mv -f "$ROOT/replacement.json" "$TARGET" 2>/dev/null; then
    incorrect=$((incorrect + 1))
  else
    correct=$((correct + 1))
    rm -f "$ROOT/replacement.json"
  fi
done
printf 'rename_overwrite,100,deny,%d,%d\n' "$correct" "$incorrect" >> "$OUT"

read_ok=0
unrelated_ok=0
for _ in $(seq 1 100); do
  cat "$TARGET" >/dev/null && read_ok=$((read_ok + 1))
  printf X > "$OTHER" && unrelated_ok=$((unrelated_ok + 1))
done
printf 'protected_read,100,allow,%d,%d\n' "$read_ok" "$((100-read_ok))" >> "$OUT"
printf 'unrelated_write,100,allow,%d,%d\n' "$unrelated_ok" "$((100-unrelated_ok))" >> "$OUT"

kill "$LOADER_PID"
wait "$LOADER_PID" || true
trap - EXIT
cat "$OUT"
