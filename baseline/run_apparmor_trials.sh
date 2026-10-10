#!/usr/bin/env bash
set -euo pipefail

ROOT=/tmp/sentinelpath_apparmor_trials
PROFILE=sentinelpath-apparmor
PROFILE_FILE=${1:?usage: run_apparmor_trials.sh PROFILE_FILE OUTPUT_CSV}
OUT=${2:?usage: run_apparmor_trials.sh PROFILE_FILE OUTPUT_CSV}
EXPECTED='{"role":"viewer"}'

if [[ "$(realpath -m "$ROOT")" != /tmp/sentinelpath_apparmor_trials ]]; then
  echo "unsafe trial path" >&2
  exit 2
fi

mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security
apparmor_parser -r "$PROFILE_FILE"
trap 'apparmor_parser -R "$PROFILE_FILE" 2>/dev/null || true' EXIT

rm -rf "$ROOT"
mkdir -p "$ROOT"

reset_fixture() {
  rm -f "$ROOT/protected.json" "$ROOT/unrelated.json" "$ROOT/symlink.json" \
    "$ROOT/hardlink.json" "$ROOT/moved.json" "$ROOT/replacement.json"
  printf '%s\n' "$EXPECTED" > "$ROOT/protected.json"
  printf '%s\n' "$EXPECTED" > "$ROOT/unrelated.json"
  ln -s "$ROOT/protected.json" "$ROOT/symlink.json"
  ln "$ROOT/protected.json" "$ROOT/hardlink.json"
}

run_confined() {
  aa-exec -p "$PROFILE" -- "$@"
}

printf 'mechanism,case,trial,expected,command_rc,decision_correct,state_correct,observed\n' > "$OUT"

run_case() {
  local name=$1 expected_decision=$2
  local trial rc decision_ok state_ok observed
  for trial in $(seq 1 100); do
    reset_fixture
    set +e
    case "$name" in
      direct_write) run_confined /usr/bin/bash -c "printf X > '$ROOT/protected.json'" ;;
      symlink_write) run_confined /usr/bin/bash -c "printf X > '$ROOT/symlink.json'" ;;
      hardlink_write) run_confined /usr/bin/bash -c "printf X > '$ROOT/hardlink.json'" ;;
      rename_away) run_confined /usr/bin/mv "$ROOT/protected.json" "$ROOT/moved.json" ;;
      unlink) run_confined /usr/bin/rm "$ROOT/protected.json" ;;
      rename_overwrite)
        printf '%s\n' '{"role":"replacement"}' > "$ROOT/replacement.json"
        run_confined /usr/bin/mv -f "$ROOT/replacement.json" "$ROOT/protected.json"
        ;;
      protected_read) run_confined /usr/bin/cat "$ROOT/protected.json" >/dev/null ;;
      unrelated_write) run_confined /usr/bin/bash -c "printf X > '$ROOT/unrelated.json'" ;;
      *) echo "unknown case: $name" >&2; exit 2 ;;
    esac
    rc=$?
    set -e

    if [[ "$expected_decision" == deny ]]; then
      [[ $rc -ne 0 ]] && decision_ok=1 || decision_ok=0
      if [[ -f "$ROOT/protected.json" ]] && [[ "$(tr -d '\n' < "$ROOT/protected.json")" == "$EXPECTED" ]]; then
        state_ok=1
      else
        state_ok=0
      fi
    else
      [[ $rc -eq 0 ]] && decision_ok=1 || decision_ok=0
      if [[ "$name" == protected_read ]]; then
        [[ -f "$ROOT/protected.json" ]] && state_ok=1 || state_ok=0
      else
        [[ "$(cat "$ROOT/unrelated.json" 2>/dev/null || true)" == X ]] && state_ok=1 || state_ok=0
      fi
    fi
    [[ $rc -eq 0 ]] && observed=allow || observed=deny
    printf 'AppArmor,%s,%d,%s,%d,%d,%d,%s\n' \
      "$name" "$trial" "$expected_decision" "$rc" "$decision_ok" "$state_ok" "$observed" >> "$OUT"
  done
}

run_case direct_write deny
run_case symlink_write deny
run_case hardlink_write deny
run_case rename_away deny
run_case unlink deny
run_case rename_overwrite deny
run_case protected_read allow
run_case unrelated_write allow

apparmor_parser -R "$PROFILE_FILE"
trap - EXIT

awk -F, 'NR>1 {k=$2 FS $4; n[k]++; d[k]+=$6; s[k]+=$7} END {print "case,expected,trials,decision_correct,state_correct"; for (k in n) print k FS n[k] FS d[k] FS s[k]}' "$OUT" | sort
