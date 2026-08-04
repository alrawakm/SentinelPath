#!/usr/bin/env bash
set -euo pipefail

ROOT=/var/tmp/sentinelpath_selinux
BIN=/usr/local/libexec/sentinelpath_op
OUT=${1:-selinux_trials.csv}
ATTEMPTS=${ATTEMPTS:-100}
SAFE='{"role":"viewer"}'
REPLACEMENT='{"role":"replacement"}'

if [[ "$(realpath -m "$ROOT")" != /var/tmp/sentinelpath_selinux ]]; then
  echo "unsafe fixture root" >&2
  exit 2
fi

reset_fixture() {
  sudo rm -rf -- "$ROOT"
  sudo install -d -m 0777 "$ROOT"
  printf '%s\n' "$SAFE" | sudo tee "$ROOT/protected.json" >/dev/null
  printf '%s\n' "$SAFE" | sudo tee "$ROOT/unrelated.json" >/dev/null
  printf '%s\n' "$REPLACEMENT" | sudo tee "$ROOT/replacement.json" >/dev/null
  sudo chmod 0666 "$ROOT"/*.json
  sudo restorecon -RF "$ROOT"
  sudo chcon -t sentinelpath_protected_t "$ROOT/protected.json"
  sudo ln -s "$ROOT/protected.json" "$ROOT/symlink.json"
  sudo ln "$ROOT/protected.json" "$ROOT/hardlink.json"
}

hash_or_missing() {
  if [[ -e "$1" ]]; then sha256sum "$1" | awk '{print $1}'; else printf missing; fi
}

printf 'case,attempt,expected,exit_code,decision_correct,state_correct,pre_device,pre_inode,post_device,post_inode,pre_hash,post_hash,hardlink_device,hardlink_inode,hardlink_type,audit_evidence\n' > "$OUT"

cases=(direct_write symlink_write hardlink_write rename_away rename_overwrite unlink protected_read unrelated_write)
for case_name in "${cases[@]}"; do
  if [[ "$case_name" == protected_read || "$case_name" == unrelated_write ]]; then
    expected=allow
  else
    expected=deny
  fi
  for attempt in $(seq 1 "$ATTEMPTS"); do
    reset_fixture
    read -r pre_dev pre_ino < <(stat -Lc '%d %i' "$ROOT/protected.json")
    pre_hash=$(hash_or_missing "$ROOT/protected.json")
    if "$BIN" "$case_name" "$ROOT" >/dev/null 2>&1; then rc=0; else rc=$?; fi
    if [[ "$expected" == deny ]]; then
      [[ $rc -ne 0 ]] && decision_correct=1 || decision_correct=0
    else
      [[ $rc -eq 0 ]] && decision_correct=1 || decision_correct=0
    fi
    post_hash=$(hash_or_missing "$ROOT/protected.json")
    if [[ -e "$ROOT/protected.json" ]]; then
      read -r post_dev post_ino < <(stat -Lc '%d %i' "$ROOT/protected.json")
    else
      post_dev=missing; post_ino=missing
    fi
    if [[ "$case_name" == unrelated_write || "$case_name" == protected_read ]]; then
      [[ "$post_hash" == "$pre_hash" ]] && state_correct=1 || state_correct=0
    else
      [[ "$post_hash" == "$pre_hash" && "$post_dev" == "$pre_dev" && "$post_ino" == "$pre_ino" ]] && state_correct=1 || state_correct=0
    fi
    read -r hard_dev hard_ino < <(stat -Lc '%d %i' "$ROOT/hardlink.json")
    hard_type=$(stat -Lc '%C' "$ROOT/hardlink.json" | awk -F: '{print $3}')
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$case_name" "$attempt" "$expected" "$rc" "$decision_correct" "$state_correct" \
      "$pre_dev" "$pre_ino" "$post_dev" "$post_ino" "$pre_hash" "$post_hash" \
      "$hard_dev" "$hard_ino" "$hard_type" "bounded_avc_log" >> "$OUT"
  done
done

python3 - "$OUT" <<'PY'
import csv, sys
from collections import defaultdict
rows = list(csv.DictReader(open(sys.argv[1], newline='', encoding='utf-8')))
groups = defaultdict(list)
for row in rows:
    groups[row['case']].append(row)
print('case,attempts,expected,decision_correct,state_correct')
for name, group in groups.items():
    print(','.join([
        name, str(len(group)), group[0]['expected'],
        str(sum(int(r['decision_correct']) for r in group)),
        str(sum(int(r['state_correct']) for r in group)),
    ]))
PY
