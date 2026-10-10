#!/usr/bin/env bash
set -euo pipefail

output="${1:-results/baseline_capabilities.csv}"
probe_path="${2:-/tmp}"
mkdir -p "$(dirname "$output")"

present() {
  if command -v "$1" >/dev/null 2>&1; then printf 'yes'; else printf 'no'; fi
}

lsm="unavailable"
if [ -r /sys/kernel/security/lsm ]; then
  lsm="$(tr -d '\n' </sys/kernel/security/lsm)"
fi

selinux_state="unavailable"
if command -v getenforce >/dev/null 2>&1; then
  selinux_state="$(getenforce 2>/dev/null || printf 'error')"
elif [ -d /sys/fs/selinux ]; then
  selinux_state="filesystem-present-no-getenforce"
fi

filesystem="$(stat -f -c %T "$probe_path" 2>/dev/null || printf 'unknown')"
kernel="$(uname -r)"

printf 'kernel,probe_path,filesystem,lsm,apparmor_parser,aa_exec,getenforce,semodule,auditctl,fapolicyd,evmctl,selinux_state\n' >"$output"
printf '"%s","%s","%s","%s",%s,%s,%s,%s,%s,%s,%s,"%s"\n' \
  "$kernel" "$probe_path" "$filesystem" "$lsm" \
  "$(present apparmor_parser)" "$(present aa-exec)" \
  "$(present getenforce)" "$(present semodule)" \
  "$(present auditctl)" "$(present fapolicyd)" \
  "$(present evmctl)" "$selinux_state" >>"$output"

cat "$output"
