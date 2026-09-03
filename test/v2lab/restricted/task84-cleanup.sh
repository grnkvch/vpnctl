#!/bin/sh
set -eu

runtime_root=/tmp/vpnctl-v2-restricted-uot-test
owner_value=vpnctl-v2-restricted-uot-test-v1
owner_path="$runtime_root/.owner"
capture_table=vpnctl_v2_task84_capture
role=${1:-}

case "$role" in
  gateway|node) ;;
  *) echo "usage: task84-cleanup.sh gateway|node" >&2; exit 2 ;;
esac

table_exists() {
  nft list table inet "$capture_table" >/dev/null 2>&1
}

if [ ! -e "$runtime_root" ]; then
  if [ "$role" = node ] && table_exists; then
    echo "refusing to delete task-8.4 capture table without the owned runtime marker" >&2
    exit 3
  fi
  exit 0
fi
if [ ! -f "$owner_path" ] || ! grep -Fxq "$owner_value" "$owner_path"; then
  echo "refusing to operate on unowned task-8.4 runtime: $runtime_root" >&2
  exit 3
fi

terminate_owned_processes() {
  signal=$1
  for executable in /proc/[0-9]*/exe; do
    target=$(readlink -f "$executable" 2>/dev/null || true)
    case "$target" in
      "$runtime_root/transport.test"|"$runtime_root/mihomo")
        pid=${executable#/proc/}
        pid=${pid%/exe}
        kill -"$signal" "$pid" >/dev/null 2>&1 || true
        ;;
    esac
  done
}

terminate_owned_processes TERM
attempt=0
while [ "$attempt" -lt 50 ]; do
  running=false
  for executable in /proc/[0-9]*/exe; do
    target=$(readlink -f "$executable" 2>/dev/null || true)
    case "$target" in
      "$runtime_root/transport.test"|"$runtime_root/mihomo") running=true ;;
    esac
  done
  [ "$running" = false ] && break
  sleep 0.1
  attempt=$((attempt + 1))
done
terminate_owned_processes KILL

if [ "$role" = node ] && table_exists; then
  nft delete table inet "$capture_table"
fi
rm -rf -- "$runtime_root"
