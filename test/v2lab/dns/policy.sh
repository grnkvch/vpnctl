#!/bin/bash
set -euo pipefail

table_name=vpnctl_v2_spike_dns
config_root=/etc/vpnctl-v2-spike/dns
runtime_root=/run/vpnctl-v2-spike-dns
dropin_path=/etc/systemd/resolved.conf.d/vpnctl-v2-dns-spike.conf
snapshot_path="$runtime_root/resolved-snapshot.env"
applied_marker="$runtime_root/integration-applied"
link_name=eth0
hold_domain='~vpnctl-v2-underlay.invalid'

table_exists() {
  nft list table inet "$table_name" >/dev/null 2>&1
}

link_value() {
  resolvectl "$1" "$link_name" | sed 's/^[^:]*: //'
}

snapshot() {
  if [ -e "$snapshot_path" ]; then
    echo "DNS integration snapshot already exists" >&2
    exit 3
  fi
  umask 077
  {
    printf 'ORIGINAL_DNS=%q\n' "$(link_value dns)"
    printf 'ORIGINAL_DOMAINS=%q\n' "$(link_value domain)"
    printf 'ORIGINAL_DEFAULT_ROUTE=%q\n' "$(link_value default-route)"
  } > "$snapshot_path"
}

load_snapshot() {
  if [ ! -f "$snapshot_path" ]; then
    echo "DNS integration snapshot is missing" >&2
    exit 3
  fi
  # shellcheck disable=SC1090
  . "$snapshot_path"
  [ -n "$ORIGINAL_DNS" ]
  [ -n "$ORIGINAL_DOMAINS" ]
  case "$ORIGINAL_DEFAULT_ROUTE" in yes|no) ;; *) echo "invalid saved default-route" >&2; exit 3 ;; esac
}

restore_link_values() {
  load_snapshot
  # Intentional word splitting restores the exact whitespace-separated values emitted by resolvectl.
  # shellcheck disable=SC2086
  resolvectl dns "$link_name" $ORIGINAL_DNS
  # shellcheck disable=SC2086
  resolvectl domain "$link_name" $ORIGINAL_DOMAINS
  resolvectl default-route "$link_name" "$ORIGINAL_DEFAULT_ROUTE"
}

preflight() {
  [ "$(systemd --version | awk 'NR == 1 {print $2}')" = 255 ]
  systemctl is-active --quiet systemd-resolved.service
  [ "$(readlink -f /etc/resolv.conf)" = /run/systemd/resolve/stub-resolv.conf ]
  ip link show "$link_name" >/dev/null
  if table_exists; then
    echo "DNS spike nftables table already exists" >&2
    exit 3
  fi
  if [ -e "$dropin_path" ]; then
    echo "DNS spike resolved drop-in already exists" >&2
    exit 3
  fi
  nft -c -f "$config_root/capture.nft"
}

restore() {
  local changed=false
  if [ -f "$snapshot_path" ] || [ -f "$applied_marker" ] || table_exists; then
    changed=true
  fi
  if [ "$changed" = false ]; then
    return
  fi
  if [ -f "$snapshot_path" ]; then
    load_snapshot
  elif [ -e "$dropin_path" ] || [ -f "$applied_marker" ]; then
    echo "refusing DNS restoration without original link snapshot" >&2
    exit 3
  fi
  rm -f "$dropin_path"
  if [ -f "$snapshot_path" ]; then
    systemctl restart systemd-resolved.service
    restore_link_values
    resolvectl flush-caches
  fi
  if table_exists; then
    nft delete table inet "$table_name"
  fi
  rm -f "$applied_marker" "$snapshot_path"
}

apply() {
  preflight
  install -d -m 0755 /etc/systemd/resolved.conf.d
  snapshot
  trap restore EXIT
  nft -f "$config_root/capture.nft"
  install -m 0644 "$config_root/resolved.conf" "$dropin_path"
  systemctl restart systemd-resolved.service
  resolvectl domain "$link_name" "$hold_domain"
  resolvectl flush-caches
  install -m 0600 /dev/null "$applied_marker"
  trap - EXIT
}

assert_applied() {
  [ -f "$applied_marker" ]
  table_exists
  [ -f "$dropin_path" ]
  [ "$(link_value domain)" = "$hold_domain" ]
  resolvectl dns | grep -Fq 'Global: 127.0.0.1:1053'
  resolvectl domain | grep -Fq 'Global: ~.'
}

assert_clean() {
  ! table_exists
  [ ! -e "$dropin_path" ]
  [ ! -e "$snapshot_path" ]
  [ ! -e "$applied_marker" ]
}

status() {
  local applied=false table=false dropin=false
  [ -f "$applied_marker" ] && applied=true
  table_exists && table=true
  [ -f "$dropin_path" ] && dropin=true
  jq -n \
    --argjson applied "$applied" \
    --argjson table "$table" \
    --argjson dropin "$dropin" \
    --arg global_dns "$(resolvectl dns | awk -F': ' '/^Global:/ {print $2}')" \
    --arg global_domains "$(resolvectl domain | awk -F': ' '/^Global:/ {print $2}')" \
    --arg link_dns "$(link_value dns)" \
    --arg link_domains "$(link_value domain)" \
    --arg link_default_route "$(link_value default-route)" \
    '{schema_version: 1, applied: $applied, nftables_table: $table, dropin: $dropin, global_dns: $global_dns, global_domains: $global_domains, link: {name: "eth0", dns: $link_dns, domains: $link_domains, default_route: $link_default_route}}'
}

case "${1:-}" in
  preflight) preflight ;;
  apply) apply ;;
  restore) restore ;;
  assert-applied) assert_applied ;;
  assert-clean) assert_clean ;;
  status) status ;;
  *) echo "usage: policy.sh <preflight|apply|restore|assert-applied|assert-clean|status>" >&2; exit 2 ;;
esac
