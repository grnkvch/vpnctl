#!/bin/bash
set -euo pipefail

table_name=vpnctl_v2_spike_routing
base_rules=/etc/vpnctl-v2-spike/routing/base.nft
runtime_root=/run/vpnctl-v2-spike-routing
snapshot_path="$runtime_root/policy-snapshot.env"
applied_marker="$runtime_root/policy-applied"
mark_mask=0xff000000
direct_mark=0x01000000
selected_mark=0x02000000
recovery_mark=0x03000000
ingress_mark=0x04000000
selected_table=20001
gateway_table=20002

table_exists() {
  nft list table inet "$table_name" >/dev/null 2>&1
}

priority_exists() {
  local priority=$1
  ip rule show | awk -F: -v priority="$priority" '$1 + 0 == priority {found = 1} END {exit !found}'
}

routes_for_table() {
  local routes
  if routes=$(ip -j route show table "$1" 2>/dev/null); then
    printf '%s\n' "$routes"
  else
    printf '[]\n'
  fi
}

assert_no_mark_overlap() {
  local mark mask
  while IFS=$'\t' read -r mark mask; do
    [ -n "$mark" ] || continue
    mask=${mask:-0xffffffff}
    if (( (mask & mark_mask) != 0 )); then
      echo "existing policy rule overlaps vpnctl high-byte mark namespace: $mark/$mask" >&2
      exit 3
    fi
  done < <(ip -j rule show | jq -r '.[] | select(.fwmark != null) | [.fwmark, (.fwmask // "0xffffffff")] | @tsv')
}

preflight() {
  if table_exists; then
    echo "routing spike nftables table already exists" >&2
    exit 3
  fi
  for priority in 10000 10010 10020; do
    if priority_exists "$priority"; then
      echo "routing spike policy priority already exists: $priority" >&2
      exit 3
    fi
  done
  if [ "$(routes_for_table "$selected_table" | jq 'length')" -ne 0 ] ||
    [ "$(routes_for_table "$gateway_table" | jq 'length')" -ne 0 ]; then
    echo "routing spike policy table is already in use" >&2
    exit 3
  fi
  assert_no_mark_overlap
  nft -c -f "$base_rules"
}

snapshot_sysctls() {
  umask 077
  {
    printf 'SRC_VALID_MARK=%q\n' "$(sysctl -n net.ipv4.conf.all.src_valid_mark)"
    printf 'RP_FILTER_ALL=%q\n' "$(sysctl -n net.ipv4.conf.all.rp_filter)"
    printf 'RP_FILTER_DIRECT=%q\n' "$(sysctl -n net.ipv4.conf.v2direct0.rp_filter)"
    printf 'RP_FILTER_GATEWAY=%q\n' "$(sysctl -n net.ipv4.conf.v2gateway0.rp_filter)"
  } > "$snapshot_path"
}

set_policy_sysctls() {
  sysctl -q -w net.ipv4.conf.all.src_valid_mark=1
  sysctl -q -w net.ipv4.conf.all.rp_filter=1
  sysctl -q -w net.ipv4.conf.v2direct0.rp_filter=1
  sysctl -q -w net.ipv4.conf.v2gateway0.rp_filter=1
}

restore_sysctls() {
  if [ ! -f "$snapshot_path" ]; then
    return
  fi
  # shellcheck disable=SC1090
  . "$snapshot_path"
  sysctl -q -w "net.ipv4.conf.all.src_valid_mark=$SRC_VALID_MARK"
  sysctl -q -w "net.ipv4.conf.all.rp_filter=$RP_FILTER_ALL"
  sysctl -q -w "net.ipv4.conf.v2direct0.rp_filter=$RP_FILTER_DIRECT"
  sysctl -q -w "net.ipv4.conf.v2gateway0.rp_filter=$RP_FILTER_GATEWAY"
}

delete_exact_rules() {
  while priority_exists 10000; do ip rule del priority 10000; done
  while priority_exists 10010; do ip rule del priority 10010; done
  while priority_exists 10020; do ip rule del priority 10020; done
}

remove_policy_routes() {
  ip route flush table "$selected_table" >/dev/null 2>&1 || true
  ip route flush table "$gateway_table" >/dev/null 2>&1 || true
}

rollback() {
  if table_exists; then
    nft delete table inet "$table_name" || true
  fi
  delete_exact_rules
  remove_policy_routes
  restore_sysctls || true
  rm -f "$applied_marker" "$snapshot_path"
}

guard() {
  local inject=${1:-}
  preflight
  install -d -m 0700 "$runtime_root"
  snapshot_sysctls
  trap rollback EXIT
  set_policy_sysctls
  ip route add unreachable default metric 42760 table "$selected_table"
  ip route add default via 10.202.0.1 dev v2gateway0 table "$gateway_table"
  ip rule add priority 10000 fwmark "$recovery_mark/$mark_mask" table "$gateway_table"
  ip rule add priority 10010 fwmark "$ingress_mark/$mark_mask" table "$gateway_table"
  ip rule add priority 10020 fwmark "$selected_mark/$mark_mask" table "$selected_table"
  if [ "$inject" = after-rules ]; then
    false
  fi
  nft -f "$base_rules"
  if [ "$inject" = after-nft ]; then
    false
  fi
  install -m 0600 /dev/null "$applied_marker"
  trap - EXIT
}

switch_readiness() {
  local target=$1
  if ! table_exists; then
    echo "routing spike guard is not installed" >&2
    exit 3
  fi
  nft -f - <<EOF
flush chain inet $table_name readiness
add rule inet $table_name readiness jump $target
EOF
}

not_ready() {
  if ! table_exists; then
    return
  fi
  switch_readiness not_ready
  ip route del default dev v2tun0 metric 10 table "$selected_table" >/dev/null 2>&1 || true
}

ready() {
  ip link show v2tun0 >/dev/null
  ip route replace default dev v2tun0 metric 10 table "$selected_table"
  switch_readiness ready
}

wait_ready() {
  local attempt
  for attempt in $(seq 1 60); do
    if ip link show v2tun0 >/dev/null 2>&1; then
      ready
      return
    fi
    sleep 0.25
  done
  echo "Mihomo TUN did not become ready" >&2
  exit 1
}

remove() {
  if table_exists; then
    not_ready
    nft delete table inet "$table_name"
  fi
  delete_exact_rules
  remove_policy_routes
  restore_sysctls
  rm -f "$applied_marker" "$snapshot_path"
}

assert_clean() {
  ! table_exists
  ! priority_exists 10000
  ! priority_exists 10010
  ! priority_exists 10020
  [ "$(routes_for_table "$selected_table" | jq 'length')" -eq 0 ]
  [ "$(routes_for_table "$gateway_table" | jq 'length')" -eq 0 ]
}

status() {
  local readiness=absent
  if table_exists; then
    if nft list chain inet "$table_name" readiness | grep -q 'jump ready'; then
      readiness=ready
    else
      readiness=not-ready
    fi
  fi
  jq -n \
    --arg readiness "$readiness" \
    --argjson rules "$(ip -j rule show | jq '[.[] | select(.priority == 10000 or .priority == 10010 or .priority == 10020)]')" \
    --argjson selected_routes "$(routes_for_table "$selected_table")" \
    --argjson gateway_routes "$(routes_for_table "$gateway_table")" \
    '{schema_version: 1, readiness: $readiness, rules: $rules, selected_routes: $selected_routes, gateway_routes: $gateway_routes}'
}

case "${1:-}" in
  preflight) preflight ;;
  guard) guard "${2:-}" ;;
  not-ready) not_ready ;;
  ready) ready ;;
  wait-ready) wait_ready ;;
  remove) remove ;;
  rollback) rollback ;;
  assert-clean) assert_clean ;;
  status) status ;;
  *) echo "usage: policy.sh <preflight|guard [after-rules|after-nft]|not-ready|ready|wait-ready|remove|rollback|assert-clean|status>" >&2; exit 2 ;;
esac
