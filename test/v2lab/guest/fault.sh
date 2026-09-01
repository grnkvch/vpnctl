#!/bin/bash
set -euo pipefail

action=${1:?action is required}
peer_ip=${2:-}
value=${3:-}
fault_table=vpnctl_v2_lab_fault
fault_qdisc_handle=1abc:

delete_fault_table() {
  nft list table inet "$fault_table" >/dev/null 2>&1 && nft delete table inet "$fault_table" || true
}

clear_netem() {
  local interface
  interface=$(peer_interface)
  if tc qdisc show dev "$interface" | grep -Fq "qdisc netem $fault_qdisc_handle"; then
    tc qdisc del dev "$interface" root >/dev/null 2>&1 || true
  fi
}

peer_interface() {
  test -n "$peer_ip"
  ip -4 -j route get "$peer_ip" | jq -er '.[0].dev'
}

case "$action" in
  clear)
    clear_netem
    delete_fault_table
    ;;
  latency)
    [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -le 60000 ]
    delete_fault_table
    tc qdisc replace dev "$(peer_interface)" root handle "$fault_qdisc_handle" netem delay "${value}ms"
    ;;
  loss)
    [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
    awk -v value="$value" 'BEGIN {exit !(value >= 0 && value <= 100)}'
    delete_fault_table
    tc qdisc replace dev "$(peer_interface)" root handle "$fault_qdisc_handle" netem loss "${value}%"
    ;;
  partition)
    test -n "$peer_ip"
    clear_netem
    delete_fault_table
    nft -f - <<EOF
table inet $fault_table {
  chain input {
    type filter hook input priority -300; policy accept;
    ip saddr $peer_ip drop
  }
  chain output {
    type filter hook output priority -300; policy accept;
    ip daddr $peer_ip drop
  }
}
EOF
    ;;
  *)
    echo "unknown fault action: $action" >&2
    exit 2
    ;;
esac
