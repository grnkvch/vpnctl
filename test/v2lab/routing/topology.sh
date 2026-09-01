#!/bin/bash
set -euo pipefail

node_ns=vpnctl-v2-rnode
direct_ns=vpnctl-v2-rdirect
gateway_ns=vpnctl-v2-rgateway
runtime_root=/run/vpnctl-v2-spike-routing

namespace_exists() {
  ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

assert_absent() {
  local namespace
  for namespace in "$node_ns" "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      echo "routing spike namespace already exists: $namespace" >&2
      exit 3
    fi
  done
  for interface in v2ndtmp v2ddtmp v2ngtmp v2ggtmp; do
    if ip link show "$interface" >/dev/null 2>&1; then
      echo "routing spike temporary interface already exists: $interface" >&2
      exit 3
    fi
  done
}

prepare() {
  assert_absent
  install -d -m 0700 "$runtime_root"

  ip netns add "$node_ns"
  ip netns add "$direct_ns"
  ip netns add "$gateway_ns"
  trap cleanup ERR

  ip link add v2ndtmp type veth peer name v2ddtmp
  ip link set v2ndtmp netns "$node_ns"
  ip link set v2ddtmp netns "$direct_ns"
  ip -n "$node_ns" link set v2ndtmp name v2direct0
  ip -n "$direct_ns" link set v2ddtmp name v2node0

  ip link add v2ngtmp type veth peer name v2ggtmp
  ip link set v2ngtmp netns "$node_ns"
  ip link set v2ggtmp netns "$gateway_ns"
  ip -n "$node_ns" link set v2ngtmp name v2gateway0
  ip -n "$gateway_ns" link set v2ggtmp name v2node0

  for namespace in "$node_ns" "$direct_ns" "$gateway_ns"; do
    ip -n "$namespace" link set lo up
  done

  ip -n "$node_ns" address add 10.201.0.2/24 dev v2direct0
  ip -n "$direct_ns" address add 10.201.0.1/24 dev v2node0
  ip -n "$node_ns" address add 10.202.0.2/24 dev v2gateway0
  ip -n "$gateway_ns" address add 10.202.0.1/24 dev v2node0

  ip -n "$node_ns" -6 address add 2001:db8:100::2/64 dev v2direct0 nodad
  ip -n "$direct_ns" -6 address add 2001:db8:100::1/64 dev v2node0 nodad

  ip -n "$direct_ns" address add 203.0.113.10/32 dev lo
  ip -n "$direct_ns" address add 203.0.113.20/32 dev lo
  ip -n "$gateway_ns" address add 203.0.113.10/32 dev lo
  ip -n "$direct_ns" address add 198.51.100.50/32 dev lo
  ip -n "$gateway_ns" address add 198.51.100.50/32 dev lo
  ip -n "$direct_ns" -6 address add 2001:db8:1::10/128 dev lo nodad
  ip -n "$direct_ns" -6 address add 2001:db8:1::20/128 dev lo nodad

  ip -n "$node_ns" link set v2direct0 up
  ip -n "$direct_ns" link set v2node0 up
  ip -n "$node_ns" link set v2gateway0 up
  ip -n "$gateway_ns" link set v2node0 up

  ip -n "$node_ns" route add default via 10.201.0.1 dev v2direct0
  ip -n "$node_ns" -6 route add default via 2001:db8:100::1 dev v2direct0

  ip netns exec "$gateway_ns" ip route add 10.202.0.2/32 dev v2node0 src 198.51.100.50

  ip netns exec "$node_ns" nft -f - <<'EOF'
table inet foreign_keep {
  counter observed {}
  chain output {
    type route hook output priority 10; policy accept;
    counter name observed
  }
}
EOF
  ip netns exec "$node_ns" ip rule add priority 12000 fwmark 0x00001234/0x0000ffff lookup main

  trap - ERR
}

cleanup() {
  local namespace
  for namespace in "$node_ns" "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      ip netns delete "$namespace"
    fi
  done
  rm -rf "$runtime_root"
}

status() {
  local namespace
  for namespace in "$node_ns" "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      printf '%s=present\n' "$namespace"
    else
      printf '%s=absent\n' "$namespace"
    fi
  done
}

case "${1:-}" in
  prepare) prepare ;;
  cleanup) cleanup ;;
  status) status ;;
  *) echo "usage: topology.sh <prepare|cleanup|status>" >&2; exit 2 ;;
esac
