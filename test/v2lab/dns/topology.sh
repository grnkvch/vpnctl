#!/bin/bash
set -euo pipefail

direct_ns=vpnctl-v2-dns-direct
gateway_ns=vpnctl-v2-dns-gateway
direct_interface=v2dnsdirect0
gateway_interface=v2dnsgateway0
runtime_root=/run/vpnctl-v2-spike-dns

namespace_exists() {
  ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

assert_absent() {
  local namespace interface
  for namespace in "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      echo "DNS spike namespace already exists: $namespace" >&2
      exit 3
    fi
  done
  for interface in "$direct_interface" "$gateway_interface" v2ddnstmp v2gdnstmp; do
    if ip link show "$interface" >/dev/null 2>&1; then
      echo "DNS spike interface already exists: $interface" >&2
      exit 3
    fi
  done
}

prepare() {
  assert_absent
  install -d -m 0700 "$runtime_root"
  ip netns add "$direct_ns"
  ip netns add "$gateway_ns"
  trap cleanup ERR

  ip link add "$direct_interface" type veth peer name v2ddnstmp
  ip link set v2ddnstmp netns "$direct_ns"
  ip -n "$direct_ns" link set v2ddnstmp name v2node0
  ip address add 10.211.0.2/30 dev "$direct_interface"
  ip -n "$direct_ns" address add 10.211.0.1/30 dev v2node0

  ip link add "$gateway_interface" type veth peer name v2gdnstmp
  ip link set v2gdnstmp netns "$gateway_ns"
  ip -n "$gateway_ns" link set v2gdnstmp name v2node0
  ip address add 10.212.0.2/30 dev "$gateway_interface"
  ip -n "$gateway_ns" address add 10.212.0.1/30 dev v2node0

  ip link set "$direct_interface" up
  ip link set "$gateway_interface" up
  ip -n "$direct_ns" link set lo up
  ip -n "$direct_ns" link set v2node0 up
  ip -n "$gateway_ns" link set lo up
  ip -n "$gateway_ns" link set v2node0 up
  trap - ERR
}

cleanup() {
  local namespace
  for namespace in "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      ip netns delete "$namespace"
    fi
  done
  for interface in "$direct_interface" "$gateway_interface"; do
    if ip link show "$interface" >/dev/null 2>&1; then
      ip link delete "$interface"
    fi
  done
  rm -rf "$runtime_root"
}

status() {
  local namespace interface
  for namespace in "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      printf '%s=present\n' "$namespace"
    else
      printf '%s=absent\n' "$namespace"
    fi
  done
  for interface in "$direct_interface" "$gateway_interface"; do
    if ip link show "$interface" >/dev/null 2>&1; then
      printf '%s=present\n' "$interface"
    else
      printf '%s=absent\n' "$interface"
    fi
  done
}

case "${1:-}" in
  prepare) prepare ;;
  cleanup) cleanup ;;
  status) status ;;
  *) echo "usage: topology.sh <prepare|cleanup|status>" >&2; exit 2 ;;
esac
