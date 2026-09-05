#!/bin/bash
set -euo pipefail

owner=vpnctl-v2-capacity-v1
root=/etc/vpnctl-v2-capacity
owner_path=$root/.owner
gateway_interface=v2capwg
client_table=vpnctl_v2_capacity_clients
client_names=(v2capc1 v2capc2 v2capc3 v2capc4 v2capc5)

owned() {
  [ -f "$owner_path" ] && grep -Fxq "$owner" "$owner_path"
}

assert_absent() {
  if [ -e "$root" ]; then
    echo "capacity root already exists" >&2
    exit 3
  fi
}

create_root() {
  install -d -m 0700 "$root"
  printf '%s\n' "$owner" > "$owner_path"
  chmod 0600 "$owner_path"
}

gateway_prepare() {
  assert_absent
  if ip link show "$gateway_interface" >/dev/null 2>&1; then
    echo "capacity gateway interface already exists" >&2
    exit 3
  fi
  if [ -n "$(ss -H -lun 'sport = :51820')" ]; then
    echo "UDP/51820 is already occupied" >&2
    exit 3
  fi
  create_root
  umask 077
  wg genkey > "$root/gateway.key"
  wg pubkey < "$root/gateway.key" > "$root/gateway.pub"
  ip link add "$gateway_interface" type wireguard
  wg set "$gateway_interface" private-key "$root/gateway.key" listen-port 51820
  ip address add 10.66.0.1/24 dev "$gateway_interface"
  ip address add 10.67.0.1/24 dev "$gateway_interface"
  ip link set "$gateway_interface" up
  cat "$root/gateway.pub"
}

node_prepare() {
  local gateway_ip=${1:?gateway IP is required}
  local gateway_public=${2:?gateway public key is required}
  local external_interface index namespace host_end host_address client_address private public
  assert_absent
  if nft list table ip "$client_table" >/dev/null 2>&1; then
    echo "capacity client nftables table already exists" >&2
    exit 3
  fi
  for namespace in "${client_names[@]}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
      echo "capacity namespace already exists: $namespace" >&2
      exit 3
    fi
  done
  external_interface=$(ip -4 route get "$gateway_ip" | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
  [ -n "$external_interface" ] || { echo "gateway route has no interface" >&2; exit 4; }
  create_root
  sysctl -n net.ipv4.ip_forward > "$root/ip-forward.before"
  sysctl -q -w net.ipv4.ip_forward=1
  nft add table ip "$client_table"
  nft "add chain ip $client_table postrouting { type nat hook postrouting priority srcnat; policy accept; }"
  nft add rule ip "$client_table" postrouting ip saddr 10.250.0.0/16 oifname "$external_interface" masquerade
  umask 077
  : > "$root/peers.conf"
  for index in 1 2 3 4 5; do
    namespace=${client_names[$((index - 1))]}
    host_end="v2cap${index}h"
    host_address="10.250.$index.1"
    client_address="10.250.$index.2"
    ip netns add "$namespace"
    ip -n "$namespace" link set lo up
    ip link add "$host_end" type veth peer name eth0 netns "$namespace"
    ip address add "$host_address/30" dev "$host_end"
    ip link set "$host_end" up
    ip -n "$namespace" address add "$client_address/30" dev eth0
    ip -n "$namespace" link set eth0 up
    ip -n "$namespace" route add default via "$host_address" dev eth0
    wg genkey > "$root/client-$index.key"
    wg pubkey < "$root/client-$index.key" > "$root/client-$index.pub"
    private=$root/client-$index.key
    public=$(tr -d '\n' < "$root/client-$index.pub")
    ip -n "$namespace" link add vpnctl-wg type wireguard
    ip netns exec "$namespace" wg set vpnctl-wg private-key "$private" \
      peer "$gateway_public" endpoint "$gateway_ip:51820" allowed-ips 10.66.0.1/32 persistent-keepalive 25
    ip -n "$namespace" address add "10.66.0.$((index + 1))/32" dev vpnctl-wg
    ip -n "$namespace" link set vpnctl-wg up
    ip -n "$namespace" route add 10.66.0.1/32 dev vpnctl-wg
    printf '%s 10.66.0.%s/32\n' "$public" "$((index + 1))" >> "$root/peers.conf"
  done
  chmod 0600 "$root"/*.key "$root/ip-forward.before" "$root/peers.conf"
  chmod 0644 "$root"/*.pub
  cat "$root/peers.conf"
}

gateway_install_peers() {
  local peers=${1:?peers file is required}
  local public allowed
  owned || { echo "capacity gateway root is not owned" >&2; exit 3; }
  [ -f "$peers" ] || { echo "capacity peers file is absent" >&2; exit 3; }
  while read -r public allowed; do
    [ -n "$public" ] && [ -n "$allowed" ] || { echo "invalid peer row" >&2; exit 3; }
    wg set "$gateway_interface" peer "$public" allowed-ips "$allowed"
  done < "$peers"
  [ "$(wg show "$gateway_interface" peers | wc -l | tr -d ' ')" = 5 ]
}

node_verify() {
  local namespace
  owned || { echo "capacity node root is not owned" >&2; exit 3; }
  for namespace in "${client_names[@]}"; do
    ip netns exec "$namespace" ping -n -q -c 2 -W 2 10.66.0.1 >/dev/null
    [ "$(ip netns exec "$namespace" wg show vpnctl-wg latest-handshakes | awk '{print $2}')" != 0 ]
  done
}

cleanup_gateway() {
  if [ ! -e "$root" ]; then
    return
  fi
  owned || { echo "refusing to clean unowned capacity gateway root" >&2; exit 3; }
  ip link delete "$gateway_interface" >/dev/null 2>&1 || true
  rm -rf -- "$root"
}

cleanup_node() {
  local namespace prior
  if [ ! -e "$root" ]; then
    return
  fi
  owned || { echo "refusing to clean unowned capacity node root" >&2; exit 3; }
  for namespace in "${client_names[@]}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
      ip netns delete "$namespace"
    fi
  done
  if nft list table ip "$client_table" >/dev/null 2>&1; then
    nft delete table ip "$client_table"
  fi
  prior=$(cat "$root/ip-forward.before")
  case "$prior" in
    0|1) sysctl -q -w "net.ipv4.ip_forward=$prior" ;;
    *) echo "refusing invalid saved ip_forward value" >&2; exit 3 ;;
  esac
  rm -rf -- "$root"
}

case "${1:-}" in
  gateway-prepare) [ "$#" -eq 1 ]; gateway_prepare ;;
  node-prepare) [ "$#" -eq 3 ]; node_prepare "$2" "$3" ;;
  gateway-install-peers) [ "$#" -eq 2 ]; gateway_install_peers "$2" ;;
  node-verify) [ "$#" -eq 1 ]; node_verify ;;
  cleanup-gateway) [ "$#" -eq 1 ]; cleanup_gateway ;;
  cleanup-node) [ "$#" -eq 1 ]; cleanup_node ;;
  *) echo "usage: clients.sh <gateway-prepare|node-prepare IP KEY|gateway-install-peers FILE|node-verify|cleanup-gateway|cleanup-node>" >&2; exit 2 ;;
esac
