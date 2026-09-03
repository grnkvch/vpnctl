#!/bin/bash
set -euo pipefail

runtime_root=/tmp/vpnctl-v2-standard-test
firewall_path="$runtime_root/gateway.nft"
backend_path="$runtime_root/backend.py"
probe_path="$runtime_root/probe.py"
gateway_ns=vpnctl-v2-wg-gateway
network_ns=vpnctl-v2-wg-network
wan_ns=vpnctl-v2-wg-wan
client_names=(vpnctl-v2-wg-c1 vpnctl-v2-wg-c2 vpnctl-v2-wg-c3 vpnctl-v2-wg-c4 vpnctl-v2-wg-c5)
node_names=(vpnctl-v2-wg-n1 vpnctl-v2-wg-n2)
all_names=("$gateway_ns" "$network_ns" "$wan_ns" "${client_names[@]}" "${node_names[@]}")
pids=()

namespace_exists() {
  ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

stop_backends() {
  local pid
  for pid in "${pids[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${pids[@]:-}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
  pids=()
}

cleanup() {
  local namespace
  stop_backends
  for namespace in "${all_names[@]}"; do
    if namespace_exists "$namespace"; then
      ip netns delete "$namespace"
    fi
  done
  rm -f "$runtime_root"/*.key "$runtime_root"/*.pub "$runtime_root"/*-state.json
}

assert_absent() {
  local namespace interface
  for namespace in "${all_names[@]}"; do
    if namespace_exists "$namespace"; then
      echo "standard test namespace already exists: $namespace" >&2
      exit 3
    fi
  done
  for interface in v2wggwh v2wggwn v2wgc1h v2wgc1n v2wgc2h v2wgc2n v2wgc3h v2wgc3n v2wgc4h v2wgc4n v2wgc5h v2wgc5n v2wgn1h v2wgn1n v2wgn2h v2wgn2n v2wgwwh v2wgwwn; do
    if ip link show "$interface" >/dev/null 2>&1; then
      echo "standard test interface already exists: $interface" >&2
      exit 3
    fi
  done
}

connect_underlay() {
  local namespace=$1 host_end=$2 network_end=$3 address=$4
  ip link add "$host_end" type veth peer name "$network_end"
  ip link set "$host_end" netns "$namespace"
  ip link set "$network_end" netns "$network_ns"
  ip -n "$namespace" link set "$host_end" name eth0
  ip -n "$network_ns" link set "$network_end" master br0
  ip -n "$namespace" address add "$address/24" dev eth0
  ip -n "$namespace" link set eth0 up
  ip -n "$network_ns" link set "$network_end" up
}

generate_key() {
  local name=$1
  umask 077
  wg genkey > "$runtime_root/$name.key"
  wg pubkey < "$runtime_root/$name.key" > "$runtime_root/$name.pub"
}

prepare_namespaces() {
  assert_absent
  trap cleanup EXIT INT TERM

  local namespace
  for namespace in "${all_names[@]}"; do
    ip netns add "$namespace"
    ip -n "$namespace" link set lo up
  done
  ip -n "$network_ns" link add br0 type bridge
  ip -n "$network_ns" link set br0 up

  connect_underlay "$gateway_ns" v2wggwh v2wggwn 192.0.2.1
  connect_underlay "${client_names[0]}" v2wgc1h v2wgc1n 192.0.2.11
  connect_underlay "${client_names[1]}" v2wgc2h v2wgc2n 192.0.2.12
  connect_underlay "${client_names[2]}" v2wgc3h v2wgc3n 192.0.2.13
  connect_underlay "${client_names[3]}" v2wgc4h v2wgc4n 192.0.2.14
  connect_underlay "${client_names[4]}" v2wgc5h v2wgc5n 192.0.2.15
  connect_underlay "${node_names[0]}" v2wgn1h v2wgn1n 192.0.2.21
  connect_underlay "${node_names[1]}" v2wgn2h v2wgn2n 192.0.2.22
  connect_underlay "$wan_ns" v2wgwwh v2wgwwn 192.0.2.254

  ip -n "$wan_ns" address add 198.51.100.254/32 dev lo
  ip -n "$gateway_ns" route add 198.51.100.254/32 via 192.0.2.254 dev eth0
  ip netns exec "$gateway_ns" sysctl -q -w net.ipv4.ip_forward=1
}

prepare_wireguard() {
  local name namespace index private_path public_key gateway_public peer_args=()
  generate_key gateway
  gateway_public=$(tr -d '\n' < "$runtime_root/gateway.pub")
  for index in 1 2 3 4 5; do
    generate_key "c$index"
    public_key=$(tr -d '\n' < "$runtime_root/c$index.pub")
    peer_args+=(peer "$public_key" allowed-ips "10.66.0.$((index + 1))/32")
  done
  for index in 1 2; do
    generate_key "n$index"
    public_key=$(tr -d '\n' < "$runtime_root/n$index.pub")
    peer_args+=(peer "$public_key" allowed-ips "10.67.0.$((index + 1))/32")
  done

  ip -n "$gateway_ns" link add vpnctl-wg type wireguard
  ip netns exec "$gateway_ns" wg set vpnctl-wg private-key "$runtime_root/gateway.key" listen-port 51820 "${peer_args[@]}"
  ip -n "$gateway_ns" address add 10.66.0.1/24 dev vpnctl-wg
  ip -n "$gateway_ns" address add 10.67.0.1/24 dev vpnctl-wg
  ip -n "$gateway_ns" link set vpnctl-wg up

  for index in 1 2 3 4 5; do
    namespace=${client_names[$((index - 1))]}
    private_path="$runtime_root/c$index.key"
    ip -n "$namespace" link add vpnctl-wg type wireguard
    ip netns exec "$namespace" wg set vpnctl-wg private-key "$private_path" \
      peer "$gateway_public" endpoint 192.0.2.1:51820 allowed-ips 0.0.0.0/0 persistent-keepalive 25
    ip -n "$namespace" address add "10.66.0.$((index + 1))/32" dev vpnctl-wg
    ip -n "$namespace" link set vpnctl-wg up
    ip -n "$namespace" route add 10.66.0.1/32 dev vpnctl-wg
    ip -n "$namespace" route add 10.67.0.0/24 dev vpnctl-wg
    ip -n "$namespace" route add 10.66.0.0/24 dev vpnctl-wg
    ip -n "$namespace" route add 198.51.100.254/32 dev vpnctl-wg
  done
  for index in 1 2; do
    namespace=${node_names[$((index - 1))]}
    private_path="$runtime_root/n$index.key"
    ip -n "$namespace" link add vpnctl-wg type wireguard
    ip netns exec "$namespace" wg set vpnctl-wg private-key "$private_path" \
      peer "$gateway_public" endpoint 192.0.2.1:51820 allowed-ips 0.0.0.0/0 persistent-keepalive 25
    ip -n "$namespace" address add "10.67.0.$((index + 1))/32" dev vpnctl-wg
    ip -n "$namespace" link set vpnctl-wg up
    ip -n "$namespace" route add 10.67.0.1/32 dev vpnctl-wg
    ip -n "$namespace" route add 10.66.0.0/24 dev vpnctl-wg
    ip -n "$namespace" route add 10.67.0.0/24 dev vpnctl-wg
    ip -n "$namespace" route add 198.51.100.254/32 dev vpnctl-wg
  done

  ip netns exec "$gateway_ns" nft --check --file "$firewall_path"
  ip netns exec "$gateway_ns" nft --file "$firewall_path"
}

start_backends() {
  ip netns exec "$gateway_ns" "$backend_path" \
    --state "$runtime_root/gateway-state.json" \
    --tcp 0.0.0.0:53=gateway-dns-tcp \
    --udp 0.0.0.0:53=gateway-dns-udp \
    --tcp 0.0.0.0:9443=gateway-control \
    --tcp 0.0.0.0:17000=gateway-tunnel &
  pids+=("$!")
  ip netns exec "$wan_ns" "$backend_path" \
    --state "$runtime_root/wan-state.json" \
    --tcp 198.51.100.254:18080=internet-tcp \
    --udp 198.51.100.254:18080=internet-udp &
  pids+=("$!")
  ip netns exec "${client_names[1]}" "$backend_path" \
    --state "$runtime_root/client-victim-state.json" \
    --tcp 0.0.0.0:18082=client-victim &
  pids+=("$!")
  ip netns exec "${node_names[1]}" "$backend_path" \
    --state "$runtime_root/node-victim-state.json" \
    --tcp 0.0.0.0:18082=node-victim &
  pids+=("$!")

  local attempt
  for attempt in $(seq 1 50); do
    if ip netns exec "$gateway_ns" ss -H -lnt | grep -q ':17000 ' && \
      ip netns exec "$wan_ns" ss -H -lnt | grep -q ':18080 ' && \
      ip netns exec "${client_names[1]}" ss -H -lnt | grep -q ':18082 ' && \
      ip netns exec "${node_names[1]}" ss -H -lnt | grep -q ':18082 '; then
      return
    fi
    sleep 0.1
  done
  echo "standard test backends did not become ready" >&2
  exit 1
}

request() {
  local namespace=$1 protocol=$2 host=$3 port=$4 expected=$5
  ip netns exec "$namespace" "$probe_path" request \
    --protocol "$protocol" --host "$host" --port "$port" --expect "$expected" --timeout 1 >/dev/null
}

blocked() {
  local namespace=$1 host=$2 port=$3
  ip netns exec "$namespace" "$probe_path" blocked \
    --protocol tcp --host "$host" --port "$port" --timeout 0.35 >/dev/null
}

verify_reachability() {
  local namespace
  for namespace in "${client_names[@]}" "${node_names[@]}"; do
    request "$namespace" tcp 198.51.100.254 18080 internet-tcp
    request "$namespace" udp 198.51.100.254 18080 internet-udp
  done
  for namespace in "${client_names[@]}"; do
    request "$namespace" tcp 10.66.0.1 53 gateway-dns-tcp
    request "$namespace" udp 10.66.0.1 53 gateway-dns-udp
    blocked "$namespace" 10.66.0.1 9443
    blocked "$namespace" 10.66.0.1 17000
  done
  for namespace in "${node_names[@]}"; do
    request "$namespace" tcp 10.67.0.1 53 gateway-dns-tcp
    request "$namespace" udp 10.67.0.1 53 gateway-dns-udp
    request "$namespace" tcp 10.67.0.1 9443 gateway-control
    request "$namespace" tcp 10.67.0.1 17000 gateway-tunnel
  done

  blocked "${client_names[0]}" 10.66.0.3 18082
  blocked "${client_names[0]}" 10.67.0.3 18082
  blocked "${node_names[0]}" 10.66.0.3 18082
  blocked "${node_names[0]}" 10.67.0.3 18082
}

verify_wireguard_state() {
  local namespace public_key handshake peer_count
  if [ "$(ip netns exec "$gateway_ns" wg show vpnctl-wg listen-port)" != "51820" ]; then
    echo "gateway WireGuard listener is not pinned to UDP/51820" >&2
    exit 1
  fi
  peer_count=$(ip netns exec "$gateway_ns" wg show vpnctl-wg peers | wc -l | tr -d ' ')
  if [ "$peer_count" != "7" ]; then
    echo "gateway WireGuard peer count is $peer_count, want 7" >&2
    exit 1
  fi
  for namespace in "${client_names[@]}" "${node_names[@]}"; do
    public_key=$(ip netns exec "$namespace" wg show vpnctl-wg peers)
    handshake=$(ip netns exec "$namespace" wg show vpnctl-wg latest-handshakes | awk -v key="$public_key" '$1 == key {print $2}')
    if [ -z "$handshake" ] || [ "$handshake" = "0" ]; then
      echo "missing WireGuard handshake in $namespace" >&2
      exit 1
    fi
  done
}

verify() {
  local required
  for required in "$firewall_path" "$backend_path" "$probe_path"; do
    if [ ! -f "$required" ]; then
      echo "missing standard test input: $required" >&2
      exit 3
    fi
  done
  for required in ip wg nft python3; do
    command -v "$required" >/dev/null
  done
  prepare_namespaces
  prepare_wireguard
  start_backends
  verify_reachability
  verify_wireguard_state
  printf '{"schema_version":1,"status":"passed","checks":{"wireguard_udp_51820":true,"unique_peer_credentials":true,"five_clients":true,"two_nodes":true,"gateway_service_scope":true,"internet_tcp_udp":true,"lateral_isolation":true,"handshakes":true}}\n'
}

status() {
  local namespace
  for namespace in "${all_names[@]}"; do
    if namespace_exists "$namespace"; then
      printf '%s=present\n' "$namespace"
    else
      printf '%s=absent\n' "$namespace"
    fi
  done
}

case "${1:-}" in
  verify) verify ;;
  cleanup) cleanup ;;
  status) status ;;
  *) echo "usage: namespace.sh <verify|cleanup|status>" >&2; exit 2 ;;
esac
