#!/bin/bash
set -euo pipefail

gateway_ns=vpnctl-v2-fw-gateway
overlay_ns=vpnctl-v2-fw-overlay
wan_ns=vpnctl-v2-fw-wan
victim_ns=vpnctl-v2-fw-victim
runtime_root=/tmp/vpnctl-v2-firewall-test
rules_path="$runtime_root/gateway.nft"
minimal_rules_path="$runtime_root/gateway-minimal.nft"
backend_path="$runtime_root/backend.py"
probe_path="$runtime_root/probe.py"
foreign_before="$runtime_root/foreign-before.nft"
foreign_after="$runtime_root/foreign-after.nft"
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
  for namespace in "$gateway_ns" "$overlay_ns" "$wan_ns" "$victim_ns"; do
    if namespace_exists "$namespace"; then
      ip netns delete "$namespace"
    fi
  done
  rm -f "$foreign_before" "$foreign_after" \
    "$runtime_root/gateway-state.json" "$runtime_root/wan-state.json" "$runtime_root/victim-state.json"
}

assert_absent() {
  local namespace interface
  for namespace in "$gateway_ns" "$overlay_ns" "$wan_ns" "$victim_ns"; do
    if namespace_exists "$namespace"; then
      echo "firewall test namespace already exists: $namespace" >&2
      exit 3
    fi
  done
  for interface in v2fwgo v2fwoh v2fwgw v2fwwh v2fwgv v2fwvh; do
    if ip link show "$interface" >/dev/null 2>&1; then
      echo "firewall test interface already exists: $interface" >&2
      exit 3
    fi
  done
}

prepare() {
  assert_absent
  trap cleanup EXIT INT TERM

  ip netns add "$gateway_ns"
  ip netns add "$overlay_ns"
  ip netns add "$wan_ns"
  ip netns add "$victim_ns"

  ip link add v2fwgo type veth peer name v2fwoh
  ip link set v2fwgo netns "$gateway_ns"
  ip link set v2fwoh netns "$overlay_ns"
  ip -n "$gateway_ns" link set v2fwgo name vpnctl-wg
  ip -n "$overlay_ns" link set v2fwoh name gateway0

  ip link add v2fwgw type veth peer name v2fwwh
  ip link set v2fwgw netns "$gateway_ns"
  ip link set v2fwwh netns "$wan_ns"
  ip -n "$gateway_ns" link set v2fwgw name eth0
  ip -n "$wan_ns" link set v2fwwh name gateway0

  ip link add v2fwgv type veth peer name v2fwvh
  ip link set v2fwgv netns "$gateway_ns"
  ip link set v2fwvh netns "$victim_ns"
  ip -n "$gateway_ns" link set v2fwgv name victim0
  ip -n "$victim_ns" link set v2fwvh name gateway0

  local namespace
  for namespace in "$gateway_ns" "$overlay_ns" "$wan_ns" "$victim_ns"; do
    ip -n "$namespace" link set lo up
  done

  ip -n "$gateway_ns" address add 10.66.0.1/24 dev vpnctl-wg
  ip -n "$gateway_ns" address add 10.67.0.1/24 dev vpnctl-wg
  ip -n "$overlay_ns" address add 10.66.0.2/24 dev gateway0
  ip -n "$overlay_ns" address add 10.67.0.2/24 dev gateway0
  ip -n "$overlay_ns" address add 198.51.100.99/32 dev gateway0

  ip -n "$gateway_ns" address add 192.0.2.1/24 dev eth0
  ip -n "$wan_ns" address add 192.0.2.2/24 dev gateway0
  ip -n "$wan_ns" address add 192.168.50.2/32 dev lo
  ip -n "$wan_ns" address add 169.254.50.2/32 dev lo

  ip -n "$gateway_ns" address add 10.90.0.1/24 dev victim0
  ip -n "$victim_ns" address add 10.90.0.2/24 dev gateway0
  ip -n "$victim_ns" address add 10.66.0.3/32 dev lo
  ip -n "$victim_ns" address add 10.67.0.3/32 dev lo

  ip -n "$gateway_ns" -6 address add 2001:db8:66::1/64 dev vpnctl-wg nodad
  ip -n "$overlay_ns" -6 address add 2001:db8:66::2/64 dev gateway0 nodad
  ip -n "$gateway_ns" -6 address add 2001:db8:100::1/64 dev eth0 nodad
  ip -n "$wan_ns" -6 address add 2001:db8:100::2/64 dev gateway0 nodad

  ip -n "$gateway_ns" link set vpnctl-wg up
  ip -n "$overlay_ns" link set gateway0 up
  ip -n "$gateway_ns" link set eth0 up
  ip -n "$wan_ns" link set gateway0 up
  ip -n "$gateway_ns" link set victim0 up
  ip -n "$victim_ns" link set gateway0 up

  ip -n "$overlay_ns" route add default via 10.66.0.1 dev gateway0
  ip -n "$overlay_ns" route add 10.66.0.3/32 via 10.66.0.1 dev gateway0
  ip -n "$overlay_ns" route add 10.67.0.3/32 via 10.67.0.1 dev gateway0
  ip -n "$gateway_ns" route add default via 192.0.2.2 dev eth0
  ip -n "$gateway_ns" route add 192.168.50.2/32 via 192.0.2.2 dev eth0
  ip -n "$gateway_ns" route add 169.254.50.2/32 via 192.0.2.2 dev eth0
  ip -n "$gateway_ns" route add 10.66.0.3/32 via 10.90.0.2 dev victim0
  ip -n "$gateway_ns" route add 10.67.0.3/32 via 10.90.0.2 dev victim0
  ip -n "$gateway_ns" route add 198.51.100.99/32 dev vpnctl-wg
  ip -n "$victim_ns" route add default via 10.90.0.1 dev gateway0

  ip -n "$overlay_ns" -6 route add default via 2001:db8:66::1 dev gateway0
  ip -n "$gateway_ns" -6 route add default via 2001:db8:100::2 dev eth0
  ip -n "$wan_ns" -6 route add 2001:db8:66::/64 via 2001:db8:100::1 dev gateway0

  ip netns exec "$gateway_ns" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$gateway_ns" sysctl -q -w net.ipv6.conf.all.forwarding=1

  ip netns exec "$gateway_ns" nft -f - <<'EOF'
table inet foreign_keep {
  counter observed {}
}
EOF
  ip netns exec "$gateway_ns" nft --stateless list table inet foreign_keep > "$foreign_before"
  ip netns exec "$gateway_ns" nft --check --file "$minimal_rules_path"
  ip netns exec "$gateway_ns" nft --check --file "$rules_path"
  ip netns exec "$gateway_ns" nft --file "$rules_path"
}

start_backends() {
  ip netns exec "$gateway_ns" "$backend_path" \
    --state "$runtime_root/gateway-state.json" \
    --tcp 0.0.0.0:2222=ssh \
    --tcp 0.0.0.0:443=https \
    --tcp 0.0.0.0:8443=restricted \
    --tcp 0.0.0.0:53=shared-dns-tcp \
    --tcp 0.0.0.0:9443=internal-control \
    --tcp 0.0.0.0:17000=internal-tunnel \
    --tcp 0.0.0.0:9999=forbidden-tcp \
    --tcp '[::]:443=https-v6' \
    --udp 0.0.0.0:53=internal-dns \
    --udp 0.0.0.0:443=forbidden-https-udp \
    --udp 0.0.0.0:8443=forbidden-restricted-udp \
    --udp 0.0.0.0:51820=wireguard \
    --udp 0.0.0.0:9999=forbidden-udp &
  pids+=("$!")

  ip netns exec "$wan_ns" "$backend_path" \
    --state "$runtime_root/wan-state.json" \
    --tcp 0.0.0.0:18080=internet-tcp \
    --tcp 0.0.0.0:18081=private-tcp \
    --tcp '[::]:18080=internet-v6' \
    --udp 0.0.0.0:18080=internet-udp &
  pids+=("$!")

  ip netns exec "$victim_ns" "$backend_path" \
    --state "$runtime_root/victim-state.json" \
    --tcp 0.0.0.0:18082=lateral &
  pids+=("$!")

  local attempt
  for attempt in $(seq 1 50); do
    if ip netns exec "$gateway_ns" ss -H -lnt | grep -q ':9999 ' && \
      ip netns exec "$wan_ns" ss -H -lnt | grep -q ':18080 ' && \
      ip netns exec "$victim_ns" ss -H -lnt | grep -q ':18082 '; then
      return
    fi
    sleep 0.1
  done
  echo "firewall test backends did not become ready" >&2
  exit 1
}

request() {
  local namespace=$1 protocol=$2 host=$3 port=$4 expected=$5
  shift 5
  ip netns exec "$namespace" "$probe_path" request \
    --protocol "$protocol" --host "$host" --port "$port" \
    --expect "$expected" --timeout 1 "$@" >/dev/null
}

blocked() {
  local namespace=$1 protocol=$2 host=$3 port=$4
  shift 4
  ip netns exec "$namespace" "$probe_path" blocked \
    --protocol "$protocol" --host "$host" --port "$port" \
    --timeout 0.35 "$@" >/dev/null
}

verify_packets() {
  request "$wan_ns" tcp 192.0.2.1 2222 ssh
  request "$wan_ns" tcp 192.0.2.1 443 https
  request "$wan_ns" tcp 192.0.2.1 8443 restricted
  request "$wan_ns" udp 192.0.2.1 51820 wireguard

  blocked "$wan_ns" tcp 192.0.2.1 9443
  blocked "$wan_ns" tcp 192.0.2.1 17000
  blocked "$wan_ns" tcp 192.0.2.1 53
  blocked "$wan_ns" tcp 192.0.2.1 9999
  blocked "$wan_ns" udp 192.0.2.1 53
  blocked "$wan_ns" udp 192.0.2.1 443
  blocked "$wan_ns" udp 192.0.2.1 8443
  blocked "$wan_ns" udp 192.0.2.1 9999

  request "$overlay_ns" tcp 10.66.0.1 53 shared-dns-tcp
  request "$overlay_ns" udp 10.66.0.1 53 internal-dns
  request "$overlay_ns" tcp 10.66.0.1 9443 internal-control --bind 10.67.0.2
  request "$overlay_ns" tcp 10.66.0.1 17000 internal-tunnel --bind 10.67.0.2
  request "$overlay_ns" udp 10.66.0.1 53 internal-dns --bind 10.67.0.2
  blocked "$overlay_ns" tcp 10.66.0.1 9443 --bind 10.66.0.2
  blocked "$overlay_ns" tcp 10.66.0.1 17000 --bind 10.66.0.2
  request "$gateway_ns" tcp 127.0.0.1 9999 forbidden-tcp

  request "$overlay_ns" tcp 192.0.2.2 18080 internet-tcp
  request "$overlay_ns" udp 192.0.2.2 18080 internet-udp
  blocked "$overlay_ns" tcp 192.168.50.2 18081
  blocked "$overlay_ns" tcp 169.254.50.2 18081
  blocked "$overlay_ns" tcp 192.0.2.2 18080 --bind 198.51.100.99

  blocked "$overlay_ns" tcp 10.66.0.3 18082 --bind 10.66.0.2
  blocked "$overlay_ns" tcp 10.67.0.3 18082 --bind 10.66.0.2
  blocked "$overlay_ns" tcp 10.66.0.3 18082 --bind 10.67.0.2
  blocked "$overlay_ns" tcp 10.67.0.3 18082 --bind 10.67.0.2

  blocked "$wan_ns" tcp 2001:db8:100::1 443
  blocked "$overlay_ns" tcp 2001:db8:100::2 18080
}

verify_foreign_table_and_replace() {
  {
    printf 'delete table inet vpnctl\n'
    cat "$rules_path"
  } | ip netns exec "$gateway_ns" nft --file -
  ip netns exec "$gateway_ns" nft --stateless list table inet foreign_keep > "$foreign_after"
  if ! cmp -s "$foreign_before" "$foreign_after"; then
    echo "foreign nftables table changed during vpnctl replacement" >&2
    diff -u "$foreign_before" "$foreign_after" >&2 || true
    exit 1
  fi
  request "$wan_ns" tcp 192.0.2.1 2222 ssh
  blocked "$wan_ns" udp 192.0.2.1 8443
}

verify() {
  for required in "$rules_path" "$minimal_rules_path" "$backend_path" "$probe_path"; do
    if [ ! -f "$required" ]; then
      echo "missing firewall test input: $required" >&2
      exit 3
    fi
  done
  prepare
  start_backends
  verify_packets
  verify_foreign_table_and_replace
  printf '{"schema_version":1,"status":"passed","checks":{"public_ports":true,"closed_udp":true,"internal_scope":true,"forward_nat":true,"lateral_isolation":true,"private_guard":true,"ipv6_fail_closed":true,"foreign_table_preserved":true,"atomic_replace":true}}\n'
}

status() {
  local namespace
  for namespace in "$gateway_ns" "$overlay_ns" "$wan_ns" "$victim_ns"; do
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
