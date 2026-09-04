#!/bin/bash
set -euo pipefail

input_root=/tmp/vpnctl-v2-personal-client-e2e
input_owner=$input_root/.owner
input_owner_value=vpnctl-v2-personal-client-input-v1
runtime_root=/run/vpnctl-v2-personal-e2e
runtime_owner=$runtime_root/.owner
runtime_owner_value=vpnctl-v2-personal-client-runtime-v1

network_ns=vpnctl-v2-pc-net
gateway_ns=vpnctl-v2-pc-gw
clash_ns=vpnctl-v2-pc-clash
wireguard_ns=vpnctl-v2-pc-wg
wan_ns=vpnctl-v2-pc-wan
namespaces=("$network_ns" "$gateway_ns" "$clash_ns" "$wireguard_ns" "$wan_ns")

namespace_exists() {
  ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

runtime_is_owned() {
  [ -d "$runtime_root" ] &&
    [ ! -L "$runtime_root" ] &&
    [ -f "$runtime_owner" ] &&
    [ ! -L "$runtime_owner" ] &&
    [ "$(tr -d '\n' < "$runtime_owner")" = "$runtime_owner_value" ]
}

input_is_owned() {
  [ -d "$input_root" ] &&
    [ ! -L "$input_root" ] &&
    [ -f "$input_owner" ] &&
    [ ! -L "$input_owner" ] &&
    [ "$(tr -d '\n' < "$input_owner")" = "$input_owner_value" ]
}

assert_cleanup_scope() {
  local namespace
  if [ -e "$runtime_root" ] || [ -L "$runtime_root" ]; then
    runtime_is_owned || {
      echo "refusing to touch unowned personal-client E2E runtime: $runtime_root" >&2
      return 3
    }
  else
    for namespace in "${namespaces[@]}"; do
      if namespace_exists "$namespace"; then
        echo "refusing to touch personal-client namespace without its runtime owner marker: $namespace" >&2
        return 3
      fi
    done
  fi
}

assert_clean() {
  local namespace
  for namespace in "${namespaces[@]}"; do
    if namespace_exists "$namespace"; then
      echo "personal-client E2E namespace remains: $namespace" >&2
      return 1
    fi
  done
  if [ -e "$runtime_root" ] || [ -L "$runtime_root" ]; then
    echo "personal-client E2E runtime remains: $runtime_root" >&2
    return 1
  fi
}

stop_recorded_processes() {
  local pid command attempt
  [ -f "$runtime_root/pids" ] || return 0
  while IFS= read -r pid; do
    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    [ -d "/proc/$pid" ] || continue
    command=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    case "$command" in
      *"$input_root/backend.py"*|*"$input_root/mihomo"*) kill -TERM "$pid" >/dev/null 2>&1 || true ;;
      *) echo "skipping reused or foreign recorded PID $pid" >&2 ;;
    esac
  done < "$runtime_root/pids"
  for attempt in $(seq 1 20); do
    local running=false
    while IFS= read -r pid; do
      [ -d "/proc/$pid" ] && running=true
    done < "$runtime_root/pids"
    [ "$running" = false ] && return 0
    sleep 0.1
  done
  while IFS= read -r pid; do
    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    [ -d "/proc/$pid" ] || continue
    command=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    case "$command" in
      *"$input_root/backend.py"*|*"$input_root/mihomo"*) kill -KILL "$pid" >/dev/null 2>&1 || true ;;
    esac
  done < "$runtime_root/pids"
}

cleanup_owned() {
  assert_cleanup_scope
  if runtime_is_owned; then
    stop_recorded_processes
  fi
  local namespace
  for namespace in "${namespaces[@]}"; do
    ip netns delete "$namespace" >/dev/null 2>&1 || true
  done
  if runtime_is_owned; then
    rm -rf -- "$runtime_root"
  fi
  assert_clean
}

require_root_and_inputs() {
  [ "$(id -u)" -eq 0 ] || {
    echo "personal-client E2E requires root" >&2
    exit 2
  }
  input_is_owned || {
    echo "personal-client E2E input tree is absent or unowned" >&2
    exit 3
  }
  local command path
  for command in ip wg wg-quick curl jq sha256sum awk grep tr seq python3 nc; do
    command -v "$command" >/dev/null || {
      echo "missing required command: $command" >&2
      exit 2
    }
  done
  for path in fixture.json gateway.key iphone.clash.yaml steamdeck.wireguard.conf mihomo backend.py; do
    [ -f "$input_root/$path" ] && [ ! -L "$input_root/$path" ] || {
      echo "missing regular E2E input: $path" >&2
      exit 3
    }
  done
}

connect_underlay() {
  local namespace=$1 namespace_end=$2 network_end=$3 address=$4
  ip -n "$network_ns" link add "$network_end" type veth peer name "$namespace_end"
  ip -n "$network_ns" link set "$namespace_end" netns "$namespace"
  ip -n "$namespace" link set "$namespace_end" name eth0
  ip -n "$namespace" address add "$address/24" dev eth0
  ip -n "$namespace" link set lo up
  ip -n "$namespace" link set eth0 up
  ip -n "$network_ns" link set "$network_end" master br0
  ip -n "$network_ns" link set "$network_end" up
}

prepare_underlay() {
  local namespace
  for namespace in "${namespaces[@]}"; do
    ip netns add "$namespace"
  done
  ip -n "$network_ns" link set lo up
  ip -n "$network_ns" link add br0 type bridge
  ip -n "$network_ns" link set br0 up
  connect_underlay "$gateway_ns" pce2e-gwh pce2e-gwn 192.0.2.1
  connect_underlay "$clash_ns" pce2e-clh pce2e-cln 192.0.2.2
  connect_underlay "$wireguard_ns" pce2e-wgh pce2e-wgn 192.0.2.3
  connect_underlay "$wan_ns" pce2e-wnh pce2e-wnn 192.0.2.254

  ip -n "$wan_ns" address add 198.51.100.10/32 dev lo
  ip -n "$wan_ns" address add 198.51.100.20/32 dev lo
  ip -n "$gateway_ns" route add 198.51.100.0/24 via 192.0.2.254 dev eth0
  ip -n "$clash_ns" route add 198.51.100.0/24 via 192.0.2.254 dev eth0
  ip -n "$wan_ns" route add 10.66.0.0/24 via 192.0.2.1 dev eth0
  ip netns exec "$gateway_ns" sysctl -q -w net.ipv4.ip_forward=1
}

prepare_gateway() {
  local clash_public wireguard_public
  clash_public=$(jq -er '.profiles.clash.public_key' "$input_root/fixture.json")
  wireguard_public=$(jq -er '.profiles.wireguard.public_key' "$input_root/fixture.json")
  ip -n "$gateway_ns" link add vpnctl-wg type wireguard
  ip netns exec "$gateway_ns" wg set vpnctl-wg \
    private-key "$input_root/gateway.key" \
    listen-port 51820 \
    peer "$clash_public" allowed-ips 10.66.0.2/32 \
    peer "$wireguard_public" allowed-ips 10.66.0.3/32
  ip -n "$gateway_ns" address add 10.66.0.1/24 dev vpnctl-wg
  ip -n "$gateway_ns" link set vpnctl-wg up
}

record_pid() {
  printf '%s\n' "$1" >> "$runtime_root/pids"
}

start_backend() {
  ip netns exec "$wan_ns" "$input_root/backend.py" \
    --listen 198.51.100.10:18080=selected \
    --listen 198.51.100.20:18080=direct \
    >"$runtime_root/backend.log" 2>&1 &
  record_pid "$!"
  local attempt
  for attempt in $(seq 1 50); do
    if ip netns exec "$gateway_ns" curl --silent --fail --max-time 1 http://198.51.100.10:18080/ready >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "personal-client HTTP backend did not become ready" >&2
  return 1
}

start_clash_client() {
  install -d -m 0700 "$runtime_root/mihomo-data"
  "$input_root/mihomo" -t -d "$runtime_root/mihomo-data" -f "$input_root/iphone.clash.yaml" >/dev/null
  cp "$input_root/iphone.clash.yaml" "$runtime_root/iphone.runtime.yaml"
  chmod 0600 "$runtime_root/iphone.runtime.yaml"
  printf '\nmixed-port: 17890\nallow-lan: false\nbind-address: 127.0.0.1\n' >> "$runtime_root/iphone.runtime.yaml"
  ip netns exec "$clash_ns" "$input_root/mihomo" \
    -d "$runtime_root/mihomo-data" -f "$runtime_root/iphone.runtime.yaml" \
    >"$runtime_root/mihomo.log" 2>&1 &
  record_pid "$!"
  local attempt
  for attempt in $(seq 1 100); do
    if ip netns exec "$clash_ns" nc -z -w 1 127.0.0.1 17890 >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "pinned Mihomo client did not expose its loopback test listener" >&2
  cat "$runtime_root/mihomo.log" >&2 || true
  return 1
}

assert_response() {
  local response=$1 destination=$2 source=$3
  if ! printf '%s' "$response" | jq -e --arg destination "$destination" --arg source "$source" \
    '.destination == $destination and .source == $source and .path == "/probe"' >/dev/null; then
    echo "unexpected $destination response: $response" >&2
    return 1
  fi
}

verify_clash_paths() {
  local selected direct
  selected=$(ip netns exec "$clash_ns" curl --silent --show-error --fail --max-time 5 \
    --proxy http://127.0.0.1:17890 --noproxy '' http://198.51.100.10:18080/probe)
  direct=$(ip netns exec "$clash_ns" curl --silent --show-error --fail --max-time 5 \
    --proxy http://127.0.0.1:17890 --noproxy '' http://198.51.100.20:18080/probe)
  assert_response "$selected" selected 10.66.0.2
  assert_response "$direct" direct 192.0.2.2
}

prepare_wireguard_client() {
	# wg-quick derives the interface name from the file basename and therefore
	# cannot consume vpnctl's descriptive managed export name directly. A
	# short, private runtime copy models client-app import without changing the
	# SCP-delivered artifact checked by verify_delivery_hashes.
	cp "$input_root/steamdeck.wireguard.conf" "$runtime_root/sd.conf"
	chmod 0600 "$runtime_root/sd.conf"
	wg-quick strip "$runtime_root/sd.conf" > "$runtime_root/steamdeck.stripped.conf"
  chmod 0600 "$runtime_root/steamdeck.stripped.conf"
  ip -n "$wireguard_ns" link add vpnctl-wg type wireguard
  ip netns exec "$wireguard_ns" wg setconf vpnctl-wg "$runtime_root/steamdeck.stripped.conf"
  ip -n "$wireguard_ns" address add 10.66.0.3/24 dev vpnctl-wg
  ip -n "$wireguard_ns" link set vpnctl-wg up
  ip -n "$wireguard_ns" route add default dev vpnctl-wg
}

verify_wireguard_paths() {
  local selected direct peer handshake
  selected=$(ip netns exec "$wireguard_ns" curl --silent --show-error --fail --max-time 5 http://198.51.100.10:18080/probe)
  direct=$(ip netns exec "$wireguard_ns" curl --silent --show-error --fail --max-time 5 http://198.51.100.20:18080/probe)
  assert_response "$selected" selected 10.66.0.3
  assert_response "$direct" direct 10.66.0.3
  peer=$(ip netns exec "$wireguard_ns" wg show vpnctl-wg peers)
  handshake=$(ip netns exec "$wireguard_ns" wg show vpnctl-wg latest-handshakes | awk -v peer="$peer" '$1 == peer {print $2}')
  [ -n "$handshake" ] && [ "$handshake" -gt 0 ] || {
    echo "full-tunnel WireGuard client has no handshake" >&2
    return 1
  }
}

verify_delivery_hashes() {
  local kind file expected actual
  for kind in clash wireguard; do
    case "$kind" in
      clash) file=iphone.clash.yaml ;;
      wireguard) file=steamdeck.wireguard.conf ;;
    esac
    expected=$(jq -er ".profiles.$kind.sha256" "$input_root/fixture.json")
    actual=$(sha256sum "$input_root/$file" | awk '{print $1}')
    [ "$actual" = "$expected" ] || {
      echo "$kind profile changed across the scp/runtime boundary" >&2
      return 1
    }
  done
}

verify() {
  require_root_and_inputs
  assert_cleanup_scope
  assert_clean
  install -d -m 0700 "$runtime_root"
  printf '%s\n' "$runtime_owner_value" > "$runtime_owner"
  chmod 0600 "$runtime_owner"
  : > "$runtime_root/pids"
  chmod 0600 "$runtime_root/pids"
  trap cleanup_owned EXIT INT TERM

  verify_delivery_hashes
  "$input_root/mihomo" -v | grep -Fq 'Mihomo Meta v1.19.30'
  prepare_underlay
  prepare_gateway
  start_backend
  start_clash_client
  verify_clash_paths
  prepare_wireguard_client
  verify_wireguard_paths
  verify_delivery_hashes

  local clash_hash wireguard_hash
  clash_hash=$(jq -er '.profiles.clash.sha256' "$input_root/fixture.json")
  wireguard_hash=$(jq -er '.profiles.wireguard.sha256' "$input_root/fixture.json")
  printf '{"schema_version":1,"status":"passed","delivery":"scp-only","clash_profile_sha256":"%s","wireguard_profile_sha256":"%s","pinned_mihomo":"v1.19.30","selective":{"selected_source":"10.66.0.2","direct_source":"192.0.2.2"},"full_tunnel":{"selected_source":"10.66.0.3","direct_source":"10.66.0.3","handshake":true}}\n' \
    "$clash_hash" "$wireguard_hash"
}

status() {
  local namespace present runtime=false
  runtime_is_owned && runtime=true
  printf '{"schema_version":1,"runtime_present":%s,"namespaces":{' "$runtime"
  local first=true
  for namespace in "${namespaces[@]}"; do
    present=false
    namespace_exists "$namespace" && present=true
    [ "$first" = true ] || printf ','
    first=false
    printf '"%s":%s' "$namespace" "$present"
  done
  printf '}}\n'
}

case "${1:-}" in
  verify) verify ;;
  cleanup) require_root_and_inputs; cleanup_owned ;;
  status) [ "$(id -u)" -eq 0 ] || exit 2; status ;;
  *) echo "usage: happy_path.sh <verify|cleanup|status>" >&2; exit 2 ;;
esac
