#!/bin/bash
set -euo pipefail

runtime_root=/run/vpnctl-v1mig-e2e
owner_marker=$runtime_root/.owner
owner_value=vpnctl-v1-migration-e2e-v1
gateway_ns=vpnctl-v1mig-e2e-gateway
client_ns=vpnctl-v1mig-e2e-client
gateway_link=v1me2e-gw
client_link=v1me2e-cl

namespace_exists() {
  ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

link_exists() {
  ip link show dev "$1" >/dev/null 2>&1
}

runtime_is_owned() {
  [ -d "$runtime_root" ] &&
    [ ! -L "$runtime_root" ] &&
    [ -f "$owner_marker" ] &&
    [ ! -L "$owner_marker" ] &&
    [ "$(tr -d '\n' < "$owner_marker")" = "$owner_value" ]
}

assert_cleanup_scope() {
  if [ -e "$runtime_root" ] || [ -L "$runtime_root" ]; then
    runtime_is_owned || {
      echo "refusing to touch unowned migration E2E runtime: $runtime_root" >&2
      exit 3
    }
  elif namespace_exists "$gateway_ns" || namespace_exists "$client_ns" ||
    link_exists "$gateway_link" || link_exists "$client_link"; then
    echo "refusing to touch migration E2E network resources without their owner marker" >&2
    exit 3
  fi
}

cleanup_owned() {
  assert_cleanup_scope
  ip link del "$client_link" >/dev/null 2>&1 || true
  ip link del "$gateway_link" >/dev/null 2>&1 || true
  ip netns del "$client_ns" >/dev/null 2>&1 || true
  ip netns del "$gateway_ns" >/dev/null 2>&1 || true
  if runtime_is_owned; then
    rm -f \
      "$runtime_root/client.conf" \
      "$runtime_root/client.key" \
      "$runtime_root/server.key" \
      "$owner_marker"
    rmdir "$runtime_root"
  fi
}

assert_clean() {
  if namespace_exists "$gateway_ns" || namespace_exists "$client_ns" ||
    link_exists "$gateway_link" || link_exists "$client_link" ||
    [ -e "$runtime_root" ] || [ -L "$runtime_root" ]; then
    echo "migration E2E cleanup is incomplete" >&2
    exit 1
  fi
}

require_root_and_tools() {
  [ "$(id -u)" -eq 0 ] || {
    echo "migration E2E requires root" >&2
    exit 2
  }
  local command
  for command in ip wg ping sha256sum awk grep tr seq; do
    command -v "$command" >/dev/null || {
      echo "missing required command: $command" >&2
      exit 2
    }
  done
}

write_runtime() {
  install -d -m 0700 "$runtime_root"
  printf '%s\n' "$owner_value" > "$owner_marker"
  chmod 0600 "$owner_marker"
  # The all-zero synthetic server key in the v1 renderer golden means
  # "remove private key" to the WireGuard kernel API. Use the valid byte-0x01
  # server key from the migration fixtures; the client identity remains the
  # exact checked-in v1 iPhone private key below.
  printf '%s\n' 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=' > "$runtime_root/server.key"
  printf '%s\n' 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=' > "$runtime_root/client.key"
  chmod 0600 "$runtime_root/server.key" "$runtime_root/client.key"
}

prepare_underlay() {
  ip netns add "$gateway_ns"
  ip netns add "$client_ns"
  ip link add "$gateway_link" type veth peer name "$client_link"
  ip link set "$gateway_link" netns "$gateway_ns"
  ip link set "$client_link" netns "$client_ns"
  ip -n "$gateway_ns" address add 192.0.2.1/24 dev "$gateway_link"
  ip -n "$client_ns" address add 192.0.2.2/24 dev "$client_link"
  ip -n "$gateway_ns" link set lo up
  ip -n "$client_ns" link set lo up
  ip -n "$gateway_ns" link set "$gateway_link" up
  ip -n "$client_ns" link set "$client_link" up
}

start_gateway() {
  local interface=$1
  local client_public=$2
  ip -n "$gateway_ns" link add "$interface" type wireguard
  ip netns exec "$gateway_ns" wg set "$interface" \
    private-key "$runtime_root/server.key" \
    listen-port 51820 \
    peer "$client_public" \
    allowed-ips 10.66.0.2/32
  ip -n "$gateway_ns" address add 10.66.0.1/24 dev "$interface"
  ip -n "$gateway_ns" link set "$interface" up
}

start_client_from_unchanged_profile() {
  ip -n "$client_ns" link add wg0 type wireguard
  ip netns exec "$client_ns" wg setconf wg0 "$runtime_root/client.conf"
  ip -n "$client_ns" address add 10.66.0.2/24 dev wg0
  ip -n "$client_ns" link set wg0 up
}

wait_for_client_traffic() {
  local label=$1
  local attempt
  for attempt in $(seq 1 20); do
    if ip netns exec "$client_ns" ping -c 1 -W 1 10.66.0.1 >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "retained client did not reach the $label gateway" >&2
  ip netns exec "$client_ns" ping -c 1 -W 1 192.0.2.1 >&2 || true
  ip -n "$client_ns" -brief address >&2 || true
  ip -n "$client_ns" route show >&2 || true
  ip netns exec "$client_ns" wg show >&2 || true
  ip -n "$gateway_ns" -brief address >&2 || true
  ip -n "$gateway_ns" route show >&2 || true
  ip netns exec "$gateway_ns" wg show >&2 || true
  return 1
}

verify() {
  require_root_and_tools
  assert_cleanup_scope
  if runtime_is_owned; then
    cleanup_owned
  fi
  assert_clean
  write_runtime
  trap cleanup_owned EXIT
  prepare_underlay

  local server_public client_public profile_hash initial_handshake migrated_handshake
  server_public=$(wg pubkey < "$runtime_root/server.key")
  client_public=$(wg pubkey < "$runtime_root/client.key")
  printf '%s\n' \
    '[Interface]' \
    'PrivateKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=' \
    '' \
    '[Peer]' \
    "PublicKey = $server_public" \
    'Endpoint = 192.0.2.1:51820' \
    'AllowedIPs = 10.66.0.0/24' \
    'PersistentKeepalive = 1' > "$runtime_root/client.conf"
  chmod 0600 "$runtime_root/client.conf"
  profile_hash=$(sha256sum "$runtime_root/client.conf" | awk '{print $1}')

  start_gateway wg0 "$client_public"
  start_client_from_unchanged_profile
  wait_for_client_traffic v1
  initial_handshake=$(ip netns exec "$gateway_ns" wg show wg0 latest-handshakes | awk -v key="$client_public" '$1 == key {print $2}')
  [ -n "$initial_handshake" ] && [ "$initial_handshake" -gt 0 ] || {
    echo "v1 gateway did not observe the retained client handshake" >&2
    exit 1
  }

  ip -n "$gateway_ns" link del wg0
  if ip netns exec "$client_ns" ping -c 1 -W 1 10.66.0.1 >/dev/null 2>&1; then
    echo "client traffic unexpectedly survived removal of the v1 gateway interface" >&2
    exit 1
  fi
  start_gateway vpnctl-wg "$client_public"

  # Recreate only the client interface, exactly as a client application would
  # reconnect from its already-copied profile. The profile itself is unchanged.
  ip -n "$client_ns" link del wg0
  start_client_from_unchanged_profile
  [ "$(sha256sum "$runtime_root/client.conf" | awk '{print $1}')" = "$profile_hash" ] || {
    echo "retained client profile changed during migration" >&2
    exit 1
  }
  wait_for_client_traffic v2
  migrated_handshake=$(ip netns exec "$gateway_ns" wg show vpnctl-wg latest-handshakes | awk -v key="$client_public" '$1 == key {print $2}')
  [ -n "$migrated_handshake" ] && [ "$migrated_handshake" -gt 0 ] || {
    echo "migrated gateway did not observe the retained client handshake" >&2
    exit 1
  }
  [ "$(ip netns exec "$gateway_ns" wg show vpnctl-wg peers)" = "$client_public" ] || {
    echo "migrated gateway peer identity changed" >&2
    exit 1
  }
  [ "$(ip netns exec "$client_ns" wg show wg0 public-key)" = "$client_public" ] || {
    echo "retained client public identity changed" >&2
    exit 1
  }
  grep -Fxq 'PrivateKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=' "$runtime_root/client.conf" || {
    echo "retained client profile no longer contains the original private key" >&2
    exit 1
  }

  printf '{"schema_version":1,"status":"passed","v1_gateway_interface":"wg0","v2_gateway_interface":"vpnctl-wg","client_profile_sha256":"%s","retained_client_address":"10.66.0.2","retained_client_private_key":true,"retained_peer_identity":true,"initial_handshake":%s,"migrated_handshake":%s,"traffic_reconnected":true}\n' \
    "$profile_hash" "$initial_handshake" "$migrated_handshake"
}

status() {
  local gateway=false client=false gateway_veth=false client_veth=false runtime=false
  namespace_exists "$gateway_ns" && gateway=true
  namespace_exists "$client_ns" && client=true
  link_exists "$gateway_link" && gateway_veth=true
  link_exists "$client_link" && client_veth=true
  [ -e "$runtime_root" ] || [ -L "$runtime_root" ] && runtime=true
  printf '{"schema_version":1,"gateway_namespace":%s,"client_namespace":%s,"gateway_link":%s,"client_link":%s,"runtime_present":%s}\n' \
    "$gateway" "$client" "$gateway_veth" "$client_veth" "$runtime"
}

case "${1:-}" in
  verify) verify ;;
  cleanup) require_root_and_tools; cleanup_owned; assert_clean ;;
  status) require_root_and_tools; status ;;
  *) echo "usage: reconnect.sh <verify|cleanup|status>" >&2; exit 2 ;;
esac
