#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/restricted"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
runtime_root=/tmp/vpnctl-v2-restricted-uot-test
owner_value=vpnctl-v2-restricted-uot-test-v1
owner_path="$runtime_root/.owner"
capture_table=vpnctl_v2_task84_capture
cache_archive="$repository_root/artifacts/v2lab/cache/mihomo-linux-amd64-v1.19.30.gz"
pinned_sha256=cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
local_test_binary=
local_mihomo_binary=
local_capture=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2restricted-uot-test.sh verify
  scripts/v2restricted-uot-test.sh status
  scripts/v2restricted-uot-test.sh cleanup
EOF
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

assert_lab_instance() {
  local instance=$1
  if ! instance_json "$instance" | jq -e --arg digest "$lab_image_digest" '
    .status == "Running" and
    .vmType == "qemu" and
    .arch == "x86_64" and
    .cpus == 1 and
    .memory == 536870912 and
    .disk == 10737418240 and
    .config.images[0].digest == $digest and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "required contract-matching lab instance is not running: $instance" >&2
    exit 4
  fi
}

assert_forward_ignored() {
  local instance=$1 port=$2
  if ! instance_json "$instance" | jq -e --argjson port "$port" '
    any(.config.portForwards[]?;
      .guestPort == $port and
      .guestIP == "0.0.0.0" and
      .guestIPMustBeZero == false and
      .proto == "any" and
      .ignore == true
    )
  ' >/dev/null; then
    echo "refusing to expose task-8.4 port $port through Lima host forwarding on $instance" >&2
    exit 3
  fi
}

guest() {
  local instance=$1
  shift
  limactl shell --tty=false "$instance" -- "$@"
}

lab_ip() {
  guest "$1" ip -4 -o address show scope global | awk '$4 ~ /^192[.]168[.]104[.]/ {sub(/\/.*/, "", $4); print $4; exit}'
}

assert_cached_archive() {
  if [ ! -f "$cache_archive" ]; then
    echo "pinned Mihomo archive cache is absent; run scripts/v2restricted-spike.sh prepare first" >&2
    exit 4
  fi
  local actual
  actual=$(shasum -a 256 "$cache_archive" | awk '{print $1}')
  if [ "$actual" != "$pinned_sha256" ]; then
    echo "cached Mihomo archive checksum does not match the pinned manifest" >&2
    exit 3
  fi
}

assert_spikes_inactive() {
  local instance=$1 unit
  for unit in \
    vpnctl-v2-spike-restricted-gateway.service \
    vpnctl-v2-spike-restricted-node.service \
    vpnctl-v2-spike-routing-engine.service \
    vpnctl-v2-spike-routing-guard.service; do
    if guest "$instance" systemctl is-active --quiet "$unit"; then
      echo "refusing task-8.4 test while another spike is active on $instance: $unit" >&2
      exit 3
    fi
  done
}

assert_port_free() {
  local instance=$1 protocol=$2 port=$3 output
  case "$protocol" in
    tcp) output=$(guest "$instance" sudo ss -H -ltn "sport = :$port") ;;
    udp) output=$(guest "$instance" sudo ss -H -lun "sport = :$port") ;;
    *) echo "unknown socket protocol: $protocol" >&2; exit 2 ;;
  esac
  if [ -n "$output" ]; then
    echo "refusing to claim occupied $protocol port $port on $instance" >&2
    exit 3
  fi
}

assert_preflight_absent() {
  local instance
  for instance in "$gateway_instance" "$node_instance"; do
    if guest "$instance" test -e "$runtime_root"; then
      echo "task-8.4 runtime already exists on $instance; inspect status or run cleanup" >&2
      exit 3
    fi
  done
  if guest "$node_instance" sudo nft list table inet "$capture_table" >/dev/null 2>&1; then
    echo "task-8.4 capture table already exists without an owned runtime" >&2
    exit 3
  fi
}

create_runtime() {
  local instance=$1
  guest "$instance" install -d -m 0700 "$runtime_root"
  if ! guest "$instance" sh -c "printf '%s\n' '$owner_value' > '$owner_path' && chmod 0600 '$owner_path'"; then
    guest "$instance" rmdir "$runtime_root" >/dev/null 2>&1 || true
    return 1
  fi
}

copy_input() {
  local source=$1 instance=$2 name=$3
  limactl copy --backend=scp "$source" "$instance:$runtime_root/$name"
}

build_inputs() {
  local_test_binary=$(mktemp -t vpnctl-v2-restricted-uot-test)
  local_mihomo_binary=$(mktemp -t vpnctl-v2-restricted-uot-mihomo)
  local_capture=$(mktemp -t vpnctl-v2-restricted-uot-capture)
  env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOCACHE=/private/tmp/vpnctl-go-cache \
    go test -c -o "$local_test_binary" ./internal/transport
  gzip -dc "$cache_archive" > "$local_mihomo_binary"
  chmod 0755 "$local_mihomo_binary"
  local gateway_ip
  gateway_ip=$(lab_ip "$gateway_instance")
  if [ -z "$gateway_ip" ]; then
    echo "gateway user-v2 IPv4 address was not found" >&2
    exit 4
  fi
  sed "s/@GATEWAY_IP@/$gateway_ip/g" "$fixture_root/task84-capture.nft.tmpl" > "$local_capture"
}

install_inputs() {
  local instance
  copy_input "$local_capture" "$node_instance" capture.nft
  for instance in "$gateway_instance" "$node_instance"; do
    copy_input "$local_test_binary" "$instance" transport.test
    copy_input "$local_mihomo_binary" "$instance" mihomo
    copy_input "$fixture_root/task84-cleanup.sh" "$instance" cleanup.sh
    guest "$instance" sudo chown root:root "$runtime_root" "$owner_path" \
      "$runtime_root/transport.test" "$runtime_root/mihomo" "$runtime_root/cleanup.sh"
    guest "$instance" sudo chmod 0700 "$runtime_root"
    guest "$instance" sudo chmod 0600 "$owner_path"
    guest "$instance" sudo chmod 0755 "$runtime_root/transport.test" "$runtime_root/mihomo" "$runtime_root/cleanup.sh"
    guest "$instance" sudo install -d -m 0700 "$runtime_root/tmp"
  done
  guest "$node_instance" sudo chown root:root "$runtime_root/capture.nft"
  guest "$node_instance" sudo chmod 0600 "$runtime_root/capture.nft"

  local local_sha256 instance guest_sha256
  local_sha256=$(shasum -a 256 "$local_mihomo_binary" | awk '{print $1}')
  for instance in "$gateway_instance" "$node_instance"; do
    guest_sha256=$(guest "$instance" sudo sha256sum "$runtime_root/mihomo" | awk '{print $1}')
    if [ "$guest_sha256" != "$local_sha256" ]; then
      echo "copied Mihomo binary differs from the verified archive payload on $instance" >&2
      exit 3
    fi
  done
}

assert_owned_runtime() {
  local instance=$1
  if ! guest "$instance" sudo test -f "$owner_path" || ! guest "$instance" sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "refusing to operate on unowned task-8.4 runtime on $instance: $runtime_root" >&2
    return 3
  fi
}

cleanup_instance() {
  local instance=$1 role=$2
  if ! guest "$instance" test -e "$runtime_root"; then
    if [ "$role" = node ] && guest "$instance" sudo nft list table inet "$capture_table" >/dev/null 2>&1; then
      echo "refusing to delete task-8.4 capture table without the owned runtime marker" >&2
      return 3
    fi
    return
  fi
  assert_owned_runtime "$instance"
  if guest "$instance" sudo test -x "$runtime_root/cleanup.sh"; then
    guest "$instance" sudo "$runtime_root/cleanup.sh" "$role"
  else
    if [ "$role" = node ] && guest "$instance" sudo nft list table inet "$capture_table" >/dev/null 2>&1; then
      echo "refusing fallback cleanup while the capture table exists" >&2
      return 3
    fi
    guest "$instance" sudo rm -rf -- "$runtime_root"
  fi
}

cleanup_local() {
  local path
  for path in "$local_test_binary" "$local_mihomo_binary" "$local_capture"; do
    if [ -n "$path" ] && [ -f "$path" ]; then
      rm -f -- "$path"
    fi
  done
  local_test_binary=
  local_mihomo_binary=
  local_capture=
}

cleanup_all() {
  local result=0
  cleanup_instance "$node_instance" node || result=$?
  cleanup_instance "$gateway_instance" gateway || result=$?
  cleanup_local
  return "$result"
}

start_gateway_helper() {
  guest "$gateway_instance" sudo sh -c "cd '$runtime_root' && nohup env TMPDIR='$runtime_root/tmp' VPNCTL_PINNED_MIHOMO='$runtime_root/mihomo' VPNCTL_RESTRICTED_UOT_GATEWAY_HELPER=1 VPNCTL_RESTRICTED_UOT_READY_PATH='$runtime_root/gateway.ready' '$runtime_root/transport.test' -test.v -test.run '^TestRestrictedPinnedUoTGatewayHelper$' </dev/null >'$runtime_root/gateway.log' 2>&1 & printf '%s\n' \$! >'$runtime_root/gateway.pid'"
  local attempt
  for attempt in $(seq 1 200); do
    if guest "$gateway_instance" sudo test -f "$runtime_root/gateway.ready"; then
      return
    fi
    if ! guest "$gateway_instance" sudo sh -c "test -s '$runtime_root/gateway.pid' && kill -0 \$(cat '$runtime_root/gateway.pid')"; then
      echo "task-8.4 gateway helper exited before readiness" >&2
      guest "$gateway_instance" sudo tail -n 20 "$runtime_root/gateway.log" >&2 || true
      exit 1
    fi
    sleep 0.1
  done
  echo "task-8.4 gateway helper did not become ready" >&2
  exit 1
}

verify() {
  local gateway_ip
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  assert_forward_ignored "$gateway_instance" 8443
  assert_forward_ignored "$gateway_instance" 18080
  assert_forward_ignored "$node_instance" 17890
  assert_cached_archive
  assert_spikes_inactive "$gateway_instance"
  assert_spikes_inactive "$node_instance"
  assert_preflight_absent
  assert_port_free "$gateway_instance" tcp 8443
  assert_port_free "$gateway_instance" udp 8443
  assert_port_free "$gateway_instance" tcp 8444
  assert_port_free "$gateway_instance" udp 8444
  assert_port_free "$gateway_instance" tcp 18080
  assert_port_free "$gateway_instance" udp 18080
  assert_port_free "$node_instance" tcp 17890
  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/transport -count=1

  trap cleanup_local EXIT INT TERM
  build_inputs
  create_runtime "$gateway_instance"
  trap cleanup_all EXIT INT TERM
  create_runtime "$node_instance"
  install_inputs
  guest "$node_instance" sudo nft -f "$runtime_root/capture.nft"
  start_gateway_helper
  if [ -n "$(guest "$gateway_instance" sudo ss -H -lun 'sport = :8443')" ]; then
    echo "gateway opened forbidden UDP/8443 during task-8.4 test" >&2
    exit 1
  fi
  gateway_ip=$(lab_ip "$gateway_instance")
  guest "$node_instance" sudo env \
    TMPDIR="$runtime_root/tmp" \
    VPNCTL_PINNED_MIHOMO="$runtime_root/mihomo" \
    VPNCTL_RESTRICTED_UOT_TEST=1 \
    VPNCTL_RESTRICTED_UOT_GATEWAY_IP="$gateway_ip" \
    VPNCTL_RESTRICTED_UOT_CAPTURE_TABLE="$capture_table" \
    "$runtime_root/transport.test" -test.v -test.run '^TestRestrictedPinnedUoTReadinessAndFailClosed$'

  trap - EXIT INT TERM
  cleanup_all
  status
}

runtime_status() {
  local instance=$1 label=$2
  if guest "$instance" test -e "$runtime_root"; then
    if guest "$instance" sudo test -f "$owner_path" && guest "$instance" sudo grep -Fxq "$owner_value" "$owner_path"; then
      printf '%s_runtime=owned\n' "$label"
    else
      printf '%s_runtime=foreign\n' "$label"
    fi
  else
    printf '%s_runtime=absent\n' "$label"
  fi
}

status() {
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  runtime_status "$gateway_instance" gateway
  runtime_status "$node_instance" node
  if guest "$node_instance" sudo nft list table inet "$capture_table" >/dev/null 2>&1; then
    printf 'capture_table=present\n'
  else
    printf 'capture_table=absent\n'
  fi
}

case "${1:-}" in
  verify) verify ;;
  status) status ;;
  cleanup)
    assert_lab_instance "$gateway_instance"
    assert_lab_instance "$node_instance"
    cleanup_all
    ;;
  *) usage; exit 2 ;;
esac
