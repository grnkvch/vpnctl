#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
spike_script="$repository_root/scripts/v2tunnel-spike.sh"
restricted_script="$repository_root/scripts/v2restricted-spike.sh"
manifest="$repository_root/test/v2lab/tunnel/manifest.json"
artifact_root="$repository_root/artifacts/v2lab/tunnel-release-gate"
cache_root="$repository_root/artifacts/v2lab/cache"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
tunnel_owner=vpnctl-v2-tunnel-spike-v1
restricted_owner=vpnctl-v2-restricted-spike-v1
guest_test=/tmp/vpnctl-v2-tunnel-release-gate.test
guest_frps=/tmp/vpnctl-v2-tunnel-release-frps
guest_frpc=/tmp/vpnctl-v2-tunnel-release-frpc
temporary_root=
tunnel_cleanup=false
restricted_cleanup=false

cd "$repository_root"

usage() {
  cat <<'EOF'
Usage:
  scripts/v2tunnel-release-gate.sh run [evidence-directory]

The evidence directory must be a new child of artifacts/v2lab/tunnel-release-gate.
Both vpnctl v2 minimum-host Lima fixtures must already be running.
EOF
}

manifest_value() {
  jq -er "$1" "$manifest"
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
    echo "release gate requires a running contract-matching fixture: $instance" >&2
    exit 4
  fi
}

assert_owned_path() {
  local instance=$1
  local path=$2
  local owner_path=$3
  local owner=$4
  if ! limactl shell --tty=false "$instance" -- sudo test -e "$path"; then
    return 1
  fi
  if ! limactl shell --tty=false "$instance" -- sudo grep -Fxq "$owner" "$owner_path"; then
    echo "release gate refuses foreign fixture path on $instance: $path" >&2
    exit 3
  fi
  return 0
}

assert_tunnel_fixture_absent() {
  local instance
  for instance in "$gateway_instance" "$node_instance"; do
    if limactl shell --tty=false "$instance" -- sudo test -e /etc/vpnctl-v2-spike/tunnel; then
      echo "release gate requires an absent tunnel spike fixture on $instance" >&2
      exit 3
    fi
  done
}

classify_restricted_fixture() {
  local gateway_present=false
  local node_present=false
  if assert_owned_path "$gateway_instance" /etc/vpnctl-v2-spike/restricted /etc/vpnctl-v2-spike/restricted/.owner "$restricted_owner"; then
    gateway_present=true
  fi
  if assert_owned_path "$node_instance" /etc/vpnctl-v2-spike/restricted /etc/vpnctl-v2-spike/restricted/.owner "$restricted_owner"; then
    node_present=true
  fi
  if [ "$gateway_present" != "$node_present" ]; then
    echo "release gate refuses a partial restricted spike fixture" >&2
    exit 3
  fi
  if [ "$gateway_present" = false ]; then
    restricted_cleanup=true
  fi
}

assert_guest_path_absent() {
  local path=$1
  if limactl shell --tty=false "$gateway_instance" -- sudo test -e "$path"; then
    echo "release gate guest path is already occupied: $path" >&2
    exit 3
  fi
}

assert_port_free() {
  local instance=$1
  local port=$2
  if [ -n "$(limactl shell --tty=false "$instance" -- sudo ss -H -ltn "sport = :$port")" ]; then
    echo "release gate port is already occupied on $instance: $port" >&2
    exit 3
  fi
}

cleanup_native_guest() {
  limactl shell --tty=false "$gateway_instance" -- sudo rm -f \
    "$guest_test" "$guest_frps" "$guest_frpc" >/dev/null 2>&1 || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  cleanup_native_guest
  if [ "$tunnel_cleanup" = true ]; then
    "$spike_script" uninstall >/dev/null 2>&1
  fi
  if [ "$restricted_cleanup" = true ]; then
    "$restricted_script" uninstall >/dev/null 2>&1
  fi
  if [ -n "$temporary_root" ] && [ -d "$temporary_root" ]; then
    rm -rf "$temporary_root"
  fi
  exit "$status"
}

record_fixture() {
  local instance=$1
  local destination=$2
  instance_json "$instance" | jq '{
    name, status, vmType, arch, cpus, memory, disk,
    image_digest: .config.images[0].digest,
    network: [.network[]? | {lima, interface}]
  }' > "$destination"
}

prepare_native_binaries() {
  local version archive expected actual extracted
  "$spike_script" fetch >/dev/null
  version=$(manifest_value '.frp.version')
  archive="$cache_root/$(manifest_value '.frp.asset')"
  expected=$(manifest_value '.frp.sha256')
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "release gate frp archive checksum mismatch" >&2
    exit 3
  fi
  tar -xzf "$archive" -C "$temporary_root" \
    "frp_${version}_linux_amd64/frps" "frp_${version}_linux_amd64/frpc"
  extracted="$temporary_root/frp_${version}_linux_amd64"
  install -m 0755 "$extracted/frps" "$temporary_root/frps"
  install -m 0755 "$extracted/frpc" "$temporary_root/frpc"
  env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOCACHE="$temporary_root/go-cache" \
    go test -c -o "$temporary_root/tunnel.test" ./internal/tunnel
  shasum -a 256 "$archive" "$temporary_root/frps" "$temporary_root/frpc" \
    "$temporary_root/tunnel.test" > "$evidence_dir/native-inputs.sha256"
}

copy_native_binaries() {
  limactl copy --backend=scp "$temporary_root/tunnel.test" "$gateway_instance:$guest_test"
  limactl copy --backend=scp "$temporary_root/frps" "$gateway_instance:$guest_frps"
  limactl copy --backend=scp "$temporary_root/frpc" "$gateway_instance:$guest_frpc"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0755 \
    "$guest_test" "$guest_frps" "$guest_frpc"
}

run_native_gate() {
  local expected
  limactl shell --tty=false "$gateway_instance" -- sudo "$guest_test" \
    -test.list '^TestFRPNative' > "$evidence_dir/native-tests.list"
  for expected in \
    TestFRPNativeConfigsWithPinnedBinaries \
    TestFRPNativeLoginUsesProductionAuthorizerAndEffectiveZeroPool \
    TestFRPNativeNewProxyUsesProductionAuthoritativeMapping \
    TestFRPNativeRejectedPingClosesRevokedSessionAndRejectsReconnect \
    TestFRPNativeReadinessRecoversWithoutStandbyAfterGatewayUpstreamAndClientRestarts \
    TestFRPNativeDynamicMappingReloadKeepsProcessConnectionAndStream; do
    if ! grep -Fxq "$expected" "$evidence_dir/native-tests.list"; then
      echo "release gate native suite is missing: $expected" >&2
      exit 3
    fi
  done
  limactl shell --tty=false "$gateway_instance" -- sudo env \
    VPNCTL_FRPS="$guest_frps" VPNCTL_FRPC="$guest_frpc" \
    "$guest_test" -test.run '^TestFRPNative' -test.v -test.timeout=180s \
    > "$evidence_dir/native-tests.log"
  grep -Fxq PASS "$evidence_dir/native-tests.log"
}

validate_spike_summary() {
  local summary=$1
  local minimum_mem
  minimum_mem=$(manifest_value '.load.minimum_mem_available_kib')
  jq -e --arg version "$(manifest_value '.frp.version')" --argjson minimum_mem "$minimum_mem" '
    .schema_version == 1 and .status == "passed" and
    .provider.name == "frp" and .provider.version == $version and .provider.tls_verified == true and
    .multiplexing.tcp_mux == true and .multiplexing.pool_count == 0 and
    .multiplexing.persistent_connections == 1 and .multiplexing.exposes == 2 and
    .dynamic_mapping.add_without_restart == true and .dynamic_mapping.remove_without_restart == true and
    .dynamic_mapping.malicious_rejected == true and .dynamic_mapping.stale_generation_rejected == true and
    .authorization.login_generation_rejected == true and
    .authorization.unexpected_pool_input_rejected == true and
    .authorization.login_pool_rewritten_to_zero == true and
    .authorization.controller_unavailable_rejected == true and
    .authorization.untrusted_tls_reached_login == false and
    .authorization.revoke_reconnect_rejected == true and
    .lifecycle.reconnect_without_frpc_restart == true and
    .transport_switch.logical_identity_preserved == true and
    .transport_switch.standard_direct_packets > 0 and
    .transport_switch.restricted_shadowtls_packets > 0 and
    .resources.gateway_mem_available_kib >= $minimum_mem and
    .resources.node_mem_available_kib >= $minimum_mem and
    .resources.oom_kills == 0
  ' "$summary" >/dev/null
}

write_summary() {
  local source_commit
  source_commit=$(git rev-parse HEAD)
  jq -n \
    --arg source_commit "$source_commit" \
    --arg archive_sha256 "$(manifest_value '.frp.sha256')" \
    --arg version "$(manifest_value '.frp.version')" \
    --slurpfile spike "$evidence_dir/spike/summary.json" \
    '{
      schema_version: 1,
      status: "passed",
      source_commit: $source_commit,
      target: {os: "Ubuntu 24.04", architecture: "amd64", vcpu: 1, memory_bytes: 536870912, disk_bytes: 10737418240},
      provider: {name: "frp", version: $version, archive_sha256: $archive_sha256},
      production_native: {status: "passed", test_regex: "^TestFRPNative", test_count: 6},
      spike_regression: $spike[0]
    }' > "$evidence_dir/summary.json"
}

run_gate() {
  local instance port
  if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "release gate requires a clean source tree" >&2
    exit 3
  fi
  for instance in "$gateway_instance" "$node_instance"; do
    assert_lab_instance "$instance"
  done
  assert_tunnel_fixture_absent
  classify_restricted_fixture
  for path in "$guest_test" "$guest_frps" "$guest_frpc"; do
    assert_guest_path_absent "$path"
  done
  for port in 3000 17000 17001 17400 19091 20000 20001 20002; do
    assert_port_free "$gateway_instance" "$port"
  done

  mkdir -p "$artifact_root"
  if [ -e "$evidence_dir" ]; then
    echo "release gate refuses to replace evidence: $evidence_dir" >&2
    exit 3
  fi
  mkdir "$evidence_dir"
  chmod 0700 "$evidence_dir"
  temporary_root=$(mktemp -d /private/tmp/vpnctl-v2-tunnel-release.XXXXXX)
  trap cleanup EXIT INT TERM
  record_fixture "$gateway_instance" "$evidence_dir/gateway-fixture.json"
  record_fixture "$node_instance" "$evidence_dir/node-fixture.json"

  prepare_native_binaries
  copy_native_binaries
  run_native_gate
  cleanup_native_guest

  tunnel_cleanup=true
  "$spike_script" prepare > "$evidence_dir/spike-prepare.log"
  "$spike_script" verify "$evidence_dir/spike" > "$evidence_dir/spike-verify.log"
  validate_spike_summary "$evidence_dir/spike/summary.json"
  "$spike_script" uninstall > "$evidence_dir/spike-uninstall.log"
  tunnel_cleanup=false
  if [ "$restricted_cleanup" = true ]; then
    "$restricted_script" uninstall > "$evidence_dir/restricted-uninstall.log"
    restricted_cleanup=false
  fi

  for path in "$guest_test" "$guest_frps" "$guest_frpc"; do
    assert_guest_path_absent "$path"
  done
  for port in 17000 17400 18111 18112 18121 18122 19091; do
    assert_port_free "$gateway_instance" "$port"
    assert_port_free "$node_instance" "$port"
  done
  write_summary
  printf 'tunnel release gate evidence: %s\n' "$evidence_dir/summary.json"
}

command=${1:-}
case "$command" in
  run)
    [ "$#" -le 2 ] || { usage >&2; exit 2; }
    evidence_dir=${2:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
    case "$evidence_dir" in
      "$artifact_root"/*) ;;
      *) echo "evidence directory must be below $artifact_root" >&2; exit 2 ;;
    esac
    run_gate
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
