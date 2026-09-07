#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
. "$repository_root/scripts/lib/v2-stage-timing.sh"
artifact_root="$repository_root/artifacts/v2lab/fleet-isolation-e2e"
cache_root="$repository_root/artifacts/v2lab/cache"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
gateway_started=false
node_started=false
run_root=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2fleet-isolation-e2e.sh verify
  scripts/v2fleet-isolation-e2e.sh status
EOF
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

instance_status() {
  instance_json "$1" | jq -er '.status'
}

assert_instance_contract() {
  local instance=$1
  if ! instance_json "$instance" | jq -e --arg digest "$lab_image_digest" --arg instance "$instance" '
    (.status == "Running" or .status == "Stopped") and
    .vmType == "qemu" and .arch == "x86_64" and
    .cpus == (if $instance == "vpnctl-v2-node" then 4 else 1 end) and
    .memory == (if $instance == "vpnctl-v2-node" then 2147483648 else 536870912 end) and
    .disk == 10737418240 and
    .config.images[0].digest == $digest and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "refusing non-lab, running-transition, or drifted instance: $instance" >&2
    exit 3
  fi
}

instance_running() {
  [ "$(instance_status "$1")" = Running ]
}

guest() {
  local instance=$1
  shift
  limactl shell --tty=false "$instance" -- "$@"
}

start_fixture() {
  local instance=$1 marker=$2
  assert_instance_contract "$instance"
  if instance_running "$instance"; then
    return
  fi
  limactl start --tty=false "$instance"
  printf -v "$marker" '%s' true
  assert_instance_contract "$instance"
  instance_running "$instance" || {
    echo "lab fixture did not reach Running: $instance" >&2
    exit 4
  }
}

assert_cached_archive() {
  local manifest=$1 section=$2
  local asset expected archive actual
  asset=$(jq -er "$section.asset" "$manifest")
  expected=$(jq -er "$section.sha256" "$manifest")
  archive="$cache_root/$asset"
  if [ ! -f "$archive" ]; then
    echo "required pinned archive is not cached: $archive" >&2
    exit 4
  fi
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "cached archive checksum mismatch: $archive" >&2
    exit 3
  fi
}

path_present() {
  guest "$1" sudo test -e "$2"
}

path_owned() {
  local instance=$1 path=$2 owner_path=$3 owner=$4
  path_present "$instance" "$path" &&
    guest "$instance" sudo test -f "$owner_path" &&
    guest "$instance" sudo grep -Fxq "$owner" "$owner_path"
}

cleanup_pair_if_fully_owned() {
  local script=$1 path=$2 owner_path=$3 owner=$4
  local gateway_owned=false node_owned=false
  if path_owned "$gateway_instance" "$path" "$owner_path" "$owner"; then
    gateway_owned=true
  fi
  if path_owned "$node_instance" "$path" "$owner_path" "$owner"; then
    node_owned=true
  fi
  if [ "$gateway_owned" = true ] && [ "$node_owned" = true ]; then
    "$repository_root/scripts/$script" uninstall >/dev/null 2>&1
  fi
}

cleanup_harnesses() {
  local result=0
  if ! instance_running "$gateway_instance" || ! instance_running "$node_instance"; then
    return
  fi
  "$repository_root/scripts/v2standard-test.sh" cleanup >/dev/null 2>&1 || result=$?
  cleanup_pair_if_fully_owned v2tunnel-spike.sh /etc/vpnctl-v2-spike/tunnel \
    /etc/vpnctl-v2-spike/tunnel/.owner vpnctl-v2-tunnel-spike-v1 || result=$?
  cleanup_pair_if_fully_owned v2restricted-spike.sh /etc/vpnctl-v2-spike/restricted \
    /etc/vpnctl-v2-spike/restricted/.owner vpnctl-v2-restricted-spike-v1 || result=$?
  return "$result"
}

restore_fixture_states() {
  local result=0
  if [ "$node_started" = true ] && instance_running "$node_instance"; then
    limactl stop "$node_instance" >/dev/null || result=$?
  fi
  if [ "$gateway_started" = true ] && instance_running "$gateway_instance"; then
    limactl stop "$gateway_instance" >/dev/null || result=$?
  fi
  return "$result"
}

cleanup_all() {
  local result=0
  cleanup_harnesses || result=$?
  restore_fixture_states || result=$?
  return "$result"
}

assert_path_absent() {
  local instance=$1 path=$2
  if path_present "$instance" "$path"; then
    echo "refusing to overlap existing fleet E2E path on $instance: $path" >&2
    exit 3
  fi
}

assert_namespace_absent() {
  local namespace=$1
  if guest "$node_instance" sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
    echo "refusing to overlap existing fleet E2E namespace: $namespace" >&2
    exit 3
  fi
}

assert_table_absent() {
  local instance=$1 table=$2
  if guest "$instance" sudo nft list table inet "$table" >/dev/null 2>&1; then
    echo "refusing to overlap existing fleet E2E table on $instance: inet/$table" >&2
    exit 3
  fi
}

assert_unit_inactive() {
  local instance=$1 unit=$2
  if guest "$instance" systemctl is-active --quiet "$unit"; then
    echo "fleet E2E service remains active on $instance: $unit" >&2
    exit 3
  fi
}

assert_clean() {
  local namespace unit
  assert_path_absent "$node_instance" /tmp/vpnctl-v2-standard-test
  for namespace in \
    vpnctl-v2-wg-gateway vpnctl-v2-wg-network vpnctl-v2-wg-wan \
    vpnctl-v2-wg-c1 vpnctl-v2-wg-c2 vpnctl-v2-wg-c3 vpnctl-v2-wg-c4 vpnctl-v2-wg-c5 \
    vpnctl-v2-wg-n1 vpnctl-v2-wg-n2; do
    assert_namespace_absent "$namespace"
  done
  for instance in "$gateway_instance" "$node_instance"; do
    assert_path_absent "$instance" /etc/vpnctl-v2-spike/tunnel
    assert_path_absent "$instance" /etc/vpnctl-v2-spike/restricted
  done
  assert_path_absent "$gateway_instance" /var/lib/vpnctl-v2-spike-tunnel-auth
  assert_table_absent "$node_instance" vpnctl_v2_spike_tunnel_capture
  assert_table_absent "$node_instance" vpnctl_v2_spike_uot_capture
  assert_table_absent "$gateway_instance" vpnctl_v2_spike_uot_capture
  for unit in \
    vpnctl-v2-spike-tunnel-auth.service vpnctl-v2-spike-tunnel-server.service \
    vpnctl-v2-spike-echo.service vpnctl-v2-spike-udp-echo.service \
    vpnctl-v2-spike-restricted-gateway.service; do
    assert_unit_inactive "$gateway_instance" "$unit"
  done
  for unit in \
    vpnctl-v2-spike-tunnel-client.service vpnctl-v2-spike-tunnel-backend.service \
    vpnctl-v2-spike-restricted-node.service; do
    assert_unit_inactive "$node_instance" "$unit"
  done
}

assert_tests_passed() {
  local log=$1
  shift
  local test_name
  for test_name in "$@"; do
    if ! grep -Fq -- "--- PASS: $test_name " "$log"; then
      echo "source isolation test did not pass: $test_name" >&2
      exit 3
    fi
  done
}

run_source_tests() {
  local enrollment_log=$run_root/enrollment.log
  local client_log=$run_root/clients.log
  local tunnel_log=$run_root/tunnel-authorization.log
  local expose_log=$run_root/expose-isolation.log

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/enrollment -v -count=1 \
    -run '^(TestMultipleJoinedNodesRetainIsolatedIdentitiesAndResources|TestNodeCredentialProvisioningCreatesUniqueTunnelCredentialPerNodeGeneration|TestRevokingOneNodePreservesOtherNodeIdentityAndPaths)$' \
    > "$enrollment_log"
  assert_tests_passed "$enrollment_log" \
    TestMultipleJoinedNodesRetainIsolatedIdentitiesAndResources \
    TestNodeCredentialProvisioningCreatesUniqueTunnelCredentialPerNodeGeneration \
    TestRevokingOneNodePreservesOtherNodeIdentityAndPaths

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/routing -v -count=1 \
    -run '^TestClientManagerCreatesFiveStableIsolatedIdentitiesAndSecretFreeViews$' \
    > "$client_log"
  assert_tests_passed "$client_log" TestClientManagerCreatesFiveStableIsolatedIdentitiesAndSecretFreeViews

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/tunnel -v -count=1 \
    -run '^(TestNodeSessionMultiplexesAllMappingsInOneRender|TestPlanRejectsCrossNodeMappingAndGlobalPortCollision|TestNewProxyAuthorizationRejectsMaliciousStaleDisabledAndCrossNodeMappings)$' \
    > "$tunnel_log"
  assert_tests_passed "$tunnel_log" \
    TestNodeSessionMultiplexesAllMappingsInOneRender \
    TestPlanRejectsCrossNodeMappingAndGlobalPortCollision \
    TestNewProxyAuthorizationRejectsMaliciousStaleDisabledAndCrossNodeMappings

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/operations ./internal/ingress -v -count=1 \
    -run '^(TestExposeRemoveSagaUnpublishesDrainsAndRemovesOnlyTargetBeforePortRelease|TestFRPExposeNodeTunnelRemovalAppliesCompleteRetainedTopology|TestExposeNormalizerAllowsSameNameOnAnotherNodeButKeepsRoutesGlobal)$' \
    > "$expose_log"
  assert_tests_passed "$expose_log" \
    TestExposeRemoveSagaUnpublishesDrainsAndRemovesOnlyTargetBeforePortRelease \
    TestFRPExposeNodeTunnelRemovalAppliesCompleteRetainedTopology \
    TestExposeNormalizerAllowsSameNameOnAnotherNodeButKeepsRoutesGlobal
}

write_summary() {
  tail -n 1 "$run_root/standard.log" > "$run_root/standard-summary.json"
  jq -n \
    --slurpfile standard "$run_root/standard-summary.json" \
    --slurpfile tunnel "$run_root/tunnel/summary.json" \
    '{
      schema_version: 1,
      status: "passed",
      fleet: {private_nodes: 2, personal_clients: 5, simultaneous_exposes: 2},
      credentials: {node_unique: true, client_unique: true, generation_scoped: true},
      networking: {
        client_to_client_blocked: $standard[0].checks.lateral_isolation,
        client_to_node_blocked: $standard[0].checks.lateral_isolation,
        node_to_node_blocked: $standard[0].checks.lateral_isolation,
        permitted_internet_tcp_udp: $standard[0].checks.internet_tcp_udp
      },
      mappings: {
        one_connection_for_two_exposes: ($tunnel[0].multiplexing.persistent_connections == 1 and $tunnel[0].multiplexing.exposes == 2),
        cross_node_rejected: true,
        malicious_rejected: $tunnel[0].dynamic_mapping.malicious_rejected,
        stale_generation_rejected: $tunnel[0].dynamic_mapping.stale_generation_rejected,
        global_port_collision_rejected: true
      },
      removal: {
        only_target_removed: true,
        other_mapping_continued: $tunnel[0].dynamic_mapping.remove_without_restart,
        other_node_preserved: true
      },
      cleanup: {owner_scoped: true, temporary_resources_absent: true}
    }' > "$run_root/summary.json"
}

verify() {
  local stamp
  VPNCTL_V2_TIMING_PRODUCER=fleet-isolation
  v2_timing_begin
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  run_root="$artifact_root/run-$stamp"
  mkdir -p "$run_root"
  chmod 0700 "$run_root"

  assert_cached_archive "$repository_root/test/v2lab/tunnel/manifest.json" '.frp'
  assert_cached_archive "$repository_root/test/v2lab/restricted/manifest.json" '.mihomo'
  run_source_tests
  v2_timing_mark source_checks

  start_fixture "$gateway_instance" gateway_started
  start_fixture "$node_instance" node_started
  trap cleanup_all EXIT INT TERM
  cleanup_harnesses
  assert_clean
  v2_timing_mark preflight

  "$repository_root/scripts/v2standard-test.sh" verify > "$run_root/standard.log"
  v2_timing_mark client_isolation
  "$repository_root/scripts/v2tunnel-spike.sh" prepare > "$run_root/tunnel-prepare.log"
  "$repository_root/scripts/v2tunnel-spike.sh" verify "$run_root/tunnel" > "$run_root/tunnel-verify.log"
  "$repository_root/scripts/v2tunnel-spike.sh" uninstall > "$run_root/tunnel-uninstall.log"
  cleanup_pair_if_fully_owned v2restricted-spike.sh /etc/vpnctl-v2-spike/restricted \
    /etc/vpnctl-v2-spike/restricted/.owner vpnctl-v2-restricted-spike-v1
  v2_timing_mark tunnel_and_mapping

  assert_clean
  write_summary
  trap - EXIT INT TERM
  restore_fixture_states
  jq -e '.status == "passed" and
    .fleet.private_nodes == 2 and .fleet.personal_clients == 5 and .fleet.simultaneous_exposes == 2 and
    .credentials.node_unique and .credentials.client_unique and .credentials.generation_scoped and
    .networking.client_to_client_blocked and .networking.client_to_node_blocked and
    .networking.node_to_node_blocked and .networking.permitted_internet_tcp_udp and
    .mappings.one_connection_for_two_exposes and .mappings.cross_node_rejected and
    .mappings.malicious_rejected and .mappings.stale_generation_rejected and
    .mappings.global_port_collision_rejected and .removal.only_target_removed and
    .removal.other_mapping_continued and .removal.other_node_preserved and
    .cleanup.owner_scoped and .cleanup.temporary_resources_absent' "$run_root/summary.json" >/dev/null
  v2_timing_finish cleanup_and_validation
  printf 'fleet isolation E2E evidence: %s\n' "$run_root/summary.json"
}

status() {
  local instance
  for instance in "$gateway_instance" "$node_instance"; do
    assert_instance_contract "$instance"
    printf '%s=%s\n' "$instance" "$(instance_status "$instance")"
  done
  if instance_running "$gateway_instance" && instance_running "$node_instance"; then
    assert_clean
    echo 'temporary_resources=absent'
  else
    echo 'temporary_resources=not-inspected-while-stopped'
  fi
}

case "${1:-}" in
  verify) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; verify ;;
  status) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; status ;;
  *) usage >&2; exit 2 ;;
esac
