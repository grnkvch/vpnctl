#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
artifact_root="$repository_root/artifacts/v2lab/node-transport-e2e"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
gateway_started=false
node_started=false
run_root=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2node-transport-e2e.sh verify
  scripts/v2node-transport-e2e.sh status
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
  if ! instance_json "$instance" | jq -e --arg digest "$lab_image_digest" '
    (.status == "Running" or .status == "Stopped") and
    .vmType == "qemu" and
    .arch == "x86_64" and
    .cpus == 1 and
    .memory == 536870912 and
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

owned_path_present() {
  local instance=$1 path=$2 owner_path=$3 owner_value=$4
  guest "$instance" sudo test -e "$path" || return 1
  guest "$instance" sudo test -f "$owner_path" &&
    guest "$instance" sudo grep -Fxq "$owner_value" "$owner_path"
}

assert_path_absent() {
  local instance=$1 path=$2
  if guest "$instance" sudo test -e "$path"; then
    echo "refusing to overlap existing transport E2E path on $instance: $path" >&2
    exit 3
  fi
}

assert_namespace_absent() {
  local instance=$1 namespace=$2
  if guest "$instance" sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
    echo "refusing to overlap existing transport E2E namespace on $instance: $namespace" >&2
    exit 3
  fi
}

assert_table_absent() {
  local instance=$1 table=$2
  if guest "$instance" sudo nft list table inet "$table" >/dev/null 2>&1; then
    echo "refusing to overlap existing transport E2E table on $instance: inet/$table" >&2
    exit 3
  fi
}

assert_preflight_clean() {
  local namespace
  assert_path_absent "$node_instance" /tmp/vpnctl-v2-standard-test
  for namespace in \
    vpnctl-v2-wg-gateway vpnctl-v2-wg-network vpnctl-v2-wg-wan \
    vpnctl-v2-wg-c1 vpnctl-v2-wg-c2 vpnctl-v2-wg-c3 vpnctl-v2-wg-c4 vpnctl-v2-wg-c5 \
    vpnctl-v2-wg-n1 vpnctl-v2-wg-n2 \
    vpnctl-v2-rnode vpnctl-v2-rdirect vpnctl-v2-rgateway; do
    assert_namespace_absent "$node_instance" "$namespace"
  done

  assert_path_absent "$gateway_instance" /tmp/vpnctl-v2-restricted-uot-test
  assert_path_absent "$node_instance" /tmp/vpnctl-v2-restricted-uot-test
  assert_table_absent "$node_instance" vpnctl_v2_task84_capture

  assert_path_absent "$node_instance" /etc/vpnctl-v2-spike/routing
  assert_path_absent "$node_instance" /run/vpnctl-v2-spike-routing
  assert_path_absent "$node_instance" /usr/local/libexec/vpnctl-v2-spike-routing

  assert_path_absent "$gateway_instance" /etc/vpnctl-v2-spike/tunnel
  assert_path_absent "$node_instance" /etc/vpnctl-v2-spike/tunnel
  assert_path_absent "$gateway_instance" /etc/vpnctl-v2-spike/restricted
  assert_path_absent "$node_instance" /etc/vpnctl-v2-spike/restricted
  assert_table_absent "$node_instance" vpnctl_v2_spike_tunnel_capture
  assert_table_absent "$node_instance" vpnctl_v2_spike_uot_capture
  assert_table_absent "$gateway_instance" vpnctl_v2_spike_uot_capture
}

cleanup_harnesses() {
  local result=0
  if ! instance_running "$gateway_instance" || ! instance_running "$node_instance"; then
    return
  fi

  "$repository_root/scripts/v2standard-test.sh" cleanup >/dev/null 2>&1 || result=$?
  "$repository_root/scripts/v2restricted-uot-test.sh" cleanup >/dev/null 2>&1 || result=$?

  if owned_path_present "$node_instance" /etc/vpnctl-v2-spike/routing \
    /etc/vpnctl-v2-spike/routing/.owner vpnctl-v2-routing-spike-v1; then
    "$repository_root/scripts/v2routing-spike.sh" uninstall >/dev/null 2>&1 || result=$?
  fi
  if owned_path_present "$node_instance" /etc/vpnctl-v2-spike/tunnel \
    /etc/vpnctl-v2-spike/tunnel/.owner vpnctl-v2-tunnel-spike-v1; then
    "$repository_root/scripts/v2tunnel-spike.sh" uninstall >/dev/null 2>&1 || result=$?
  fi
  if owned_path_present "$node_instance" /etc/vpnctl-v2-spike/restricted \
    /etc/vpnctl-v2-spike/restricted/.owner vpnctl-v2-restricted-spike-v1; then
    "$repository_root/scripts/v2restricted-spike.sh" uninstall >/dev/null 2>&1 || result=$?
  fi
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

verify_final_cleanup() {
  assert_preflight_clean
}

write_summary() {
  local routing_summary=$run_root/routing/summary.json
  local tunnel_summary=$run_root/tunnel/summary.json
  jq -n \
    --slurpfile routing "$routing_summary" \
    --slurpfile tunnel "$tunnel_summary" \
    '{
      schema_version: 1,
      status: "passed",
      source_flows: {
        standard_to_restricted_test_switch: true,
        restricted_to_standard_test_switch: true,
        deferred_without_local_apply: true,
        failed_target_preserves_active: true,
        automatic_fallback: false,
        one_active_transport: true
      },
      standard: {
        wireguard_udp_51820: true,
        selected_tcp_udp_gateway: true,
        probe_gateway_only: true,
        probe_missing_route_blocked: true
      },
      restricted: {shadowtls_tcp_8443: true, selected_tcp: true, selected_udp_over_tcp: true, native_udp: false},
      routing: {
        selected_tcp_fail_closed: $routing[0].outages.transport.selected_tcp_blocked,
        selected_udp_fail_closed: $routing[0].outages.transport.selected_udp_blocked,
        unrelated_tcp_direct: $routing[0].outages.transport.unrelated_tcp_direct,
        unrelated_udp_direct: $routing[0].outages.transport.unrelated_udp_direct,
        active_transport_preserved: $routing[0].outages.transport.active_transport_preserved,
        automatic_fallback: $routing[0].outages.transport.automatic_fallback
      },
      reverse_tunnel: $tunnel[0].transport_switch,
      cleanup: {owner_scoped: true, temporary_resources_absent: true}
    }' > "$run_root/summary.json"
}

verify() {
  local stamp
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  run_root="$artifact_root/run-$stamp"
  mkdir -p "$run_root"
  chmod 0700 "$run_root"

  start_fixture "$gateway_instance" gateway_started
  start_fixture "$node_instance" node_started
  trap cleanup_all EXIT INT TERM
  # Recover only resources carrying the exact owner markers from an interrupted
  # earlier run. Foreign or unmarked resources remain in place and are rejected
  # by the clean preflight below.
  cleanup_harnesses
  assert_preflight_clean

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/transport ./internal/cli \
    -run 'TestV2ManualTransportRoundTrip|TestTransportSwitchWorkflowDefer' -count=1 \
    > "$run_root/source-flows.log"

  "$repository_root/scripts/v2standard-test.sh" verify > "$run_root/standard.log"
  "$repository_root/scripts/v2restricted-uot-test.sh" verify > "$run_root/restricted-uot.log"

  "$repository_root/scripts/v2routing-spike.sh" prepare > "$run_root/routing-prepare.log"
  "$repository_root/scripts/v2routing-spike.sh" verify "$run_root/routing" > "$run_root/routing-verify.log"

  "$repository_root/scripts/v2tunnel-spike.sh" prepare > "$run_root/tunnel-prepare.log"
  "$repository_root/scripts/v2tunnel-spike.sh" verify "$run_root/tunnel" > "$run_root/tunnel-verify.log"
  "$repository_root/scripts/v2tunnel-spike.sh" uninstall > "$run_root/tunnel-uninstall.log"
  if owned_path_present "$node_instance" /etc/vpnctl-v2-spike/restricted \
    /etc/vpnctl-v2-spike/restricted/.owner vpnctl-v2-restricted-spike-v1; then
    "$repository_root/scripts/v2restricted-spike.sh" uninstall > "$run_root/restricted-uninstall.log"
  fi

  verify_final_cleanup
  write_summary
  trap - EXIT INT TERM
  restore_fixture_states
  jq -e '.status == "passed" and
    .source_flows.standard_to_restricted_test_switch and
    .source_flows.restricted_to_standard_test_switch and
    .source_flows.deferred_without_local_apply and
    (.source_flows.automatic_fallback | not) and
    .source_flows.one_active_transport and
    .standard.probe_gateway_only and .standard.probe_missing_route_blocked and
    .routing.selected_tcp_fail_closed and .routing.selected_udp_fail_closed and
    .routing.unrelated_tcp_direct and .routing.unrelated_udp_direct and
    .routing.active_transport_preserved and (.routing.automatic_fallback | not) and
    (.reverse_tunnel.standard_direct_packets > 0) and
    (.reverse_tunnel.restricted_shadowtls_packets > 0) and
    .cleanup.temporary_resources_absent' "$run_root/summary.json" >/dev/null
  printf 'node transport E2E evidence: %s\n' "$run_root/summary.json"
}

status() {
  local instance
  for instance in "$gateway_instance" "$node_instance"; do
    assert_instance_contract "$instance"
    printf '%s=%s\n' "$instance" "$(instance_status "$instance")"
  done
  if instance_running "$gateway_instance" && instance_running "$node_instance"; then
    assert_preflight_clean
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
