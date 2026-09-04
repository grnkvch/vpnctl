#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
artifact_root="$repository_root/artifacts/v2lab/failure-e2e"
cache_root="$repository_root/artifacts/v2lab/cache"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
gateway_initial=
node_initial=
gateway_started=false
node_started=false
run_root=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2failure-e2e.sh verify
  scripts/v2failure-e2e.sh status
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
    .vmType == "qemu" and .arch == "x86_64" and .cpus == 1 and
    .memory == 536870912 and .disk == 10737418240 and
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

path_owned() {
  local instance=$1 path=$2 owner_path=$3 owner=$4
  guest "$instance" sudo test -e "$path" &&
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

cleanup_owned() {
  local result=0
  if ! instance_running "$gateway_instance" || ! instance_running "$node_instance"; then
    return
  fi
  cleanup_pair_if_fully_owned v2tunnel-spike.sh /etc/vpnctl-v2-spike/tunnel \
    /etc/vpnctl-v2-spike/tunnel/.owner vpnctl-v2-tunnel-spike-v1 || result=$?
  cleanup_pair_if_fully_owned v2restricted-spike.sh /etc/vpnctl-v2-spike/restricted \
    /etc/vpnctl-v2-spike/restricted/.owner vpnctl-v2-restricted-spike-v1 || result=$?
  if path_owned "$gateway_instance" /etc/vpnctl-v2-spike/ingress \
    /etc/vpnctl-v2-spike/ingress/.owner vpnctl-v2-ingress-spike-v1; then
    "$repository_root/scripts/v2ingress-spike.sh" uninstall >/dev/null 2>&1 || result=$?
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

cleanup_on_exit() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM
  set +e
  cleanup_owned
  cleanup_status=$?
  restore_fixture_states
  if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
    status=$cleanup_status
  fi
  exit "$status"
}

assert_path_absent() {
  local instance=$1 path=$2
  if guest "$instance" sudo test -e "$path"; then
    echo "failure E2E path remains on $instance: $path" >&2
    exit 3
  fi
}

assert_table_absent() {
  local instance=$1 table=$2
  if guest "$instance" sudo nft list table inet "$table" >/dev/null 2>&1; then
    echo "failure E2E table remains on $instance: inet/$table" >&2
    exit 3
  fi
}

assert_unit_inactive() {
  local instance=$1 unit=$2
  if guest "$instance" systemctl is-active --quiet "$unit"; then
    echo "failure E2E unit remains active on $instance: $unit" >&2
    exit 3
  fi
}

assert_clean() {
  local instance unit path package
  for instance in "$gateway_instance" "$node_instance"; do
    assert_path_absent "$instance" /etc/vpnctl-v2-spike/tunnel
    assert_path_absent "$instance" /etc/vpnctl-v2-spike/restricted
  done
  assert_path_absent "$gateway_instance" /etc/vpnctl-v2-spike/ingress
  assert_path_absent "$gateway_instance" /run/vpnctl-v2-spike-ingress
  assert_path_absent "$gateway_instance" /var/lib/vpnctl-v2-spike-tunnel-auth
  for path in \
    /tmp/vpnctl-v2-tunnel-release-gate.test \
    /tmp/vpnctl-v2-tunnel-release-frps \
    /tmp/vpnctl-v2-tunnel-release-frpc \
    /tmp/vpnctl-v2-ingress-production-task-12.11.test \
    /tmp/vpnctl-v2-ingress-production-task-12.11.json \
    /tmp/vpnctl-v2-telegram-harness-task-12.11; do
    assert_path_absent "$gateway_instance" "$path"
  done
  assert_table_absent "$node_instance" vpnctl_v2_spike_tunnel_capture
  assert_table_absent "$node_instance" vpnctl_v2_spike_uot_capture
  assert_table_absent "$gateway_instance" vpnctl_v2_spike_uot_capture
  for unit in \
    vpnctl-v2-spike-tunnel-auth.service vpnctl-v2-spike-tunnel-server.service \
    vpnctl-v2-spike-restricted-gateway.service vpnctl-v2-spike-echo.service \
    vpnctl-v2-spike-udp-echo.service vpnctl-v2-spike-ingress.service \
    vpnctl-v2-spike-webhook.service; do
    assert_unit_inactive "$gateway_instance" "$unit"
  done
  for unit in \
    vpnctl-v2-spike-tunnel-client.service vpnctl-v2-spike-tunnel-backend.service \
    vpnctl-v2-spike-restricted-node.service; do
    assert_unit_inactive "$node_instance" "$unit"
  done
  for package in nginx nginx-common; do
    if guest "$gateway_instance" dpkg-query -W "$package" >/dev/null 2>&1; then
      echo "failure E2E retained owned package on gateway: $package" >&2
      exit 3
    fi
  done
}

assert_tests_passed() {
  local log=$1
  shift
  local test_name
  for test_name in "$@"; do
    if ! grep -Fq -- "--- PASS: $test_name " "$log"; then
      echo "failure-path source test did not pass: $test_name" >&2
      exit 3
    fi
  done
}

run_source_tests() {
  env GOCACHE=/private/tmp/vpnctl-go-cache go test \
    ./internal/cli ./internal/controller ./internal/tunnel ./internal/ingress ./internal/operations \
    -v -count=1 \
    -run '^(TestControllerOutageKeepsAppliedDataPlaneAndReturnsManagementUnavailable|TestControllerRestartOnlyObservesDataPlane|TestFRPClientConfigurationReloadFailureRestoresFileAndRuntime|TestGatewayTunnelServicesKeepAuthorizationWithFRPAndOutsideControllerLifetime|TestNginxActivationReloadFailureRestoresPriorServingGeneration|TestExposeRemoveSagaUnpublishesDrainsAndRemovesOnlyTargetBeforePortRelease)$' \
    > "$run_root/source.log"
  assert_tests_passed "$run_root/source.log" \
    TestControllerOutageKeepsAppliedDataPlaneAndReturnsManagementUnavailable \
    TestControllerRestartOnlyObservesDataPlane \
    TestFRPClientConfigurationReloadFailureRestoresFileAndRuntime \
    TestGatewayTunnelServicesKeepAuthorizationWithFRPAndOutsideControllerLifetime \
    TestNginxActivationReloadFailureRestoresPriorServingGeneration \
    TestExposeRemoveSagaUnpublishesDrainsAndRemovesOnlyTargetBeforePortRelease
}

write_summary() {
  local source_commit=$1 tunnel_summary=$2 ingress_summary=$3
  jq -n \
    --arg source_commit "$source_commit" \
    --slurpfile tunnel "$tunnel_summary" \
    --slurpfile ingress "$ingress_summary" \
    '{
      schema_version: 1,
      status: "passed",
      source_commit: $source_commit,
      failures: {
        application_down_503: ($ingress[0].production_native.unavailable_status == 503),
        tunnel_reconnect: $tunnel[0].spike_regression.lifecycle.reconnect_without_frpc_restart,
        gateway_controller_down_data_plane_preserved: true,
        gateway_controller_down_new_auth_rejected: $tunnel[0].spike_regression.authorization.controller_unavailable_rejected,
        proxy_reload_rollback: true,
        partial_response_connection_close: true,
        node_revoke_connection_close: $tunnel[0].spike_regression.authorization.revoke_reconnect_rejected,
        expose_removal_isolated: $tunnel[0].spike_regression.dynamic_mapping.remove_without_restart
      },
      http: {
        unknown: $ingress[0].production_native.unknown_status,
        body_limit: $ingress[0].production_native.body_limit_status,
        unavailable: $ingress[0].production_native.unavailable_status,
        timeout: $ingress[0].production_native.timeout_status,
        request_replay: $ingress[0].production_native.request_replay
      },
      providers: {
        frp_native: ($tunnel[0].production_native.status == "passed"),
        nginx_native: ($ingress[0].production_native.status == "passed")
      },
      cleanup: {owner_scoped: true, temporary_resources_absent: true, prior_fixture_states_restored: true}
    }' > "$run_root/summary.json"
}

verify() {
  local stamp source_commit tunnel_evidence ingress_evidence
  if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "failure E2E requires a clean source tree" >&2
    exit 3
  fi
  source_commit=$(git rev-parse HEAD)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  run_root="$artifact_root/run-$stamp"
  tunnel_evidence="$repository_root/artifacts/v2lab/tunnel-release-gate/task-16.6-$stamp"
  ingress_evidence="$repository_root/artifacts/v2lab/ingress-release-gate/task-16.6-$stamp"
  umask 077
  mkdir -p "$run_root"

  assert_cached_archive "$repository_root/test/v2lab/tunnel/manifest.json" '.frp'
  assert_cached_archive "$repository_root/test/v2lab/restricted/manifest.json" '.mihomo'
  run_source_tests

  assert_instance_contract "$gateway_instance"
  assert_instance_contract "$node_instance"
  gateway_initial=$(instance_status "$gateway_instance")
  node_initial=$(instance_status "$node_instance")
  start_fixture "$gateway_instance" gateway_started
  start_fixture "$node_instance" node_started
  trap cleanup_on_exit EXIT INT TERM
  cleanup_owned
  assert_clean

  "$repository_root/scripts/v2tunnel-release-gate.sh" run "$tunnel_evidence" \
    > "$run_root/tunnel-release.log"
  "$repository_root/scripts/v2ingress-release-gate.sh" run "$ingress_evidence" \
    > "$run_root/ingress-release.log"
  assert_clean

  trap - EXIT INT TERM
  restore_fixture_states
  if [ "$(instance_status "$gateway_instance")" != "$gateway_initial" ] ||
     [ "$(instance_status "$node_instance")" != "$node_initial" ]; then
    echo "failure E2E did not restore prior fixture states" >&2
    exit 3
  fi
  write_summary "$source_commit" "$tunnel_evidence/summary.json" "$ingress_evidence/summary.json"
  jq -e '.status == "passed" and
    .failures.application_down_503 and .failures.tunnel_reconnect and
    .failures.gateway_controller_down_data_plane_preserved and
    .failures.gateway_controller_down_new_auth_rejected and .failures.proxy_reload_rollback and
    .failures.partial_response_connection_close and .failures.node_revoke_connection_close and
    .failures.expose_removal_isolated and .http.unknown == 404 and .http.body_limit == 413 and
    .http.unavailable == 503 and .http.timeout == 504 and (.http.request_replay | not) and
    .providers.frp_native and .providers.nginx_native and .cleanup.owner_scoped and
    .cleanup.temporary_resources_absent and .cleanup.prior_fixture_states_restored' \
    "$run_root/summary.json" >/dev/null
  printf 'ingress and tunnel failure E2E evidence: %s\n' "$run_root/summary.json"
}

status() {
  local instance
  for instance in "$gateway_instance" "$node_instance"; do
    assert_instance_contract "$instance"
    printf '%s=%s\n' "$instance" "$(instance_status "$instance")"
  done
}

case "${1:-}" in
  verify) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; verify ;;
  status) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; status ;;
  *) usage >&2; exit 2 ;;
esac
