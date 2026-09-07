#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
. "$repository_root/scripts/lib/v2-stage-timing.sh"
artifact_root="$repository_root/artifacts/v2lab/adversarial-e2e"
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
  scripts/v2adversarial-e2e.sh verify
  scripts/v2adversarial-e2e.sh status
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

path_owned() {
  local instance=$1 path=$2 owner_path=$3 owner=$4
  guest "$instance" sudo test -e "$path" &&
    guest "$instance" sudo test -f "$owner_path" &&
    guest "$instance" sudo grep -Fxq "$owner" "$owner_path"
}

cleanup_owned() {
  local result=0
  if ! instance_running "$gateway_instance" || ! instance_running "$node_instance"; then
    return
  fi
  if path_owned "$node_instance" /etc/vpnctl-v2-spike/dns \
    /etc/vpnctl-v2-spike/dns/.owner vpnctl-v2-dns-spike-v1; then
    "$repository_root/scripts/v2dns-spike.sh" uninstall >/dev/null 2>&1 || result=$?
  fi
  if path_owned "$node_instance" /etc/vpnctl-v2-spike/routing \
    /etc/vpnctl-v2-spike/routing/.owner vpnctl-v2-routing-spike-v1; then
    "$repository_root/scripts/v2routing-spike.sh" uninstall >/dev/null 2>&1 || result=$?
  fi
  if path_owned "$node_instance" /tmp/vpnctl-v2-firewall-test \
    /tmp/vpnctl-v2-firewall-test/.owner vpnctl-v2-firewall-test-v1; then
    "$repository_root/scripts/v2firewall-test.sh" cleanup >/dev/null 2>&1 || result=$?
  fi
  if path_owned "$gateway_instance" /var/lib/vpnctl-v2-spike-backup \
    /var/lib/vpnctl-v2-spike-backup/.owner vpnctl-v2-backup-spike-v1; then
    "$repository_root/scripts/v2backup-spike.sh" uninstall >/dev/null 2>&1 || result=$?
  fi
  if path_owned "$gateway_instance" /var/lib/vpnctl-v2-spike-control \
    /var/lib/vpnctl-v2-spike-control/.owner vpnctl-v2-control-spike-v1; then
    "$repository_root/scripts/v2control-spike.sh" uninstall >/dev/null 2>&1 || result=$?
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
    echo "adversarial E2E path remains on $instance: $path" >&2
    exit 3
  fi
}

assert_unit_inactive() {
  local instance=$1 unit=$2
  if guest "$instance" systemctl is-active --quiet "$unit"; then
    echo "adversarial E2E unit remains active on $instance: $unit" >&2
    exit 3
  fi
}

assert_namespace_absent() {
  local namespace=$1
  if guest "$node_instance" sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
    echo "adversarial E2E namespace remains on node: $namespace" >&2
    exit 3
  fi
}

assert_table_absent() {
  local table=$1
  if guest "$node_instance" sudo nft list table inet "$table" >/dev/null 2>&1; then
    echo "adversarial E2E nftables table remains on node: inet/$table" >&2
    exit 3
  fi
}

assert_no_test_process() {
  local binary=$1
  if guest "$gateway_instance" sudo pgrep -f "^$binary" >/dev/null 2>&1; then
    echo "adversarial E2E test process remains on gateway: $binary" >&2
    exit 3
  fi
}

assert_clean() {
  local path unit namespace
  for path in /var/lib/vpnctl-v2-spike-control /var/lib/vpnctl-v2-spike-backup; do
    assert_path_absent "$gateway_instance" "$path"
  done
  for path in \
    /etc/vpnctl-v2-spike/routing /run/vpnctl-v2-spike-routing \
    /usr/local/libexec/vpnctl-v2-spike-routing /etc/vpnctl-v2-spike/dns \
    /run/vpnctl-v2-spike-dns /var/lib/vpnctl-v2-spike-dns \
    /usr/local/libexec/vpnctl-v2-spike-dns /tmp/vpnctl-v2-firewall-test \
    /etc/systemd/resolved.conf.d/vpnctl-v2-dns-spike.conf; do
    assert_path_absent "$node_instance" "$path"
  done
  assert_no_test_process /var/lib/vpnctl-v2-spike-control/vpnctl-v2-control-spike.test
  assert_no_test_process /var/lib/vpnctl-v2-spike-backup/vpnctl-v2-backup-spike.test
  for unit in \
    vpnctl-v2-spike-routing-guard.service vpnctl-v2-spike-routing-engine.service \
    vpnctl-v2-spike-routing-direct.service vpnctl-v2-spike-routing-gateway.service \
    vpnctl-v2-spike-routing-node.service vpnctl-v2-spike-dns-resolver.service \
    vpnctl-v2-spike-dns-direct.service vpnctl-v2-spike-dns-gateway.service; do
    assert_unit_inactive "$node_instance" "$unit"
  done
  for namespace in \
    vpnctl-v2-fw-gateway vpnctl-v2-fw-overlay vpnctl-v2-fw-wan vpnctl-v2-fw-victim \
    vpnctl-v2-rnode vpnctl-v2-rdirect vpnctl-v2-rgateway \
    vpnctl-v2-dns-direct vpnctl-v2-dns-gateway; do
    assert_namespace_absent "$namespace"
  done
  assert_table_absent vpnctl_v2_spike_routing
  assert_table_absent vpnctl_v2_spike_dns
}

assert_tests_passed() {
  local log=$1
  shift
  local test_name
  for test_name in "$@"; do
    if ! grep -Fq -- "--- PASS: $test_name " "$log"; then
      echo "adversarial source test did not pass: $test_name" >&2
      exit 3
    fi
  done
}

run_source_tests() {
  env GOCACHE=/private/tmp/vpnctl-go-cache go test \
    ./internal/enrollment ./internal/control ./internal/controller ./internal/tunnel \
    ./internal/store ./internal/output ./internal/regression ./internal/platform/linux ./internal/lifecycle \
    -v -count=1 \
    -run '^(TestInviteConsumptionRejectsReplayWithoutSecondMutation|TestNodeRecoveryReplacesCompleteGenerationAndPreservesStableResources|TestRPCServerRejectsPublicBindingAndNonMTLSClients|TestRPCNodeAuthorizationBindsCertificateToCurrentCredentialGeneration|TestNewProxyAuthorizationRejectsMaliciousStaleDisabledAndCrossNodeMappings|TestSecretStoreRejectsSymlinkComponents|TestPermissionRepairDoesNotTouchTreeWithUnsafeEntry|TestSensitiveValuesRefuseSerializationAndGenericResults|TestProviderAndServerRawLogsCannotBypassRedaction|TestNetworkManagerRejectsReservedForeignRuleAndUnsafeSysctlBeforeMutation|TestReleaseBundleVerificationFailsBeforeInstallMutation|TestReleaseBundleRejectsInvalidProviderArchiveBeforeInstall|TestBackupArchiveRejectsWrongPassphraseAndAuthenticatedCorruption|TestGatewayRestoreInvalidInputsAndArchivesNeverReachHostMutation)$' \
    > "$run_root/source.log"
  assert_tests_passed "$run_root/source.log" \
    TestInviteConsumptionRejectsReplayWithoutSecondMutation \
    TestNodeRecoveryReplacesCompleteGenerationAndPreservesStableResources \
    TestRPCServerRejectsPublicBindingAndNonMTLSClients \
    TestRPCNodeAuthorizationBindsCertificateToCurrentCredentialGeneration \
    TestNewProxyAuthorizationRejectsMaliciousStaleDisabledAndCrossNodeMappings \
    TestSecretStoreRejectsSymlinkComponents \
    TestPermissionRepairDoesNotTouchTreeWithUnsafeEntry \
    TestSensitiveValuesRefuseSerializationAndGenericResults \
    TestProviderAndServerRawLogsCannotBypassRedaction \
    TestNetworkManagerRejectsReservedForeignRuleAndUnsafeSysctlBeforeMutation \
    TestReleaseBundleVerificationFailsBeforeInstallMutation \
    TestReleaseBundleRejectsInvalidProviderArchiveBeforeInstall \
    TestBackupArchiveRejectsWrongPassphraseAndAuthenticatedCorruption \
    TestGatewayRestoreInvalidInputsAndArchivesNeverReachHostMutation
}

write_summary() {
  local source_commit=$1 control=$2 backup=$3 routing=$4 dns=$5
  jq -n \
    --arg source_commit "$source_commit" \
    --slurpfile control "$control" \
    --slurpfile backup "$backup" \
    --slurpfile routing "$routing" \
    --slurpfile dns "$dns" \
    '{
      schema_version: 1,
      status: "passed",
      source_commit: $source_commit,
      identity: {
        invite_replay_rejected: true,
        recovery_replay_rejected: true,
        enrollment_transcript_replay_rejected: $control[0].verified.transcript_replay_rejected,
        mtls_impersonation_rejected: ($control[0].verified.mtls_required and $control[0].verified.authoritative_generation_checked),
        stale_generation_rejected: true,
        malicious_tunnel_mapping_rejected: true
      },
      filesystem_and_output: {
        symlink_attacks_rejected: true,
        unsafe_permissions_fail_closed: true,
        secret_redaction_enforced: true
      },
      artifacts: {
        corrupt_release_bundle_rejected_before_mutation: true,
        wrong_backup_passphrase_rejected: $backup[0].verified.wrong_passphrase_rejected,
        corrupt_backup_rejected: ($backup[0].verified.authenticated_header_corruption_rejected and
          $backup[0].verified.record_order_corruption_rejected and
          $backup[0].verified.ciphertext_corruption_rejected and
          $backup[0].verified.truncation_rejected and
          $backup[0].verified.appended_data_rejected),
        failed_restore_output_absent: $backup[0].verified.failed_restore_output_absent
      },
      network: {
        firewall_conflict_rejected_and_foreign_preserved: true,
        selected_ipv6_tcp_udp_fail_closed: ($routing[0].ipv6.static_tcp_udp_blocked and $routing[0].ipv6.resolved_aaaa_tcp_udp_blocked),
        selected_tcp_udp_never_fail_direct: ($routing[0].lifecycle.crash_fail_closed and
          $routing[0].lifecycle.restart_fail_closed and $routing[0].conntrack.selected_never_failed_direct),
        dns_selected_direct_fallback_queries: $dns[0].failure.selected_direct_fallback_queries,
        dns_resolver_loss_bypass_queries: $dns[0].failure.resolver_loss.upstream_bypass_queries,
        foreign_network_resources_preserved: ($routing[0].coexistence.foreign_nft_preserved and
          $routing[0].coexistence.foreign_rule_preserved and $routing[0].coexistence.root_namespace_preserved and
          $dns[0].coexistence.foreign_nftables_preserved and $dns[0].coexistence.root_network_restored)
      },
      providers: {
        control_native: ($control[0].status == "passed"),
        backup_native: ($backup[0].status == "passed"),
        firewall_namespace_native: true,
        routing_native: ($routing[0].status == "passed"),
        dns_native: ($dns[0].status == "passed")
      },
      cleanup: {owner_scoped: true, temporary_resources_absent: true, prior_fixture_states_restored: true}
    }' > "$run_root/summary.json"
}

verify() {
  local stamp source_commit control_evidence backup_evidence routing_evidence dns_evidence
  VPNCTL_V2_TIMING_PRODUCER=adversarial
  v2_timing_begin
  if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "adversarial E2E requires a clean source tree" >&2
    exit 3
  fi
  source_commit=$(git rev-parse HEAD)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  run_root="$artifact_root/run-$stamp"
  control_evidence="$run_root/control"
  backup_evidence="$run_root/backup"
  routing_evidence="$run_root/routing"
  dns_evidence="$run_root/dns"
  (umask 077; mkdir -p "$run_root")

  assert_cached_archive "$repository_root/test/v2lab/routing/manifest.json" '.mihomo'
  assert_cached_archive "$repository_root/test/v2lab/dns/manifest.json" '.mihomo'
  run_source_tests
  v2_timing_mark source_checks

  assert_instance_contract "$gateway_instance"
  assert_instance_contract "$node_instance"
  gateway_initial=$(instance_status "$gateway_instance")
  node_initial=$(instance_status "$node_instance")
  start_fixture "$gateway_instance" gateway_started
  start_fixture "$node_instance" node_started
  trap cleanup_on_exit EXIT INT TERM
  cleanup_owned
  assert_clean
  v2_timing_mark preflight

  "$repository_root/scripts/v2control-spike.sh" verify "$control_evidence" > "$run_root/control.log"
  assert_clean
  "$repository_root/scripts/v2backup-spike.sh" verify "$backup_evidence" > "$run_root/backup.log"
  assert_clean
  v2_timing_mark control_and_backup
  "$repository_root/scripts/v2firewall-test.sh" verify > "$run_root/firewall.log"
  assert_clean
  v2_timing_mark firewall
  "$repository_root/scripts/v2routing-spike.sh" prepare > "$run_root/routing-prepare.log"
  "$repository_root/scripts/v2routing-spike.sh" verify "$routing_evidence" > "$run_root/routing-verify.log"
  assert_clean
  v2_timing_mark routing
  "$repository_root/scripts/v2dns-spike.sh" prepare > "$run_root/dns-prepare.log"
  "$repository_root/scripts/v2dns-spike.sh" verify "$dns_evidence" > "$run_root/dns-verify.log"
  assert_clean
  v2_timing_mark dns

  trap - EXIT INT TERM
  restore_fixture_states
  if [ "$(instance_status "$gateway_instance")" != "$gateway_initial" ] ||
     [ "$(instance_status "$node_instance")" != "$node_initial" ]; then
    echo "adversarial E2E did not restore prior fixture states" >&2
    exit 3
  fi
  write_summary "$source_commit" "$control_evidence/summary.json" "$backup_evidence/summary.json" \
    "$routing_evidence/summary.json" "$dns_evidence/summary.json"
  jq -e '.status == "passed" and
    .identity.invite_replay_rejected and .identity.recovery_replay_rejected and
    .identity.enrollment_transcript_replay_rejected and .identity.mtls_impersonation_rejected and
    .identity.stale_generation_rejected and .identity.malicious_tunnel_mapping_rejected and
    .filesystem_and_output.symlink_attacks_rejected and .filesystem_and_output.unsafe_permissions_fail_closed and
    .filesystem_and_output.secret_redaction_enforced and
    .artifacts.corrupt_release_bundle_rejected_before_mutation and
    .artifacts.wrong_backup_passphrase_rejected and .artifacts.corrupt_backup_rejected and
    .artifacts.failed_restore_output_absent and
    .network.firewall_conflict_rejected_and_foreign_preserved and
    .network.selected_ipv6_tcp_udp_fail_closed and .network.selected_tcp_udp_never_fail_direct and
    .network.dns_selected_direct_fallback_queries == 0 and .network.dns_resolver_loss_bypass_queries == 0 and
    .network.foreign_network_resources_preserved and
    .providers.control_native and .providers.backup_native and .providers.firewall_namespace_native and
    .providers.routing_native and .providers.dns_native and .cleanup.owner_scoped and
    .cleanup.temporary_resources_absent and .cleanup.prior_fixture_states_restored' \
    "$run_root/summary.json" >/dev/null
  v2_timing_finish cleanup_and_validation
  printf 'adversarial E2E evidence: %s\n' "$run_root/summary.json"
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
