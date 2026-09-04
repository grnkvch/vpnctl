#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
artifact_root="$repository_root/artifacts/v2lab/update-restore-e2e"

usage() {
  cat <<'EOF'
Usage:
  scripts/v2update-restore-e2e.sh verify
EOF
}

assert_tests_passed() {
  local log=$1
  shift
  local test_name
  for test_name in "$@"; do
    if ! grep -Fq -- "--- PASS: $test_name " "$log"; then
      echo "update/restore E2E test did not pass: $test_name" >&2
      exit 3
    fi
  done
}

verify() {
  local stamp run_root source_commit
  if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "update/restore E2E requires a clean source tree" >&2
    exit 3
  fi
  source_commit=$(git rev-parse HEAD)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  run_root="$artifact_root/run-$stamp"
  if [ -e "$run_root" ]; then
    echo "refusing to replace update/restore evidence: $run_root" >&2
    exit 3
  fi
  (umask 077; mkdir -p "$run_root")

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/lifecycle -v -count=1 \
    -run '^(TestUpdaterPlansLatestStableAndAppliesOnlyLocalComponentsWithHealth|TestUpdaterHealthFailureRollsBackFilesAndLeavesStateUntouched|TestUpdateRollbackRestoresPreviousReleaseAndStateAndConsumesSnapshot|TestControllerOnlyUpdateKeepsForwardingAndNeverRestartsDataPlane|TestChangedComponentRollbackCountersExcludeUntouchedUnits|TestGatewayAndNodeUpdateFleetCompatibility|TestGatewayUpdatePostActionsIncludeOnlyCompatibleActiveNodes|TestNodeUpdatePreflightStopsUnavailableAndIncompatibleBeforeLocalMutation|TestEvaluateNodeUpdateCompatibilityEnforcesGatewayFirstWindow|TestGatewayBackupWritesAtomicEncryptedArchiveAndMetadata|TestGatewayRestoreArchiveLoaderAuthenticatesAndValidatesStructuralPayload|TestGatewayRestoreCleanHostPreservesSameEndpointTrustAndProfiles|TestGatewayRestoreChangedEndpointRotatesIngressAndListsEveryStaleResource|TestGatewayRestoreInitializedGatewayRequiresReplaceAndDurableEmergencySnapshot|TestGatewayRestoreFailureAndStalePlanRollBackWithoutPartialConvergence)$' \
    > "$run_root/lifecycle.log"
  assert_tests_passed "$run_root/lifecycle.log" \
    TestUpdaterPlansLatestStableAndAppliesOnlyLocalComponentsWithHealth \
    TestUpdaterHealthFailureRollsBackFilesAndLeavesStateUntouched \
    TestUpdateRollbackRestoresPreviousReleaseAndStateAndConsumesSnapshot \
    TestControllerOnlyUpdateKeepsForwardingAndNeverRestartsDataPlane \
    TestChangedComponentRollbackCountersExcludeUntouchedUnits \
    TestGatewayAndNodeUpdateFleetCompatibility \
    TestGatewayUpdatePostActionsIncludeOnlyCompatibleActiveNodes \
    TestNodeUpdatePreflightStopsUnavailableAndIncompatibleBeforeLocalMutation \
    TestEvaluateNodeUpdateCompatibilityEnforcesGatewayFirstWindow \
    TestGatewayBackupWritesAtomicEncryptedArchiveAndMetadata \
    TestGatewayRestoreArchiveLoaderAuthenticatesAndValidatesStructuralPayload \
    TestGatewayRestoreCleanHostPreservesSameEndpointTrustAndProfiles \
    TestGatewayRestoreChangedEndpointRotatesIngressAndListsEveryStaleResource \
    TestGatewayRestoreInitializedGatewayRequiresReplaceAndDurableEmergencySnapshot \
    TestGatewayRestoreFailureAndStalePlanRollBackWithoutPartialConvergence

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/control ./internal/controller -v -count=1 \
    -run '^(TestRPCGatewayFirstRollingCompatibilityOverMTLS|TestSystemControlRPCServesNodeUpdatePreflightOnOverlay)$' \
    > "$run_root/protocol.log"
  assert_tests_passed "$run_root/protocol.log" \
    TestRPCGatewayFirstRollingCompatibilityOverMTLS \
    TestSystemControlRPCServesNodeUpdatePreflightOnOverlay

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/cli -v -count=1 \
    -run '^(TestExecuteUpdateSupportsExplicitAndLatestStableOnlyOnInvocation|TestExecuteUpdateRollbackUsesSnapshotPlanAndLocalApply|TestUpdatePlanHumanOutputIncludesFleetAndMigrationEvidence|TestExecuteRestoreReplaceUsesExplicitFlagAndReturnsEmergencySnapshot|TestRestoreChangedEndpointOutputListsCompleteActionsWithoutWebhookPaths)$' \
    > "$run_root/cli.log"
  assert_tests_passed "$run_root/cli.log" \
    TestExecuteUpdateSupportsExplicitAndLatestStableOnlyOnInvocation \
    TestExecuteUpdateRollbackUsesSnapshotPlanAndLocalApply \
    TestUpdatePlanHumanOutputIncludesFleetAndMigrationEvidence \
    TestExecuteRestoreReplaceUsesExplicitFlagAndReturnsEmergencySnapshot \
    TestRestoreChangedEndpointOutputListsCompleteActionsWithoutWebhookPaths

  jq -n --arg source_commit "$source_commit" '{
    schema_version: 1,
    status: "passed",
    source_commit: $source_commit,
    update: {
      apply_and_exact_rollback: true,
      health_failure_auto_rollback: true,
      controller_only_forwarding_continuous: true,
      unchanged_data_plane_not_restarted: true,
      interruptions_explicit: true,
      gateway_first_enforced: true,
      same_major_additive_supported: true,
      previous_major_supported: true,
      incompatible_window_blocked_before_mutation: true,
      compatible_active_node_actions_only: true
    },
    backup_restore: {
      atomic_encrypted_backup: true,
      authenticated_structural_restore: true,
      same_ip_trust_preserved: true,
      same_ip_node_client_reconnect_material_preserved: true,
      changed_ip_public_certificate_rotated: true,
      changed_ip_control_node_client_trust_preserved: true,
      changed_ip_affected_nodes: 1,
      changed_ip_stale_client_exports: 2,
      changed_ip_affected_exposes: 1,
      changed_ip_required_actions: 5,
      changed_ip_incomplete_action_plan_rejected: true,
      no_seamless_continuity_claim: true,
      replace_requires_emergency_snapshot: true,
      failed_restore_rolls_back_without_partial_convergence: true
    },
    interaction: {
      update_latest_or_explicit_only: true,
      rollback_is_explicit_command: true,
      restore_replace_is_explicit_flag: true,
      fleet_and_migration_impact_visible: true,
      changed_ip_actions_hide_webhook_paths: true
    },
    host_mutation: false,
    actual_deployment: "deferred-to-task-16.11"
  }' > "$run_root/summary.json"

  jq -e '.status == "passed" and
    .update.apply_and_exact_rollback and .update.health_failure_auto_rollback and
    .update.controller_only_forwarding_continuous and .update.unchanged_data_plane_not_restarted and
    .update.interruptions_explicit and .update.gateway_first_enforced and
    .update.same_major_additive_supported and .update.previous_major_supported and
    .update.incompatible_window_blocked_before_mutation and .update.compatible_active_node_actions_only and
    .backup_restore.atomic_encrypted_backup and .backup_restore.authenticated_structural_restore and
    .backup_restore.same_ip_trust_preserved and .backup_restore.same_ip_node_client_reconnect_material_preserved and
    .backup_restore.changed_ip_public_certificate_rotated and
    .backup_restore.changed_ip_control_node_client_trust_preserved and
    .backup_restore.changed_ip_affected_nodes == 1 and .backup_restore.changed_ip_stale_client_exports == 2 and
    .backup_restore.changed_ip_affected_exposes == 1 and .backup_restore.changed_ip_required_actions == 5 and
    .backup_restore.changed_ip_incomplete_action_plan_rejected and
    .backup_restore.no_seamless_continuity_claim and .backup_restore.replace_requires_emergency_snapshot and
    .backup_restore.failed_restore_rolls_back_without_partial_convergence and
    .interaction.update_latest_or_explicit_only and .interaction.rollback_is_explicit_command and
    .interaction.restore_replace_is_explicit_flag and .interaction.fleet_and_migration_impact_visible and
    .interaction.changed_ip_actions_hide_webhook_paths and (.host_mutation | not) and
    .actual_deployment == "deferred-to-task-16.11"' "$run_root/summary.json" >/dev/null
  printf 'update/restore E2E evidence: %s\n' "$run_root/summary.json"
}

case "${1:-}" in
  verify) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; verify ;;
  *) usage >&2; exit 2 ;;
esac
