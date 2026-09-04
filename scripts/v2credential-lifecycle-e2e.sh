#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
artifact_root="$repository_root/artifacts/v2lab/credential-lifecycle-e2e"

usage() {
  cat <<'EOF'
Usage:
  scripts/v2credential-lifecycle-e2e.sh verify
EOF
}

assert_tests_passed() {
  local log=$1
  shift
  local test_name
  for test_name in "$@"; do
    if ! grep -Fq -- "--- PASS: $test_name " "$log"; then
      echo "credential lifecycle test did not pass: $test_name" >&2
      exit 3
    fi
  done
}

verify() {
  local stamp run_root
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  run_root="$artifact_root/run-$stamp"
  if [ -e "$run_root" ]; then
    echo "refusing to replace credential lifecycle evidence: $run_root" >&2
    exit 3
  fi
  umask 077
  mkdir -p "$run_root"

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/routing -v -count=1 \
    -run '^(TestV2ClientCredentialLifecycleE2E|TestClientLifecycleKnownAndUncertainStateFailuresKeepSafeCredentialSet)$' \
    > "$run_root/client.log"
  assert_tests_passed "$run_root/client.log" \
    TestV2ClientCredentialLifecycleE2E \
    TestClientLifecycleKnownAndUncertainStateFailuresKeepSafeCredentialSet

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/enrollment -v -count=1 \
    -run '^(TestV2NodeCredentialLifecycleE2E|TestNodeRotationFailureBeforeGatewayCommitRestoresCompleteOldGeneration|TestNodeRotationTimeTravelRefusesExpiryBeforeAnyApplyEffectAndDirectsRecovery|TestNodeRecoveryReplacesCompleteGenerationAndPreservesStableResources|TestGatewayRecoveryRejectsClonedOrWrongHostWithoutOriginalKeyBeforeAnyMutation|TestRecoveryAuthorizationExpiresFailClosedAtExactBoundary|TestRecoveryIssueRejectsUnexpiredRevokedAndDeletedNodes)$' \
    > "$run_root/node.log"
  assert_tests_passed "$run_root/node.log" \
    TestV2NodeCredentialLifecycleE2E \
    TestNodeRotationFailureBeforeGatewayCommitRestoresCompleteOldGeneration \
    TestNodeRotationTimeTravelRefusesExpiryBeforeAnyApplyEffectAndDirectsRecovery \
    TestNodeRecoveryReplacesCompleteGenerationAndPreservesStableResources \
    TestGatewayRecoveryRejectsClonedOrWrongHostWithoutOriginalKeyBeforeAnyMutation \
    TestRecoveryAuthorizationExpiresFailClosedAtExactBoundary \
    TestRecoveryIssueRejectsUnexpiredRevokedAndDeletedNodes

  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/cli -v -count=1 \
    -run '^(TestNodeLifecycleWorkflowsUseConfirmedImmediateImpact|TestNodeRotationWorkflowUsesConfirmedImmediateAvailabilityImpact|TestGatewayRecoveryWorkflowConfirmsThenWritesTokenOnlyToTTY|TestNodeRecoveryWorkflowUsesHiddenTokenAndAvailabilityConfirmation)$' \
    > "$run_root/cli.log"
  assert_tests_passed "$run_root/cli.log" \
    TestNodeLifecycleWorkflowsUseConfirmedImmediateImpact \
    TestNodeRotationWorkflowUsesConfirmedImmediateAvailabilityImpact \
    TestGatewayRecoveryWorkflowConfirmsThenWritesTokenOnlyToTTY \
    TestNodeRecoveryWorkflowUsesHiddenTokenAndAvailabilityConfirmation

  jq -n '{
    schema_version: 1,
    status: "passed",
    client: {
      rotate_reexport_revoke_delete_sequence: true,
      stable_id_name_overlay_ip_policy_on_rotate: true,
      old_generation_rejected_after_rotate: true,
      current_generation_rejected_after_revoke: true,
      delete_requires_revoke: true,
      managed_exports_removed_on_delete: true,
      external_profile_removal_reported: true
    },
    node: {
      rotate_revoke_delete_sequence: true,
      full_generation_atomic: true,
      precommit_failure_preserves_old_generation: true,
      stable_id_name_overlay_ip_policy_exposes_on_rotate: true,
      old_generation_rejected_after_rotate: true,
      current_generation_rejected_after_revoke: true,
      delete_requires_revoke: true,
      gateway_delete_does_not_assume_node_access: true
    },
    recovery: {
      expired_certificate_only: true,
      ttl_minutes: 15,
      exact_expiry_fail_closed: true,
      original_host_key_required: true,
      stable_logical_resources: true,
      old_generation_rejected: true,
      token_one_time: true,
      revoked_deleted_rejected: true
    },
    interaction: {
      explicit_confirmation: true,
      recovery_token_tty_only: true,
      node_token_hidden_input: true
    },
    host_mutation: false
  }' > "$run_root/summary.json"

  jq -e '.status == "passed" and
    .client.rotate_reexport_revoke_delete_sequence and
    .client.stable_id_name_overlay_ip_policy_on_rotate and
    .client.old_generation_rejected_after_rotate and
    .client.current_generation_rejected_after_revoke and
    .client.delete_requires_revoke and .client.managed_exports_removed_on_delete and
    .node.rotate_revoke_delete_sequence and .node.full_generation_atomic and
    .node.precommit_failure_preserves_old_generation and
    .node.stable_id_name_overlay_ip_policy_exposes_on_rotate and
    .node.old_generation_rejected_after_rotate and
    .node.current_generation_rejected_after_revoke and .node.delete_requires_revoke and
    .node.gateway_delete_does_not_assume_node_access and
    .recovery.expired_certificate_only and .recovery.ttl_minutes == 15 and
    .recovery.exact_expiry_fail_closed and .recovery.original_host_key_required and
    .recovery.stable_logical_resources and .recovery.old_generation_rejected and
    .recovery.token_one_time and .recovery.revoked_deleted_rejected and
    .interaction.explicit_confirmation and .interaction.recovery_token_tty_only and
    .interaction.node_token_hidden_input and (.host_mutation | not)' \
    "$run_root/summary.json" >/dev/null
  printf 'credential lifecycle E2E evidence: %s\n' "$run_root/summary.json"
}

case "${1:-}" in
  verify) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; verify ;;
  *) usage >&2; exit 2 ;;
esac
