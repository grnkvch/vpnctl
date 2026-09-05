package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2UpdateRestoreE2EContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "update-restore-e2e")
	var manifest struct {
		Status           string `json:"status"`
		Scope            string `json:"scope"`
		ActualDeployment string `json:"actual_deployment"`
		Update           struct {
			ExactRollback        bool `json:"apply_and_exact_rollback"`
			HealthRollback       bool `json:"health_failure_auto_rollback"`
			ControllerContinuity bool `json:"controller_only_forwarding_continuous"`
			DataPlaneUnchanged   bool `json:"unchanged_data_plane_not_restarted"`
			Interruptions        bool `json:"interruptions_explicit"`
			GatewayFirst         bool `json:"gateway_first_enforced"`
			SameMajor            bool `json:"same_major_additive_supported"`
			PreviousMajor        bool `json:"previous_major_supported"`
			IncompatibleBlocked  bool `json:"incompatible_window_blocked_before_mutation"`
			CompatibleActions    bool `json:"compatible_active_node_actions_only"`
		} `json:"update"`
		BackupRestore struct {
			Encrypted            bool `json:"atomic_encrypted_backup"`
			Authenticated        bool `json:"authenticated_structural_restore"`
			SameIPTrust          bool `json:"same_ip_trust_preserved"`
			SameIPReconnect      bool `json:"same_ip_node_client_reconnect_material_preserved"`
			ChangedIPCertificate bool `json:"changed_ip_public_certificate_rotated"`
			ChangedIPTrust       bool `json:"changed_ip_control_node_client_trust_preserved"`
			AffectedNodes        int  `json:"changed_ip_affected_nodes"`
			StaleClientExports   int  `json:"changed_ip_stale_client_exports"`
			AffectedExposes      int  `json:"changed_ip_affected_exposes"`
			RequiredActions      int  `json:"changed_ip_required_actions"`
			IncompleteRejected   bool `json:"changed_ip_incomplete_action_plan_rejected"`
			NoSeamlessClaim      bool `json:"no_seamless_continuity_claim"`
			EmergencySnapshot    bool `json:"replace_requires_emergency_snapshot"`
			FailureRollback      bool `json:"failed_restore_rolls_back_without_partial_convergence"`
		} `json:"backup_restore"`
		Interaction struct {
			VersionSelection bool `json:"update_latest_or_explicit_only"`
			RollbackCommand  bool `json:"rollback_is_explicit_command"`
			ReplaceFlag      bool `json:"restore_replace_is_explicit_flag"`
			ImpactVisible    bool `json:"fleet_and_migration_impact_visible"`
			PathsHidden      bool `json:"changed_ip_actions_hide_webhook_paths"`
		} `json:"interaction"`
		HostMutation bool `json:"host_mutation"`
	}
	if err := json.Unmarshal([]byte(readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))), &manifest); err != nil {
		t.Fatalf("decode update/restore E2E manifest: %v", err)
	}
	if manifest.Status != "accepted" || manifest.Scope != "source-production-workflows" ||
		manifest.ActualDeployment != "deferred-to-task-16.11" || manifest.HostMutation {
		t.Fatalf("update/restore acceptance identity is incomplete: %+v", manifest)
	}
	if !manifest.Update.ExactRollback || !manifest.Update.HealthRollback || !manifest.Update.ControllerContinuity ||
		!manifest.Update.DataPlaneUnchanged || !manifest.Update.Interruptions || !manifest.Update.GatewayFirst ||
		!manifest.Update.SameMajor || !manifest.Update.PreviousMajor || !manifest.Update.IncompatibleBlocked ||
		!manifest.Update.CompatibleActions {
		t.Fatalf("update evidence = %+v", manifest.Update)
	}
	if !manifest.BackupRestore.Encrypted || !manifest.BackupRestore.Authenticated ||
		!manifest.BackupRestore.SameIPTrust || !manifest.BackupRestore.SameIPReconnect ||
		!manifest.BackupRestore.ChangedIPCertificate || !manifest.BackupRestore.ChangedIPTrust ||
		manifest.BackupRestore.AffectedNodes != 1 || manifest.BackupRestore.StaleClientExports != 2 ||
		manifest.BackupRestore.AffectedExposes != 1 || manifest.BackupRestore.RequiredActions != 5 ||
		!manifest.BackupRestore.IncompleteRejected || !manifest.BackupRestore.NoSeamlessClaim ||
		!manifest.BackupRestore.EmergencySnapshot || !manifest.BackupRestore.FailureRollback {
		t.Fatalf("backup/restore evidence = %+v", manifest.BackupRestore)
	}
	if !manifest.Interaction.VersionSelection || !manifest.Interaction.RollbackCommand ||
		!manifest.Interaction.ReplaceFlag || !manifest.Interaction.ImpactVisible || !manifest.Interaction.PathsHidden {
		t.Fatalf("update/restore interaction evidence = %+v", manifest.Interaction)
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2update-restore-e2e.sh"))
	for _, required := range []string{
		"TestUpdaterPlansLatestStableAndAppliesOnlyLocalComponentsWithHealth",
		"TestUpdaterHealthFailureRollsBackFilesAndLeavesStateUntouched",
		"TestUpdateRollbackRestoresPreviousReleaseAndStateAndConsumesSnapshot",
		"TestControllerOnlyUpdateKeepsForwardingAndNeverRestartsDataPlane",
		"TestChangedComponentRollbackCountersExcludeUntouchedUnits",
		"TestGatewayAndNodeUpdateFleetCompatibility", "TestGatewayUpdatePostActionsIncludeOnlyCompatibleActiveNodes",
		"TestNodeUpdatePreflightStopsUnavailableAndIncompatibleBeforeLocalMutation",
		"TestEvaluateNodeUpdateCompatibilityEnforcesGatewayFirstWindow",
		"TestGatewayBackupWritesAtomicEncryptedArchiveAndMetadata",
		"TestGatewayRestoreArchiveLoaderAuthenticatesAndValidatesStructuralPayload",
		"TestGatewayRestoreCleanHostPreservesSameEndpointTrustAndProfiles",
		"TestGatewayRestoreChangedEndpointRotatesIngressAndListsEveryStaleResource",
		"TestGatewayRestoreInitializedGatewayRequiresReplaceAndDurableEmergencySnapshot",
		"TestGatewayRestoreFailureAndStalePlanRollBackWithoutPartialConvergence",
		"TestRPCGatewayFirstRollingCompatibilityOverMTLS", "TestSystemControlRPCServesNodeUpdatePreflightOnOverlay",
		"TestExecuteUpdateSupportsExplicitAndLatestStableOnlyOnInvocation",
		"TestExecuteUpdateRollbackUsesSnapshotPlanAndLocalApply",
		"TestUpdatePlanHumanOutputIncludesFleetAndMigrationEvidence",
		"TestExecuteRestoreReplaceUsesExplicitFlagAndReturnsEmergencySnapshot",
		"TestRestoreChangedEndpointOutputListsCompleteActionsWithoutWebhookPaths",
		"changed_ip_required_actions: 5", "host_mutation: false",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("update/restore orchestrator is missing %q", required)
		}
	}
	for _, forbidden := range []string{"limactl", "sudo ", "curl ", "rm -rf", "ssh "} {
		if strings.Contains(orchestrator, forbidden) {
			t.Errorf("source-only update/restore gate contains host/network surface %q", forbidden)
		}
	}
}
