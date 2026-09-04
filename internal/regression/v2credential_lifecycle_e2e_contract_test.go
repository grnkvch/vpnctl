package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2CredentialLifecycleE2EContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "credential-lifecycle")
	var manifest struct {
		Status           string `json:"status"`
		Scope            string `json:"scope"`
		ActualDeployment string `json:"actual_deployment"`
		Client           struct {
			Sequence          bool `json:"rotate_reexport_revoke_delete_sequence"`
			Stable            bool `json:"stable_id_name_overlay_ip_policy_on_rotate"`
			OldRejected       bool `json:"old_generation_rejected_after_rotate"`
			RevokedRejected   bool `json:"current_generation_rejected_after_revoke"`
			DeleteAfterRevoke bool `json:"delete_requires_revoke"`
			ExportsRemoved    bool `json:"managed_exports_removed_on_delete"`
			ExternalReported  bool `json:"external_profile_removal_reported"`
		} `json:"client"`
		Node struct {
			Sequence          bool `json:"rotate_revoke_delete_sequence"`
			Atomic            bool `json:"full_generation_atomic"`
			Rollback          bool `json:"precommit_failure_preserves_old_generation"`
			Stable            bool `json:"stable_id_name_overlay_ip_policy_exposes_on_rotate"`
			OldRejected       bool `json:"old_generation_rejected_after_rotate"`
			RevokedRejected   bool `json:"current_generation_rejected_after_revoke"`
			DeleteAfterRevoke bool `json:"delete_requires_revoke"`
			GatewayOnlyDelete bool `json:"gateway_delete_does_not_assume_node_access"`
		} `json:"node"`
		Recovery struct {
			ExpiredOnly     bool `json:"expired_certificate_only"`
			TTLMinutes      int  `json:"ttl_minutes"`
			ExpiryBoundary  bool `json:"exact_expiry_fail_closed"`
			OriginalHostKey bool `json:"original_host_key_required"`
			Stable          bool `json:"stable_logical_resources"`
			OldRejected     bool `json:"old_generation_rejected"`
			OneTime         bool `json:"token_one_time"`
			InactiveReject  bool `json:"revoked_deleted_rejected"`
		} `json:"recovery"`
		Interaction struct {
			Confirm   bool `json:"explicit_confirmation"`
			TTYOutput bool `json:"recovery_token_tty_only"`
			Hidden    bool `json:"node_token_hidden_input"`
		} `json:"interaction"`
		HostMutation bool `json:"host_mutation"`
	}
	if err := json.Unmarshal([]byte(readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))), &manifest); err != nil {
		t.Fatalf("decode credential-lifecycle E2E manifest: %v", err)
	}
	if manifest.Status != "accepted" || manifest.Scope != "source-production-workflows" ||
		manifest.ActualDeployment != "deferred-to-task-16.11" || manifest.HostMutation {
		t.Fatalf("credential-lifecycle acceptance identity is incomplete: %+v", manifest)
	}
	if !manifest.Client.Sequence || !manifest.Client.Stable || !manifest.Client.OldRejected ||
		!manifest.Client.RevokedRejected || !manifest.Client.DeleteAfterRevoke ||
		!manifest.Client.ExportsRemoved || !manifest.Client.ExternalReported {
		t.Fatalf("client lifecycle evidence = %+v", manifest.Client)
	}
	if !manifest.Node.Sequence || !manifest.Node.Atomic || !manifest.Node.Rollback || !manifest.Node.Stable ||
		!manifest.Node.OldRejected || !manifest.Node.RevokedRejected || !manifest.Node.DeleteAfterRevoke ||
		!manifest.Node.GatewayOnlyDelete {
		t.Fatalf("node lifecycle evidence = %+v", manifest.Node)
	}
	if !manifest.Recovery.ExpiredOnly || manifest.Recovery.TTLMinutes != 15 || !manifest.Recovery.ExpiryBoundary ||
		!manifest.Recovery.OriginalHostKey || !manifest.Recovery.Stable || !manifest.Recovery.OldRejected ||
		!manifest.Recovery.OneTime || !manifest.Recovery.InactiveReject || !manifest.Interaction.Confirm ||
		!manifest.Interaction.TTYOutput || !manifest.Interaction.Hidden {
		t.Fatalf("recovery/interaction evidence = recovery:%+v interaction:%+v", manifest.Recovery, manifest.Interaction)
	}

	clientE2E := readContractFile(t, filepath.Join(repositoryRoot, "internal", "routing", "v2_client_credential_lifecycle_test.go"))
	for _, required := range []string{
		"TestV2ClientCredentialLifecycleE2E", "PlanRotate", "CommitRotate", "ClientStandardCredentialAccepted",
		"RequiresClientReExport", "PlanRevoke", "CommitRevoke", "PlanDelete", "CommitDelete",
	} {
		if !strings.Contains(clientE2E, required) {
			t.Errorf("client credential E2E is missing %q", required)
		}
	}
	nodeE2E := readContractFile(t, filepath.Join(repositoryRoot, "internal", "enrollment", "v2_node_credential_lifecycle_test.go"))
	for _, required := range []string{
		"TestV2NodeCredentialLifecycleE2E", "fixture.rotation.Apply", "assertSuccessfulNodeRotation",
		"PlanRevoke", "CommitRevoke", "AuthorizeRPC", "PlanDelete", "CommitDelete",
	} {
		if !strings.Contains(nodeE2E, required) {
			t.Errorf("node credential E2E is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2credential-lifecycle-e2e.sh"))
	for _, required := range []string{
		"TestV2ClientCredentialLifecycleE2E", "TestV2NodeCredentialLifecycleE2E",
		"TestNodeRotationFailureBeforeGatewayCommitRestoresCompleteOldGeneration",
		"TestNodeRecoveryReplacesCompleteGenerationAndPreservesStableResources",
		"TestRecoveryAuthorizationExpiresFailClosedAtExactBoundary",
		"TestRecoveryIssueRejectsUnexpiredRevokedAndDeletedNodes",
		"TestGatewayRecoveryWorkflowConfirmsThenWritesTokenOnlyToTTY",
		"TestNodeRecoveryWorkflowUsesHiddenTokenAndAvailabilityConfirmation",
		"host_mutation: false",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("credential lifecycle orchestrator is missing %q", required)
		}
	}
	for _, forbidden := range []string{"limactl", "sudo ", "curl ", "rm -rf", "ssh "} {
		if strings.Contains(orchestrator, forbidden) {
			t.Errorf("source-only credential lifecycle gate contains host/network surface %q", forbidden)
		}
	}
}
