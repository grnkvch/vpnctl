package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2AdversarialE2EContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "adversarial-e2e")
	var manifest struct {
		Status           string `json:"status"`
		Scope            string `json:"scope"`
		ActualDeployment string `json:"actual_deployment"`
		Target           struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			VCPU         int    `json:"vcpu"`
			MemoryBytes  int64  `json:"memory_bytes"`
			DiskBytes    int64  `json:"disk_bytes"`
		} `json:"target"`
		Identity struct {
			InviteReplay      bool `json:"invite_replay_rejected"`
			RecoveryReplay    bool `json:"recovery_replay_rejected"`
			TranscriptReplay  bool `json:"enrollment_transcript_replay_rejected"`
			MTLSImpersonation bool `json:"mtls_impersonation_rejected"`
			StaleGeneration   bool `json:"stale_generation_rejected"`
			MaliciousMapping  bool `json:"malicious_tunnel_mapping_rejected"`
		} `json:"identity"`
		FilesystemAndOutput struct {
			Symlink     bool `json:"symlink_attacks_rejected"`
			Permissions bool `json:"unsafe_permissions_fail_closed"`
			Redaction   bool `json:"secret_redaction_enforced"`
		} `json:"filesystem_and_output"`
		Artifacts struct {
			ReleaseBundle bool `json:"corrupt_release_bundle_rejected_before_mutation"`
			Passphrase    bool `json:"wrong_backup_passphrase_rejected"`
			Backup        bool `json:"corrupt_backup_rejected"`
			NoOutput      bool `json:"failed_restore_output_absent"`
		} `json:"artifacts"`
		Network struct {
			Firewall         bool `json:"firewall_conflict_rejected_and_foreign_preserved"`
			IPv6UDP          bool `json:"selected_ipv6_tcp_udp_fail_closed"`
			NeverDirect      bool `json:"selected_tcp_udp_never_fail_direct"`
			DNSFallback      int  `json:"dns_selected_direct_fallback_queries"`
			DNSBypass        int  `json:"dns_resolver_loss_bypass_queries"`
			ForeignPreserved bool `json:"foreign_network_resources_preserved"`
		} `json:"network"`
		Providers struct {
			Control  bool `json:"control_native"`
			Backup   bool `json:"backup_native"`
			Firewall bool `json:"firewall_namespace_native"`
			Routing  bool `json:"routing_native"`
			DNS      bool `json:"dns_native"`
		} `json:"providers"`
		Cleanup struct {
			OwnerScoped     bool `json:"owner_scoped"`
			ResourcesAbsent bool `json:"temporary_resources_absent"`
			FixturesStopped bool `json:"fixtures_restored_stopped"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal([]byte(readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))), &manifest); err != nil {
		t.Fatalf("decode adversarial E2E manifest: %v", err)
	}
	if manifest.Status != "accepted" || manifest.Scope != "automated-linux-adversarial" ||
		manifest.ActualDeployment != "deferred-to-task-16.11" || manifest.Target.OS != "Ubuntu 24.04" ||
		manifest.Target.Architecture != "amd64" || manifest.Target.VCPU != 1 ||
		manifest.Target.MemoryBytes != 536870912 || manifest.Target.DiskBytes != 10737418240 {
		t.Fatalf("adversarial acceptance identity is incomplete: %+v", manifest)
	}
	if !manifest.Identity.InviteReplay || !manifest.Identity.RecoveryReplay || !manifest.Identity.TranscriptReplay ||
		!manifest.Identity.MTLSImpersonation || !manifest.Identity.StaleGeneration || !manifest.Identity.MaliciousMapping {
		t.Fatalf("identity adversarial evidence = %+v", manifest.Identity)
	}
	if !manifest.FilesystemAndOutput.Symlink || !manifest.FilesystemAndOutput.Permissions ||
		!manifest.FilesystemAndOutput.Redaction || !manifest.Artifacts.ReleaseBundle ||
		!manifest.Artifacts.Passphrase || !manifest.Artifacts.Backup || !manifest.Artifacts.NoOutput {
		t.Fatalf("filesystem/artifact evidence = filesystem:%+v artifacts:%+v", manifest.FilesystemAndOutput, manifest.Artifacts)
	}
	if !manifest.Network.Firewall || !manifest.Network.IPv6UDP || !manifest.Network.NeverDirect ||
		manifest.Network.DNSFallback != 0 || manifest.Network.DNSBypass != 0 || !manifest.Network.ForeignPreserved {
		t.Fatalf("network adversarial evidence = %+v", manifest.Network)
	}
	if !manifest.Providers.Control || !manifest.Providers.Backup || !manifest.Providers.Firewall ||
		!manifest.Providers.Routing || !manifest.Providers.DNS || !manifest.Cleanup.OwnerScoped ||
		!manifest.Cleanup.ResourcesAbsent || !manifest.Cleanup.FixturesStopped {
		t.Fatalf("provider/cleanup evidence = providers:%+v cleanup:%+v", manifest.Providers, manifest.Cleanup)
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2adversarial-e2e.sh"))
	for _, required := range []string{
		"assert_cached_archive", "assert_instance_contract", "path_owned", "cleanup_owned", "assert_clean",
		"restore_fixture_states", "vpnctl-v2-control-spike-v1", "vpnctl-v2-backup-spike-v1",
		"vpnctl-v2-firewall-test-v1", "vpnctl-v2-routing-spike-v1", "vpnctl-v2-dns-spike-v1",
		"v2control-spike.sh", "v2backup-spike.sh", "v2firewall-test.sh", "v2routing-spike.sh", "v2dns-spike.sh",
		"TestInviteConsumptionRejectsReplayWithoutSecondMutation",
		"TestNodeRecoveryReplacesCompleteGenerationAndPreservesStableResources",
		"TestRPCServerRejectsPublicBindingAndNonMTLSClients",
		"TestRPCNodeAuthorizationBindsCertificateToCurrentCredentialGeneration",
		"TestNewProxyAuthorizationRejectsMaliciousStaleDisabledAndCrossNodeMappings",
		"TestSecretStoreRejectsSymlinkComponents", "TestPermissionRepairDoesNotTouchTreeWithUnsafeEntry",
		"TestSensitiveValuesRefuseSerializationAndGenericResults",
		"TestProviderAndServerRawLogsCannotBypassRedaction",
		"TestNetworkManagerRejectsReservedForeignRuleAndUnsafeSysctlBeforeMutation",
		"TestReleaseBundleVerificationFailsBeforeInstallMutation",
		"TestReleaseBundleRejectsInvalidProviderArchiveBeforeInstall",
		"TestBackupArchiveRejectsWrongPassphraseAndAuthenticatedCorruption",
		"TestGatewayRestoreInvalidInputsAndArchivesNeverReachHostMutation",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("adversarial E2E orchestrator is missing %q", required)
		}
	}
	cacheCheck := strings.Index(orchestrator, "assert_cached_archive \"$repository_root/test/v2lab/routing/manifest.json\"")
	fixtureStart := strings.Index(orchestrator, "start_fixture \"$gateway_instance\"")
	if cacheCheck < 0 || fixtureStart < 0 || cacheCheck > fixtureStart {
		t.Error("adversarial E2E must validate cached provider archives before starting mutable fixtures")
	}
	for _, forbidden := range []string{"curl http://github.com", "curl https://github.com", "limactl delete", "flush ruleset"} {
		if strings.Contains(orchestrator, forbidden) {
			t.Errorf("adversarial E2E contains unsafe or network-fetch surface %q", forbidden)
		}
	}

	childContracts := map[string][]string{
		"v2control-spike.sh": {
			"transcript_replay_rejected: true", "mtls_required: true", "authoritative_generation_checked: true",
		},
		"v2backup-spike.sh": {
			"wrong_passphrase_rejected: true", "authenticated_header_corruption_rejected: true",
			"ciphertext_corruption_rejected: true", "failed_restore_output_absent: true",
		},
		"v2firewall-test.sh": {
			"assert_owned_runtime", "refusing to delete firewall namespaces without the owned runtime marker",
		},
		"v2routing-spike.sh": {
			"selected_ipv6_never_direct", "foreign_nft_preserved: true", "foreign_rule_preserved: true",
		},
		"v2dns-spike.sh": {
			"selected_direct_fallback_queries: 0", "upstream_bypass_queries", "foreign_nftables_preserved: true",
		},
	}
	for name, requiredValues := range childContracts {
		child := readContractFile(t, filepath.Join(repositoryRoot, "scripts", name))
		for _, required := range requiredValues {
			if !strings.Contains(child, required) {
				t.Errorf("%s is missing adversarial evidence %q", name, required)
			}
		}
	}
}
