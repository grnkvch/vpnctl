package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2FleetIsolationE2EContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "fleet-isolation")
	var manifest struct {
		Status           string `json:"status"`
		Scope            string `json:"scope"`
		ActualDeployment string `json:"actual_deployment"`
		Fleet            struct {
			Nodes   int `json:"private_nodes"`
			Clients int `json:"personal_clients"`
			Exposes int `json:"simultaneous_exposes"`
		} `json:"fleet"`
		Credentials struct {
			NodeUnique       bool `json:"node_unique"`
			ClientUnique     bool `json:"client_unique"`
			GenerationScoped bool `json:"generation_scoped"`
		} `json:"credentials"`
		Networking struct {
			ClientToClient bool `json:"client_to_client_blocked"`
			ClientToNode   bool `json:"client_to_node_blocked"`
			NodeToNode     bool `json:"node_to_node_blocked"`
			Internet       bool `json:"permitted_internet_tcp_udp"`
		} `json:"networking"`
		Mappings struct {
			Multiplexed   bool `json:"one_connection_for_two_exposes"`
			CrossNode     bool `json:"cross_node_rejected"`
			Malicious     bool `json:"malicious_rejected"`
			Stale         bool `json:"stale_generation_rejected"`
			PortCollision bool `json:"global_port_collision_rejected"`
		} `json:"mappings"`
		Removal struct {
			OnlyTarget   bool `json:"only_target_removed"`
			OtherMapping bool `json:"other_mapping_continued"`
			OtherNode    bool `json:"other_node_preserved"`
		} `json:"removal"`
		Cleanup struct {
			OwnerScoped     bool `json:"owner_scoped"`
			ResourcesAbsent bool `json:"temporary_resources_absent"`
			FixturesStopped bool `json:"fixtures_restored_stopped"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal([]byte(readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))), &manifest); err != nil {
		t.Fatalf("decode fleet-isolation E2E manifest: %v", err)
	}
	if manifest.Status != "accepted" || manifest.Scope != "automated-linux-fleet" ||
		manifest.ActualDeployment != "deferred-to-task-16.11" || manifest.Fleet.Nodes != 2 ||
		manifest.Fleet.Clients != 5 || manifest.Fleet.Exposes != 2 {
		t.Fatalf("fleet-isolation acceptance identity is incomplete: %+v", manifest)
	}
	if !manifest.Credentials.NodeUnique || !manifest.Credentials.ClientUnique || !manifest.Credentials.GenerationScoped ||
		!manifest.Networking.ClientToClient || !manifest.Networking.ClientToNode ||
		!manifest.Networking.NodeToNode || !manifest.Networking.Internet {
		t.Fatalf("fleet identity/network evidence = credentials:%+v networking:%+v", manifest.Credentials, manifest.Networking)
	}
	if !manifest.Mappings.Multiplexed || !manifest.Mappings.CrossNode || !manifest.Mappings.Malicious ||
		!manifest.Mappings.Stale || !manifest.Mappings.PortCollision || !manifest.Removal.OnlyTarget ||
		!manifest.Removal.OtherMapping || !manifest.Removal.OtherNode {
		t.Fatalf("mapping/removal evidence = mappings:%+v removal:%+v", manifest.Mappings, manifest.Removal)
	}
	if !manifest.Cleanup.OwnerScoped || !manifest.Cleanup.ResourcesAbsent || !manifest.Cleanup.FixturesStopped {
		t.Fatalf("fleet cleanup evidence = %+v", manifest.Cleanup)
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2fleet-isolation-e2e.sh"))
	for _, required := range []string{
		"assert_cached_archive", "assert_instance_contract", "cleanup_pair_if_fully_owned", "assert_clean",
		"restore_fixture_states", "vpnctl-v2-tunnel-spike-v1",
		"vpnctl-v2-restricted-spike-v1", "v2standard-test.sh", "v2tunnel-spike.sh",
		"TestMultipleJoinedNodesRetainIsolatedIdentitiesAndResources",
		"TestNodeCredentialProvisioningCreatesUniqueTunnelCredentialPerNodeGeneration",
		"TestRevokingOneNodePreservesOtherNodeIdentityAndPaths",
		"TestClientManagerCreatesFiveStableIsolatedIdentitiesAndSecretFreeViews",
		"TestPlanRejectsCrossNodeMappingAndGlobalPortCollision",
		"TestNewProxyAuthorizationRejectsMaliciousStaleDisabledAndCrossNodeMappings",
		"TestExposeRemoveSagaUnpublishesDrainsAndRemovesOnlyTargetBeforePortRelease",
		"one_connection_for_two_exposes", "cross_node_rejected", "only_target_removed",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("fleet-isolation E2E orchestrator is missing %q", required)
		}
	}
	cacheCheck := strings.Index(orchestrator, "assert_cached_archive \"$repository_root/test/v2lab/tunnel/manifest.json\"")
	fixtureStart := strings.Index(orchestrator, "start_fixture \"$gateway_instance\"")
	if cacheCheck < 0 || fixtureStart < 0 || cacheCheck > fixtureStart {
		t.Error("fleet-isolation E2E must validate cached archives before starting mutable fixtures")
	}
	for _, forbidden := range []string{
		"curl http://github.com", "curl https://github.com", "rm -rf", "limactl delete",
	} {
		if strings.Contains(orchestrator, forbidden) {
			t.Errorf("fleet-isolation E2E contains unsafe or network-fetch surface %q", forbidden)
		}
	}
}
