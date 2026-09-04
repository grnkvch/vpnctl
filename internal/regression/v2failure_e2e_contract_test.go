package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2IngressTunnelFailureE2EContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "failure-e2e")
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
		Providers struct {
			FRPNative    bool   `json:"frp_native"`
			FRPVersion   string `json:"frp_version"`
			NginxNative  bool   `json:"nginx_native"`
			NginxVersion string `json:"nginx_version"`
		} `json:"providers"`
		Failures struct {
			ApplicationDown503       bool `json:"application_down_503"`
			TunnelReconnect          bool `json:"tunnel_reconnect"`
			ControllerDataPlane      bool `json:"gateway_controller_down_data_plane_preserved"`
			ControllerRejectsNewAuth bool `json:"gateway_controller_down_new_auth_rejected"`
			ProxyReloadRollback      bool `json:"proxy_reload_rollback"`
			PartialResponseClose     bool `json:"partial_response_connection_close"`
			NodeRevokeClose          bool `json:"node_revoke_connection_close"`
			ExposeRemovalIsolated    bool `json:"expose_removal_isolated"`
		} `json:"failures"`
		HTTP struct {
			Unknown       int  `json:"unknown"`
			BodyLimit     int  `json:"body_limit"`
			Unavailable   int  `json:"unavailable"`
			Timeout       int  `json:"timeout"`
			RequestReplay bool `json:"request_replay"`
		} `json:"http"`
		Cleanup struct {
			OwnerScoped     bool `json:"owner_scoped"`
			ResourcesAbsent bool `json:"temporary_resources_absent"`
			PackagesRemoved bool `json:"owned_packages_removed"`
			FixturesStopped bool `json:"fixtures_restored_stopped"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal([]byte(readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))), &manifest); err != nil {
		t.Fatalf("decode ingress/tunnel failure E2E manifest: %v", err)
	}
	if manifest.Status != "accepted" || manifest.Scope != "automated-linux-production-native" ||
		manifest.ActualDeployment != "deferred-to-task-16.11" || manifest.Target.OS != "Ubuntu 24.04" ||
		manifest.Target.Architecture != "amd64" || manifest.Target.VCPU != 1 ||
		manifest.Target.MemoryBytes != 536870912 || manifest.Target.DiskBytes != 10737418240 {
		t.Fatalf("failure E2E acceptance identity is incomplete: %+v", manifest)
	}
	if !manifest.Providers.FRPNative || manifest.Providers.FRPVersion != "0.69.0" ||
		!manifest.Providers.NginxNative || manifest.Providers.NginxVersion != "1.24.0" {
		t.Fatalf("production-native provider evidence = %+v", manifest.Providers)
	}
	if !manifest.Failures.ApplicationDown503 || !manifest.Failures.TunnelReconnect ||
		!manifest.Failures.ControllerDataPlane || !manifest.Failures.ControllerRejectsNewAuth ||
		!manifest.Failures.ProxyReloadRollback || !manifest.Failures.PartialResponseClose ||
		!manifest.Failures.NodeRevokeClose || !manifest.Failures.ExposeRemovalIsolated {
		t.Fatalf("failure-path evidence = %+v", manifest.Failures)
	}
	if manifest.HTTP.Unknown != 404 || manifest.HTTP.BodyLimit != 413 || manifest.HTTP.Unavailable != 503 ||
		manifest.HTTP.Timeout != 504 || manifest.HTTP.RequestReplay {
		t.Fatalf("HTTP failure semantics = %+v", manifest.HTTP)
	}
	if !manifest.Cleanup.OwnerScoped || !manifest.Cleanup.ResourcesAbsent ||
		!manifest.Cleanup.PackagesRemoved || !manifest.Cleanup.FixturesStopped {
		t.Fatalf("failure E2E cleanup evidence = %+v", manifest.Cleanup)
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2failure-e2e.sh"))
	for _, required := range []string{
		"assert_cached_archive", "assert_instance_contract", "cleanup_pair_if_fully_owned", "assert_clean",
		"restore_fixture_states", "vpnctl-v2-tunnel-spike-v1", "vpnctl-v2-restricted-spike-v1",
		"vpnctl-v2-ingress-spike-v1", "v2tunnel-release-gate.sh", "v2ingress-release-gate.sh",
		"TestControllerOutageKeepsAppliedDataPlaneAndReturnsManagementUnavailable",
		"TestControllerRestartOnlyObservesDataPlane",
		"TestFRPClientConfigurationReloadFailureRestoresFileAndRuntime",
		"TestGatewayTunnelServicesKeepAuthorizationWithFRPAndOutsideControllerLifetime",
		"TestNginxActivationReloadFailureRestoresPriorServingGeneration",
		"TestExposeRemoveSagaUnpublishesDrainsAndRemovesOnlyTargetBeforePortRelease",
		"application_down_503", "partial_response_connection_close", "request_replay",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("failure E2E orchestrator is missing %q", required)
		}
	}
	cacheCheck := strings.Index(orchestrator, "assert_cached_archive \"$repository_root/test/v2lab/tunnel/manifest.json\"")
	fixtureStart := strings.Index(orchestrator, "start_fixture \"$gateway_instance\"")
	if cacheCheck < 0 || fixtureStart < 0 || cacheCheck > fixtureStart {
		t.Error("failure E2E must validate cached archives before starting mutable fixtures")
	}
	for _, forbidden := range []string{"curl http://github.com", "curl https://github.com", "rm -rf", "limactl delete"} {
		if strings.Contains(orchestrator, forbidden) {
			t.Errorf("failure E2E contains unsafe or network-fetch surface %q", forbidden)
		}
	}

	ingressGate := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2ingress-release-gate.sh"))
	for _, required := range []string{
		"TestNginxRuntimeDoesNotReplayNonIdempotentRequests", ".unknown_status == 404",
		".body_limit_status == 413", ".unavailable_status == 503", ".timeout_status == 504",
		".request_replay == false", "nginx nginx-common", "$spike_script\" uninstall",
	} {
		if !strings.Contains(ingressGate, required) {
			t.Errorf("ingress release gate is missing %q", required)
		}
	}
	tunnelGate := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2tunnel-release-gate.sh"))
	for _, required := range []string{
		"TestFRPNativeRejectedPingClosesRevokedSessionAndRejectsReconnect",
		".dynamic_mapping.remove_without_restart == true",
		".authorization.controller_unavailable_rejected == true",
		".lifecycle.reconnect_without_frpc_restart == true", "$spike_script\" uninstall",
	} {
		if !strings.Contains(tunnelGate, required) {
			t.Errorf("tunnel release gate is missing %q", required)
		}
	}
}
