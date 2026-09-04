package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	v1state "github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

func TestV1MigrationImpactReportsEveryFixtureTransformationAndRequiredReExportReadOnly(t *testing.T) {
	workspace, systemRoot, serverPrivate, clientPrivate := completeV1InspectionFixture(t)
	writeExactV1ClashProfile(t, workspace, clientPrivate)
	writeExactV1WireGuardProfile(t, workspace, clientPrivate)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	before := snapshotV1InspectionTrees(t, workspace, systemRoot)
	parent := canonicalConversionTestRoot(t)
	stage := filepath.Join(parent, "must-not-be-created")
	input := v1ImpactTestInput(&inspection, "8.8.4.4")
	input.StageRoot = stage
	report, err := InspectV1MigrationImpact(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "requires-action" || !report.ReadyForMigration || report.InspectionStatus != V1InspectionReady {
		t.Fatalf("impact status = %s ready=%t inspection=%s", report.Status, report.ReadyForMigration, report.InspectionStatus)
	}
	wantCodes := []string{
		"client_id_mapped", "client_tags_dropped", "forwarding_config_replaced",
		"gateway_id_mapped", "gateway_name_dropped", "generated_artifact_relocated", "generated_artifact_relocated",
		"public_endpoint_changed", "ruleset_display_name_dropped", "ufw_backend_replaced",
		"ufw_ssh_rule_replaced", "ufw_ssh_rule_replaced", "ufw_wireguard_rule_replaced", "ufw_wireguard_rule_replaced",
		"wireguard_config_replaced", "wireguard_interface_changed",
	}
	gotCodes := make([]string, len(report.Impacts))
	for index, impact := range report.Impacts {
		gotCodes[index] = impact.Code
		if impact.SourceField == "" || (impact.Disposition != V1ImpactTransformed && impact.Disposition != V1ImpactDropped && impact.Disposition != V1ImpactBlocker) {
			t.Fatalf("incomplete impact = %+v", impact)
		}
	}
	sort.Strings(gotCodes)
	sort.Strings(wantCodes)
	if !reflect.DeepEqual(gotCodes, wantCodes) {
		t.Fatalf("impact codes = %v, want %v", gotCodes, wantCodes)
	}
	if len(report.RequiredReExports) != 1 {
		t.Fatalf("required re-exports = %+v", report.RequiredReExports)
	}
	reexport := report.RequiredReExports[0]
	if reexport.SourceClientID != "iphone" || reexport.TargetClientID != report.Clients[0].TargetID ||
		!reflect.DeepEqual(reexport.Formats, []string{"clash", "wireguard"}) ||
		!reflect.DeepEqual(reexport.Reasons, []string{"public_endpoint_changed"}) ||
		!reflect.DeepEqual(reexport.Commands, []string{
			"sudo vpnctl client export " + reexport.TargetClientID + " clash",
			"sudo vpnctl client export " + reexport.TargetClientID + " wireguard",
		}) {
		t.Fatalf("required re-export = %+v", reexport)
	}
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("impact analysis created staging root: %v", err)
	}
	after := snapshotV1InspectionTrees(t, workspace, systemRoot)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("impact analysis changed the v1 fixture")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{report.String(), report.GoString(), fmt.Sprintf("%#v", report), string(encoded)} {
		if strings.Contains(rendered, serverPrivate) || strings.Contains(rendered, clientPrivate) ||
			strings.Contains(rendered, workspace) || strings.Contains(rendered, systemRoot) || strings.Contains(rendered, parent) {
			t.Fatal("impact report exposed a credential or physical path")
		}
	}
}

func TestV1MigrationImpactDistinguishesCompatibleAndUnverifiedProfiles(t *testing.T) {
	t.Run("compatible exact profiles", func(t *testing.T) {
		workspace, systemRoot, _, clientPrivate := completeV1InspectionFixture(t)
		writeExactV1ClashProfile(t, workspace, clientPrivate)
		writeExactV1WireGuardProfile(t, workspace, clientPrivate)
		inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
		defer inspection.Destroy()
		report, err := InspectV1MigrationImpact(v1ImpactTestInput(&inspection, "198.51.100.10"))
		if err != nil {
			t.Fatal(err)
		}
		if report.Status != "compatible" || !report.ReadyForMigration || len(report.RequiredReExports) != 0 {
			t.Fatalf("compatible impact = status %s ready=%t reexports=%+v", report.Status, report.ReadyForMigration, report.RequiredReExports)
		}
		if !hasV1ImpactCode(report.Impacts, "public_endpoint_normalized") {
			t.Fatalf("compatible report omitted endpoint field mapping: %+v", report.Impacts)
		}
	})

	t.Run("unverified profiles and unresolved preset", func(t *testing.T) {
		workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
		inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
		defer inspection.Destroy()
		report, err := InspectV1MigrationImpact(v1ImpactTestInput(&inspection, "198.51.100.10"))
		if err != nil {
			t.Fatal(err)
		}
		if report.Status != "requires-action" || !report.ReadyForMigration || !hasV1ImpactCode(report.Impacts, "client_preset_assignment_unresolved") ||
			len(report.RequiredReExports) != 1 {
			t.Fatalf("unverified impact = %+v", report)
		}
		got := report.RequiredReExports[0]
		if !reflect.DeepEqual(got.Formats, []string{"clash", "wireguard"}) ||
			!reflect.DeepEqual(got.Reasons, []string{"legacy_profile_unverified", "preset_assignment_unresolved"}) {
			t.Fatalf("unverified profile actions = %+v", got)
		}
	})
}

func TestV1MigrationImpactRequiresReExportButAllowsFixedPortConversion(t *testing.T) {
	workspace, systemRoot, serverPrivate, clientPrivate := completeV1InspectionFixture(t)
	stateDir := filepath.Join(workspace, ".vpnctl")
	state, err := v1state.Load(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state.Server.WireGuardPort = 51821
	if err := v1state.Save(stateDir, state); err != nil {
		t.Fatal(err)
	}
	writeExactV1ClashProfile(t, workspace, clientPrivate)
	writeExactV1WireGuardProfile(t, workspace, clientPrivate)
	rewriteV1AppliedWireGuard(t, systemRoot, state, serverPrivate)
	for _, name := range []string{"user.rules", "user6.rules"} {
		path := filepath.Join(systemRoot, "etc", "ufw", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		writeV1FixtureFile(t, path, []byte(strings.ReplaceAll(string(data), "udp 51820", "udp 51821")), 0o640)
	}
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	input := v1ImpactTestInput(&inspection, "198.51.100.10")
	report, err := InspectV1MigrationImpact(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "requires-action" || !report.ReadyForMigration || !hasV1ImpactCode(report.Impacts, "wireguard_port_changed") ||
		hasV1ImpactCode(report.Impacts, "conversion_preflight_failed") || len(report.RequiredReExports) != 1 ||
		!reflect.DeepEqual(report.RequiredReExports[0].Reasons, []string{"wireguard_port_changed"}) {
		t.Fatalf("fixed-port impact = %+v", report)
	}
	plan, err := buildV1ConversionPlan(input)
	if err != nil {
		t.Fatalf("fixed-port conversion plan failed: %v", err)
	}
	if len(plan.state.Transports) != 1 || plan.state.Transports[0].Port != 51820 {
		t.Fatalf("fixed-port converted transport = %+v", plan.state.Transports)
	}
}

func TestV1MigrationImpactBlocksUnknownUFWKeyLossAndInvalidClientName(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string, string)
		code    string
	}{
		{name: "foreign UFW rule", code: "ufw_tcp_rule_ownership_unresolved", prepare: func(t *testing.T, _, systemRoot string) {
			path := filepath.Join(systemRoot, "etc", "ufw", "user.rules")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, []byte("### tuple ### allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in\n")...)
			writeV1FixtureFile(t, path, data, 0o640)
		}},
		{name: "missing client key", code: "client_private_key_unavailable", prepare: func(t *testing.T, workspace, _ string) {
			if err := os.Remove(v1state.ClientPrivateKeyPath(filepath.Join(workspace, ".vpnctl"), "iphone")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "invalid v2 client name", code: "client_name_not_convertible", prepare: func(t *testing.T, workspace, _ string) {
			stateDir := filepath.Join(workspace, ".vpnctl")
			state, err := v1state.Load(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			state.Clients[0].Name = "My iPhone"
			if err := v1state.Save(stateDir, state); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
			test.prepare(t, workspace, systemRoot)
			inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
			defer inspection.Destroy()
			report, err := InspectV1MigrationImpact(v1ImpactTestInput(&inspection, "198.51.100.10"))
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != "blocked" || report.ReadyForMigration || !hasV1ImpactCode(report.Impacts, test.code) {
				t.Fatalf("blocked impact = %+v", report)
			}
		})
	}
}

func inspectV1ImpactFixture(t *testing.T, workspace, systemRoot string) V1Inspection {
	t.Helper()
	inspector, err := NewV1InstallationInspector(workspace, systemRoot)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := inspector.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Report.Status != V1InspectionReady && inspection.Report.Status != V1InspectionPartial {
		t.Fatalf("impact fixture inspection = %s: %+v", inspection.Report.Status, inspection.Report.Issues)
	}
	return inspection
}

func v1ImpactTestInput(inspection *V1Inspection, publicIPv4 string) V1ConversionInput {
	return V1ConversionInput{
		Inspection: inspection, PublicIPv4: publicIPv4, SSHPort: 22,
		ConvertedAt: time.Date(2026, time.September, 4, 12, 30, 0, 0, time.UTC),
		Components:  gatewayTestManifest(), HandshakeHost: gatewayTestHandshakeHost(),
	}
}

func writeExactV1WireGuardProfile(t *testing.T, workspace, privateKey string) {
	t.Helper()
	stateDir := filepath.Join(workspace, ".vpnctl")
	state, err := v1state.Load(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	address, err := wireguard.ClientAddress(state.Clients[0].AssignedIP, state.Server.WireGuardSubnet)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := wireguard.RenderClientConfig(wireguard.ClientConfig{
		PrivateKey: privateKey, Address: address, DNSServers: state.Server.DNSServers,
		ServerPublicKey: state.Server.WireGuardPublicKey,
		Endpoint:        wireguard.Endpoint(state.Server.PublicEndpoint, state.Server.WireGuardPort),
	})
	if err != nil {
		t.Fatal(err)
	}
	writeV1FixtureFile(t, filepath.Join(stateDir, "generated", "delivery", "iphone.conf"), []byte(profile), 0o600)
}

func rewriteV1AppliedWireGuard(t *testing.T, systemRoot string, state v1state.State, serverPrivate string) {
	t.Helper()
	address, err := wireguard.ServerAddress(state.Server.WireGuardSubnet)
	if err != nil {
		t.Fatal(err)
	}
	peers := make([]wireguard.ServerPeer, 0, len(state.Clients))
	for _, client := range state.Clients {
		peers = append(peers, wireguard.ServerPeer{
			Name: client.ID, PublicKey: client.WireGuardPublicKey, AllowedIPs: client.AssignedIP + "/32", Status: client.Status,
		})
	}
	config, err := wireguard.RenderServerConfig(wireguard.ServerConfig{
		InterfaceName: state.Server.WireGuardInterface, Address: address, ListenPort: state.Server.WireGuardPort,
		PrivateKey: serverPrivate, ExternalInterface: state.Server.ExternalInterface, Peers: peers,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeV1FixtureFile(t, filepath.Join(systemRoot, "etc", "wireguard", state.Server.WireGuardInterface+".conf"), []byte(config), 0o600)
}
