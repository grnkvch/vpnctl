package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

func TestNodeConfigurationCompilerRendersCompleteJoinedServiceBoundary(t *testing.T) {
	for _, activeTransport := range []model.TransportKind{model.TransportStandard, model.TransportRestricted} {
		activeTransport := activeTransport
		t.Run(string(activeTransport), func(t *testing.T) {
			fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
			defer fixture.destroy()
			presets := []string{}
			if activeTransport == model.TransportRestricted {
				presets = []string{"telegram"}
			}
			if _, err := fixture.workflow.Join(context.Background(), fixture.token, activeTransport, presets); err != nil {
				t.Fatal(err)
			}
			state, err := fixture.nodeState.Load()
			if err != nil {
				t.Fatal(err)
			}
			state.DNS = &model.DNSUpstreamState{
				SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamDirect,
				IPv4: []string{"192.0.2.53", "198.51.100.53"},
			}
			state.Components.Components = append(state.Components.Components, nodeConfigurationFRPPin())
			if err := state.Validate(); err != nil {
				t.Fatalf("joined compiler state: %v", err)
			}
			root := t.TempDir()
			compiler, err := NewNodeConfigurationCompiler(root, fixture.nodeSecrets, NodeConfigurationRuntime{
				WireGuardRunner: &joinWireGuardRunner{}, Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
			})
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := compiler.Compile(context.Background(), state, linuxplatform.HostSnapshot{Routes: []linuxplatform.Route{
				{Family: "ipv4", Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Table: "main", Metric: 100},
				{Family: "ipv4", Destination: "default", Gateway: "198.51.100.1", Device: "ens4", Table: "254", Metric: 200},
			}})
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}
			if configuration.StateGeneration() != state.Generation {
				t.Fatalf("configuration generation = %d", configuration.StateGeneration())
			}
			files := nodeConfigurationFiles(t, configuration)
			wantNames := []string{
				nodeRoutingGuardReadyFileName, nodeRoutingReadyFileName, nodeStandardReadyFileName,
				routing.NodeRoutingConfigFileName, routing.NodeRoutingGuardConfigFileName, routing.NodeDNSIntegrationConfigName,
				transport.StandardConfigFileName, tunnel.FRPClientConfigFileName, tunnel.FRPClientReadyFileName, tunnel.FRPServerCertificateName,
			}
			sort.Strings(wantNames)
			gotNames := make([]string, 0, len(files))
			for name := range files {
				gotNames = append(gotNames, name)
			}
			sort.Strings(gotNames)
			if !reflect.DeepEqual(gotNames, wantNames) {
				t.Fatalf("compiled files = %v, want %v", gotNames, wantNames)
			}
			if !bytes.Contains(files[transport.StandardConfigFileName], []byte("Table = off")) ||
				!bytes.Contains(files[transport.StandardConfigFileName], []byte("AllowedIPs = 0.0.0.0/0")) {
				t.Fatalf("standard config is not route-neutral: %s", files[transport.StandardConfigFileName])
			}
			if err := routing.ValidateNodeRoutingConfig(files[routing.NodeRoutingConfigFileName], routing.NodeRoutingDNSPolicy); err != nil {
				t.Fatalf("routing config: %v", err)
			}
			var guard routing.NodeRoutingGuardConfig
			if err := json.Unmarshal(files[routing.NodeRoutingGuardConfigFileName], &guard); err != nil || guard.Validate() != nil {
				t.Fatalf("guard config = %+v, decode=%v validate=%v", guard, err, guard.Validate())
			}
			if guard.DirectRoute.Interface != "ens3" || guard.DirectRoute.GatewayIPv4 != "192.0.2.1" || guard.ActiveTransport != activeTransport ||
				!reflect.DeepEqual(guard.RecoveryPorts, []routing.NodeRoutingRecoveryPort{
					{Protocol: routing.NodeRoutingTCP, Port: 443},
					{Protocol: routing.NodeRoutingTCP, Port: 8443},
					{Protocol: routing.NodeRoutingUDP, Port: transport.StandardUDPPort},
				}) || len(guard.IngressEndpoints) != 0 {
				t.Fatalf("guard bindings = %+v", guard)
			}
			if err := tunnel.ValidateFRPClientConfig(files[tunnel.FRPClientConfigFileName]); err != nil {
				t.Fatalf("frp client config: %v", err)
			}
			if !bytes.Contains(files[tunnel.FRPClientConfigFileName], []byte("serverAddr = \"10.67.0.1\"")) ||
				!bytes.Contains(files[tunnel.FRPClientConfigFileName], []byte("trustedCaFile = \""+root+"/etc/vpnctl/generated/node/tunnel-server.crt\"")) {
				t.Fatalf("frp client trust binding is incomplete: %s", files[tunnel.FRPClientConfigFileName])
			}
			storedCertificate, err := fixture.nodeSecrets.Get(state.Nodes[0].Gateway.TunnelCertificateRef)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(files[tunnel.FRPServerCertificateName], storedCertificate) {
				t.Fatal("published tunnel certificate differs from joined trust material")
			}
			for _, marker := range []string{nodeStandardReadyFileName, nodeRoutingReadyFileName, nodeRoutingGuardReadyFileName, tunnel.FRPClientReadyFileName} {
				if !bytes.Contains(files[marker], []byte("state_generation=2\n")) || bytes.Contains(files[marker], []byte("token")) {
					t.Fatalf("unsafe or unbound marker %s: %s", marker, files[marker])
				}
			}
			copied := configuration.ConfigFiles()
			copied[0].Content[0] ^= 0xff
			if bytes.Equal(copied[0].Content, configuration.ConfigFiles()[0].Content) {
				t.Fatal("ConfigFiles() did not return defensive content copies")
			}
		})
	}
}

func TestNodeConfigurationCompilerRejectsTunnelTrustSubstitution(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	if _, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportStandard, []string{}); err != nil {
		t.Fatal(err)
	}
	state, _ := fixture.nodeState.Load()
	state.DNS = &model.DNSUpstreamState{SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamDirect, IPv4: []string{"192.0.2.53"}}
	state.Components.Components = append(state.Components.Components, nodeConfigurationFRPPin())
	state.Nodes[0].Gateway.TunnelCertificateFingerprint = "sha256:" + strings.Repeat("f", 64)
	compiler, err := NewNodeConfigurationCompiler(t.TempDir(), fixture.nodeSecrets, NodeConfigurationRuntime{
		WireGuardRunner: &joinWireGuardRunner{}, Now: func() time.Time { return fixture.now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiler.Compile(context.Background(), state, linuxplatform.HostSnapshot{Routes: []linuxplatform.Route{{
		Family: "ipv4", Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Table: "main",
	}}})
	if err == nil || !strings.Contains(err.Error(), "fingerprint differs") {
		t.Fatalf("Compile() substitution error = %v", err)
	}
}

func TestDeriveNodeDirectRouteUsesUniqueBestMainDefault(t *testing.T) {
	for _, test := range []struct {
		name     string
		routes   []linuxplatform.Route
		want     routing.NodeRoutingDirectRoute
		wantCode string
	}{
		{name: "missing", routes: []linuxplatform.Route{{Family: "ipv4", Destination: "default", Device: "eth0", Table: "100"}}, wantCode: "no usable"},
		{name: "equal cost ambiguity", routes: []linuxplatform.Route{
			{Family: "ipv4", Destination: "default", Device: "eth0", Table: "main", Metric: 10},
			{Family: "ipv4", Destination: "default", Device: "eth1", Table: "254", Metric: 10},
		}, wantCode: "multiple equal-priority"},
		{name: "best metric", routes: []linuxplatform.Route{
			{Family: "ipv4", Destination: "default", Gateway: "198.51.100.1", Device: "eth1", Table: "main", Metric: 20},
			{Family: "ipv4", Destination: "default", Gateway: "192.0.2.1", Device: "eth0", Table: "254", Metric: 10},
			{Family: "ipv4", Destination: "default", Device: "reject0", Table: "main", Type: "blackhole", Metric: 1},
		}, want: routing.NodeRoutingDirectRoute{Interface: "eth0", GatewayIPv4: "192.0.2.1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := deriveNodeDirectRoute(linuxplatform.HostSnapshot{Routes: test.routes})
			if test.wantCode != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantCode) {
					t.Fatalf("deriveNodeDirectRoute() = %+v, %v", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("deriveNodeDirectRoute() = %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func nodeConfigurationFiles(t *testing.T, configuration NodeConfiguration) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, file := range configuration.ConfigFiles() {
		if _, duplicate := result[file.Name]; duplicate {
			t.Fatalf("duplicate configuration file %s", file.Name)
		}
		result[file.Name] = file.Content
	}
	return result
}

func nodeConfigurationFRPPin() model.ComponentPin {
	return model.ComponentPin{
		Name: tunnel.FRPProviderName, Version: tunnel.FRPProviderVersion, Source: "vpnctl-release-bundle", Bundled: true,
		SHA256:       tunnel.FRPProviderSHA256,
		Capabilities: []string{"dynamic-reload", "http-plugin-authorization", "tcp-mux", "tls-server-verification"},
	}
}
