package routing

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
)

func TestRenderNodeRoutingBundleDerivesOneStandardOrRestrictedBinding(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		binding func(*testing.T) NodeRoutingActiveOutbound
		target  string
	}{
		{name: "standard", binding: func(*testing.T) NodeRoutingActiveOutbound { return nodeRoutingStandardBinding() }, target: NodeRoutingStandardProxy},
		{name: "restricted", binding: nodeRoutingRestrictedBinding, target: NodeRoutingRestrictedProxy},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
			request.ActiveOutbound = test.binding(t)
			guard := nodeRoutingGuardFixture(t).Config()
			guard.Matcher = MatcherIR{SchemaVersion: MatcherIRSchemaVersion}
			guard.GatewayIPv4 = "198.51.100.99"
			guard.GatewayOverlayIPv4 = ""
			guard.ActiveTransport = ""
			bundle, err := RenderNodeRoutingBundle(request, guard)
			if err != nil {
				t.Fatal(err)
			}
			config := bundle.Guard().Config()
			if config.ActiveTransport != request.ActiveOutbound.Kind || config.GatewayIPv4 != request.ActiveOutbound.GatewayPublicIPv4 ||
				config.GatewayOverlayIPv4 != request.ActiveOutbound.GatewayOverlayIPv4 {
				t.Fatalf("derived %s bundle = %+v", test.name, config)
			}
			engine := string(bundle.Routing().Bytes())
			if !strings.Contains(engine, "      - "+test.target+"\n") || strings.Contains(engine, "      - DIRECT\n") {
				t.Fatalf("%s engine does not have one active target:\n%s", test.name, engine)
			}
			guardNFT := string(bundle.Guard().NFTablesDefinition())
			if !strings.Contains(guardNFT, "ip daddr 10.67.0.1 meta mark set") {
				t.Fatalf("%s guard does not select internal gateway:\n%s", test.name, guardNFT)
			}
			dns := bundle.DNS()
			if dns.Config().LinkName != config.DirectRoute.Interface || !strings.Contains(string(dns.NFTablesDefinition()), "redirect to :1053") {
				t.Fatalf("%s DNS integration is not derived from the guard underlay: %+v", test.name, dns.Config())
			}
			dnsBytes := dns.Bytes()
			dnsBytes[0] = 'X'
			if string(dns.Bytes()[0]) == "X" {
				t.Fatal("node DNS bundle candidate exposed mutable bytes")
			}
		})
	}
}

func TestRenderNodeRoutingBundleRejectsUnboundProductionCandidate(t *testing.T) {
	t.Parallel()
	request := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
	if _, err := RenderNodeRoutingBundle(request, nodeRoutingGuardFixture(t).Config()); err == nil {
		t.Fatal("unbound production bundle rendered")
	}
	request.ActiveOutbound = nodeRoutingStandardBinding()
	request.ActiveOutbound.Kind = model.TransportKind("automatic")
	if _, err := RenderNodeRoutingBundle(request, nodeRoutingGuardFixture(t).Config()); err == nil {
		t.Fatal("unknown active transport bundle rendered")
	}
}

func TestResolveNodeRoutingActiveOutboundUsesOnlyAuthoritativeManualSelection(t *testing.T) {
	t.Parallel()
	_, _, _, localStore, _ := newNodePolicyFixture(t)
	state, err := localStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	standard, err := ResolveNodeRoutingActiveOutbound(state, nil)
	if err != nil {
		t.Fatal(err)
	}
	if standard.Kind != model.TransportStandard || standard.CredentialGeneration != 1 || standard.GatewayPublicIPv4 != "203.0.113.10" ||
		standard.GatewayOverlayIPv4 != "10.45.0.1" || standard.RestrictedIdentitySecret != nil {
		t.Fatalf("standard binding = %+v", standard)
	}

	state.Nodes[0].ActiveTransport = model.TransportRestricted
	for index := range state.Transports {
		if state.Transports[index].Kind == model.TransportStandard {
			state.Transports[index].State = model.TransportStandby
		} else {
			state.Transports[index].State = model.TransportActive
		}
	}
	gatewaySecret, err := restricted.EncodeSecret(restricted.GatewaySecret{
		SchemaVersion:              restricted.SecretSchemaVersion,
		ShadowsocksPassword:        base64.StdEncoding.EncodeToString([]byte(strings.Repeat("g", restricted.SymmetricKeyByteCount))),
		BootstrapShadowTLSPassword: strings.Repeat("62", restricted.SymmetricKeyByteCount),
	})
	if err != nil {
		t.Fatal(err)
	}
	identitySecret, err := restricted.EncodeSecret(restricted.IdentitySecret{
		SchemaVersion: restricted.SecretSchemaVersion, ShadowTLSPassword: strings.Repeat("63", restricted.SymmetricKeyByteCount),
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := nodeRoutingCredentialMap{
		state.Nodes[0].Gateway.RestrictedServerCredentialRef: gatewaySecret,
		model.SecretRef("node:restricted"):                   identitySecret,
	}
	bound, err := ResolveNodeRoutingActiveOutbound(state, credentials)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Kind != model.TransportRestricted || bound.RestrictedHandshakeHost != "www.microsoft.com" ||
		bound.RestrictedServerPassword == "" || string(bound.RestrictedIdentitySecret) != string(identitySecret) {
		t.Fatalf("restricted binding = %+v", bound)
	}
	bound.RestrictedIdentitySecret[0] = 'X'
	if credentials[state.Transports[1].CredentialRef][0] == 'X' {
		t.Fatal("resolved routing binding exposed credential store bytes")
	}

	delete(credentials, state.Transports[1].CredentialRef)
	if _, err := ResolveNodeRoutingActiveOutbound(state, credentials); err == nil {
		t.Fatal("restricted binding resolved without its exact identity credential")
	}
}

type nodeRoutingCredentialMap map[model.SecretRef][]byte

func (values nodeRoutingCredentialMap) Get(reference model.SecretRef) ([]byte, error) {
	value, found := values[reference]
	if !found {
		return nil, fmt.Errorf("credential not found")
	}
	return append([]byte(nil), value...), nil
}
