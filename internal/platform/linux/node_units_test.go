package linux

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestRenderNodeRoleInstallationStagesOnlyNodeUnits(t *testing.T) {
	t.Parallel()

	request, err := RenderNodeRoleInstallation(DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatalf("RenderNodeRoleInstallation() error = %v", err)
	}
	if request.Role != model.RoleNode {
		t.Fatalf("role = %q", request.Role)
	}
	want := []string{"vpnctl-routing.service", "vpnctl-standard.service", "vpnctl-tunnel-client.service"}
	got := make([]string, 0, len(request.Units))
	for _, unit := range request.Units {
		got = append(got, unit.Name)
		content := string(unit.Content)
		if unit.Enable || unit.Start {
			t.Fatalf("unjoined unit %s is active: enable=%t start=%t", unit.Name, unit.Enable, unit.Start)
		}
		if !strings.Contains(content, "Restart=on-failure") || strings.Contains(content, "Type=oneshot") {
			t.Fatalf("unit %s does not have the long-running restart contract", unit.Name)
		}
		if !strings.Contains(content, "ConditionPathExists=/etc/vpnctl/generated/node/") {
			t.Fatalf("unit %s lacks its enrollment/readiness guard", unit.Name)
		}
		if strings.Contains(content, "gateway-") {
			t.Fatalf("unit %s contains a gateway service mode", unit.Name)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unit names = %v, want %v", got, want)
	}
	if len(request.Configs) != 1 || request.Configs[0].Name != "bootstrap.conf" ||
		string(request.Configs[0].Content) != nodeBootstrapConfig {
		t.Fatalf("bootstrap configs = %+v", request.Configs)
	}
}

func TestRenderNodeRoleInstallationRejectsUnsafeBinaryPath(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", "vpnctl", "/usr/local/bin/vpn ctl", "/usr/local/bin/vpnctl%I"} {
		if _, err := RenderNodeRoleInstallation(path); err == nil {
			t.Fatalf("RenderNodeRoleInstallation(%q) succeeded", path)
		}
	}
}
