package linux

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestRenderGatewayRoleInstallationUsesOnlyGatewayUnits(t *testing.T) {
	t.Parallel()

	request, err := RenderGatewayRoleInstallation(DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatalf("RenderGatewayRoleInstallation() error = %v", err)
	}
	if request.Role != model.RoleGateway {
		t.Fatalf("role = %s", request.Role)
	}
	names := make([]string, len(request.Units))
	for index, unit := range request.Units {
		names[index] = unit.Name
		content := string(unit.Content)
		for _, required := range []string{
			"ConditionPathExists=/etc/vpnctl/generated/gateway/", "Restart=on-failure",
			"StandardOutput=null", "StandardError=null", "ExecStart=/usr/local/bin/vpnctl __service gateway-",
		} {
			if !strings.Contains(content, required) {
				t.Errorf("unit %s missing %q", unit.Name, required)
			}
		}
		if !unit.Enable || !unit.Start {
			t.Errorf("gateway unit %s is not enabled and started", unit.Name)
		}
		if unit.Name == "vpnctl-controller.service" {
			for _, required := range []string{"RuntimeDirectory=vpnctl", "RuntimeDirectoryMode=0700", "RuntimeDirectoryPreserve=yes", "UMask=0077", "TimeoutStopSec=30s"} {
				if !strings.Contains(content, required) {
					t.Errorf("controller unit missing %q", required)
				}
			}
		}
		if unit.Name == "vpnctl-restricted.service" {
			for _, required := range []string{
				"ExecStart=/usr/local/bin/vpnctl __service gateway-restricted",
				"StateDirectory=vpnctl/restricted", "StateDirectoryMode=0700", "UMask=0077",
				"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK", "TimeoutStopSec=15s",
			} {
				if !strings.Contains(content, required) {
					t.Errorf("restricted unit missing %q", required)
				}
			}
		}
	}
	if want := RoleUnitNames(model.RoleGateway); !reflect.DeepEqual(names, want) {
		t.Fatalf("gateway rendered units = %v, want %v", names, want)
	}
	if len(request.Configs) != 2 || request.Configs[0].Name != "bootstrap.conf" || request.Configs[1].Name != "gateway-controller.ready" {
		t.Fatalf("gateway configs = %+v", request.Configs)
	}
	for _, fixed := range []string{"public_https_tcp=443", "restricted_tcp=8443", "standard_udp=51820", "pki_status=unprovisioned"} {
		if !strings.Contains(string(request.Configs[0].Content), fixed) {
			t.Errorf("bootstrap config missing %q", fixed)
		}
	}
	if string(request.Configs[1].Content) != "schema_version=1\n" {
		t.Fatalf("controller readiness content = %q", request.Configs[1].Content)
	}
}

func TestRenderGatewayRoleInstallationRejectsUnsafeBinaryPath(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"vpnctl", "/usr/local/bin/vpnctl bad", "/usr/local/bin/%i"} {
		if _, err := RenderGatewayRoleInstallation(path); err == nil {
			t.Errorf("unsafe binary path %q was accepted", path)
		}
	}
}
