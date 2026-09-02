package linux

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const gatewayBootstrapConfig = `schema_version=1
role=gateway
public_https_tcp=443
restricted_tcp=8443
standard_udp=51820
pki_status=unprovisioned
presets_status=source_files
`

// RenderGatewayRoleInstallation returns the initial role-owned process units.
// Component tasks activate their readiness markers and generated configs; the
// ConditionPathExists guards keep an incomplete development bundle from
// entering a restart loop while preserving the final unit identities.
func RenderGatewayRoleInstallation(binaryPath string) (RoleInstallationRequest, error) {
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath || strings.ContainsAny(binaryPath, " \t\r\n%") {
		return RoleInstallationRequest{}, fmt.Errorf("gateway service binary path must be clean, absolute, and systemd-safe")
	}
	modes := map[string]string{
		"vpnctl-controller.service":    "gateway-controller",
		"vpnctl-dns.service":           "gateway-dns",
		"vpnctl-restricted.service":    "gateway-restricted",
		"vpnctl-standard.service":      "gateway-standard",
		"vpnctl-tunnel-server.service": "gateway-tunnel-server",
	}
	names := make([]string, 0, len(modes))
	for name := range modes {
		names = append(names, name)
	}
	sort.Strings(names)
	units := make([]RoleUnitFile, 0, len(names))
	for _, name := range names {
		mode := modes[name]
		serviceIsolation := ""
		if mode == "gateway-controller" {
			serviceIsolation = `RuntimeDirectory=vpnctl
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
UMask=0077
TimeoutStopSec=30s
`
		}
		content := fmt.Sprintf(`[Unit]
Description=vpnctl %s
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/vpnctl/generated/gateway/%s.ready

[Service]
Type=simple
ExecStart=%s __service %s
Restart=on-failure
RestartSec=2s
StandardOutput=null
StandardError=null
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/vpnctl /run/vpnctl
MemoryMax=128M
TasksMax=128
%s

[Install]
WantedBy=multi-user.target
`, mode, mode, binaryPath, mode, serviceIsolation)
		units = append(units, RoleUnitFile{Name: name, Content: []byte(content), Enable: true, Start: true})
	}
	request := RoleInstallationRequest{
		Role: model.RoleGateway, Units: units,
		Configs: []RoleConfigFile{
			{Name: "bootstrap.conf", Content: []byte(gatewayBootstrapConfig)},
			{Name: "gateway-controller.ready", Content: []byte("schema_version=1\n")},
		},
	}
	return request, nil
}
