package linux

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const nodeBootstrapConfig = `schema_version=1
role=node
enrollment_status=unjoined
`

// RenderNodeRoleInstallation returns the node-owned process units in a staged
// state. init --node establishes only the immutable host role; join writes the
// enrolled identity and generated configs before enabling or starting these
// units.
func RenderNodeRoleInstallation(binaryPath string) (RoleInstallationRequest, error) {
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath || strings.ContainsAny(binaryPath, " \t\r\n%") {
		return RoleInstallationRequest{}, fmt.Errorf("node service binary path must be clean, absolute, and systemd-safe")
	}
	modes := map[string]string{
		"vpnctl-routing.service":       "node-routing",
		"vpnctl-standard.service":      "node-standard",
		"vpnctl-tunnel-client.service": "node-tunnel-client",
	}
	names := make([]string, 0, len(modes))
	for name := range modes {
		names = append(names, name)
	}
	sort.Strings(names)
	units := make([]RoleUnitFile, 0, len(names))
	for _, name := range names {
		mode := modes[name]
		content := fmt.Sprintf(`[Unit]
Description=vpnctl %s
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/vpnctl/generated/node/%s.ready

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

[Install]
WantedBy=multi-user.target
`, mode, mode, binaryPath, mode)
		units = append(units, RoleUnitFile{Name: name, Content: []byte(content)})
	}
	return RoleInstallationRequest{
		Role: model.RoleNode, Units: units,
		Configs: []RoleConfigFile{{Name: "bootstrap.conf", Content: []byte(nodeBootstrapConfig)}},
	}, nil
}
